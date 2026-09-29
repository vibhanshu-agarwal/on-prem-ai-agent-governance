"""ProposalSink over the control-plane HTTP API (POST /v1/discovery/proposals).

Each feed authenticates as its own IdP client (role `feed`); the control plane takes the feed name
from the authenticated subject, so one feed can never spend another feed's daily quota or file
proposals under another name.
"""
from __future__ import annotations

import logging
import time

import httpx

from ..model import Observation, SubmitResult
from ..ports import ProposalSink

log = logging.getLogger("govdisc.sink")


class ControlPlaneSink(ProposalSink):
    def __init__(self, control_plane_url: str, token_url: str, client_id: str, client_secret: str,
                 audience: str = "govpilot-control-plane", client: httpx.Client | None = None):
        self.cp = control_plane_url.rstrip("/")
        self.token_url = token_url
        self.client_id, self.secret, self.audience = client_id, client_secret, audience
        self.http = client or httpx.Client(timeout=10)
        self._tok: str | None = None
        self._exp = 0.0

    def _token(self) -> str:
        if self._tok and time.time() < self._exp - 30:
            return self._tok
        r = self.http.post(self.token_url, data={"grant_type": "client_credentials", "client_id": self.client_id,
                                                 "client_secret": self.secret, "audience": self.audience})
        r.raise_for_status()
        d = r.json()
        self._tok, self._exp = d["access_token"], time.time() + int(d.get("expires_in", 300))
        return self._tok

    def submit(self, feed: str, obs: Observation) -> SubmitResult:
        # `feed` is informational: the server names the feed from our token subject
        try:
            for attempt in (1, 2):
                r = self.http.post(self.cp + "/v1/discovery/proposals", json=obs.to_payload(),
                                   headers={"Authorization": f"Bearer {self._token()}"})
                if r.status_code == 401 and attempt == 1:
                    self._tok = None                     # expired/rotated: fetch a fresh token once
                    continue
                break
        except httpx.HTTPError as e:
            return SubmitResult("error", detail=str(e))
        if r.status_code == 429:
            return SubmitResult("rate_limited", detail=r.text[:200])
        if r.status_code in (200, 201):
            b = r.json()
            if b.get("status") == "known":
                return SubmitResult("known", detail=b.get("agent_id", ""))
            if b.get("duplicate"):
                return SubmitResult("duplicate", b.get("proposal_id"))
            return SubmitResult("created", b.get("proposal_id"))
        if 500 <= r.status_code:
            return SubmitResult("error", detail=f"HTTP {r.status_code}")
        return SubmitResult("rejected", detail=f"HTTP {r.status_code}: {r.text[:200]}")
