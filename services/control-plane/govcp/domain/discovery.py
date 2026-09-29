"""Pending discovery queue: feeds propose, humans approve, nothing spends until then.

A proposal holds zero budget and no gateway key (the key is created only on
approval). Each feed has a daily cap on new proposals so a noisy or compromised
feed cannot flood the queue into rubber-stamping, and auto-proposed entries must
carry evidence (report section 3).
"""
from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone
from typing import Any

from .context import Ports
from .errors import Conflict, Forbidden, InvalidRequest, NotFound, RateLimited
from .models import DiscoveryObservation, Principal
from .policy import Policy
from .register import RegisterService
from .repository import KV, PROPOSALS


WORKLOAD_IMAGE_LABEL = "workload_image"   # agent label binding an agent to the image its workloads run


def _day(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d")


class DiscoveryService:
    def __init__(self, ports: Ports, policy: Policy, register: RegisterService):
        self.p = ports
        self.policy = policy
        self.register = register

    def submit(self, feed: str, obs: DiscoveryObservation, submitted_by: str | None = None) -> dict[str, Any]:
        fp = self.policy.discovery.feed(feed)
        if not obs.fingerprint:
            raise InvalidRequest("fingerprint is required")
        if fp.auto and self.policy.discovery.require_evidence_for_auto and not obs.evidence:
            raise InvalidRequest("auto-proposed entries must include evidence (deployment record, first-seen traffic)")
        allp = self.p.repo.list(PROPOSALS)
        for p in allp:
            if p["fingerprint"] == obs.fingerprint and p["status"] in ("pending", "approved"):
                return {**p, "duplicate": True}
        spoof = None
        claimed = obs.labels.get("govpilot.agent_id")
        agent = self.register.find(claimed) if claimed else None
        if agent is not None:
            # A label is only a claim: anyone can copy `govpilot.agent_id` onto a rogue container. When the
            # register binds the agent to an image (agent label `workload_image`, a tag or a digest), the
            # observed workload must run that image to be folded as known; otherwise it is filed as a
            # suspected spoof with high priority (zero budget, no key, like every proposal).
            bound = (agent.labels or {}).get(WORKLOAD_IMAGE_LABEL)
            seen = {obs.image, (obs.evidence or {}).get("image"), (obs.evidence or {}).get("image_id")} - {None, ""}
            if not bound or bound in seen:
                return {"status": "known", "agent_id": claimed, "fingerprint": obs.fingerprint,
                        "binding": "image" if bound else "unbound"}
            spoof = {"claimed_agent_id": claimed, "expected_image": bound, "seen_image": obs.image}
        today = _day(time.time())
        counter = f"feedcount:{feed}:{today}"
        self.p.repo.insert(KV, counter, {"count": 0})

        def bump(d):  # atomic per-feed daily counter (row locked)
            if d["count"] >= fp.daily_limit:
                raise RateLimited(f"feed {feed!r} reached its daily limit of {fp.daily_limit} proposals",
                                  daily_limit=fp.daily_limit)
            d["count"] += 1
            return d
        try:
            self.p.repo.update(KV, counter, bump)
        except RateLimited:
            self.p.audit.append(submitted_by or feed, "discovery.rate_limited", feed,
                                {"daily_limit": fp.daily_limit, "fingerprint": obs.fingerprint}, severity="warning")
            raise
        prop = {
            "proposal_id": "dp-" + uuid.uuid4().hex[:12], "feed": feed, "fingerprint": obs.fingerprint,
            "observation": obs.to_dict(), "status": "pending", "budget_usd": 0.0, "gateway_key": None,
            "created_at": time.time(), "day": today, "submitted_by": submitted_by or feed,
            "priority": "high" if spoof else "normal",
        }
        if spoof:
            prop["flags"] = ["label_spoof_suspected"]
            prop["spoof"] = spoof
        self.p.repo.put(PROPOSALS, prop["proposal_id"], prop)
        if spoof:
            self.p.audit.append(submitted_by or feed, "discovery.label_spoof_suspected", prop["proposal_id"],
                                {"feed": feed, "fingerprint": obs.fingerprint, **spoof}, severity="alert")
        self.p.audit.append(submitted_by or feed, "discovery.proposed", prop["proposal_id"], {
            "feed": feed, "fingerprint": obs.fingerprint, "name": obs.name, "image": obs.image,
            "suggested_team": obs.suggested_team, "budget_usd": 0.0})
        return prop

    def list(self, status: str | None = None) -> list[dict[str, Any]]:
        out = self.p.repo.list(PROPOSALS)
        if status:
            out = [p for p in out if p["status"] == status]
        return sorted(out, key=lambda p: p["created_at"])

    def get(self, pid: str) -> dict[str, Any]:
        p = self.p.repo.get(PROPOSALS, pid)
        if not p:
            raise NotFound(f"proposal {pid!r} not found")
        return p

    def approve(self, pid: str, actor: Principal, spec: dict[str, Any]) -> dict[str, Any]:
        prop = self.get(pid)
        if prop["status"] != "pending":
            raise Conflict(f"proposal is {prop['status']}")
        team = spec.get("team") or prop["observation"].get("suggested_team")
        if not team:
            raise InvalidRequest("team is required to approve")
        if actor.kind != "user" or not (actor.has_role("owner") and actor.owns_team(team)):
            raise Forbidden(f"only a human owner of team {team!r} can approve")
        obs = prop["observation"]
        reg_spec = {
            "agent_id": spec.get("agent_id") or obs.get("name"), "team": team,
            "owner": spec.get("owner") or actor.subject, "max_budget_usd": spec.get("max_budget_usd", 0),
            "models": spec.get("models") or [], "sandbox_tier": spec.get("sandbox_tier", "container"),
            "capabilities": spec.get("capabilities") or [], "workload_labels": spec.get("workload_labels") or None,
            "oidc_subjects": spec.get("oidc_subjects") or ([obs["evidence"]["subject"]] if obs.get("kind") ==
                                                           "identity" and obs.get("evidence", {}).get("subject")
                                                           else []),
            "labels": {"discovered_by": prop["feed"], "proposal_id": pid},
        }
        res = self.register.register(reg_spec, actor, audit_action="agent.registered_from_discovery")

        def fin(p):
            p.update(status="approved", decided_by=actor.subject, decided_at=time.time(),
                     agent_id=res["agent"].agent_id, budget_usd=res["agent"].max_budget_usd)
            return p
        out = self.p.repo.update(PROPOSALS, pid, fin)
        self.p.audit.append(actor.subject, "discovery.approved", pid, {"agent_id": res["agent"].agent_id,
                                                                      "budget_usd": res["agent"].max_budget_usd})
        return {"proposal": out, "agent": res["agent"].to_dict(), "gateway_key": res["gateway_key"],
                "delegation_token": res["delegation_token"]}

    def reject(self, pid: str, actor: Principal, reason: str) -> dict[str, Any]:
        prop = self.get(pid)
        if prop["status"] != "pending":
            raise Conflict(f"proposal is {prop['status']}")
        team = prop["observation"].get("suggested_team")
        if not (actor.has_role("operator") or (team and actor.has_role("owner") and actor.owns_team(team))):
            raise Forbidden("operator or team owner required")
        out = self.p.repo.update(PROPOSALS, pid, lambda p: {**p, "status": "rejected", "decided_by": actor.subject,
                                                            "decided_at": time.time(), "reason": reason})
        self.p.audit.append(actor.subject, "discovery.rejected", pid, {"reason": reason})
        return out
