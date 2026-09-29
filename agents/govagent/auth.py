"""How an agent proves who it is. The gateway side maps each of these to the agent's own key.

  StaticKeyAuth              Authorization: Bearer <LiteLLM virtual key>           (straight to the gateway)
  OIDCClientCredentialsAuth  Authorization: Bearer <JWT from the IdP>              (through the auth proxy)
  MacaroonAuth               Authorization: Macaroon <attenuated delegation token> (through the auth proxy)
"""
from __future__ import annotations

import json
import threading
import time
import urllib.parse
from typing import Callable, Protocol

from .transport import Transport, TransportError, UrllibTransport


class AuthError(Exception):
    pass


class AuthProvider(Protocol):
    scheme: str

    def headers(self) -> dict[str, str]: ...
    def invalidate(self) -> None: ...


class StaticKeyAuth:
    scheme = "key"

    def __init__(self, key: str) -> None:
        self._key = key

    def headers(self) -> dict[str, str]:
        return {"authorization": f"Bearer {self._key}"}

    def invalidate(self) -> None:
        pass


class MacaroonAuth:
    scheme = "delegation"

    def __init__(self, token: str) -> None:
        self._token = token

    def headers(self) -> dict[str, str]:
        return {"authorization": f"Macaroon {self._token}"}

    def invalidate(self) -> None:
        pass


class OIDCClientCredentialsAuth:
    """client_credentials at the IdP; caches the JWT and refreshes it before it expires or after a 401."""
    scheme = "oidc"

    def __init__(self, token_url: str, client_id: str, client_secret: str, *, audience: str | None = None,
                 transport: Transport | None = None, clock: Callable[[], float] = time.time,
                 skew_s: float = 60.0) -> None:
        self.token_url, self.client_id, self._secret, self.audience = token_url, client_id, client_secret, audience
        self.transport, self.clock, self.skew = transport or UrllibTransport(), clock, skew_s
        self._tok: str | None = None
        self._exp = 0.0
        self._lock = threading.Lock()
        self.fetches = 0

    def _fetch(self) -> None:
        form = {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self._secret}
        if self.audience:
            form["audience"] = self.audience
        try:
            r = self.transport.send("POST", self.token_url, {"content-type": "application/x-www-form-urlencoded"},
                                    urllib.parse.urlencode(form).encode(), 10.0)
        except TransportError as e:
            raise AuthError(f"identity provider unreachable: {e}") from None
        if r.status != 200:
            raise AuthError(f"identity provider refused the token request: HTTP {r.status}")
        d = json.loads(r.body)
        self._tok = d["access_token"]
        self._exp = self.clock() + float(d.get("expires_in", 300))
        self.fetches += 1

    def headers(self) -> dict[str, str]:
        with self._lock:
            if self._tok is None or self.clock() >= self._exp - self.skew:
                self._fetch()
            return {"authorization": f"Bearer {self._tok}"}

    def invalidate(self) -> None:
        with self._lock:
            self._tok = None
