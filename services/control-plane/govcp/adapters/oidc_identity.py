"""IdentityProvider adapter for a generic OIDC issuer (RS256 JWTs + JWKS).

Token verification is standard OIDC and works against any compliant issuer
(Keycloak, Entra ID, Okta...). Subject disable/enable uses the stand-in IdP's
admin API; against a corporate IdP this becomes a SCIM / Graph call.
"""
from __future__ import annotations

import threading
import time

import httpx
import jwt

from ..domain.errors import AdapterError, Unauthorized
from ..domain.models import Principal
from ..domain.ports import IdentityProvider


class OIDCIdentityProvider(IdentityProvider):
    def __init__(self, issuer: str, jwks_url: str, admin_url: str | None = None, admin_token: str | None = None,
                 jwks_cache_s: float = 30.0, leeway_s: float = 5.0):
        self.issuer = issuer
        self.jwks_url = jwks_url
        self.admin_url = (admin_url or "").rstrip("/")
        self.admin_token = admin_token
        self.jwks_cache_s = jwks_cache_s
        self.leeway = leeway_s
        self._keys: dict[str, object] = {}
        self._fetched = 0.0
        self._lock = threading.Lock()

    def _refresh(self, force=False):
        with self._lock:
            if not force and self._keys and time.time() - self._fetched < self.jwks_cache_s:
                return
            try:
                data = httpx.get(self.jwks_url, timeout=5).json()
            except Exception as e:  # noqa: BLE001
                if self._keys:
                    return  # keep serving from cache if the IdP blips
                raise AdapterError(f"cannot fetch JWKS: {e}") from None
            self._keys = {k["kid"]: jwt.PyJWK(k).key for k in data.get("keys", [])}
            self._fetched = time.time()

    def verify(self, token, audience):
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except jwt.PyJWTError as e:
            raise Unauthorized(f"malformed token: {e}") from None
        self._refresh()          # TTL 30 s: a kid the IdP removed (key compromise) stops verifying within that bound
        if kid not in self._keys:
            self._refresh(force=True)
        key = self._keys.get(kid)
        if key is None:
            raise Unauthorized("unknown signing key")
        try:
            claims = jwt.decode(token, key=key, algorithms=["RS256"], audience=audience, issuer=self.issuer,
                                leeway=self.leeway, options={"require": ["exp", "iat", "sub", "iss", "aud"]})
        except jwt.PyJWTError as e:
            raise Unauthorized(f"invalid token: {e}") from None
        # `kind` decides who counts as a human for human-only actions (bulk quarantine, approvals). A token
        # that does not say is treated as a machine: an IdP that lacks the claim must map it explicitly.
        return Principal(subject=claims["sub"], roles=list(claims.get("roles") or []),
                         teams=list(claims.get("teams") or []), kind=claims.get("kind") or "client", claims=claims)

    def _admin(self, method, path):
        if not self.admin_url or not self.admin_token:
            raise AdapterError("IdP admin API not configured")
        try:
            r = httpx.request(method, self.admin_url + path, headers={"Authorization": f"Bearer {self.admin_token}"},
                              timeout=5)
        except httpx.HTTPError as e:
            raise AdapterError(f"IdP unreachable: {e}") from None
        if r.status_code >= 400:
            raise AdapterError(f"IdP admin {path} -> {r.status_code}: {r.text[:200]}")
        return r.json()

    def disable_subject(self, subject):
        self._admin("POST", f"/admin/subjects/{subject}/disable")

    def enable_subject(self, subject):
        self._admin("POST", f"/admin/subjects/{subject}/enable")

    def subject_enabled(self, subject):
        return bool(self._admin("GET", f"/admin/subjects/{subject}").get("enabled"))
