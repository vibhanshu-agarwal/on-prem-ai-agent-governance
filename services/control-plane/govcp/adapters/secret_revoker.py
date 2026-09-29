"""CredentialRevoker adapter for credentials held in the SecretStore.

Simulated tool / DB / MCP credentials: revocation destroys the secret so any
consumer that validates against the store refuses it.
A real deployment adds one revoker per system (ALTER ROLE ... NOLOGIN, MCP
server token revoke, PKI CRL/short-lived cert expiry...).
"""
from __future__ import annotations

from ..domain.models import RevocationResult
from ..domain.ports import CredentialRevoker, SecretStore


class SecretStoreRevoker(CredentialRevoker):
    def __init__(self, store: SecretStore, kinds: list[str] | None = None):
        self.store = store
        self.kinds = set(kinds or ["db", "tool", "mcp", "queue", "api"])

    def supports(self, kind):
        return kind in self.kinds

    def revoke(self, cred):
        rec = self.store.revoke(cred.ref)
        return RevocationResult(kind=cred.kind, ref=cred.ref, revoked=rec is not None and rec.revoked,
                                method="secret_store.revoke", details={"known": rec is not None,
                                                                        "version": rec.version if rec else None})

    def is_revoked(self, cred):
        s = self.store.get(cred.ref)
        return s is None or s.revoked
