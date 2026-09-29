"""The bundle of port instances the domain services work with (built by govcp.wiring)."""
from __future__ import annotations

from dataclasses import dataclass, field

from .ports import (AuditSink, CredentialRevoker, GatewayAdmin, IdentityProvider, NetworkQuarantine, Orchestrator,
                    SecretStore)
from .repository import Repository


@dataclass
class Ports:
    gateway: GatewayAdmin
    orchestrator: Orchestrator
    network: NetworkQuarantine
    identity: IdentityProvider
    secrets: SecretStore
    audit: AuditSink
    repo: Repository
    revokers: list[CredentialRevoker] = field(default_factory=list)

    def revoker_for(self, kind: str) -> CredentialRevoker | None:
        for r in self.revokers:
            if r.supports(kind):
                return r
        return None
