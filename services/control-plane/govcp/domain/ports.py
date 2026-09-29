"""Ports: the only way the control plane talks to the outside world.

Each port has one production adapter today (see govcp/adapters) plus an
in-memory adapter used by unit tests and to validate the contract suites in
tests/control/contracts/. A sponsor adopting this repo writes a new adapter
(e.g. Kubernetes instead of Docker, Vault instead of a file, a SIEM instead of
Postgres), points config at it, and runs the same contract suite.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Iterable

from .models import (AuditRecord, ChainVerification, CredentialRef, DiscoveryObservation, IsolationResult,
                     IssuedKey, KeyStatus, Principal, RevocationResult, Secret, Workload)


class GatewayAdmin(ABC):
    """Admin surface of the AI gateway (LiteLLM today)."""

    @abstractmethod
    def health(self) -> bool: ...

    @abstractmethod
    def ensure_team(self, team: str, max_budget_usd: float | None = None) -> str:
        """Return the gateway team id for a team name, creating it if needed."""

    @abstractmethod
    def create_key(self, alias: str, team: str | None, models: list[str], max_budget_usd: float,
                   metadata: dict[str, Any], blocked: bool = False,
                   budget_duration: str | None = None) -> IssuedKey: ...

    @abstractmethod
    def block_key(self, key_hash: str) -> None:
        """Deny every subsequent request made with this key. Must be effective for the next request."""

    @abstractmethod
    def unblock_key(self, key_hash: str) -> None: ...

    @abstractmethod
    def key_status(self, key_hash: str) -> KeyStatus | None: ...

    @abstractmethod
    def find_keys(self, alias: str | None = None, team: str | None = None,
                  agent_id: str | None = None) -> list[KeyStatus]:
        """Find keys by alias, by team name, or by agent (metadata.agent_id / root_agent_id)."""

    @abstractmethod
    def delete_key(self, key_hash: str) -> None: ...

    @abstractmethod
    def probe(self, raw_key: str) -> bool:
        """True if the gateway currently accepts this key (a zero-cost authenticated call)."""


class Orchestrator(ABC):
    """Compute platform that runs agent workloads (Docker today; Kubernetes later)."""

    @abstractmethod
    def host_name(self) -> str: ...

    @abstractmethod
    def list_workloads(self, labels: dict[str, str] | None = None, image: str | None = None,
                       host: str | None = None, include_stopped: bool = True) -> list[Workload]: ...

    @abstractmethod
    def get(self, workload_id: str) -> Workload | None: ...

    @abstractmethod
    def prevent_restart(self, workload_id: str) -> str:
        """Change desired state so the platform will not restart the workload. Returns the previous policy."""

    @abstractmethod
    def stop(self, workload_id: str, grace_s: float = 2.0) -> None: ...

    @abstractmethod
    def restore_restart(self, workload_id: str, policy: str) -> None: ...

    @abstractmethod
    def start(self, workload_id: str) -> None: ...


class NetworkQuarantine(ABC):
    """Cuts a workload off the governed networks and tears down its established connections."""

    @abstractmethod
    def isolate(self, workloads: list[Workload]) -> list[IsolationResult]: ...

    @abstractmethod
    def restore(self, workload_id: str, networks: list[str], aliases: dict[str, list[str]] | None = None) -> None: ...

    @abstractmethod
    def is_isolated(self, workload_id: str) -> bool:
        """True if the workload is attached to none of the governed networks."""


class IdentityProvider(ABC):
    """Validates tokens and controls whether a subject can obtain new ones (corporate OIDC/LDAP later)."""

    @abstractmethod
    def verify(self, token: str, audience: str) -> Principal:
        """Return the principal or raise govcp.domain.errors.Unauthorized."""

    @abstractmethod
    def disable_subject(self, subject: str) -> None: ...

    @abstractmethod
    def enable_subject(self, subject: str) -> None: ...

    @abstractmethod
    def subject_enabled(self, subject: str) -> bool: ...


class SecretStore(ABC):
    """Holds raw secrets the control plane must keep (env/file today; Vault later)."""

    @abstractmethod
    def put(self, path: str, value: str, metadata: dict[str, Any] | None = None) -> Secret: ...

    @abstractmethod
    def get(self, path: str) -> Secret | None: ...

    @abstractmethod
    def revoke(self, path: str) -> Secret | None:
        """Mark revoked and destroy the value. Returns the revoked record, None if unknown."""

    @abstractmethod
    def list(self, prefix: str = "") -> list[str]: ...


class CredentialRevoker(ABC):
    """Revokes a non-gateway credential (tool/MCP token, DB login, certificate)."""

    @abstractmethod
    def supports(self, kind: str) -> bool: ...

    @abstractmethod
    def revoke(self, cred: CredentialRef) -> RevocationResult: ...

    @abstractmethod
    def is_revoked(self, cred: CredentialRef) -> bool: ...


class AuditSink(ABC):
    """Append-only, hash-chained record of every action (Postgres today; SIEM later)."""

    @abstractmethod
    def append(self, actor: str, action: str, target: str, details: dict[str, Any] | None = None,
               severity: str = "info") -> AuditRecord: ...

    @abstractmethod
    def list(self, limit: int = 100, since_seq: int = 0, action_prefix: str | None = None,
             severity: str | None = None, target: str | None = None) -> list[AuditRecord]: ...

    @abstractmethod
    def verify(self) -> ChainVerification: ...


class DiscoveryFeed(ABC):
    """Source of discovery observations (docker events today; k8s watch / OpenLIT Controller later).

    Interface only in T3; T6 implements the feeds. A feed never creates agents or
    keys: it hands observations to `submit`, which files them in the pending queue
    (zero budget until an owner approves) and applies the per-feed daily rate limit.
    """

    name: str

    @abstractmethod
    def observations(self) -> Iterable[DiscoveryObservation]:
        """Yield observations since the last call (pull model)."""

    def run(self, submit: Callable[[str, DiscoveryObservation], Any], should_stop: Callable[[], bool]) -> None:
        """Default push loop: forward every observation to `submit(feed_name, obs)`."""
        while not should_stop():
            for obs in self.observations():
                submit(self.name, obs)
