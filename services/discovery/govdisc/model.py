"""Value objects shared by feeds, ports and adapters. Plain data, no I/O."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Observation:
    """One thing a feed saw. Same shape as the control plane's proposal body (POST /v1/discovery/proposals)."""
    fingerprint: str                       # stable identity, used by the queue to fold duplicates
    kind: str = "workload"                 # workload | traffic | identity
    name: str = ""
    image: str | None = None
    labels: dict[str, str] = field(default_factory=dict)
    suggested_team: str | None = None
    suggested_owner: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ContainerInfo:
    """What the container runtime tells us about a workload (no environment variables: they hold secrets)."""
    id: str
    name: str
    image: str
    labels: dict[str, str] = field(default_factory=dict)
    networks: dict[str, str] = field(default_factory=dict)     # network name -> IPv4
    created: str = ""                                          # ISO timestamp
    started: str = ""
    status: str = ""


@dataclass
class RefusedCall:
    """A request to the gateway that it refused (no/invalid key, blocked key)."""
    ts: float
    src_ip: str
    method: str
    path: str
    status: int


@dataclass
class CallSummary:
    """Calls one gateway key made in a window, from the gateway's own telemetry."""
    key_hash: str
    key_alias: str
    team: str
    agent_id: str
    owner: str
    calls: int
    spend_usd: float
    models: list[str]
    first_seen: str
    last_seen: str


@dataclass
class SubmitResult:
    status: str                            # created | duplicate | known | rate_limited | rejected | error
    proposal_id: str | None = None
    detail: str = ""
