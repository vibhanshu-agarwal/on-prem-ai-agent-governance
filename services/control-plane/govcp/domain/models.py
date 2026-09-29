"""Domain objects: the governed agent identity and what the ports exchange.

Plain dataclasses so the domain has no framework dependency. `to_dict` /
`from_dict` give a stable JSON shape for persistence and the API.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field, fields
from typing import Any

AGENT_LABEL = "govpilot.agent_id"
TEAM_LABEL = "govpilot.team"
ROOT_AGENT_LABEL = "govpilot.root_agent_id"

STATUS_ACTIVE = "active"
STATUS_STOPPED = "stopped"
STATUS_QUARANTINED = "quarantined"

DESIRED_RUNNING = "running"
DESIRED_STOPPED = "stopped"


def now() -> float:
    return time.time()


def _from(cls, data: dict):
    names = {f.name for f in fields(cls)}
    return cls(**{k: v for k, v in (data or {}).items() if k in names})


@dataclass
class GatewayKeyRef:
    key_hash: str
    alias: str | None = None
    secret_path: str | None = None  # where the raw key lives in the SecretStore, if we hold it

    @classmethod
    def from_dict(cls, d):
        return _from(cls, d)


@dataclass
class CredentialRef:
    """A non-gateway credential the agent holds (tool/MCP token, DB login, cert...)."""
    kind: str               # e.g. "db", "tool", "mcp", "queue"
    ref: str                # SecretStore path or external id
    description: str = ""

    @classmethod
    def from_dict(cls, d):
        return _from(cls, d)


@dataclass
class Agent:
    """One governed identity per agent. Every handle the agent holds hangs off this."""
    agent_id: str
    owner: str
    team: str
    display_name: str = ""
    status: str = STATUS_ACTIVE
    desired_state: str = DESIRED_RUNNING
    max_budget_usd: float = 0.0
    budget_duration: str | None = "30d"
    models: list[str] = field(default_factory=list)
    gateway_keys: list[GatewayKeyRef] = field(default_factory=list)
    workload_labels: dict[str, str] = field(default_factory=dict)   # selector for its containers/pods
    oidc_subjects: list[str] = field(default_factory=list)          # IdP subjects that resolve to this agent
    credentials: list[CredentialRef] = field(default_factory=list)
    sandbox_tier: str = "container"
    capabilities: list[str] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)            # free-form agent tags (e.g. host, version)
    parent_agent_id: str | None = None
    root_agent_id: str | None = None
    delegation_depth: int = 0
    quarantine_state: dict[str, Any] = field(default_factory=dict)  # what to restore on resume
    created_at: float = field(default_factory=now)
    updated_at: float = field(default_factory=now)

    def __post_init__(self):
        if not self.workload_labels:
            self.workload_labels = {AGENT_LABEL: self.agent_id}
        if self.root_agent_id is None:
            self.root_agent_id = self.agent_id

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "Agent":
        d = dict(d)
        d["gateway_keys"] = [GatewayKeyRef.from_dict(k) for k in d.get("gateway_keys", [])]
        d["credentials"] = [CredentialRef.from_dict(c) for c in d.get("credentials", [])]
        return _from(cls, d)


@dataclass
class Workload:
    """A running unit of an agent (a container here; a pod/deployment in Kubernetes)."""
    id: str
    name: str
    image: str
    labels: dict[str, str]
    host: str
    running: bool
    restart_policy: str = "no"
    networks: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    started_at: str | None = None
    controller: str | None = None  # e.g. "compose:project/service" when a controller owns it

    @property
    def agent_id(self) -> str | None:
        return self.labels.get(AGENT_LABEL)

    def to_dict(self):
        return asdict(self)


@dataclass
class Selector:
    """Bulk-quarantine selector. All given predicates are ANDed. `all=True` selects the fleet."""
    team: str | None = None
    image: str | None = None
    labels: dict[str, str] = field(default_factory=dict)
    host: str | None = None
    agent_ids: list[str] = field(default_factory=list)
    all: bool = False

    def is_empty(self) -> bool:
        return not (self.team or self.image or self.labels or self.host or self.agent_ids or self.all)

    def has_workload_predicates(self) -> bool:
        return bool(self.image or self.labels or self.host)

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return _from(cls, d or {})


@dataclass
class KeyStatus:
    key_hash: str
    alias: str | None
    blocked: bool
    team_id: str | None
    models: list[str]
    max_budget: float | None
    spend: float
    metadata: dict[str, Any]

    def to_dict(self):
        return asdict(self)


@dataclass
class IssuedKey:
    key_hash: str
    raw_key: str
    alias: str


@dataclass
class IsolationResult:
    workload_id: str
    workload_name: str
    method: str
    connections_before: int = 0      # established connections seen at the chokepoints before teardown
    connections_after: int = 0       # still established after teardown (should be 0)
    networks_removed: list[str] = field(default_factory=list)
    network_aliases: dict[str, list[str]] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    ok: bool = True

    def to_dict(self):
        return asdict(self)


@dataclass
class Secret:
    path: str
    value: str | None
    revoked: bool = False
    version: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RevocationResult:
    kind: str
    ref: str
    revoked: bool
    method: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self):
        return asdict(self)


@dataclass
class Principal:
    """An authenticated caller (human operator, machine client, feed, service)."""
    subject: str
    roles: list[str] = field(default_factory=list)
    teams: list[str] = field(default_factory=list)
    kind: str = "user"                 # user | client
    claims: dict[str, Any] = field(default_factory=dict)

    def has_role(self, *roles: str) -> bool:
        return "admin" in self.roles or any(r in self.roles for r in roles)

    def owns_team(self, team: str) -> bool:
        return "admin" in self.roles or "*" in self.teams or team in self.teams


@dataclass
class AuditRecord:
    seq: int
    ts: str
    actor: str
    action: str
    target: str
    severity: str
    details: dict[str, Any]
    prev_hash: str
    hash: str

    def to_dict(self):
        return asdict(self)


@dataclass
class ChainVerification:
    ok: bool
    count: int
    first_bad_seq: int | None = None
    reason: str | None = None
    head_hash: str | None = None

    def to_dict(self):
        return asdict(self)


@dataclass
class DiscoveryObservation:
    """What a discovery feed saw. Feeds propose; humans approve."""
    fingerprint: str                     # stable id of the thing seen (e.g. container name + image)
    kind: str = "workload"               # workload | identity | traffic
    name: str = ""
    image: str | None = None
    labels: dict[str, str] = field(default_factory=dict)
    suggested_team: str | None = None
    suggested_owner: str | None = None
    evidence: dict[str, Any] = field(default_factory=dict)  # deployment record, first-seen traffic...

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, d):
        return _from(cls, d)
