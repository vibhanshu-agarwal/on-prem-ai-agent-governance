"""Tunable policy values. Loaded from the `policy:` section of the config file."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StopPolicy:
    stop_grace_s: float = 2.0          # SIGTERM grace before SIGKILL
    verify_settle_s: float = 1.5       # wait, then re-check nothing restarted
    target_s: float = 30.0             # the acceptance target (report section 8)
    cascade_to_delegates: bool = True  # stopping a parent stops its sub-agents
    disable_idp_subjects: bool = True  # IdP-level fallback: no new tokens for the agent's subjects


@dataclass
class QuarantinePolicy:
    preview_ttl_s: float = 600.0
    dual_control_min_agents: int = 4   # >= this many agents => fleet-wide => two approvals
    dual_control_min_teams: int = 2    # spanning >= this many teams => fleet-wide
    approvals_required: int = 2


@dataclass
class FeedPolicy:
    daily_limit: int = 20
    auto: bool = True                  # auto-proposed feeds must supply evidence


@dataclass
class DiscoveryPolicy:
    default_daily_limit: int = 20
    require_evidence_for_auto: bool = True
    feeds: dict[str, FeedPolicy] = field(default_factory=dict)

    def feed(self, name: str) -> FeedPolicy:
        return self.feeds.get(name) or FeedPolicy(daily_limit=self.default_daily_limit)


@dataclass
class DelegationPolicy:
    max_depth: int = 2
    default_ttl_s: float = 3600.0


@dataclass
class Policy:
    sandbox_tiers: list[str] = field(default_factory=lambda: ["container", "gvisor", "microvm"])
    stop: StopPolicy = field(default_factory=StopPolicy)
    quarantine: QuarantinePolicy = field(default_factory=QuarantinePolicy)
    discovery: DiscoveryPolicy = field(default_factory=DiscoveryPolicy)
    delegation: DelegationPolicy = field(default_factory=DelegationPolicy)

    @classmethod
    def from_dict(cls, d: dict[str, Any] | None) -> "Policy":
        d = d or {}
        disc = d.get("discovery", {}) or {}
        feeds = {k: FeedPolicy(**(v or {})) for k, v in (disc.get("feeds") or {}).items()}
        return cls(
            sandbox_tiers=d.get("sandbox_tiers") or ["container", "gvisor", "microvm"],
            stop=StopPolicy(**(d.get("stop") or {})),
            quarantine=QuarantinePolicy(**(d.get("quarantine") or {})),
            discovery=DiscoveryPolicy(default_daily_limit=disc.get("default_daily_limit", 20),
                                      require_evidence_for_auto=disc.get("require_evidence_for_auto", True),
                                      feeds=feeds),
            delegation=DelegationPolicy(**(d.get("delegation") or {})),
        )
