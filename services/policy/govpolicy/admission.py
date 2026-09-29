"""Admission check: the Docker-era stand-in for a Kubernetes admission controller.

A deployment request is admitted only if the agent exists in the (signed, verified) policy, the
image is allowed, every requested capability is declared, and the requested sandbox tier is at least
as strong as the strongest tier demanded by the agent's declared tier and its capabilities.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from .schema import Policy


@dataclass(frozen=True)
class AdmissionRequest:
    agent_id: str
    image: str
    capabilities: List[str] = field(default_factory=list)
    sandbox_tier: str = "container"


@dataclass(frozen=True)
class AdmissionDecision:
    allowed: bool
    reasons: List[str]
    required_tier: Optional[str] = None
    policy_version: Optional[str] = None

    def to_dict(self) -> dict:
        return {"allowed": self.allowed, "reasons": self.reasons,
                "required_tier": self.required_tier, "policy_version": self.policy_version}


def admit(policy: Policy, req: AdmissionRequest, policy_version: Optional[str] = None) -> AdmissionDecision:
    agent = policy.agent(req.agent_id)
    if agent is None:
        return AdmissionDecision(False, [f"agent {req.agent_id!r} is not in the signed policy"],
                                 None, policy_version)
    g = policy.globals
    reasons: List[str] = []

    if not agent.image_allowed(req.image):
        reasons.append(f"image {req.image!r} is not allowed for {agent.id} "
                       f"(allowed: {agent.allowed_images})")

    requested = list(dict.fromkeys(req.capabilities))
    for cap in requested:
        if cap not in g.capability_min_tier:
            reasons.append(f"capability {cap!r} is unknown to policy")
        elif cap not in agent.capabilities:
            reasons.append(f"capability {cap!r} is not declared for {agent.id} "
                           f"(declared: {agent.capabilities})")

    # Declared capabilities always count, so a request cannot lower the bar by omitting them.
    known = [c for c in dict.fromkeys(agent.capabilities + requested) if c in g.capability_min_tier]
    required = policy.required_tier(agent.id, known)

    if req.sandbox_tier not in g.sandbox_tiers:
        reasons.append(f"unknown sandbox tier {req.sandbox_tier!r} (known: {g.sandbox_tiers})")
    elif g.tier_rank(req.sandbox_tier) < g.tier_rank(required):
        drivers = [c for c in known if g.capability_min_tier[c] == required] or ["agent declaration"]
        reasons.append(f"sandbox tier {req.sandbox_tier!r} is weaker than required {required!r} "
                       f"(driven by: {', '.join(drivers)})")

    return AdmissionDecision(not reasons, reasons or ["admitted"], required, policy_version)
