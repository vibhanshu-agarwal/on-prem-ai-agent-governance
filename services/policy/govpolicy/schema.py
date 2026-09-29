"""Policy schema (pydantic) and compilation of policy/ YAML files into one Policy object.

Layout of a policy directory:
  global.yaml            tier ladder + capability -> minimum tier
  teams/*.yaml           team budget + model allowlist
  agents/*.yaml          one file per agent
"""
from __future__ import annotations

import fnmatch
from pathlib import Path
from typing import Dict, List, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator


class PolicyError(ValueError):
    """Policy files are invalid (schema or cross-reference)."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Budget(_Strict):
    max_usd: float = Field(gt=0)
    duration: str = Field(default="30d", pattern=r"^\d+[smhd]$")


class GlobalRules(_Strict):
    schema_version: int = 1
    sandbox_tiers: List[str] = Field(min_length=1)  # weakest -> strongest
    capability_min_tier: Dict[str, str]
    default_max_tokens_ceiling: int = Field(gt=0)

    @model_validator(mode="after")
    def _check(self):
        if len(set(self.sandbox_tiers)) != len(self.sandbox_tiers):
            raise ValueError("sandbox_tiers must be unique")
        for cap, tier in self.capability_min_tier.items():
            if tier not in self.sandbox_tiers:
                raise ValueError(f"capability {cap!r} names unknown tier {tier!r}")
        return self

    def tier_rank(self, tier: str) -> int:
        return self.sandbox_tiers.index(tier)


class Team(_Strict):
    name: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    models: List[str] = Field(min_length=1)
    budget: Budget


class AgentPolicy(_Strict):
    id: str = Field(pattern=r"^[a-z][a-z0-9-]*$")
    team: str
    models: List[str] = Field(min_length=1)
    budget: Budget
    max_tokens_ceiling: int = Field(gt=0)
    # e.g. executes_model_code, calls_tools, external_send (names defined in global.yaml)
    capabilities: List[str] = Field(default_factory=list)
    required_sandbox_tier: str
    allowed_images: Optional[List[str]] = None  # fnmatch globs; None = any image
    # consequential actions that need a human approval before execution
    require_human_approval: List[str] = Field(default_factory=list)

    def image_allowed(self, image: str) -> bool:
        return self.allowed_images is None or any(
            fnmatch.fnmatchcase(image, p) for p in self.allowed_images)


class Policy(_Strict):
    globals: GlobalRules
    teams: Dict[str, Team]
    agents: Dict[str, AgentPolicy]

    @model_validator(mode="after")
    def _cross_check(self):
        g = self.globals
        errs: List[str] = []
        spent: Dict[str, float] = {}
        for a in self.agents.values():
            t = self.teams.get(a.team)
            if t is None:
                errs.append(f"agent {a.id}: unknown team {a.team!r}")
                continue
            extra = set(a.models) - set(t.models)
            if extra:
                errs.append(f"agent {a.id}: models {sorted(extra)} not in team {t.name} allowlist")
            spent[t.name] = spent.get(t.name, 0) + a.budget.max_usd
            if a.required_sandbox_tier not in g.sandbox_tiers:
                errs.append(f"agent {a.id}: unknown sandbox tier {a.required_sandbox_tier!r}")
                continue
            for cap in a.capabilities:
                need = g.capability_min_tier.get(cap)
                if need is None:
                    errs.append(f"agent {a.id}: unknown capability {cap!r}")
                elif g.tier_rank(a.required_sandbox_tier) < g.tier_rank(need):
                    errs.append(f"agent {a.id}: capability {cap} needs tier >= {need}, "
                                f"but required_sandbox_tier is {a.required_sandbox_tier}")
        for name, total in spent.items():
            cap = self.teams[name].budget.max_usd
            if total > cap + 1e-9:
                errs.append(f"team {name}: agent budgets sum to {total} > team budget {cap}")
        if errs:
            raise ValueError("; ".join(errs))
        return self

    # ---- convenience queries used by the control plane / gateway hooks ----
    def agent(self, agent_id: str) -> Optional[AgentPolicy]:
        return self.agents.get(agent_id)

    def model_allowed(self, agent_id: str, model: str) -> bool:
        a = self.agents.get(agent_id)
        return a is not None and model in a.models

    def max_tokens_ceiling(self, agent_id: str) -> int:
        a = self.agents.get(agent_id)
        return a.max_tokens_ceiling if a else self.globals.default_max_tokens_ceiling

    def requires_approval(self, agent_id: str, action: str) -> bool:
        """Unknown agents require approval for everything (fail closed)."""
        a = self.agents.get(agent_id)
        return True if a is None else action in a.require_human_approval

    def required_tier(self, agent_id: str, capabilities: Optional[List[str]] = None) -> Optional[str]:
        """Strongest tier demanded by the agent's declared tier and the given (or declared) capabilities."""
        a = self.agents.get(agent_id)
        if a is None:
            return None
        caps = a.capabilities if capabilities is None else capabilities
        tiers = [a.required_sandbox_tier] + [
            self.globals.capability_min_tier[c] for c in caps if c in self.globals.capability_min_tier]
        return max(tiers, key=self.globals.tier_rank)


def _load_yaml(path: Path) -> dict:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise PolicyError(f"{path}: invalid YAML: {e}") from e
    if not isinstance(data, dict):
        raise PolicyError(f"{path}: expected a mapping at top level")
    return data


def compile_policy_dir(root: Path) -> Policy:
    """Read and validate every policy file under root; raises PolicyError."""
    root = Path(root)
    if not (root / "global.yaml").is_file():
        raise PolicyError(f"{root}: missing global.yaml")
    try:
        g = GlobalRules(**_load_yaml(root / "global.yaml"))
        teams: Dict[str, Team] = {}
        for p in sorted((root / "teams").glob("*.yaml")):
            t = Team(**_load_yaml(p))
            if t.name != p.stem:
                raise PolicyError(f"{p}: name {t.name!r} must match file name")
            teams[t.name] = t
        agents: Dict[str, AgentPolicy] = {}
        for p in sorted((root / "agents").glob("*.yaml")):
            a = AgentPolicy(**_load_yaml(p))
            if a.id != p.stem:
                raise PolicyError(f"{p}: id {a.id!r} must match file name")
            agents[a.id] = a
        return Policy(globals=g, teams=teams, agents=agents)
    except ValidationError as e:
        raise PolicyError(str(e)) from e


def json_schema() -> dict:
    return Policy.model_json_schema()
