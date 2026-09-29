"""Agent identity register: one governed identity per agent linking every handle it holds."""
from __future__ import annotations

import re
from typing import Any

from .context import Ports
from .errors import Conflict, Forbidden, InvalidRequest, NotFound
from .models import (AGENT_LABEL, ROOT_AGENT_LABEL, TEAM_LABEL, Agent, CredentialRef, GatewayKeyRef, Principal,
                     now)
from .policy import Policy
from .repository import AGENTS

AGENT_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,94}$")
TIER_ORDER = {"container": 0, "gvisor": 1, "microvm": 2}
# Minimal deploy-time admission rule from report section 4 (T7 owns the full policy-as-code gate).
# Capability names and tiers mirror policy/global.yaml `capability_min_tier` (one vocabulary for T3 and T7).
CAPABILITY_MIN_TIER = {"executes_model_code": "microvm", "shell": "microvm", "external_send": "gvisor",
                       "calls_tools": "container"}


def key_secret_path(agent_id: str, alias: str) -> str:
    return f"gateway-keys/{agent_id}/{alias}"


class RegisterService:
    def __init__(self, ports: Ports, policy: Policy):
        self.p = ports
        self.policy = policy
        self.delegation = None  # set by wiring (DelegationService issues the root capability token)

    # ---- reads -------------------------------------------------------------
    def get(self, agent_id: str) -> Agent:
        d = self.p.repo.get(AGENTS, agent_id)
        if not d:
            raise NotFound(f"agent {agent_id!r} not registered")
        return Agent.from_dict(d)

    def find(self, agent_id: str) -> Agent | None:
        d = self.p.repo.get(AGENTS, agent_id)
        return Agent.from_dict(d) if d else None

    def list(self, team: str | None = None, status: str | None = None) -> list[Agent]:
        out = [Agent.from_dict(d) for d in self.p.repo.list(AGENTS)]
        if team:
            out = [a for a in out if a.team == team]
        if status:
            out = [a for a in out if a.status == status]
        return sorted(out, key=lambda a: a.agent_id)

    def by_subject(self, subject: str) -> Agent | None:
        for a in self.list():
            if subject in a.oidc_subjects:
                return a
        return None

    def descendants(self, agent_id: str) -> list[Agent]:
        agents = self.list()
        children: dict[str, list[Agent]] = {}
        for a in agents:
            if a.parent_agent_id:
                children.setdefault(a.parent_agent_id, []).append(a)
        out, stack = [], [agent_id]
        while stack:
            for c in children.get(stack.pop(), []):
                out.append(c)
                stack.append(c.agent_id)
        return out

    def lineage(self, agent: Agent) -> list[str]:
        chain, cur, seen = [agent.agent_id], agent, set()
        while cur.parent_agent_id and cur.parent_agent_id not in seen:
            seen.add(cur.agent_id)
            cur = self.get(cur.parent_agent_id)
            chain.append(cur.agent_id)
        return list(reversed(chain))

    # ---- writes ------------------------------------------------------------
    def save(self, agent: Agent) -> Agent:
        agent.updated_at = now()
        self.p.repo.put(AGENTS, agent.agent_id, agent.to_dict())
        return agent

    def mutate(self, agent_id: str, fn) -> Agent:
        def _f(d):
            a = Agent.from_dict(d)
            fn(a)
            a.updated_at = now()
            return a.to_dict()
        try:
            return Agent.from_dict(self.p.repo.update(AGENTS, agent_id, _f))
        except KeyError:
            raise NotFound(f"agent {agent_id!r} not registered") from None

    def check_admission(self, tier: str, capabilities: list[str]) -> None:
        if tier not in self.policy.sandbox_tiers:
            raise InvalidRequest(f"unknown sandbox tier {tier!r}", allowed=self.policy.sandbox_tiers)
        for cap in capabilities:
            need = CAPABILITY_MIN_TIER.get(cap)
            if need and TIER_ORDER.get(tier, -1) < TIER_ORDER[need]:
                raise InvalidRequest(f"capability {cap!r} requires sandbox tier >= {need!r}, got {tier!r}")

    def register(self, spec: dict[str, Any], actor: Principal, *, parent: Agent | None = None,
                 depth: int = 0, audit_action: str = "agent.registered") -> dict[str, Any]:
        agent_id = str(spec.get("agent_id", "")).strip()
        team = str(spec.get("team", "")).strip()
        if not AGENT_ID_RE.match(agent_id):
            raise InvalidRequest("agent_id must match ^[a-z0-9][a-z0-9._-]{1,94}$")
        if not team:
            raise InvalidRequest("team is required")
        if not (actor.has_role("operator") or actor.owns_team(team) and actor.has_role("owner")
                or parent is not None):
            raise Forbidden(f"{actor.subject} may not register agents for team {team!r}")
        if self.find(agent_id):
            raise Conflict(f"agent {agent_id!r} already registered")
        # one IdP subject resolves to exactly one agent: a second claim would let by_subject() pick either
        for sub in spec.get("oidc_subjects") or []:
            owner = self.by_subject(sub)
            if owner is not None:
                raise Conflict(f"oidc subject {sub!r} already belongs to agent {owner.agent_id!r}")
        tier = spec.get("sandbox_tier", "container")
        caps = list(spec.get("capabilities") or [])
        self.check_admission(tier, caps)
        models = list(spec.get("models") or [])
        budget = float(spec.get("max_budget_usd", 0) or 0)
        if budget < 0:
            raise InvalidRequest("max_budget_usd must be >= 0")

        agent = Agent(
            agent_id=agent_id, owner=str(spec.get("owner") or actor.subject), team=team,
            display_name=spec.get("display_name", ""), max_budget_usd=budget,
            budget_duration=spec.get("budget_duration", "30d"), models=models,
            workload_labels=dict(spec.get("workload_labels") or {AGENT_LABEL: agent_id}),
            oidc_subjects=list(spec.get("oidc_subjects") or []), sandbox_tier=tier, capabilities=caps,
            labels=dict(spec.get("labels") or {}),
            parent_agent_id=parent.agent_id if parent else None,
            root_agent_id=(parent.root_agent_id if parent else agent_id), delegation_depth=depth,
        )
        # Other credentials (tool / DB / MCP). A value, if given, goes to the SecretStore, never the register.
        for c in spec.get("credentials") or []:
            ref = c.get("ref") or f"creds/{agent_id}/{c['kind']}"
            if c.get("value"):
                self.p.secrets.put(ref, c["value"], {"agent_id": agent_id, "kind": c["kind"]})
            agent.credentials.append(CredentialRef(kind=c["kind"], ref=ref, description=c.get("description", "")))

        raw_key = None
        # Link keys that already exist at the gateway (e.g. provisioned by scripts/bootstrap.sh).
        for alias in spec.get("link_key_aliases") or []:
            found = self.p.gateway.find_keys(alias=alias)
            if not found:
                raise InvalidRequest(f"no gateway key with alias {alias!r}")
            for k in found:
                agent.gateway_keys.append(GatewayKeyRef(key_hash=k.key_hash, alias=k.alias))
        if spec.get("provision_key", True) and not spec.get("link_key_aliases"):
            issued = self.provision_key(agent)
            raw_key = issued.raw_key

        self.save(agent)
        token = None
        if self.delegation is not None and parent is None:
            token = self.delegation.issue_root(agent)
        self.p.audit.append(actor.subject, audit_action, agent_id, {
            "team": team, "owner": agent.owner, "budget_usd": budget, "models": models,
            "keys": [k.key_hash[:12] for k in agent.gateway_keys], "sandbox_tier": tier,
            "capabilities": caps, "credentials": [c.ref for c in agent.credentials],
            "oidc_subjects": agent.oidc_subjects, "parent": agent.parent_agent_id})
        return {"agent": agent, "gateway_key": raw_key, "delegation_token": token}

    def provision_key(self, agent: Agent, blocked: bool = False):
        alias = agent.agent_id if not agent.gateway_keys else f"{agent.agent_id}-{len(agent.gateway_keys) + 1}"
        issued = self.p.gateway.create_key(
            alias=alias, team=agent.team, models=agent.models, max_budget_usd=agent.max_budget_usd,
            metadata={"agent_id": agent.agent_id, "team": agent.team, "root_agent_id": agent.root_agent_id,
                      "parent_agent_id": agent.parent_agent_id, "governed_by": "govcp",
                      # lets the emergency stop find non-default-labelled workloads without the register
                      "workload_labels": dict(agent.workload_labels)},
            blocked=blocked, budget_duration=agent.budget_duration)
        path = key_secret_path(agent.agent_id, alias)
        self.p.secrets.put(path, issued.raw_key, {"agent_id": agent.agent_id, "key_hash": issued.key_hash})
        agent.gateway_keys.append(GatewayKeyRef(key_hash=issued.key_hash, alias=alias, secret_path=path))
        return issued

    def rotate_secrets(self, agent_id: str, actor: str, reason: str) -> dict[str, Any]:
        """T8 host-compromise drill: re-issue every secret an agent holds. A new gateway key is minted (blocked
        while the agent is not meant to run), every old key is deleted at the gateway (blocked if the delete
        fails) and its stored value revoked, and every tool/DB credential gets a fresh random value. Returns the
        new raw key once, like registration. Audited as `secrets.rotated` (hash prefixes only, never values)."""
        import secrets as _secrets
        agent = self.get(agent_id)
        old = list(agent.gateway_keys)
        out: dict[str, Any] = {"agent_id": agent_id, "old_keys": [], "credentials": []}

        def _mint(a: Agent):
            out["_issued"] = self.provision_key(a, blocked=a.desired_state != "running")
        agent = self.mutate(agent_id, _mint)
        issued = out.pop("_issued")
        for k in old:
            try:
                self.p.gateway.delete_key(k.key_hash)
                how = "deleted"
            except Exception as e:  # noqa: BLE001 - a key that cannot be deleted must at least be blocked
                try:
                    self.p.gateway.block_key(k.key_hash)
                    how = f"blocked (delete failed: {type(e).__name__})"
                except Exception as e2:  # noqa: BLE001
                    how = f"FAILED: {type(e2).__name__}"
            if k.secret_path:
                self.p.secrets.revoke(k.secret_path)
            out["old_keys"].append({"alias": k.alias, "key_hash_prefix": k.key_hash[:12], "result": how})
        for c in agent.credentials:
            self.p.secrets.put(c.ref, "rot-" + _secrets.token_urlsafe(24), {"agent_id": agent_id, "kind": c.kind,
                                                                           "rotated_by": actor})
            out["credentials"].append({"kind": c.kind, "ref": c.ref, "result": "re-issued"})

        def _drop_old(a: Agent):
            gone = {k.key_hash for k in old}
            a.gateway_keys = [k for k in a.gateway_keys if k.key_hash not in gone]
        self.mutate(agent_id, _drop_old)
        out["new_key"] = {"alias": issued.alias, "key_hash_prefix": issued.key_hash[:12]}
        # complete = every old key is dead at the gateway (deleted, or at least blocked). A key that could be
        # neither deleted nor blocked is still LIVE: the caller must not read that as success (API: HTTP 502).
        out["complete"] = not any(k["result"].startswith("FAILED") for k in out["old_keys"])
        self.p.audit.append(actor, "secrets.rotated" if out["complete"] else "secrets.rotation_incomplete",
                            agent_id, {"reason": reason, **out}, severity="info" if out["complete"] else "alert")
        return {**out, "gateway_key": issued.raw_key, "key_hash": issued.key_hash}

    def raw_key(self, agent: Agent) -> str | None:
        for k in agent.gateway_keys:
            if k.secret_path:
                s = self.p.secrets.get(k.secret_path)
                if s and not s.revoked and s.value:
                    return s.value
        return None

    def workload_labels_for(self, agent: Agent) -> dict[str, str]:
        return dict(agent.workload_labels)


def default_container_labels(agent: Agent) -> dict[str, str]:
    """Labels an agent's containers should carry so the Orchestrator can find them."""
    return {AGENT_LABEL: agent.agent_id, TEAM_LABEL: agent.team, ROOT_AGENT_LABEL: agent.root_agent_id or agent.agent_id}
