"""Delegation attenuation (report section 5, "runaway delegation").

Every agent gets a root capability token at registration. A sub-agent credential
can only be minted by presenting the parent's token and asking for a scope that
is a subset of the parent's effective scope (budget, model subset, depth cap,
expiry). Anything broader is denied and raised as an alert. The child's token is
the parent's token with extra caveats appended, so it can never be wider than the
parent, and its gateway key is created with the narrower budget and models.
"""
from __future__ import annotations

import re
import secrets as pysecrets
import time
import uuid
from typing import Any

from . import macaroon
from .context import Ports
from .errors import Conflict, DelegationDenied, Forbidden, InvalidRequest
from .models import DESIRED_RUNNING, STATUS_ACTIVE, Agent, DiscoveryObservation, Principal
from .policy import Policy
from .register import RegisterService
from .repository import DELEGATIONS

ROOT_KEY_PATH = "delegation/root-key"
CHILD_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,30}$")


def token_secret_path(agent_id: str) -> str:
    return f"delegation/{agent_id}/token"


class DelegationService:
    def __init__(self, ports: Ports, policy: Policy, register: RegisterService):
        self.p = ports
        self.policy = policy
        self.register = register

    def _root_key(self) -> bytes:
        s = self.p.secrets.get(ROOT_KEY_PATH)
        if s is None or not s.value:
            self.p.secrets.put(ROOT_KEY_PATH, pysecrets.token_hex(32), {"purpose": "delegation macaroon root key"})
            s = self.p.secrets.get(ROOT_KEY_PATH)
        return bytes.fromhex(s.value)

    def issue_root(self, agent: Agent) -> str:
        caveats = [f"agent = {agent.agent_id}", f"budget_usd <= {agent.max_budget_usd}",
                   f"models in {','.join(agent.models)}", f"max_depth <= {self.policy.delegation.max_depth}"]
        tok = macaroon.mint(self._root_key(), f"{agent.agent_id}:{uuid.uuid4().hex[:12]}", caveats)
        self.p.secrets.put(token_secret_path(agent.agent_id), tok, {"agent_id": agent.agent_id})
        return tok

    def _alert(self, action: str, target: str, details: dict[str, Any]) -> None:
        self.p.audit.append("delegation-guard", action, target, details, severity="alert")

    def verify_holder(self, token: str, purpose: str) -> tuple[macaroon.Scope, Agent]:
        try:
            scope = macaroon.verify(self._root_key(), token)
        except macaroon.InvalidToken as e:
            self._alert("delegation.invalid_token", "unknown", {"purpose": purpose, "error": str(e),
                                                                "token_prefix": token[:24]})
            raise DelegationDenied(f"invalid delegation token: {e}") from None
        holder = self.register.find(scope.holder)
        problems = []
        if holder is None:
            problems.append(f"holder {scope.holder!r} is not registered")
        else:
            lineage = self.register.lineage(holder)
            if lineage != scope.chain:
                problems.append(f"token chain {scope.chain} does not match registered lineage {lineage}")
            for aid in lineage:
                a = self.register.find(aid)
                # desired_state flips to stopped at the very start of a stop, status only at its end:
                # checking both closes the window in which a stop in progress could still mint or use tokens
                if a is None or a.status != STATUS_ACTIVE or a.desired_state != DESIRED_RUNNING:
                    problems.append(f"{aid} in the chain is not active")
        if problems:
            self._alert("delegation.chain_rejected", scope.holder, {"purpose": purpose, "problems": problems,
                                                                     "chain": scope.chain})
            raise DelegationDenied("; ".join(problems))
        return scope, holder

    def _allocated(self, parent_id: str) -> float:
        return sum(float(a.max_budget_usd) for a in self.register.list()
                   if a.parent_agent_id == parent_id and a.status == STATUS_ACTIVE)

    def mint_child(self, token: str, request: dict[str, Any]) -> dict[str, Any]:
        scope, parent = self.verify_holder(token, "mint")
        name = str(request.get("name", "")).strip()
        if not CHILD_NAME_RE.match(name):
            raise InvalidRequest("name must match ^[a-z0-9][a-z0-9_-]{0,30}$")
        budget = float(request.get("max_budget_usd", 0))
        models = list(request.get("models") or [])
        if request.get("ttl_s"):
            ttl = float(request["ttl_s"])
            expires = time.time() + ttl
        else:  # default lifetime, never beyond the parent's
            ttl = self.policy.delegation.default_ttl_s
            expires = min(time.time() + ttl, scope.expires)
        remaining = scope.budget_usd - self._allocated(parent.agent_id)
        reasons = []
        if scope.depth + 1 > scope.max_depth:
            reasons.append(f"delegation depth {scope.depth + 1} exceeds cap {scope.max_depth}")
        if budget <= 0:
            reasons.append("budget must be > 0")
        if budget > remaining + 1e-9:
            reasons.append(f"budget {budget} exceeds parent's remaining delegable budget {round(remaining, 6)}")
        if not models:
            reasons.append("models must be a non-empty subset of the parent's models")
        outside = sorted(set(models) - (scope.models or set()))
        if outside:
            reasons.append(f"models {outside} are outside the parent's scope {sorted(scope.models or [])}")
        if expires > scope.expires:
            reasons.append("requested lifetime outlives the parent token")
        if reasons:
            self._alert("delegation.broadening_denied", parent.agent_id, {
                "requested": {"name": name, "max_budget_usd": budget, "models": models, "ttl_s": ttl},
                "parent_scope": scope.to_dict(), "remaining_budget_usd": round(remaining, 6), "reasons": reasons})
            raise DelegationDenied("delegation broader than parent scope", reasons=reasons)

        child_id = f"{parent.agent_id}.{name}"
        if self.register.find(child_id):
            raise Conflict(f"sub-agent {child_id!r} already exists")
        system = Principal(subject=f"delegation:{parent.agent_id}", roles=[], kind="client")
        res = self.register.register({
            "agent_id": child_id, "team": parent.team, "owner": parent.owner, "max_budget_usd": budget,
            "models": models, "sandbox_tier": parent.sandbox_tier,
            "capabilities": [c for c in (request.get("capabilities") or parent.capabilities)
                             if c in parent.capabilities],
            "labels": {"delegated_by": parent.agent_id},
        }, system, parent=parent, depth=scope.depth + 1, audit_action="delegation.child_registered")
        child_tok = macaroon.attenuate(token, [f"agent = {child_id}", f"budget_usd <= {budget}",
                                               f"models in {','.join(models)}", f"expires < {round(expires, 3)}"])
        self.p.secrets.put(token_secret_path(child_id), child_tok, {"agent_id": child_id})
        rec = {"delegation_id": "dg-" + uuid.uuid4().hex[:12], "parent_agent_id": parent.agent_id,
               "child_agent_id": child_id, "depth": scope.depth + 1, "max_budget_usd": budget, "models": models,
               "expires": expires, "created_at": time.time()}
        self.p.repo.put(DELEGATIONS, rec["delegation_id"], rec)
        self.p.audit.append(f"agent:{parent.agent_id}", "delegation.minted", child_id, rec)
        return {"child_agent_id": child_id, "delegation_token": child_tok, "gateway_key": res["gateway_key"],
                "scope": macaroon.verify(self._root_key(), child_tok).to_dict(), "delegation": rec}

    def authorize(self, token: str, model: str | None) -> tuple[Agent, macaroon.Scope]:
        """Used when a delegated caller uses its token (via the auth proxy). Out-of-scope use is denied + alerted."""
        scope, holder = self.verify_holder(token, "use")
        if model is not None and model not in (scope.models or set()):
            self._alert("delegation.scope_violation", holder.agent_id, {
                "model": model, "allowed": sorted(scope.models or [])})
            raise DelegationDenied(f"model {model!r} is outside this credential's scope")
        return holder, scope


class AccessService:
    """Resolve an authenticated caller to its per-agent gateway key (the OSS 'JWT -> virtual key' route)."""

    def __init__(self, ports: Ports, register: RegisterService, delegation: DelegationService, discovery):
        self.p = ports
        self.register = register
        self.delegation = delegation
        self.discovery = discovery

    def resolve_subject(self, subject: str, issuer: str | None = None) -> dict[str, Any]:
        agent = self.register.by_subject(subject)
        if agent is None:
            # first use of an unregistered identity: propose it, grant nothing
            try:
                self.discovery.submit("idp-first-use", DiscoveryObservation(
                    fingerprint=f"oidc:{subject}", kind="identity", name=subject.lower().replace("_", "-"),
                    evidence={"subject": subject, "issuer": issuer, "first_seen": time.time()}),
                    submitted_by="authproxy")
            except Exception:  # noqa: BLE001 - rate limit etc. must not turn into access
                pass
            raise Forbidden("identity is not registered to any agent; proposed for approval")
        return self._key_for(agent, via="oidc", ref=subject)

    def resolve_delegation(self, token: str, model: str | None) -> dict[str, Any]:
        agent, scope = self.delegation.authorize(token, model)
        return self._key_for(agent, via="delegation", ref=scope.holder)

    def authorize_action(self, key_hash: str, action: str, target: str | None = None,
                         caller: str = "tool-gateway") -> dict[str, Any]:
        """T8 in-window harm: a consequential side effect (external send, DB write, payment) is authorized at
        commit time by the tool gateway, against the agent's desired state in the register. The stop sequence
        persists `desired_state=stopped` as its very first step (before keys, network, workloads), so from the
        stop decision on no new side effect can be committed, even while containment is still in progress.
        The agent is identified by the hash of the gateway key it presented (the same identity the gateway uses)."""
        if not key_hash or not action:
            raise InvalidRequest("key_hash and action are required")
        # linearization point: a read that STARTS after the stop persisted desired_state sees it (read committed)
        state_read_at = time.time()
        agent = next((a for a in self.register.list() if any(k.key_hash == key_hash for k in a.gateway_keys)), None)
        details = {"action": action, "target": target, "key_hash_prefix": key_hash[:12]}
        if agent is None:
            self.p.audit.append(caller, "action.denied", "unknown", {**details, "reason": "unknown key"},
                                severity="alert")
            raise Forbidden("key is not registered to any agent")
        if agent.status != STATUS_ACTIVE or agent.desired_state != DESIRED_RUNNING:
            self.p.audit.append(caller, "action.denied", agent.agent_id,
                                {**details, "reason": f"{agent.status}/{agent.desired_state}"}, severity="alert")
            raise Forbidden(f"agent {agent.agent_id!r} is {agent.status} (desired: {agent.desired_state})")
        decision = "act-" + uuid.uuid4().hex[:12]
        self.p.audit.append(caller, "action.authorized", agent.agent_id, {**details, "decision_id": decision})
        return {"allowed": True, "agent_id": agent.agent_id, "decision_id": decision,
                "state_read_at": state_read_at, "decided_at": time.time()}

    def _key_for(self, agent: Agent, via: str, ref: str) -> dict[str, Any]:
        if agent.status != STATUS_ACTIVE or agent.desired_state != DESIRED_RUNNING:
            # a stop in progress must not be able to mint a fresh (unblocked) key at first use
            raise Forbidden(f"agent {agent.agent_id!r} is {agent.status} (desired: {agent.desired_state})")
        raw = self.register.raw_key(agent)
        if raw is None:
            # map at first use: mint the agent's own blockable key now
            def add_key(a: Agent):
                self.register.provision_key(a)
            agent = self.register.mutate(agent.agent_id, add_key)
            raw = self.register.raw_key(agent)
            self.p.audit.append("authproxy", "access.key_mapped_at_first_use", agent.agent_id, {"via": via, "ref": ref})
        return {"agent_id": agent.agent_id, "team": agent.team, "gateway_key": raw}
