"""Bulk quarantine by selector: blast-radius preview, human trigger, dual control.

Flow: preview(selector) -> execute(preview_id) -> [approve x2 if fleet-wide] -> run.
At run time the selector is re-resolved; if it now matches agents the humans did
not see in the preview, the action is refused as stale (re-preview required).
An executed action leaves an active quarantine rule that the reconciler keeps
enforcing (new containers matching the selector are stopped on sight) until lifted.
"""
from __future__ import annotations

import time
import uuid
from typing import Any

from .context import Ports
from .errors import Conflict, Forbidden, InvalidRequest, NotFound, StalePreview
from .models import STATUS_ACTIVE, STATUS_QUARANTINED, TEAM_LABEL, Agent, Principal, Selector, Workload
from .policy import Policy
from .register import RegisterService
from .repository import ACTIONS, PREVIEWS, RULES
from .stop import StopService


class QuarantineService:
    def __init__(self, ports: Ports, policy: Policy, register: RegisterService, stop: StopService):
        self.p = ports
        self.policy = policy
        self.register = register
        self.stopper = stop

    # ------------------------------------------------------------ resolution
    def resolve(self, sel: Selector) -> tuple[list[Agent], list[Workload]]:
        if sel.is_empty():
            raise InvalidRequest("empty selector: give team/image/labels/host/agent_ids, or all=true for the fleet")
        everyone = self.register.list()
        registered = {a.agent_id for a in everyone}
        cands = [a for a in everyone if a.status == STATUS_ACTIVE]
        if not sel.all:
            if sel.team:
                cands = [a for a in cands if a.team == sel.team]
            if sel.agent_ids:
                cands = [a for a in cands if a.agent_id in set(sel.agent_ids)]
        unmanaged: list[Workload] = []
        if sel.has_workload_predicates():
            wl = self.p.orchestrator.list_workloads(labels=sel.labels or None, image=sel.image, host=sel.host)
            if sel.team:
                team_of = {a.agent_id: a.team for a in everyone}
                wl = [w for w in wl if w.labels.get(TEAM_LABEL) == sel.team or team_of.get(w.agent_id) == sel.team]
            owners = {w.agent_id for w in wl if w.agent_id}
            cands = [a for a in cands if a.agent_id in owners]
            unmanaged = [w for w in wl if (not w.agent_id or w.agent_id not in registered) and w.running]
        return cands, unmanaged

    def _is_fleet_wide(self, sel: Selector, agents: list[Agent]) -> bool:
        q = self.policy.quarantine
        teams = {a.team for a in agents}
        return bool(sel.all or len(agents) >= q.dual_control_min_agents or len(teams) >= q.dual_control_min_teams)

    # --------------------------------------------------------------- preview
    def preview(self, sel: Selector, actor: Principal) -> dict[str, Any]:
        if not actor.has_role("operator"):
            raise Forbidden("operator role required to preview a quarantine")
        agents, unmanaged = self.resolve(sel)
        rows, n_keys, n_wl, n_run, n_cred, n_sub = [], 0, 0, 0, 0, 0
        for a in agents:
            wl = self.p.orchestrator.list_workloads(labels=a.workload_labels)
            children = self.register.descendants(a.agent_id)
            rows.append({"agent_id": a.agent_id, "team": a.team, "owner": a.owner, "status": a.status,
                         "keys": len(a.gateway_keys), "workloads": [w.name for w in wl],
                         "running": sum(1 for w in wl if w.running), "credentials": len(a.credentials),
                         "oidc_subjects": len(a.oidc_subjects), "delegates": [c.agent_id for c in children]})
            n_keys += len(a.gateway_keys)
            n_wl += len(wl)
            n_run += sum(1 for w in wl if w.running)
            n_cred += len(a.credentials)
            n_sub += len(a.oidc_subjects)
        fleet = self._is_fleet_wide(sel, agents)
        now = time.time()
        prev = {
            "preview_id": "pv-" + uuid.uuid4().hex[:12], "selector": sel.to_dict(),
            "agent_ids": [a.agent_id for a in agents],
            "unmanaged_workloads": [{"id": w.id, "name": w.name, "image": w.image} for w in unmanaged],
            "teams": sorted({a.team for a in agents}), "agents": rows,
            "counts": {"agents": len(agents), "gateway_keys": n_keys, "workloads": n_wl, "running_workloads": n_run,
                       "unmanaged_workloads": len(unmanaged), "credentials": n_cred, "oidc_subjects": n_sub},
            "fleet_wide": fleet, "approvals_required": self.policy.quarantine.approvals_required if fleet else 0,
            "created_by": actor.subject, "created_at": now, "expires_at": now + self.policy.quarantine.preview_ttl_s,
        }
        self.p.repo.put(PREVIEWS, prev["preview_id"], prev)
        self.p.audit.append(actor.subject, "quarantine.previewed", prev["preview_id"],
                            {"selector": sel.to_dict(), "counts": prev["counts"], "fleet_wide": fleet})
        return prev

    # --------------------------------------------------------------- execute
    def execute(self, preview_id: str, actor: Principal, reason: str) -> dict[str, Any]:
        if not actor.has_role("operator"):
            raise Forbidden("operator role required")
        if actor.kind != "user":
            raise Forbidden("bulk quarantine is human-triggered: machine clients cannot execute it")
        prev = self.p.repo.get(PREVIEWS, preview_id)
        if not prev:
            raise NotFound(f"preview {preview_id!r} not found")
        if time.time() > prev["expires_at"]:
            raise Conflict("preview expired; create a new one")
        if not reason:
            raise InvalidRequest("reason is required")
        action = {
            "action_id": "qa-" + uuid.uuid4().hex[:12], "preview_id": preview_id, "selector": prev["selector"],
            "reason": reason, "requested_by": actor.subject, "requested_at": time.time(),
            "fleet_wide": prev["fleet_wide"], "approvals_required": prev["approvals_required"], "approvals": [],
            "status": "pending_approval" if prev["approvals_required"] else "executing", "report": None,
            "rule_id": None,
        }
        self.p.repo.put(ACTIONS, action["action_id"], action)
        self.p.audit.append(actor.subject, "quarantine.requested", action["action_id"], {
            "preview_id": preview_id, "reason": reason, "fleet_wide": prev["fleet_wide"],
            "approvals_required": prev["approvals_required"], "counts": prev["counts"]}, severity="warning")
        if prev["approvals_required"]:
            return action
        return self._run(action["action_id"], actor.subject)

    def approve(self, action_id: str, actor: Principal) -> dict[str, Any]:
        if not actor.has_role("approver"):
            raise Forbidden("approver role required")
        if actor.kind != "user":
            raise Forbidden("approvals must come from a human")
        fire = {"now": False}

        def fn(a):
            if a["status"] != "pending_approval":
                raise Conflict(f"action is {a['status']}, not pending approval")
            if actor.subject == a["requested_by"]:
                raise Forbidden("dual control: the requester cannot approve their own action")
            if any(x["by"] == actor.subject for x in a["approvals"]):
                raise Forbidden("dual control: approvals must come from distinct people")
            a["approvals"].append({"by": actor.subject, "at": time.time()})
            if len(a["approvals"]) >= a["approvals_required"]:
                a["status"] = "executing"
                fire["now"] = True
            return a

        try:
            action = self.p.repo.update(ACTIONS, action_id, fn)
        except KeyError:
            raise NotFound(f"action {action_id!r} not found") from None
        self.p.audit.append(actor.subject, "quarantine.approved", action_id, {
            "approvals": [x["by"] for x in action["approvals"]], "required": action["approvals_required"]})
        if fire["now"]:
            return self._run(action_id, f"dual-control:{','.join(x['by'] for x in action['approvals'])}")
        return action

    def _run(self, action_id: str, actor: str) -> dict[str, Any]:
        action = self.p.repo.get(ACTIONS, action_id)
        prev = self.p.repo.get(PREVIEWS, action["preview_id"])
        sel = Selector.from_dict(action["selector"])
        agents, unmanaged = self.resolve(sel)
        new = sorted({a.agent_id for a in agents} - set(prev["agent_ids"]))
        if new:
            self.p.repo.update(ACTIONS, action_id, lambda a: {**a, "status": "stale", "stale_new_agents": new})
            self.p.audit.append(actor, "quarantine.stale", action_id, {"new_agents": new}, severity="warning")
            raise StalePreview("selector now matches agents not shown in the preview; re-preview", new_agents=new)
        rule_id = "qr-" + uuid.uuid4().hex[:12]
        self.p.repo.put(RULES, rule_id, {"rule_id": rule_id, "action_id": action_id, "selector": sel.to_dict(),
                                         "active": True, "created_at": time.time()})
        ids = [a.agent_id for a in agents]
        report = self.stopper.stop(ids, actor, action["reason"], extra_workloads=unmanaged,
                                   status=STATUS_QUARANTINED,
                                   context={"quarantine_action": action_id, "selector": sel.to_dict()}) if (
            ids or unmanaged) else {"agents": [], "note": "nothing matched"}

        def fin(a):
            a.update(status="executed", executed_at=time.time(), rule_id=rule_id, report=report)
            return a
        out = self.p.repo.update(ACTIONS, action_id, fin)
        self.p.audit.append(actor, "quarantine.executed", action_id, {
            "agents": ids, "unmanaged": [w.name for w in unmanaged], "rule_id": rule_id,
            "timings_ms": report.get("timings_ms"), "verified": (report.get("verify") or {}).get("ok")},
            severity="warning")
        return out

    # ------------------------------------------------------------------ lift
    def lift(self, action_id: str, actor: Principal, resume_agents: bool = True) -> dict[str, Any]:
        if not actor.has_role("operator"):
            raise Forbidden("operator role required")
        action = self.p.repo.get(ACTIONS, action_id)
        if not action:
            raise NotFound(f"action {action_id!r} not found")
        if action["status"] != "executed":
            raise Conflict(f"action is {action['status']}")
        if action.get("rule_id"):
            self.p.repo.update(RULES, action["rule_id"], lambda r: {**r, "active": False, "lifted_at": time.time()})
        resumed = []
        if resume_agents:
            for aid in (action.get("report") or {}).get("agents", []):
                resumed.append(self.stopper.resume(aid, actor.subject, f"lift {action_id}"))
        out = self.p.repo.update(ACTIONS, action_id, lambda a: {**a, "status": "lifted", "lifted_by": actor.subject,
                                                                  "lifted_at": time.time()})
        self.p.audit.append(actor.subject, "quarantine.lifted", action_id, {"resumed": [r["agent_id"] for r in resumed]})
        return out

    def active_rules(self) -> list[dict[str, Any]]:
        return [r for r in self.p.repo.list(RULES) if r.get("active")]
