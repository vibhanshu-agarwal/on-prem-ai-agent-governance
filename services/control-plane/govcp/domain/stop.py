"""The stop sequence (report section 2), for one agent or many.

Order, each phase across all selected agents in parallel:
  0. record desired state = stopped (so the reconciler enforces it even if we crash midway)
  1. gateway   block every key tied to the agent (registered + any key whose metadata names it)
  2. network   tear down established connections, detach from governed networks
  3. desired   change desired state on the platform (restart policy off), then stop instances
  4. creds     revoke tool/DB/MCP credentials; disable the agent's IdP subjects (no new tokens)
  5. verify    keys blocked and refused, workloads down and not restarting, creds revoked
A step failing never aborts the later steps; it is reported and fails verification.
"""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from .context import Ports
from .models import (DESIRED_RUNNING, DESIRED_STOPPED, STATUS_ACTIVE, STATUS_QUARANTINED, STATUS_STOPPED, Agent,
                     Workload)
from .policy import Policy
from .register import RegisterService
from .repository import STOP_REPORTS

POOL_SIZE = 16


def _pmap(fn: Callable, items: list) -> list:
    if not items:
        return []
    if len(items) == 1:
        return [fn(items[0])]
    with ThreadPoolExecutor(max_workers=min(POOL_SIZE, len(items))) as ex:
        return list(ex.map(fn, items))


def _safe(fn: Callable, *a, **kw) -> tuple[Any, str | None]:
    try:
        return fn(*a, **kw), None
    except Exception as e:  # noqa: BLE001 - a stop keeps going; errors are reported
        return None, f"{type(e).__name__}: {e}"


class StopService:
    def __init__(self, ports: Ports, policy: Policy, register: RegisterService):
        self.p = ports
        self.policy = policy
        self.register = register

    # ------------------------------------------------------------------ stop
    def stop(self, agent_ids: list[str], actor: str, reason: str, *, extra_workloads: list[Workload] | None = None,
             status: str = STATUS_STOPPED, context: dict[str, Any] | None = None) -> dict[str, Any]:
        t0 = time.monotonic()
        wall0 = time.time()
        stop_id = "stop-" + uuid.uuid4().hex[:12]
        agents: dict[str, Agent] = {}
        for aid in agent_ids:
            a = self.register.get(aid)
            agents[a.agent_id] = a
            if self.policy.stop.cascade_to_delegates:
                for d in self.register.descendants(a.agent_id):
                    agents.setdefault(d.agent_id, d)
        ids = sorted(agents)
        mark: dict[str, float] = {}

        def phase_done(name):
            mark[name] = time.monotonic()

        # 0. desired state first (persisted), so the reconciler backs us up from here on
        for aid in ids:
            self.register.mutate(aid, lambda a: (setattr(a, "desired_state", DESIRED_STOPPED)))
        self.p.audit.append(actor, "stop.started", ",".join(ids), {
            "stop_id": stop_id, "reason": reason, "agents": ids,
            "extra_workloads": [w.name for w in (extra_workloads or [])], **(context or {})}, severity="warning")

        # 1. gateway: block keys
        key_refs: list[tuple[str, str, str | None]] = []  # (agent_id, key_hash, alias)
        for a in agents.values():
            for k in a.gateway_keys:
                key_refs.append((a.agent_id, k.key_hash, k.alias))

        def stray_keys(a: Agent):
            found, err = _safe(self.p.gateway.find_keys, agent_id=a.agent_id)
            return [(a.agent_id, k.key_hash, k.alias) for k in (found or [])], err

        known = {h for _, h, _ in key_refs}

        def block(ref):
            _, err = _safe(self.p.gateway.block_key, ref[1])
            return {"agent_id": ref[0], "key_hash": ref[1], "alias": ref[2], "blocked": err is None, "error": err}

        gw_results = _pmap(block, key_refs)
        t_first_block = time.monotonic()
        # keys minted outside the register but tagged with the agent (defence against drift)
        strays, stray_errors = [], []
        for found, err in _pmap(stray_keys, list(agents.values())):
            if err:
                stray_errors.append(err)
            strays.extend(r for r in found if r[1] not in known)
        gw_results += _pmap(block, strays)
        phase_done("gateway")

        # 2. network: tear down live connections, detach from governed networks
        workloads: dict[str, Workload] = {}
        wl_errors = []
        for a in agents.values():
            found, err = _safe(self.p.orchestrator.list_workloads, labels=a.workload_labels)
            if err:
                wl_errors.append({"agent_id": a.agent_id, "error": err})
            for w in found or []:
                workloads[w.id] = w
        for w in extra_workloads or []:
            workloads.setdefault(w.id, w)
        wl_list = list(workloads.values())
        iso, iso_err = _safe(self.p.network.isolate, wl_list)
        iso = iso or []
        phase_done("network")

        # 3. desired state on the platform, then stop instances
        def halt(w: Workload):
            prev, e1 = _safe(self.p.orchestrator.prevent_restart, w.id)
            _, e2 = _safe(self.p.orchestrator.stop, w.id, self.policy.stop.stop_grace_s)
            return {"workload_id": w.id, "name": w.name, "agent_id": w.agent_id, "controller": w.controller,
                    "previous_restart_policy": prev, "stopped": e2 is None, "error": e1 or e2}

        halted = _pmap(halt, wl_list)
        phase_done("desired_state")

        # remember what to restore on resume
        iso_by_id = {r.workload_id: r for r in iso}
        for aid in ids:
            state = {}
            for h in halted:
                if h["agent_id"] == aid:
                    r = iso_by_id.get(h["workload_id"])
                    state[h["workload_id"]] = {
                        "name": h["name"], "restart_policy": h["previous_restart_policy"] or "no",
                        "networks": r.networks_removed if r else [],
                        "aliases": r.network_aliases if r else {}}
            if state:
                self.register.mutate(aid, lambda a, s=state: a.quarantine_state.update(s))

        # 4. revoke everything else
        cred_results = []
        for a in agents.values():
            for c in a.credentials:
                rv = self.p.revoker_for(c.kind)
                if rv is None:
                    cred_results.append({"agent_id": a.agent_id, "kind": c.kind, "ref": c.ref, "revoked": False,
                                         "error": "no revoker for kind"})
                    continue
                res, err = _safe(rv.revoke, c)
                cred_results.append({"agent_id": a.agent_id, "kind": c.kind, "ref": c.ref,
                                     "revoked": bool(res and res.revoked), "method": res.method if res else None,
                                     "error": err})
            if self.policy.stop.disable_idp_subjects:
                for sub in a.oidc_subjects:
                    _, err = _safe(self.p.identity.disable_subject, sub)
                    cred_results.append({"agent_id": a.agent_id, "kind": "oidc_subject", "ref": sub,
                                         "revoked": err is None, "method": "idp.disable_subject", "error": err})
        phase_done("credentials")

        # 5. verify
        verify = self.verify(list(agents.values()), wl_list)
        phase_done("verify")

        for aid in ids:
            self.register.mutate(aid, lambda a: setattr(a, "status", status))

        order = ["gateway", "network", "desired_state", "credentials", "verify"]
        timings, prev = {}, t0
        for name in order:
            timings[name] = round((mark[name] - prev) * 1000, 1)
            prev = mark[name]
        timings["time_to_first_key_block"] = round((t_first_block - t0) * 1000, 1)
        timings["time_to_contained"] = round((mark["credentials"] - t0) * 1000, 1)
        timings["total"] = round((mark["verify"] - t0) * 1000, 1)
        phase_end_wall = {k: round(wall0 + (mark[k] - t0), 3) for k in order}
        report = {
            "stop_id": stop_id, "actor": actor, "reason": reason, "agents": ids, "status": status,
            "started_at": round(wall0, 3), "phase_end_wall": phase_end_wall, "timings_ms": timings,
            "target_s": self.policy.stop.target_s,
            "within_target": timings["total"] / 1000.0 <= self.policy.stop.target_s,
            "gateway": {"keys": gw_results, "errors": stray_errors},
            "network": {"results": [r.to_dict() for r in iso], "error": iso_err, "workload_errors": wl_errors},
            "workloads": halted, "credentials": cred_results, "verify": verify, "context": context or {},
        }
        self.p.repo.put(STOP_REPORTS, stop_id, report)
        self.p.audit.append(actor, "stop.completed", ",".join(ids), {
            "stop_id": stop_id, "timings_ms": timings, "verified": verify["ok"],
            "keys_blocked": sum(1 for g in gw_results if g["blocked"]), "workloads_stopped":
            sum(1 for h in halted if h["stopped"]),
            "connections_cut": sum(r.connections_before - r.connections_after for r in iso),
            "credentials_revoked": sum(1 for c in cred_results if c["revoked"])},
            severity="info" if verify["ok"] else "alert")
        return report

    # ---------------------------------------------------------------- verify
    def verify(self, agents: list[Agent], workloads: list[Workload]) -> dict[str, Any]:
        checks: list[dict[str, Any]] = []

        def add(kind, target, ok, detail=""):
            checks.append({"check": kind, "target": target, "ok": bool(ok), "detail": detail})

        def check_key(pair):
            a, k = pair
            st, err = _safe(self.p.gateway.key_status, k.key_hash)
            out = [("gateway.key_blocked", k.alias or k.key_hash[:12], bool(st and st.blocked), err or "")]
            if k.secret_path:
                sec = self.p.secrets.get(k.secret_path)
                if sec and sec.value:
                    accepted, err = _safe(self.p.gateway.probe, sec.value)
                    out.append(("gateway.request_refused", k.alias or k.key_hash[:12], accepted is False,
                                err or ("accepted!" if accepted else "401 from gateway")))
            return out

        for rows in _pmap(check_key, [(a, k) for a in agents for k in a.gateway_keys]):
            for r in rows:
                add(*r)

        def check_wl(w: Workload):
            cur, err = _safe(self.p.orchestrator.get, w.id)
            isolated, err2 = _safe(self.p.network.is_isolated, w.id)
            return w, cur, err, isolated, err2

        for w, cur, err, isolated, err2 in _pmap(check_wl, workloads):
            if cur is None and err is None:
                add("workload.gone", w.name, True, "removed")
                continue
            add("workload.not_running", w.name, cur is not None and not cur.running, err or "")
            add("workload.no_restart", w.name, cur is not None and cur.restart_policy in ("no", "", None),
                cur.restart_policy if cur else err)
            add("network.isolated", w.name, bool(isolated), err2 or "")

        for a in agents:
            for c in a.credentials:
                rv = self.p.revoker_for(c.kind)
                revoked, err = _safe(rv.is_revoked, c) if rv else (False, "no revoker")
                add("credential.revoked", c.ref, bool(revoked), err or "")
            if self.policy.stop.disable_idp_subjects:
                for sub in a.oidc_subjects:
                    enabled, err = _safe(self.p.identity.subject_enabled, sub)
                    add("idp.subject_disabled", sub, enabled is False, err or "")

        # nothing comes back: wait, then re-check the workloads
        if workloads and self.policy.stop.verify_settle_s > 0:
            time.sleep(self.policy.stop.verify_settle_s)
            for w, cur, err, _, _ in _pmap(check_wl, workloads):
                add("workload.stayed_down", w.name, cur is None or not cur.running, err or "")
        return {"ok": all(c["ok"] for c in checks), "checks": checks,
                "failed": [c for c in checks if not c["ok"]]}

    # ---------------------------------------------------------------- resume
    def resume(self, agent_id: str, actor: str, reason: str) -> dict[str, Any]:
        """Reverse a quarantine: unblock keys, reattach networks, restore restart policy, start.

        Revoked credentials stay revoked (they must be re-issued by the owner)."""
        a = self.register.get(agent_id)
        self.register.mutate(agent_id, lambda x: (setattr(x, "desired_state", DESIRED_RUNNING)))
        out: dict[str, Any] = {"agent_id": agent_id, "keys": [], "workloads": [], "subjects": []}
        for k in a.gateway_keys:
            _, err = _safe(self.p.gateway.unblock_key, k.key_hash)
            out["keys"].append({"alias": k.alias, "unblocked": err is None, "error": err})
        for wid, st in (a.quarantine_state or {}).items():
            _, e1 = _safe(self.p.network.restore, wid, st.get("networks", []), st.get("aliases", {}))
            _, e2 = _safe(self.p.orchestrator.restore_restart, wid, st.get("restart_policy", "no"))
            _, e3 = _safe(self.p.orchestrator.start, wid)
            out["workloads"].append({"workload_id": wid, "name": st.get("name"), "error": e1 or e2 or e3})
        for sub in a.oidc_subjects:
            _, err = _safe(self.p.identity.enable_subject, sub)
            out["subjects"].append({"subject": sub, "enabled": err is None, "error": err})

        def fin(x: Agent):
            x.status = STATUS_ACTIVE
            x.quarantine_state = {}
        self.register.mutate(agent_id, fin)
        out["credentials_note"] = "revoked credentials are not restored; the owner must re-issue them"
        self.p.audit.append(actor, "agent.resumed", agent_id, {"reason": reason, **out})
        return out


__all__ = ["StopService", "STATUS_QUARANTINED"]
