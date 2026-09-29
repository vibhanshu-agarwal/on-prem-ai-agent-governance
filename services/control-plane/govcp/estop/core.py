"""Emergency stop: the separately authenticated kill path (report section 5, "kill-plane outage").

Deliberately independent of the main control plane: no register, no Postgres,
no IdP. It needs only the gateway admin API and the orchestrator, and finds an
agent's handles from those systems directly:
  keys       -> gateway keys whose alias or metadata.agent_id/root_agent_id names the agent
  workloads  -> containers labelled govpilot.agent_id / govpilot.root_agent_id (or govpilot.team)
It writes a hash-chained local journal; the control plane ingests it when back.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from ..domain.models import AGENT_LABEL, ROOT_AGENT_LABEL, TEAM_LABEL, Workload
from ..domain.ports import AuditSink, GatewayAdmin, NetworkQuarantine, Orchestrator


def _safe(fn, *a, **kw):
    try:
        return fn(*a, **kw), None
    except Exception as e:  # noqa: BLE001
        return None, f"{type(e).__name__}: {e}"


class EmergencyStop:
    def __init__(self, gateway: GatewayAdmin, orchestrator: Orchestrator, network: NetworkQuarantine,
                 journal: AuditSink, grace_s: float = 1.0):
        self.g = gateway
        self.o = orchestrator
        self.n = network
        self.j = journal
        self.grace_s = grace_s

    def _run(self, kind: str, target: str, operator: str, reason: str, keys: list, workloads: list[Workload]):
        t0 = time.monotonic()
        self.j.append(operator, f"estop.{kind}_requested", target, {"reason": reason}, severity="alert")
        with ThreadPoolExecutor(max_workers=8) as ex:
            blocked = list(ex.map(lambda k: (k, _safe(self.g.block_key, k.key_hash)[1]), keys))
        t_keys = time.monotonic()
        iso, iso_err = _safe(self.n.isolate, workloads)
        t_net = time.monotonic()

        def halt(w):
            _, e1 = _safe(self.o.prevent_restart, w.id)
            _, e2 = _safe(self.o.stop, w.id, self.grace_s)
            return {"name": w.name, "error": e1 or e2}
        with ThreadPoolExecutor(max_workers=8) as ex:
            halted = list(ex.map(halt, workloads))
        t_stop = time.monotonic()
        checks = []
        for k, _ in blocked:
            st, err = _safe(self.g.key_status, k.key_hash)
            checks.append({"check": "key_blocked", "target": k.alias, "ok": bool(st and st.blocked)})
        for w in workloads:
            cur, _ = _safe(self.o.get, w.id)
            checks.append({"check": "workload_down", "target": w.name,
                           "ok": cur is None or (not cur.running and cur.restart_policy in ("no", ""))})
        ok = all(c["ok"] for c in checks)
        out: dict[str, Any] = {
            "kind": kind, "target": target, "operator": operator, "reason": reason,
            "keys": [{"alias": k.alias, "key_hash": k.key_hash[:12], "error": e} for k, e in blocked],
            "workloads": halted, "network": [r.to_dict() for r in (iso or [])], "network_error": iso_err,
            "verify": {"ok": ok, "checks": checks},
            "timings_ms": {"gateway": round((t_keys - t0) * 1000, 1), "network": round((t_net - t_keys) * 1000, 1),
                           "workloads": round((t_stop - t_net) * 1000, 1),
                           "total": round((time.monotonic() - t0) * 1000, 1)}}
        self.j.append(operator, f"estop.{kind}_stopped", target, {
            "reason": reason, "keys": [k.alias for k, _ in blocked], "workloads": [w.name for w in workloads],
            "timings_ms": out["timings_ms"], "verified": ok}, severity="alert")
        return out

    def stop_agent(self, agent_id: str, operator: str, reason: str) -> dict[str, Any]:
        keys = {k.key_hash: k for k in self.g.find_keys(agent_id=agent_id)}
        wl = {w.id: w for w in self.o.list_workloads(labels={AGENT_LABEL: agent_id})}
        wl.update({w.id: w for w in self.o.list_workloads(labels={ROOT_AGENT_LABEL: agent_id})})
        return self._run("agent", agent_id, operator, reason, list(keys.values()), list(wl.values()))

    def stop_team(self, team: str, operator: str, reason: str) -> dict[str, Any]:
        keys = self.g.find_keys(team=team)
        wl = self.o.list_workloads(labels={TEAM_LABEL: team})
        return self._run("team", team, operator, reason, keys, wl)
