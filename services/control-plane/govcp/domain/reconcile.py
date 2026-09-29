"""Desired-state reconciler: the control plane acts as the controller.

Docker has no controller that owns desired state the way a Kubernetes Deployment
does (a later `docker compose up` or `docker start` would revive a stopped
container). So the register's desired_state plus the active quarantine rules are
the source of truth, and this loop stops anything that contradicts them, and
re-blocks any key of a stopped agent that someone unblocked out of band.
"""
from __future__ import annotations

import time
from typing import Any

from .context import Ports
from .models import DESIRED_STOPPED, TEAM_LABEL, Selector
from .register import RegisterService


class Reconciler:
    def __init__(self, ports: Ports, register: RegisterService, quarantine, key_check_every: int = 10,
                 stop_grace_s: float = 1.0, keys_per_check: int = 25):
        self.p = ports
        self.register = register
        self.quarantine = quarantine
        self.key_check_every = key_check_every
        self.stop_grace_s = stop_grace_s
        self.keys_per_check = keys_per_check
        self._n = 0
        self._key_cursor = 0

    def run_once(self) -> dict[str, Any]:
        self._n += 1
        enforced, reblocked = [], []
        stopped_agents = [a for a in self.register.list() if a.desired_state == DESIRED_STOPPED]
        rules = [(r, Selector.from_dict(r["selector"])) for r in self.quarantine.active_rules()]
        targets = {}
        # one listing per tick, matched in memory (cost does not grow with the number of stopped agents)
        running = self.p.orchestrator.list_workloads(include_stopped=False) if (stopped_agents or rules) else []
        for w in running:
            for a in stopped_agents:
                if all(w.labels.get(k) == v for k, v in a.workload_labels.items()):
                    targets[w.id] = (w, f"agent:{a.agent_id}")
                    break
            if w.id in targets:
                continue
            for r, sel in rules:
                if not (sel.has_workload_predicates() or sel.team):
                    continue
                if sel.labels and any(w.labels.get(k) != v for k, v in sel.labels.items()):
                    continue
                if sel.image and not w.image.startswith(sel.image):
                    continue
                if sel.host and sel.host != w.host:
                    continue
                if sel.team and w.labels.get(TEAM_LABEL) != sel.team:
                    continue
                targets[w.id] = (w, f"rule:{r['rule_id']}")
                break
        for w, why in targets.values():
            if why.startswith("agent:") and not self._still_stopped(why[6:]):
                continue                      # resumed since the start of this tick (T8: resume/reconciler race)
            t0 = time.monotonic()
            iso = self.p.network.isolate([w])
            self.p.orchestrator.prevent_restart(w.id)
            self.p.orchestrator.stop(w.id, self.stop_grace_s)
            enforced.append(w.name)
            self.p.audit.append("reconciler", "reconciler.enforced_stop", w.name, {
                "workload_id": w.id, "why": why, "image": w.image, "controller": w.controller,
                "connections_cut": sum(r.connections_before - r.connections_after for r in iso),
                "ms": round((time.monotonic() - t0) * 1000, 1)}, severity="warning")
        if self._n % self.key_check_every == 0:
            # drift check on a rotating slice of stopped agents' keys (bounded gateway load per tick)
            pairs = [(a, k) for a in stopped_agents for k in a.gateway_keys]
            if pairs:
                start = self._key_cursor % len(pairs)
                batch = (pairs[start:] + pairs[:start])[:self.keys_per_check]
                self._key_cursor = start + len(batch)
                for a, k in batch:
                    st = self.p.gateway.key_status(k.key_hash)
                    if st is not None and not st.blocked:
                        # T8: re-read the desired state around the block. A resume that lands between this tick's
                        # snapshot and the block (it sets desired_state=running, then unblocks) used to leave the
                        # agent "running" in the register with its key blocked for good (found by the pilot sim).
                        if not self._still_stopped(a.agent_id):
                            continue
                        self.p.gateway.block_key(k.key_hash)
                        if not self._still_stopped(a.agent_id):
                            self.p.gateway.unblock_key(k.key_hash)
                            self.p.audit.append("reconciler", "reconciler.reblock_reverted", a.agent_id,
                                                {"alias": k.alias, "why": "agent resumed during the re-block"})
                            continue
                        reblocked.append(k.alias)
                        self.p.audit.append("reconciler", "reconciler.reblocked_key", a.agent_id,
                                            {"alias": k.alias}, severity="alert")
        return {"enforced": enforced, "reblocked": reblocked}

    def _still_stopped(self, agent_id: str) -> bool:
        cur = self.register.find(agent_id)
        return cur is not None and cur.desired_state == DESIRED_STOPPED
