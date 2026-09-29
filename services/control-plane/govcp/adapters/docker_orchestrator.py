"""Orchestrator + NetworkQuarantine adapters for a single Docker engine.

Kubernetes equivalents a sponsor would write instead:
  prevent_restart -> scale Deployment/StatefulSet to 0 or suspend the Job (desired state)
  stop            -> delete the pods after desired state changed
  isolate         -> deny-all NetworkPolicy (Cilium/Calico) + conntrack flush / Cilium connection kill
"""
from __future__ import annotations

import math
import re
from concurrent.futures import ThreadPoolExecutor

import docker
from docker.errors import APIError, NotFound

from ..domain.errors import AdapterError
from ..domain.models import IsolationResult, Workload
from ..domain.ports import NetworkQuarantine, Orchestrator

HELPER_LABEL = "govpilot.role"
HELPER_VALUE = "quarantine-helper"


def _client(base_url: str | None):
    return docker.DockerClient(base_url=base_url) if base_url else docker.from_env()


def to_workload(c, host: str) -> Workload:
    a = c.attrs
    labels = a.get("Config", {}).get("Labels") or {}
    nets = a.get("NetworkSettings", {}).get("Networks") or {}
    ctrl = None
    if labels.get("com.docker.compose.project"):
        ctrl = f"compose:{labels['com.docker.compose.project']}/{labels.get('com.docker.compose.service', '')}"
    return Workload(
        id=c.id, name=c.name, image=a.get("Config", {}).get("Image", ""), labels=labels, host=host,
        running=bool(a.get("State", {}).get("Running")),
        restart_policy=(a.get("HostConfig", {}).get("RestartPolicy") or {}).get("Name") or "no",
        networks=sorted(nets.keys()), ip_addresses=[n.get("IPAddress") for n in nets.values() if n.get("IPAddress")],
        started_at=a.get("State", {}).get("StartedAt"), controller=ctrl)


class DockerOrchestrator(Orchestrator):
    def __init__(self, base_url: str | None = None, host_name: str | None = None):
        self.d = _client(base_url)
        self._host = host_name

    def host_name(self):
        if not self._host:
            self._host = self.d.info().get("Name", "docker")
        return self._host

    def list_workloads(self, labels=None, image=None, host=None, include_stopped=True):
        if host and host != self.host_name():
            return []
        filters = {}
        if labels:
            filters["label"] = [f"{k}={v}" for k, v in labels.items()]
        try:
            cs = self.d.containers.list(all=include_stopped, filters=filters)
        except APIError as e:
            raise AdapterError(f"docker list failed: {e}") from None
        out = []
        for c in cs:
            w = to_workload(c, self.host_name())
            if w.labels.get(HELPER_LABEL) == HELPER_VALUE:
                continue
            if image and not (w.image == image or w.image.startswith(image + ":") or w.image.startswith(image)):
                continue
            out.append(w)
        return out

    def _c(self, wid):
        try:
            return self.d.containers.get(wid)
        except NotFound:
            return None

    def get(self, workload_id):
        c = self._c(workload_id)
        return to_workload(c, self.host_name()) if c else None

    def prevent_restart(self, workload_id):
        c = self._c(workload_id)
        if c is None:
            return "no"
        prev = (c.attrs.get("HostConfig", {}).get("RestartPolicy") or {}).get("Name") or "no"
        c.update(restart_policy={"Name": "no", "MaximumRetryCount": 0})
        return prev

    def stop(self, workload_id, grace_s=2.0):
        c = self._c(workload_id)
        if c is None:
            return
        try:
            c.stop(timeout=max(0, int(math.ceil(grace_s))))
        except APIError:
            c.reload()
            if c.attrs.get("State", {}).get("Running"):
                c.kill()

    def restore_restart(self, workload_id, policy):
        c = self._c(workload_id)
        if c is not None and policy:
            c.update(restart_policy={"Name": policy, "MaximumRetryCount": 0})

    def start(self, workload_id):
        c = self._c(workload_id)
        if c is not None:
            c.start()


# Runs inside the agent's network namespace: count its established TCP connections,
# then reset every TCP flow (incoming segments answered with RST, outgoing ones
# refused locally) and drop everything else. RSTs themselves must stay allowed out.
AGENT_NETNS_SCRIPT = r"""
n=$(ss -Htn state established | wc -l)
iptables -w -I INPUT 1 -p tcp -j REJECT --reject-with tcp-reset &&
iptables -w -I INPUT 2 ! -p tcp -j DROP &&
iptables -w -I OUTPUT 1 -p tcp ! --tcp-flags RST RST -j REJECT --reject-with tcp-reset &&
iptables -w -I OUTPUT 2 ! -p tcp -j DROP
echo "RESULT $n $?"
"""

# Runs inside a chokepoint's (gateway / auth proxy) network namespace: wait until
# no established connection from the quarantined IPs remains, or the drain timeout.
CHOKEPOINT_SCRIPT = r"""
end=$(( $(date +%s%3N) + {timeout_ms} ))
first=-1
while :; do
  n=$(ss -Htn state established | grep -cE '[[:space:]]({ips}):[0-9]+' || true)
  [ "$first" -lt 0 ] && first=$n
  [ "$n" -eq 0 ] && break
  [ "$(date +%s%3N)" -ge "$end" ] && break
  sleep 0.05
done
echo "RESULT $first $n"
"""


class DockerNetworkQuarantine(NetworkQuarantine):
    def __init__(self, governed_networks: list[str], chokepoints: list[str], helper_image: str,
                 drain_timeout_s: float = 3.0, base_url: str | None = None):
        self.d = _client(base_url)
        self.governed = list(governed_networks)
        self.chokepoints = list(chokepoints)
        self.helper_image = helper_image
        self.drain_ms = int(drain_timeout_s * 1000)

    def _helper(self, target: str, script: str, net_admin: bool) -> str:
        try:
            out = self.d.containers.run(
                self.helper_image, command=["sh", "-c", script], network_mode=f"container:{target}",
                cap_add=["NET_ADMIN"] if net_admin else None, remove=True, stdout=True, stderr=True,
                labels={HELPER_LABEL: HELPER_VALUE})
            return out.decode(errors="replace")
        except Exception as e:  # noqa: BLE001
            return f"ERROR {type(e).__name__}: {e}"

    @staticmethod
    def _parse(out: str) -> list[int] | None:
        m = re.search(r"RESULT ([\-\d]+) ([\-\d]+)", out)
        return [int(m.group(1)), int(m.group(2))] if m else None

    def _running_chokepoints(self):
        out = []
        for name in self.chokepoints:
            try:
                c = self.d.containers.get(name)
                if c.status == "running":
                    out.append(c.id)
            except NotFound:
                pass
        return out

    def isolate(self, workloads):
        results: dict[str, IsolationResult] = {}
        containers = {}
        for w in workloads:
            try:
                containers[w.id] = self.d.containers.get(w.id)
            except NotFound:
                results[w.id] = IsolationResult(w.id, w.name, "docker", details={"note": "workload gone"})
        running = [w for w in workloads if w.id in containers and containers[w.id].status == "running"]
        ips = sorted({ip for w in running for n, ip in self._ips(containers[w.id]).items() if n in self.governed})

        # 1. reset live TCP flows inside each running agent's netns (parallel)
        def cut(w):
            return w, self._helper(w.id, AGENT_NETNS_SCRIPT, net_admin=True)
        with ThreadPoolExecutor(max_workers=max(1, min(16, len(running)))) as ex:
            cut_out = list(ex.map(cut, running)) if running else []

        # 2. wait for the chokepoints to drop every connection from those IPs (parallel)
        chk_out = []
        if ips:
            script = CHOKEPOINT_SCRIPT.replace("{timeout_ms}", str(self.drain_ms)).replace(
                "{ips}", "|".join(re.escape(i) for i in ips))
            cps = self._running_chokepoints()
            with ThreadPoolExecutor(max_workers=max(1, len(cps))) as ex:
                chk_out = list(ex.map(lambda cid: (cid, self._helper(cid, script, net_admin=False)), cps))
        remaining = sum((self._parse(o) or [0, 0])[1] for _, o in chk_out)
        chk_first = sum(max((self._parse(o) or [0, 0])[0], 0) for _, o in chk_out)

        # 3. detach from the governed networks (running or not, so a restart cannot rejoin them)
        for w in workloads:
            c = containers.get(w.id)
            if c is None:
                continue
            c.reload()
            nets = c.attrs.get("NetworkSettings", {}).get("Networks") or {}
            removed, aliases = [], {}
            for n, cfg in nets.items():
                if n not in self.governed:
                    continue
                aliases[n] = [a for a in (cfg.get("Aliases") or []) if a != c.id[:12]]
                try:
                    self.d.networks.get(n).disconnect(c, force=True)
                    removed.append(n)
                except (APIError, NotFound):
                    pass
            out = next((o for x, o in cut_out if x.id == w.id), None)
            parsed = self._parse(out) if out else None
            results[w.id] = IsolationResult(
                workload_id=w.id, workload_name=w.name, method="docker:netns-iptables-rst+network-disconnect",
                connections_before=(parsed[0] if parsed else 0), connections_after=0,
                networks_removed=removed, network_aliases=aliases,
                details={"agent_netns": (out or "").strip()[-200:], "rules_applied": bool(parsed and parsed[1] == 0)
                         if out else False})
        # attribute chokepoint leftovers to the batch (per-IP attribution is not needed for the verdict)
        if running:
            first = results[running[0].id]
            first.connections_after = remaining
            first.details["chokepoints"] = {cid[:12]: (self._parse(o) or o) for cid, o in chk_out}
            first.details["chokepoint_connections_at_start"] = chk_first
        for r in results.values():
            r.ok = bool(r.details.get("rules_applied", True)) or r.details.get("note") == "workload gone"
        return [results[w.id] for w in workloads if w.id in results]

    @staticmethod
    def _ips(c) -> dict[str, str]:
        nets = c.attrs.get("NetworkSettings", {}).get("Networks") or {}
        return {n: v.get("IPAddress") for n, v in nets.items() if v.get("IPAddress")}

    def restore(self, workload_id, networks, aliases=None):
        c = self.d.containers.get(workload_id)
        c.reload()
        have = set((c.attrs.get("NetworkSettings", {}).get("Networks") or {}).keys())
        for n in networks:
            if n not in have:
                self.d.networks.get(n).connect(c, aliases=(aliases or {}).get(n) or None)

    def is_isolated(self, workload_id):
        try:
            c = self.d.containers.get(workload_id)
        except NotFound:
            return True
        nets = set((c.attrs.get("NetworkSettings", {}).get("Networks") or {}).keys())
        return not (nets & set(self.governed))
