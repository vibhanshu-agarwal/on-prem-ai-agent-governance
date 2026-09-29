"""Feed (c): workloads the OpenLIT Controller's eBPF scanner saw connecting to LLM endpoints.

This is the bypass detector: a container talking straight to a provider (api.openai.com, ...) without
going through the gateway. The controller runs kprobes on tcp_v4/v6_connect and reports the process,
runtime and provider; we enrich with the container's labels when the name matches a running container
and file a proposal. Only the controller's local REST API is used (GET /api/services), so this works
with the open-source OpenLIT: the OpenLIT UI's "Agents" page for the controller is an enterprise
feature (see docs/results/T6.md).
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from ..evidence import Hints, container_evidence, first_label, iso_now
from ..model import Observation
from ..ports import ContainerSource, DiscoveryFeed, ServiceListSource
from .docker_events import container_fingerprint

log = logging.getLogger("govdisc.controller")


@dataclass
class ControllerFeedConfig:
    governed_networks: list[str] = field(default_factory=list)
    ignore_names: list[str] = field(default_factory=list)
    hints: Hints = field(default_factory=Hints)


class OpenlitControllerFeed(DiscoveryFeed):
    def __init__(self, source: ServiceListSource, containers: ContainerSource | None, cfg: ControllerFeedConfig,
                 name: str = "openlit-controller", clock: Callable[[], float] = time.time,
                 seen: set[str] | None = None):
        self.name = name
        self.src = source
        self.containers = containers
        self.cfg = cfg
        self.clock = clock
        self.seen: set[str] = seen if seen is not None else set()

    def observations(self) -> Iterable[Observation]:
        now = self.clock()
        try:
            services = self.src.services()
        except Exception as e:
            log.warning("controller source failed: %s", e)
            return []
        out = []
        for s in services:
            sname = s.get("service_name") or ""
            wkey = s.get("workload_key") or sname
            if not sname:
                continue
            from ..evidence import matches_any
            if matches_any(sname, self.cfg.ignore_names):
                continue
            c = self.containers.find_by_name(sname) if self.containers else None
            fp = container_fingerprint(c) if c else f"ebpf:{wkey}"
            if fp in self.seen:
                continue
            self.seen.add(fp)
            ev = (container_evidence(c, self.cfg.hints, "openlit-controller-ebpf", self.cfg.governed_networks, now)
                  if c else {"source": "openlit-controller-ebpf", "first_seen": iso_now(now)})
            ev["ebpf"] = {"detected_by": "kprobe tcp_v4/v6_connect to a known LLM endpoint",
                          "llm_providers": s.get("llm_providers") or [], "language_runtime": s.get("language_runtime"),
                          "pid": s.get("pid"), "exe_path": s.get("exe_path"), "workload_key": wkey,
                          "controller_first_seen": s.get("first_seen"), "controller_last_seen": s.get("last_seen"),
                          "bypasses_gateway": True,
                          "note": "connected to a provider endpoint directly; the gateway was not involved"}
            owner, _ = first_label(c.labels, self.cfg.hints.owner_label_keys) if c else (None, None)
            team, _ = first_label(c.labels, self.cfg.hints.team_label_keys) if c else (None, None)
            labels = {k: v for k, v in (c.labels if c else {}).items()
                      if k.startswith("govpilot.") and k != "govpilot.discover"}
            out.append(Observation(fingerprint=fp, kind="traffic", name=sname, image=c.image if c else None,
                                   labels=labels, suggested_team=team, suggested_owner=owner, evidence=ev))
        return out
