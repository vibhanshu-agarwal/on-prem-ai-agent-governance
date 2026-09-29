"""Feed (a): new containers on the governed networks that nobody registered.

First call = baseline of what is already running; later calls = container create/start events since
the last call. A container is a candidate when it is attached to a governed network (the networks
agents use to reach the gateway) or carries `govpilot.discover=true`, and is not part of the platform
itself (name/label ignore lists). The control plane folds candidates that are registered agents
(label `govpilot.agent_id`), so this feed does not need to read the register.
"""
from __future__ import annotations

import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from ..evidence import Hints, container_evidence, first_label, matches_any
from ..model import ContainerInfo, Observation
from ..ports import ContainerSource, DiscoveryFeed

log = logging.getLogger("govdisc.docker")

DISCOVER_LABEL = "govpilot.discover"


def container_fingerprint(c: ContainerInfo) -> str:
    return f"container:{c.name}:{c.image}"


@dataclass
class DockerFeedConfig:
    governed_networks: list[str] = field(default_factory=list)
    ignore_names: list[str] = field(default_factory=list)          # regexes
    ignore_labels: list[str] = field(default_factory=list)         # label keys whose presence excludes
    hints: Hints = field(default_factory=Hints)
    ignore_label_values: dict[str, list[str]] = field(default_factory=dict)   # e.g. compose project of the platform
    settle_s: float = 0.0        # a container must still be running this long before it is proposed (filters
                                 # health probes and test runners that live for a second; the gateway
                                 # access-log feed still catches a short-lived caller that actually calls)


def is_candidate(c: ContainerInfo, cfg: DockerFeedConfig) -> bool:
    if matches_any(c.name, cfg.ignore_names):
        return False
    if any(k in c.labels for k in cfg.ignore_labels):
        return False
    if any(c.labels.get(k) in vals for k, vals in cfg.ignore_label_values.items()):
        return False
    if c.labels.get(DISCOVER_LABEL, "").lower() == "true":
        return True
    return bool(set(c.networks) & set(cfg.governed_networks))


def to_observation(c: ContainerInfo, cfg: DockerFeedConfig, source: str, now: float) -> Observation:
    ev = container_evidence(c, cfg.hints, source, cfg.governed_networks, now)
    owner, _ = first_label(c.labels, cfg.hints.owner_label_keys)
    team, _ = first_label(c.labels, cfg.hints.team_label_keys)
    labels = {k: v for k, v in c.labels.items() if k.startswith("govpilot.") and k != DISCOVER_LABEL}
    return Observation(fingerprint=container_fingerprint(c), kind="workload", name=c.name, image=c.image,
                       labels=labels, suggested_team=team, suggested_owner=owner, evidence=ev)


class DockerEventsFeed(DiscoveryFeed):
    def __init__(self, source: ContainerSource, cfg: DockerFeedConfig, name: str = "docker-events",
                 clock: Callable[[], float] = time.time, seen: set[str] | None = None):
        self.name = name
        self.src = source
        self.cfg = cfg
        self.clock = clock
        self.seen: set[str] = seen if seen is not None else set()
        self._last: float | None = None
        self._settling: dict[str, tuple[float, str]] = {}     # fingerprint -> (first sighting, container id)

    def _emit(self, c: ContainerInfo | None, out: list[Observation], now: float):
        if c is None or not is_candidate(c, self.cfg):
            return
        fp = container_fingerprint(c)
        if fp in self.seen or fp in self._settling:
            return
        if self.cfg.settle_s > 0:
            self._settling[fp] = (now, c.id)
            return
        self._release(c, out, now)

    def _release(self, c: ContainerInfo, out: list[Observation], now: float):
        obs = to_observation(c, self.cfg, "docker-events", now)
        self.seen.add(obs.fingerprint)
        out.append(obs)

    def _settled(self, out: list[Observation], now: float):
        for fp, (t0, cid) in list(self._settling.items()):
            if now - t0 < self.cfg.settle_s:
                continue
            del self._settling[fp]
            c = self.src.inspect(cid)
            if c is not None and c.status in ("running", "") and is_candidate(c, self.cfg):
                self._release(c, out, now)             # survived the settle window
            else:
                log.info("dropped %s: gone before it settled", fp)

    def observations(self) -> Iterable[Observation]:
        now = self.clock()
        out: list[Observation] = []
        try:
            if self._last is None:
                for c in self.src.list_running():
                    self._emit(c, out, now)
            else:
                for action, cid in self.src.events(self._last, now):
                    if action in ("start", "create", "connect"):
                        self._emit(self.src.inspect(cid), out, now)
                # events can be missed across a restart of this process or the docker daemon:
                # a cheap reconcile against the running list closes that gap
                for c in self.src.list_running():
                    self._emit(c, out, now)
        except Exception as e:  # docker unreachable: try again next tick, do not crash the runner
            log.warning("docker source failed: %s", e)
            return []
        self._settled(out, now)
        self._last = now
        return out
