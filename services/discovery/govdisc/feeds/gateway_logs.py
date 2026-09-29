"""Feed (b): callers seen at the gateway that are not registered.

Two evidence streams, both read-only:
  refused calls    the gateway's access log: a caller with no key / a blocked key was refused. The source IP is
                   mapped back to a container on the governed networks. This is the "unregistered agent tried
                   to spend" case; the request already failed, nothing was spent.
  key call records the gateway's OpenTelemetry spans (OpenLIT/ClickHouse): a virtual key that made calls but
                   is not one of the register's. Registered agents are recognised by the control plane through
                   the `govpilot.agent_id` label carried from the key's metadata, so this feed never reads
                   the register or holds a gateway admin credential.
"""
from __future__ import annotations

import ipaddress
import logging
import time
from collections import defaultdict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from ..evidence import Hints, container_evidence, first_label, iso_now
from ..model import CallSummary, Observation, RefusedCall
from ..ports import AccessLogSource, CallRecordSource, ContainerSource, DiscoveryFeed
from .docker_events import container_fingerprint

log = logging.getLogger("govdisc.gateway")


@dataclass
class GatewayFeedConfig:
    governed_networks: list[str] = field(default_factory=list)
    min_refused_calls: int = 1
    hints: Hints = field(default_factory=Hints)
    ignore_agent_id_prefixes: list[str] = field(default_factory=list)
    telemetry_slack_s: float = 120.0     # spans reach ClickHouse a few seconds after the call: re-read a little history


class GatewayLogsFeed(DiscoveryFeed):
    def __init__(self, cfg: GatewayFeedConfig, containers: ContainerSource,
                 access: AccessLogSource | None = None, calls: CallRecordSource | None = None,
                 name: str = "gateway-logs", clock: Callable[[], float] = time.time,
                 seen: set[str] | None = None, lookback_s: float = 600):
        self.name = name
        self.cfg = cfg
        self.containers = containers
        self.access = access
        self.calls = calls
        self.clock = clock
        self.seen: set[str] = seen if seen is not None else set()
        self._last: float = clock() - lookback_s     # first call looks back a little: a refusal just before start counts

    def observations(self) -> Iterable[Observation]:
        now = self.clock()
        since, self._last = self._last, now
        out: list[Observation] = []
        if self.access:
            try:
                out += self._refused(self.access.refused_calls(since), now)
            except Exception as e:
                log.warning("access log source failed: %s", e)
        if self.calls:
            try:
                out += self._keys(self.calls.calls_since(since - self.cfg.telemetry_slack_s), now)
            except Exception as e:
                log.warning("call record source failed: %s", e)
        return out

    def _in_governed_range(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in ipaddress.ip_network(c) for c in self.containers.network_cidrs(self.cfg.governed_networks))
        except Exception as e:
            log.warning("cannot check %s against governed ranges: %s", ip, e)
            return False

    def _refused(self, refused: list[RefusedCall], now: float) -> list[Observation]:
        by_ip: dict[str, list[RefusedCall]] = defaultdict(list)
        for r in refused:
            by_ip[r.src_ip].append(r)
        out = []
        for ip, calls in by_ip.items():
            if len(calls) < self.cfg.min_refused_calls:
                continue
            c = self.containers.find_by_ip(ip)
            if c is not None and not (set(c.networks) & set(self.cfg.governed_networks)):
                continue                                      # not on a governed network: not our caller
            if c is None and not self._in_governed_range(ip):
                continue                                      # e.g. the host reaching the published port
            fp = container_fingerprint(c) if c else f"caller:{ip}"
            if fp in self.seen:
                continue
            self.seen.add(fp)
            ev = (container_evidence(c, self.cfg.hints, "gateway-access-log", self.cfg.governed_networks, now)
                  if c else {"source": "gateway-access-log", "first_seen": iso_now(now),
                             "note": "caller container not resolvable (already gone, or not on a governed network)"})
            ev["refused"] = {"src_ip": ip, "count": len(calls), "statuses": sorted({r.status for r in calls}),
                             "paths": sorted({r.path for r in calls})[:5],
                             "first": iso_now(min(r.ts for r in calls)), "last": iso_now(max(r.ts for r in calls)),
                             "spent_usd": 0.0, "outcome": "refused by the gateway; nothing was spent"}
            owner, _ = first_label(c.labels, self.cfg.hints.owner_label_keys) if c else (None, None)
            team, _ = first_label(c.labels, self.cfg.hints.team_label_keys) if c else (None, None)
            labels = {k: v for k, v in (c.labels if c else {}).items() if k.startswith("govpilot.")
                      and k != "govpilot.discover"}
            out.append(Observation(fingerprint=fp, kind="traffic", name=c.name if c else f"caller-{ip}",
                                   image=c.image if c else None, labels=labels, suggested_team=team,
                                   suggested_owner=owner, evidence=ev))
        return out

    def _keys(self, summaries: list[CallSummary], now: float) -> list[Observation]:
        out = []
        for s in summaries:
            if any(s.agent_id.startswith(p) for p in self.cfg.ignore_agent_id_prefixes if p and s.agent_id):
                continue
            fp = f"key:{s.key_hash[:16]}"
            if fp in self.seen:
                continue
            self.seen.add(fp)
            labels = {"govpilot.agent_id": s.agent_id} if s.agent_id else {}
            out.append(Observation(
                fingerprint=fp, kind="traffic", name=s.key_alias or f"key-{s.key_hash[:8]}", image=None,
                labels=labels, suggested_team=s.team or None, suggested_owner=s.owner or None,
                evidence={"source": "gateway-otel", "key_alias": s.key_alias, "key_hash_prefix": s.key_hash[:12],
                          "claimed_agent_id": s.agent_id or None, "team": s.team, "calls": s.calls,
                          "spend_usd": round(s.spend_usd, 6), "models": s.models,
                          "first_seen": s.first_seen, "last_seen": s.last_seen,
                          "probable_owner": {"value": s.owner, "from": "key metadata"} if s.owner else None,
                          "note": "a gateway key that is making calls but is not in the agent register"}))
        return out
