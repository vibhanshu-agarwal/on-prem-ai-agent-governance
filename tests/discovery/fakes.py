"""In-memory fakes for the discovery ports (no Docker, no network)."""
from __future__ import annotations

from govdisc.model import CallSummary, ContainerInfo, Observation, RefusedCall, SubmitResult
from govdisc.ports import (AccessLogSource, CallRecordSource, ContainerSource, DiscoveryFeed, ProposalSink,
                           ServiceListSource)

GOVERNED = ["govpilot_agents", "govpilot_agents_sso"]


def container(name="rogue-1", image="python:3.12-slim", nets=None, labels=None, cid=None):
    return ContainerInfo(id=cid or (name + "0" * 12), name=name, image=image, labels=labels or {},
                         networks=nets if nets is not None else {"govpilot_agents": "172.22.0.9"},
                         created="2026-09-29T10:00:00Z", started="2026-09-29T10:00:01Z", status="running")


class FakeContainers(ContainerSource):
    def __init__(self, running=None):
        self.running = {c.id: c for c in (running or [])}
        self.pending_events: list[tuple[str, str]] = []
        self.gone: dict[str, ContainerInfo] = {}

    def start(self, c: ContainerInfo, keep=True):
        self.pending_events.append(("start", c.id))
        if keep:
            self.running[c.id] = c
        else:
            self.gone[c.id] = c        # short-lived: inspect() still works only while it exists

    def list_running(self):
        return list(self.running.values())

    def events(self, since, until):
        ev, self.pending_events = self.pending_events, []
        return ev

    def inspect(self, cid):
        return self.running.get(cid)

    def find_by_ip(self, ip):
        return next((c for c in self.running.values() if ip in c.networks.values()), None)

    def find_by_name(self, name):
        return next((c for c in self.running.values() if c.name == name), None)

    def network_cidrs(self, networks):
        return ["172.22.0.0/16"]


class FakeAccess(AccessLogSource):
    def __init__(self, calls=None):
        self.calls = calls or []

    def refused_calls(self, since):
        return [c for c in self.calls if c.ts >= since]


class FakeCalls(CallRecordSource):
    def __init__(self, summaries=None):
        self.summaries = summaries or []

    def calls_since(self, since):
        return list(self.summaries)


class FakeServices(ServiceListSource):
    def __init__(self, services=None):
        self.svcs = services or []

    def services(self):
        return list(self.svcs)


class ListFeed(DiscoveryFeed):
    """Emits everything it is given, once (a noisy feed)."""

    def __init__(self, name, obs):
        self.name = name
        self._obs = list(obs)
        self.seen = set()

    def push(self, more):
        self._obs += list(more)

    def observations(self):
        out, self._obs = self._obs, []
        return out


class RecordingSink(ProposalSink):
    """Behaves like the control plane: folds duplicates, enforces a daily cap, records every call."""

    def __init__(self, server_limit=None, known_agent_ids=()):
        self.calls: list[Observation] = []
        self.created: list[Observation] = []
        self.limit = server_limit
        self.known = set(known_agent_ids)
        self.fail_next = 0
        self.rejected_fps: set[str] = set()

    def submit(self, feed, obs):
        self.calls.append(obs)
        if self.fail_next:
            self.fail_next -= 1
            return SubmitResult("error", detail="boom")
        if obs.fingerprint in self.rejected_fps:
            return SubmitResult("rejected", detail="HTTP 422")
        if obs.labels.get("govpilot.agent_id") in self.known:
            return SubmitResult("known")
        if any(o.fingerprint == obs.fingerprint for o in self.created):
            return SubmitResult("duplicate")
        if self.limit is not None and len(self.created) >= self.limit:
            return SubmitResult("rate_limited")
        self.created.append(obs)
        return SubmitResult("created", f"dp-{len(self.created)}")


def obs(i, fp=None):
    return Observation(fingerprint=fp or f"container:noisy-{i}:img", name=f"noisy-{i}", image="img",
                       evidence={"first_seen": "2026-09-29T10:00:00Z"})


def refused(ip="172.22.0.9", ts=1000.0, status=401, path="/v1/chat/completions"):
    return RefusedCall(ts, ip, "POST", path, status)


def summary(hash_="abcdef0123456789abcdef", alias="shadow-key", agent="shadow-agent", team="finance", owner="", calls=3):
    return CallSummary(hash_, alias, team, agent, owner, calls, 0.001, ["mock-local"],
                       "2026-09-29 10:00:00", "2026-09-29 10:01:00")
