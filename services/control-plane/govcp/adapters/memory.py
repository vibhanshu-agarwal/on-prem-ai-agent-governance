"""In-memory adapters for every port.

Used by unit tests of the domain and as the reference implementation that each
contract suite is also run against (proving the suite tests the contract, not
one product's quirks).
"""
from __future__ import annotations

import copy
import hashlib
import secrets
import threading
from typing import Any, Callable, Iterable

from ..domain import audit as chain
from ..domain.errors import Unauthorized
from ..domain.models import (AuditRecord, ChainVerification, CredentialRef, DiscoveryObservation, IsolationResult,
                             IssuedKey, KeyStatus, Principal, RevocationResult, Secret, Workload)
from ..domain.ports import (AuditSink, CredentialRevoker, DiscoveryFeed, GatewayAdmin, IdentityProvider,
                            NetworkQuarantine, Orchestrator, SecretStore)
from ..domain.repository import Repository


class MemoryRepository(Repository):
    def __init__(self):
        self._d: dict[str, dict[str, dict]] = {}
        self._lock = threading.RLock()

    def get(self, collection, doc_id):
        with self._lock:
            v = self._d.get(collection, {}).get(doc_id)
            return copy.deepcopy(v)

    def put(self, collection, doc_id, data):
        with self._lock:
            self._d.setdefault(collection, {})[doc_id] = copy.deepcopy(data)

    def insert(self, collection, doc_id, data):
        with self._lock:
            c = self._d.setdefault(collection, {})
            if doc_id in c:
                return False
            c[doc_id] = copy.deepcopy(data)
            return True

    def list(self, collection):
        with self._lock:
            return [copy.deepcopy(v) for v in self._d.get(collection, {}).values()]

    def update(self, collection, doc_id, fn: Callable):
        with self._lock:
            c = self._d.setdefault(collection, {})
            if doc_id not in c:
                raise KeyError(doc_id)
            new = fn(copy.deepcopy(c[doc_id]))
            c[doc_id] = copy.deepcopy(new)
            return copy.deepcopy(new)

    def delete(self, collection, doc_id):
        with self._lock:
            self._d.get(collection, {}).pop(doc_id, None)


class MemoryGateway(GatewayAdmin):
    def __init__(self):
        self.keys: dict[str, dict[str, Any]] = {}
        self.raw: dict[str, str] = {}
        self.teams: dict[str, str] = {}
        self.calls: list[tuple[str, str]] = []

    def health(self):
        return True

    def ensure_team(self, team, max_budget_usd=None):
        return self.teams.setdefault(team, "team-" + hashlib.sha1(team.encode()).hexdigest()[:8])

    def create_key(self, alias, team, models, max_budget_usd, metadata, blocked=False, budget_duration=None):
        if any(k["alias"] == alias for k in self.keys.values()):
            raise ValueError(f"alias {alias} exists")
        raw = "sk-mem-" + secrets.token_hex(12)
        h = hashlib.sha256(raw.encode()).hexdigest()
        self.keys[h] = {"alias": alias, "blocked": blocked, "team_id": self.ensure_team(team) if team else None,
                        "team": team, "models": list(models), "max_budget": max_budget_usd, "spend": 0.0,
                        "metadata": dict(metadata)}
        self.raw[raw] = h
        self.calls.append(("create_key", h))
        return IssuedKey(key_hash=h, raw_key=raw, alias=alias)

    def block_key(self, key_hash):
        if key_hash not in self.keys:
            raise KeyError(key_hash)
        self.keys[key_hash]["blocked"] = True
        self.calls.append(("block_key", key_hash))

    def unblock_key(self, key_hash):
        self.keys[key_hash]["blocked"] = False
        self.calls.append(("unblock_key", key_hash))

    def _status(self, h):
        k = self.keys[h]
        return KeyStatus(key_hash=h, alias=k["alias"], blocked=k["blocked"], team_id=k["team_id"],
                         models=k["models"], max_budget=k["max_budget"], spend=k["spend"], metadata=k["metadata"])

    def key_status(self, key_hash):
        return self._status(key_hash) if key_hash in self.keys else None

    def find_keys(self, alias=None, team=None, agent_id=None):
        out = []
        for h, k in self.keys.items():
            if alias and k["alias"] != alias:
                continue
            if team and k["team"] != team:
                continue
            if agent_id and agent_id not in (k["metadata"].get("agent_id"), k["metadata"].get("root_agent_id")):
                continue
            out.append(self._status(h))
        return out

    def delete_key(self, key_hash):
        self.keys.pop(key_hash, None)

    def probe(self, raw_key):
        h = self.raw.get(raw_key)
        return bool(h and h in self.keys and not self.keys[h]["blocked"])


class MemoryOrchestrator(Orchestrator):
    def __init__(self, host="mem-host"):
        self.host = host
        self.w: dict[str, Workload] = {}
        self.calls: list[tuple[str, str]] = []

    def add(self, w: Workload):
        self.w[w.id] = w
        return w

    def host_name(self):
        return self.host

    def list_workloads(self, labels=None, image=None, host=None, include_stopped=True):
        out = []
        for w in self.w.values():
            if labels and any(w.labels.get(k) != v for k, v in labels.items()):
                continue
            if image and not w.image.startswith(image):
                continue
            if host and w.host != host:
                continue
            if not include_stopped and not w.running:
                continue
            out.append(copy.deepcopy(w))
        return out

    def get(self, workload_id):
        w = self.w.get(workload_id)
        return copy.deepcopy(w) if w else None

    def prevent_restart(self, workload_id):
        prev = self.w[workload_id].restart_policy
        self.w[workload_id].restart_policy = "no"
        self.calls.append(("prevent_restart", workload_id))
        return prev

    def stop(self, workload_id, grace_s=2.0):
        self.w[workload_id].running = False
        self.calls.append(("stop", workload_id))

    def restore_restart(self, workload_id, policy):
        self.w[workload_id].restart_policy = policy

    def start(self, workload_id):
        self.w[workload_id].running = True
        self.calls.append(("start", workload_id))


class MemoryNetwork(NetworkQuarantine):
    def __init__(self, orchestrator: MemoryOrchestrator, governed=("agents",)):
        self.o = orchestrator
        self.governed = set(governed)
        self.connections: dict[str, int] = {}  # workload id -> live connections at the chokepoint
        self.calls: list[tuple[str, str]] = []

    def isolate(self, workloads):
        out = []
        for w in workloads:
            cur = self.o.w[w.id]
            before = self.connections.get(w.id, 0)
            removed = [n for n in cur.networks if n in self.governed]
            cur.networks = [n for n in cur.networks if n not in self.governed]
            self.connections[w.id] = 0
            self.calls.append(("isolate", w.id))
            out.append(IsolationResult(workload_id=w.id, workload_name=w.name, method="memory",
                                       connections_before=before, connections_after=0, networks_removed=removed))
        return out

    def restore(self, workload_id, networks, aliases=None):
        cur = self.o.w[workload_id]
        cur.networks = sorted(set(cur.networks) | set(networks))

    def is_isolated(self, workload_id):
        return not (set(self.o.w[workload_id].networks) & self.governed)


class MemoryIdentity(IdentityProvider):
    """Tokens are opaque strings registered with a principal."""

    def __init__(self):
        self.tokens: dict[str, tuple[Principal, str]] = {}
        self.disabled: set[str] = set()

    def issue(self, principal: Principal, audience: str) -> str:
        if principal.subject in self.disabled:
            raise Unauthorized("subject disabled")
        t = "mem-" + secrets.token_hex(8)
        self.tokens[t] = (principal, audience)
        return t

    def verify(self, token, audience):
        if token not in self.tokens:
            raise Unauthorized("unknown token")
        p, aud = self.tokens[token]
        if aud != audience:
            raise Unauthorized("wrong audience")
        return p

    def disable_subject(self, subject):
        self.disabled.add(subject)

    def enable_subject(self, subject):
        self.disabled.discard(subject)

    def subject_enabled(self, subject):
        return subject not in self.disabled


class MemorySecretStore(SecretStore):
    def __init__(self):
        self.s: dict[str, Secret] = {}
        self._lock = threading.Lock()

    def put(self, path, value, metadata=None):
        with self._lock:
            old = self.s.get(path)
            sec = Secret(path=path, value=value, revoked=False, version=(old.version + 1) if old else 1,
                         metadata=dict(metadata or {}))
            self.s[path] = sec
            return copy.deepcopy(sec)

    def get(self, path):
        with self._lock:
            return copy.deepcopy(self.s.get(path))

    def revoke(self, path):
        with self._lock:
            sec = self.s.get(path)
            if sec is None:
                return None
            sec.value, sec.revoked, sec.version = None, True, sec.version + 1
            return copy.deepcopy(sec)

    def list(self, prefix=""):
        with self._lock:
            return sorted(p for p in self.s if p.startswith(prefix))


class MemoryRevoker(CredentialRevoker):
    def __init__(self, kinds=("db", "tool", "mcp", "queue")):
        self.kinds = set(kinds)
        self.revoked: set[str] = set()

    def supports(self, kind):
        return kind in self.kinds

    def revoke(self, cred):
        self.revoked.add(cred.ref)
        return RevocationResult(kind=cred.kind, ref=cred.ref, revoked=True, method="memory")

    def is_revoked(self, cred):
        return cred.ref in self.revoked


class MemoryAudit(AuditSink):
    def __init__(self):
        self.records: list[AuditRecord] = []
        self._lock = threading.Lock()

    def append(self, actor, action, target, details=None, severity="info"):
        with self._lock:
            rec = chain.build_record(self.records[-1] if self.records else None, actor, action, target, details,
                                     severity)
            self.records.append(rec)
            return copy.deepcopy(rec)

    def list(self, limit=100, since_seq=0, action_prefix=None, severity=None, target=None):
        out = [r for r in self.records if r.seq > since_seq
               and (not action_prefix or r.action.startswith(action_prefix))
               and (not severity or r.severity == severity) and (not target or r.target == target)]
        return copy.deepcopy(out[-limit:])

    def verify(self):
        return chain.verify_chain(self.records)


class ListFeed(DiscoveryFeed):
    """Reference DiscoveryFeed: replays a fixed list once. Shows T6 the shape of a feed."""

    def __init__(self, name: str, items: Iterable[DiscoveryObservation]):
        self.name = name
        self._items = list(items)

    def observations(self):
        items, self._items = self._items, []
        yield from items
