"""Small stateful ports with file adapters: audit sink, override store, approval store.

Adapters are deliberately simple (a directory of JSON files + an append-only JSONL log) so
the gateway process and the `guardctl` CLI share state without a database. A sponsor swaps
them for Postgres / a ticketing system / a SIEM by implementing the same small Protocols.
Audit events never contain prompt text, PII values or secrets: only rule ids, entity types,
counts, hashes and identifiers.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import time
from pathlib import Path
from typing import Any, Callable, Protocol

log = logging.getLogger("govpilot.guardrails")

OVERRIDABLE = re.compile(r"^(pii(\.[A-Z_]+)?|injection|secrets|tool\.[A-Za-z0-9_.:-]+)$")
DEFAULT_MAX_OVERRIDE_TTL = 24 * 3600
MIN_REASON_CHARS = 10


class AuditSink(Protocol):
    def emit(self, event: str, **fields: Any) -> None: ...


class LogAuditSink:
    def emit(self, event: str, **fields: Any) -> None:
        log.info("audit %s", json.dumps({"event": event, **fields}, default=str, sort_keys=True))


class JsonlAuditSink:
    """Append-only JSONL file (O_APPEND: safe for concurrent writers of small records)."""

    def __init__(self, path: str | os.PathLike, clock: Callable[[], float] = time.time, also_log: bool = True):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.clock = clock
        self.also_log = also_log

    def emit(self, event: str, **fields: Any) -> None:
        rec = {"ts": round(self.clock(), 3), "event": event, **fields}
        line = json.dumps(rec, default=str, sort_keys=True, separators=(",", ":")) + "\n"
        try:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)
        except OSError:
            log.exception("audit write failed")  # audit failure must be loud, never silent
        if self.also_log:
            log.info("audit %s", line.strip())


class MemoryAuditSink:
    def __init__(self):
        self.events: list[dict] = []

    def emit(self, event: str, **fields: Any) -> None:
        self.events.append({"event": event, **fields})

    def of(self, event: str) -> list[dict]:
        return [e for e in self.events if e["event"] == event]


class OverrideError(ValueError):
    pass


def _atomic_write(path: Path, obj: dict) -> None:
    tmp = path.with_suffix(path.suffix + f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(obj, sort_keys=True, indent=1), encoding="utf-8")
    os.replace(tmp, path)


class FileOverrideStore:
    """Audited, time-limited, per-agent false-positive overrides.

    An override names ONE rule id for ONE agent: `pii` (all PII entities), `pii.<ENTITY>`,
    `injection`, `secrets`, or `tool.<name>`. It needs a reason and an approver, has a hard
    TTL (capped at `max_ttl_seconds`), can be revoked, and every grant/use/revoke is audited.
    Consequential-action approval is NOT overridable (it has its own single-use flow).
    """

    def __init__(self, directory: str | os.PathLike, audit: AuditSink, max_ttl_seconds: int = DEFAULT_MAX_OVERRIDE_TTL,
                 clock: Callable[[], float] = time.time, cache_seconds: float = 1.0):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.audit, self.max_ttl, self.clock, self.cache_seconds = audit, max_ttl_seconds, clock, cache_seconds
        self._cache: tuple[float, list[dict]] | None = None

    def grant(self, agent_id: str, rule: str, ttl_seconds: int, reason: str, granted_by: str) -> dict:
        if not agent_id:
            raise OverrideError("agent_id required")
        if not OVERRIDABLE.match(rule or ""):
            raise OverrideError(f"rule {rule!r} is not overridable (allowed: pii, pii.<ENTITY>, injection, "
                                "secrets, tool.<name>; approval gates cannot be overridden)")
        if not isinstance(ttl_seconds, (int, float)) or ttl_seconds <= 0:
            raise OverrideError("ttl_seconds must be > 0")
        if ttl_seconds > self.max_ttl:
            raise OverrideError(f"ttl_seconds {ttl_seconds} exceeds the maximum {self.max_ttl}")
        if len((reason or "").strip()) < MIN_REASON_CHARS:
            raise OverrideError(f"a reason of at least {MIN_REASON_CHARS} characters is required")
        if not (granted_by or "").strip():
            raise OverrideError("granted_by required")
        now = self.clock()
        rec = {"id": "ovr_" + secrets.token_hex(6), "agent_id": agent_id, "rule": rule,
               "reason": reason.strip(), "granted_by": granted_by.strip(),
               "granted_at": now, "expires_at": now + ttl_seconds, "revoked_at": None, "revoked_by": None}
        _atomic_write(self.dir / f"{rec['id']}.json", rec)
        self._cache = None
        self.audit.emit("override.granted", override_id=rec["id"], agent_id=agent_id, rule=rule,
                        granted_by=rec["granted_by"], reason=rec["reason"], expires_at=rec["expires_at"],
                        ttl_seconds=ttl_seconds)
        return rec

    def revoke(self, override_id: str, revoked_by: str) -> dict:
        p = self.dir / f"{override_id}.json"
        if not re.fullmatch(r"ovr_[0-9a-f]{12}", override_id or "") or not p.exists():
            raise OverrideError(f"unknown override {override_id!r}")
        rec = json.loads(p.read_text(encoding="utf-8"))
        rec["revoked_at"], rec["revoked_by"] = self.clock(), revoked_by
        _atomic_write(p, rec)
        self._cache = None
        self.audit.emit("override.revoked", override_id=override_id, agent_id=rec["agent_id"],
                        rule=rec["rule"], revoked_by=revoked_by)
        return rec

    def _all(self) -> list[dict]:
        now = time.monotonic()
        if self._cache and now - self._cache[0] < self.cache_seconds:
            return self._cache[1]
        recs = []
        for p in self.dir.glob("ovr_*.json"):
            try:
                recs.append(json.loads(p.read_text(encoding="utf-8")))
            except (OSError, ValueError):
                log.warning("unreadable override file %s ignored", p)  # unreadable = not granted
        self._cache = (now, recs)
        return recs

    def list(self, agent_id: str | None = None, include_inactive: bool = False) -> list[dict]:
        now = self.clock()
        return [r for r in self._all()
                if (agent_id is None or r["agent_id"] == agent_id)
                and (include_inactive or (not r.get("revoked_at") and r["expires_at"] > now))]

    def active_rules(self, agent_id: str) -> dict[str, dict]:
        """rule -> override record, for this agent, unexpired and unrevoked."""
        return {r["rule"]: r for r in self.list(agent_id)}


class NullOverrideStore:
    def active_rules(self, agent_id: str) -> dict[str, dict]:
        return {}


class FileApprovalStore:
    """Pending-approval records for consequential actions. Single use, bound to
    (agent, tool[, arguments digest]), time-limited. Approve/deny via `guardctl approvals`."""

    def __init__(self, directory: str | os.PathLike, audit: AuditSink, clock: Callable[[], float] = time.time):
        self.dir = Path(directory)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.audit, self.clock = audit, clock

    def create_pending(self, *, agent_id: str, tool: str, action: str | None, action_class: str | None,
                       args_digest: str, request_id: str | None, ttl_seconds: int, bind_arguments: bool) -> dict:
        now = self.clock()
        rec = {"id": "apr_" + secrets.token_hex(6), "state": "pending", "agent_id": agent_id, "tool": tool,
               "action": action, "class": action_class, "args_digest": args_digest, "bind_arguments": bind_arguments,
               "request_id": request_id, "created_at": now, "expires_at": now + ttl_seconds,
               "decided_by": None, "decided_at": None, "note": None}
        _atomic_write(self.dir / f"{rec['id']}.json", rec)
        self.audit.emit("approval.pending", approval_id=rec["id"], agent_id=agent_id, tool=tool, action=action,
                        action_class=action_class, args_digest=args_digest, request_id=request_id)
        return rec

    def get(self, approval_id: str) -> dict | None:
        if not re.fullmatch(r"apr_[0-9a-f]{12}", approval_id or ""):
            return None
        p = self.dir / f"{approval_id}.json"
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def list(self, state: str | None = None) -> list[dict]:
        out = []
        for p in sorted(self.dir.glob("apr_*.json")):
            try:
                r = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if state is None or r["state"] == state:
                out.append(r)
        return out

    def decide(self, approval_id: str, approve: bool, by: str, note: str = "") -> dict:
        rec = self.get(approval_id)
        if rec is None:
            raise OverrideError(f"unknown approval {approval_id!r}")
        if rec["state"] != "pending":
            raise OverrideError(f"approval {approval_id} is already {rec['state']}")
        if rec["expires_at"] <= self.clock():
            raise OverrideError(f"approval {approval_id} has expired")
        if not (by or "").strip():
            raise OverrideError("decided_by required")
        rec.update(state="approved" if approve else "denied", decided_by=by.strip(), decided_at=self.clock(), note=note)
        _atomic_write(self.dir / f"{approval_id}.json", rec)
        self.audit.emit("approval.approved" if approve else "approval.denied", approval_id=approval_id,
                        agent_id=rec["agent_id"], tool=rec["tool"], decided_by=by)
        return rec

    def consume(self, approval_id: str, agent_id: str, tool: str, args_digest: str) -> tuple[bool, str]:
        """Atomically spend an approved record. Returns (ok, reason)."""
        rec = self.get(approval_id)
        if rec is None:
            return False, "unknown_approval"
        if rec["state"] != "approved":
            return False, f"approval_{rec['state']}"
        if rec["expires_at"] <= self.clock():
            return False, "approval_expired"
        if rec["agent_id"] != agent_id or rec["tool"] != tool:
            return False, "approval_mismatch"
        if rec.get("bind_arguments") and rec["args_digest"] != args_digest:
            return False, "approval_arguments_mismatch"
        try:  # O_EXCL marker => exactly one consumer wins, even across processes
            fd = os.open(self.dir / f"{approval_id}.consumed", os.O_WRONLY | os.O_CREAT | os.O_EXCL)
            os.close(fd)
        except FileExistsError:
            return False, "approval_already_used"
        self.audit.emit("approval.consumed", approval_id=approval_id, agent_id=agent_id, tool=tool)
        return True, "ok"
