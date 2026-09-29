"""Hash-chain rules for the append-only audit log (shared by every AuditSink adapter).

hash_n = sha256( prev_hash_n || canonical_json({seq, ts, actor, action, target, severity, details}) )
The first record chains to GENESIS. Any edit, deletion or reordering breaks
every later hash, which `verify_chain` reports with the first bad sequence number.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from .models import AuditRecord, ChainVerification

GENESIS = "0" * 64


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str, ensure_ascii=True)


def utc_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def record_hash(prev_hash: str, seq: int, ts: str, actor: str, action: str, target: str,
                severity: str, details: dict[str, Any]) -> str:
    body = canonical({"seq": seq, "ts": ts, "actor": actor, "action": action, "target": target,
                      "severity": severity, "details": details})
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


def build_record(prev: AuditRecord | None, actor: str, action: str, target: str,
                 details: dict[str, Any] | None, severity: str, ts: str | None = None) -> AuditRecord:
    seq = (prev.seq + 1) if prev else 1
    prev_hash = prev.hash if prev else GENESIS
    ts = ts or utc_ts()
    # round-trip details through canonical JSON so what we hash is exactly what we store
    details = json.loads(canonical(details or {}))
    h = record_hash(prev_hash, seq, ts, actor, action, target, severity, details)
    return AuditRecord(seq=seq, ts=ts, actor=actor, action=action, target=target, severity=severity,
                       details=details, prev_hash=prev_hash, hash=h)


def verify_chain(records: Iterable[AuditRecord]) -> ChainVerification:
    prev_hash = GENESIS
    expected_seq = 1
    count = 0
    for r in records:
        if r.seq != expected_seq:
            return ChainVerification(False, count, r.seq, f"sequence gap: expected {expected_seq}, got {r.seq}")
        if r.prev_hash != prev_hash:
            return ChainVerification(False, count, r.seq, "prev_hash does not match previous record")
        h = record_hash(r.prev_hash, r.seq, r.ts, r.actor, r.action, r.target, r.severity, r.details)
        if h != r.hash:
            return ChainVerification(False, count, r.seq, "record hash mismatch (content altered)")
        prev_hash = r.hash
        expected_seq += 1
        count += 1
    return ChainVerification(True, count, None, None, prev_hash)
