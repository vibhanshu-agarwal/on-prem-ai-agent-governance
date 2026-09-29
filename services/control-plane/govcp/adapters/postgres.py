"""Postgres adapters: the Repository (document store) and the append-only AuditSink.

The app connects as `cp_app`, which has SELECT/INSERT on audit_log and nothing
else there (no UPDATE/DELETE/TRUNCATE); a trigger additionally rejects any
UPDATE/DELETE/TRUNCATE even from the table owner. Appends are serialised with a
transaction-scoped advisory lock so the hash chain has no forks.
"""
from __future__ import annotations

import json
from typing import Any, Callable

from psycopg.types.json import Jsonb
from psycopg_pool import ConnectionPool

from ..domain import audit as chain
from ..domain.models import AuditRecord, ChainVerification
from ..domain.ports import AuditSink
from ..domain.repository import Repository

AUDIT_LOCK_ID = 7_304_221


def make_pool(dsn: str, max_size: int = 10) -> ConnectionPool:
    pool = ConnectionPool(dsn, min_size=1, max_size=max_size, open=False, kwargs={"autocommit": True})
    pool.open(wait=True, timeout=30)
    return pool


class PostgresRepository(Repository):
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def get(self, collection, doc_id):
        with self.pool.connection() as c:
            row = c.execute("SELECT data FROM documents WHERE collection=%s AND id=%s", (collection, doc_id)).fetchone()
        return row[0] if row else None

    def put(self, collection, doc_id, data):
        with self.pool.connection() as c:
            c.execute("INSERT INTO documents(collection, id, data) VALUES (%s,%s,%s) "
                      "ON CONFLICT (collection, id) DO UPDATE SET data=EXCLUDED.data, updated_at=now()",
                      (collection, doc_id, Jsonb(data)))

    def insert(self, collection, doc_id, data):
        with self.pool.connection() as c:
            cur = c.execute("INSERT INTO documents(collection, id, data) VALUES (%s,%s,%s) "
                            "ON CONFLICT (collection, id) DO NOTHING", (collection, doc_id, Jsonb(data)))
            return cur.rowcount == 1

    def list(self, collection):
        with self.pool.connection() as c:
            rows = c.execute("SELECT data FROM documents WHERE collection=%s ORDER BY created_at, id",
                             (collection,)).fetchall()
        return [r[0] for r in rows]

    def update(self, collection, doc_id, fn: Callable[[dict], dict]):
        with self.pool.connection() as c:
            with c.transaction():
                row = c.execute("SELECT data FROM documents WHERE collection=%s AND id=%s FOR UPDATE",
                                (collection, doc_id)).fetchone()
                if row is None:
                    raise KeyError(doc_id)
                new = fn(row[0])
                c.execute("UPDATE documents SET data=%s, updated_at=now() WHERE collection=%s AND id=%s",
                          (Jsonb(new), collection, doc_id))
                return new

    def delete(self, collection, doc_id):
        with self.pool.connection() as c:
            c.execute("DELETE FROM documents WHERE collection=%s AND id=%s", (collection, doc_id))


def _rec(row) -> AuditRecord:
    seq, ts, actor, action, target, severity, details, prev_hash, h = row
    return AuditRecord(seq=seq, ts=ts, actor=actor, action=action, target=target, severity=severity,
                       details=json.loads(details), prev_hash=prev_hash, hash=h)


COLS = "seq, ts, actor, action, target, severity, details, prev_hash, hash"


class PostgresAuditSink(AuditSink):
    def __init__(self, pool: ConnectionPool):
        self.pool = pool

    def append(self, actor, action, target, details=None, severity="info"):
        with self.pool.connection() as c:
            with c.transaction():
                c.execute("SELECT pg_advisory_xact_lock(%s)", (AUDIT_LOCK_ID,))
                row = c.execute(f"SELECT {COLS} FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
                rec = chain.build_record(_rec(row) if row else None, actor, action, target, details, severity)
                c.execute(f"INSERT INTO audit_log ({COLS}) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)",
                          (rec.seq, rec.ts, rec.actor, rec.action, rec.target, rec.severity,
                           chain.canonical(rec.details), rec.prev_hash, rec.hash))
        return rec

    def list(self, limit=100, since_seq=0, action_prefix=None, severity=None, target=None):
        q = f"SELECT {COLS} FROM audit_log WHERE seq > %s"
        args: list[Any] = [since_seq]
        if action_prefix:
            q += " AND action LIKE %s"
            args.append(action_prefix.replace("%", r"\%") + "%")
        if severity:
            q += " AND severity = %s"
            args.append(severity)
        if target:
            q += " AND target = %s"
            args.append(target)
        q += " ORDER BY seq DESC LIMIT %s"
        args.append(limit)
        with self.pool.connection() as c:
            rows = c.execute(q, args).fetchall()
        return [_rec(r) for r in reversed(rows)]

    def all(self) -> list[AuditRecord]:
        with self.pool.connection() as c:
            rows = c.execute(f"SELECT {COLS} FROM audit_log ORDER BY seq").fetchall()
        return [_rec(r) for r in rows]

    def verify(self) -> ChainVerification:
        return chain.verify_chain(self.all())
