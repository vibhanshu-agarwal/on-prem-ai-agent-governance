"""AuditSink adapter writing a hash-chained JSON-lines file.

Used by the emergency-stop path, which must keep an audit trail when the main
control plane and its database are down. The control plane later ingests the
journal into the Postgres audit log (each entry keeps its original hash).
"""
from __future__ import annotations

import json
import os
import threading

from ..domain import audit as chain
from ..domain.models import AuditRecord
from ..domain.ports import AuditSink


class JsonlAuditSink(AuditSink):
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def _read(self) -> list[AuditRecord]:
        try:
            with open(self.path, encoding="utf-8") as f:
                return [AuditRecord(**json.loads(line)) for line in f if line.strip()]
        except FileNotFoundError:
            return []

    def append(self, actor, action, target, details=None, severity="info"):
        with self._lock:
            recs = self._read()
            rec = chain.build_record(recs[-1] if recs else None, actor, action, target, details, severity)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec.to_dict(), sort_keys=True) + "\n")
                f.flush()
                os.fsync(f.fileno())
            return rec

    def list(self, limit=100, since_seq=0, action_prefix=None, severity=None, target=None):
        out = [r for r in self._read() if r.seq > since_seq
               and (not action_prefix or r.action.startswith(action_prefix))
               and (not severity or r.severity == severity) and (not target or r.target == target)]
        return out[-limit:]

    def verify(self):
        return chain.verify_chain(self._read())
