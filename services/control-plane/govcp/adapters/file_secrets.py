"""SecretStore adapter backed by one JSON file (0600) on a private volume.

Stand-in for Vault / a cloud secrets manager. Revocation destroys the value and
bumps the version; the record stays so verification can prove it was revoked.
"""
from __future__ import annotations

import json
import os
import threading
import time

from ..domain.models import Secret
from ..domain.ports import SecretStore


class FileSecretStore(SecretStore):
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)

    def _load(self) -> dict:
        try:
            with open(self.path, encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            return {}

    def _save(self, data: dict):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f)
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        os.replace(tmp, self.path)

    @staticmethod
    def _to(path, d) -> Secret:
        return Secret(path=path, value=d.get("value"), revoked=d.get("revoked", False), version=d.get("version", 1),
                      metadata=d.get("metadata", {}))

    def put(self, path, value, metadata=None):
        with self._lock:
            data = self._load()
            old = data.get(path) or {}
            data[path] = {"value": value, "revoked": False, "version": old.get("version", 0) + 1,
                          "metadata": dict(metadata or {}), "updated_at": time.time()}
            self._save(data)
            return self._to(path, data[path])

    def get(self, path):
        with self._lock:
            d = self._load().get(path)
            return self._to(path, d) if d else None

    def revoke(self, path):
        with self._lock:
            data = self._load()
            d = data.get(path)
            if d is None:
                return None
            d.update(value=None, revoked=True, version=d.get("version", 1) + 1, revoked_at=time.time())
            self._save(data)
            return self._to(path, d)

    def list(self, prefix=""):
        with self._lock:
            return sorted(p for p in self._load() if p.startswith(prefix))
