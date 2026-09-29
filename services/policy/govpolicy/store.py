"""Bundle store: versioned signed bundles, an active pointer, and an append-only history.

Layout under <root>:
  bundles/<effective_version>.bundle.json
  active.json            {"version": "..."}   (pointer only; never trusted without re-verifying the bundle)
  history.jsonl          append-only events: published | activate | rollback
The loader fails closed: any problem raises PolicyLoadError and no policy is returned.
"""
from __future__ import annotations

import datetime as dt
import getpass
import json
import os
import re
from pathlib import Path
from typing import List, Optional

from .bundle import Bundle, BundleError, build_bundle, git_info, verify_bundle
from .signing import Signer, Verifier

_VERSION_RE = re.compile(r"^v\d+-[0-9a-f]{12}$")


class PolicyLoadError(Exception):
    """No verified policy could be loaded (fail closed)."""


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class PolicyStore:
    def __init__(self, root, verifier: Verifier):
        self.root = Path(root)
        self.verifier = verifier
        self.bundles = self.root / "bundles"
        self.history_path = self.root / "history.jsonl"
        self.active_path = self.root / "active.json"

    # ---- history ----
    def history(self) -> List[dict]:
        if not self.history_path.exists():
            return []
        out = []
        for line in self.history_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
        return out

    def _append(self, event: dict) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        event = {"ts": _now(), "actor": getpass.getuser(), **event}
        with open(self.history_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, sort_keys=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def next_seq(self) -> int:
        seqs = [e["seq"] for e in self.history() if e.get("event") == "published"]
        return max(seqs, default=0) + 1

    def versions(self) -> List[str]:
        return [e["version"] for e in self.history() if e.get("event") == "published"]

    # ---- publish ----
    def publish(self, policy_dir, signer: Signer) -> Bundle:
        """Build + sign + store. Re-publishing identical content returns the existing bundle."""
        bundle = build_bundle(policy_dir, signer, self.next_seq(), git=git_info(Path(policy_dir)))
        for e in self.history():
            if e.get("event") == "published" and e["content_hash"] == bundle.manifest["content_hash"]:
                return self.get(e["version"])
        self.bundles.mkdir(parents=True, exist_ok=True)
        (self.bundles / f"{bundle.version}.bundle.json").write_text(bundle.to_json(), encoding="utf-8")
        self._append({"event": "published", "version": bundle.version, "seq": bundle.manifest["seq"],
                      "content_hash": bundle.manifest["content_hash"],
                      "git_commit": bundle.manifest["git_commit"]})
        return bundle

    # ---- read ----
    def get(self, version: str) -> Bundle:
        """Load one stored bundle, verifying its signature. Raises PolicyLoadError."""
        if not _VERSION_RE.match(version or ""):
            raise PolicyLoadError(f"invalid version {version!r}")
        path = self.bundles / f"{version}.bundle.json"
        try:
            b = verify_bundle(path.read_bytes(), self.verifier)
        except OSError as e:
            raise PolicyLoadError(f"cannot read bundle {version}: {e}") from e
        except BundleError as e:
            raise PolicyLoadError(f"bundle {version} rejected: {e}") from e
        if b.version != version:
            raise PolicyLoadError(f"bundle file {version} contains version {b.version}")
        return b

    def active_version(self) -> Optional[str]:
        try:
            return json.loads(self.active_path.read_text(encoding="utf-8"))["version"]
        except (OSError, ValueError, KeyError, TypeError):
            return None

    def load_active(self) -> Bundle:
        """The only way callers should obtain the enforced policy. Verifies on every call."""
        v = self.active_version()
        if v is None:
            raise PolicyLoadError("no active policy bundle (fail closed)")
        return self.get(v)

    # ---- activation / rollback ----
    def _set_active(self, version: str, event: str, reason: str = "") -> Bundle:
        bundle = self.get(version)  # verify BEFORE switching
        prev = self.active_version()
        tmp = self.active_path.with_suffix(".tmp")
        tmp.write_text(json.dumps({"version": version}), encoding="utf-8")
        os.replace(tmp, self.active_path)
        self._append({"event": event, "version": version, "previous": prev,
                      "content_hash": bundle.manifest["content_hash"], "reason": reason})
        return bundle

    def activate(self, version: str, reason: str = "") -> Bundle:
        return self._set_active(version, "activate", reason)

    def rollback(self, to: Optional[str] = None, reason: str = "") -> Bundle:
        """Activate an earlier signed bundle: `to`, or the most recently active different version."""
        current = self.active_version()
        if to is None:
            acts = [e["version"] for e in self.history() if e.get("event") in ("activate", "rollback")]
            candidates = [v for v in reversed(acts) if v != current]
            if not candidates:
                raise PolicyLoadError("no previous version to roll back to")
            to = candidates[0]
        elif to not in self.versions():
            raise PolicyLoadError(f"unknown version {to!r}")
        return self._set_active(to, "rollback", reason)
