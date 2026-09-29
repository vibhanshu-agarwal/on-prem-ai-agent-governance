"""Versioned, signed policy bundles.

On disk a bundle is one JSON file:
  {"format": "govpolicy-bundle/1", "payload": "<canonical JSON string>", "signature": {...}}
The signature covers the exact bytes of `payload`, so there is no canonicalisation ambiguity on verify.
payload = {"manifest": {...}, "policy": {...compiled policy...}}
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Union

from pydantic import ValidationError

from .schema import Policy, compile_policy_dir
from .signing import Signature, SignatureError, Signer, Verifier

FORMAT = "govpolicy-bundle/1"


class BundleError(Exception):
    """Bundle is malformed, unsigned, tampered with, or signed by an untrusted key."""


def canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def content_hash(policy_dict: dict) -> str:
    return hashlib.sha256(canonical_json(policy_dict).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Bundle:
    manifest: dict
    policy: Policy
    payload: str
    signature: Signature

    @property
    def version(self) -> str:
        return self.manifest["effective_version"]

    def to_json(self) -> str:
        return json.dumps({"format": FORMAT, "payload": self.payload,
                           "signature": self.signature.to_dict()}, indent=2) + "\n"


def git_info(path: Path) -> dict:
    """Best-effort commit + dirty flag for the repo containing `path`."""
    def run(*args):
        return subprocess.run(["git", "-C", str(path), *args], capture_output=True, text=True,
                              timeout=15, check=True).stdout.strip()
    try:
        return {"git_commit": run("rev-parse", "HEAD"),
                "git_dirty": bool(run("status", "--porcelain", "--", str(path.resolve())))}
    except (OSError, subprocess.SubprocessError):
        return {"git_commit": "unknown", "git_dirty": None}


def build_bundle(policy_dir, signer: Signer, seq: int, created_at: Optional[str] = None,
                 git: Optional[dict] = None) -> Bundle:
    """Validate policy_dir, then produce a signed bundle. `seq` is the store's next sequence number."""
    policy_dir = Path(policy_dir)
    policy = compile_policy_dir(policy_dir)  # raises PolicyError on invalid policy
    policy_dict = json.loads(policy.model_dump_json())
    chash = content_hash(policy_dict)
    manifest = {
        "seq": seq,
        "content_hash": chash,
        "effective_version": f"v{seq}-{chash[:12]}",
        "created_at": created_at or dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **(git if git is not None else git_info(policy_dir)),
    }
    payload = canonical_json({"manifest": manifest, "policy": policy_dict})
    return Bundle(manifest, policy, payload, signer.sign(payload.encode("utf-8")))


def verify_bundle(raw: Union[str, bytes], verifier: Verifier) -> Bundle:
    """Parse + verify. Signature is checked BEFORE the payload is parsed or trusted."""
    try:
        outer = json.loads(raw)
        if outer.get("format") != FORMAT:
            raise BundleError(f"unsupported bundle format {outer.get('format')!r}")
        payload = outer["payload"]
        if not isinstance(payload, str) or "signature" not in outer or outer["signature"] is None:
            raise BundleError("bundle is unsigned or malformed")
        sig = Signature.from_dict(outer["signature"])
    except (ValueError, KeyError, TypeError, AttributeError, SignatureError) as e:
        raise BundleError(f"malformed bundle: {e}") from e
    try:
        verifier.verify(payload.encode("utf-8"), sig)
    except SignatureError as e:
        raise BundleError(f"signature verification failed: {e}") from e
    try:
        inner = json.loads(payload)
        manifest, policy_dict = inner["manifest"], inner["policy"]
        policy = Policy.model_validate(policy_dict)
    except (ValueError, KeyError, TypeError, ValidationError) as e:
        raise BundleError(f"signed payload is not a valid policy: {e}") from e
    # Defence in depth: manifest must agree with the content it claims to describe.
    if manifest.get("content_hash") != content_hash(policy_dict):
        raise BundleError("content hash in manifest does not match policy")
    if manifest.get("effective_version") != f"v{manifest.get('seq')}-{manifest['content_hash'][:12]}":
        raise BundleError("effective_version does not match seq/content hash")
    return Bundle(manifest, policy, payload, sig)
