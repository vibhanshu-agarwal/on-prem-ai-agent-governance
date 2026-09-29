"""Signer / Verifier interfaces plus the default Ed25519 implementation.

A sponsor can plug in cosign/Sigstore, an HSM or a KMS by implementing Signer/Verifier and
pointing POLICY_SIGNER / POLICY_VERIFIER at "package.module:factory" (see make_signer/make_verifier).
Nothing else in the package knows which algorithm is used.
"""
from __future__ import annotations

import base64
import hashlib
import importlib
import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class SignatureError(Exception):
    """Signature missing, malformed, from an untrusted key, or not matching the data."""


@dataclass(frozen=True)
class Signature:
    alg: str
    key_id: str
    value: str  # base64

    def to_dict(self) -> dict:
        return {"alg": self.alg, "key_id": self.key_id, "value": self.value}

    @classmethod
    def from_dict(cls, d) -> "Signature":
        try:
            return cls(alg=str(d["alg"]), key_id=str(d["key_id"]), value=str(d["value"]))
        except (KeyError, TypeError) as e:
            raise SignatureError(f"malformed signature block: {e!r}") from e


class Signer(ABC):
    @abstractmethod
    def sign(self, data: bytes) -> Signature: ...


class Verifier(ABC):
    @abstractmethod
    def verify(self, data: bytes, signature: Signature) -> None:
        """Return None if valid; raise SignatureError otherwise."""


def _key_id(pub_raw: bytes) -> str:
    return hashlib.sha256(pub_raw).hexdigest()[:16]


def _pub_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class Ed25519Signer(Signer):
    ALG = "ed25519"

    def __init__(self, private_key: Ed25519PrivateKey):
        self._key = private_key
        self.key_id = _key_id(_pub_raw(private_key.public_key()))

    @classmethod
    def from_file(cls, path) -> "Ed25519Signer":
        try:
            key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        except (OSError, ValueError) as e:
            raise SignatureError(f"cannot load signing key {path}: {e}") from e
        if not isinstance(key, Ed25519PrivateKey):
            raise SignatureError(f"{path}: not an Ed25519 key")
        return cls(key)

    @classmethod
    def generate(cls, private_path, trust_dir, force: bool = False) -> "Ed25519Signer":
        """Create a keypair: private key to private_path (gitignored), public key to trust_dir (committed)."""
        private_path = Path(private_path)
        if private_path.exists() and not force:
            raise SignatureError(f"{private_path} exists; pass force to overwrite")
        key = Ed25519PrivateKey.generate()
        private_path.parent.mkdir(parents=True, exist_ok=True)
        private_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        try:
            os.chmod(private_path, 0o600)
        except OSError:
            pass
        signer = cls(key)
        Path(trust_dir).mkdir(parents=True, exist_ok=True)
        pub = {"alg": cls.ALG, "key_id": signer.key_id,
               "public_key": base64.b64encode(_pub_raw(key.public_key())).decode()}
        (Path(trust_dir) / f"{signer.key_id}.pub.json").write_text(
            json.dumps(pub, indent=2) + "\n", encoding="utf-8")
        return signer

    def sign(self, data: bytes) -> Signature:
        return Signature(self.ALG, self.key_id, base64.b64encode(self._key.sign(data)).decode())


class Ed25519Verifier(Verifier):
    """Trusts an explicit set of public keys (key_id -> key). Everything else is rejected."""

    def __init__(self, trusted: Dict[str, Ed25519PublicKey]):
        self._trusted = dict(trusted)

    @classmethod
    def from_trust_dir(cls, trust_dir) -> "Ed25519Verifier":
        trusted: Dict[str, Ed25519PublicKey] = {}
        d = Path(trust_dir)
        for p in sorted(d.glob("*.pub.json")) if d.is_dir() else []:
            try:
                j = json.loads(p.read_text(encoding="utf-8"))
                raw = base64.b64decode(j["public_key"], validate=True)
                if j.get("alg") != Ed25519Signer.ALG or _key_id(raw) != j["key_id"]:
                    raise ValueError("alg/key_id mismatch")
                trusted[j["key_id"]] = Ed25519PublicKey.from_public_bytes(raw)
            except (OSError, ValueError, KeyError, TypeError) as e:
                raise SignatureError(f"bad trust file {p}: {e}") from e
        return cls(trusted)

    def verify(self, data: bytes, signature: Signature) -> None:
        if signature.alg != Ed25519Signer.ALG:
            raise SignatureError(f"unsupported signature algorithm {signature.alg!r}")
        pub = self._trusted.get(signature.key_id)
        if pub is None:
            raise SignatureError(f"signing key {signature.key_id!r} is not in the trust store")
        try:
            pub.verify(base64.b64decode(signature.value, validate=True), data)
        except (InvalidSignature, ValueError) as e:
            raise SignatureError("signature does not match bundle contents") from e


def _load_factory(spec: str) -> Callable:
    mod, _, attr = spec.partition(":")
    if not mod or not attr:
        raise SignatureError(f"plugin spec must be 'package.module:factory', got {spec!r}")
    return getattr(importlib.import_module(mod), attr)


def make_signer(kind: str, key_path) -> Signer:
    """kind: 'ed25519' (default) or 'package.module:factory' called as factory(key_path) -> Signer."""
    if kind == "ed25519":
        return Ed25519Signer.from_file(key_path)
    return _load_factory(kind)(key_path)


def make_verifier(kind: str, trust_dir) -> Verifier:
    """kind: 'ed25519' (default) or 'package.module:factory' called as factory(trust_dir) -> Verifier."""
    if kind == "ed25519":
        return Ed25519Verifier.from_trust_dir(trust_dir)
    return _load_factory(kind)(trust_dir)
