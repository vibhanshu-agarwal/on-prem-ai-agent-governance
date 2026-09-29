"""Minimal macaroon-style capability tokens for delegation attenuation.

Token = "gpm1." + b64url(json{"id", "caveats"}) + "." + hex(sig)
    sig_0 = HMAC(root_key, id)
    sig_i = HMAC(sig_{i-1}, caveat_i)

Anyone holding a token can append caveats (attenuate) without the root key, but
nobody can remove or edit one without invalidating the signature. Caveats are
predicates that must ALL hold, so the effective scope is their intersection:

    agent = <id>          delegation chain marker; the last one is the holder
    budget_usd <= <x>     effective budget = min
    models in a,b,c       effective models = intersection
    max_depth <= <n>      effective depth cap = min
    expires < <epoch>     effective expiry = min

A caveat can therefore only narrow scope. "Broadening" a delegated credential is
impossible by construction; the mint endpoint additionally rejects (and alerts
on) requests that ask for more than the parent's effective scope.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import time
from dataclasses import dataclass, field

PREFIX = "gpm1"


class InvalidToken(Exception):
    pass


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _mac(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()


@dataclass
class Scope:
    chain: list[str] = field(default_factory=list)
    budget_usd: float = math.inf
    models: set[str] | None = None        # None = unrestricted (never true for issued tokens)
    max_depth: int = 1_000_000
    expires: float = math.inf

    @property
    def holder(self) -> str:
        return self.chain[-1] if self.chain else ""

    @property
    def root(self) -> str:
        return self.chain[0] if self.chain else ""

    @property
    def depth(self) -> int:
        return max(len(self.chain) - 1, 0)

    def to_dict(self):
        return {"chain": self.chain, "holder": self.holder, "depth": self.depth,
                "budget_usd": None if math.isinf(self.budget_usd) else self.budget_usd,
                "models": sorted(self.models) if self.models is not None else None,
                "max_depth": self.max_depth,
                "expires": None if math.isinf(self.expires) else self.expires}


def mint(root_key: bytes, token_id: str, caveats: list[str]) -> str:
    sig = _mac(root_key, token_id)
    for c in caveats:
        sig = _mac(sig, c)
    return _encode(token_id, caveats, sig)


def attenuate(token: str, extra_caveats: list[str]) -> str:
    token_id, caveats, sig = _decode(token)
    for c in extra_caveats:
        sig = _mac(sig, c)
    return _encode(token_id, caveats + list(extra_caveats), sig)


def _encode(token_id: str, caveats: list[str], sig: bytes) -> str:
    body = json.dumps({"id": token_id, "caveats": caveats}, separators=(",", ":")).encode()
    return f"{PREFIX}.{_b64e(body)}.{sig.hex()}"


def _decode(token: str) -> tuple[str, list[str], bytes]:
    try:
        prefix, body, sig = token.split(".")
        if prefix != PREFIX:
            raise ValueError("prefix")
        data = json.loads(_b64d(body))
        return str(data["id"]), [str(c) for c in data["caveats"]], bytes.fromhex(sig)
    except Exception as e:  # noqa: BLE001
        raise InvalidToken(f"malformed token: {e}") from None


def token_id(token: str) -> str:
    return _decode(token)[0]


def caveats_of(token: str) -> list[str]:
    return _decode(token)[1]


def verify(root_key: bytes, token: str, at: float | None = None) -> Scope:
    """Check the signature chain and evaluate caveats into an effective scope."""
    tid, caveats, sig = _decode(token)
    expected = _mac(root_key, tid)
    for c in caveats:
        expected = _mac(expected, c)
    if not hmac.compare_digest(expected, sig):
        raise InvalidToken("signature mismatch (token forged or caveats altered)")
    scope = Scope()
    for c in caveats:
        _apply(scope, c)
    if (at or time.time()) >= scope.expires:
        raise InvalidToken("token expired")
    if not scope.chain:
        raise InvalidToken("token has no agent caveat")
    return scope


def _apply(scope: Scope, caveat: str) -> None:
    try:
        if caveat.startswith("agent = "):
            scope.chain.append(caveat[len("agent = "):].strip())
        elif caveat.startswith("budget_usd <= "):
            scope.budget_usd = min(scope.budget_usd, float(caveat.split("<=", 1)[1]))
        elif caveat.startswith("models in "):
            ms = {m.strip() for m in caveat[len("models in "):].split(",") if m.strip()}
            scope.models = ms if scope.models is None else (scope.models & ms)
        elif caveat.startswith("max_depth <= "):
            scope.max_depth = min(scope.max_depth, int(caveat.split("<=", 1)[1]))
        elif caveat.startswith("expires < "):
            scope.expires = min(scope.expires, float(caveat.split("<", 1)[1]))
        else:
            # unknown caveats fail closed: a predicate we cannot evaluate is never satisfied
            raise InvalidToken(f"unknown caveat: {caveat!r}")
    except InvalidToken:
        raise
    except Exception as e:  # noqa: BLE001
        raise InvalidToken(f"bad caveat {caveat!r}: {e}") from None
