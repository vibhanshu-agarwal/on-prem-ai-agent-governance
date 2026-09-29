"""Stand-in corporate IdP: a tiny OIDC-style issuer (RS256 JWTs, JWKS, discovery doc).

Grants:
  client_credentials  machine clients (agents, feeds, the auth proxy)
  password            human operators from config (passwords come from env IDP_PASSWORD_<USER>)
Admin API (bearer IDP_ADMIN_TOKEN): register clients, disable/enable subjects.
A disabled subject cannot obtain NEW tokens; tokens already issued stay valid
until `exp` - which is exactly why the gateway key mapping (not token expiry) is
the stop mechanism for SSO agents.

Swap: point the control plane and auth proxy at Keycloak / Entra ID / Okta by
changing `issuer` and `jwks_url` in config; only disable/enable needs a new adapter.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI, Form, Header, HTTPException
from pydantic import BaseModel

from ..config import load_config

DATA = os.environ.get("IDP_DATA_DIR", "/data")
CFG = (load_config().get("idp") or {}) if os.path.exists(os.environ.get("GOVCP_CONFIG", "/etc/govcp/config.yaml")) else {}
ISSUER = CFG.get("issuer", "http://idp:8300")
TTL = int(CFG.get("token_ttl_s", 900))
USER_TTL = int(CFG.get("user_token_ttl_s", 3600))
ADMIN_TOKEN = os.environ.get("IDP_ADMIN_TOKEN", "")
_lock = threading.Lock()


def _b64(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _load_key():
    os.makedirs(DATA, exist_ok=True)
    p = os.path.join(DATA, "signing-key.pem")
    if os.path.exists(p):
        with open(p, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), password=None)
    else:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(p, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        os.chmod(p, 0o600)
    pub = key.public_key().public_numbers()
    kid = hashlib.sha256(f"{pub.n}:{pub.e}".encode()).hexdigest()[:16]
    jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid, "n": _b64(pub.n), "e": _b64(pub.e)}
    return key, kid, jwk


KEY, KID, JWK = _load_key()
CLIENTS_FILE = os.path.join(DATA, "clients.json")


def _sha(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _clients() -> dict:
    try:
        with open(CLIENTS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


def _save_clients(d: dict):
    tmp = CLIENTS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(d, f)
    os.replace(tmp, CLIENTS_FILE)


def _static_clients() -> dict:
    out = {}
    for cid, spec in (CFG.get("static_clients") or {}).items():
        secret = os.environ.get(spec.get("secret_env", ""), "")
        if secret:
            out[cid] = {"secret_sha256": _sha(secret), "roles": spec.get("roles", []), "kind": "client"}
    return out


def _disabled() -> set:
    return set(_clients().get("__disabled__", []))


def _sign(claims: dict) -> str:
    return jwt.encode(claims, KEY, algorithm="RS256", headers={"kid": KID})


app = FastAPI(title="govpilot stand-in IdP", version="0.1.0")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/.well-known/openid-configuration")
def discovery():
    return {"issuer": ISSUER, "jwks_uri": f"{ISSUER}/jwks.json", "token_endpoint": f"{ISSUER}/token",
            "grant_types_supported": ["client_credentials", "password"],
            "id_token_signing_alg_values_supported": ["RS256"]}


@app.get("/jwks.json")
def jwks():
    return {"keys": [JWK]}


@app.post("/token")
def token(grant_type: str = Form(...), client_id: str = Form(None), client_secret: str = Form(None),
          username: str = Form(None), password: str = Form(None), audience: str = Form(None)):
    now = int(time.time())
    if grant_type == "client_credentials":
        if not client_id or not client_secret:
            raise HTTPException(400, "client_id and client_secret required")
        with _lock:
            c = {**_clients(), **_static_clients()}.get(client_id)
            disabled = _disabled()
        if not c or not hmac.compare_digest(c["secret_sha256"], _sha(client_secret)):
            raise HTTPException(401, "invalid client")
        if client_id in disabled or c.get("disabled"):
            raise HTTPException(403, "client disabled")
        claims = {"iss": ISSUER, "sub": client_id, "aud": audience or "govpilot-gateway", "iat": now,
                  "exp": now + TTL, "jti": uuid.uuid4().hex, "roles": c.get("roles", []), "kind": "client",
                  "azp": client_id}
    elif grant_type == "password":
        u = (CFG.get("users") or {}).get(username or "")
        expected = os.environ.get(f"IDP_PASSWORD_{(username or '').upper()}", "")
        if not u or not expected or not hmac.compare_digest(expected, password or ""):
            raise HTTPException(401, "invalid credentials")
        if username in _disabled():
            raise HTTPException(403, "user disabled")
        claims = {"iss": ISSUER, "sub": username, "aud": audience or "govpilot-control-plane", "iat": now,
                  "exp": now + USER_TTL, "jti": uuid.uuid4().hex, "roles": u.get("roles", []),
                  "teams": u.get("teams", []), "kind": "user", "name": u.get("name", username)}
    else:
        raise HTTPException(400, "unsupported grant_type")
    return {"access_token": _sign(claims), "token_type": "Bearer", "expires_in": claims["exp"] - now}


def _admin(authorization: str | None):
    if not ADMIN_TOKEN or not authorization or not hmac.compare_digest(authorization, f"Bearer {ADMIN_TOKEN}"):
        raise HTTPException(401, "admin token required")


class ClientIn(BaseModel):
    client_id: str
    roles: list[str] = ["agent"]


@app.post("/admin/clients", status_code=201)
def create_client(body: ClientIn, authorization: str | None = Header(None)):
    _admin(authorization)
    secret = secrets.token_urlsafe(24)
    with _lock:
        d = _clients()
        if body.client_id in d or body.client_id in _static_clients():
            raise HTTPException(409, "client exists")
        d[body.client_id] = {"secret_sha256": _sha(secret), "roles": body.roles, "kind": "client",
                             "created_at": time.time()}
        _save_clients(d)
    return {"client_id": body.client_id, "client_secret": secret, "roles": body.roles}


@app.post("/admin/subjects/{subject}/disable")
def disable(subject: str, authorization: str | None = Header(None)):
    _admin(authorization)
    with _lock:
        d = _clients()
        d["__disabled__"] = sorted(set(d.get("__disabled__", [])) | {subject})
        _save_clients(d)
    return {"subject": subject, "enabled": False}


@app.post("/admin/subjects/{subject}/enable")
def enable(subject: str, authorization: str | None = Header(None)):
    _admin(authorization)
    with _lock:
        d = _clients()
        d["__disabled__"] = sorted(set(d.get("__disabled__", [])) - {subject})
        _save_clients(d)
    return {"subject": subject, "enabled": True}


@app.get("/admin/subjects/{subject}")
def subject(subject: str, authorization: str | None = Header(None)):
    _admin(authorization)
    return {"subject": subject, "enabled": subject not in _disabled()}
