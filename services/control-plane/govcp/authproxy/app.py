"""Auth layer in front of the LiteLLM OSS gateway (the report section 2 "custom auth layer" route).

  Authorization: Bearer <JWT from the IdP>   -> validate (JWKS, RS256, iss, aud, exp)
  Authorization: Macaroon <delegation token> -> checked by the control plane (scope, lineage)
then resolve the caller to its OWN per-agent LiteLLM virtual key via the control
plane and forward the request with that key. Blocking the key at the gateway
therefore stops an SSO agent immediately, even though its JWT is still valid.

Fails closed: if the caller cannot be resolved (control plane down and nothing
cached), the request is refused. Resolution is cached briefly per subject; the
cache never matters for a stop, because the key itself is blocked at the gateway.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import time

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.background import BackgroundTask

from ..adapters.oidc_identity import OIDCIdentityProvider
from ..config import load_config
from ..domain.errors import DomainError

log = logging.getLogger("authproxy")
CFG = load_config().get("authproxy") or {}
GATEWAY = CFG.get("gateway_url", "http://gateway:4000").rstrip("/")
CP = CFG.get("control_plane_url", "http://control-plane:8100").rstrip("/")
IDP_TOKEN_URL = CFG.get("idp_token_url", "http://idp:8300/token")
AUDIENCE = CFG.get("audience", "govpilot-gateway")
CACHE_S = float(CFG.get("resolve_cache_s", 5))
CLIENT_ID = CFG.get("client_id", "authproxy")
CLIENT_SECRET = os.environ.get(CFG.get("client_secret_env", "IDP_CLIENT_SECRET_AUTHPROXY"), "")

idp = OIDCIdentityProvider(issuer=CFG.get("issuer", "http://idp:8300"),
                           jwks_url=CFG.get("jwks_url", "http://idp:8300/jwks.json"))
_cache: dict[str, tuple[float, dict]] = {}
_svc_token: dict[str, float | str] = {"token": "", "exp": 0.0}
client = httpx.AsyncClient(timeout=httpx.Timeout(connect=5, read=600, write=30, pool=5))

app = FastAPI(title="govpilot auth proxy", version="0.1.0")


def _err(status: int, code: str, msg: str):
    return JSONResponse(status_code=status, content={"error": {"type": code, "message": msg, "code": str(status)}})


async def _service_token() -> str:
    if _svc_token["token"] and time.time() < float(_svc_token["exp"]) - 30:
        return str(_svc_token["token"])
    r = await client.post(IDP_TOKEN_URL, data={"grant_type": "client_credentials", "client_id": CLIENT_ID,
                                               "client_secret": CLIENT_SECRET, "audience": "govpilot-control-plane"})
    r.raise_for_status()
    d = r.json()
    _svc_token.update(token=d["access_token"], exp=time.time() + d["expires_in"])
    return d["access_token"]


async def _resolve(body: dict, cache_key: str | None) -> tuple[int, dict]:
    if cache_key:
        hit = _cache.get(cache_key)
        if hit and time.time() - hit[0] < CACHE_S:
            return 200, hit[1]
    try:
        tok = await _service_token()
        r = await client.post(f"{CP}/v1/internal/resolve", json=body, headers={"Authorization": f"Bearer {tok}"})
    except httpx.HTTPError as e:
        return 503, {"message": f"control plane unavailable ({type(e).__name__}); failing closed"}
    d = r.json() if r.content else {}
    if r.status_code == 200 and cache_key:
        _cache[cache_key] = (time.time(), d)
    if r.status_code != 200 and cache_key:
        _cache.pop(cache_key, None)
    return r.status_code, d


@app.get("/healthz")
def healthz():
    return {"ok": True}


# Same inference-only allowlist as deploy/hardening/nginx.conf (T9): an SSO agent is resolved to its own gateway
# key, but must not be able to reach the admin/management routes with it (e.g. /v1/key/*, /v1/team/*).
ALLOWED_ROUTES = {("POST", "chat/completions"), ("POST", "completions"), ("POST", "embeddings"),
                  ("GET", "models")}


@app.api_route("/v1/{path:path}", methods=["GET", "POST"])
async def proxy(path: str, request: Request):
    if (request.method, path.strip("/")) not in ALLOWED_ROUTES:
        return _err(403, "forbidden_route", "route not available to agents")
    auth = request.headers.get("authorization", "")
    raw = await request.body()
    model = None
    if raw:
        try:
            model = json.loads(raw).get("model")
        except (ValueError, AttributeError):
            pass
    if auth.startswith("Macaroon "):
        tok = auth[len("Macaroon "):].strip()
        status, d = await _resolve({"kind": "delegation", "token": tok, "model": model}, None)
    elif auth.startswith("Bearer ") and auth.count(".") == 2:
        try:
            p = idp.verify(auth[len("Bearer "):].strip(), AUDIENCE)
        except DomainError as e:
            return _err(401, "auth_error", e.message)
        ck = hashlib.sha256(f"{p.claims.get('iss')}|{p.subject}".encode()).hexdigest()
        status, d = await _resolve({"kind": "oidc", "subject": p.subject, "issuer": p.claims.get("iss")}, ck)
    else:
        return _err(401, "auth_error", "send a JWT from the IdP (Bearer) or a delegation token (Macaroon)")
    if status != 200:
        return _err(status if status in (401, 403, 429, 503) else 403, "auth_error",
                    d.get("message") or str(d)[:200])

    # drop every header the gateway could read a credential or identity from; only ours go upstream
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in ("authorization", "host", "content-length", "connection",
                                    "api-key", "x-api-key", "x-litellm-api-key", "x-govpilot-agent")}
    headers["authorization"] = f"Bearer {d['gateway_key']}"
    headers["x-govpilot-agent"] = d["agent_id"]
    req = client.build_request(request.method, f"{GATEWAY}/v1/{path}", headers=headers, content=raw,
                               params=request.query_params)
    try:
        upstream = await client.send(req, stream=True)
    except httpx.HTTPError as e:
        return _err(502, "gateway_error", f"gateway unreachable: {type(e).__name__}")
    drop = {"content-length", "transfer-encoding", "connection", "content-encoding"}
    out_headers = {k: v for k, v in upstream.headers.items() if k.lower() not in drop}
    if "text/event-stream" in upstream.headers.get("content-type", ""):
        # Stream through; if the downstream socket dies the generator is closed and so is the upstream stream.
        if upstream.headers.get("content-encoding"):
            out_headers["content-encoding"] = upstream.headers["content-encoding"]
        return StreamingResponse(upstream.aiter_raw(), status_code=upstream.status_code, headers=out_headers,
                                 background=BackgroundTask(upstream.aclose))
    body = await upstream.aread()
    await upstream.aclose()
    return Response(content=body, status_code=upstream.status_code, headers=out_headers)
