"""Status page backend (BFF).

Holds the operator credentials and IdP-issued tokens server-side; the browser only ever
sees this service's /api/* routes. Everything it knows about the platform comes from the
control-plane HTTP API (services/control-plane, OpenAPI at /docs), so it is swappable: point
CP_URL / IDP_TOKEN_URL at another implementation of the same API and nothing else changes.

Personas: the demo IdP has five humans. The page can act as any persona that has a password
in the environment (STATUS_PERSONAS), so the two-approver flow can be shown from one screen.
The browser sends only a persona *name*; it is validated against the configured list.
"""
from __future__ import annotations

import asyncio
import os
import re
import time
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

CP_URL = os.environ.get("CP_URL", "http://control-plane:8100").rstrip("/")
IDP_TOKEN_URL = os.environ.get("IDP_TOKEN_URL", "http://idp:8300/token")
AUDIENCE = os.environ.get("CP_AUDIENCE", "govpilot-control-plane")
GRAFANA_URL = os.environ.get("GRAFANA_URL", "http://127.0.0.1:3400")
OPENLIT_URL = os.environ.get("OPENLIT_URL", "http://127.0.0.1:3300")
API_DOCS_URL = os.environ.get("API_DOCS_URL", "http://127.0.0.1:8100/docs")
DEFAULT_PERSONA = os.environ.get("STATUS_DEFAULT_PERSONA", "alice")
PERSONA_NAMES = [p.strip() for p in os.environ.get("STATUS_PERSONAS", "alice,bob,carol,dave,erin").split(",")
                 if p.strip()]

# Hide test-fixture agents (ids/teams like t3a-1f2e, t3dlg-...) left behind by the automated suites.
# Empty string shows everything. Purely presentational; the register is untouched.
HIDE = re.compile(os.environ.get("STATUS_HIDE_PATTERN", r"^t[0-9]")) if os.environ.get("STATUS_HIDE_PATTERN", "x") else None

app = FastAPI(title="Agent status page", docs_url=None, redoc_url=None)
_client = httpx.AsyncClient(timeout=httpx.Timeout(20.0, connect=4.0))
_tokens: dict[str, tuple[str, float]] = {}
_me: dict[str, dict] = {}
_cache: dict[str, tuple[float, Any]] = {}
_lock = asyncio.Lock()


def _password(persona: str) -> str:
    return os.environ.get(f"IDP_PASSWORD_{persona.upper()}", "")


def _available() -> list[str]:
    return [p for p in PERSONA_NAMES if _password(p)]


def _persona(request: Request) -> str:
    p = request.headers.get("x-persona") or DEFAULT_PERSONA
    if p not in _available():
        raise HTTPException(400, f"unknown persona {p!r}")
    return p


async def _token(persona: str) -> str:
    tok = _tokens.get(persona)
    if tok and tok[1] > time.time() + 60:
        return tok[0]
    async with _lock:
        tok = _tokens.get(persona)
        if tok and tok[1] > time.time() + 60:
            return tok[0]
        try:
            r = await _client.post(IDP_TOKEN_URL, data={"grant_type": "password", "username": persona,
                                                        "password": _password(persona), "audience": AUDIENCE})
        except httpx.HTTPError as e:
            raise HTTPException(503, f"identity provider unreachable: {type(e).__name__}") from e
        if r.status_code != 200:
            raise HTTPException(502, f"IdP refused token for {persona}: {r.status_code}")
        j = r.json()
        _tokens[persona] = (j["access_token"], time.time() + int(j.get("expires_in", 300)))
        return j["access_token"]


async def cp(persona: str, method: str, path: str, *, params: dict | None = None, body: Any = None) -> Any:
    for attempt in (0, 1):
        tok = await _token(persona)
        try:
            r = await _client.request(method, CP_URL + path, params=params, json=body,
                                      headers={"Authorization": f"Bearer {tok}"})
        except httpx.HTTPError as e:
            raise HTTPException(503, f"control plane unreachable: {type(e).__name__}") from e
        if r.status_code == 401 and attempt == 0:
            _tokens.pop(persona, None)
            continue
        break
    if r.status_code >= 400:
        try:
            j = r.json()
            detail = j.get("message") or j.get("detail") or r.text
        except Exception:
            detail = r.text
        raise HTTPException(r.status_code, detail if isinstance(detail, str) else str(detail))
    return r.json()


async def cached(key: str, ttl: float, fn):
    hit = _cache.get(key)
    if hit and hit[0] > time.time():
        return hit[1]
    val = await fn()
    _cache[key] = (time.time() + ttl, val)
    return val


@app.exception_handler(HTTPException)
async def _http_err(_: Request, exc: HTTPException):
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)


@app.middleware("http")
async def _csrf(request: Request, call_next):
    # State-changing calls must carry a custom header, which a cross-site form cannot set.
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get("x-requested-with") != "status-page":
        return JSONResponse({"detail": "missing X-Requested-With"}, status_code=403)
    resp = await call_next(request)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/api/config")
async def config():
    people = []
    for p in _available():
        try:
            me = _me.get(p) or await cp(p, "GET", "/v1/me")
            _me[p] = me
            people.append({"name": p, "roles": me["roles"], "teams": me.get("teams", [])})
        except HTTPException:
            people.append({"name": p, "roles": [], "teams": [], "error": True})
    return {"personas": people, "default": DEFAULT_PERSONA, "grafana": GRAFANA_URL, "openlit": OPENLIT_URL,
            "api_docs": API_DOCS_URL}


@app.get("/api/health")
async def health():
    try:
        r = await _client.get(CP_URL + "/healthz")
        return {"control_plane": r.status_code == 200}
    except httpx.HTTPError:
        return {"control_plane": False}


def _slim(a: dict) -> dict:
    keep = ("agent_id", "owner", "team", "display_name", "status", "desired_state", "max_budget_usd", "models",
            "sandbox_tier", "capabilities", "parent_agent_id", "root_agent_id", "delegation_depth",
            "quarantine_state", "created_at", "updated_at")
    d = {k: a.get(k) for k in keep}
    d["keys"] = len(a.get("gateway_keys") or [])
    d["auth"] = "sso" if a.get("oidc_subjects") else "api-key"
    return d


@app.get("/api/agents")
async def agents(request: Request):
    p = _persona(request)
    data = await cached("agents:" + p, 1.5, lambda: cp(p, "GET", "/v1/agents"))
    return {"agents": [_slim(a) for a in data["agents"]
                       if not (HIDE and (HIDE.search(a["agent_id"]) or HIDE.search(a.get("team") or "")))]}


@app.get("/api/live")
async def live(request: Request, ids: str = ""):
    """Live spend + workloads + recent audit activity for the agents that are on screen."""
    p = _persona(request)
    wanted = [i for i in ids.split(",") if i][:40]
    sem = asyncio.Semaphore(8)

    async def one(aid: str):
        async with sem:
            try:
                return aid, await cached(f"live:{aid}", 2.5, lambda: cp(p, "GET", f"/v1/agents/{aid}/live"))
            except HTTPException as e:
                return aid, {"error": e.detail}

    async def recent():
        return (await cp(p, "GET", "/v1/audit", params={"limit": 400}))["records"]

    lives = dict(await asyncio.gather(*(one(a) for a in wanted)))
    recs = await cached("recent:" + p, 2.5, recent)
    out = {}
    for aid in wanted:
        ev = [{"seq": r["seq"], "ts": r["ts"], "action": r["action"], "actor": r["actor"], "severity": r["severity"]}
              for r in recs if r["target"] == aid][-5:]
        out[aid] = {"live": lives.get(aid), "events": list(reversed(ev))}
    return out


@app.get("/api/audit")
async def audit(request: Request, limit: int = 40, since_seq: int = 0, severity: str | None = None):
    p = _persona(request)
    params: dict[str, Any] = {"limit": min(limit, 200), "since_seq": since_seq}
    if severity:
        params["severity"] = severity
    data = await cp(p, "GET", "/v1/audit", params=params)
    recs = data["records"]
    for r in recs:
        r.pop("prev_hash", None)
    return {"records": recs}


@app.get("/api/audit/verify")
async def audit_verify(request: Request):
    return await cp(_persona(request), "GET", "/v1/audit/verify")


@app.get("/api/alerts")
async def alerts(request: Request):
    p = _persona(request)
    data = await cached("alerts:" + p, 3, lambda: cp(p, "GET", "/v1/alerts", params={"limit": 5000}))
    recs = data["alerts"]
    return {"count": len(recs)}


@app.get("/api/discovery")
async def discovery(request: Request):
    p = _persona(request)
    data = await cached("disc:" + p, 1.5, lambda: cp(p, "GET", "/v1/discovery/proposals"))
    props = data["proposals"]
    pending = [x for x in props if x["status"] == "pending"]
    pending.sort(key=lambda x: x["created_at"], reverse=True)
    return {"pending": pending[:50], "pending_total": len(pending), "decided_total": len(props) - len(pending)}


def _post(path: str, cp_path: str, with_body: bool = True):
    async def handler(request: Request):
        _cache.clear()
        body = await request.json() if with_body else None
        return await cp(_persona(request), "POST", cp_path.format(**request.path_params), body=body)
    app.post(path)(handler)


_post("/api/discovery/{pid}/approve", "/v1/discovery/proposals/{pid}/approve")
_post("/api/discovery/{pid}/reject", "/v1/discovery/proposals/{pid}/reject")
_post("/api/agents/{aid}/stop", "/v1/agents/{aid}/stop")
_post("/api/agents/{aid}/resume", "/v1/agents/{aid}/resume")
_post("/api/quarantine/preview", "/v1/quarantine/preview")
_post("/api/quarantine/actions", "/v1/quarantine/actions")
_post("/api/quarantine/actions/{action_id}/approve", "/v1/quarantine/actions/{action_id}/approve", with_body=False)
_post("/api/quarantine/actions/{action_id}/lift", "/v1/quarantine/actions/{action_id}/lift")


@app.get("/api/quarantine/actions")
async def q_list(request: Request):
    data = await cp(_persona(request), "GET", "/v1/quarantine/actions")
    acts = sorted(data["actions"], key=lambda a: a.get("requested_at", 0), reverse=True)
    order = {"pending_approval": 0, "executing": 0, "executed": 1}
    acts.sort(key=lambda a: order.get(a["status"], 2))
    return {"actions": acts[:10]}


STATIC = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")
