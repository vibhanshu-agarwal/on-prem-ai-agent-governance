"""Control-plane HTTP API (FastAPI). OpenAPI at /docs and /openapi.json.

Every route except /healthz requires a bearer JWT from the IdP (audience
`govpilot-control-plane`). Roles come from the token: admin, operator, approver,
owner (+teams), feed, authproxy.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time
from contextlib import asynccontextmanager
from typing import Any, Literal

from fastapi import Depends, FastAPI, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ..config import load_config
from ..domain import audit as chain
from ..domain.errors import DomainError, Forbidden, NotFound, Unauthorized
from ..domain.models import (DESIRED_STOPPED, STATUS_STOPPED, AuditRecord, DiscoveryObservation, Principal,
                             Selector)
from ..domain.repository import ACTIONS, KV, STOP_REPORTS
from ..wiring import App, build_app

log = logging.getLogger("govcp")
AUDIENCE = os.environ.get("GOVCP_AUDIENCE", "govpilot-control-plane")
STATE: dict[str, Any] = {}


def app_() -> App:
    return STATE["app"]


# ------------------------------------------------------------------ models
class CredentialIn(BaseModel):
    kind: str = Field(description="db | tool | mcp | queue | api")
    ref: str | None = Field(None, description="SecretStore path; default creds/<agent>/<kind>")
    value: str | None = Field(None, description="If given, stored in the SecretStore (never in the register)")
    description: str = ""


class AgentCreate(BaseModel):
    agent_id: str
    team: str
    owner: str | None = None
    display_name: str = ""
    max_budget_usd: float = 0.0
    budget_duration: str | None = "30d"
    models: list[str] = []
    provision_key: bool = Field(True, description="Create a per-agent LiteLLM virtual key")
    link_key_aliases: list[str] = Field([], description="Link existing gateway keys instead of provisioning")
    oidc_subjects: list[str] = Field([], description="IdP subjects (client ids) that resolve to this agent")
    credentials: list[CredentialIn] = []
    sandbox_tier: Literal["container", "gvisor", "microvm"] = "container"
    capabilities: list[str] = []
    labels: dict[str, str] = {}
    workload_labels: dict[str, str] | None = Field(None, description="Container label selector; default "
                                                                     "{govpilot.agent_id: <agent_id>}")


class ReasonIn(BaseModel):
    reason: str = Field(min_length=1)


class SelectorIn(BaseModel):
    team: str | None = None
    image: str | None = None
    labels: dict[str, str] = {}
    host: str | None = None
    agent_ids: list[str] = []
    all: bool = False


class ExecuteIn(BaseModel):
    preview_id: str
    reason: str = Field(min_length=1)


class LiftIn(BaseModel):
    resume_agents: bool = True


class ProposalIn(BaseModel):
    fingerprint: str
    kind: Literal["workload", "identity", "traffic"] = "workload"
    name: str = ""
    image: str | None = None
    labels: dict[str, str] = {}
    suggested_team: str | None = None
    suggested_owner: str | None = None
    evidence: dict[str, Any] = {}
    feed: str | None = Field(None, description="Admin only: submit on behalf of a named feed")


class ProposalApprove(BaseModel):
    agent_id: str | None = None
    team: str | None = None
    owner: str | None = None
    max_budget_usd: float = Field(0.0, ge=0)
    models: list[str] = []
    sandbox_tier: Literal["container", "gvisor", "microvm"] = "container"
    capabilities: list[str] = []
    workload_labels: dict[str, str] | None = None
    oidc_subjects: list[str] = []


class DelegationIn(BaseModel):
    parent_token: str = Field(description="The parent agent's delegation (macaroon) token")
    name: str = Field(description="Sub-agent name; the child id becomes <parent>.<name>")
    max_budget_usd: float
    models: list[str]
    ttl_s: float | None = None
    capabilities: list[str] | None = None


class ResolveIn(BaseModel):
    kind: Literal["oidc", "delegation"]
    subject: str | None = None
    issuer: str | None = None
    token: str | None = None
    model: str | None = None


# ------------------------------------------------------------------ auth
bearer = HTTPBearer(auto_error=False)


def principal(creds: HTTPAuthorizationCredentials | None = Depends(bearer)) -> Principal:
    if creds is None:
        raise Unauthorized("bearer token required")
    return app_().ports.identity.verify(creds.credentials, AUDIENCE)


def require(p: Principal, *roles: str):
    if not p.has_role(*roles):
        raise Forbidden(f"requires one of roles {list(roles)}")


# ------------------------------------------------------------------ startup
def seed_agents(a: App) -> None:
    system = Principal(subject="seed", roles=["admin"], kind="client")
    for spec in a.config.get("seed_agents") or []:
        if a.register.find(spec["agent_id"]):
            continue
        try:
            a.register.register(dict(spec), system, audit_action="agent.seeded")
            log.info("seeded agent %s", spec["agent_id"])
        except DomainError as e:
            log.warning("seed %s skipped: %s", spec["agent_id"], e.message)


def ingest_estop_journal(a: App) -> int:
    """Pull entries written by the emergency-stop path while we were down into the main audit log."""
    path = a.config.get("estop", {}).get("journal_path")
    if not path or not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8") as f:
        recs = [AuditRecord(**json.loads(x)) for x in f if x.strip()]
    v = chain.verify_chain(recs)
    if not v.ok:
        a.ports.audit.append("estop-ingest", "estop.journal_tampered", path, v.to_dict(), severity="alert")
        return 0
    cur = a.ports.repo.get(KV, "estop_ingest") or {"seq": 0}
    n = 0
    for r in recs:
        if r.seq <= cur["seq"]:
            continue
        a.ports.audit.append(f"estop:{r.actor}", "estop.ingested", r.target, {
            "journal_seq": r.seq, "journal_hash": r.hash, "journal_ts": r.ts, "action": r.action,
            "details": r.details}, severity="warning")
        if r.action == "estop.agent_stopped" and a.register.find(r.target):
            def mark(x):
                x.status = STATUS_STOPPED
                x.desired_state = DESIRED_STOPPED
            a.register.mutate(r.target, mark)
        n += 1
    if recs:
        a.ports.repo.put(KV, "estop_ingest", {"seq": recs[-1].seq, "hash": recs[-1].hash})
    return n


def _reconcile_loop(a: App, interval: float, stop_evt: threading.Event):
    while not stop_evt.wait(interval):
        try:
            a.reconciler.run_once()
            if int(time.time()) % 10 == 0:
                ingest_estop_journal(a)
        except Exception as e:  # noqa: BLE001
            log.warning("reconcile error: %s", e)


@asynccontextmanager
async def lifespan(_: FastAPI):
    if "app" not in STATE:
        cfg = load_config()
        STATE["app"] = build_app(cfg)
    a = app_()
    a.ports.audit.append("control-plane", "service.started", "control-plane", {"pid": os.getpid()})
    try:
        seed_agents(a)
    except Exception as e:  # noqa: BLE001 - the gateway may still be starting
        log.warning("seeding failed: %s", e)
    ingest_estop_journal(a)
    evt = threading.Event()
    rc = a.config.get("reconciler", {})
    if rc.get("enabled", True):
        threading.Thread(target=_reconcile_loop, args=(a, float(rc.get("interval_s", 1.0)), evt),
                         daemon=True).start()
    yield
    evt.set()


api = FastAPI(title="govpilot control plane", version="0.1.0", lifespan=lifespan,
              description="Agent identity register, stop sequence, bulk quarantine, discovery queue, "
                          "delegation attenuation and append-only audit for AI agents behind LiteLLM.")
app = api


@api.exception_handler(DomainError)
async def _domain_error(_: Request, e: DomainError):
    return JSONResponse(status_code=e.status, content={"error": e.code, "message": e.message, "details": e.details})


@api.get("/healthz", tags=["meta"])
def healthz():
    return {"ok": True}


@api.get("/v1/me", tags=["meta"])
def me(p: Principal = Depends(principal)):
    return {"subject": p.subject, "roles": p.roles, "teams": p.teams, "kind": p.kind}


# ------------------------------------------------------------------ agents
@api.post("/v1/agents", tags=["agents"], status_code=201)
def create_agent(body: AgentCreate, p: Principal = Depends(principal)):
    spec = body.model_dump()
    spec["credentials"] = [c.model_dump() for c in body.credentials]
    res = app_().register.register(spec, p)
    return {"agent": res["agent"].to_dict(), "gateway_key": res["gateway_key"],
            "delegation_token": res["delegation_token"],
            "note": "gateway_key and delegation_token are shown once"}


@api.get("/v1/agents", tags=["agents"])
def list_agents(team: str | None = None, status: str | None = None, p: Principal = Depends(principal)):
    return {"agents": [a.to_dict() for a in app_().register.list(team=team, status=status)]}


@api.get("/v1/agents/{agent_id}", tags=["agents"])
def get_agent(agent_id: str, p: Principal = Depends(principal)):
    return app_().register.get(agent_id).to_dict()


@api.get("/v1/agents/{agent_id}/live", tags=["agents"], summary="Live status: keys, spend, workloads")
def live(agent_id: str, p: Principal = Depends(principal)):
    a = app_()
    ag = a.register.get(agent_id)
    keys = []
    for k in ag.gateway_keys:
        st = a.ports.gateway.key_status(k.key_hash)
        keys.append({"alias": k.alias, "blocked": st.blocked if st else None, "spend": st.spend if st else None,
                     "max_budget": st.max_budget if st else None})
    wl = a.ports.orchestrator.list_workloads(labels=ag.workload_labels)
    return {"agent_id": agent_id, "status": ag.status, "desired_state": ag.desired_state, "team": ag.team,
            "keys": keys, "spend_usd": sum(k["spend"] or 0 for k in keys), "max_budget_usd": ag.max_budget_usd,
            "workloads": [{"name": w.name, "running": w.running, "restart_policy": w.restart_policy,
                           "networks": w.networks, "image": w.image} for w in wl],
            "delegates": [d.agent_id for d in a.register.descendants(agent_id)]}


@api.post("/v1/agents/{agent_id}/stop", tags=["stop"], summary="Run the full stop sequence for one agent")
def stop_agent(agent_id: str, body: ReasonIn, p: Principal = Depends(principal)):
    require(p, "operator")
    a = app_()
    ag = a.register.get(agent_id)
    if not (p.has_role("operator") or p.owns_team(ag.team)):
        raise Forbidden("not allowed")
    return a.stop.stop([agent_id], p.subject, body.reason)


@api.post("/v1/agents/{agent_id}/resume", tags=["stop"], summary="Reverse a stop/quarantine (creds stay revoked)")
def resume_agent(agent_id: str, body: ReasonIn, p: Principal = Depends(principal)):
    require(p, "operator")
    return app_().stop.resume(agent_id, p.subject, body.reason)


@api.get("/v1/stops", tags=["stop"])
def list_stops(limit: int = 20, p: Principal = Depends(principal)):
    reps = sorted(app_().ports.repo.list(STOP_REPORTS), key=lambda r: r["started_at"], reverse=True)[:limit]
    return {"stops": [{k: r[k] for k in ("stop_id", "actor", "reason", "agents", "timings_ms", "within_target")}
                      | {"verified": r["verify"]["ok"]} for r in reps]}


@api.get("/v1/stops/{stop_id}", tags=["stop"])
def get_stop(stop_id: str, p: Principal = Depends(principal)):
    r = app_().ports.repo.get(STOP_REPORTS, stop_id)
    if not r:
        raise NotFound("no such stop")
    return r


# ------------------------------------------------------------------ quarantine
@api.post("/v1/quarantine/preview", tags=["quarantine"], summary="Blast-radius preview for a selector")
def q_preview(body: SelectorIn, p: Principal = Depends(principal)):
    return app_().quarantine.preview(Selector(**body.model_dump()), p)


@api.post("/v1/quarantine/actions", tags=["quarantine"], summary="Fire a previewed quarantine (human-triggered)")
def q_execute(body: ExecuteIn, p: Principal = Depends(principal)):
    return app_().quarantine.execute(body.preview_id, p, body.reason)


@api.get("/v1/quarantine/actions", tags=["quarantine"])
def q_list(p: Principal = Depends(principal)):
    acts = sorted(app_().ports.repo.list(ACTIONS), key=lambda x: x["requested_at"], reverse=True)
    return {"actions": [{k: v for k, v in x.items() if k != "report"} for x in acts]}


@api.get("/v1/quarantine/actions/{action_id}", tags=["quarantine"])
def q_get(action_id: str, p: Principal = Depends(principal)):
    x = app_().ports.repo.get(ACTIONS, action_id)
    if not x:
        raise NotFound("no such action")
    return x


@api.post("/v1/quarantine/actions/{action_id}/approve", tags=["quarantine"], summary="Dual-control approval")
def q_approve(action_id: str, p: Principal = Depends(principal)):
    return app_().quarantine.approve(action_id, p)


@api.post("/v1/quarantine/actions/{action_id}/lift", tags=["quarantine"], summary="Reverse a quarantine")
def q_lift(action_id: str, body: LiftIn, p: Principal = Depends(principal)):
    return app_().quarantine.lift(action_id, p, body.resume_agents)


@api.get("/v1/quarantine/rules", tags=["quarantine"])
def q_rules(p: Principal = Depends(principal)):
    return {"rules": app_().quarantine.active_rules()}


# ------------------------------------------------------------------ discovery
@api.post("/v1/discovery/proposals", tags=["discovery"], status_code=201,
          summary="Feeds submit observations; they land pending with zero budget")
def d_submit(body: ProposalIn, p: Principal = Depends(principal)):
    if not p.has_role("feed"):
        raise Forbidden("feed role required")
    feed = body.feed if (body.feed and "admin" in p.roles) else p.subject
    obs = DiscoveryObservation(**body.model_dump(exclude={"feed"}))
    return app_().discovery.submit(feed, obs, submitted_by=p.subject)


@api.get("/v1/discovery/proposals", tags=["discovery"])
def d_list(status: str | None = Query(None), p: Principal = Depends(principal)):
    return {"proposals": app_().discovery.list(status)}


@api.post("/v1/discovery/proposals/{pid}/approve", tags=["discovery"], summary="Owner approval (creates the key)")
def d_approve(pid: str, body: ProposalApprove, p: Principal = Depends(principal)):
    return app_().discovery.approve(pid, p, body.model_dump())


@api.post("/v1/discovery/proposals/{pid}/reject", tags=["discovery"])
def d_reject(pid: str, body: ReasonIn, p: Principal = Depends(principal)):
    return app_().discovery.reject(pid, p, body.reason)


# ------------------------------------------------------------------ delegation
@api.post("/v1/delegations", tags=["delegation"], status_code=201,
          summary="Mint a sub-agent credential by attenuating the parent's token")
def mint(body: DelegationIn):
    # The parent's capability token is the credential here (macaroon bearer), not a JWT.
    return app_().delegation.mint_child(body.parent_token, body.model_dump(exclude={"parent_token"}))


# ------------------------------------------------------------------ internal (auth proxy)
@api.post("/v1/internal/resolve", tags=["internal"], summary="Map an authenticated caller to its per-agent key")
def resolve(body: ResolveIn, p: Principal = Depends(principal)):
    require(p, "authproxy")
    a = app_()
    if body.kind == "oidc":
        if not body.subject:
            raise Forbidden("subject required")
        return a.access.resolve_subject(body.subject, body.issuer)
    if not body.token:
        raise Forbidden("token required")
    return a.access.resolve_delegation(body.token, body.model)


# ------------------------------------------------------------------ audit
@api.get("/v1/audit", tags=["audit"])
def audit_list(limit: int = 100, since_seq: int = 0, action_prefix: str | None = None,
               severity: str | None = None, target: str | None = None, p: Principal = Depends(principal)):
    recs = app_().ports.audit.list(limit=limit, since_seq=since_seq, action_prefix=action_prefix,
                                   severity=severity, target=target)
    return {"records": [r.to_dict() for r in recs]}


@api.get("/v1/audit/verify", tags=["audit"], summary="Recompute the hash chain")
def audit_verify(p: Principal = Depends(principal)):
    return app_().ports.audit.verify().to_dict()


@api.get("/v1/alerts", tags=["audit"], summary="Audit records with severity=alert")
def alerts(limit: int = 50, since_seq: int = 0, p: Principal = Depends(principal)):
    return {"alerts": [r.to_dict() for r in app_().ports.audit.list(limit=limit, since_seq=since_seq,
                                                                  severity="alert")]}


@api.post("/v1/admin/estop-ingest", tags=["audit"], summary="Ingest the emergency-stop journal now")
def estop_ingest(p: Principal = Depends(principal)):
    require(p, "operator")
    return {"ingested": ingest_estop_journal(app_())}
