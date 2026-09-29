"""Emergency-stop HTTP service. Own credential (ESTOP_TOKEN_SHA256), no dependency on the
control-plane API, its database or the IdP. Every call is journaled (hash-chained JSONL)."""
from __future__ import annotations

import hashlib
import hmac
import os

from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from ..adapters.docker_orchestrator import DockerNetworkQuarantine, DockerOrchestrator
from ..adapters.jsonl_audit import JsonlAuditSink
from ..adapters.litellm_gateway import LiteLLMGatewayAdmin
from .core import EmergencyStop

TOKEN_SHA = os.environ.get("ESTOP_TOKEN_SHA256", "")
journal = JsonlAuditSink(os.environ.get("ESTOP_JOURNAL", "/data/estop/journal.jsonl"))
es = EmergencyStop(
    gateway=LiteLLMGatewayAdmin(os.environ.get("GATEWAY_URL", "http://gateway:4000"),
                                os.environ["LITELLM_MASTER_KEY"]),
    orchestrator=DockerOrchestrator(),
    network=DockerNetworkQuarantine(
        governed_networks=os.environ.get("ESTOP_GOVERNED_NETWORKS", "govpilot_agents,govpilot_agents_sso").split(","),
        chokepoints=[c for c in os.environ.get("ESTOP_CHOKEPOINTS", "gov-gateway,gov-authproxy").split(",") if c],
        helper_image=os.environ.get("ESTOP_HELPER_IMAGE", "govpilot/control-plane:1"),
        drain_timeout_s=float(os.environ.get("ESTOP_DRAIN_TIMEOUT_S", "3"))),
    journal=journal)

app = FastAPI(title="govpilot emergency stop", version="0.1.0")


class StopIn(BaseModel):
    reason: str = Field(min_length=1)


def _auth(authorization: str | None, operator: str | None):
    if not TOKEN_SHA or not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "estop token required")
    got = hashlib.sha256(authorization[len("Bearer "):].encode()).hexdigest()
    if not hmac.compare_digest(got, TOKEN_SHA):
        journal.append(operator or "unknown", "estop.auth_failed", "estop", {}, severity="alert")
        raise HTTPException(401, "bad estop token")
    if not operator:
        raise HTTPException(400, "X-Estop-Operator header (who is pulling the brake) is required")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.post("/estop/agents/{agent_id}")
def stop_agent(agent_id: str, body: StopIn, authorization: str | None = Header(None),
               x_estop_operator: str | None = Header(None)):
    _auth(authorization, x_estop_operator)
    return es.stop_agent(agent_id, x_estop_operator, body.reason)


@app.post("/estop/teams/{team}")
def stop_team(team: str, body: StopIn, authorization: str | None = Header(None),
              x_estop_operator: str | None = Header(None)):
    _auth(authorization, x_estop_operator)
    return es.stop_team(team, x_estop_operator, body.reason)


@app.get("/estop/journal")
def get_journal(limit: int = 50, authorization: str | None = Header(None),
                x_estop_operator: str | None = Header(None)):
    _auth(authorization, x_estop_operator)
    return {"verify": journal.verify().to_dict(), "records": [r.to_dict() for r in journal.list(limit=limit)]}
