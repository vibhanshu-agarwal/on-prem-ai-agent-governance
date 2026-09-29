"""Mock tool gateway (T8 test fixture for S8-10 'in-window harm').

Stands in for the systems an agent can change the world through: an e-mail relay (`email.send`) and a database
(`db.write`). Each call does its work first (TOOL_WORK_MS: compose the mail, prepare the row), then asks the
control plane at COMMIT time whether the agent may act (`POST /v1/actions/authorize`, authenticated as the
IdP client `tool-gateway`), and only then commits (appends to its outbox / table). The agent is identified by the
gateway virtual key it presents (the tool gateway only sees its SHA-256). Control plane unreachable = fail closed.

Runs inside govpilot/control-plane:1 (fastapi, uvicorn, httpx); the code is passed in the TOOL_SRC env var.
GET /log returns every attempt with its receive / authorize / commit timestamps.
"""
import asyncio
import hashlib
import os
import time

import httpx
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

app = FastAPI()
LOG: list = []
CP = os.environ.get("CP_URL", "http://control-plane:8100")
TOKEN_URL = os.environ.get("IDP_TOKEN_URL", "http://idp:8300/token")
WORK_S = int(os.environ.get("TOOL_WORK_MS", "150")) / 1000
_tok = {"v": None, "exp": 0.0}
client = httpx.AsyncClient(timeout=5)


async def token() -> str:
    if _tok["v"] and time.time() < _tok["exp"] - 30:
        return _tok["v"]
    r = await client.post(TOKEN_URL, data={"grant_type": "client_credentials", "client_id": os.environ["CLIENT_ID"],
                                           "client_secret": os.environ["CLIENT_SECRET"],
                                           "audience": "govpilot-control-plane"})
    r.raise_for_status()
    d = r.json()
    _tok["v"], _tok["exp"] = d["access_token"], time.time() + int(d.get("expires_in", 300))
    return _tok["v"]


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/log")
def log():
    return {"attempts": LOG}


@app.post("/tools/{action}")
async def act(action: str, req: Request):
    rec = {"action": action, "received_at": time.time()}
    auth = req.headers.get("authorization", "")
    key = auth.split(" ", 1)[1] if " " in auth else ""
    body = await req.json()
    await asyncio.sleep(WORK_S)                                  # the tool does its work before committing
    rec["authorize_at"] = time.time()
    try:
        r = await client.post(CP + "/v1/actions/authorize", headers={"Authorization": "Bearer " + await token()},
                              json={"key_hash": hashlib.sha256(key.encode()).hexdigest(), "action": action,
                                    "target": str(body.get("to") or body.get("table") or "")[:80]})
    except Exception as e:  # noqa: BLE001 - control plane unreachable: fail closed
        rec.update(outcome="unavailable", error=type(e).__name__)
        LOG.append(rec)
        return JSONResponse({"error": "authorization unavailable (fail closed)"}, status_code=503)
    if r.status_code != 200:
        rec.update(outcome="denied", status=r.status_code)
        LOG.append(rec)
        return JSONResponse({"error": "not authorized", "detail": r.text[:200]}, status_code=403)
    d = r.json()
    rec.update(outcome="committed", committed_at=time.time(), agent_id=d["agent_id"], decided_at=d["decided_at"],
               state_read_at=d["state_read_at"],
               decision_id=d["decision_id"])
    LOG.append(rec)
    return {"ok": True, "decision_id": d["decision_id"]}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000, log_level="warning")
