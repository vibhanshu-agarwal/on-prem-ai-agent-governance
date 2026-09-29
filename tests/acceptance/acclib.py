"""Shared helpers for the T8 acceptance suite (report section 8 + the July minimum criteria).

Reuses the T3 client helpers (tests/control/cpclient.py) for IdP logins, the control-plane API and the gateway
admin API. Every throwaway container made here carries the label `govpilot.t8test=1` (scripts/down.sh and the
suite's own cleanup remove them); every throwaway agent is registered in a team whose name starts with `t8`.
Measured numbers go to .local/acceptance/results.json through the `record` fixture (see conftest.py).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import threading
import time
import uuid
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "control"))
sys.path.insert(0, str(ROOT / "services" / "control-plane"))
import cpclient  # noqa: E402

ENV = cpclient.ENV
GW_URL, CP_URL, AUTHPROXY_URL, ESTOP_URL = cpclient.GW_URL, cpclient.CP_URL, cpclient.AUTHPROXY_URL, cpclient.ESTOP_URL
AGENTS_NET, SSO_NET = cpclient.AGENTS_NET, cpclient.SSO_NET
DRILL_IMAGE = cpclient.AGENT_IMAGE            # govpilot/control-plane:1 carries the rogue sample agent + python
PROBE_IMAGE = "govpilot/mock-provider:1"       # python + fastapi/uvicorn/httpx
T8_LABEL = {"govpilot.t8test": "1"}
RESULTS = ROOT / ".local" / "acceptance"
# Git Bash, not C:\Windows\System32ash.exe (WSL), which subprocess would find first for a bare "bash"
import shutil as _shutil
BASH = os.environ.get("GIT_BASH") or _shutil.which("bash") or "bash"


def uid(prefix="t8") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6]}"


def dclient():
    return cpclient.dclient()


def gw_admin() -> httpx.Client:
    return cpclient.gw_admin()


def key_hash(raw_key: str) -> str:
    return hashlib.sha256(raw_key.encode()).hexdigest()


def chat(key: str, model="mock-local", base=GW_URL, max_tokens=2, content="hi", run_id=None, timeout=30,
         **extra) -> httpx.Response:
    h = {"Authorization": f"Bearer {key}", "x-govpilot-run-id": run_id or f"run-{uuid.uuid4().hex[:16]}"}
    return httpx.post(f"{base}/v1/chat/completions", headers=h, timeout=timeout,
                      json={"model": model, "max_tokens": max_tokens,
                            "messages": [{"role": "user", "content": content}], **extra})


def wait_until(fn, timeout=15.0, interval=0.25):
    return cpclient.wait_until(fn, timeout=timeout, interval=interval)


def wait_for_log(container, pattern, timeout=40.0):
    return cpclient.wait_for_log(container, pattern, timeout=timeout)


def events(container):
    return cpclient.parse_events(container.logs().decode(errors="replace"))


def healthy(name: str) -> bool:
    try:
        c = dclient().containers.get(name)
        return (c.attrs.get("State", {}).get("Health") or {}).get("Status") == "healthy"
    except Exception:  # noqa: BLE001
        return False


def wait_healthy(*names, timeout=180):
    assert wait_until(lambda: all(healthy(n) for n in names), timeout=timeout, interval=1.0), \
        f"not healthy after {timeout}s: {[n for n in names if not healthy(n)]}"


# --------------------------------------------------------------------------------------- drill agents
class Drill:
    """Registers throwaway agents through the control-plane API and runs drill containers; cleans up after."""

    def __init__(self, alice):
        self.alice = alice
        self.agents: list[dict] = []
        self.containers = []
        self.extra_keys: list[str] = []

    def agent(self, team: str, models=("mock-local", "mock-local-slow"), budget=1.0, passthrough=True, **extra):
        agent_id = extra.pop("agent_id", None) or uid("t8a")
        body = {"agent_id": agent_id, "team": team, "owner": "alice", "max_budget_usd": budget,
                "models": list(models), "sandbox_tier": extra.pop("sandbox_tier", "container"), **extra}
        r = self.alice.post("/v1/agents", body)
        assert r.status_code == 201, r.text
        ag = r.json()
        if passthrough:
            cpclient.mark_drill_keys([k["key_hash"] for k in ag["agent"]["gateway_keys"]])
        self.agents.append(ag)
        return ag

    def run(self, ag: dict, env: dict | None = None, network=AGENTS_NET, labels: dict | None = None,
            restart="always", name=None, image=DRILL_IMAGE, command=None):
        a = ag["agent"]
        base_env = {"GATEWAY_URL": "http://gateway:4000", "AGENT_KEY": ag.get("gateway_key", ""),
                    "MODEL": "mock-local-slow", "MAX_TOKENS": "200"}
        lab = {"govpilot.agent_id": a["agent_id"], "govpilot.team": a["team"], "govpilot.root_agent_id": a["agent_id"],
               **T8_LABEL, **(labels or {})}
        c = dclient().containers.run(image, command=command or ["python", "-u", "-m", "govcp.tools.sample_agent"],
                                     name=name or f"t8-agent-{a['agent_id']}", detach=True, labels=lab,
                                     environment={**base_env, **(env or {})}, network=network,
                                     restart_policy={"Name": restart})
        self.containers.append(c)
        return c

    def container(self, name, image=PROBE_IMAGE, command=None, network=AGENTS_NET, labels=None, env=None,
                  entrypoint=None, restart="no"):
        c = dclient().containers.run(image, command=command, name=name, detach=True, entrypoint=entrypoint,
                                     labels={**T8_LABEL, **(labels or {})}, environment=env or {},
                                     network=network, restart_policy={"Name": restart})
        self.containers.append(c)
        return c

    def cleanup(self):
        for c in self.containers:
            try:
                c.remove(force=True)
            except Exception:  # noqa: BLE001
                pass
        hashes = list(self.extra_keys)
        for ag in self.agents:
            hashes += [k["key_hash"] for k in ag["agent"].get("gateway_keys", [])]
            try:
                live = self.alice.get(f"/v1/agents/{ag['agent']['agent_id']}/live").json()
                for d in live.get("delegates", []):
                    hashes += [k["key_hash"] for k in self.alice.get(f"/v1/agents/{d}").json()["gateway_keys"]]
            except Exception:  # noqa: BLE001
                pass
        if hashes:
            gw_admin().post("/key/delete", json={"keys": hashes})


class DenialProbe(cpclient.DenialProbe):
    pass


def cleanup_t8_containers():
    d = dclient()
    for c in d.containers.list(all=True, filters={"label": "govpilot.t8test=1"}):
        try:
            c.remove(force=True)
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------------------- spend logs
def spend_rows(key_hash_: str | None = None, since_s: float = 900) -> list[dict]:
    sys.path.insert(0, str(ROOT / "scripts"))
    from datetime import datetime, timedelta, timezone
    from attribution_report import fetch_rows
    now = datetime.now(timezone.utc)
    rows = fetch_rows(GW_URL, ENV["LITELLM_MASTER_KEY"], now - timedelta(seconds=since_s), now + timedelta(minutes=1))
    if key_hash_:
        rows = [r for r in rows if r.get("api_key") == key_hash_]
    return rows


def key_info(key_hash_: str) -> dict:
    return gw_admin().get("/key/info", params={"key": key_hash_}).json().get("info") or {}


def mint_key(alias=None, budget=0.05, models=("mock-local",), metadata=None, **extra) -> dict:
    r = gw_admin().post("/key/generate", json={"key_alias": alias or uid("t8k"), "models": list(models),
                                                "max_budget": budget, "metadata": metadata or {}, **extra})
    r.raise_for_status()
    return r.json()


def delete_keys(*hashes):
    if hashes:
        gw_admin().post("/key/delete", json={"keys": list(hashes)})


def pct(values, p):
    v = sorted(values)
    if not v:
        return 0.0
    k = (len(v) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(v) - 1)
    return v[f] + (v[c] - v[f]) * (k - f)


def redis_cli(*args, container="gov-redis") -> str:
    c = dclient().containers.get(container)
    pw = next(e.split("=", 1)[1] for e in c.attrs["Config"]["Env"] if e.startswith("REDIS_PASSWORD="))
    return c.exec_run(["redis-cli", "-a", pw, "--no-auth-warning", *args]).output.decode().strip()


def save_json(name: str, data) -> Path:
    RESULTS.mkdir(parents=True, exist_ok=True)
    p = RESULTS / name
    p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return p


def read_env_file(p: Path) -> dict:
    out = {}
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def agent_keys() -> dict:
    return json.loads((ROOT / ".local" / "agent-keys.json").read_text())["agents"]


def strip_ansi(s: str) -> str:
    return re.sub(r"\x1b\[[0-9;]*m", "", s)


__all__ = [n for n in dir() if not n.startswith("_")] + ["os", "time", "threading", "json", "httpx", "cpclient"]
