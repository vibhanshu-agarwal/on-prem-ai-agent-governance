"""Shared helpers for the T2 budget tests (gateway client, Redis/Postgres probes)."""
from __future__ import annotations

import asyncio
import json
import pathlib
import subprocess
import time
import uuid
from dataclasses import dataclass, field

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[2]
MSG = [{"role": "user", "content": "one two three four"}]  # mock: 7 prompt tokens

# deploy/litellm/config.yaml prices (USD per token)
PRICE = {"mock-local": (1e-6, 2e-6), "mock-local-slow": (1e-6, 2e-6), "mock-remote": (5e-6, 15e-6),
         "mock-runaway": (1e-6, 2e-6), "mock-flaky": (1e-6, 2e-6), "mock-local-broken": (1e-6, 2e-6),
         "mock-local-dead": (1e-6, 2e-6)}
EPS = 1e-12


def load_env() -> dict:
    env = {}
    for line in (ROOT / "deploy" / ".env").read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    return env


ENV = load_env()


def cost(model: str, prompt_tokens: int, completion_tokens: int) -> float:
    i, o = PRICE[model]
    return prompt_tokens * i + completion_tokens * o


def sh(*args, check=False, timeout=180) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, check=check)


@dataclass
class Key:
    key: str
    token: str      # hashed token (LiteLLM's key id, used in Redis counter names)
    alias: str


@dataclass
class Gateway:
    name: str
    url: str
    redis_container: str
    pg_container: str
    container: str
    master: str = field(default_factory=lambda: ENV["LITELLM_MASTER_KEY"])
    created_keys: list = field(default_factory=list)
    created_teams: list = field(default_factory=list)

    # ------------------------------------------------------------- admin
    @property
    def admin(self) -> dict:
        return {"Authorization": f"Bearer {self.master}"}

    def new_key(self, max_budget=None, models=("mock-local",), team_id=None, metadata=None, **extra) -> Key:
        alias = f"t2-{uuid.uuid4().hex[:10]}"
        body = {"key_alias": alias, "models": list(models), **extra}
        if max_budget is not None:
            body["max_budget"] = max_budget
        if team_id:
            body["team_id"] = team_id
        if metadata:
            body["metadata"] = metadata
        r = httpx.post(f"{self.url}/key/generate", headers=self.admin, json=body, timeout=30)
        assert r.status_code == 200, r.text
        j = r.json()
        self.created_keys.append(j["key"])
        return Key(j["key"], j["token"], alias)

    def new_team(self, max_budget, metadata=None) -> str:
        r = httpx.post(f"{self.url}/team/new", headers=self.admin, timeout=30,
                       json={"team_alias": f"t2-team-{uuid.uuid4().hex[:8]}", "max_budget": max_budget,
                             "metadata": metadata or {}})
        assert r.status_code == 200, r.text
        tid = r.json()["team_id"]
        self.created_teams.append(tid)
        return tid

    def cleanup(self) -> None:
        if self.created_keys:
            httpx.post(f"{self.url}/key/delete", headers=self.admin, json={"keys": self.created_keys}, timeout=30)
        if self.created_teams:
            httpx.post(f"{self.url}/team/delete", headers=self.admin, json={"team_ids": self.created_teams},
                       timeout=30)
        self.created_keys, self.created_teams = [], []

    def key_info(self, key: str) -> dict:
        r = httpx.get(f"{self.url}/key/info", headers=self.admin, params={"key": key}, timeout=30)
        return r.json().get("info", {})

    def wait_ready(self, timeout=180) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = httpx.get(f"{self.url}/health/readiness", timeout=5)
                if r.status_code == 200 and r.json().get("db") == "connected":
                    return
            except Exception:
                pass
            time.sleep(2)
        raise TimeoutError(f"{self.name} not ready")

    def wait_budget_enforcement(self, timeout=180) -> float:
        """Block until a budgeted request is served (e.g. Redis circuit breaker closed again
        after an outage). Returns seconds waited."""
        t0 = time.time()
        self.wait_ready(timeout=timeout)
        probe = self.new_key(max_budget=1.0)
        while time.time() - t0 < timeout:
            try:
                r = httpx.post(f"{self.url}/v1/chat/completions", headers={"Authorization": f"Bearer {probe.key}"},
                               json={"model": "mock-local", "messages": MSG, "max_tokens": 1}, timeout=60)
                if r.status_code == 200:
                    return time.time() - t0
            except httpx.HTTPError:
                pass
            time.sleep(3)
        raise TimeoutError(f"{self.name}: budget enforcement did not recover")

    # ------------------------------------------------------------- state probes
    def redis(self, *args) -> str:
        return sh("docker", "exec", self.redis_container, "redis-cli", "-a", ENV["REDIS_PASSWORD"],
                  "--no-auth-warning", *args).stdout.strip()

    def counter(self, kind: str, ident: str) -> float:
        v = self.redis("GET", f"spend:{kind}:{ident}")
        return float(v) if v else 0.0

    def counter_ttl(self, kind: str, ident: str) -> int:
        return int(self.redis("TTL", f"spend:{kind}:{ident}") or -2)

    def sql(self, q: str) -> str:
        return sh("docker", "exec", self.pg_container, "psql", "-U", "litellm", "-d", "litellm", "-tA", "-c",
                  q).stdout.strip()

    def spend_logs_total(self, token: str) -> tuple[float, int]:
        out = self.sql(f"select coalesce(sum(spend),0), count(*) from \"LiteLLM_SpendLogs\" "
                       f"where api_key='{token}' and spend > 0")
        s, n = out.split("|")
        return float(s), int(n)

    def budget_events(self, since: float | None = None) -> list[dict]:
        out = sh("docker", "logs", self.container).stdout + sh("docker", "logs", self.container).stderr
        evs = []
        for line in out.splitlines():
            if "GOVPILOT_BUDGET_EVENT " in line:
                try:
                    e = json.loads(line.split("GOVPILOT_BUDGET_EVENT ", 1)[1])
                except json.JSONDecodeError:
                    continue
                if since is None or e.get("ts", 0) >= since:
                    evs.append(e)
        return evs

    # ------------------------------------------------------------- calls
    async def chat(self, client: httpx.AsyncClient, key: Key | str, **body) -> httpx.Response:
        k = key.key if isinstance(key, Key) else key
        payload = {"model": "mock-local", "messages": MSG, **body}
        payload = {a: b for a, b in payload.items() if b is not None}
        return await client.post(f"{self.url}/v1/chat/completions", headers={"Authorization": f"Bearer {k}"},
                                 json=payload)

    async def stream(self, client: httpx.AsyncClient, key: Key, stop_after=None, on_first=None, **body) -> dict:
        payload = {"model": "mock-local", "messages": MSG, "stream": True,
                   "stream_options": {"include_usage": True}, **body}
        out = {"status": None, "chunks": 0, "usage": None, "finish": None, "error": None}
        async with client.stream("POST", f"{self.url}/v1/chat/completions",
                                 headers={"Authorization": f"Bearer {key.key}"}, json=payload) as r:
            out["status"] = r.status_code
            if r.status_code != 200:
                out["error"] = (await r.aread()).decode()[:400]
                return out
            async for line in r.aiter_lines():
                if not line.startswith("data: ") or line == "data: [DONE]":
                    continue
                d = json.loads(line[6:])
                if "error" in d:
                    out["error"] = d["error"]
                if d.get("usage"):
                    out["usage"] = d["usage"]
                for ch in d.get("choices") or []:
                    if (ch.get("delta") or {}).get("content"):
                        out["chunks"] += 1
                        if out["chunks"] == 1 and on_first:
                            await on_first()
                    if ch.get("finish_reason"):
                        out["finish"] = ch["finish_reason"]
                if stop_after and out["chunks"] >= stop_after:
                    break
        return out


def resp_cost(r: httpx.Response) -> float:
    return float(r.headers.get("x-litellm-response-cost") or 0.0) if r.status_code == 200 else 0.0


def error_of(r: httpx.Response) -> dict:
    try:
        return r.json().get("error", {})
    except Exception:
        return {"message": r.text}


async def gather_limited(coros, limit=64):
    sem = asyncio.Semaphore(limit)

    async def run(c):
        async with sem:
            return await c
    return await asyncio.gather(*(run(c) for c in coros))
