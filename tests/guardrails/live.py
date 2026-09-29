"""Helpers for tests that run against the live govpilot stack."""
import json
import pathlib
import subprocess
import time
import uuid

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[2]
STATE = ROOT / ".local" / "guardrails"
COMPOSE = ["docker", "compose", "-p", "govpilot", "--env-file", str(ROOT / "deploy" / ".env"),
           "-f", str(ROOT / "deploy" / "docker-compose.yml"),
           "-f", str(ROOT / "tests" / "guardrails" / "stack" / "compose.echo.yml"),
           "-f", str(ROOT / "tests" / "guardrails" / "stack" / "compose.down.yml")]


def sh(*args, check=True, timeout=300):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, check=check)


def load_env() -> dict:
    return dict(l.split("=", 1) for l in (ROOT / "deploy" / ".env").read_text().splitlines()
                if "=" in l and not l.startswith("#"))


def wait_healthy(container: str, timeout=180):
    end = time.time() + timeout
    while time.time() < end:
        r = sh("docker", "inspect", "-f", "{{.State.Health.Status}}", container, check=False)
        if r.stdout.strip() == "healthy":
            return
        time.sleep(2)
    raise TimeoutError(f"{container} not healthy")


class Gateway:
    def __init__(self, base: str, master: str):
        self.base, self.master = base, master
        self.keys: list[str] = []

    def mk_key(self, agent: str, team: str, models=("mock-echo", "mock-local")) -> str:
        r = httpx.post(f"{self.base}/key/generate", headers={"Authorization": f"Bearer {self.master}"}, timeout=30,
                       json={"key_alias": "t5-" + uuid.uuid4().hex[:8], "models": list(models), "max_budget": 5,
                             "metadata": {"agent_id": agent, "team": team}})
        r.raise_for_status()
        k = r.json()["key"]
        self.keys.append(k)
        return k

    def chat(self, key: str, content, *, model="mock-echo", stream=False, messages=None, **extra) -> httpx.Response:
        body = {"model": model, "max_tokens": 60, "stream": stream,
                "messages": messages or [{"role": "user", "content": content}], **extra}
        return httpx.post(f"{self.base}/v1/chat/completions", json=body, timeout=60,
                          headers={"Authorization": f"Bearer {key}", "x-govpilot-run-id": "run-" + uuid.uuid4().hex[:16]})

    def cleanup(self):
        if self.keys:
            httpx.post(f"{self.base}/key/delete", headers={"Authorization": f"Bearer {self.master}"},
                       json={"keys": self.keys}, timeout=30)


def sse_text(resp: httpx.Response) -> tuple[str, str | None, list]:
    """(concatenated content, last finish_reason, tool_call fragments) of an SSE response."""
    text, fin, tcs = [], None, []
    for line in resp.text.splitlines():
        if not line.startswith("data: ") or line.endswith("[DONE]"):
            continue
        d = json.loads(line[6:])
        for ch in d.get("choices") or []:
            dl = ch.get("delta") or {}
            if dl.get("content"):
                text.append(dl["content"])
            tcs += dl.get("tool_calls") or []
            fin = ch.get("finish_reason") or fin
    return "".join(text), fin, tcs


def echo_received(container="gov-t5-mock-echo") -> list:
    r = sh("docker", "exec", container, "python", "-c",
           "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8000/_received').read().decode())")
    return json.loads(r.stdout)


def audit_events(path=STATE / "audit.jsonl", since_ts: float = 0.0) -> list:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("ts", 0) >= since_ts:
            out.append(e)
    return out
