"""Shared helpers for T3 tests: env loading, IdP logins, API client, throwaway agent containers."""
from __future__ import annotations

import os
import re
import time
import uuid
from pathlib import Path

import docker
import httpx

ROOT = Path(__file__).resolve().parents[2]
CP_SRC = ROOT / "services" / "control-plane"
TEST_LABEL = {"govpilot.test": "t3"}
AGENT_IMAGE = "govpilot/control-plane:1"
AGENTS_NET = "govpilot_agents"
SSO_NET = "govpilot_agents_sso"


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for f in (ROOT / "deploy" / ".env", ROOT / ".local" / "control-plane.env"):
        if f.exists():
            for line in f.read_text().splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    return env


ENV = load_env()
CP_URL = f"http://127.0.0.1:{ENV.get('CP_PORT', '8100')}"
IDP_URL = f"http://127.0.0.1:{ENV.get('IDP_PORT', '8300')}"
GW_URL = f"http://127.0.0.1:{ENV.get('GATEWAY_PORT', '4000')}"
AUTHPROXY_URL = f"http://127.0.0.1:{ENV.get('AUTHPROXY_PORT', '4180')}"
ESTOP_URL = f"http://127.0.0.1:{ENV.get('ESTOP_PORT', '8190')}"


def uid(prefix="t3") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6]}"


def user_token(user: str, audience: str = "govpilot-control-plane") -> str:
    r = httpx.post(f"{IDP_URL}/token", data={"grant_type": "password", "username": user,
                                             "password": ENV[f"IDP_PASSWORD_{user.upper()}"],
                                             "audience": audience}, timeout=10)
    r.raise_for_status()
    return r.json()["access_token"]


def client_token(client_id: str, secret: str, audience: str | None = None) -> httpx.Response:
    data = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}
    if audience:
        data["audience"] = audience
    return httpx.post(f"{IDP_URL}/token", data=data, timeout=10)


def idp_admin(method: str, path: str, **kw) -> httpx.Response:
    return httpx.request(method, IDP_URL + path, headers={"Authorization": f"Bearer {ENV['IDP_ADMIN_TOKEN']}"},
                         timeout=10, **kw)


class CP:
    """Control-plane API client acting as one IdP user."""

    def __init__(self, user: str):
        self.user = user
        self.c = httpx.Client(base_url=CP_URL, timeout=120,
                              headers={"Authorization": f"Bearer {user_token(user)}"})

    def get(self, path, **kw):
        return self.c.get(path, **kw)

    def post(self, path, json=None, **kw):
        return self.c.post(path, json=json or {}, **kw)


def gw_admin() -> httpx.Client:
    return httpx.Client(base_url=GW_URL, timeout=30,
                        headers={"Authorization": f"Bearer {ENV['LITELLM_MASTER_KEY']}"})


# T8: drill agents must stream token by token so a test can see the live stream being cut. The T5 guardrail
# hook buffers streamed output by default (output redaction), so drill keys get the admin-set key policy
# `guardrails.streaming: passthrough` (production agents keep buffering; a buffered stream is still cancelled
# upstream when its connection dies, see tests/acceptance).
DRILL_KEY_METADATA = {"guardrails": {"streaming": "passthrough"}}


def mark_drill_keys(key_hashes) -> None:
    gw = gw_admin()
    for h in key_hashes:
        info = gw.get("/key/info", params={"key": h}).json().get("info") or {}
        md = {**(info.get("metadata") or {}), **DRILL_KEY_METADATA}
        r = gw.post("/key/update", json={"key": h, "metadata": md})
        r.raise_for_status()


def chat(key: str, model: str = "mock-local", base: str = GW_URL, auth_scheme="Bearer") -> httpx.Response:
    return httpx.post(f"{base}/v1/chat/completions", timeout=30,
                      headers={"Authorization": f"{auth_scheme} {key}"},
                      json={"model": model, "max_tokens": 2, "messages": [{"role": "user", "content": "hi"}]})


# ---------------------------------------------------------------- containers
def dclient():
    return docker.from_env()


def run_agent_container(agent_id: str, team: str, env: dict[str, str], name: str | None = None,
                        restart: str = "always", extra_labels: dict | None = None, network: str = AGENTS_NET):
    d = dclient()
    labels = {"govpilot.agent_id": agent_id, "govpilot.team": team, "govpilot.root_agent_id": agent_id,
              **TEST_LABEL, **(extra_labels or {})}
    return d.containers.run(AGENT_IMAGE, command=["python", "-u", "-m", "govcp.tools.sample_agent"],
                            name=name or f"t3-agent-{agent_id}", detach=True, labels=labels, environment=env,
                            network=network, restart_policy={"Name": restart})


def wait_for_log(container, pattern: str, timeout: float = 30.0) -> str:
    rx = re.compile(pattern)
    deadline = time.time() + timeout
    while time.time() < deadline:
        logs = container.logs().decode(errors="replace")
        if rx.search(logs):
            return logs
        time.sleep(0.3)
    raise AssertionError(f"pattern {pattern!r} not seen in logs:\n{container.logs().decode()[-2000:]}")


def parse_events(logs: str) -> list[tuple[str, float, str]]:
    out = []
    for line in logs.splitlines():
        parts = line.split(" ", 2)
        if len(parts) >= 2 and parts[0] in ("START", "TOK", "END", "ERR", "DENIED", "TOKEN"):
            try:
                out.append((parts[0], float(parts[1]), parts[2] if len(parts) > 2 else ""))
            except ValueError:
                pass
    return out


def cleanup_test_containers():
    d = dclient()
    for c in d.containers.list(all=True, filters={"label": "govpilot.test=t3"}):
        try:
            c.remove(force=True)
        except docker.errors.APIError:
            pass


# ---------------------------------------------------------------- test utilities
RESULTS_DIR = ROOT / ".local" / "t3-results"


def record_result(name: str, data: dict) -> None:
    """Measured numbers land in .local/t3-results/ (gitignored); docs/results/T3.md quotes them."""
    import json
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    (RESULTS_DIR / f"{name}.json").write_text(json.dumps(data, indent=2, default=str))


def wait_until(fn, timeout=15.0, interval=0.25):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        last = fn()
        if last:
            return last
        time.sleep(interval)
    return last


def stack_up() -> bool:
    try:
        return (httpx.get(CP_URL + "/healthz", timeout=3).status_code == 200
                and httpx.get(GW_URL + "/health/liveliness", timeout=3).status_code == 200)
    except httpx.HTTPError:
        return False


def live_or_skip():
    import pytest
    if not stack_up():
        pytest.skip("live stack not running (scripts/bootstrap.sh + scripts/control-plane-up.sh)")


class DenialProbe:
    """Hammer a request in a background thread; remember when it was first refused (401/403)."""

    def __init__(self, fn, interval=0.05):
        import threading
        self.fn, self.interval = fn, interval
        self.first_denied: float | None = None
        self.ok_after_denial = 0
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, daemon=True)

    def _run(self):
        while not self._stop.is_set():
            try:
                code = self.fn().status_code
            except httpx.HTTPError:
                code = None
            now = time.time()
            if code in (401, 403) and self.first_denied is None:
                self.first_denied = now
            elif code == 200 and self.first_denied is not None:
                self.ok_after_denial += 1
            time.sleep(self.interval)

    def __enter__(self):
        self._t.start()
        time.sleep(0.3)
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._t.join(timeout=10)
