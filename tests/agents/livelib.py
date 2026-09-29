"""Helpers for the live (Docker) T4 tests."""
from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

import attribution_report as rep
from govagent.events import parse_log

ROOT = Path(__file__).resolve().parents[2]
IMAGE = "govpilot/agents:1"
AGENTS_NET, SSO_NET = "govpilot_agents", "govpilot_agents_sso"
LABEL = {"govpilot.test": "t4"}


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for f in (ROOT / "deploy" / ".env", ROOT / ".local" / "control-plane.env", ROOT / ".local" / "agents.env"):
        if f.exists():
            for line in f.read_text().splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    return env


ENV = load_env()
GW = f"http://127.0.0.1:{ENV.get('GATEWAY_PORT', '4000')}"
AUTHPROXY = f"http://127.0.0.1:{ENV.get('AUTHPROXY_PORT', '4180')}"
CP = f"http://127.0.0.1:{ENV.get('CP_PORT', '8100')}"
MASTER = ENV.get("LITELLM_MASTER_KEY", "")


def uid(p="t4") -> str:
    return f"{p}-{uuid.uuid4().hex[:6]}"


def admin() -> httpx.Client:
    return httpx.Client(base_url=GW, headers={"Authorization": f"Bearer {MASTER}"}, timeout=30)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def stack_ready() -> str | None:
    """None when everything the live tests need is there, else the reason to skip."""
    try:
        if httpx.get(GW + "/health/liveliness", timeout=3).status_code != 200:
            return "gateway not healthy"
    except httpx.HTTPError:
        return "gateway not running (scripts/bootstrap.sh)"
    try:
        if not _gateway_settled():
            return "gateway kept restarting for 5 minutes (someone is redeploying it); rerun when it is quiet"
    except RuntimeError as e:
        return (f"{e}: docker compose -f deploy/docker-compose.yml [-f overlays] --env-file deploy/.env up -d --no-deps gateway")
    if "HR_AGENT_KEY" not in ENV:
        return "run scripts/agents-up.sh once (no .local/agents.env)"
    import docker
    try:
        docker.from_env().images.get(IMAGE)
    except Exception:  # noqa: BLE001
        return f"image {IMAGE} not built (scripts/agents-up.sh)"
    # the attribution callback must be loaded in the running gateway: an enforcing key must refuse a request without a run id
    r = httpx.post(GW + "/v1/chat/completions", headers={"Authorization": f"Bearer {ENV['HR_AGENT_KEY']}"}, timeout=15,
                   json={"model": "mock-local", "max_tokens": 1, "messages": [{"role": "user", "content": "x"}]})
    if r.status_code != 400 or "run_id_required" not in r.text:
        return ("gateway does not have callbacks.run_attribution loaded (or hr-agent key is not in enforce mode); "
                "recreate it: docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d --no-deps gateway")
    return None


def _gateway_settled(min_age_s: float = 75.0, wait_s: float = 300.0) -> bool:
    """The shared gateway is redeployed by other work streams; wait until it has been up for a while."""
    import docker
    deadline = time.time() + wait_s
    while True:
        try:
            st = docker.from_env().containers.get("gov-gateway").attrs["State"]
            started = datetime.fromisoformat(st["StartedAt"].split(".")[0]).replace(tzinfo=timezone.utc)
            cb = ROOT / "deploy" / "litellm" / "callbacks" / "run_attribution.py"
            stale = datetime.fromtimestamp(cb.stat().st_mtime, timezone.utc) > started      # callback edited after the gateway loaded it
            if st["Running"] and st.get("Health", {}).get("Status") == "healthy" and (utcnow() - started).total_seconds() > min_age_s:
                if stale:
                    raise RuntimeError("gateway predates run_attribution.py; recreate it")
                return True
        except RuntimeError:
            raise
        except Exception:  # noqa: BLE001
            pass
        if time.time() > deadline:
            return False
        time.sleep(5)


def fetch_rows(since: datetime) -> list[dict]:
    raw = rep.fetch_rows(GW, MASTER, since - timedelta(seconds=5), utcnow() + timedelta(minutes=2))
    return [rep.normalise(r) for r in raw]


def rows_for_roots(roots: set[str], since: datetime, expected: int, timeout: float = 60.0) -> list[dict]:
    """Poll the spend logs until `expected` rows for these run trees are there (the DB write is batched)."""
    deadline = time.time() + timeout
    got: list[dict] = []
    while time.time() < deadline:
        got = [r for r in fetch_rows(since) if r["root_run_id"] in roots or r["run_id"] in roots]
        if len(got) >= expected:
            time.sleep(1.5)                                    # let any straggler land, then take a fresh look
            return [r for r in fetch_rows(since) if r["root_run_id"] in roots or r["run_id"] in roots]
        time.sleep(2.0)
    return got


def run_container(module: str, agent_id: str, env: dict, network: str, *, name: str | None = None, mounts=None,
                  detach=False, timeout=120):
    import docker
    d = docker.from_env()
    labels = {"govpilot.agent_id": agent_id, "govpilot.root_agent_id": agent_id, **LABEL}
    c = d.containers.run(IMAGE, ["python", "-m", module], name=name or uid(f"t4-{agent_id}"), detach=True,
                         environment=env, network=network, labels=labels, mounts=mounts or [],
                         read_only=True, tmpfs={"/tmp": ""}, cap_drop=["ALL"], mem_limit="256m")
    if detach:
        return c
    try:
        c.wait(timeout=timeout)
        return c
    except Exception:
        c.kill()
        raise


def events_of(c) -> list[dict]:
    return parse_log(c.logs().decode(errors="replace"))


def cleanup() -> None:
    import docker
    d = docker.from_env()
    for c in d.containers.list(all=True, filters={"label": "govpilot.test=t4"}):
        try:
            c.remove(force=True)
        except docker.errors.APIError:
            pass


def record(name: str, data: dict) -> None:
    """Measured numbers land in .local/t4-results/ (gitignored); docs/results/T4.md quotes them."""
    d = ROOT / ".local" / "t4-results"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{name}.json").write_text(json.dumps(data, indent=2, default=str))


def _gateway_started() -> str | None:
    try:
        import docker
        return docker.from_env().containers.get("gov-gateway").attrs["State"]["StartedAt"]
    except Exception:  # noqa: BLE001
        return None


def resilient(fn):
    """Re-run a live test when the shared gateway was redeployed while it ran (other work streams recreate it);
    a failure with the gateway untouched is a real failure and is raised as is."""
    import functools

    @functools.wraps(fn)
    def wrapper(*a, **kw):
        for attempt in range(4):
            before = _gateway_started()
            try:
                return fn(*a, **kw)
            except BaseException as e:  # noqa: BLE001
                if attempt == 3 or isinstance(e, (KeyboardInterrupt, SystemExit)) or _gateway_started() == before:
                    raise
                cleanup()
                _gateway_settled()
    return wrapper
