"""T9 hardening checks: assertions about the RUNNING stack (scripts/up.sh applies deploy/hardening/).

Everything here talks to Docker, so a missing stack is a skip with the reason, never a silent pass.
"""
import json
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROBE_IMAGE = "govpilot/mock-provider:1"      # has python; throwaway stand-in agent container
GATEWAY = "gov-gateway"
EDGE = "gov-gateway-edge"


def sh(*args, check=True, timeout=120):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, check=check)


def inspect(name: str) -> dict:
    return json.loads(sh("docker", "inspect", name).stdout)[0]


def running(name: str) -> bool:
    r = sh("docker", "inspect", "-f", "{{.State.Running}}", name, check=False)
    return r.stdout.strip() == "true"


def probe(code: str, network: str = "govpilot_agents", timeout=90) -> subprocess.CompletedProcess:
    """Run python inside a throwaway container attached only to `network` (an agent's point of view)."""
    # govpilot.t8test: on the discovery ignore list, so these refused probes are not proposed as shadow AI
    return sh("docker", "run", "--rm", "--label", "govpilot.t8test=1", "--network", network, "--entrypoint", "python",
              PROBE_IMAGE, "-c", code,
              check=False, timeout=timeout)


def load_env() -> dict:
    env = {}
    for line in (ROOT / "deploy" / ".env").read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    return env


def container_env(name: str) -> dict:
    return dict(e.split("=", 1) for e in inspect(name)["Config"]["Env"] or [])


def gov_containers() -> list[str]:
    return [n for n in sh("docker", "ps", "--format", "{{.Names}}").stdout.split() if n.startswith("gov-")]


@pytest.fixture(scope="session", autouse=True)
def stack_up():
    if not running(GATEWAY) or not running(EDGE):
        pytest.skip(f"{GATEWAY} / {EDGE} not running: bash scripts/up.sh")


@pytest.fixture(scope="session")
def env():
    return load_env()


@pytest.fixture(scope="session")
def agent_key():
    p = ROOT / ".local" / "agent-keys.json"
    if not p.exists():
        pytest.skip("no .local/agent-keys.json (scripts/bootstrap.sh)")
    return json.loads(p.read_text())["agents"]["hr-agent"]["key"]
