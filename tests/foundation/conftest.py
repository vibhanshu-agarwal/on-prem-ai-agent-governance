import json
import pathlib
import subprocess

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
CONTAINERS = ["gov-postgres", "gov-redis", "gov-mock-local", "gov-mock-remote", "gov-gateway", "gov-gateway-edge"]
NON_GATEWAY = [c for c in CONTAINERS if c != "gov-gateway"]
PROBE_IMAGE = "govpilot/mock-provider:1"   # has python; used as a stand-in agent container


def load_env() -> dict:
    env = {}
    for line in (ROOT / "deploy" / ".env").read_text().splitlines():
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k] = v
    return env


def sh(*args, check=True, timeout=120) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, check=check)


@pytest.fixture(scope="session")
def env():
    return load_env()


@pytest.fixture(scope="session")
def gateway_url(env):
    return f"http://127.0.0.1:{env.get('GATEWAY_PORT', '4000')}"


@pytest.fixture(scope="session")
def keys():
    p = ROOT / ".local" / "agent-keys.json"
    assert p.exists(), "run scripts/bootstrap.sh first"
    return json.loads(p.read_text())["agents"]


def probe(python_code: str, network: str = "govpilot_agents", timeout=60) -> subprocess.CompletedProcess:
    """Run python inside a throwaway container attached only to `network`."""
    return sh("docker", "run", "--rm", "--network", network, "--entrypoint", "python",
              PROBE_IMAGE, "-c", python_code, check=False, timeout=timeout)
