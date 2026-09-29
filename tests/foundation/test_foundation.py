"""T1 acceptance: foundation stack.

Assumes `scripts/bootstrap.sh` has been run (stack up, keys provisioned).
"""
import json
import re

import httpx
import pytest

from conftest import CONTAINERS, NON_GATEWAY, ROOT, load_env, probe, sh

MESSAGES = [{"role": "user", "content": "one two three four"}]  # 4 words + 3 overhead = 7 prompt tokens


def auth(key):
    return {"Authorization": f"Bearer {key}"}


# ---------------------------------------------------------------- health
@pytest.mark.parametrize("name", CONTAINERS)
def test_container_healthy(name):
    out = sh("docker", "inspect", "-f", "{{.State.Status}} {{.State.Health.Status}}", name).stdout.strip()
    assert out == "running healthy", f"{name}: {out}"


def test_gateway_readiness_reports_db(gateway_url):
    r = httpx.get(f"{gateway_url}/health/readiness", timeout=10)
    assert r.status_code == 200
    assert r.json().get("db") == "connected"


def test_redis_and_postgres_not_published_on_host():
    for name in ("gov-redis", "gov-postgres"):
        ports = sh("docker", "port", name, check=False).stdout.strip()
        assert ports == "", f"{name} must not publish host ports, got: {ports}"


def test_gateway_version_pinned_and_recent():
    image = sh("docker", "inspect", "-f", "{{.Config.Image}}", "gov-gateway").stdout.strip()
    m = re.search(r":v(\d+)\.(\d+)\.(\d+)", image)
    assert m, image
    assert tuple(map(int, m.groups())) >= (1, 83, 7)


# ---------------------------------------------------------------- keyed calls
@pytest.mark.parametrize("agent,model", [
    ("hr-agent", "mock-local"),
    ("finance-recon-agent", "mock-local"),
    ("finance-recon-agent", "mock-remote"),
    ("coding-agent", "mock-remote"),
])
def test_keyed_nonstreaming_call(gateway_url, keys, agent, model):
    r = httpx.post(f"{gateway_url}/v1/chat/completions", headers=auth(keys[agent]["key"]), timeout=30,
                   json={"model": model, "messages": MESSAGES, "max_tokens": 10})
    assert r.status_code == 200, r.text
    body = r.json()
    u = body["usage"]
    assert (u["prompt_tokens"], u["completion_tokens"], u["total_tokens"]) == (7, 10, 17)
    assert body["choices"][0]["message"]["content"].split() == [f"tok{i}" for i in range(10)]


@pytest.mark.parametrize("model", ["mock-local", "mock-remote"])
def test_keyed_streaming_call_with_final_usage(gateway_url, keys, model):
    chunks = []
    with httpx.stream("POST", f"{gateway_url}/v1/chat/completions", headers=auth(keys["coding-agent"]["key"]),
                      timeout=30, json={"model": model, "messages": MESSAGES, "max_tokens": 6, "stream": True,
                                        "stream_options": {"include_usage": True}}) as r:
        assert r.status_code == 200
        for line in r.iter_lines():
            if line.startswith("data: ") and line != "data: [DONE]":
                chunks.append(json.loads(line[6:]))
    text = "".join(c["choices"][0]["delta"].get("content") or "" for c in chunks if c.get("choices"))
    assert text.split() == [f"tok{i}" for i in range(6)]
    final_usage = chunks[-1].get("usage") or {}
    assert {k: final_usage.get(k) for k in ("prompt_tokens", "completion_tokens", "total_tokens")} == \
        {"prompt_tokens": 7, "completion_tokens": 6, "total_tokens": 13}, "usage must arrive in the final chunk"


def test_default_max_tokens_ceiling_applies_when_omitted(gateway_url, keys):
    r = httpx.post(f"{gateway_url}/v1/chat/completions", headers=auth(keys["coding-agent"]["key"]), timeout=30,
                   json={"model": "mock-local", "messages": MESSAGES})
    assert r.status_code == 200
    assert r.json()["usage"]["completion_tokens"] == 256  # litellm_params.max_tokens default


def test_models_endpoint_honours_allowlist(gateway_url, keys):
    r = httpx.get(f"{gateway_url}/v1/models", headers=auth(keys["hr-agent"]["key"]), timeout=10)
    assert r.status_code == 200
    assert {m["id"] for m in r.json()["data"]} == {"mock-local"}


def test_model_outside_allowlist_rejected(gateway_url, keys):
    r = httpx.post(f"{gateway_url}/v1/chat/completions", headers=auth(keys["hr-agent"]["key"]), timeout=30,
                   json={"model": "mock-remote", "messages": MESSAGES, "max_tokens": 5})
    assert r.status_code in (401, 403), r.text


def test_spend_is_nonzero_and_attributed(gateway_url, keys):
    r = httpx.post(f"{gateway_url}/v1/chat/completions", headers=auth(keys["finance-recon-agent"]["key"]),
                   timeout=30, json={"model": "mock-remote", "messages": MESSAGES, "max_tokens": 100})
    assert r.status_code == 200
    expected = 7 * 0.000005 + 100 * 0.000015  # mock-remote pricing
    assert float(r.headers["x-litellm-response-cost"]) == pytest.approx(expected, rel=1e-3)
    info = httpx.get(f"{gateway_url}/key/info", headers=auth(keys["finance-recon-agent"]["key"]),
                     timeout=10).json()["info"]
    assert info["metadata"] == {"agent_id": "finance-recon-agent", "team": "finance"}
    assert info["max_budget"] == 2.0
    assert info["team_id"] == keys["finance-recon-agent"]["team_id"]
    assert set(info["models"]) == {"mock-local", "mock-remote"}


# ---------------------------------------------------------------- auth
def test_unkeyed_call_rejected(gateway_url):
    r = httpx.post(f"{gateway_url}/v1/chat/completions", timeout=10,
                   json={"model": "mock-local", "messages": MESSAGES, "max_tokens": 5})
    assert r.status_code == 401


def test_bogus_key_rejected(gateway_url):
    r = httpx.post(f"{gateway_url}/v1/chat/completions", headers=auth("sk-not-a-real-key"), timeout=10,
                   json={"model": "mock-local", "messages": MESSAGES, "max_tokens": 5})
    assert r.status_code in (401, 403)


def test_agent_key_cannot_use_admin_api(gateway_url, keys):
    r = httpx.post(f"{gateway_url}/key/generate", headers=auth(keys["hr-agent"]["key"]), timeout=10, json={})
    assert r.status_code in (401, 403)


# ---------------------------------------------------------------- network isolation
def _container_ip(name, network):
    fmt = '{{(index .NetworkSettings.Networks "%s").IPAddress}}' % network
    return sh("docker", "inspect", "-f", fmt, name).stdout.strip()


def _connect_code(host, port):
    # Prints CONNECTED on success, BLOCKED:<exc> on a network error, so a probe that fails for
    # an unrelated reason (docker error, missing image/network) cannot pass as "blocked".
    return ("import socket\n"
            "try:\n"
            f"    socket.create_connection(({host!r},{port}),timeout=3); print('CONNECTED')\n"
            "except OSError as x:\n"
            "    print('BLOCKED:' + type(x).__name__)\n")


def _assert_blocked(r, what):
    out = r.stdout.strip()
    assert out.startswith("BLOCKED:"), f"{what}: expected a network error, got rc={r.returncode} {out!r} {r.stderr!r}"


def test_agent_container_reaches_gateway_only():
    r = probe("import urllib.request as u;print(u.urlopen('http://gateway:4000/health/liveliness',timeout=5).status)")
    assert r.returncode == 0 and r.stdout.strip() == "200", r.stderr
    for host, port in [("mock-local", 8000), ("mock-remote", 8000), ("postgres", 5432), ("redis", 6379)]:
        _assert_blocked(probe(_connect_code(host, port)), f"agents network must not reach {host}")


def test_agent_container_cannot_reach_provider_ips_directly():
    for name in ["gov-mock-local", "gov-mock-remote"]:
        ip = _container_ip(name, "govpilot_providers")
        assert ip
        _assert_blocked(probe(_connect_code(ip, 8000)), f"{name} ({ip}) reachable from agents network")


def test_agent_container_has_no_internet():
    _assert_blocked(probe(_connect_code("1.1.1.1", 443)), "agents network must have no internet")


def test_only_gateway_on_agents_network():
    names = sh("docker", "network", "inspect", "govpilot_agents", "-f",
               "{{range .Containers}}{{.Name}} {{end}}").stdout.split()
    assert sorted(names) == ["gov-gateway"]


def test_providers_network_members_and_internal_flags():
    names = sh("docker", "network", "inspect", "govpilot_providers", "-f",
               "{{range .Containers}}{{.Name}} {{end}}").stdout.split()
    assert sorted(names) == ["gov-gateway", "gov-mock-local", "gov-mock-remote"]
    for net in ("govpilot_agents", "govpilot_providers", "govpilot_backend"):
        assert sh("docker", "network", "inspect", net, "-f", "{{.Internal}}").stdout.strip() == "true", net


def test_mock_rejects_calls_without_provider_key():
    # From the providers network, bypassing the gateway: the mock itself demands the (hashed) key.
    code = ("import urllib.request as u, urllib.error as e\n"
            "try:\n"
            "    u.urlopen('http://mock-local:8000/v1/models', timeout=5); print('OPEN')\n"
            "except e.HTTPError as x:\n"
            "    print(x.code)\n")
    r = probe(code, network="govpilot_providers")
    assert r.stdout.strip() == "401", (r.stdout, r.stderr)


# ---------------------------------------------------------------- credentials
def _container_env(name):
    raw = sh("docker", "inspect", "-f", "{{json .Config.Env}}", name).stdout
    return dict(e.split("=", 1) for e in json.loads(raw))


def test_no_provider_credentials_outside_gateway(env, keys):
    secrets = [env["MOCK_LOCAL_API_KEY"], env["MOCK_REMOTE_API_KEY"], env["LITELLM_MASTER_KEY"],
               env["LITELLM_SALT_KEY"]] + [a["key"] for a in keys.values()]
    for name in NON_GATEWAY:
        cenv = _container_env(name)
        blob = json.dumps(cenv)
        for s in secrets:
            assert s not in blob, f"{name} env leaks a gateway secret"
        bad = [k for k in cenv if re.search(r"API_KEY(?!_SHA256)|MASTER_KEY|SALT_KEY", k)]
        assert not bad, f"{name} has credential-like env vars: {bad}"


def test_provider_credentials_present_in_gateway(env):
    genv = _container_env("gov-gateway")
    assert genv["MOCK_LOCAL_API_KEY"] == env["MOCK_LOCAL_API_KEY"]
    assert genv["MOCK_REMOTE_API_KEY"] == env["MOCK_REMOTE_API_KEY"]


def test_no_secrets_in_committed_config():
    text = ((ROOT / "deploy" / "litellm" / "config.yaml").read_text()
            + (ROOT / "deploy" / "docker-compose.yml").read_text())
    e = load_env()
    for k in ("MOCK_LOCAL_API_KEY", "MOCK_REMOTE_API_KEY", "LITELLM_MASTER_KEY", "POSTGRES_PASSWORD",
              "REDIS_PASSWORD"):
        assert e[k] not in text


def test_env_file_and_keys_are_gitignored():
    for p in ("deploy/.env", ".local/agent-keys.json"):
        r = sh("git", "-C", str(ROOT), "check-ignore", p, check=False)
        assert r.returncode == 0, f"{p} must be gitignored"
