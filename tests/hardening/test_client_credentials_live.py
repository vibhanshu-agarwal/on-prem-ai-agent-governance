"""Client credential passthrough, against the running gateway (T9 review open item).

Before the guard (deploy/litellm/callbacks/client_credentials_guard.py) LiteLLM v1.100.3 refused only
`api_base` / `base_url`: an agent's own `api_key`, `extra_headers` or `headers` replaced the gateway's provider
credential on the call, and a WRONG key made the provider answer 401, which put the shared deployment into
cooldown for every other agent ("No deployments available", 429). These tests pin the fixed behaviour.
"""
import json
import time
import urllib.error
import urllib.request
import uuid

import pytest

from conftest import GATEWAY, sh


@pytest.fixture(scope="module")
def gw(env):
    return f"http://127.0.0.1:{env.get('GATEWAY_PORT', '4000')}"


def chat(gw, key, extra=None, model="mock-local"):
    body = {"model": model, "messages": [{"role": "user", "content": "hello"}], "max_tokens": 8, **(extra or {})}
    req = urllib.request.Request(
        gw + "/v1/chat/completions", data=json.dumps(body).encode(), method="POST",
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json",
                 "x-govpilot-run-id": "run-" + uuid.uuid4().hex[:16]})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw}


def _wait_healthy_call(gw, key):
    """A clean request must succeed at once: proves the refused ones did not push the deployment into cooldown."""
    st, body = chat(gw, key)
    assert st == 200, (st, body)


def test_an_agents_own_api_key_is_refused_and_does_not_reach_the_provider(gw, agent_key):
    t0 = time.time()
    st, body = chat(gw, agent_key, {"api_key": "sk-agent-own-provider-key"})
    assert st == 400, (st, body)
    assert body["error"]["type"] == "client_credentials_not_allowed"
    assert "api_key" in body["error"]["message"] and "sk-agent-own" not in json.dumps(body)   # named, never echoed
    _wait_healthy_call(gw, agent_key)          # NOT 429 "No deployments available": the provider was never called
    time.sleep(1.5)
    logs = sh("docker", "logs", "--since", f"{int(time.time() - t0) + 5}s", GATEWAY, check=False)
    lines = [l for l in (logs.stdout + logs.stderr).splitlines() if "GOVPILOT_REQUEST_GUARD" in l]
    assert lines, "no GOVPILOT_REQUEST_GUARD audit line"
    ev = json.loads(lines[-1].split("GOVPILOT_REQUEST_GUARD ", 1)[1])
    assert ev["event"] == "request.client_credentials_rejected" and ev["fields"] == ["api_key"]
    assert ev["agent_id"] == "hr-agent" and "sk-agent-own" not in lines[-1]


@pytest.mark.parametrize("extra", [
    {"extra_headers": {"Authorization": "Bearer sk-agent-own"}},
    {"headers": {"Authorization": "Bearer sk-agent-own"}},
    {"custom_llm_provider": "anthropic"},
    {"api_version": "2020-01-01"},
    {"aws_secret_access_key": "sk-agent-own"},
    {"litellm_params": {"api_key": "sk-agent-own"}},
    {"metadata": {"api_key": "sk-agent-own"}},
    {"extra_body": {"api_key": "sk-agent-own"}},
], ids=["extra_headers", "headers", "custom_llm_provider", "api_version", "aws_secret_access_key",
     "litellm_params.api_key", "metadata.api_key", "extra_body.api_key"])
def test_other_credential_carrying_fields_are_refused(gw, agent_key, extra):
    st, body = chat(gw, agent_key, extra)
    assert st == 400 and body["error"]["type"] == "client_credentials_not_allowed", (st, body)
    assert "sk-agent-own" not in json.dumps(body)


def test_a_client_endpoint_is_still_refused(gw, agent_key):
    """api_base / base_url are refused natively by LiteLLM (401 auth error) before our hook; either way: not forwarded."""
    st, body = chat(gw, agent_key, {"api_base": "http://evil.test/v1", "api_key": "sk-agent-own"})
    assert st in (400, 401) and "Rejected Request" in json.dumps(body), (st, body)
    _wait_healthy_call(gw, agent_key)


def test_ordinary_requests_are_unaffected(gw, agent_key):
    st, body = chat(gw, agent_key, {"user": "E1001", "metadata": {"trace": "x"}, "extra_body": {"foo": 1}, "temperature": 0.1})
    assert st == 200, (st, body)
    assert body["choices"][0]["message"]["content"]
