"""Client credential guard (deploy/litellm/callbacks/client_credentials_guard.py): pure logic, no stack needed.

The live behaviour (a real gateway refusing a request that carries api_key / extra_headers, and not being pushed
into provider cooldown) is tests/hardening/test_client_credentials_live.py.
"""
import asyncio
import json
import sys
import types

import pytest

from conftest import ROOT


@pytest.fixture(scope="session", autouse=True)
def stack_up():
    """Override the directory-wide fixture that skips without the Docker stack: these tests are offline."""


def _load():
    try:
        import litellm  # noqa: F401
    except ImportError:
        pkg = types.ModuleType("litellm")
        integ = types.ModuleType("litellm.integrations")
        cl = types.ModuleType("litellm.integrations.custom_logger")

        class CustomLogger:  # stand-in: the guard only needs a base class
            def __init__(self, *a, **k):
                pass
        cl.CustomLogger = CustomLogger
        sys.modules.update({"litellm": pkg, "litellm.integrations": integ, "litellm.integrations.custom_logger": cl})
    p = str(ROOT / "deploy" / "litellm")
    if p not in sys.path:
        sys.path.insert(0, p)
    from callbacks import client_credentials_guard
    return client_credentials_guard


G = _load()


class Sink:
    def __init__(self):
        self.events = []

    def emit(self, e):
        self.events.append(e)


class Key:
    key_alias, team_id = "hr-agent", "team-1"
    metadata = {"agent_id": "hr-agent"}


def guard(mode="reject", **env):
    import os
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        s = Sink()
        return G.ClientCredentialsGuard(sink=s, mode=mode), s
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def pre(g, body):
    return asyncio.run(g.async_pre_call_hook(Key(), None, body, "acompletion"))


def status_and_type(exc):
    return (getattr(exc, "status_code", None) or int(getattr(exc, "code", 0)),
            getattr(exc, "type", None) or (getattr(exc, "detail", None) or {}).get("type"))


CLEAN = {"model": "mock-local", "messages": [{"role": "user", "content": "hi"}], "max_tokens": 8, "user": "E1001",
         "stream": True, "stream_options": {"include_usage": True}, "temperature": 0.2, "tools": [], "n": 1,
         "response_format": {"type": "text"}, "metadata": {"tags": ["x"], "headers": {"host": "gw"}, "user_api_key": "h"},
         "extra_body": {"foo": 1}, "proxy_server_request": {"headers": {"authorization": "Bearer x"}}}


def test_a_normal_body_is_untouched_including_the_headers_litellm_itself_puts_in_metadata():
    g, s = guard()
    assert pre(g, dict(CLEAN)) == CLEAN and s.events == []


@pytest.mark.parametrize("field,value", [
    ("api_key", "sk-secret"), ("api_base", "http://evil.test/v1"), ("base_url", "http://evil.test"),
    ("extra_headers", {"Authorization": "Bearer sk-secret"}), ("headers", {"Authorization": "Bearer sk-secret"}),
    ("custom_llm_provider", "anthropic"), ("api_version", "2020-01-01"), ("organization", "org-x"),
    ("azure_ad_token", "t"), ("aws_secret_access_key", "sk-secret"), ("aws_access_key_id", "AKIAX"),
    ("vertex_credentials", "{}"), ("deployment_id", "d"), ("user_config", {}), ("model_list", []),
    ("litellm_params", {"api_key": "sk-secret"}), ("client", "x"),
])
def test_provider_credentials_endpoints_and_headers_are_refused_with_400_and_never_echoed(field, value):
    g, s = guard()
    with pytest.raises(Exception) as ei:
        pre(g, {**CLEAN, field: value})
    assert status_and_type(ei.value) == (400, "client_credentials_not_allowed")
    text = str(getattr(ei.value, "message", "")) + str(getattr(ei.value, "detail", ""))
    assert field in text and "sk-secret" not in text and "evil.test" not in text
    (ev,) = s.events
    assert ev["event"] == "request.client_credentials_rejected" and field in ev["fields"] and ev["agent_id"] == "hr-agent"
    assert "sk-secret" not in json.dumps(ev)              # field NAMES only, never values


@pytest.mark.parametrize("container", ["extra_body", "metadata", "litellm_metadata", "litellm_embedding_config"])
def test_credentials_hidden_in_the_nested_containers_litellm_merges_are_refused(container):
    g, _ = guard()
    with pytest.raises(Exception) as ei:
        pre(g, {**CLEAN, container: {"api_key": "sk-secret"}})
    assert f"{container}.api_key" in str(ei.value.message if hasattr(ei.value, "message") else ei.value.detail)


def test_json_encoded_metadata_is_decoded_before_checking():
    g, _ = guard()
    with pytest.raises(Exception):
        pre(g, {**CLEAN, "metadata": json.dumps({"api_base": "http://evil.test"})})


def test_audit_mode_lets_it_through_but_records_it_and_off_does_nothing():
    g, s = guard("audit")
    body = {**CLEAN, "api_key": "sk-secret"}
    assert pre(g, body) is body
    assert s.events[0]["event"] == "request.client_credentials_seen" and s.events[0]["fields"] == ["api_key"]
    g, s = guard("off")
    assert pre(g, {**CLEAN, "api_key": "sk-secret"})["api_key"] == "sk-secret" and s.events == []


def test_an_unknown_mode_fails_closed_to_reject():
    g, _ = guard("Enforce-ish")
    assert g.mode == "reject"


def test_operator_allow_and_extra_lists_are_config_not_code():
    g, _ = guard(GOVPILOT_CLIENT_CREDENTIALS_ALLOW="api_version,extra_headers", GOVPILOT_CLIENT_CREDENTIALS_EXTRA="x_secret_field")
    pre(g, {**CLEAN, "api_version": "2024-01-01", "extra_headers": {"x-team": "a"}})       # explicit opt-ins pass
    with pytest.raises(Exception):
        pre(g, {**CLEAN, "api_key": "sk-secret"})                                          # not opted in
    with pytest.raises(Exception):
        pre(g, {**CLEAN, "x_secret_field": 1})


def test_a_failing_audit_sink_never_lets_a_bad_request_through_or_breaks_a_good_one():
    class Boom:
        def emit(self, e):
            raise RuntimeError("sink down")
    g = G.ClientCredentialsGuard(sink=Boom(), mode="reject")
    with pytest.raises(Exception) as ei:
        pre(g, {**CLEAN, "api_key": "sk-secret"})
    assert status_and_type(ei.value)[0] == 400
    assert pre(g, dict(CLEAN)) == CLEAN


def test_the_guard_is_first_in_the_callback_list_and_the_module_exports_the_instance():
    import yaml
    cfg = yaml.safe_load((ROOT / "deploy" / "litellm" / "config.yaml").read_text())
    cbs = cfg["litellm_settings"]["callbacks"]
    assert cbs[0] == "callbacks.client_credentials_guard.client_credentials_guard"
    assert isinstance(G.client_credentials_guard, G.ClientCredentialsGuard)
