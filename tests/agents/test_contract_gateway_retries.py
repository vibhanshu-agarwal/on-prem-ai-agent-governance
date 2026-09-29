"""Contract: run_id propagation through LLM calls and retries (GatewayClient)."""
from __future__ import annotations

import json

import pytest

from fakes import ScriptedTransport, chat_ok, err
from govagent import (GatewayClient, GatewayError, MacaroonAuth, OIDCClientCredentialsAuth, RetryPolicy, RunContext,
                      StaticKeyAuth, TransportError)

MSGS = [{"role": "user", "content": "hi"}]


def client(script, sink, **kw):
    sleeps: list[float] = []
    t = ScriptedTransport(script)
    return (GatewayClient("http://gateway:4000", kw.pop("auth", StaticKeyAuth("sk-test")), transport=t, sink=sink,
                          retry=kw.pop("retry", RetryPolicy(max_attempts=4, base_delay_s=0.1)), sleep=sleeps.append),
            t, sleeps)


def test_every_llm_call_carries_the_run_headers_and_end_user(sink):
    gw, t, _ = client([chat_ok()], sink)
    run = RunContext.root("hr-agent", user="E1002")
    res = gw.chat(run, "mock-local", MSGS, max_tokens=32)
    req = t.requests[0]
    assert req["url"] == "http://gateway:4000/v1/chat/completions"
    assert req["headers"]["authorization"] == "Bearer sk-test"
    assert req["headers"]["x-govpilot-run-id"] == run.run_id and req["headers"]["x-govpilot-attempt"] == "1"
    assert req["body"]["user"] == "E1002" and req["body"]["max_tokens"] == 32
    assert (res.run_id, res.attempts, res.cost_usd, res.prompt_tokens, res.completion_tokens) == (run.run_id, 1, 0.000012, 10, 5)
    ev = sink.of("llm.attempt")
    assert len(ev) == 1 and ev[0]["run_id"] == run.run_id and ev[0]["ok"] and ev[0]["attempt"] == 1


@pytest.mark.parametrize("first", [err(503, "service_unavailable"), err(502), err(429, "rate_limit_error"),
                                   err(500), TransportError("connection reset")])
def test_retry_carries_the_same_run_id_and_bumps_the_attempt(sink, first):
    gw, t, sleeps = client([first, chat_ok()], sink)
    child = RunContext.root("a-agent").child("tool", "t", tool="t")
    res = gw.chat(child, "mock-local", MSGS)
    assert res.attempts == 2 and len(t.requests) == 2 and len(sleeps) == 1
    h1, h2 = t.requests[0]["headers"], t.requests[1]["headers"]
    for k in ("x-govpilot-run-id", "x-govpilot-parent-run-id", "x-govpilot-root-run-id", "x-govpilot-run-kind",
              "x-govpilot-tool"):
        assert h1[k] == h2[k], k
    assert (h1["x-govpilot-attempt"], h2["x-govpilot-attempt"]) == ("1", "2")
    assert json.loads(h2["x-litellm-spend-logs-metadata"])["attempt"] == 2
    ev = sink.of("llm.attempt")
    assert [e["attempt"] for e in ev] == [1, 2] and {e["run_id"] for e in ev} == {child.run_id}
    assert [e["ok"] for e in ev] == [False, True]


def test_attempts_are_capped_and_the_error_names_the_run(sink):
    gw, t, _ = client([err(503)] * 10, sink, retry=RetryPolicy(max_attempts=3, base_delay_s=0.01))
    run = RunContext.root("a-agent")
    with pytest.raises(GatewayError) as ei:
        gw.chat(run, "mock-local", MSGS)
    assert len(t.requests) == 3 and ei.value.attempts == 3 and ei.value.run_id == run.run_id and ei.value.status == 503
    assert [r["headers"]["x-govpilot-attempt"] for r in t.requests] == ["1", "2", "3"]


def test_backoff_grows_and_honours_retry_after(sink):
    gw, _, sleeps = client([err(503), err(503, headers={"retry-after": "2"}), err(503), chat_ok()], sink,
                           retry=RetryPolicy(max_attempts=5, base_delay_s=0.1, max_delay_s=5))
    gw.chat(RunContext.root("a-agent"), "m", MSGS)
    assert sleeps == [0.1, 2.0, 0.4]


@pytest.mark.parametrize("resp", [err(400, "invalid_request_error"), err(403, "auth_error"),
                                  err(404), err(429, "budget_exceeded", "Budget has been exceeded"),
                                  err(400, "max_tokens_exceeds_ceiling"), err(400, "guardrail_violation"),
                                  err(400, "run_id_required")])
def test_non_retryable_failures_are_not_retried(sink, resp):
    gw, t, sleeps = client([resp, chat_ok()], sink)
    with pytest.raises(GatewayError) as ei:
        gw.chat(RunContext.root("a-agent"), "m", MSGS)
    assert len(t.requests) == 1 and not sleeps and ei.value.attempts == 1


def test_budget_refusal_is_recognisable_and_a_stop_is_recognisable(sink):
    gw, _, _ = client([err(429, "budget_exceeded", "Budget has been exceeded")], sink)
    with pytest.raises(GatewayError) as ei:
        gw.chat(RunContext.root("a-agent"), "m", MSGS)
    assert ei.value.budget_exceeded and not ei.value.stopped
    gw, _, _ = client([err(401, "auth_error", "key blocked"), err(401, "auth_error", "key blocked")], sink)
    with pytest.raises(GatewayError) as ei:
        gw.chat(RunContext.root("a-agent"), "m", MSGS)
    assert ei.value.stopped


def test_expired_jwt_is_refreshed_once_and_the_retry_keeps_the_run(sink):
    calls = {"tokens": 0}

    class Idp:
        def send(self, method, url, headers, body, timeout):
            calls["tokens"] += 1
            from govagent import HttpResponse
            return HttpResponse(200, {}, json.dumps({"access_token": f"jwt{calls['tokens']}", "expires_in": 900}).encode())
    auth = OIDCClientCredentialsAuth("http://idp/token", "cid", "sec", transport=Idp())
    gw, t, _ = client([err(401, "auth_error", "expired"), chat_ok()], sink, auth=auth)
    run = RunContext.root("finance-recon-agent")
    res = gw.chat(run, "m", MSGS)
    assert res.attempts == 2 and calls["tokens"] == 2
    assert [r["headers"]["authorization"] for r in t.requests] == ["Bearer jwt1", "Bearer jwt2"]
    assert {r["headers"]["x-govpilot-run-id"] for r in t.requests} == {run.run_id}


def test_oidc_token_is_cached_and_refreshed_before_expiry():
    now = [1000.0]
    n = {"c": 0}

    class Idp:
        def send(self, *a):
            from govagent import HttpResponse
            n["c"] += 1
            return HttpResponse(200, {}, json.dumps({"access_token": f"t{n['c']}", "expires_in": 300}).encode())
    a = OIDCClientCredentialsAuth("http://idp/token", "c", "s", transport=Idp(), clock=lambda: now[0])
    assert a.headers()["authorization"] == "Bearer t1" and a.headers()["authorization"] == "Bearer t1" and n["c"] == 1
    now[0] += 250                           # inside the 60 s skew: refresh
    assert a.headers()["authorization"] == "Bearer t2"


def test_auth_schemes_use_the_right_header():
    assert StaticKeyAuth("k").headers() == {"authorization": "Bearer k"}
    assert MacaroonAuth("gpm1.x.y").headers() == {"authorization": "Macaroon gpm1.x.y"}


def test_unreachable_identity_provider_is_a_gateway_error_not_a_crash(sink):
    class Down:
        def send(self, *a):
            raise TransportError("refused")
    gw, t, _ = client([], sink, auth=OIDCClientCredentialsAuth("http://idp/token", "c", "s", transport=Down()))
    run = RunContext.root("finance-recon-agent")
    with pytest.raises(GatewayError) as ei:
        gw.chat(run, "m", MSGS)
    assert ei.value.run_id == run.run_id and not t.requests


def test_concurrent_runs_never_share_a_run_id(sink):
    import threading
    t = ScriptedTransport([])
    gw = GatewayClient("http://gateway:4000", StaticKeyAuth("k"), transport=t, sink=sink)
    runs = [RunContext.root("a-agent") for _ in range(40)]
    ths = [threading.Thread(target=gw.chat, args=(r, "m", MSGS)) for r in runs]
    [x.start() for x in ths]
    [x.join() for x in ths]
    assert sorted(r["headers"]["x-govpilot-run-id"] for r in t.requests) == sorted(r.run_id for r in runs)
