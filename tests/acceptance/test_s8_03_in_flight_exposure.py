"""S8-03 In-flight exposure: streaming/cancel behaviour measured per provider; the residual spend of the request
that is in flight when the agent is stopped is bounded by the output-token ceiling and a time ceiling.

For each provider (mock-local, mock-remote, slow streaming variants) and each gateway streaming mode:
  passthrough  the drill key streams token by token (T3 drills)
  buffer       the production default for agents (T5 output guardrails hold the stream until it is complete)
a drill agent streams `max_tokens=MAX` completions; the agent is stopped mid-stream; from the gateway's own spend
log row of the in-flight request we take the billed completion tokens, the spend, and when billing stopped.

Finding that shaped T8: in buffer mode no byte reaches the agent before the stream ends, so the network cut
alone did not reach the gateway's upstream and the provider generated all max_tokens (billed in full, 29 s
after the stop). The budget guard now re-checks the key every second mid-stream and closes the upstream once
the stop has blocked it (budget.stream_terminated, reason key_revoked).
"""
from __future__ import annotations

import time

import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")

MAX = 60                         # output-token ceiling of the in-flight request
PRICE_OUT = {"mock-local-slow": 0.000002, "mock-remote-slow": 0.000015}
PRICE_IN = {"mock-local-slow": 0.000001, "mock-remote-slow": 0.000005}
SEC_PER_TOKEN = {"mock-local-slow": 0.5, "mock-remote-slow": 1.0}      # mock latency x SLOW_FACTOR


def _one(alice, drill, model, passthrough):
    ag = drill.agent(L.uid("t8fly"), models=(model,), passthrough=passthrough)
    agent_id, key = ag["agent"]["agent_id"], ag["gateway_key"]
    kh = ag["agent"]["gateway_keys"][0]["key_hash"]
    c = drill.run(ag, env={"MODEL": model, "MAX_TOKENS": str(MAX)})
    L.wait_for_log(c, r"START ")
    time.sleep(4.0)                                            # a few tokens into the first stream
    t0 = time.time()
    rep = alice.post(f"/v1/agents/{agent_id}/stop", {"reason": "acceptance S8-03"}).json()
    t_contained = time.time()
    worst = (MAX * PRICE_OUT[model]) + 20 * PRICE_IN[model]          # generous input allowance for the bound
    full_s = MAX * SEC_PER_TOKEN[model]
    # wait for the in-flight row: it ends either at the cut or, if nothing cuts it upstream, at max_tokens
    # (the stop's own verification makes one refused request with the key: a failure row with 0 tokens)
    row = L.wait_until(lambda: next((r for r in L.spend_rows(kh, since_s=600)
                                     if r.get("status") == "success"), None), timeout=full_s + 30, interval=2.0)
    assert row, "no spend-log row for the in-flight request"
    from datetime import datetime
    end = datetime.fromisoformat(row["endTime"].replace("Z", "+00:00")).timestamp()
    toks = int(row.get("completion_tokens") or 0)
    spend = float(row.get("spend") or 0)
    return {"model": model, "mode": "passthrough" if passthrough else "buffer (production default)",
            "billed_completion_tokens": toks, "max_tokens": MAX, "spend_usd": round(spend, 8),
            "worst_case_usd": round(worst, 8), "billing_ended_after_decision_s": round(end - t0, 2),
            "stream_would_take_s": full_s, "stop_total_s": round(t_contained - t0, 2),
            "network_connections_before_after": [rep["network"]["results"][0].get("connections_before"),
                                                 rep["network"]["results"][0].get("connections_after")],
            "verify_ok": rep["verify"]["ok"], "within_bound": toks <= MAX and spend <= worst + 1e-9}


@pytest.mark.accept(
    id="S8-03", title="In-flight exposure",
    criterion="Per provider and streaming mode: residual spend of the in-flight request <= its output-token "
              "ceiling (reservation), and billing ends within a time ceiling (the stop, or max_tokens x per-token latency)",
    simplification="Two mock providers with deterministic token latency; a real provider's cancel semantics "
                   "(does it stop generating when the gateway drops the upstream?) must be measured per provider.")
def test_in_flight_exposure(alice, drill, record):
    rows = []
    for model in ("mock-local-slow", "mock-remote-slow"):
        for passthrough in (True, False):
            rows.append(_one(alice, drill, model, passthrough))
    record(results=rows)
    for r in rows:
        assert r["within_bound"], r
        assert r["billing_ended_after_decision_s"] <= r["stream_would_take_s"] + 5, r
        # not merely the max_tokens ceiling: the gateway must have cut the in-flight stream itself (key re-checked
        # every second mid-stream, upstream closed once blocked), so billing ends with the stop, not 30-60 s later
        assert r["billing_ended_after_decision_s"] <= r["stop_total_s"] + 5, \
            f"stream ran on after the stop instead of being cut by the gateway: {r}"
