"""Streaming: reservation = input estimate + output ceiling, held for the stream's life;
usage committed at stream end; unused reservation released; a provider that overruns
the reserved output ceiling is cut off with an auditable budget event."""
import asyncio
import time

import httpx
import pytest

from t2lib import EPS, cost, gather_limited

CAP = 0.002


def test_reservation_held_during_stream_then_reconciled(guarded, record):
    key = guarded.new_key(max_budget=1.0, models=["mock-local-slow"])
    mid = {}

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            async def on_first():
                mid["counter"] = guarded.counter("key", key.token)
            return await guarded.stream(c, key, model="mock-local-slow", max_tokens=6, on_first=on_first)
    out = asyncio.run(go())
    time.sleep(1)
    final = guarded.counter("key", key.token)
    actual = cost("mock-local-slow", 7, 6)
    record(mid_stream_counter=mid["counter"], final_counter=final, actual_cost=actual,
           released=mid["counter"] - final, usage=out["usage"])
    assert out["status"] == 200 and out["chunks"] == 6 and out["usage"]["completion_tokens"] == 6
    assert mid["counter"] >= actual - EPS          # reservation covers the worst case while streaming
    assert mid["counter"] > final                  # ...and the unused part is released at the end
    assert abs(final - actual) < 1e-12             # usage committed at stream end (provider usage)


def test_client_disconnect_bills_partial_and_releases_rest(guarded, record):
    key = guarded.new_key(max_budget=1.0)

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return await guarded.stream(c, key, max_tokens=800, stop_after=100)
    out = asyncio.run(go())
    time.sleep(4)
    final = guarded.counter("key", key.token)
    reserved_upper = 20 * 1e-6 + 800 * 2e-6
    record(delivered_chunks=out["chunks"], counter_after=final, reserved_upper_bound=reserved_upper)
    assert out["chunks"] >= 100
    assert final > cost("mock-local", 7, 0)          # partial output is billed, not refunded to input-only
    assert final < reserved_upper                    # the unused reservation is released


def test_parallel_streams_never_exceed_cap(guarded, record):
    key = guarded.new_key(max_budget=CAP)

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return await gather_limited([guarded.stream(c, key, max_tokens=100) for _ in range(40)])
    outs = asyncio.run(go())
    time.sleep(1)
    ok = [o for o in outs if o["status"] == 200]
    counter = guarded.counter("key", key.token)
    record(admitted=len(ok), rejected=len(outs) - len(ok), counter=counter, cap=CAP)
    assert ok and counter <= CAP + EPS
    assert all(o["status"] == 429 and "Budget has been exceeded" in o["error"] for o in outs if o["status"] != 200)


@pytest.mark.native_baseline
def test_native_runaway_stream_overruns_reservation(native, record):
    key = native.new_key(max_budget=1.0, models=["mock-runaway"])

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return await native.stream(c, key, model="mock-runaway", max_tokens=50)
    out = asyncio.run(go())
    time.sleep(1)
    spent = native.counter("key", key.token)
    reserved = 11 * 1e-6 + 50 * 2e-6
    record(chunks=out["chunks"], spend=spent, reserved_estimate=reserved, overrun_x=spent / reserved)
    assert out["chunks"] == 600 and spent > 5 * reserved


def test_runaway_stream_cut_at_reservation_with_audit_event(guarded, record):
    key = guarded.new_key(max_budget=1.0, models=["mock-runaway"])
    t0 = time.time()

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return await guarded.stream(c, key, model="mock-runaway", max_tokens=50)
    out = asyncio.run(go())
    time.sleep(2)
    counter = guarded.counter("key", key.token)
    evs = [e for e in guarded.budget_events(since=t0)
           if e["key_hash"] == key.token and e["event"] == "budget.stream_terminated"]
    assert out["status"] == 200 and out["chunks"] == 50 and out["finish"] == "length"
    assert len(evs) == 1 and evs[0]["partial_billed"] is True
    reserved = evs[0]["reserved_cost"]
    one_token = 2e-6
    record(chunks=out["chunks"], finish=out["finish"], counter=counter, reserved=reserved,
           over_reservation=counter - reserved, event=evs[0])
    # billed as received: the one token that proved the overrun is charged (never hidden)
    assert counter <= reserved + one_token + EPS
    assert counter >= cost("mock-runaway", 7, 50)
    # usage lands in the audit trail (spend log) once the batch writer flushes
    deadline = time.time() + 40
    while time.time() < deadline and guarded.spend_logs_total(key.token)[1] == 0:
        time.sleep(2)
    logged, n = guarded.spend_logs_total(key.token)
    record(spend_log_total=logged, spend_log_rows=n)
    assert n == 1 and abs(logged - counter) < 1e-9


def test_runaway_non_streaming_detected(guarded, record):
    """Non-streaming responses arrive whole: the gateway cannot cut them. The overrun is
    billed truthfully and flagged; residual risk documented (provider must honour max_tokens)."""
    key = guarded.new_key(max_budget=1.0, models=["mock-runaway"])
    t0 = time.time()

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return await guarded.chat(c, key, model="mock-runaway", max_tokens=50)
    r = asyncio.run(go())
    time.sleep(1)
    evs = [e for e in guarded.budget_events(since=t0)
           if e["key_hash"] == key.token and e["event"] == "budget.provider_exceeded_max_tokens"]
    record(completion_tokens=r.json()["usage"]["completion_tokens"], counter=guarded.counter("key", key.token),
           events=len(evs))
    assert r.status_code == 200 and len(evs) == 1
