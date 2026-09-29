"""M-02 Zero hard-cap overshoot and M-03 max_tokens default, on the PRODUCTION gateway (all callbacks on).

The full T2 matrix (concurrency, retries, fallbacks, streaming, delayed telemetry, restarts, Redis/Postgres
outages, runaway provider) runs on the isolated stack in tests/budget (scripts/acceptance.sh runs it and the
report shows its result next to these rows); M-02b adds the restart drill.
"""
from __future__ import annotations

import asyncio
import json
import time

import httpx
import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")

COST = 7 * 1e-6 + 100 * 2e-6          # mock-local, 7 prompt tokens, 100 output tokens = $0.000207
MSG = [{"role": "user", "content": "one two three four"}]


async def _burst(key, n, stream=False):
    async with httpx.AsyncClient(timeout=120) as c:
        async def one(i):
            body = {"model": "mock-local", "messages": MSG, "max_tokens": 100, "stream": stream}
            h = {"Authorization": f"Bearer {key}", "x-govpilot-run-id": f"run-t8burst{i:08d}"}
            if not stream:
                r = await c.post(f"{L.GW_URL}/v1/chat/completions", headers=h, json=body)
                return r.status_code
            async with c.stream("POST", f"{L.GW_URL}/v1/chat/completions", headers=h, json=body) as r:
                await r.aread()
                return r.status_code
        return await asyncio.gather(*(one(i) for i in range(n)))


def _settled_spend(kh, want_rows_at_least=1, timeout=40):
    def total():
        rows = [r for r in L.spend_rows(kh, since_s=600) if float(r.get("spend") or 0) > 0]
        return (round(sum(float(r["spend"]) for r in rows), 9), len(rows)) if len(rows) >= want_rows_at_least else None
    return L.wait_until(total, timeout=timeout, interval=2.0)


@pytest.mark.accept(
    id="M-02", title="Zero hard-cap overshoot (production gateway)",
    criterion="On the production gateway with every callback loaded: 60 parallel requests and 40 parallel "
              "streams against keys capped at $0.002 never spend more than the cap (spend logs, Redis counter)",
    simplification="Mock providers honour max_tokens; the isolated T2 suite covers retries, fallbacks, runaway "
                   "providers, delayed telemetry and outages; one gateway replica.")
def test_zero_overshoot_production(record):
    cap = 0.002
    out = {}
    for label, n, stream in (("parallel_requests", 60, False), ("parallel_streams", 40, True)):
        k = L.mint_key(budget=cap, models=["mock-local"], metadata={"agent_id": L.uid("t8cap")})
        try:
            statuses = asyncio.run(_burst(k["key"], n, stream))
            ok = sum(1 for s in statuses if s == 200)
            time.sleep(6)
            spent, rows = _settled_spend(k["token"], want_rows_at_least=min(ok, 1)) or (0.0, 0)
            counter = float(L.redis_cli("GET", f"spend:key:{k['token']}") or 0)
            out[label] = {"sent": n, "admitted": ok, "refused": n - ok, "spend_logs_usd": spent,
                          "redis_counter_usd": round(counter, 9), "cap_usd": cap,
                          "overshoot_usd": round(max(0.0, spent - cap, counter - cap), 9)}
        finally:
            L.delete_keys(k["token"])
    record(**out)
    for label, r in out.items():
        assert r["overshoot_usd"] == 0, (label, r)
        assert r["admitted"] <= int(cap / COST) + 1, (label, r)


@pytest.mark.accept(
    id="M-03", title="max_tokens default and auditable stream termination",
    criterion="A request without max_tokens is bounded by the agent default (key token_policy), one above the "
              "agent ceiling is refused (400), and a terminated streaming reservation leaves a "
              "budget.stream_terminated event in the gateway log",
    simplification="The 'reservation exhausted by a runaway provider' cut needs the runaway mock and runs in the "
                   "isolated T2 suite (test_runaway_stream_cut_at_reservation_with_audit_event); here the event "
                   "comes from the in-flight kill of a stream whose key is blocked mid-stream.")
def test_max_tokens_default_and_stream_event(record):
    pol = {"token_policy": {"max_tokens_ceiling": 64, "default_max_tokens": 24, "on_exceed": "reject"}}
    k = L.mint_key(budget=0.05, models=["mock-local"], metadata={"agent_id": L.uid("t8mt"), **pol})
    try:
        h = {"Authorization": f"Bearer {k['key']}", "x-govpilot-run-id": "run-t8maxtokens01"}
        r = httpx.post(f"{L.GW_URL}/v1/chat/completions", headers=h, timeout=30,
                       json={"model": "mock-local", "messages": MSG})
        assert r.status_code == 200, r.text
        default_tokens = r.json()["usage"]["completion_tokens"]
        big = httpx.post(f"{L.GW_URL}/v1/chat/completions", headers=h, timeout=30,
                         json={"model": "mock-local", "messages": MSG, "max_tokens": 100000})
        code = (big.json().get("error") or {}).get("code") if big.status_code != 200 else None
        # a buffered stream (production default) whose key is blocked mid-stream is terminated and audited
        since = time.time()
        k2 = L.mint_key(budget=0.05, models=["mock-local-slow"], metadata={"agent_id": L.uid("t8mt")})

        async def stream_then_block():
            async with httpx.AsyncClient(timeout=120) as c:
                async def blocker():
                    await asyncio.sleep(2.5)
                    await c.post(f"{L.GW_URL}/key/block", json={"key": k2["token"]},
                                 headers={"Authorization": f"Bearer {L.ENV['LITELLM_MASTER_KEY']}"})
                t = asyncio.create_task(blocker())
                t0 = time.time()
                async with c.stream("POST", f"{L.GW_URL}/v1/chat/completions", json={
                        "model": "mock-local-slow", "messages": MSG, "max_tokens": 40, "stream": True},
                        headers={"Authorization": f"Bearer {k2['key']}"}) as r:
                    await r.aread()
                await t
                return time.time() - t0
        stream_s = asyncio.run(stream_then_block())
    finally:
        L.delete_keys(k["token"])
    time.sleep(1)
    logs = L.dclient().containers.get("gov-gateway").logs(since=int(since) - 1).decode(errors="replace")
    evs = [json.loads(l.split("GOVPILOT_BUDGET_EVENT ", 1)[1]) for l in logs.splitlines()
           if "GOVPILOT_BUDGET_EVENT " in l and "budget.stream_terminated" in l]
    evs = [e for e in evs if e.get("ts", 0) >= since]
    L.delete_keys(k2["token"])
    record(default_applied_tokens=default_tokens, agent_default=24, above_ceiling_status=big.status_code,
           above_ceiling_code=code, stream_terminated_events_in_gateway_log=len(evs),
           blocked_stream_ended_after_s=round(stream_s, 1), full_stream_would_take_s=20,
           sample_event={k2: evs[-1].get(k2) for k2 in ("event", "reason", "partial_billed", "agent_id")} if evs else None)
    assert default_tokens == 24
    assert big.status_code == 400
    assert evs and "key_revoked" in (evs[-1].get("reason") or ""), evs
    assert stream_s < 10, "the blocked stream ran on instead of being terminated"
