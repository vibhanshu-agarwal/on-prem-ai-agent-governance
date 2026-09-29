"""Concurrency: N parallel requests against a key with a small max_budget.

Per request (mock-local, 7 prompt tokens, max_tokens=100): actual $0.000207; native
reservation $0.000211 (tiktoken input estimate 11 tokens + 100 output tokens).
"""
import asyncio

import httpx
import pytest

from t2lib import EPS, gather_limited, resp_cost, error_of

CAP = 0.002
N = 60


async def _burst(gw, key, n, **body):
    async with httpx.AsyncClient(timeout=120) as c:
        return await gather_limited([gw.chat(c, key, **body) for _ in range(n)])


@pytest.mark.parametrize("model,max_tokens", [("mock-local", 100), ("mock-remote", 20)])
def test_parallel_requests_never_exceed_key_cap(guarded, record, model, max_tokens):
    key = guarded.new_key(max_budget=CAP, models=[model])
    rs = asyncio.run(_burst(guarded, key, N, model=model, max_tokens=max_tokens))
    ok = [r for r in rs if r.status_code == 200]
    rejected = [r for r in rs if r.status_code != 200]
    total = sum(resp_cost(r) for r in ok)
    counter = guarded.counter("key", key.token)
    record(**{f"{model}.admitted": len(ok), f"{model}.rejected": len(rejected),
              f"{model}.spend": total, f"{model}.counter": counter, "cap": CAP})
    assert ok, "some requests must be admitted"
    assert total <= CAP + EPS, f"overshoot: {total} > {CAP}"
    assert counter <= CAP + EPS and abs(counter - total) < 1e-9
    # every rejection is a clear budget error, never a 5xx or a provider error
    for r in rejected:
        e = error_of(r)
        assert r.status_code == 429, (r.status_code, e)
        assert e.get("type") == "budget_exceeded" and "Budget has been exceeded" in e.get("message", "")
    # the cap is actually used up (not a trivially-low admission): < one request of headroom left
    per = total / len(ok)
    assert CAP - total < 2 * per


def test_follow_up_requests_after_exhaustion_stay_rejected(guarded, record):
    key = guarded.new_key(max_budget=CAP)
    asyncio.run(_burst(guarded, key, 40, max_tokens=100))
    rs = asyncio.run(_burst(guarded, key, 20, max_tokens=1))   # tiny requests cannot sneak in above cap
    total = guarded.counter("key", key.token)
    record(spend_after=total, tiny_admitted=sum(r.status_code == 200 for r in rs))
    assert total <= CAP + EPS


@pytest.mark.native_baseline
@pytest.mark.parametrize("model,max_tokens,cap", [("mock-local", 100, 0.002), ("mock-remote", 1000, 0.02)])
def test_native_partial_reservation_overshoots_sequentially(native, guarded, record, model, max_tokens, cap):
    """Native LiteLLM resizes the reservation down to the remaining budget and still
    admits the request; the request then costs its full price. Deterministic, no
    concurrency needed. mock-local: 9 requests leave $0.000137, the 10th is admitted and
    costs $0.000207. mock-remote/1000 tokens: the 2nd request is admitted on $0.005 left
    and costs $0.015."""
    out = {}
    for gw in (native, guarded):
        key = gw.new_key(max_budget=cap, models=[model])

        async def seq():
            async with httpx.AsyncClient(timeout=60) as c:
                return [await gw.chat(c, key, model=model, max_tokens=max_tokens) for _ in range(12)]
        rs = asyncio.run(seq())
        out[gw.name] = (sum(r.status_code == 200 for r in rs), sum(resp_cost(r) for r in rs))
    record(cap=cap, native_admitted=out["native"][0], native_spend=out["native"][1],
           guarded_admitted=out["guarded"][0], guarded_spend=out["guarded"][1],
           native_overshoot_pct=100 * (out["native"][1] - cap) / cap)
    assert out["native"][1] > cap, "native overshoot no longer reproduces (LiteLLM changed?)"
    assert out["guarded"][1] <= cap + EPS


@pytest.mark.native_baseline
def test_native_parallel_overshoot(native, record):
    key = native.new_key(max_budget=CAP)
    rs = asyncio.run(_burst(native, key, N, max_tokens=100))
    total = sum(resp_cost(r) for r in rs)
    record(native_admitted=sum(r.status_code == 200 for r in rs), native_spend=total,
           native_overshoot_pct=100 * (total - CAP) / CAP)
    assert total > CAP
