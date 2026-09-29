"""Retries and fallbacks must not overshoot.

Isolated-stack models (tests/budget/stack/t2stack.py):
  mock-flaky         two deployments, one on a dead port -> router retries
  mock-local-broken  dead port, router fallback -> mock-remote ($5/$15 per M, 7.5x mock-local output)
  mock-local-dead    dead port, no router fallback (client sends request-body fallbacks)
Native reservation is priced on the REQUESTED model only, so a fallback to a pricier
model can cost more than was reserved.
"""
import asyncio

import httpx
import pytest

from t2lib import EPS, cost, error_of, gather_limited, resp_cost

CAP = 0.002


def _run(coro):
    return asyncio.run(coro)


def test_router_retries_bill_once_and_never_overshoot(guarded, record):
    key = guarded.new_key(max_budget=CAP, models=["mock-flaky"])

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return [await guarded.chat(c, key, model="mock-flaky", max_tokens=100, num_retries=3)
                    for _ in range(15)]
    rs = _run(go())
    ok = [r for r in rs if r.status_code == 200]
    retries = sum(int(r.headers.get("x-litellm-attempted-retries") or 0) for r in rs)
    total = sum(resp_cost(r) for r in ok)
    record(admitted=len(ok), attempted_retries=retries, spend=total, counter=guarded.counter("key", key.token))
    assert ok and retries > 0, "retries were not exercised"
    for r in ok:   # a retried request is billed once, for the attempt that produced tokens
        assert abs(resp_cost(r) - cost("mock-local", 7, 100)) < 1e-12
    assert total <= CAP + EPS
    assert abs(guarded.counter("key", key.token) - total) < 1e-9
    assert all(r.status_code in (200, 429) for r in rs), [r.text[:200] for r in rs if r.status_code not in (200, 429)]


def test_concurrent_retries_never_overshoot(guarded, record):
    key = guarded.new_key(max_budget=CAP, models=["mock-flaky"])

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return await gather_limited([guarded.chat(c, key, model="mock-flaky", max_tokens=100, num_retries=3)
                                         for _ in range(40)])
    rs = _run(go())
    total = sum(resp_cost(r) for r in rs)
    record(admitted=sum(r.status_code == 200 for r in rs), spend=total)
    assert total <= CAP + EPS


@pytest.mark.native_baseline
def test_native_fallback_to_pricier_model_overshoots(native, record):
    key = native.new_key(max_budget=CAP, models=["mock-local-broken", "mock-remote"])

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return await native.chat(c, key, model="mock-local-broken", max_tokens=200)
    r = _run(go())
    spent = resp_cost(r)
    record(status=r.status_code, served_by=r.headers.get("x-litellm-model-api-base"), spend=spent, cap=CAP,
           reserved_estimate=11 * 1e-6 + 200 * 2e-6, overshoot_pct=100 * (spent - CAP) / CAP)
    assert r.status_code == 200 and "mock-remote" in (r.headers.get("x-litellm-model-api-base") or "")
    assert spent > CAP     # one fallback request spends 1.5x the key's whole budget


def test_fallback_rejected_when_reservation_cannot_cover_it(guarded, record):
    key = guarded.new_key(max_budget=CAP, models=["mock-local-broken", "mock-remote"])

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return await guarded.chat(c, key, model="mock-local-broken", max_tokens=200)
    r = _run(go())
    e = error_of(r)
    record(status=r.status_code, error=e.get("message", "")[:160], counter=guarded.counter("key", key.token))
    assert r.status_code == 429 and e.get("type") == "budget_exceeded"
    assert "mock-remote" in e["message"]
    assert guarded.counter("key", key.token) == 0.0


def test_fallback_clamped_to_reservation_never_overshoots(guarded, record):
    """on_insufficient_reservation=clamp: max_tokens is cut so the pricier fallback fits
    the reservation; under concurrency the key never exceeds its cap."""
    key = guarded.new_key(max_budget=CAP, models=["mock-local-broken", "mock-remote"],
                          metadata={"token_policy": {"on_insufficient_reservation": "clamp"}})

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return await gather_limited([guarded.chat(c, key, model="mock-local-broken", max_tokens=200)
                                         for _ in range(30)])
    rs = _run(go())
    ok = [r for r in rs if r.status_code == 200]
    total = sum(resp_cost(r) for r in ok)
    completions = sorted({r.json()["usage"]["completion_tokens"] for r in ok})
    record(admitted=len(ok), spend=total, cap=CAP, clamped_completion_tokens=completions)
    assert ok and all("mock-remote" in (r.headers.get("x-litellm-model-api-base") or "") for r in ok)
    assert max(completions) < 200
    assert total <= CAP + EPS


@pytest.mark.parametrize("gw_name", ["native", "guarded"])
def test_request_body_fallbacks(request, record, gw_name):
    """Client-supplied fallbacks: the key allowlist is enforced natively; the guard also
    prices them."""
    gw = request.getfixturevalue(gw_name)
    denied_key = gw.new_key(max_budget=CAP, models=["mock-local-dead"])
    key = gw.new_key(max_budget=CAP, models=["mock-local-dead", "mock-remote"])

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            a = await gw.chat(c, denied_key, model="mock-local-dead", max_tokens=200, fallbacks=["mock-remote"])
            b = await gw.chat(c, key, model="mock-local-dead", max_tokens=200, fallbacks=["mock-remote"])
            return a, b
    a, b = _run(go())
    record(not_allowlisted_status=a.status_code, allowlisted_status=b.status_code, spend=resp_cost(b))
    assert a.status_code in (401, 403)          # fallback outside the key's allowlist is refused
    if gw_name == "native":
        assert b.status_code == 200 and resp_cost(b) > CAP    # gap: priced on the primary only
    else:
        assert b.status_code == 429 and error_of(b)["type"] == "budget_exceeded"
