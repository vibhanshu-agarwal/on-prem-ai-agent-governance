"""Non-destructive checks on the SHARED `govpilot` stack (127.0.0.1:4000): proves the
production wiring (deploy/litellm/config.yaml + deploy/docker-compose.yml) carries the
budget guard. Creates its own throwaway keys and deletes them afterwards."""
import asyncio

import httpx
import pytest

from t2lib import EPS, error_of, gather_limited, resp_cost

pytestmark = pytest.mark.shared
CAP = 0.002


def test_shared_guard_rejects_huge_max_tokens(shared, record):
    key = shared.new_key(max_budget=CAP)

    async def go():
        async with httpx.AsyncClient(timeout=60) as c:
            return await shared.chat(c, key, max_tokens=100000)
    r = asyncio.run(go())
    record(status=r.status_code, error_type=error_of(r).get("type"))
    assert r.status_code == 400 and error_of(r)["type"] == "max_tokens_exceeds_ceiling"


def test_shared_parallel_and_sequential_zero_overshoot(shared, record):
    k1, k2 = shared.new_key(max_budget=CAP), shared.new_key(max_budget=CAP)

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            par = await gather_limited([shared.chat(c, k1, max_tokens=100) for _ in range(40)])
            seq = [await shared.chat(c, k2, max_tokens=100) for _ in range(12)]
            return par, seq
    par, seq = asyncio.run(go())
    p, s = sum(resp_cost(r) for r in par), sum(resp_cost(r) for r in seq)
    ttl = shared.counter_ttl("key", k1.token)
    record(parallel_spend=p, sequential_spend=s, cap=CAP, counter_ttl_s=ttl)
    assert p <= CAP + EPS and s <= CAP + EPS
    assert ttl > 60      # spend counters pinned for the budget period (default_redis_ttl)
