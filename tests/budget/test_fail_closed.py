"""Fail closed: with Redis down and with Postgres down, budgeted requests are rejected.
Destructive: stops containers of the ISOLATED stack only (t2-redis / t2-postgres)."""
import asyncio
import time

import httpx
import pytest

from t2lib import EPS, error_of, gather_limited, resp_cost, sh

pytestmark = pytest.mark.destructive
CAP = 0.002


async def _call(gw, key, timeout=60):
    async with httpx.AsyncClient(timeout=timeout) as c:
        t = time.time()
        try:
            r = await gw.chat(c, key, max_tokens=5)
            return r.status_code, error_of(r) if r.status_code != 200 else {}, time.time() - t
        except httpx.HTTPError as e:
            return None, {"exc": type(e).__name__}, time.time() - t


def test_redis_down_rejects_budgeted_requests(native, guarded, record):
    keys = {gw.name: (gw.new_key(max_budget=1.0), gw.new_key()) for gw in (native, guarded)}
    for gw in (native, guarded):                     # warm the auth cache
        for k in keys[gw.name]:
            assert asyncio.run(_call(gw, k))[0] == 200
    sh("docker", "stop", "t2-redis")
    try:
        res = {}
        for gw in (native, guarded):
            budgeted, unbudgeted = keys[gw.name]
            b = [asyncio.run(_call(gw, budgeted)) for _ in range(3)]
            u = asyncio.run(_call(gw, unbudgeted))
            res[gw.name] = (b, u)
            record(**{f"{gw.name}.budgeted": [(s, round(t, 1)) for s, _, t in b],
                      f"{gw.name}.budgeted_error": b[0][1].get("message", "")[:120],
                      f"{gw.name}.unbudgeted_status": u[0]})
        for name, (b, u) in res.items():
            assert all(s == 503 for s, _, _ in b), (name, b)
            assert "fail_closed_budget_enforcement" in b[0][1]["message"]
            assert u[0] == 200          # keys/teams without any budget have nothing to enforce
    finally:
        sh("docker", "start", "t2-redis")
    t_back = time.time()
    for gw in (guarded, native):
        gw.wait_budget_enforcement()
    # the Redis client circuit breaker keeps failing closed for up to ~60 s after Redis returns
    record(budget_enforcement_back_after_s=round(time.time() - t_back, 1))
    # recovery: enforcement resumes against the persisted counters
    key = guarded.new_key(max_budget=CAP)

    async def burst():
        async with httpx.AsyncClient(timeout=120) as c:
            return await gather_limited([guarded.chat(c, key, max_tokens=100) for _ in range(30)])
    total = sum(resp_cost(r) for r in asyncio.run(burst()))
    record(after_recovery_spend=total)
    assert 0 < total <= CAP + EPS


def test_postgres_down_rejects_budgeted_requests(native, guarded, record):
    keys = {gw.name: guarded.new_key(max_budget=CAP) if gw is guarded else native.new_key(max_budget=CAP)
            for gw in (native, guarded)}
    for gw in (native, guarded):
        assert asyncio.run(_call(gw, keys[gw.name]))[0] == 200
    sh("docker", "stop", "t2-postgres")
    t0 = time.time()
    timeline = {"native": [], "guarded": []}

    async def probe_loop(gw):     # one independent loop per gateway so a slow one cannot skew the other
        while time.time() - t0 < 80:
            s, e, dt = await _call(gw, keys[gw.name], timeout=40)
            timeline[gw.name].append((round(time.time() - t0, 1), s))
            await asyncio.sleep(2)

    async def both():
        await asyncio.gather(probe_loop(native), probe_loop(guarded))
    try:
        asyncio.run(both())
    finally:
        sh("docker", "start", "t2-postgres")

    def first_reject(tl):
        return next((t for t, s in tl if s != 200), None)
    admitted_native = sum(1 for _, s in timeline["native"] if s == 200)
    admitted_guarded = sum(1 for _, s in timeline["guarded"] if s == 200)
    counter_native = native.counter("key", keys["native"].token)
    record(native_admitted_while_db_down=admitted_native, native_first_reject_s=first_reject(timeline["native"]),
           guarded_admitted_while_db_down=admitted_guarded, guarded_first_reject_s=first_reject(timeline["guarded"]),
           native_counter=counter_native, timeline=timeline)
    guarded.wait_budget_enforcement()
    native.wait_budget_enforcement()
    after = asyncio.run(_call(guarded, keys["guarded"]))
    record(guarded_status_after_recovery=after[0])
    # guarded: fail closed within the probe staleness window (5 s) + one probe interval + call time
    assert first_reject(timeline["guarded"]) is not None and first_reject(timeline["guarded"]) <= 12
    assert all(s != 200 for t, s in timeline["guarded"] if t > 12)
    # native (documented): admits from its auth cache for a while; the Redis counter still caps spend
    assert counter_native <= CAP + EPS
    assert after[0] == 200
