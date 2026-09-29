"""Delayed telemetry: Postgres key/team spend lags the live Redis counters by up to
proxy_batch_write_at (15 s in the isolated stack, 5 s on the shared one). The lag must
not open an overshoot window, including across gateway restarts and a Redis restart."""
import asyncio
import subprocess
import time

import httpx
import pytest

from t2lib import EPS, gather_limited, resp_cost, sh

CAP = 0.002


def _burst(gw, key, n=30, **body):
    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return await gather_limited([gw.chat(c, key, max_tokens=100, **body) for _ in range(n)])
    return asyncio.run(go())


def test_db_lag_does_not_open_overshoot_window(guarded, record):
    key = guarded.new_key(max_budget=CAP)
    first = _burst(guarded, key)
    spent = sum(resp_cost(r) for r in first)
    db_right_after = float(guarded.key_info(key.key).get("spend") or 0.0)
    second = _burst(guarded, key)                     # fired while the DB still lags
    lag_admitted = sum(r.status_code == 200 for r in second)
    deadline = time.time() + 60
    while time.time() < deadline and abs(float(guarded.key_info(key.key).get("spend") or 0) - spent) > 1e-9:
        time.sleep(2)
    db_later = float(guarded.key_info(key.key).get("spend") or 0.0)
    record(spent=spent, db_spend_immediately=db_right_after, admitted_during_lag=lag_admitted,
           db_spend_after_flush=db_later, counter=guarded.counter("key", key.token))
    assert db_right_after < spent                    # the lag is real ...
    assert lag_admitted == 0                         # ... but enforcement reads the live counter
    assert spent <= CAP + EPS and abs(db_later - spent) < 1e-9


@pytest.mark.destructive
@pytest.mark.native_baseline
def test_gateway_restart_within_write_window_then_idle(native, guarded, record):
    """Spend, then restart the gateway before the DB batch write (native: graceful
    restart; guarded: SIGKILL, the harsher case), stay idle past the native counter TTL
    (60 s), spend again."""
    kn, kg = native.new_key(max_budget=CAP), guarded.new_key(max_budget=CAP)
    s1n = sum(resp_cost(r) for r in _burst(native, kn))
    s1g = sum(resp_cost(r) for r in _burst(guarded, kg))
    ttl_native, ttl_guarded = native.counter_ttl("key", kn.token), guarded.counter_ttl("key", kg.token)
    sh("docker", "restart", "-t", "10", native.container)
    sh("docker", "kill", "-s", "KILL", guarded.container)
    sh("docker", "start", guarded.container)
    native.wait_ready()
    guarded.wait_ready()
    deadline = time.time() + 120
    while time.time() < deadline and native.counter("key", kn.token) > 0:
        time.sleep(5)
    time.sleep(5)
    counter_after_idle_native = native.counter("key", kn.token)
    counter_after_idle_guarded = guarded.counter("key", kg.token)
    s2n = sum(resp_cost(r) for r in _burst(native, kn))
    s2g = sum(resp_cost(r) for r in _burst(guarded, kg))
    time.sleep(25)                                   # let the batch writer flush
    db_n = float(native.key_info(kn.key).get("spend") or 0)
    db_g = float(guarded.key_info(kg.key).get("spend") or 0)
    logs_g = guarded.spend_logs_total(kg.token)[0]
    record(native_ttl_s=ttl_native, guarded_ttl_s=ttl_guarded,
           native_counter_after_idle=counter_after_idle_native, guarded_counter_after_idle=counter_after_idle_guarded,
           native_total=s1n + s2n, guarded_total=s1g + s2g, cap=CAP,
           native_overshoot_pct=100 * (s1n + s2n - CAP) / CAP,
           native_db_key_spend=db_n, guarded_db_key_spend=db_g, guarded_spend_logs_total=logs_g)
    assert ttl_native <= 60 < ttl_guarded
    assert s1n + s2n > CAP, "native restart window no longer reproduces"
    assert s1g + s2g <= CAP + EPS
    # Documented, not a cap overshoot: SIGKILL inside the batch window loses the queued
    # spend-log rows and key.spend increment (DB under-reports); the Redis counter still
    # holds the true spend and keeps enforcing. Recorded as an open issue in T2.md.
    record(guarded_db_unrecorded_spend=(s1g + s2g) - logs_g,
           guarded_counter_final=guarded.counter("key", kg.token))
    assert logs_g <= s1g + s2g + EPS
    assert abs(guarded.counter("key", kg.token) - (s1g + s2g)) < 1e-9


@pytest.mark.destructive
def test_redis_restart_during_lag_keeps_counters(guarded, record):
    key = guarded.new_key(max_budget=CAP)
    s1 = sum(resp_cost(r) for r in _burst(guarded, key))
    sh("docker", "restart", "t2-redis")
    waited = guarded.wait_budget_enforcement()      # circuit breaker closed again
    counter = guarded.counter("key", key.token)
    rs = _burst(guarded, key)
    s2 = sum(resp_cost(r) for r in rs)
    record(first=s1, counter_after_redis_restart=counter, enforcement_back_after_s=round(waited, 1),
           second=s2, second_statuses=sorted({r.status_code for r in rs}), total=s1 + s2)
    assert all(r.status_code == 429 for r in rs)     # rejected by the persisted counter, not by an outage
    assert abs(counter - s1) < 1e-9                 # AOF persisted the live counter
    assert s1 + s2 <= CAP + EPS
