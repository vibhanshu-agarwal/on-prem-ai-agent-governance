"""M-02b Hard cap across gateway restarts: settles T4 finding 8 (one 0.35 % overshoot seen while the shared gateway
was recreated during a rogue run).

Plan from docs/results/T4.md, run on the ISOLATED T2 stack (tests/budget/stack, project govpilot-t2, guarded gateway
127.0.0.1:4100, proxy_batch_write_at 15 s so the DB lag window is wide): a budgeted key within 3 requests of its cap
is driven 4-way concurrent; the gateway is restarted at a random offset while requests are in flight (graceful
`docker restart`, `kill -9` + start, `compose up --force-recreate`, in rotation), N times. After each run, once the
key refuses and the DB write window has passed, compare the spend-log sum with the cap, the Redis spend counter and
key.spend, and look for duplicate request ids.
"""
from __future__ import annotations

import os
import random
import sys
import threading
import time

import httpx
import pytest

import acclib as L

sys.path.insert(0, str(L.ROOT / "tests" / "budget"))
sys.path.insert(0, str(L.ROOT / "tests" / "budget" / "stack"))
import t2lib  # noqa: E402
import t2stack  # noqa: E402

N = int(os.environ.get("T8_RESTART_ITERATIONS", "21"))
COST = t2lib.cost("mock-local", 7, 100)                     # 0.000207 per request
CAP = round(5 * COST + COST / 2, 6)                          # 5 requests fit, the 6th does not
METHODS = ("restart", "kill9", "recreate")


@pytest.fixture(scope="module")
def t2():
    started = False
    if not t2stack.is_up():
        t2stack.up()
        started = True
    g = t2lib.Gateway(name="guarded", url=f"http://127.0.0.1:{t2stack.GUARDED_PORT}", redis_container="t2-redis",
                      pg_container="t2-postgres", container="t2-gateway")
    g.wait_budget_enforcement()
    yield g
    g.cleanup()
    if started and os.environ.get("T2_KEEP_STACK") != "1":
        t2stack.down()


def _bounce(method):
    if method == "restart":
        t2lib.sh("docker", "restart", "-t", "10", "t2-gateway")
    elif method == "kill9":
        t2lib.sh("docker", "kill", "-s", "KILL", "t2-gateway")
        t2lib.sh("docker", "start", "t2-gateway")
    else:
        t2stack.compose("up", "-d", "--no-deps", "--force-recreate", "gateway")


def _one(g, i):
    method = METHODS[i % len(METHODS)]
    key = g.new_key(max_budget=CAP)
    h = {"Authorization": f"Bearer {key.key}"}
    body = {"model": "mock-local", "messages": t2lib.MSG, "max_tokens": 100}
    for _ in range(2):                                         # pre-spend: 3 requests of headroom left
        assert httpx.post(f"{g.url}/v1/chat/completions", headers=h, json=body, timeout=60).status_code == 200
    ok_cost, statuses, lock, done = [], [], threading.Lock(), threading.Event()
    refused_after_bounce = [0]
    bounced = threading.Event()

    def worker():
        with httpx.Client(timeout=60) as c:
            while not done.is_set():
                try:
                    r = c.post(f"{g.url}/v1/chat/completions", headers=h, json=body)
                    code = r.status_code
                except httpx.HTTPError:
                    code = None
                with lock:
                    statuses.append(code)
                    if code == 200:
                        ok_cost.append(t2lib.resp_cost(r))
                    elif code in (400, 429) and bounced.is_set():
                        refused_after_bounce[0] += 1
                        if refused_after_bounce[0] >= 8:
                            done.set()
                if code is None:
                    time.sleep(0.3)

    ts = [threading.Thread(target=worker, daemon=True) for _ in range(4)]
    for t in ts:
        t.start()
    time.sleep(random.uniform(0.02, 0.4))                      # random offset: requests are in flight
    t_b = time.time()
    _bounce(method)
    bounced.set()
    g.wait_ready(timeout=180)
    done.wait(timeout=120)
    done.set()
    for t in ts:
        t.join(timeout=70)
    time.sleep(t2stack.LAG_SECONDS + 5)                         # past the DB batch-write window
    logs_sum, logs_n = g.spend_logs_total(key.token)
    counter = g.counter("key", key.token)
    key_spend = float(g.sql(f"select spend from \"LiteLLM_VerificationToken\" where token='{key.token}'") or 0)
    dup = g.sql(f"select count(*) - count(distinct request_id) from \"LiteLLM_SpendLogs\" where api_key='{key.token}'")
    return {"i": i, "method": method, "bounce_s": round(time.time() - t_b, 1), "spend_logs_usd": round(logs_sum, 6),
            "spend_log_rows": logs_n, "redis_counter_usd": round(counter, 6), "key_spend_db_usd": round(key_spend, 6),
            "client_ok_usd": round(sum(ok_cost), 6) + round(2 * COST, 6), "duplicate_rows": int(dup or 0),
            "cap_usd": CAP, "overshoot_usd": round(max(0.0, max(logs_sum, sum(ok_cost) + 2 * COST) - CAP), 9),
            "errors_during_bounce": sum(1 for s in statuses if s is None or s >= 500)}


@pytest.mark.accept(
    id="M-02b", title="Zero overshoot across gateway restarts (T4 finding 8)",
    criterion=f"{N} restarts (graceful / kill -9 / recreate) with 4 requests in flight on a key 3 requests from its "
              "cap: spend-log sum <= cap every time; counter, key.spend and client view reported",
    simplification="One guarded gateway instance on the isolated stack; multi-replica gateways share the Redis "
                   "counters but were not tested; restarts are container restarts, not node failures.")
def test_restart_overshoot(t2, record):
    runs = [_one(t2, i) for i in range(N)]
    over = [r for r in runs if r["overshoot_usd"] > 1e-9]
    record(iterations=N, cap_usd=CAP, overshoots=len(over), max_overshoot_usd=max((r["overshoot_usd"] for r in runs), default=0),
           max_spend_logs_usd=max(r["spend_logs_usd"] for r in runs),
           max_client_observed_spend_usd=max(r["client_ok_usd"] for r in runs),
           # findings (safe direction / reporting only, see ACCEPTANCE.md):
           runs_spend_log_rows_lost=sum(1 for r in runs if r["spend_logs_usd"] + 1e-9 < r["client_ok_usd"]),
           runs_counter_above_cap_leaked_reservations=sum(1 for r in runs if r["redis_counter_usd"] > CAP + 1e-9),
           runs_counter_below_logs=sum(1 for r in runs if r["redis_counter_usd"] + 1e-9 < r["spend_logs_usd"]),
           runs_key_spend_db_below_logs=sum(1 for r in runs if r["key_spend_db_usd"] + 1e-9 < r["spend_logs_usd"]),
           duplicate_rows=sum(r["duplicate_rows"] for r in runs),
           by_method={m: sum(1 for r in runs if r["method"] == m) for m in METHODS})
    L.save_json("m02b_restart_overshoot.json", runs)
    assert not over, over
