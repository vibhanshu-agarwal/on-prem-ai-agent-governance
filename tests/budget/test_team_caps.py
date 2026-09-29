"""Team-level budget caps across multiple keys (one business unit, several agents)."""
import asyncio

import httpx
import pytest

from t2lib import EPS, error_of, gather_limited, resp_cost

TEAM_CAP = 0.003


def _keys(gw, team):
    # a mix: no key budget, a generous key budget, and a key budget above the team cap
    return [gw.new_key(team_id=team), gw.new_key(team_id=team, max_budget=1.0),
            gw.new_key(team_id=team, max_budget=0.01)]


def test_parallel_requests_across_keys_never_exceed_team_cap(guarded, record):
    team = guarded.new_team(max_budget=TEAM_CAP)
    keys = _keys(guarded, team)

    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            # T8: one request per key first, so the team's spend really comes from several keys (under load the
            # key without a key budget, which reserves less, used to win every race of the burst)
            first = [await guarded.chat(c, k, max_tokens=100) for k in keys]
            return first + await gather_limited([guarded.chat(c, keys[i % 3], max_tokens=100) for i in range(3, 90)])
    rs = asyncio.run(go())
    ok = [r for r in rs if r.status_code == 200]
    total = sum(resp_cost(r) for r in ok)
    team_counter = guarded.counter("team", team)
    per_key = [sum(1 for i, r in enumerate(rs) if r.status_code == 200 and i % 3 == k) for k in range(3)]
    record(admitted=len(ok), per_key_admitted=per_key, spend=total, team_counter=team_counter, cap=TEAM_CAP)
    assert total <= TEAM_CAP + EPS and team_counter <= TEAM_CAP + EPS
    assert sum(1 for n in per_key if n) >= 2          # spend really came from several keys
    for r in rs:
        if r.status_code != 200:
            e = error_of(r)
            assert r.status_code == 429 and "Budget has been exceeded" in e.get("message", ""), e


@pytest.mark.native_baseline
def test_native_team_cap_overshoot_sequential_round_robin(native, guarded, record):
    out = {}
    for gw in (native, guarded):
        team = gw.new_team(max_budget=TEAM_CAP)
        keys = _keys(gw, team)

        async def go():
            async with httpx.AsyncClient(timeout=60) as c:
                return [await gw.chat(c, keys[i % 3], max_tokens=100) for i in range(20)]
        rs = asyncio.run(go())
        out[gw.name] = sum(resp_cost(r) for r in rs)
        if gw.name == "native":
            msgs = {error_of(r).get("message", "")[:40] for r in rs if r.status_code != 200}
    record(native_spend=out["native"], guarded_spend=out["guarded"], cap=TEAM_CAP,
           native_overshoot_pct=100 * (out["native"] - TEAM_CAP) / TEAM_CAP, native_reject_msgs=sorted(msgs))
    assert out["native"] > TEAM_CAP
    assert out["guarded"] <= TEAM_CAP + EPS
