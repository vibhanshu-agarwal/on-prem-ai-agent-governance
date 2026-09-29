"""max_tokens ceiling (T1 finding): native LiteLLM has no per-key ceiling; a request with
max_tokens=100000 is forwarded while the reservation clamps at max_output_tokens (1024).
The budget guard enforces a per-agent ceiling/default from key (or team) metadata so that
reservation >= worst-case cost."""
import asyncio
import time

import httpx
import pytest

from t2lib import EPS, cost, error_of, resp_cost


def _one(gw, key, **body):
    async def go():
        async with httpx.AsyncClient(timeout=120) as c:
            return await gw.chat(c, key, **body)
    return asyncio.run(go())


@pytest.mark.native_baseline
def test_native_huge_max_tokens_spends_past_reservation_and_cap(native, record):
    key = native.new_key(max_budget=0.002)
    r = _one(native, key, max_tokens=100000)
    spent = resp_cost(r)
    record(status=r.status_code, completion_tokens=r.json()["usage"]["completion_tokens"], spend=spent,
           cap=0.002, overshoot_x=spent / 0.002)
    assert r.status_code == 200 and spent > 0.002   # one request = 4x the key's cap


def test_huge_max_tokens_rejected_with_default_policy(guarded, record):
    key = guarded.new_key(max_budget=0.002)
    t0 = time.time()
    r = _one(guarded, key, max_tokens=100000)
    e = error_of(r)
    record(status=r.status_code, error_type=e.get("type"), counter_after=guarded.counter("key", key.token))
    assert r.status_code == 400 and e.get("type") == "max_tokens_exceeds_ceiling"
    assert "1024" in e["message"]                          # model max_output_tokens is the default ceiling
    assert guarded.counter("key", key.token) == 0.0        # reservation released, nothing spent
    evs = [ev for ev in guarded.budget_events(since=t0) if ev["key_hash"] == key.token]
    assert any(ev["event"] == "budget.max_tokens_rejected" and ev["requested"] == 100000 for ev in evs)


def test_per_key_ceiling_reject(guarded, record):
    key = guarded.new_key(max_budget=1.0, metadata={"agent_id": "t2", "token_policy": {"max_tokens_ceiling": 64}})
    over = _one(guarded, key, max_tokens=65)
    at = _one(guarded, key, max_tokens=64)
    record(over_status=over.status_code, at_status=at.status_code,
           at_completion=at.json()["usage"]["completion_tokens"])
    assert over.status_code == 400 and error_of(over)["type"] == "max_tokens_exceeds_ceiling"
    assert at.status_code == 200 and at.json()["usage"]["completion_tokens"] == 64


def test_per_key_ceiling_clamp(guarded, record):
    key = guarded.new_key(max_budget=1.0, metadata={"token_policy": {"max_tokens_ceiling": 64, "on_exceed": "clamp"}})
    r = _one(guarded, key, max_tokens=5000)
    u = r.json()["usage"]
    record(requested=5000, completion_tokens=u["completion_tokens"], spend=resp_cost(r))
    assert r.status_code == 200 and u["completion_tokens"] == 64
    assert abs(resp_cost(r) - cost("mock-local", 7, 64)) < 1e-12


def test_default_applied_when_absent(guarded, record):
    with_policy = guarded.new_key(max_budget=1.0, metadata={"token_policy": {"default_max_tokens": 32}})
    no_policy = guarded.new_key(max_budget=1.0)
    a = _one(guarded, with_policy, max_tokens=None)
    b = _one(guarded, no_policy, max_tokens=None)
    record(policy_default_completion=a.json()["usage"]["completion_tokens"],
           model_default_completion=b.json()["usage"]["completion_tokens"])
    assert a.json()["usage"]["completion_tokens"] == 32
    assert b.json()["usage"]["completion_tokens"] == 256   # litellm_params.max_tokens of mock-local


def test_max_completion_tokens_alias_also_clamped(guarded):
    key = guarded.new_key(max_budget=1.0, metadata={"token_policy": {"max_tokens_ceiling": 16, "on_exceed": "clamp"}})
    r = _one(guarded, key, max_tokens=None, max_completion_tokens=900)
    assert r.status_code == 200 and r.json()["usage"]["completion_tokens"] <= 16


def test_team_policy_applies_and_key_overrides(guarded, record):
    team = guarded.new_team(max_budget=1.0, metadata={"token_policy": {"max_tokens_ceiling": 20}})
    team_key = guarded.new_key(max_budget=1.0, team_id=team)
    override = guarded.new_key(max_budget=1.0, team_id=team, metadata={"token_policy": {"max_tokens_ceiling": 40}})
    a = _one(guarded, team_key, max_tokens=30)
    b = _one(guarded, override, max_tokens=30)
    record(team_ceiling_status=a.status_code, key_override_status=b.status_code)
    assert a.status_code == 400 and "20" in error_of(a)["message"]
    assert b.status_code == 200 and b.json()["usage"]["completion_tokens"] == 30


def test_reservation_covers_worst_case_under_any_max_tokens(guarded, record):
    """Sweep max_tokens (absent, small, ceiling, far above) on a small budget with clamp:
    every admitted request's actual cost stays inside its reservation, so the cap holds."""
    cap = 0.01
    key = guarded.new_key(max_budget=cap, metadata={"token_policy": {"on_exceed": "clamp"}})

    async def go():
        out = []
        async with httpx.AsyncClient(timeout=120) as c:
            for mt in [None, 1, 100, 1024, 5000, 100000, 999999999] * 3:
                out.append(await c.post(f"{guarded.url}/v1/chat/completions",
                                        headers={"Authorization": f"Bearer {key.key}"},
                                        json={k: v for k, v in {"model": "mock-local", "messages": [
                                            {"role": "user", "content": "one two three four"}],
                                            "max_tokens": mt}.items() if v is not None}))
        return out
    rs = asyncio.run(go())
    total = sum(resp_cost(r) for r in rs)
    max_completion = max(r.json()["usage"]["completion_tokens"] for r in rs if r.status_code == 200)
    record(spend=total, cap=cap, admitted=sum(r.status_code == 200 for r in rs), max_completion=max_completion)
    assert total <= cap + EPS
    assert max_completion <= 1024
