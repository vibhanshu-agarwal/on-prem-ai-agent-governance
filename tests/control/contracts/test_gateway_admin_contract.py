"""GatewayAdmin contract (LiteLLM adapter + in-memory reference)."""
from __future__ import annotations

import pytest

import cpclient
from cpclient import live_or_skip

from govcp.adapters.memory import MemoryGateway

TEAM = "t3-contract"


@pytest.fixture(params=["memory", "litellm"])
def gw(request):
    if request.param == "memory":
        yield MemoryGateway()
        return
    live_or_skip()
    from govcp.adapters.litellm_gateway import LiteLLMGatewayAdmin
    g = LiteLLMGatewayAdmin(cpclient.GW_URL, cpclient.ENV["LITELLM_MASTER_KEY"])
    made = []
    orig = g.create_key

    def track(*a, **kw):
        k = orig(*a, **kw)
        made.append(k.key_hash)
        return k
    g.create_key = track
    yield g
    for h in made:
        g.delete_key(h)


def _new(gw, agent_id=None, blocked=False):
    agent_id = agent_id or cpclient.uid("gwc")
    return agent_id, gw.create_key(alias=agent_id, team=TEAM, models=["mock-local"], max_budget_usd=0.05,
                                   metadata={"agent_id": agent_id, "root_agent_id": agent_id, "team": TEAM},
                                   blocked=blocked)


def test_health_and_team(gw):
    assert gw.health() is True
    assert gw.ensure_team(TEAM) == gw.ensure_team(TEAM)


def test_create_and_status(gw):
    aid, k = _new(gw)
    assert k.raw_key and k.key_hash and k.alias == aid
    st = gw.key_status(k.key_hash)
    assert st.alias == aid and st.blocked is False and st.models == ["mock-local"]
    assert st.max_budget == 0.05 and st.metadata["agent_id"] == aid and st.team_id == gw.ensure_team(TEAM)
    assert gw.probe(k.raw_key) is True


def test_find_by_alias_agent_and_team(gw):
    aid, k = _new(gw)
    assert [x.key_hash for x in gw.find_keys(alias=aid)] == [k.key_hash]
    assert k.key_hash in [x.key_hash for x in gw.find_keys(agent_id=aid)]
    assert k.key_hash in [x.key_hash for x in gw.find_keys(team=TEAM)]
    assert gw.find_keys(alias=cpclient.uid("nope")) == []


def test_block_is_effective_for_next_request_and_reversible(gw):
    _, k = _new(gw)
    gw.block_key(k.key_hash)
    assert gw.key_status(k.key_hash).blocked is True
    assert gw.probe(k.raw_key) is False
    gw.unblock_key(k.key_hash)
    assert gw.probe(k.raw_key) is True


def test_create_blocked_and_delete(gw):
    _, k = _new(gw, blocked=True)
    assert gw.probe(k.raw_key) is False
    gw.delete_key(k.key_hash)
    assert gw.key_status(k.key_hash) is None
