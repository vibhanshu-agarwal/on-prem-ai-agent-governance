"""Domain unit tests on in-memory adapters (no Docker, no LiteLLM): the rules themselves."""
from __future__ import annotations

import math
import uuid

import pytest

from govcp.adapters.memory import (MemoryAudit, MemoryGateway, MemoryIdentity, MemoryNetwork, MemoryOrchestrator,
                                   MemoryRepository, MemoryRevoker, MemorySecretStore)
from govcp.domain import macaroon
from govcp.domain.context import Ports
from govcp.domain.errors import DelegationDenied, Forbidden, InvalidRequest, RateLimited, StalePreview
from govcp.domain.models import DiscoveryObservation, Principal, Selector, Workload
from govcp.wiring import build_app

OPS = Principal("alice", ["admin", "operator", "approver"], kind="user")
BOB = Principal("bob", ["operator", "approver"], kind="user")
CAROL = Principal("carol", ["owner", "approver"], teams=["hr"], kind="user")


@pytest.fixture
def app():
    o = MemoryOrchestrator()
    net = MemoryNetwork(o, governed=["agents"])
    ports = Ports(gateway=MemoryGateway(), orchestrator=o, network=net, identity=MemoryIdentity(),
                  secrets=MemorySecretStore(), audit=MemoryAudit(), repo=MemoryRepository(),
                  revokers=[MemoryRevoker()])
    a = build_app({"policy": {"stop": {"verify_settle_s": 0},
                              "discovery": {"feeds": {"tiny": {"daily_limit": 2}}}}}, ports)
    return a


def _agent(app, team="hr", n_workloads=1, **kw):
    aid = "a-" + uuid.uuid4().hex[:6]
    res = app.register.register({"agent_id": aid, "team": team, "max_budget_usd": 1, "models": ["m1", "m2"],
                                 "credentials": [{"kind": "db", "value": "pw"}], "oidc_subjects": [f"sub-{aid}"],
                                 **kw}, OPS)
    for i in range(n_workloads):
        w = app.ports.orchestrator.add(Workload(id=f"{aid}-{i}", name=f"{aid}-{i}", image="img:1",
                                                labels={"govpilot.agent_id": aid, "govpilot.team": team},
                                                host="mem-host", running=True, restart_policy="always",
                                                networks=["agents"]))
        app.ports.network.connections[w.id] = 2
    return res


def test_stop_sequence_order_and_verification(app):
    res = _agent(app)
    aid = res["agent"].agent_id
    rep = app.stop.stop([aid], "alice", "test")
    assert rep["verify"]["ok"], rep["verify"]["failed"]
    g, o, n = app.ports.gateway.calls, app.ports.orchestrator.calls, app.ports.network.calls
    assert ("block_key", res["agent"].gateway_keys[0].key_hash) in g
    assert n == [("isolate", f"{aid}-0")] and o == [("prevent_restart", f"{aid}-0"), ("stop", f"{aid}-0")]
    assert app.ports.gateway.probe(res["gateway_key"]) is False
    assert app.ports.identity.subject_enabled(f"sub-{aid}") is False
    assert app.register.get(aid).desired_state == "stopped"
    acts = [r.action for r in app.ports.audit.records]
    assert acts.index("stop.started") < acts.index("stop.completed")
    assert set(rep["timings_ms"]) >= {"gateway", "network", "desired_state", "credentials", "verify", "total"}


def test_stray_keys_tagged_with_the_agent_are_blocked_too(app):
    aid = _agent(app)["agent"].agent_id
    stray = app.ports.gateway.create_key("stray", "hr", ["m1"], 1, {"agent_id": aid})
    app.stop.stop([aid], "alice", "t")
    assert app.ports.gateway.probe(stray.raw_key) is False


def test_reconciler_restops_revived_workloads(app):
    aid = _agent(app)["agent"].agent_id
    app.stop.stop([aid], "alice", "t")
    app.ports.orchestrator.w[f"{aid}-0"].running = True           # someone restarted it
    out = app.reconciler.run_once()
    assert out["enforced"] == [f"{aid}-0"] and not app.ports.orchestrator.w[f"{aid}-0"].running


def test_admission_rule_for_code_execution(app):
    with pytest.raises(InvalidRequest):
        app.register.register({"agent_id": "coder-x", "team": "eng", "capabilities": ["executes_code"],
                               "sandbox_tier": "container"}, OPS)
    app.register.register({"agent_id": "coder-y", "team": "eng", "capabilities": ["executes_code"],
                           "sandbox_tier": "microvm"}, OPS)


def test_dual_control_rules(app):
    for t in ("hr", "finance"):
        _agent(app, team=t)
    pv = app.quarantine.preview(Selector(all=True), OPS)
    assert pv["fleet_wide"] and pv["approvals_required"] == 2
    act = app.quarantine.execute(pv["preview_id"], OPS, "incident")
    assert act["status"] == "pending_approval"
    with pytest.raises(Forbidden):
        app.quarantine.approve(act["action_id"], OPS)
    app.quarantine.approve(act["action_id"], BOB)
    with pytest.raises(Forbidden):
        app.quarantine.approve(act["action_id"], BOB)
    done = app.quarantine.approve(act["action_id"], CAROL)
    assert done["status"] == "executed"


def test_machines_cannot_fire_bulk_quarantine(app):
    _agent(app)
    pv = app.quarantine.preview(Selector(team="hr"), OPS)
    bot = Principal("bot", ["operator"], kind="client")
    with pytest.raises(Forbidden):
        app.quarantine.execute(pv["preview_id"], bot, "x")


def test_stale_preview(app):
    _agent(app, team="ops")
    pv = app.quarantine.preview(Selector(team="ops"), OPS)
    _agent(app, team="ops")
    with pytest.raises(StalePreview):
        app.quarantine.execute(pv["preview_id"], OPS, "x")


def test_discovery_rate_limit_and_zero_budget(app):
    ok = [app.discovery.submit("tiny", DiscoveryObservation(fingerprint=f"f{i}", evidence={"x": 1}))
          for i in range(2)]
    assert all(p["budget_usd"] == 0 and p["gateway_key"] is None for p in ok)
    with pytest.raises(RateLimited):
        app.discovery.submit("tiny", DiscoveryObservation(fingerprint="f3", evidence={"x": 1}))
    assert app.ports.gateway.keys == {}


def test_macaroon_properties():
    k = b"k" * 32
    t = macaroon.mint(k, "id1", ["agent = p", "budget_usd <= 5", "models in a,b", "max_depth <= 2"])
    s = macaroon.verify(k, t)
    assert s.holder == "p" and s.budget_usd == 5 and s.models == {"a", "b"} and s.depth == 0
    t2 = macaroon.attenuate(t, ["budget_usd <= 50", "models in b,c"])       # "broader" caveats cannot widen
    s2 = macaroon.verify(k, t2)
    assert s2.budget_usd == 5 and s2.models == {"b"}
    with pytest.raises(macaroon.InvalidToken):
        macaroon.verify(b"x" * 32, t)
    with pytest.raises(macaroon.InvalidToken):
        macaroon.verify(k, macaroon.attenuate(t, ["unknown caveat"]))
    with pytest.raises(macaroon.InvalidToken):
        macaroon.verify(k, macaroon.attenuate(t, ["expires < 1"]))
    assert math.isinf(macaroon.Scope().budget_usd)


def test_delegation_denies_and_alerts(app):
    res = _agent(app)
    tok = res["delegation_token"]
    with pytest.raises(DelegationDenied):
        app.delegation.mint_child(tok, {"name": "c", "max_budget_usd": 2, "models": ["m1"]})
    child = app.delegation.mint_child(tok, {"name": "c", "max_budget_usd": 0.5, "models": ["m1"]})
    assert child["scope"]["models"] == ["m1"]
    with pytest.raises(DelegationDenied):
        app.delegation.authorize(child["delegation_token"], "m2")
    assert [r.action for r in app.ports.audit.records if r.severity == "alert"] == \
        ["delegation.broadening_denied", "delegation.scope_violation"]


def test_reconciler_reblocks_keys_unblocked_out_of_band(app):
    res = _agent(app)
    aid = res["agent"].agent_id
    app.stop.stop([aid], "alice", "t")
    app.ports.gateway.unblock_key(res["agent"].gateway_keys[0].key_hash)     # drift at the gateway
    app.reconciler.key_check_every = 1
    out = app.reconciler.run_once()
    assert out["reblocked"] == [aid] and app.ports.gateway.probe(res["gateway_key"]) is False


def test_reconciler_enforces_quarantine_rules_on_new_workloads(app):
    _agent(app, team="ops")
    pv = app.quarantine.preview(Selector(team="ops"), OPS)
    app.quarantine.execute(pv["preview_id"], OPS, "x")
    late = app.ports.orchestrator.add(Workload(id="late", name="late", image="img:1",
                                               labels={"govpilot.team": "ops"}, host="mem-host", running=True))
    assert app.reconciler.run_once()["enforced"] == ["late"] and not late.running
