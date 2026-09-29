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
        app.register.register({"agent_id": "coder-x", "team": "eng", "capabilities": ["executes_model_code"],
                               "sandbox_tier": "container"}, OPS)
    app.register.register({"agent_id": "coder-y", "team": "eng", "capabilities": ["executes_model_code"],
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


def test_discovery_feed_counter_reset_is_a_human_admin_action_and_audited(app):
    for i in range(2):
        app.discovery.submit("tiny", DiscoveryObservation(fingerprint=f"r{i}", evidence={"x": 1}))
    assert {u["feed"]: u["count"] for u in app.discovery.feed_usage()}["tiny"] == 2
    feed_client = Principal("tiny", ["feed", "admin"], kind="client")      # a machine client cannot lift its own cap
    for who in (feed_client, BOB):
        with pytest.raises(Forbidden):
            app.discovery.reset_feed_count("tiny", who, "demo")
    with pytest.raises(InvalidRequest):
        app.discovery.reset_feed_count("tiny", OPS, " ")
    res = app.discovery.reset_feed_count("tiny", OPS, "demo rerun")
    assert res["previous_count"] == 2 and res["count"] == 0 and res["daily_limit"] == 2
    rec = [r for r in app.ports.audit.records if r.action == "discovery.feed_count_reset"]
    assert len(rec) == 1 and rec[0].actor == "alice" and rec[0].severity == "warning"
    app.discovery.submit("tiny", DiscoveryObservation(fingerprint="r9", evidence={"x": 1}))   # budget available again


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


def test_verify_sees_workloads_and_keys_that_appeared_after_the_stop_started(app):
    """Verification must check the live systems, not the snapshot the stop took: a container re-created
    (or a key minted) between the block phase and verification is a failed stop, not a passed one."""
    res = _agent(app)
    aid = res["agent"].agent_id
    assert app.stop.stop([aid], "alice", "t")["verify"]["ok"]
    revived = app.ports.orchestrator.add(Workload(id=f"{aid}-new", name=f"{aid}-new", image="img:1",
                                                  labels={"govpilot.agent_id": aid}, host="mem-host", running=True,
                                                  networks=["agents"]))
    v = app.stop.verify([app.register.get(aid)], [])
    assert not v["ok"]
    failed = {(c["check"], c["target"]) for c in v["failed"]}
    assert ("workload.appeared_during_stop", revived.name) in failed and ("workload.not_running", revived.name) in failed
    app.ports.orchestrator.w[revived.id].running = False
    app.ports.orchestrator.w[revived.id].networks = []
    stray = app.ports.gateway.create_key("late-key", "hr", ["m1"], 1, {"agent_id": aid})
    v = app.stop.verify([app.register.get(aid)], [])
    assert ("gateway.key_blocked", "late-key") in {(c["check"], c["target"]) for c in v["failed"]}
    app.ports.gateway.block_key(stray.key_hash)
    # once the late key is blocked and the revived container is down, only its appearance is still flagged
    assert {c["check"] for c in app.stop.verify([app.register.get(aid)], [])["failed"]} == \
        {"workload.appeared_during_stop"}


def test_stop_in_progress_cannot_mint_tokens_or_keys(app):
    """desired_state flips first and status last; in between, neither delegation nor first-use key mapping may work."""
    res = _agent(app, oidc_subjects=["sso-sub"])
    aid = res["agent"].agent_id
    app.register.mutate(aid, lambda a: setattr(a, "desired_state", "stopped"))   # what stop() does in phase 0
    assert app.register.get(aid).status == "active"
    with pytest.raises(DelegationDenied):
        app.delegation.mint_child(res["delegation_token"], {"name": "c", "max_budget_usd": 0.1, "models": ["m1"]})
    with pytest.raises(DelegationDenied):
        app.delegation.authorize(res["delegation_token"], "m1")
    with pytest.raises(Forbidden):
        app.access.resolve_subject("sso-sub")
    assert len(app.ports.gateway.keys) == 1      # no key minted at first use


def test_quarantine_refuses_when_unmanaged_blast_radius_grew_or_preview_expired(app):
    _agent(app, team="lab")
    pv = app.quarantine.preview(Selector(labels={"govpilot.team": "lab"}), OPS)
    assert pv["counts"]["unmanaged_workloads"] == 0
    app.ports.orchestrator.add(Workload(id="shadow", name="shadow", image="img:1",
                                        labels={"govpilot.team": "lab"}, host="mem-host", running=True))
    with pytest.raises(StalePreview):
        app.quarantine.execute(pv["preview_id"], OPS, "x")
    # dual control: approvals that land after the preview expired do not fire the action
    _agent(app, team="lab2")
    pv = app.quarantine.preview(Selector(all=True), OPS)
    act = app.quarantine.execute(pv["preview_id"], OPS, "incident")
    app.quarantine.approve(act["action_id"], BOB)
    app.ports.repo.update("previews", pv["preview_id"], lambda p: {**p, "expires_at": 0})
    with pytest.raises(StalePreview):
        app.quarantine.approve(act["action_id"], CAROL)
    assert app.ports.repo.get("quarantine_actions", act["action_id"])["status"] == "stale"
    assert all(a.status == "active" for a in app.register.list())


# ---- T8 additions: commit-time action authorization (in-window harm) and secret rotation (host drill) ----
def test_consequential_action_denied_from_the_stop_decision_on(app):
    res = _agent(app)
    aid, kh = res["agent"].agent_id, res["agent"].gateway_keys[0].key_hash
    assert app.access.authorize_action(kh, "email.send", "x@y")["allowed"] is True
    # the stop's first step persists desired_state=stopped; nothing else of the stop has to have happened yet
    app.register.mutate(aid, lambda a: setattr(a, "desired_state", "stopped"))
    with pytest.raises(Forbidden):
        app.access.authorize_action(kh, "email.send", "x@y")
    with pytest.raises(Forbidden):
        app.access.authorize_action("0" * 64, "db.write")                          # unknown key
    acts = [(r.action, r.severity) for r in app.ports.audit.records if r.action.startswith("action.")]
    assert acts == [("action.authorized", "info"), ("action.denied", "alert"), ("action.denied", "alert")]


def test_rotate_secrets_reissues_key_and_credentials(app):
    res = _agent(app)
    aid = res["agent"].agent_id
    old_key, old_hash = res["gateway_key"], res["agent"].gateway_keys[0].key_hash
    cred = res["agent"].credentials[0].ref
    app.stop.stop([aid], "alice", "host compromised")
    out = app.register.rotate_secrets(aid, "alice", "host compromised")
    ag = app.register.get(aid)
    assert [k.key_hash for k in ag.gateway_keys] == [out["key_hash"]] and out["key_hash"] != old_hash
    assert app.ports.gateway.probe(old_key) is False
    assert app.ports.gateway.key_status(out["key_hash"]).blocked is True          # agent is still stopped
    s = app.ports.secrets.get(cred)
    assert s is not None and not s.revoked and s.value not in ("pw", None)
    assert any(r.action == "secrets.rotated" for r in app.ports.audit.records)


def test_reconciler_does_not_reblock_a_key_of_an_agent_resumed_mid_tick(app):
    """T8 regression (found by the pilot simulation): resume between the reconciler's snapshot and its re-block
    left the agent 'running' with its key blocked forever."""
    res = _agent(app)
    aid, kh = res["agent"].agent_id, res["agent"].gateway_keys[0].key_hash
    app.stop.stop([aid], "alice", "test")
    app.ports.gateway.unblock_key(kh)                      # out-of-band unblock: the reconciler must re-block ...
    rec = app.reconciler
    rec.key_check_every = 1
    real_block = app.ports.gateway.block_key

    def block_then_resume(h):                              # ... but the operator resumes at that very moment
        real_block(h)
        app.register.mutate(aid, lambda a: setattr(a, "desired_state", "running"))
    app.ports.gateway.block_key = block_then_resume
    rec.run_once()
    app.ports.gateway.block_key = real_block
    assert app.ports.gateway.key_status(kh).blocked is False
    assert any(r.action == "reconciler.reblock_reverted" for r in app.ports.audit.records)


# ---------------------------------------------------------------- T9 leftovers
def test_oidc_subject_belongs_to_exactly_one_agent(app):
    from govcp.domain.errors import Conflict
    first = _agent(app)["agent"]
    sub = first.oidc_subjects[0]
    with pytest.raises(Conflict, match=first.agent_id):
        app.register.register({"agent_id": "thief-" + uuid.uuid4().hex[:4], "team": "hr", "max_budget_usd": 1,
                               "models": ["m1"], "oidc_subjects": [sub]}, OPS)
    assert app.register.by_subject(sub).agent_id == first.agent_id


def test_rotate_secrets_reports_incomplete_when_an_old_key_can_be_neither_deleted_nor_blocked(app):
    res = _agent(app)
    aid = res["agent"].agent_id

    def boom(*a, **k):
        raise RuntimeError("gateway unreachable")
    app.ports.gateway.delete_key = boom
    app.ports.gateway.block_key = boom
    out = app.register.rotate_secrets(aid, "alice", "drill")
    assert out["complete"] is False and out["old_keys"][0]["result"].startswith("FAILED")
    alerts = [r for r in app.ports.audit.records if r.action == "secrets.rotation_incomplete"]
    assert alerts and alerts[-1].severity == "alert"


def test_rotate_secrets_complete_flag_when_blocked_instead_of_deleted(app):
    aid = _agent(app)["agent"].agent_id

    def boom(*a, **k):
        raise RuntimeError("delete failed")
    app.ports.gateway.delete_key = boom
    out = app.register.rotate_secrets(aid, "alice", "drill")
    assert out["complete"] is True and "blocked" in out["old_keys"][0]["result"]


def test_estop_finds_workloads_with_a_custom_selector_through_the_key_metadata(app):
    from govcp.estop.core import EmergencyStop
    aid = "custom-" + uuid.uuid4().hex[:4]
    app.register.register({"agent_id": aid, "team": "hr", "max_budget_usd": 1, "models": ["m1"],
                           "workload_labels": {"app": aid}}, OPS)
    w = app.ports.orchestrator.add(Workload(id="w-" + aid, name="w-" + aid, image="img:1", labels={"app": aid},
                                            host="mem-host", running=True, restart_policy="always",
                                            networks=["agents"]))
    es = EmergencyStop(app.ports.gateway, app.ports.orchestrator, app.ports.network, MemoryAudit(), grace_s=0)
    out = es.stop_agent(aid, "op", "drill")           # no register access, no default label on the workload
    assert [x["name"] for x in out["workloads"]] == [w.name]
    assert not app.ports.orchestrator.w[w.id].running


def test_jwks_cache_drops_a_removed_signing_key_within_the_short_ttl(monkeypatch):
    import time as _time

    import jwt
    from cryptography.hazmat.primitives.asymmetric import rsa
    from govcp.adapters import oidc_identity as mod
    from govcp.domain.errors import Unauthorized

    def mk(kid):
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(k.public_key(), as_dict=True) | {"kid": kid, "alg": "RS256", "use": "sig"}
        return k, jwk
    ka, ja = mk("A")
    kb, jb = mk("B")
    served = {"keys": [ja, jb]}

    class R:
        def json(self):
            return served
    monkeypatch.setattr(mod.httpx, "get", lambda *a, **k: R())
    real = _time.time
    now = [real()]
    monkeypatch.setattr(mod.time, "time", lambda: now[0])
    idp = mod.OIDCIdentityProvider("iss", "http://idp/jwks", leeway_s=5)

    def token(key, kid):
        return jwt.encode({"iss": "iss", "aud": "aud", "sub": "s", "iat": real() - 1, "exp": real() + 600}, key,
                          algorithm="RS256", headers={"kid": kid})
    ta = token(ka, "A")
    assert idp.verify(ta, "aud").subject == "s"
    served["keys"] = [jb]                              # the IdP removes A (compromised)
    now[0] += 5
    assert idp.verify(ta, "aud").subject == "s"        # still inside the cache window
    now[0] += 31
    with pytest.raises(Unauthorized):                  # was accepted for 300 s before T9
        idp.verify(ta, "aud")
    assert idp.verify(token(kb, "B"), "aud").subject == "s"
