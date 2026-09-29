"""Delegation attenuation (report section 5 'runaway delegation', section 8 'delegation attenuation')."""
from __future__ import annotations

import base64
import json

import httpx
import pytest

import cpclient
from cpclient import record_result

pytestmark = pytest.mark.usefixtures("live")


def _mint(parent_token, name, budget, models, **kw):
    return httpx.post(f"{cpclient.CP_URL}/v1/delegations", timeout=30, json={
        "parent_token": parent_token, "name": name, "max_budget_usd": budget, "models": models, **kw})


def _alerts_since(alice, seq):
    return [a for a in alice.get("/v1/alerts", params={"since_seq": seq, "limit": 200}).json()["alerts"]]


def _head(alice):
    recs = alice.get("/v1/audit", params={"limit": 1}).json()["records"]
    return recs[-1]["seq"] if recs else 0


@pytest.fixture
def parent(make_agent):
    ag = make_agent(cpclient.uid("t3dlg"), models=("mock-local", "mock-remote"), budget=2.0)
    assert ag["delegation_token"].startswith("gpm1.")
    return ag


def test_narrower_child_is_minted_and_enforced(alice, parent):
    r = _mint(parent["delegation_token"], "summariser", 0.5, ["mock-local"])
    assert r.status_code == 201, r.text
    child = r.json()
    assert child["child_agent_id"] == parent["agent"]["agent_id"] + ".summariser"
    assert child["scope"]["budget_usd"] == 0.5 and child["scope"]["models"] == ["mock-local"]
    assert child["scope"]["chain"] == [parent["agent"]["agent_id"], child["child_agent_id"]]
    # the child's own gateway key carries the narrower scope
    assert cpclient.chat(child["gateway_key"], "mock-local").status_code == 200
    assert cpclient.chat(child["gateway_key"], "mock-remote").status_code in (401, 403)
    info = alice.get(f"/v1/agents/{child['child_agent_id']}").json()
    assert info["parent_agent_id"] == parent["agent"]["agent_id"] and info["delegation_depth"] == 1
    assert info["max_budget_usd"] == 0.5


def test_broadening_attempts_are_denied_and_alerted(alice, parent):
    tok = parent["delegation_token"]
    seq = _head(alice)
    denied = {
        "budget": _mint(tok, "big", 5.0, ["mock-local"]),
        "models": _mint(tok, "wide", 0.1, ["mock-local", "mock-remote-slow"]),
    }
    ok = _mint(tok, "first", 1.5, ["mock-local"])
    assert ok.status_code == 201
    denied["remaining_budget"] = _mint(tok, "second", 0.6, ["mock-local"])      # 2.0 - 1.5 = 0.5 left
    for what, r in denied.items():
        assert r.status_code == 403, (what, r.text)
        assert r.json()["error"] == "delegation_denied"
    alerts = [a for a in _alerts_since(alice, seq) if a["action"] == "delegation.broadening_denied"]
    assert len(alerts) == 3
    assert any("outside the parent's scope" in " ".join(a["details"]["reasons"]) for a in alerts)
    record_result("delegation_denials", {k: v.json() for k, v in denied.items()})


def test_depth_cap(parent):
    c1 = _mint(parent["delegation_token"], "lvl1", 1.0, ["mock-local"]).json()
    c2 = _mint(c1["delegation_token"], "lvl2", 0.5, ["mock-local"])
    assert c2.status_code == 201 and c2.json()["scope"]["depth"] == 2
    c3 = _mint(c2.json()["delegation_token"], "lvl3", 0.1, ["mock-local"])
    assert c3.status_code == 403 and "depth" in json.dumps(c3.json())
    # a child may not outlive its parent credential either
    long = _mint(c1["delegation_token"], "forever", 0.1, ["mock-local"], ttl_s=10 ** 7)
    assert long.status_code == 403 and "outlives" in json.dumps(long.json())


def test_tampered_and_lateral_tokens_rejected_and_alerted(alice, parent):
    tok = parent["delegation_token"]
    seq = _head(alice)
    # 1. edit a caveat in place (budget 2.0 -> 200) keeping the signature
    prefix, body, sig = tok.split(".")
    data = json.loads(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))
    data["caveats"] = [c.replace("budget_usd <= 2.0", "budget_usd <= 200") for c in data["caveats"]]
    forged = ".".join([prefix, base64.urlsafe_b64encode(json.dumps(data, separators=(",", ":")).encode())
                       .decode().rstrip("="), sig])
    assert _mint(forged, "x", 10, ["mock-local"]).status_code == 403
    # 2. append a broader caveat offline (legal macaroon op): scope is still the intersection
    import sys
    sys.path.insert(0, str(cpclient.CP_SRC))
    from govcp.domain import macaroon
    wider = macaroon.attenuate(tok, ["budget_usd <= 100"])
    r = _mint(wider, "y", 3.0, ["mock-local"])
    assert r.status_code == 403 and "exceeds" in json.dumps(r.json())
    # 3. lateral move: claim to be another registered agent
    lateral = macaroon.attenuate(tok, ["agent = hr-agent"])
    assert _mint(lateral, "z", 0.1, ["mock-local"]).status_code == 403
    acts = {a["action"] for a in _alerts_since(alice, seq)}
    assert {"delegation.invalid_token", "delegation.broadening_denied", "delegation.chain_rejected"} <= acts


def test_out_of_scope_use_via_auth_proxy_denied_and_alerted(alice, parent):
    child = _mint(parent["delegation_token"], "scoped", 0.5, ["mock-local"]).json()
    tok = child["delegation_token"]
    assert cpclient.chat(tok, "mock-local", base=cpclient.AUTHPROXY_URL, auth_scheme="Macaroon").status_code == 200
    seq = _head(alice)
    r = cpclient.chat(tok, "mock-remote", base=cpclient.AUTHPROXY_URL, auth_scheme="Macaroon")
    assert r.status_code == 403
    assert any(a["action"] == "delegation.scope_violation" for a in _alerts_since(alice, seq))


def test_stopping_parent_cascades_to_sub_agents(alice, parent):
    child = _mint(parent["delegation_token"], "worker", 0.5, ["mock-local"]).json()
    assert cpclient.chat(child["gateway_key"]).status_code == 200
    rep = alice.post(f"/v1/agents/{parent['agent']['agent_id']}/stop", {"reason": "orchestrator compromised"}).json()
    assert child["child_agent_id"] in rep["agents"] and rep["verify"]["ok"]
    assert cpclient.chat(child["gateway_key"]).status_code == 401
    # and nothing further can be minted from the dead lineage
    assert _mint(child["delegation_token"], "more", 0.1, ["mock-local"]).status_code == 403
