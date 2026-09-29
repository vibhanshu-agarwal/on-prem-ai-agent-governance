"""S8-11 Delegation attenuation: a sub-agent attempting to use or mint broader scope than its parent is denied,
and the attempt is alerted."""
from __future__ import annotations

import httpx
import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")


def _mint(tok, name, budget, models, **kw):
    return httpx.post(f"{L.CP_URL}/v1/delegations", timeout=30, json={
        "parent_token": tok, "name": name, "max_budget_usd": budget, "models": models, **kw})


def _head(alice):
    recs = alice.get("/v1/audit", params={"limit": 1}).json()["records"]
    return recs[-1]["seq"] if recs else 0


@pytest.mark.accept(
    id="S8-11", title="Delegation attenuation",
    criterion="Minting a child with more budget, other models, more depth or a longer life than its parent is "
              "denied; a child using a model outside its scope is refused by the auth proxy and the gateway; "
              "every attempt raises an alert-severity audit record",
    simplification="Macaroon-style HMAC tokens issued by the control plane; no cross-organisation delegation, "
                   "no OAuth token exchange (RFC 8693) with a real IdP.")
def test_delegation_attenuation(alice, drill, record):
    parent = drill.agent(L.uid("t8dlg"), models=("mock-local", "mock-remote"), budget=1.0, passthrough=False)
    tok = parent["delegation_token"]
    seq = _head(alice)
    ok = _mint(tok, "analyst", 0.3, ["mock-local"])
    assert ok.status_code == 201, ok.text
    child = ok.json()
    denied = {
        "more_budget_than_parent": _mint(tok, "big", 5.0, ["mock-local"]),
        "model_outside_parent": _mint(tok, "wide", 0.1, ["mock-local", "mock-remote-slow"]),
        "outlives_parent": _mint(child["delegation_token"], "forever", 0.05, ["mock-local"], ttl_s=10 ** 8),
        "child_broadens_itself": _mint(child["delegation_token"], "grand", 0.1, ["mock-remote"]),
    }
    lvl2 = _mint(child["delegation_token"], "lvl2", 0.1, ["mock-local"])
    assert lvl2.status_code == 201
    denied["depth_beyond_cap"] = _mint(lvl2.json()["delegation_token"], "lvl3", 0.01, ["mock-local"])
    for what, r in denied.items():
        assert r.status_code == 403, (what, r.text)
    # use of broader scope: through the auth proxy with the child's delegation token, and with its raw key
    use = httpx.post(f"{L.AUTHPROXY_URL}/v1/chat/completions", timeout=30,
                     headers={"Authorization": f"Macaroon {child['delegation_token']}"},
                     json={"model": "mock-remote", "max_tokens": 2, "messages": [{"role": "user", "content": "hi"}]})
    assert use.status_code in (401, 403), use.text
    in_scope = httpx.post(f"{L.AUTHPROXY_URL}/v1/chat/completions", timeout=30,
                          headers={"Authorization": f"Macaroon {child['delegation_token']}"},
                          json={"model": "mock-local", "max_tokens": 2, "messages": [{"role": "user", "content": "hi"}]})
    assert in_scope.status_code == 200, in_scope.text
    alerts = [a for a in alice.get("/v1/alerts", params={"since_seq": seq, "limit": 200}).json()["alerts"]
              if a["action"].startswith("delegation.")]
    kinds = sorted({a["action"] for a in alerts})
    assert len(alerts) >= len(denied) + 1, kinds
    assert "delegation.scope_violation" in kinds and "delegation.broadening_denied" in kinds
    record(denied_attempts={k: v.status_code for k, v in denied.items()}, out_of_scope_use_status=use.status_code,
           in_scope_use_status=in_scope.status_code, alerts_raised=len(alerts), alert_kinds=kinds,
           child_scope=child["scope"])
