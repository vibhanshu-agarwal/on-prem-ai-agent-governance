"""Pending discovery queue (report section 3): feeds propose, humans approve, zero budget until then."""
from __future__ import annotations

import httpx
import pytest

import cpclient

pytestmark = pytest.mark.usefixtures("live")


def _obs(name, **kw):
    return {"fingerprint": f"container:{name}", "kind": "workload", "name": name, "image": "python:3.12-slim",
            "suggested_team": "hr", "evidence": {"first_seen_call": "2026-09-29T10:00:00Z", "via": "test"}, **kw}


def _feed_client():
    tok = cpclient.client_token("feed-test", cpclient.ENV["IDP_CLIENT_SECRET_FEED_TEST"],
                                audience="govpilot-control-plane").json()["access_token"]
    return httpx.Client(base_url=cpclient.CP_URL, headers={"Authorization": f"Bearer {tok}"}, timeout=30)


def test_proposal_lands_pending_with_zero_budget_and_no_key(alice):
    feed = cpclient.uid("feed")                      # admin submits on behalf of a fresh feed name
    name = cpclient.uid("shadow-svc")
    r = alice.post("/v1/discovery/proposals", {**_obs(name), "feed": feed})
    assert r.status_code == 201, r.text
    p = r.json()
    assert p["status"] == "pending" and p["budget_usd"] == 0 and p["gateway_key"] is None and p["feed"] == feed
    # nothing exists at the gateway for it: it can spend nothing
    keys = cpclient.gw_admin().get("/key/list", params={"key_alias": name}).json()
    assert keys.get("keys") == []
    # resubmitting the same thing does not create a second entry
    again = alice.post("/v1/discovery/proposals", {**_obs(name), "feed": feed}).json()
    assert again.get("duplicate") is True and again["proposal_id"] == p["proposal_id"]


def test_auto_proposals_need_evidence(alice):
    r = alice.post("/v1/discovery/proposals", {**_obs(cpclient.uid("noev")), "evidence": {},
                                                "feed": cpclient.uid("feed")})
    assert r.status_code == 422


def test_per_feed_daily_rate_limit():
    fc = _feed_client()
    statuses = [fc.post("/v1/discovery/proposals", json=_obs(cpclient.uid("flood"))) for _ in range(4)]
    codes = [s.status_code for s in statuses]
    assert 429 in codes, codes                                    # feed-test is capped at 3/day in config
    assert codes.count(201) <= 3
    limited = next(s for s in statuses if s.status_code == 429).json()
    assert limited["details"]["daily_limit"] == 3


def test_only_a_human_team_owner_can_approve(alice, carol, dave, make_agent):
    feed = cpclient.uid("feed")
    name = cpclient.uid("found-agent")
    p = alice.post("/v1/discovery/proposals", {**_obs(name), "feed": feed}).json()
    body = {"agent_id": name, "team": "hr", "max_budget_usd": 0.25, "models": ["mock-local"]}
    assert dave.post(f"/v1/discovery/proposals/{p['proposal_id']}/approve", body).status_code == 403  # not hr owner
    fc = _feed_client()
    assert fc.post(f"/v1/discovery/proposals/{p['proposal_id']}/approve", json=body).status_code == 403
    r = carol.post(f"/v1/discovery/proposals/{p['proposal_id']}/approve", body)
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["proposal"]["status"] == "approved" and out["agent"]["max_budget_usd"] == 0.25
    assert out["agent"]["owner"] == "carol" and out["agent"]["labels"]["discovered_by"] == feed
    assert cpclient.chat(out["gateway_key"]).status_code == 200          # budget exists only now
    cpclient.gw_admin().post("/key/delete", json={"keys": [out["agent"]["gateway_keys"][0]["key_hash"]]})


def test_reject(alice, bob):
    p = alice.post("/v1/discovery/proposals", {**_obs(cpclient.uid("junk")), "feed": cpclient.uid("feed")}).json()
    r = bob.post(f"/v1/discovery/proposals/{p['proposal_id']}/reject", {"reason": "test container"})
    assert r.status_code == 200 and r.json()["status"] == "rejected"
