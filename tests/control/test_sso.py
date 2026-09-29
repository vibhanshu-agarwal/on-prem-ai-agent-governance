"""Authenticated (SSO/JWT) agents behind the auth proxy (report section 2, section 8 'authenticated-agent stop')."""
from __future__ import annotations

import base64
import json
import time

import httpx
import jwt
import pytest

import cpclient
from cpclient import record_result, wait_until

pytestmark = pytest.mark.usefixtures("live")


def _sso_agent(make_agent):
    client_id = cpclient.uid("sso-agent")
    r = cpclient.idp_admin("POST", "/admin/clients", json={"client_id": client_id, "roles": ["agent"]})
    assert r.status_code == 201, r.text
    secret = r.json()["client_secret"]
    ag = make_agent(cpclient.uid("t3sso"), oidc_subjects=[client_id])
    return client_id, secret, ag


def _jwt(client_id, secret):
    r = cpclient.client_token(client_id, secret)
    assert r.status_code == 200, r.text
    return r.json()["access_token"]


def test_jwt_is_mapped_to_the_agents_own_key(make_agent):
    client_id, secret, ag = _sso_agent(make_agent)
    tok = _jwt(client_id, secret)
    r = cpclient.chat(tok, base=cpclient.AUTHPROXY_URL)
    assert r.status_code == 200, r.text
    # spend lands on the agent's own virtual key (the object we can block)
    key_hash = ag["agent"]["gateway_keys"][0]["key_hash"]
    info = cpclient.gw_admin().get("/key/info", params={"key": key_hash}).json()["info"]
    assert info["metadata"]["agent_id"] == ag["agent"]["agent_id"]
    assert wait_until(lambda: cpclient.gw_admin().get("/key/info", params={"key": key_hash}).json()["info"]
                      ["spend"] > 0, timeout=20)


def test_sso_agent_stopped_without_waiting_for_token_expiry(alice, make_agent):
    client_id, secret, ag = _sso_agent(make_agent)
    agent_id, team = ag["agent"]["agent_id"], ag["agent"]["team"]
    # a streaming SSO agent in a container, going through the auth proxy on the agents network
    c = cpclient.run_agent_container(agent_id, team, {
        "AUTH_MODE": "oidc", "IDP_TOKEN_URL": "http://idp:8300/token", "CLIENT_ID": client_id,
        "CLIENT_SECRET": secret, "GATEWAY_URL": "http://sso-gateway:8080", "MODEL": "mock-local-slow",
        "MAX_TOKENS": "200"}, network=cpclient.SSO_NET)
    cpclient.wait_for_log(c, r"TOK .*\nTOK ", timeout=40)
    tok = _jwt(client_id, secret)
    exp = jwt.decode(tok, options={"verify_signature": False})["exp"]
    assert cpclient.chat(tok, base=cpclient.AUTHPROXY_URL).status_code == 200

    with cpclient.DenialProbe(lambda: cpclient.chat(tok, base=cpclient.AUTHPROXY_URL)) as probe:
        t0 = time.time()
        rep = alice.post(f"/v1/agents/{agent_id}/stop", {"reason": "SSO agent drill"}).json()
        time.sleep(0.5)
    assert rep["verify"]["ok"], rep["verify"]["failed"]
    assert probe.first_denied is not None and probe.ok_after_denial == 0
    r = cpclient.chat(tok, base=cpclient.AUTHPROXY_URL)
    t_denied = time.time()
    assert r.status_code in (401, 403), r.text
    assert exp - time.time() > 600, "token must still be valid for many minutes: we did not wait for expiry"
    assert t_denied - t0 < 30
    # IdP fallback: no new tokens for that subject
    assert cpclient.client_token(client_id, secret).status_code == 403
    # the in-flight stream through the proxy was cut too
    cut_at = rep["phase_end_wall"]["network"]
    ev = cpclient.parse_events(c.logs().decode())
    assert not [t for k, t, _ in ev if k == "TOK" and t > cut_at + 0.25]
    record_result("sso_stop", {"decision_to_first_denied_request_s": round(probe.first_denied - t0, 3),
                               "decision_to_stop_complete_s": round(t_denied - t0, 3), "token_seconds_left":
                               round(exp - time.time()), "timings_ms": rep["timings_ms"],
                               "network": rep["network"]["results"][0]})


def test_unregistered_identity_gets_nothing_and_is_proposed(alice):
    client_id = cpclient.uid("shadow-sso")
    secret = cpclient.idp_admin("POST", "/admin/clients", json={"client_id": client_id}).json()["client_secret"]
    r = cpclient.chat(_jwt(client_id, secret), base=cpclient.AUTHPROXY_URL)
    assert r.status_code == 403
    props = alice.get("/v1/discovery/proposals", params={"status": "pending"}).json()["proposals"]
    mine = [p for p in props if p["fingerprint"] == f"oidc:{client_id}"]
    assert mine and mine[0]["feed"] == "idp-first-use" and mine[0]["budget_usd"] == 0 and mine[0]["gateway_key"] is None


def test_forged_and_wrong_audience_tokens_rejected(make_agent):
    client_id, secret, _ = _sso_agent(make_agent)
    tok = _jwt(client_id, secret)
    h, p, s = tok.split(".")
    claims = json.loads(base64.urlsafe_b64decode(p + "=="))
    claims["sub"] = "coding-agent"
    forged = ".".join([h, base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("="), s])
    assert cpclient.chat(forged, base=cpclient.AUTHPROXY_URL).status_code == 401
    cp_aud = cpclient.client_token(client_id, secret, audience="govpilot-control-plane").json()["access_token"]
    assert cpclient.chat(cp_aud, base=cpclient.AUTHPROXY_URL).status_code == 401
    assert httpx.post(f"{cpclient.AUTHPROXY_URL}/v1/chat/completions", json={}).status_code == 401


def test_sso_network_reaches_only_auth_proxy_and_idp(live):
    code = ("import socket\n"
            "for h,p in [('sso-gateway',8080),('idp',8300),('gateway',4000),('control-plane',8100),"
            "('mock-local',8000),('1.1.1.1',443)]:\n"
            "    try:\n"
            "        socket.create_connection((h,p),timeout=3); print(h,'OPEN')\n"
            "    except OSError as e:\n"
            "        print(h,'BLOCKED')\n")
    out = cpclient.dclient().containers.run(cpclient.AGENT_IMAGE, ["python", "-c", code], remove=True,
                                            network=cpclient.SSO_NET, labels=cpclient.TEST_LABEL).decode()
    res = dict(line.split() for line in out.strip().splitlines())
    assert res == {"sso-gateway": "OPEN", "idp": "OPEN", "gateway": "BLOCKED", "control-plane": "BLOCKED",
                   "mock-local": "BLOCKED", "1.1.1.1": "BLOCKED"}, res


def test_machine_clients_cannot_read_the_register_or_audit_log(make_agent):
    """A valid token is not read access: an agent that asks the IdP for the control-plane audience gets 403
    on the register, stop reports, quarantine state and audit log (viewer/operator/approver/owner only)."""
    client_id, secret, _ = _sso_agent(make_agent)
    tok = cpclient.client_token(client_id, secret, audience="govpilot-control-plane").json()["access_token"]
    h = {"Authorization": f"Bearer {tok}"}
    for path in ("/v1/agents", "/v1/stops", "/v1/quarantine/actions", "/v1/audit", "/v1/alerts",
                 "/v1/discovery/proposals"):
        assert httpx.get(cpclient.CP_URL + path, headers=h, timeout=10).status_code == 403, path
    assert httpx.get(cpclient.CP_URL + "/v1/agents", headers={"Authorization": "Bearer x.y.z"},
                     timeout=10).status_code == 401
