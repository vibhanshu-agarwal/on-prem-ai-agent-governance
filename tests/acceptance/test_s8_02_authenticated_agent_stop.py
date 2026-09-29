"""S8-02 Authenticated-agent stop: an SSO/JWT agent is stopped without waiting for its token to expire."""
from __future__ import annotations

import time

import jwt
import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")


@pytest.mark.accept(
    id="S8-02", title="Authenticated-agent stop",
    criterion="An OIDC/JWT agent is refused while its token is still valid; the IdP issues it no new token",
    simplification="Stand-in OIDC issuer (govcp.idp) instead of a corporate IdP; mTLS/certificate agents are "
                   "not built (the auth proxy maps JWTs only).")
def test_authenticated_agent_stop(alice, drill, record):
    client_id = L.uid("t8-sso")
    r = L.cpclient.idp_admin("POST", "/admin/clients", json={"client_id": client_id, "roles": ["agent"]})
    assert r.status_code == 201, r.text
    secret = r.json()["client_secret"]
    ag = drill.agent(L.uid("t8sso"), oidc_subjects=[client_id])
    agent_id = ag["agent"]["agent_id"]
    c = drill.run(ag, env={"AUTH_MODE": "oidc", "IDP_TOKEN_URL": "http://idp:8300/token", "CLIENT_ID": client_id,
                           "CLIENT_SECRET": secret, "GATEWAY_URL": "http://sso-gateway:8080"}, network=L.SSO_NET)
    L.wait_for_log(c, r"TOK .*\nTOK ")
    tok = L.cpclient.client_token(client_id, secret).json()["access_token"]
    exp = jwt.decode(tok, options={"verify_signature": False})["exp"]
    assert L.chat(tok, base=L.AUTHPROXY_URL).status_code == 200

    with L.DenialProbe(lambda: L.chat(tok, base=L.AUTHPROXY_URL)) as probe:
        t0 = time.time()
        rep = alice.post(f"/v1/agents/{agent_id}/stop", {"reason": "acceptance S8-02"}).json()
        time.sleep(0.5)
    assert rep["verify"]["ok"], rep["verify"]["failed"]
    assert probe.first_denied is not None and probe.ok_after_denial == 0
    left = exp - time.time()
    assert L.chat(tok, base=L.AUTHPROXY_URL).status_code in (401, 403)
    assert left > 300, "the token must still be valid: the stop did not wait for expiry"
    assert L.cpclient.client_token(client_id, secret).status_code == 403     # no new tokens either
    cut = rep["phase_end_wall"]["network"]
    assert not [t for k, t, _ in L.events(c) if k == "TOK" and t > cut + 0.25]
    record(decision_to_first_denied_request_s=round(probe.first_denied - t0, 3),
           token_seconds_left_at_denial=round(left), idp_new_token_status=403, timings_ms=rep["timings_ms"])
