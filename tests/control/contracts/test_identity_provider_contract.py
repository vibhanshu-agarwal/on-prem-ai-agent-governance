"""IdentityProvider contract (generic OIDC adapter against the stand-in IdP, in-memory reference)."""
from __future__ import annotations

import pytest

import cpclient
from cpclient import live_or_skip

from govcp.adapters.memory import MemoryIdentity
from govcp.domain.errors import Unauthorized
from govcp.domain.models import Principal

AUD = "govpilot-gateway"


@pytest.fixture(params=["memory", "oidc"])
def fx(request):
    if request.param == "memory":
        idp = MemoryIdentity()

        def issue(sub, aud=AUD):
            return idp.issue(Principal(subject=sub, roles=["agent"], kind="client"), aud)
        return "memory", idp, issue
    live_or_skip()
    from govcp.adapters.oidc_identity import OIDCIdentityProvider
    idp = OIDCIdentityProvider(issuer="http://idp:8300", jwks_url=f"{cpclient.IDP_URL}/jwks.json",
                               admin_url=cpclient.IDP_URL, admin_token=cpclient.ENV["IDP_ADMIN_TOKEN"])
    secrets = {}

    def issue(sub, aud=AUD):
        if sub not in secrets:
            secrets[sub] = cpclient.idp_admin("POST", "/admin/clients",
                                              json={"client_id": sub, "roles": ["agent"]}).json()["client_secret"]
        r = cpclient.client_token(sub, secrets[sub], audience=aud)
        if r.status_code != 200:
            raise Unauthorized(r.text)
        return r.json()["access_token"]
    return "oidc", idp, issue


def test_verify_valid_token(fx):
    _, idp, issue = fx
    sub = cpclient.uid("idc")
    p = idp.verify(issue(sub), AUD)
    assert p.subject == sub and "agent" in p.roles and p.kind == "client"


def test_wrong_audience_and_garbage_rejected(fx):
    _, idp, issue = fx
    sub = cpclient.uid("idc")
    with pytest.raises(Unauthorized):
        idp.verify(issue(sub, aud="govpilot-control-plane"), AUD)
    with pytest.raises(Unauthorized):
        idp.verify("not-a-token", AUD)


def test_disable_blocks_new_tokens_but_not_issued_ones(fx):
    kind, idp, issue = fx
    sub = cpclient.uid("idc")
    tok = issue(sub)
    idp.disable_subject(sub)
    assert idp.subject_enabled(sub) is False
    with pytest.raises(Unauthorized):
        issue(sub)
    if kind == "oidc":
        # the property that makes key mapping necessary: an issued JWT stays cryptographically valid
        assert idp.verify(tok, AUD).subject == sub
    idp.enable_subject(sub)
    assert idp.subject_enabled(sub) is True
    assert idp.verify(issue(sub), AUD).subject == sub
