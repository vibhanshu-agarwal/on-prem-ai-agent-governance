"""Append-only, hash-chained audit log (report section 5 'identity register compromised')."""
from __future__ import annotations

import copy
import sys

import psycopg
import pytest

import cpclient

sys.path.insert(0, str(cpclient.CP_SRC))
from govcp.domain.audit import verify_chain  # noqa: E402
from govcp.domain.models import AuditRecord  # noqa: E402

pytestmark = pytest.mark.usefixtures("live")


def _dsn(role):
    pw = cpclient.ENV["CP_APP_PASSWORD" if role == "cp_app" else "CP_OWNER_PASSWORD"]
    return f"postgresql://{role}:{pw}@127.0.0.1:{cpclient.ENV.get('CP_PG_PORT', '55432')}/controlplane"


def test_chain_verifies_and_actions_are_recorded(alice, make_agent):
    ag = make_agent(cpclient.uid("t3aud"))
    aid = ag["agent"]["agent_id"]
    alice.post(f"/v1/agents/{aid}/stop", {"reason": "audit test"})
    acts = [r["action"] for r in alice.get("/v1/audit", params={"target": aid}).json()["records"]]
    assert acts[0] == "agent.registered" and "stop.started" in acts and "stop.completed" in acts
    v = alice.get("/v1/audit/verify").json()
    assert v["ok"] is True and v["count"] > 0, v


@pytest.mark.parametrize("sql", ["UPDATE audit_log SET actor='mallory' WHERE seq=1",
                                 "DELETE FROM audit_log WHERE seq=1", "TRUNCATE audit_log"])
def test_app_role_cannot_rewrite_history(sql):
    with psycopg.connect(_dsn("cp_app"), autocommit=True) as c:
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            c.execute(sql)


@pytest.mark.parametrize("sql", ["UPDATE audit_log SET actor='mallory' WHERE seq=1",
                                 "DELETE FROM audit_log WHERE seq=1", "TRUNCATE audit_log"])
def test_even_the_owner_is_blocked_by_trigger(sql):
    with psycopg.connect(_dsn("cp_owner"), autocommit=True) as c:
        with pytest.raises(psycopg.errors.RaiseException, match="append-only"):
            c.execute(sql)


def test_app_role_grants_are_exactly_select_insert():
    with psycopg.connect(_dsn("cp_app"), autocommit=True) as c:
        rows = c.execute("SELECT privilege_type FROM information_schema.role_table_grants "
                         "WHERE grantee='cp_app' AND table_name='audit_log'").fetchall()
    assert sorted(r[0] for r in rows) == ["INSERT", "SELECT"]


def test_tampering_is_detected(alice):
    recs = [AuditRecord(**r) for r in alice.get("/v1/audit", params={"limit": 100000}).json()["records"]]
    assert verify_chain(recs).ok
    edited = copy.deepcopy(recs)
    edited[len(edited) // 2].details["reason"] = "nothing to see here"
    bad = verify_chain(edited)
    assert not bad.ok and bad.first_bad_seq == edited[len(edited) // 2].seq
    dropped = recs[:3] + recs[4:]
    assert not verify_chain(dropped).ok
