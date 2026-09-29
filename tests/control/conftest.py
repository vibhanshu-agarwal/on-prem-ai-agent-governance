"""Fixtures for the T3 control-plane tests.

Live tests need the T1 stack plus the control plane (scripts/control-plane-up.sh).
Unit tests (test_domain_unit.py) and the memory half of the contract suites need nothing.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "services" / "control-plane"))

import cpclient  # noqa: E402


@pytest.fixture(scope="session")
def live():
    if not cpclient.stack_up():
        pytest.skip("control plane / gateway not running (scripts/bootstrap.sh + scripts/control-plane-up.sh)")
    yield
    cpclient.cleanup_test_containers()


@pytest.fixture(scope="module", autouse=True)
def _remove_test_containers_after_module():
    yield
    cpclient.cleanup_test_containers()


@pytest.fixture(scope="session")
def alice(live):
    return cpclient.CP("alice")   # admin, operator, approver


@pytest.fixture(scope="session")
def bob(live):
    return cpclient.CP("bob")     # operator, approver


@pytest.fixture(scope="session")
def carol(live):
    return cpclient.CP("carol")   # owner(hr), approver


@pytest.fixture(scope="session")
def dave(live):
    return cpclient.CP("dave")    # owner(engineering, finance)


@pytest.fixture(scope="session")
def erin(live):
    return cpclient.CP("erin")    # viewer


@pytest.fixture
def make_agent(alice):
    """Register a throwaway agent (with its own gateway key) through the API; clean keys up after."""
    created = []

    def _make(team: str, models=("mock-local", "mock-local-slow"), budget=1.0, **extra):
        agent_id = extra.pop("agent_id", None) or cpclient.uid("t3a")
        body = {"agent_id": agent_id, "team": team, "owner": "alice", "max_budget_usd": budget,
                "models": list(models), "sandbox_tier": extra.pop("sandbox_tier", "container"), **extra}
        r = alice.post("/v1/agents", body)
        assert r.status_code == 201, r.text
        cpclient.mark_drill_keys([k["key_hash"] for k in r.json()["agent"]["gateway_keys"]])
        created.append(r.json())
        return r.json()

    yield _make
    gw = cpclient.gw_admin()
    for c in created:
        hashes = [k["key_hash"] for k in c["agent"]["gateway_keys"]]
        # sub-agent keys minted during the test
        try:
            info = alice.get(f"/v1/agents/{c['agent']['agent_id']}/live").json()
            for d in info.get("delegates", []):
                hashes += [k["key_hash"] for k in alice.get(f"/v1/agents/{d}").json()["gateway_keys"]]
        except Exception:  # noqa: BLE001
            pass
        if hashes:
            gw.post("/key/delete", json={"keys": hashes})
