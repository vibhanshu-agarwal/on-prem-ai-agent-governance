"""Fixtures for the T6 discovery tests.

Unit tests (test_feeds_unit.py, test_runner_unit.py, test_feed_contract.py) need nothing running.
Live tests (test_live_*.py) need the T1 stack, the control plane (scripts/control-plane-up.sh), and the
discovery service (scripts/discovery-up.sh); the gateway-key and eBPF ones also need the observability
stack (scripts/observability-up.sh gateway-demo ebpf).
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "services" / "discovery"))
sys.path.insert(0, str(ROOT / "tests" / "control"))              # cpclient (IdP logins, CP client)
sys.path.insert(0, str(ROOT / "services" / "control-plane"))     # govcp, for the DiscoveryFeed contract

import docker  # noqa: E402

from common import _running  # noqa: E402


@pytest.fixture(scope="session")
def live():
    import cpclient
    if not cpclient.stack_up():
        pytest.skip("control plane / gateway not running (scripts/bootstrap.sh + scripts/control-plane-up.sh)")
    if not _running("gov-discovery"):
        pytest.skip("gov-discovery not running (scripts/discovery-up.sh)")
    yield
    cleanup()


@pytest.fixture(autouse=True)
def _remove_test_containers_after_each_test():
    """The rogue containers sit on govpilot_agents: never leave them behind for other suites (T1 asserts
    that only the gateway is on that network)."""
    yield
    cleanup()


def cleanup():
    d = docker.from_env()
    for c in d.containers.list(all=True, filters={"label": "govpilot.t6test=1"}):
        try:
            c.remove(force=True)
        except docker.errors.APIError:
            pass


@pytest.fixture(scope="session")
def alice(live):
    import cpclient
    return cpclient.CP("alice")


@pytest.fixture
def reject_after(alice):
    """Collect proposal ids a test created; reject them afterwards so the demo queue stays clean."""
    ids: list[str] = []
    yield ids
    for pid in ids:
        alice.post(f"/v1/discovery/proposals/{pid}/reject", {"reason": "T6 test cleanup"})
