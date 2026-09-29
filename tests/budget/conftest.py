"""T2 budget-enforcement tests.

Most tests run on an ISOLATED compose project (`govpilot-t2`, tests/budget/stack/) with
two gateways sharing one Postgres/Redis/mock set:
  guarded  127.0.0.1:4100  production config + budget guard callback
  native   127.0.0.1:4101  same config without the callback (LiteLLM-native baseline)
so destructive tests (stop Redis/Postgres, restart/kill gateways) never touch the shared
`govpilot` stack. `test_shared_stack.py` runs non-destructive checks on the shared stack.

Env:
  T2_KEEP_STACK=1   leave the isolated stack running after the session (faster reruns)
Measured numbers are written to .local/t2/results.json (source for docs/results/T2.md).
"""
import json
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "stack"))
import t2stack  # noqa: E402
from t2lib import ROOT, Gateway, sh  # noqa: E402

RESULTS = ROOT / ".local" / "t2" / "results.json"
_results: dict = {}


def pytest_configure(config):
    config.addinivalue_line("markers", "native_baseline: documents a native LiteLLM gap (expected to reproduce)")
    config.addinivalue_line("markers", "destructive: stops/restarts containers of the isolated stack")
    config.addinivalue_line("markers", "shared: runs against the shared govpilot stack (non-destructive)")


@pytest.fixture(scope="session")
def t2_stack():
    started = False
    if not t2stack.is_up():
        t2stack.up()
        started = True
    else:
        t2stack.write_configs()
    yield
    if started and os.getenv("T2_KEEP_STACK") != "1":
        t2stack.down()


def _gw(name, port, container):
    return Gateway(name=name, url=f"http://127.0.0.1:{port}", redis_container="t2-redis",
                   pg_container="t2-postgres", container=container)


def _ensure_running():
    """Destructive tests stop containers; make sure every isolated-stack container is
    running again before the next test (never touches the shared stack)."""
    for c in t2stack.CONTAINERS.values():
        st = sh("docker", "inspect", "-f", "{{.State.Running}}", c).stdout.strip()
        if st != "true":
            sh("docker", "start", c)


@pytest.fixture
def guarded(t2_stack):
    _ensure_running()
    g = _gw("guarded", t2stack.GUARDED_PORT, "t2-gateway")
    g.wait_budget_enforcement()
    yield g
    g.cleanup()


@pytest.fixture
def native(t2_stack):
    _ensure_running()
    g = _gw("native", t2stack.NATIVE_PORT, "t2-gateway-native")
    g.wait_budget_enforcement()
    yield g
    g.cleanup()


@pytest.fixture
def shared():
    port = 4000
    g = Gateway(name="shared", url=f"http://127.0.0.1:{port}", redis_container="gov-redis",
                pg_container="gov-postgres", container="gov-gateway")
    g.wait_ready(timeout=30)
    yield g
    g.cleanup()


@pytest.fixture
def record(request):
    """record(**numbers): store measured values under this test's id."""
    tid = request.node.nodeid.split("::", 1)[-1]

    def _rec(**kw):
        _results.setdefault(tid, {}).update(kw)
    return _rec


def pytest_sessionfinish(session, exitstatus):
    if not _results:
        return
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    old = json.loads(RESULTS.read_text()) if RESULTS.exists() else {}
    old.update(_results)
    old["_last_run"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    RESULTS.write_text(json.dumps(old, indent=2, sort_keys=True))
