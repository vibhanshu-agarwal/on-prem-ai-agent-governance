"""T8 acceptance suite: one test per report section 8 test, plus the July minimum pilot criteria.

Runs against the full live stack (scripts/up.sh). Each test is tagged with
    @pytest.mark.accept(id=..., title=..., criterion=..., simplification=...)
and records its measured numbers with the `record` fixture. At the end of the session the outcome, the numbers
and the simplification note of every test are merged into .local/acceptance/results.json, which
scripts/acceptance_report.py turns into docs/results/ACCEPTANCE.md.

Destructive drills (stopping Presidio, Redis, Postgres, the control plane, the evidence plane) restore what
they stopped in a `finally` block and wait for health before the next test.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import acclib  # noqa: E402

RESULTS = acclib.RESULTS / "results.json"
_meta: dict[str, dict] = {}
_metrics: dict[str, dict] = {}
_outcome: dict[str, dict] = {}


def pytest_configure(config):
    config.addinivalue_line("markers", "accept(id, title, criterion, simplification): acceptance test metadata")


@pytest.fixture(scope="session")
def live():
    if not acclib.cpclient.stack_up():
        pytest.skip("full stack not running (scripts/up.sh)")
    yield
    acclib.cleanup_t8_containers()


@pytest.fixture(scope="session")
def alice(live):
    return acclib.cpclient.CP("alice")     # admin, operator, approver


@pytest.fixture(scope="session")
def bob(live):
    return acclib.cpclient.CP("bob")       # operator, approver


@pytest.fixture(scope="session")
def carol(live):
    return acclib.cpclient.CP("carol")     # owner(hr), approver


@pytest.fixture
def drill(alice):
    d = acclib.Drill(alice)
    yield d
    d.cleanup()


def _aid(item) -> str | None:
    m = item.get_closest_marker("accept")
    return m.kwargs.get("id") if m else None


@pytest.fixture
def record(request):
    aid = _aid(request.node) or request.node.nodeid

    def _rec(**kw):
        _metrics.setdefault(aid, {}).update(kw)
    return _rec


def pytest_collection_modifyitems(items):
    for it in items:
        m = it.get_closest_marker("accept")
        if m:
            _meta[m.kwargs["id"]] = {**m.kwargs, "nodeid": it.nodeid}


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    out = yield
    rep = out.get_result()
    aid = _aid(item)
    if not aid:
        return
    cur = _outcome.setdefault(aid, {"outcome": "passed", "duration_s": 0.0})
    cur["duration_s"] = round(cur["duration_s"] + rep.duration, 1)
    if rep.failed:
        cur["outcome"] = "failed" if rep.when == "call" else "error"
        msg = acclib.strip_ansi(str(rep.longrepr))
        cur["failure"] = msg[-1500:]
    elif rep.skipped and cur["outcome"] == "passed":
        cur["outcome"] = "skipped"
        cur["failure"] = str(rep.longrepr)[-400:]


def pytest_sessionfinish(session, exitstatus):
    if not _outcome:
        return
    RESULTS.parent.mkdir(parents=True, exist_ok=True)
    old = json.loads(RESULTS.read_text()) if RESULTS.exists() else {"tests": {}}
    for aid, o in _outcome.items():
        old["tests"][aid] = {**_meta.get(aid, {}), **o, "metrics": _metrics.get(aid, {}),
                             "ran_at": time.strftime("%Y-%m-%dT%H:%M:%S")}
    old["last_run"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    RESULTS.write_text(json.dumps(old, indent=2, default=str), encoding="utf-8")
