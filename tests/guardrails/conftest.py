"""T5 guardrail tests.

Unit tests (no stack): rules, pipeline, overrides, approvals, fail modes, engine swap, signed-policy
overlay. They run the REAL deploy/guardrails/guardrails.yaml through the real pipeline with the
builtin engine or small fakes.
Live tests (`live_*`): need the govpilot stack (scripts/bootstrap.sh; Presidio + gateway healthy).
The Presidio adapter/latency tests talk to Presidio on 127.0.0.1:5301/5302 (published by
tests/guardrails/stack/compose.echo.yml); the gateway tests use the echo provider from the same overlay.
Run:  .venv/Scripts/python -m pytest tests/guardrails
"""
import asyncio
import copy
import json
import pathlib
import subprocess
import sys
import time
import uuid

import pytest
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "guardrails"))
sys.path.insert(0, str(ROOT / "services" / "policy"))

from govguard import (BuiltinEngine, CallContext, EngineUnavailable, FileApprovalStore,  # noqa: E402
                      FileOverrideStore, GuardrailConfig, GuardrailPipeline, MemoryAuditSink, Span)

CONFIG_PATH = ROOT / "deploy" / "guardrails" / "guardrails.yaml"
PRESIDIO_ANALYZER = "http://127.0.0.1:5301"
PRESIDIO_ANONYMIZER = "http://127.0.0.1:5302"
COMPOSE = ["docker", "compose", "-p", "govpilot", "--env-file", str(ROOT / "deploy" / ".env"),
           "-f", str(ROOT / "deploy" / "docker-compose.yml"),
           "-f", str(ROOT / "tests" / "guardrails" / "stack" / "compose.echo.yml")]


def run(coro):
    return asyncio.run(coro)


class Clock:
    def __init__(self, t=1_800_000_000.0):
        self.t = t

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


class DownEngine:
    name = "down"

    def __init__(self):
        self.calls = 0

    async def analyze(self, *a, **k):
        self.calls += 1
        raise EngineUnavailable("engine down (test)")

    async def anonymize(self, *a, **k):
        raise EngineUnavailable("engine down (test)")

    async def aclose(self):
        pass


class Harness:
    def __init__(self, tmp_path, engine=None, raw=None, overlay=None, clock=None):
        self.clock = clock or Clock()
        raw = raw or yaml.safe_load(CONFIG_PATH.read_text())
        self.config = GuardrailConfig(raw, overlay)
        self.audit = MemoryAuditSink()
        self.overrides = FileOverrideStore(tmp_path / "ovr", self.audit, 86400, clock=self.clock, cache_seconds=0)
        self.approvals = FileApprovalStore(tmp_path / "apr", self.audit, clock=self.clock)
        self.engine = engine or BuiltinEngine()
        self.pipeline = GuardrailPipeline(self.config, self.engine, overrides=self.overrides,
                                          approvals=self.approvals, audit=self.audit, clock=self.clock)

    def ctx(self, agent="finance-recon-agent", team=None, approval_id=None):
        return CallContext(agent_id=agent, team=team, request_id=uuid.uuid4().hex[:8], approval_id=approval_id)

    def request(self, messages, agent="finance-recon-agent", **data):
        d = {"model": "mock-local", "messages": messages, **data}
        out = run(self.pipeline.check_request(self.ctx(agent), d))
        return d, out

    def response(self, content=None, tool_calls=None, agent="finance-recon-agent", approval_id=None):
        return run(self.pipeline.check_response(self.ctx(agent, approval_id=approval_id), content, tool_calls))


@pytest.fixture
def harness(tmp_path):
    return Harness(tmp_path)


@pytest.fixture
def make_harness(tmp_path):
    def _mk(**kw):
        return Harness(tmp_path, **kw)
    return _mk


@pytest.fixture
def raw_config():
    return copy.deepcopy(yaml.safe_load(CONFIG_PATH.read_text()))


def sh(*args, check=True, timeout=180):
    return subprocess.run(list(args), capture_output=True, text=True, timeout=timeout, check=check)
