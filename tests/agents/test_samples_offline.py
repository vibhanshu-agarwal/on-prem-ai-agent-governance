"""The three sample agents, driven against an in-memory gateway (no Docker): what they do, and that every
LLM request they make sits inside a closed run tree."""
from __future__ import annotations

import ast
import json
import re

import pytest

from fakes import FakeGateway
from govagent import MemorySink, RunContext
from samples import fixtures
from samples.coding_agent import CAPABILITIES, CodingAgent
from samples.finance_agent import FinanceReconAgent, reconcile
from samples.hr_agent import HRAgent

KEY_ENV = {"GATEWAY_URL": "http://gateway:4000", "AUTH_MODE": "key", "AGENT_KEY": "sk-x", "AGENT_MAX_ITERATIONS": "1",
           "AGENT_RATES_FILE": ""}
SSO_ENV = {"GATEWAY_URL": "http://sso-gateway:8080", "AUTH_MODE": "oidc", "IDP_TOKEN_URL": "http://idp:8300/token",
           "CLIENT_ID": "finance-recon-agent", "CLIENT_SECRET": "s", "DELEGATION_TOKEN": "gpm1.parent.sig",
           "BROKER_URL": "http://delegation-broker:8090", "FIN_DELEGATE_THRESHOLD_USD": "0", "FIN_BATCH_SIZE": "8"}


def run_once(agent):
    root = RunContext.root(agent.agent_id)
    agent.work(root)
    return root


def tree_is_closed(sink, root, fake):
    """Every parent id seen by the gateway or in the agent log is a known run; all runs share the root."""
    starts = {e["run_id"] for e in sink.of("run.start")} | {root.run_id}
    for e in sink.events:
        if e.get("parent_run_id"):
            assert e["parent_run_id"] in starts, e
    for r in fake.llm_requests():
        h = r["headers"]
        assert h["x-govpilot-root-run-id"] == root.run_id
        assert h["x-govpilot-run-id"] in starts
        if h.get("x-govpilot-parent-run-id"):
            assert h["x-govpilot-parent-run-id"] in starts


# ------------------------------------------------------------------ HR
def test_hr_agent_answers_with_tool_runs_and_leaks_pii_into_the_prompt_on_purpose():
    fake, sink = FakeGateway(), MemorySink()
    agent = HRAgent(KEY_ENV | {"AGENT_ID": "hr-agent"}, sink=sink, transport=fake)
    root = run_once(agent)
    reqs = fake.llm_requests()
    assert len(reqs) == 2                                     # rewrite_query (tool run) + the answer (root run)
    tools = [r["headers"].get("x-govpilot-tool") for r in reqs]
    assert tools == ["rewrite_query", None]
    answer = reqs[1]
    assert answer["headers"]["x-govpilot-run-id"] == root.run_id and answer["headers"]["x-govpilot-user"].startswith("E")
    prompt = json.dumps(answer["body"]["messages"])
    assert re.search(r"\b9\d\d-\d\d-\d{4}\b", prompt) and re.search(r"[\w.]+@example\.test", prompt), "PII must reach the prompt"
    assert {e["tool"] for e in sink.of("run.start")} == {"rewrite_query", "search_policies", "lookup_employee"}
    assert answer["body"]["max_tokens"] == 128 and reqs[0]["body"]["max_tokens"] == 16
    tree_is_closed(sink, root, fake)


def test_hr_fixture_pii_is_synthetic_and_never_a_real_issued_range():
    for e in fixtures.EMPLOYEES.values():
        assert e["ssn"].startswith("9") and e["email"].endswith("@example.test") and e["phone"].startswith("+1 555-01")


# ------------------------------------------------------------------ Finance
def test_reconcile_finds_missing_variance_and_timing():
    ledger = [{"txn_id": "a", "vendor": "v", "amount": 10.0, "date": "2026-09-01"},
              {"txn_id": "b", "vendor": "v", "amount": 20.0, "date": "2026-09-01"},
              {"txn_id": "c", "vendor": "v", "amount": 30.0, "date": "2026-09-01"},
              {"txn_id": "d", "vendor": "v", "amount": 40.0, "date": "2026-09-01"}]
    bank = [dict(ledger[0]), {**ledger[1], "amount": 25.5}, {**ledger[2], "date": "2026-09-04"}]
    kinds = {e["txn_id"]: (e["kind"], e["variance"]) for e in reconcile(ledger, bank)}
    assert kinds == {"b": ("amount_variance", 5.5), "c": ("timing", 0.0), "d": ("missing_at_bank", 40.0)}


def test_finance_agent_uses_sso_jwt_and_delegates_with_an_attenuated_token():
    fake, sink = FakeGateway(), MemorySink()
    agent = FinanceReconAgent(SSO_ENV | {"AGENT_ID": "finance-recon-agent"}, sink=sink, transport=fake)
    import random
    random.seed(4)
    root = run_once(agent)
    reqs = fake.llm_requests()
    parent_reqs = [r for r in reqs if r["headers"]["authorization"] == "Bearer jwt.fake.token"]
    child_reqs = [r for r in reqs if r["headers"]["authorization"].startswith("Macaroon ")]
    assert parent_reqs and child_reqs, "both identity routes must be exercised"
    assert all(r["headers"]["x-govpilot-run-kind"] == "delegation" for r in child_reqs)
    assert {r["headers"]["x-govpilot-parent-run-id"] for r in child_reqs} == {root.run_id}
    assert fake.delegations[0]["parent_token"] == "gpm1.parent.sig" and fake.delegations[0]["models"] == ["mock-local"]
    assert any(r["headers"].get("x-govpilot-tool") == "classify_exception" for r in parent_reqs)
    assert parent_reqs[-1]["body"]["model"] == "mock-remote"        # the summary uses the larger model
    tree_is_closed(sink, root, fake)


def test_finance_agent_without_a_broker_still_reconciles():
    env = {k: v for k, v in SSO_ENV.items() if k not in ("DELEGATION_TOKEN", "BROKER_URL")}
    fake, sink = FakeGateway(), MemorySink()
    agent = FinanceReconAgent(env | {"AGENT_ID": "finance-recon-agent"}, sink=sink, transport=fake)
    run_once(agent)
    assert not fake.delegations and sink.of("finance.batch_done")


def test_finance_survives_a_denied_delegation():
    fake, sink = FakeGateway(), MemorySink()
    fake.mint_deny = ["depth 3 exceeds cap 2"]
    agent = FinanceReconAgent(SSO_ENV | {"AGENT_ID": "finance-recon-agent"}, sink=sink, transport=fake)
    import random
    random.seed(4)
    run_once(agent)
    assert sink.of("delegation.denied") and sink.of("finance.batch_done")


# ------------------------------------------------------------------ Coding
def test_coding_agent_declares_executes_model_code_and_never_executes_anything(monkeypatch):
    assert "executes_model_code" in CAPABILITIES
    import builtins
    real_exec = builtins.exec
    monkeypatch.setattr(builtins, "exec", lambda *a, **k: pytest.fail("agent executed model code"))
    fake, sink = FakeGateway(), MemorySink()
    agent = CodingAgent(KEY_ENV | {"AGENT_ID": "coding-agent"}, sink=sink, transport=fake)
    root = run_once(agent)
    monkeypatch.setattr(builtins, "exec", real_exec)
    reqs = fake.llm_requests()
    assert [r["headers"].get("x-govpilot-tool") for r in reqs] == ["plan_change", "generate_code", None]
    assert [r["body"]["model"] for r in reqs] == ["mock-local", "mock-remote", "mock-local"]
    cand = sink.of("coding.candidate")[0]
    assert cand["sandbox"]["ok"] and cand["sandbox"]["executed"] is False
    tree_is_closed(sink, root, fake)


def test_fixture_programs_compile():
    for t in fixtures.CODE_TASKS:
        ast.parse(t["code"])


# ------------------------------------------------------------------ shared
@pytest.mark.parametrize("cls,env,rogue_key", [(HRAgent, KEY_ENV, "hr-agent"), (CodingAgent, KEY_ENV, "coding-agent")])
def test_operator_max_tokens_override_applies_to_every_call(cls, env, rogue_key):
    fake, sink = FakeGateway(), MemorySink()
    agent = cls(env | {"AGENT_ID": rogue_key, "AGENT_MAX_TOKENS": "77"}, sink=sink, transport=fake)
    run_once(agent)
    assert {r["body"]["max_tokens"] for r in fake.llm_requests()} == {77}


def test_each_iteration_is_a_new_root_run():
    fake, sink = FakeGateway(), MemorySink()
    agent = CodingAgent(KEY_ENV | {"AGENT_ID": "coding-agent"}, sink=sink, transport=fake)
    a, b = run_once(agent), run_once(agent)
    assert a.run_id != b.run_id
    roots = {r["headers"]["x-govpilot-root-run-id"] for r in fake.llm_requests()}
    assert roots == {a.run_id, b.run_id}


def test_registered_image_binding_matches_the_compose_image_for_every_agent():
    """T6 discovery folds a workload into a registered agent only if it runs the image the register binds to."""
    import yaml
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    prov = json.loads((root / "deploy" / "agents.json").read_text())["agents"]
    compose = yaml.safe_load((root / "deploy" / "compose.agents.yml").read_text())["services"]
    by_id = {s["labels"]["govpilot.agent_id"]: s for s in compose.values() if "govpilot.agent_id" in s.get("labels", {})}
    assert set(by_id) == set(prov)
    for aid, cfg in prov.items():
        assert cfg["image"] == by_id[aid]["image"], aid
        assert by_id[aid]["labels"]["govpilot.team"] == cfg["team"]
        assert by_id[aid]["labels"]["govpilot.sandbox_tier"] == cfg["sandbox_tier"]
        assert sorted(by_id[aid]["labels"]["govpilot.capabilities"].split(",")) == sorted(cfg["capabilities"])
        assert by_id[aid]["labels"]["govpilot.auth"] == cfg["auth"]
