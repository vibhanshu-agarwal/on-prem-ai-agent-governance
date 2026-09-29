"""Contract: run_id propagation through tool calls and delegation."""
from __future__ import annotations

import pytest

from fakes import FakeGateway
from govagent import (DelegationDenied, Delegator, GatewayClient, RetryPolicy, RunContext, StaticKeyAuth, ToolBox,
                      ToolNotAllowed)


def gw_for(fake, sink):
    return GatewayClient("http://gateway:4000", StaticKeyAuth("k"), transport=fake, sink=sink,
                         retry=RetryPolicy(max_attempts=3, base_delay_s=0), sleep=lambda s: None)


MSGS = [{"role": "user", "content": "x"}]


# ------------------------------------------------------------------ tools
def test_a_tool_call_is_a_child_run_and_its_llm_call_is_attributed_to_it(sink):
    fake = FakeGateway()
    gw = gw_for(fake, sink)
    box = ToolBox("hr-agent", sink, allowed={"summarise"})
    root = RunContext.root("hr-agent")
    seen = {}

    def summarise(run, text):
        seen["run"] = run
        return gw.chat(run, "mock-local", MSGS).text

    box.call(root, "summarise", summarise, text="t")
    h = fake.llm_requests()[0]["headers"]
    assert seen["run"].kind == "tool" and seen["run"].tool == "summarise" and seen["run"].parent_run_id == root.run_id
    assert h["x-govpilot-run-id"] == seen["run"].run_id and h["x-govpilot-run-id"] != root.run_id
    assert h["x-govpilot-parent-run-id"] == root.run_id and h["x-govpilot-root-run-id"] == root.run_id
    assert h["x-govpilot-tool"] == "summarise" and h["x-govpilot-run-kind"] == "tool"
    start, end = sink.of("run.start")[0], sink.of("run.end")[0]
    assert start["run_id"] == end["run_id"] == seen["run"].run_id and end["status"] == "ok"


def test_tools_that_never_call_the_model_still_leave_a_run_in_the_tree(sink):
    box = ToolBox("hr-agent", sink)
    root = RunContext.root("hr-agent")
    assert box.call(root, "lookup", lambda run, k: {"k": k}, k=1) == {"k": 1}
    ev = sink.of("run.start")
    assert len(ev) == 1 and ev[0]["parent_run_id"] == root.run_id and ev[0]["tool"] == "lookup"


def test_nested_tools_chain_parents(sink):
    fake = FakeGateway()
    gw = gw_for(fake, sink)
    box = ToolBox("a-agent", sink)
    root = RunContext.root("a-agent")

    def outer(run):
        return box.call(run, "inner", lambda r: gw.chat(r, "m", MSGS))

    box.call(root, "outer", outer)
    starts = {e["tool"]: e for e in sink.of("run.start")}
    assert starts["inner"]["parent_run_id"] == starts["outer"]["run_id"] and starts["outer"]["parent_run_id"] == root.run_id
    assert fake.llm_requests()[0]["headers"]["x-govpilot-run-id"] == starts["inner"]["run_id"]
    assert fake.llm_requests()[0]["headers"]["x-govpilot-root-run-id"] == root.run_id


def test_failing_tool_closes_its_run_with_the_error(sink):
    box = ToolBox("a-agent", sink)

    def boom(run):
        raise RuntimeError("db down")
    with pytest.raises(RuntimeError):
        box.call(RunContext.root("a-agent"), "boom", boom)
    end = sink.of("run.end")[0]
    assert end["status"] == "error" and "db down" in end["error"]


def test_undeclared_tool_is_refused_and_recorded(sink):
    box = ToolBox("a-agent", sink, allowed={"ok"})
    with pytest.raises(ToolNotAllowed):
        box.call(RunContext.root("a-agent"), "shell", lambda run: None)
    assert sink.of("tool.denied")[0]["tool"] == "shell" and not sink.of("run.start")


def test_each_call_of_the_same_tool_is_a_new_run(sink):
    box = ToolBox("a-agent", sink)
    root = RunContext.root("a-agent")
    ids = {box.call(root, "t", lambda run: run.run_id) for _ in range(5)}
    assert len(ids) == 5


# ------------------------------------------------------------------ delegation
def delegator(fake, sink, **kw):
    return Delegator("parent", "http://delegation-broker:8090", "gpm1.parent.sig", "http://sso-gateway:8080", sink,
                     transport=fake,
                     client_factory=lambda url, auth: GatewayClient(url, auth, transport=fake, sink=sink,
                                                                    retry=RetryPolicy(max_attempts=3, base_delay_s=0),
                                                                    sleep=lambda s: None), **kw)


def test_delegation_creates_a_delegation_run_under_an_attenuated_token(sink):
    fake = FakeGateway()
    d = delegator(fake, sink, budget_usd=0.2, models=["mock-local"], ttl_s=600)
    root = RunContext.root("parent")
    got = {}

    def sub(child_run, child_gw):
        got["run"] = child_run
        return child_gw.chat(child_run, "mock-local", MSGS)

    d.delegate(root, "analyst", "variance", sub)
    mint = fake.delegations[0]
    assert mint["parent_token"] == "gpm1.parent.sig" and mint["max_budget_usd"] == 0.2
    assert mint["models"] == ["mock-local"] and mint["ttl_s"] == 600 and mint["name"].startswith("analyst-")
    req = fake.llm_requests()[0]
    assert req["headers"]["authorization"] == "Macaroon gpm1.child1.sig"          # NOT the parent's credential
    assert req["headers"]["x-govpilot-run-kind"] == "delegation"
    assert req["headers"]["x-govpilot-parent-run-id"] == root.run_id and req["headers"]["x-govpilot-root-run-id"] == root.run_id
    assert got["run"].agent_id == "parent.analyst-" + mint["name"].split("-", 1)[1]
    assert "gpm1.parent.sig" not in str(req["headers"])
    assert sink.of("delegation.minted")[0]["child_agent_id"] == got["run"].agent_id


def test_child_credential_is_reused_until_it_expires_then_reminted(sink):
    now = [1000.0]
    fake = FakeGateway(clock=lambda: now[0])
    d = delegator(fake, sink, ttl_s=100, clock=lambda: now[0])
    root = RunContext.root("parent")
    f = lambda r, g: g.chat(r, "m", MSGS)      # noqa: E731
    d.delegate(root, "w", "t", f)
    d.delegate(root, "w", "t", f)
    assert len(fake.delegations) == 1
    now[0] += 200                               # past the 100 s lifetime
    d.delegate(root, "w", "t", f)
    assert len(fake.delegations) == 2
    tokens = [r["headers"]["authorization"] for r in fake.llm_requests()]
    assert tokens == ["Macaroon gpm1.child1.sig", "Macaroon gpm1.child1.sig", "Macaroon gpm1.child2.sig"]


def test_every_delegated_call_is_its_own_run_even_with_a_shared_child(sink):
    fake = FakeGateway()
    d = delegator(fake, sink)
    root = RunContext.root("parent")
    for _ in range(3):
        d.delegate(root, "w", "t", lambda r, g: g.chat(r, "m", MSGS))
    ids = [r["headers"]["x-govpilot-run-id"] for r in fake.llm_requests()]
    assert len(set(ids)) == 3 and {r["headers"]["x-govpilot-parent-run-id"] for r in fake.llm_requests()} == {root.run_id}


def test_broadening_is_denied_reported_and_never_uses_the_parents_credential(sink):
    fake = FakeGateway()
    fake.mint_deny = ["budget 5 exceeds parent's remaining delegable budget 0.2"]
    d = delegator(fake, sink, budget_usd=5.0)
    with pytest.raises(DelegationDenied) as ei:
        d.delegate(RunContext.root("parent"), "w", "t", lambda r, g: g.chat(r, "m", MSGS))
    assert "remaining delegable budget" in ei.value.reasons[0]
    assert sink.of("delegation.denied")[0]["http_status"] == 403 and not fake.llm_requests()


def test_a_retry_inside_delegation_keeps_the_delegation_run_id(sink):
    from fakes import err
    fake = FakeGateway()
    fake.fail_next = [err(503)]
    d = delegator(fake, sink)
    d.delegate(RunContext.root("parent"), "w", "t", lambda r, g: g.chat(r, "m", MSGS))
    a, b = fake.llm_requests()
    assert a["headers"]["x-govpilot-run-id"] == b["headers"]["x-govpilot-run-id"]
    assert (a["headers"]["x-govpilot-attempt"], b["headers"]["x-govpilot-attempt"]) == ("1", "2")
    assert a["headers"]["x-govpilot-parent-run-id"] == b["headers"]["x-govpilot-parent-run-id"]


def test_a_stopped_child_is_forgotten_so_the_next_delegation_mints_afresh(sink):
    from fakes import err
    fake = FakeGateway()
    d = delegator(fake, sink)
    fake.fail_next = [err(401, "auth_error", "key blocked"), err(401, "auth_error", "key blocked")]
    with pytest.raises(Exception):
        d.delegate(RunContext.root("parent"), "w", "t", lambda r, g: g.chat(r, "m", MSGS))
    d.delegate(RunContext.root("parent"), "w", "t", lambda r, g: g.chat(r, "m", MSGS))
    assert len(fake.delegations) == 2
