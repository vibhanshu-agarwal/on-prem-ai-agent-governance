"""Contract: how run ids are generated and how they travel (agent side), and that the gateway callback
accepts exactly what the agent library sends (same headers, same validation rules)."""
from __future__ import annotations

import asyncio
import json
import re

import pytest

from govagent import RunContext, new_run_id
from govagent.context import RUN_ID_RE


# ------------------------------------------------------------------ generation
def test_run_ids_are_unique_and_valid():
    ids = {new_run_id() for _ in range(5000)}
    assert len(ids) == 5000
    assert all(RUN_ID_RE.match(i) for i in ids)


def test_root_run_is_its_own_root_and_has_no_parent():
    r = RunContext.root("hr-agent", user="E1001")
    assert r.root_run_id == r.run_id and r.parent_run_id is None and r.kind == "task" and r.attempt == 1


def test_child_run_gets_new_id_and_points_at_parent():
    root = RunContext.root("hr-agent", user="E1001")
    tool = root.child("tool", "tool:x", tool="x")
    deleg = root.child("delegation", "d", agent_id="hr-agent.kid")
    grandchild = tool.child("tool", "tool:y", tool="y")
    for c in (tool, deleg, grandchild):
        assert c.run_id != root.run_id
        assert c.root_run_id == root.run_id and c.user == "E1001"
    assert tool.parent_run_id == root.run_id and deleg.parent_run_id == root.run_id
    assert grandchild.parent_run_id == tool.run_id
    assert deleg.agent_id == "hr-agent.kid" and tool.agent_id == "hr-agent"


def test_retry_keeps_run_and_parent_and_only_bumps_attempt():
    root = RunContext.root("a-agent")
    child = root.child("tool", "t", tool="t")
    again = child.with_attempt(3)
    assert (again.run_id, again.parent_run_id, again.root_run_id) == (child.run_id, child.parent_run_id, child.root_run_id)
    assert again.attempt == 3 and child.attempt == 1


@pytest.mark.parametrize("bad", ["", "short", "has space in it", "-leadingdash1", "x" * 81, "run/with/slash"])
def test_malformed_run_ids_are_refused_at_construction(bad):
    with pytest.raises(ValueError):
        RunContext(agent_id="a", run_id=bad, root_run_id="run-abcdef12")


def test_a_run_cannot_be_its_own_parent_and_kind_is_checked():
    with pytest.raises(ValueError):
        RunContext(agent_id="a", run_id="run-abcdef12", root_run_id="run-abcdef12", parent_run_id="run-abcdef12")
    with pytest.raises(ValueError):
        RunContext(agent_id="a", run_id="run-abcdef12", root_run_id="run-abcdef12", kind="bogus")


# ------------------------------------------------------------------ propagation
def test_headers_carry_every_field_two_ways():
    root = RunContext.root("hr-agent", user="E1004")
    c = root.child("tool", "tool:lookup", tool="lookup").with_attempt(2)
    h = c.headers()
    assert h["x-govpilot-run-id"] == c.run_id and h["x-govpilot-parent-run-id"] == root.run_id
    assert h["x-govpilot-root-run-id"] == root.run_id and h["x-govpilot-run-kind"] == "tool"
    assert h["x-govpilot-attempt"] == "2" and h["x-govpilot-tool"] == "lookup" and h["x-govpilot-user"] == "E1004"
    meta = json.loads(h["x-litellm-spend-logs-metadata"])          # LiteLLM's own carrier: works without our callback
    assert meta["run_id"] == c.run_id and meta["parent_run_id"] == root.run_id and meta["attempt"] == 2
    assert meta["run_kind"] == "tool" and meta["tool"] == "lookup" and meta["user"] == "E1004"


def test_root_run_sends_no_parent_header():
    h = RunContext.root("a-agent").headers()
    assert "x-govpilot-parent-run-id" not in h
    assert "parent_run_id" not in json.loads(h["x-litellm-spend-logs-metadata"])


def test_traceparent_is_w3c_shaped_and_stable_across_the_tree():
    root = RunContext.root("a-agent")
    a, b = root.child("tool", "a", tool="a"), root.child("tool", "b", tool="b")
    tp = lambda r: re.fullmatch(r"00-([0-9a-f]{32})-([0-9a-f]{16})-01", r.traceparent())     # noqa: E731
    assert tp(root) and tp(a) and tp(b)
    assert tp(a).group(1) == tp(b).group(1) == tp(root).group(1)          # one trace per run tree
    assert len({tp(root).group(2), tp(a).group(2), tp(b).group(2)}) == 3   # one span per run


# ------------------------------------------------------------------ agent library <-> gateway callback
def _req(headers, body=None):
    return {"proxy_server_request": {"headers": headers}, "metadata": {}, **(body or {})}


def test_callback_parses_exactly_what_the_library_sends(callback):
    root = RunContext.root("hr-agent", user="E1001")
    c = root.child("tool", "tool:x", tool="x").with_attempt(2)
    rf, extra = callback.parse_run_fields(_req(c.headers()))
    assert rf.problems == []
    assert (rf.run_id, rf.parent_run_id, rf.root_run_id, rf.kind, rf.attempt, rf.tool, rf.user) == \
           (c.run_id, root.run_id, root.run_id, "tool", 2, "x", "E1001")
    assert "agent_run_name" in extra          # unknown client keys are kept, reserved ones are not


def test_callback_accepts_the_litellm_metadata_header_alone(callback):
    c = RunContext.root("a-agent")
    only_meta = {"x-litellm-spend-logs-metadata": c.headers()["x-litellm-spend-logs-metadata"]}
    rf, _ = callback.parse_run_fields(_req(only_meta))
    assert rf.run_id == c.run_id and rf.problems == []


def test_callback_and_library_agree_on_the_run_id_grammar(callback):
    assert callback.RUN_ID_RE.pattern == RUN_ID_RE.pattern
    assert set(callback.KINDS) == {"task", "tool", "delegation"}


@pytest.mark.parametrize("headers,needle", [
    ({}, "missing run id"),
    ({"x-govpilot-run-id": "bad id"}, "must match"),
    ({"x-govpilot-run-id": "run-abcdef12", "x-govpilot-attempt": "zero"}, "attempt"),
    ({"x-govpilot-run-id": "run-abcdef12", "x-govpilot-run-kind": "tool"}, "needs a parent"),
    ({"x-govpilot-run-id": "run-abcdef12", "x-govpilot-parent-run-id": "run-abcdef12"}, "own parent"),
])
def test_callback_flags_bad_run_fields(callback, headers, needle):
    rf, _ = callback.parse_run_fields(_req(headers))
    assert any(needle in p for p in rf.problems), rf.problems


class _Key:
    def __init__(self, md=None, team_md=None, alias="hr-agent", team="hr"):
        self.metadata, self.team_metadata, self.key_alias, self.team_alias, self.team_id = md or {}, team_md or {}, alias, team, "tid"


def _pre(cb, key, data, call_type="acompletion"):
    return asyncio.run(cb.async_pre_call_hook(key, None, data, call_type))


def test_enforce_rejects_missing_run_id_with_400(callback):
    cb = callback.RunAttribution(sink=type("S", (), {"emit": lambda s, e: events.append(e)})())
    events: list[dict] = []
    key = _Key({"agent_id": "hr-agent", "attribution": {"mode": "enforce"}})
    with pytest.raises(Exception) as ei:
        _pre(cb, key, _req({}, {"model": "mock-local"}))
    assert getattr(ei.value, "code", None) in (400, "400") or "400" in repr(ei.value)
    assert events and events[0]["event"] == "attribution.rejected" and events[0]["agent_id"] == "hr-agent"


def test_audit_mode_lets_it_through_but_marks_and_reports_it(callback):
    events: list[dict] = []
    cb = callback.RunAttribution(sink=type("S", (), {"emit": lambda s, e: events.append(e)})(), default_mode="audit")
    data = _pre(cb, _Key({"agent_id": "x-agent"}), _req({}, {"model": "mock-local"}))
    assert data["metadata"]["spend_logs_metadata"]["attribution"] == "missing_run_id"
    assert events[0]["event"] == "attribution.missing_run_id"


def test_policy_precedence_key_over_team_over_env(callback):
    r = callback.resolve_mode
    assert r(_Key(md={"attribution": {"mode": "enforce"}}, team_md={"attribution": {"mode": "off"}}), "audit") == "enforce"
    assert r(_Key(team_md={"attribution": {"mode": "off"}}), "audit") == "off"
    assert r(_Key(), "audit") == "audit"
    assert r(_Key(md={"attribution": {"mode": "nonsense"}}), "audit") == "audit"


def test_identity_is_stamped_from_the_key_never_from_the_request(callback):
    cb = callback.RunAttribution(sink=type("S", (), {"emit": lambda s, e: None})())
    c = RunContext.root("liar")
    forged = dict(c.headers())
    forged["x-litellm-spend-logs-metadata"] = json.dumps({**json.loads(forged["x-litellm-spend-logs-metadata"]),
                                                          "agent_id": "finance-recon-agent", "team": "finance"})
    data = _pre(cb, _Key({"agent_id": "hr-agent", "attribution": {"mode": "enforce"}}), _req(forged, {"model": "m"}))
    sl = data["metadata"]["spend_logs_metadata"]
    assert sl["agent_id"] == "hr-agent" and sl["team"] == "hr" and sl["run_id"] == c.run_id
    assert data["litellm_session_id"] == c.run_id


def test_delegated_child_key_identity_carries_lineage(callback):
    cb = callback.RunAttribution(sink=type("S", (), {"emit": lambda s, e: None})())
    parent = RunContext.root("p")
    child = parent.child("delegation", "d", agent_id="p.kid")
    key = _Key({"agent_id": "p.kid", "root_agent_id": "p", "parent_agent_id": "p"}, alias="p.kid")
    sl = _pre(cb, key, _req(child.headers(), {"model": "m"}))["metadata"]["spend_logs_metadata"]
    assert (sl["agent_id"], sl["root_agent_id"], sl["parent_agent_id"]) == ("p.kid", "p", "p")
    assert sl["run_kind"] == "delegation" and sl["parent_run_id"] == parent.run_id


def test_non_llm_call_types_are_left_alone(callback):
    cb = callback.RunAttribution(sink=type("S", (), {"emit": lambda s, e: None})())
    data = {"metadata": {}}
    assert _pre(cb, _Key({"attribution": {"mode": "enforce"}}), data, "list_models") is data
    assert "spend_logs_metadata" not in data["metadata"]


def test_response_headers_echo_run_and_agent(callback):
    cb = callback.RunAttribution(sink=type("S", (), {"emit": lambda s, e: None})())
    c = RunContext.root("hr-agent").with_attempt(3)
    data = _pre(cb, _Key({"agent_id": "hr-agent"}), _req(c.headers(), {"model": "m"}))
    h = asyncio.run(cb.async_post_call_response_headers_hook(data, _Key(), None))
    assert h == {"x-govpilot-run-id": c.run_id, "x-govpilot-attribution": "ok", "x-govpilot-attempt": "3",
                 "x-govpilot-agent": "hr-agent"}
