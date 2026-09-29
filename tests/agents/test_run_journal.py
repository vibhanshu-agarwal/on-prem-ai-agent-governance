"""The durable run journal and the orphan-parent accounting built on it (offline; no Docker).

Why it exists: a parent run that never made an LLM call of its own (its first tool call was refused by a fail-closed
guardrail, or the process was killed) has no gateway row, so a child row's `parent_run_id` dangles in the spend log.
The gateway cannot explain that; the agent's own record of how the run ended can (scripts/run_journal.py, acceptance
test M-01). These tests pin what the agent writes and how each kind of dangling parent is classified.
"""
from __future__ import annotations

import json
import os

import pytest

from fakes import FakeGateway, err
from govagent import JournalSink, MemorySink, RunContext, TeeSink, default_sink
from govagent.events import error_fields
from govagent.gateway import GatewayError
from govagent.runtime import AgentRuntime
from samples.finance_agent import FinanceReconAgent

import run_journal as RJ

ENV = {"GATEWAY_URL": "http://sso-gateway:8080", "AUTH_MODE": "oidc", "IDP_TOKEN_URL": "http://idp:8300/token",
       "CLIENT_ID": "finance-recon-agent", "CLIENT_SECRET": "s", "AGENT_MAX_ITERATIONS": "1", "AGENT_RATES_FILE": "",
       "AGENT_MAX_ATTEMPTS": "1", "AGENT_RETRY_BASE_S": "0"}


def read(path):
    return [json.loads(l) for l in open(path, encoding="utf-8").read().splitlines()]


# ------------------------------------------------------------------ the sink
def test_journal_keeps_only_run_level_events_with_a_process_id(tmp_path):
    j = JournalSink(str(tmp_path), "a-agent")
    for ev in ("agent.start", "run.start", "llm.attempt", "run.end", "loop.settings", "tool.denied", "agent.stop"):
        j.emit({"event": ev, "agent_id": "a-agent", "run_id": "run-abcdef12"})
    got = read(j.path)
    assert [e["event"] for e in got] == ["agent.start", "run.start", "run.end", "agent.stop"]
    assert len({e["boot"] for e in got}) == 1 and all("ts" in e for e in got)
    assert os.path.basename(j.path) == "a-agent.jsonl"


def test_two_processes_have_different_boot_ids(tmp_path):
    assert JournalSink(str(tmp_path), "a").boot != JournalSink(str(tmp_path), "a").boot


def test_journal_rotates_one_generation_and_keeps_appending(tmp_path):
    j = JournalSink(str(tmp_path), "a-agent", max_bytes=600)
    for i in range(30):
        j.emit({"event": "run.end", "agent_id": "a-agent", "run_id": f"run-{i:012d}", "status": "ok"})
    assert os.path.exists(j.path + ".1") and os.path.getsize(j.path) <= 600
    assert read(j.path)[-1]["run_id"] == "run-000000000029"


def test_an_unwritable_journal_never_breaks_the_agent(tmp_path, capsys):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("x")
    j = JournalSink(str(blocker), "a-agent")
    j.emit({"event": "run.start", "agent_id": "a-agent", "run_id": "run-abcdef12"})       # must not raise
    j.emit({"event": "run.end", "agent_id": "a-agent", "run_id": "run-abcdef12"})
    assert j.errors == 2 and capsys.readouterr().err.count("AGENT_JOURNAL_ERROR") == 1     # reported once


def test_tee_sink_isolates_a_failing_sink():
    class Boom:
        def emit(self, e):
            raise RuntimeError("down")
    mem = MemorySink()
    TeeSink(Boom(), mem).emit({"event": "run.start"})
    assert len(mem.events) == 1


def test_default_sink_adds_the_journal_only_when_configured(tmp_path):
    assert type(default_sink({}, "a-agent")).__name__ == "StdoutSink"
    s = default_sink({"AGENT_JOURNAL_DIR": str(tmp_path)}, "a-agent")
    assert isinstance(s, TeeSink) and any(isinstance(x, JournalSink) for x in s.sinks)


def test_processes_running_as_the_same_agent_can_journal_to_files_of_their_own(tmp_path):
    """A test container runs real agent code under a pilot identity: same agent id in the records, its own file."""
    s = default_sink({"AGENT_JOURNAL_DIR": str(tmp_path), "AGENT_JOURNAL_NAME": "t4-coding-agent-abc123"}, "coding-agent")
    s.emit({"event": "run.start", "agent_id": "coding-agent", "run_id": "run-abcdef12"})
    assert [p.name for p in tmp_path.iterdir()] == ["t4-coding-agent-abc123.jsonl"]
    assert read(tmp_path / "t4-coding-agent-abc123.jsonl")[0]["agent_id"] == "coding-agent"


def test_error_fields_carry_the_gateway_refusal_when_there_is_one():
    e = GatewayError("nope", status=503, etype="guardrail_unavailable", run_id="run-abcdef12", attempts=2)
    f = error_fields(e)
    assert f["gateway_error"] == {"http_status": 503, "etype": "guardrail_unavailable", "request_run_id": "run-abcdef12",
                                  "attempts": 2}
    assert "gateway_error" not in error_fields(ValueError("bug"))


# ------------------------------------------------------------------ what a refused run writes
def test_a_task_aborted_by_a_fail_closed_refusal_records_its_terminal_state(tmp_path):
    """The finance agent's first tool call gets a guardrail 503: the task never makes its own LLM call (so no gateway
    row exists for it) but the journal holds run.start + run.end(error, 503 guardrail_unavailable, which request)."""
    fake = FakeGateway()
    fake.fail_next = [err(503, "guardrail_unavailable", "PII engine unavailable, fail-closed")] * 5
    sink = default_sink({"AGENT_JOURNAL_DIR": str(tmp_path)}, "finance-recon-agent")
    agent = FinanceReconAgent(ENV, sink=sink, transport=fake)
    agent.runtime.sink = sink
    agent.runtime.run(agent.work)
    recs = read(tmp_path / "finance-recon-agent.jsonl")
    ends = [r for r in recs if r["event"] == "run.end"]
    task_end = next(r for r in ends if r["run_kind"] == "task")
    tool_end = next(r for r in ends if r.get("tool") == "classify_exception")
    assert task_end["status"] == "error" and task_end["gateway_error"]["http_status"] == 503
    assert task_end["gateway_error"]["etype"] == "guardrail_unavailable"
    assert task_end["gateway_error"]["request_run_id"] == tool_end["run_id"]          # names the refused request's run
    assert tool_end["parent_run_id"] == task_end["run_id"]
    # and the gateway saw only the tool run's request: the parent has no row of its own
    assert {r["headers"]["x-govpilot-run-id"] for r in fake.llm_requests()} == {tool_end["run_id"]}


def test_a_stopped_agent_records_status_stopped(tmp_path):
    sink = MemorySink()
    rt = AgentRuntime("a-agent", sink, rates_path="", env={"AGENT_MAX_ITERATIONS": "1"}, sleep=lambda s: None)
    rt.run(lambda run: (_ for _ in ()).throw(GatewayError("blocked", status=401, etype="auth_error", run_id=run.run_id, attempts=1)))
    (end,) = sink.of("run.end")
    assert end["status"] == "stopped" and end["gateway_error"]["http_status"] == 401


# ------------------------------------------------------------------ orphan accounting
NOW = 1_000_000.0


def child(agent="finance-recon-agent", status="failure", kind="tool"):
    return {"agent": agent, "status": status, "run_kind": kind}


def rec(event, run_id, ts, agent="finance-recon-agent", boot="b1", **kw):
    return {"event": event, "run_id": run_id, "ts": ts, "agent_id": agent, "boot": boot, **kw}


def account(orphans, records, **kw):
    return {e["parent_run_id"]: e for e in RJ.account_orphans(orphans, records, now=NOW, **kw)}


def test_orphan_parents_are_parents_named_in_the_window_that_no_known_row_owns():
    rows = [{"run_id": "run-a", "parent_run_id": None}, {"run_id": "run-b", "parent_run_id": "run-a"},
            {"run_id": "run-c", "parent_run_id": "run-gone"}, {"run_id": None, "parent_run_id": None}]
    early = [{"run_id": "run-gone", "parent_run_id": None}]                       # started before the window
    assert list(RJ.orphan_parents(rows, rows)) == ["run-gone"]
    assert RJ.orphan_parents(rows, rows + early) == {}


def test_each_kind_of_dangling_parent_is_classified_from_the_journal():
    orphans = {p: [child()] for p in ("refused", "bad-gw", "bug", "fine", "killed", "running", "unknown")}
    orphans["stuck"] = [child(agent="hr-agent")]
    records = [
        rec("agent.start", "-", NOW - 900, boot="b1"), rec("agent.start", "-", NOW - 400, boot="b2"),
        rec("agent.start", "-", NOW - 3100, agent="hr-agent", boot="h1"),
        rec("run.start", "refused", NOW - 800), rec("run.end", "refused", NOW - 799, status="error",
            gateway_error={"http_status": 503, "etype": "guardrail_unavailable", "request_run_id": "rq"}),
        rec("run.start", "bad-gw", NOW - 800), rec("run.end", "bad-gw", NOW - 799, status="error",
            gateway_error={"http_status": 502, "etype": "gateway_error"}),
        rec("run.start", "bug", NOW - 800), rec("run.end", "bug", NOW - 799, status="error", error="KeyError: 'x'"),
        rec("run.start", "fine", NOW - 800), rec("run.end", "fine", NOW - 799, status="ok"),
        rec("run.start", "killed", NOW - 800),                                        # b1 replaced by b2 at NOW-400
        rec("run.start", "running", NOW - 30, boot="b2"),
        rec("run.start", "stuck", NOW - 3000, agent="hr-agent", boot="h1"),
    ]
    got = account(orphans, records)
    assert got["refused"]["state"] == "aborted" and got["refused"]["kind"] == "fail_closed_refusal"
    assert got["refused"]["cause"] == "503 guardrail_unavailable" and got["refused"]["refused_request_run"] == "rq"
    assert got["bad-gw"]["kind"] == "gateway_unavailable" and got["bug"]["kind"] == "agent_error"
    assert got["fine"]["state"] == "ended_ok"
    assert got["killed"]["state"] == "interrupted"
    assert got["running"]["state"] == "in_flight"
    assert got["stuck"]["state"] == "unaccounted" and "no run.end" in got["stuck"]["reason"]
    assert got["unknown"]["state"] == "unaccounted" and "no run record" in got["unknown"]["reason"]


def test_records_without_the_structured_field_are_read_from_the_error_text():
    got = account({"old": [child()]}, [rec("run.start", "old", NOW - 9), rec("run.end", "old", NOW - 8, status="error",
                  error="503 guardrail_unavailable: gateway returned 503: PII guardrail engine unavailable")])
    assert got["old"]["cause"] == "503 guardrail_unavailable" and got["old"]["kind"] == "fail_closed_refusal"


def test_a_journal_record_of_another_agent_does_not_account_for_the_parent():
    got = account({"p": [child(agent="finance-recon-agent.variance-1")]}, [
        rec("run.start", "p", NOW - 9, agent="hr-agent"), rec("run.end", "p", NOW - 8, agent="hr-agent", status="ok")])
    assert got["p"]["state"] == "unaccounted" and "hr-agent" in got["p"]["reason"]
    ok = account({"p": [child(agent="finance-recon-agent.variance-1")]}, [
        rec("run.start", "p", NOW - 9), rec("run.end", "p", NOW - 8, status="ok")])
    assert ok["p"]["state"] == "ended_ok"                        # a delegated child agent is matched by its root agent


def test_when_a_run_is_in_both_the_journal_and_the_container_logs_the_journal_record_wins():
    logs = rec("run.start", "p", NOW - 9, boot="log:abc", source="docker-logs")
    journal = rec("run.start", "p", NOW - 9)
    for order in ([logs, journal], [journal, logs]):
        got = account({"p": [child()]}, order + [rec("run.end", "p", NOW - 8, status="ok")])
        assert got["p"]["state"] == "ended_ok" and got["p"]["source"] == "journal"


def test_rotated_key_aliases_and_delegated_children_belong_to_their_agent():
    S = RJ.same_agent
    assert S("finance-recon-agent", "finance-recon-agent") and S("finance-recon-agent", "finance-recon-agent-2")
    assert S("finance-recon-agent", "finance-recon-agent.variance-analyst-1790709131")
    assert not S("finance-recon-agent", "finance-recon-agent-x") and not S("hr-agent", "finance-recon-agent-2")
    assert not S("finance", "finance-recon-agent") and not S(None, "a") and not S("a", None)


def test_a_process_that_started_after_the_run_does_not_make_it_interrupted_unless_it_is_a_different_process():
    # same process' own agent.start precedes its runs; a run without run.end in a still-running process is not "interrupted"
    got = account({"p": [child()]}, [rec("agent.start", "-", NOW - 900, boot="b1"), rec("run.start", "p", NOW - 800, boot="b1")])
    assert got["p"]["state"] == "unaccounted"


def test_summary_counts_and_lists_only_the_unaccounted():
    ev = RJ.account_orphans({"a": [child()], "b": [child()], "c": [child()]}, [
        rec("run.start", "a", NOW - 9), rec("run.end", "a", NOW - 8, status="error",
                                            gateway_error={"http_status": 503, "etype": "guardrail_unavailable"}),
        rec("run.start", "b", NOW - 9), rec("run.end", "b", NOW - 8, status="error",
                                            gateway_error={"http_status": 503, "etype": "guardrail_unavailable"})], now=NOW)
    s = RJ.summarise(ev)
    assert s["by_state"] == {"aborted": 2, "unaccounted": 1}
    assert s["aborted_causes"] == {"503 guardrail_unavailable (fail_closed_refusal)": 2}
    assert [u["parent_run_id"] for u in s["unaccounted"]] == ["c"]


def test_spend_log_timestamps_parse_with_and_without_a_zone():
    assert RJ.parse_ts("2026-09-29T19:22:19.500Z") == RJ.parse_ts("2026-09-29T19:22:19.500+00:00") == RJ.parse_ts("2026-09-29T19:22:19.500")
    assert RJ.parse_ts(None) is None and RJ.parse_ts("garbage") is None
