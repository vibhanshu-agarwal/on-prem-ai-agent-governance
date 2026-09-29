"""Loop rate is configuration: env < rates file default < rates file agent entry, live-reloaded."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from fakes import FakeGateway, err
from govagent import MemorySink
from govagent.runtime import AgentRuntime, LoopSettings, RatesFile, env_layer

ROOT = Path(__file__).resolve().parents[2]


def write(p: Path, d: dict):
    p.write_text(json.dumps(d))
    st = p.stat()
    os.utime(p, (st.st_atime, st.st_mtime + 1))            # make the reload detectable within the same second


def test_layering_env_then_file_default_then_agent(tmp_path):
    f = tmp_path / "rates.json"
    write(f, {"default": {"interval_s": 7, "concurrency": 2}, "a-agent": {"interval_s": 3}})
    rt = AgentRuntime("a-agent", MemorySink(), rates_path=str(f), env={"AGENT_INTERVAL_S": "99", "AGENT_MAX_TOKENS": "50"})
    s = rt.settings()
    assert (s.interval_s, s.concurrency, s.max_tokens) == (3.0, 2, 50)
    other = AgentRuntime("b-agent", MemorySink(), rates_path=str(f), env={})
    assert other.settings().interval_s == 7.0


def test_running_agent_picks_up_a_changed_rate_without_restart(tmp_path):
    f = tmp_path / "rates.json"
    write(f, {"a-agent": {"interval_s": 10}})
    rt = AgentRuntime("a-agent", MemorySink(), rates_path=str(f), env={})
    assert rt.settings().interval_s == 10
    write(f, {"a-agent": {"interval_s": 0.05, "concurrency": 4, "profile": "rogue", "on_budget_exceeded": "hammer"}})
    s = rt.settings()
    assert (s.interval_s, s.concurrency, s.profile, s.on_budget_exceeded) == (0.05, 4, "rogue", "hammer")


def test_a_half_written_or_missing_file_keeps_the_last_good_settings(tmp_path):
    f = tmp_path / "rates.json"
    write(f, {"a-agent": {"interval_s": 4}})
    rt = AgentRuntime("a-agent", MemorySink(), rates_path=str(f), env={})
    assert rt.settings().interval_s == 4
    f.write_text("{ not json")
    os.utime(f, (time.time() + 5, time.time() + 5))
    assert rt.settings().interval_s == 4
    f.unlink()
    assert rt.settings().interval_s == 4
    assert AgentRuntime("a", MemorySink(), rates_path=str(tmp_path / "nope.json"), env={}).settings().interval_s == 10


def test_bool_and_type_coercion():
    s = LoopSettings.merge({"paused": "true", "concurrency": "3", "interval_s": "0.5"}, {"max_tokens": None})
    assert s.paused is True and s.concurrency == 3 and s.interval_s == 0.5 and s.max_tokens is None
    assert env_layer({"AGENT_INTERVAL_S": "2", "OTHER": "x"}) == {"interval_s": "2"}


def test_loop_runs_at_the_configured_concurrency_and_stops_at_max_iterations(tmp_path):
    f = tmp_path / "rates.json"
    write(f, {"a-agent": {"interval_s": 0, "jitter": 0, "concurrency": 3}})
    sink = MemorySink()
    calls = []
    rt = AgentRuntime("a-agent", sink, rates_path=str(f), env={"AGENT_MAX_ITERATIONS": "7"}, sleep=lambda s: None)
    rt.run(lambda run: calls.append(run.run_id))
    assert len(calls) == 7 and len(set(calls)) == 7
    ends = sink.of("run.end")
    assert len(ends) == 7 and all(e["status"] == "ok" and e["parent_run_id"] is None for e in ends)
    assert sink.of("agent.stop")[0]["iterations"] == 7


def test_a_sleeping_agent_wakes_when_the_rates_file_changes_and_on_stop(tmp_path):
    import threading
    f = tmp_path / "rates.json"
    write(f, {"a-agent": {"interval_s": 300}})
    rt = AgentRuntime("a-agent", MemorySink(), rates_path=str(f), env={})
    rt.settings()                                           # reads the file (mtime remembered)
    done = threading.Event()
    threading.Thread(target=lambda: (rt._nap(60), done.set()), daemon=True).start()
    assert not done.wait(1.0), "must keep sleeping while nothing changes"
    write(f, {"a-agent": {"interval_s": 0.05, "concurrency": 8}})
    assert done.wait(3.0), "a changed rates file must end the nap"
    done.clear()
    rt.settings()
    threading.Thread(target=lambda: (rt._nap(60), done.set()), daemon=True).start()
    rt.stop_evt.set()
    assert done.wait(3.0), "a stop signal must end the nap"


def test_a_rates_file_that_stays_broken_does_not_turn_the_loop_into_a_busy_loop(tmp_path):
    import threading
    f = tmp_path / "rates.json"
    write(f, {"a-agent": {"interval_s": 300}})
    rt = AgentRuntime("a-agent", MemorySink(), rates_path=str(f), env={})
    rt.settings()
    f.write_text("{ not json")                              # half-written / broken and it stays that way
    st = f.stat()
    os.utime(f, (st.st_atime, st.st_mtime + 2))
    rt._nap(0.2)                                            # wakes once for the change ...
    done = threading.Event()
    threading.Thread(target=lambda: (rt._nap(60), done.set()), daemon=True).start()
    assert not done.wait(1.5), "... but the next nap sleeps normally (the file is unchanged since it started)"
    rt.stop_evt.set()


def test_paused_agent_does_not_work(tmp_path):
    f = tmp_path / "rates.json"
    write(f, {"a-agent": {"paused": True}})
    rt = AgentRuntime("a-agent", MemorySink(), rates_path=str(f), env={})
    n = []
    rt.sleep = lambda s: rt.stop_evt.set()
    rt.run(lambda run: n.append(1))
    assert n == []


def _refusing_work(exc):
    def work(run):
        raise exc
    return work


def test_budget_refusal_makes_a_polite_agent_back_off_but_a_rogue_one_hammer(tmp_path):
    from govagent import GatewayError
    refusal = GatewayError("budget", status=429, etype="budget_exceeded", run_id="run-abcdef12", attempts=1)
    for mode, expect_backoff in (("backoff", True), ("hammer", False)):
        f = tmp_path / f"{mode}.json"
        write(f, {"a-agent": {"interval_s": 0.01, "jitter": 0, "on_budget_exceeded": mode}})
        sleeps: list[float] = []
        rt = AgentRuntime("a-agent", MemorySink(), rates_path=str(f), env={"AGENT_MAX_ITERATIONS": "4"}, sleep=sleeps.append)
        rt.run(_refusing_work(refusal))
        assert (max(sleeps) > 1) is expect_backoff, (mode, sleeps)
        assert rt.failures == 4


def test_an_agent_loop_survives_its_own_exceptions_and_reports_them(tmp_path):
    sink = MemorySink()
    rt = AgentRuntime("a-agent", sink, rates_path="", env={"AGENT_MAX_ITERATIONS": "2", "AGENT_INTERVAL_S": "0"},
                      sleep=lambda s: None)
    rt.run(_refusing_work(RuntimeError("bug")))
    assert [e["status"] for e in sink.of("run.end")] == ["error", "error"] and "bug" in sink.of("run.end")[0]["error"]


def test_stop_flag_ends_the_loop_gracefully(tmp_path):
    rt = AgentRuntime("a-agent", MemorySink(), rates_path="", env={"AGENT_INTERVAL_S": "0"}, sleep=lambda s: None)
    n = []

    def work(run):
        n.append(1)
        if len(n) == 3:
            rt.stop_evt.set()
    rt.run(work)
    assert len(n) == 3


# ------------------------------------------------------------------ the operator CLI
def ctl(tmp_path, *args):
    env = {**os.environ, "AGENT_RATES_FILE": str(tmp_path / "rates.json")}
    return subprocess.run([sys.executable, str(ROOT / "scripts" / "agents_ctl.py"), *args], capture_output=True, text=True,
                          env=env, timeout=30)


def test_ctl_rogue_and_calm_round_trip_restores_the_base_rate(tmp_path):
    f = tmp_path / "rates.json"
    base = {"default": {"interval_s": 10}, "fin": {"interval_s": 12}}
    f.write_text(json.dumps(base))
    assert ctl(tmp_path, "rogue", "fin", "--max-tokens", "300").returncode == 0
    d = json.loads(f.read_text())
    assert d["fin"]["interval_s"] == 0.05 and d["fin"]["concurrency"] == 4 and d["fin"]["max_tokens"] == 300
    assert d["fin"]["on_budget_exceeded"] == "hammer" and d["fin"]["profile"] == "rogue"
    rt = AgentRuntime("fin", MemorySink(), rates_path=str(f), env={})
    assert rt.settings().profile == "rogue"
    assert ctl(tmp_path, "calm", "fin").returncode == 0
    d = json.loads(f.read_text())
    assert d["fin"] == {"interval_s": 12} and "fin@base" not in d
    assert ctl(tmp_path, "pause", "fin").returncode == 0 and json.loads(f.read_text())["fin"]["paused"] is True
    assert ctl(tmp_path, "resume", "fin").returncode == 0 and "paused" not in json.loads(f.read_text())["fin"]
    assert ctl(tmp_path, "set", "fin", "interval_s=2", "concurrency=2").returncode == 0
    assert json.loads(f.read_text())["fin"]["concurrency"] == 2
    assert "fin" in ctl(tmp_path, "status").stdout


def test_shipped_rates_file_is_valid_and_names_the_three_agents():
    d = json.loads((ROOT / "deploy" / "agents" / "config" / "rates.json").read_text())
    assert {"hr-agent", "finance-recon-agent", "coding-agent"} <= set(d)
    rf = RatesFile(str(ROOT / "deploy" / "agents" / "config" / "rates.json"))
    assert rf.get("hr-agent")["interval_s"] == 8
