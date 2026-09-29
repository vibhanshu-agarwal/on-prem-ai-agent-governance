#!/usr/bin/env python3
"""Close the run tree: account for parent runs the gateway never saw, from the agents' run journal.

A child request names its parent run (`parent_run_id`). A parent that never made an LLM call of its own (a task
aborted because its first tool call was refused by a fail-closed control, a run killed mid-flight) has no gateway
row, so the link dangles in the spend log. That is not a spend hole (the child rows are attributed to an agent, a run
and a team), but a run tree that does not close is still a finding unless something explains it, and the gateway
cannot: only the agent knows its run existed and how it ended.

The agent library writes `run.start` / `run.end` (with the terminal state and, for a gateway refusal, the HTTP status
and error type) to a journal that outlives the container (govagent.events.JournalSink, volume govpilot_agent_journal).
`account_orphans` looks every dangling parent up there. A parent with no record, or a record of a different agent, or a
run that neither ended nor was interrupted, stays `unaccounted`; nothing is tolerated by count.

Trust note: the journal is the agent's own account. It explains a dangling link; it does not authenticate it. The
security property (every spend is attributed to a key, an agent and a team) comes from the gateway alone.

  python scripts/run_journal.py --since 30m          dangling parents in the window and what the journal says
  python scripts/run_journal.py --since 30m --json

Standard library only; needs Docker to read the journal volume (a sponsor with a log shipper feeds `account_orphans`
the same records instead).
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))
import attribution_report as AR  # noqa: E402

JOURNAL_VOLUME = "govpilot_agent_journal"
JOURNAL_IMAGE = "govpilot/agents:1"
_RUN_EVENTS = ("agent.start", "run.start", "run.end")


def parse_ts(ts: str | None) -> float | None:
    """ISO 8601 from a spend-log row -> epoch seconds (a naive timestamp is UTC)."""
    if not ts:
        return None
    try:
        d = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    return (d if d.tzinfo else d.replace(tzinfo=timezone.utc)).timestamp()


def _jsonl(text: str) -> list[dict]:
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except ValueError:
                pass
    return out


def read_journal_volume(volume: str = JOURNAL_VOLUME, image: str = JOURNAL_IMAGE, timeout: float = 90.0) -> list[dict]:
    """Every record of the durable run journal (a throwaway, network-less container reads the volume read-only)."""
    if subprocess.run(["docker", "volume", "inspect", volume], capture_output=True).returncode != 0:
        return []                          # never `docker run -v missing:` (it would create an empty root-owned volume)
    r = subprocess.run(["docker", "run", "--rm", "--network", "none", "--label", "govpilot.t8test=1", "-v",
                        f"{volume}:/j:ro", "--entrypoint", "sh", image, "-c", "cat /j/* 2>/dev/null; true"],
                       capture_output=True, text=True, errors="replace", timeout=timeout)
    return _jsonl(r.stdout)


def read_agent_container_logs(since_s: float) -> list[dict]:
    """Run-level events from `docker logs` of the agent containers that exist now: the fallback for runs made before
    the journal volume existed (a re-created container's logs are gone; that loss is why the journal exists)."""
    ps = subprocess.run(["docker", "ps", "-a", "--filter", "label=govpilot.agent_id", "--format", "{{.ID}}"],
                        capture_output=True, text=True)
    out: list[dict] = []
    for cid in ps.stdout.split():
        lg = subprocess.run(["docker", "logs", "--since", f"{int(since_s)}s", cid], capture_output=True, text=True,
                            errors="replace")
        for line in (lg.stdout + lg.stderr).splitlines():
            i = line.find("AGENT_EVENT ")
            if i < 0:
                continue
            try:
                ev = json.loads(line[i + len("AGENT_EVENT "):])
            except ValueError:
                continue
            if ev.get("event") in _RUN_EVENTS:
                out.append({"boot": f"log:{cid}", "source": "docker-logs", **ev})
    return out


def journal_records(since_s: float) -> list[dict]:
    """The journal volume plus, as a fallback, the logs of the agent containers that exist now."""
    return read_journal_volume() + read_agent_container_logs(since_s)


def same_agent(agent_id: str | None, row_agent: str | None) -> bool:
    """Does a gateway row's agent name belong to the agent `agent_id` of the journal? The gateway stamps the agent id
    from the key, except on rows refused during LiteLLM's own auth (budget exceeded...), which carry only the key
    alias; a rotated key's alias is `<agent>-<n>`, and a delegated child is `<agent>.<child>`."""
    if not agent_id or not row_agent:
        return False
    return row_agent == agent_id or row_agent.startswith(agent_id + ".") or re.fullmatch(re.escape(agent_id) + r"-\d+", row_agent) is not None


def orphan_parents(window_rows: list[dict], known_rows: list[dict]) -> dict[str, list[dict]]:
    """Parent run ids named by a row of the window that no row of `known_rows` (the window plus a lookback that covers
    parents which started just before it) carries as its own run id -> the window rows that name it."""
    known = {r["run_id"] for r in known_rows if r["run_id"]}
    out: dict[str, list[dict]] = {}
    for r in window_rows:
        p = r["parent_run_id"]
        if p and p not in known:
            out.setdefault(p, []).append(r)
    return out


def account_orphans(orphans: dict[str, list[dict]], records: Iterable[dict], *, now: float | None = None,
                    in_flight_s: float = 600.0) -> list[dict]:
    """One evidence record per dangling parent run id (-> the child rows that name it):

      state  ended_ok      the journal says the run ended fine, having made no LLM call of its own
             aborted       the run ended in error or was stopped; `cause` says why (e.g. "503 guardrail_unavailable"),
                           `kind` is fail_closed_refusal (a control refused it: guardrail, budget, stop, enforcement
                           unavailable), gateway_unavailable (5xx / unreachable) or agent_error
             interrupted   run.start but no run.end, and the agent process was replaced afterwards (killed)
             in_flight     run.start but no run.end yet, started less than `in_flight_s` ago
             unaccounted   anything else: no record at all, a record of another agent, a run that neither ended nor
                           was interrupted. The only state that is a finding.
    """
    now = time.time() if now is None else now
    starts: dict[str, dict] = {}
    ends: dict[str, dict] = {}
    agent_starts: dict[str, list[dict]] = collections.defaultdict(list)
    last_seen: dict[str, float] = {}                     # boot -> its latest record: a process that kept writing
    def keep(table: dict, r: dict) -> None:
        cur = table.get(r.get("run_id"))
        if cur is None or (cur.get("source") == "docker-logs" and r.get("source") != "docker-logs"):
            table[r.get("run_id")] = r          # the same run can be in both sources: the journal's record wins

    for r in sorted(records, key=lambda r: r.get("ts") or 0):
        if r.get("boot") is not None:
            last_seen[r["boot"]] = max(last_seen.get(r["boot"], 0), r.get("ts") or 0)
        ev = r.get("event")
        if ev == "run.start":
            keep(starts, r)
        elif ev == "run.end":
            keep(ends, r)
        elif ev == "agent.start":
            agent_starts[r.get("agent_id")].append(r)
    out = []
    for pid, children in sorted(orphans.items()):
        child_agents = sorted({c.get("agent") or "" for c in children} - {""})
        ev: dict[str, Any] = {"parent_run_id": pid, "children": len(children), "child_agents": child_agents,
                              "child_kinds": sorted({c.get("run_kind") or "?" for c in children}),
                              "failed_child_rows": sum(1 for c in children if c.get("status") != "success")}
        st, en = starts.get(pid), ends.get(pid)
        rec = st or en
        if rec is None:
            out.append({**ev, "state": "unaccounted", "reason": "no run record in the agent journal"})
            continue
        if child_agents and not all(same_agent(rec.get("agent_id"), a) for a in child_agents):
            out.append({**ev, "state": "unaccounted",
                        "reason": f"journal says agent {rec.get('agent_id')!r}, the gateway says {child_agents}"})
            continue
        ev.update(agent=rec.get("agent_id"), started=(st or {}).get("ts"), source=rec.get("source", "journal"))
        if en is not None:
            gw = en.get("gateway_error") or {}
            if en.get("status") == "ok":
                out.append({**ev, "state": "ended_ok", "ended": en.get("ts")})
                continue
            http = gw.get("http_status")
            m = re.match(r"^(\d{3}) (\S+?):", str(en.get("error") or ""))        # records without the structured field
            if http is None and m:
                http, gw = int(m.group(1)), {"etype": m.group(2)}
            if http in (401, 403, 429, 503):
                kind = "fail_closed_refusal"
            elif http is not None or gw:
                kind = "gateway_unavailable"
            else:
                kind = "agent_error"
            cause = f"{http} {gw.get('etype')}" if http is not None else str(en.get("error") or en.get("status"))[:80]
            out.append({**ev, "state": "aborted", "kind": kind, "cause": cause, "status": en.get("status"),
                        "ended": en.get("ts"), "refused_request_run": gw.get("request_run_id")})
            continue
        t0 = ev.get("started") or 0
        # replaced: another process of the same agent started after the run AND the run's own process wrote nothing
        # after that start (a second process running concurrently as the same agent, e.g. a live-test container, is
        # not a replacement: the original is still alive and its run is still open)
        replaced = st is not None and any(
            (a.get("ts") or 0) > t0 and a.get("boot") != st.get("boot")
            and last_seen.get(st.get("boot"), 0) <= (a.get("ts") or 0)
            for a in agent_starts.get(rec.get("agent_id"), []))
        if replaced:
            out.append({**ev, "state": "interrupted", "reason": "the agent process was replaced before the run ended"})
        elif now - t0 < in_flight_s:
            out.append({**ev, "state": "in_flight"})
        else:
            out.append({**ev, "state": "unaccounted",
                        "reason": f"run.start {round(now - t0)} s ago, no run.end and no restart of the agent"})
    return out


def summarise(evidence: list[dict]) -> dict:
    """Counts for a report: by state, and the causes of the aborted ones."""
    return {"by_state": dict(collections.Counter(e["state"] for e in evidence)),
            "aborted_causes": dict(collections.Counter(f"{e['cause']} ({e['kind']})" for e in evidence
                                                       if e["state"] == "aborted")),
            "unaccounted": [{k: e[k] for k in ("parent_run_id", "reason") if k in e}
                            for e in evidence if e["state"] == "unaccounted"]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", default="30m")
    ap.add_argument("--lookback", default="10m", help="extra time before the window in which a parent's own rows count")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--gateway", default=None)
    a = ap.parse_args(argv)
    env = AR._env()
    now = datetime.now(timezone.utc)
    win = AR.parse_duration(a.since)
    raw = AR.fetch_rows(a.gateway or env.get("GATEWAY_URL") or f"http://127.0.0.1:{env.get('GATEWAY_PORT', '4000')}",
                        env["LITELLM_MASTER_KEY"], now - win - AR.parse_duration(a.lookback), now + timedelta(minutes=1))
    rows = [AR.normalise(r) for r in raw]
    cut = (now - win).timestamp()
    window = [r for r in rows if (parse_ts(r["ts"]) or 0) >= cut]
    orphans = orphan_parents(window, rows)
    ev = account_orphans(orphans, journal_records(win.total_seconds() + AR.parse_duration(a.lookback).total_seconds() + 600))
    s = summarise(ev)
    if a.json:
        print(json.dumps({"window_requests": len(window), "dangling_parents": len(orphans), **s, "evidence": ev}, indent=2))
    else:
        print(f"{len(window)} requests in the window, {len(orphans)} dangling parent runs: {s['by_state']}")
        for e in ev:
            why = e.get("cause") or e.get("reason") or ""
            print(f"  {e['parent_run_id']}  {e['state']:<11}  {e.get('agent', '-'):<20} children={e['children']}  {why}")
    return 1 if s["unaccounted"] else 0


if __name__ == "__main__":
    sys.exit(main())
