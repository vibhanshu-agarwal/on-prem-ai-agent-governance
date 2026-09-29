#!/usr/bin/env python3
"""Who spent what, on whose behalf: query the gateway's spend logs by agent / run / parent run / user / team /
provider / model, including retries, tool calls and delegation. Standard library only.

  python scripts/attribution_report.py --since 30m                    summary per agent + completeness
  python scripts/attribution_report.py --since 30m --by model         group by agent|team|user|provider|model|run|root|kind
  python scripts/attribution_report.py --since 1h --tree              run trees (root -> tool/delegation runs) with cost roll-up
  python scripts/attribution_report.py --run run-0123456789abcdef     one run tree (any run id in it)
  python scripts/attribution_report.py --since 1h --rows --agent hr-agent
  python scripts/attribution_report.py --since 10m --check            exit 1 if any spending request is unattributed
  python scripts/attribution_report.py --json ...                     machine readable

Source: the gateway admin API (GET /spend/logs/v2, master key). Env: GATEWAY_URL (default
http://127.0.0.1:4000), LITELLM_MASTER_KEY (or deploy/.env). `--from-json FILE` reads rows saved earlier,
so a sponsor with another gateway only has to produce the same normalised rows (see `normalise`).

Row meaning. LiteLLM writes one spend-log row per gateway request, success or failure. The gateway
callback (deploy/litellm/callbacks/run_attribution.py) stamps `metadata.spend_logs_metadata` with the
trusted agent/team (from the virtual key) and the run fields the agent sent. A retry is a new row with
the SAME run_id, the same step and attempt = n; failed attempts (provider errors, budget refusals, guardrail blocks)
are rows too, with status=failure and their error text. A request refused for lacking a run id is a
row with no run_id: it cost nothing and is reported as `rejected`, not as a hole.

A child row can name a parent run that has no row of its own (a task aborted before its own first LLM call). The
gateway cannot explain that; the agents' run journal can: `python scripts/run_journal.py --since 30m`.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------- source
def _env() -> dict[str, str]:
    env = dict(os.environ)
    p = ROOT / "deploy" / ".env"
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                env.setdefault(k.strip(), v.strip())
    return env


def parse_duration(s: str) -> timedelta:
    m = re.fullmatch(r"(\d+)([smhd])", s.strip())
    if not m:
        raise SystemExit(f"bad duration {s!r} (use 30s, 15m, 2h, 1d)")
    return timedelta(**{{"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}[m.group(2)]: int(m.group(1))})


def fetch_rows(gateway: str, master_key: str, start: datetime, end: datetime, page_size: int = 200,
               timeout: float = 60.0) -> list[dict]:
    rows: list[dict] = []
    page = 1
    while True:
        q = urllib.parse.urlencode({"start_date": start.strftime("%Y-%m-%d %H:%M:%S"),
                                    "end_date": end.strftime("%Y-%m-%d %H:%M:%S"),
                                    "page": page, "page_size": page_size})
        req = urllib.request.Request(f"{gateway.rstrip('/')}/spend/logs/v2?{q}",
                                     headers={"Authorization": f"Bearer {master_key}"})
        for attempt in range(4):                     # the gateway may be mid-restart: retry transient failures
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    d = json.loads(r.read())
                break
            except (urllib.error.URLError, ConnectionError, OSError):
                if attempt == 3:
                    raise
                time.sleep(2 * (attempt + 1))
        rows += d.get("data", [])
        if page >= int(d.get("total_pages") or 1) or not d.get("data"):
            return rows
        page += 1


# --------------------------------------------------------------------------- normalisation
def _host(api_base: str | None) -> str | None:
    return urllib.parse.urlparse(api_base).hostname if api_base else None


def normalise(row: dict) -> dict:
    """One LiteLLM spend-log row -> the attribution record. This is the contract other gateways must meet."""
    md = row.get("metadata") or {}
    sl = md.get("spend_logs_metadata") or {}
    err = md.get("error_information") or {}
    start = row.get("startTime")
    return {
        "request_id": row.get("request_id"),
        "litellm_call_id": md.get("litellm_call_id"),
        "ts": start,
        "status": row.get("status") or "success",
        "agent": sl.get("agent_id") or md.get("user_api_key_alias"),
        "team": sl.get("team") or md.get("user_api_key_team_alias") or row.get("team_id"),
        "user": sl.get("user") or row.get("end_user") or None,
        "run_id": sl.get("run_id"),
        "parent_run_id": sl.get("parent_run_id"),
        "root_run_id": sl.get("root_run_id"),
        "run_kind": sl.get("run_kind"),
        "step": sl.get("step"),
        "attempt": sl.get("attempt"),
        "tool": sl.get("tool"),
        "provider": _host(row.get("api_base")) or row.get("custom_llm_provider"),
        "model": row.get("model_group") or row.get("model"),
        "prompt_tokens": row.get("prompt_tokens") or 0,
        "completion_tokens": row.get("completion_tokens") or 0,
        "cost_usd": float(row.get("spend") or 0.0),
        "error": (err.get("error_message") or None) if row.get("status") == "failure" else None,
        "error_code": err.get("error_code") if row.get("status") == "failure" else None,
    }


def classify(r: dict) -> str:
    """attributed | rejected (refused before any spend, no run id) | unattributed (a HOLE: spent or served without a run)."""
    if r["run_id"] and r["agent"]:
        return "attributed"
    if r["status"] == "failure" and r["cost_usd"] == 0 and r["prompt_tokens"] == 0:
        return "rejected"
    return "unattributed"


def completeness(rows: list[dict]) -> dict:
    c = collections.Counter(classify(r) for r in rows)
    return {"requests": len(rows), "attributed": c["attributed"], "rejected_before_spend": c["rejected"],
            "unattributed": c["unattributed"], "complete": c["unattributed"] == 0,
            "unattributed_cost_usd": round(sum(r["cost_usd"] for r in rows if classify(r) == "unattributed"), 8)}


# --------------------------------------------------------------------------- aggregation
GROUPS = {"agent": "agent", "team": "team", "user": "user", "provider": "provider", "model": "model",
          "run": "run_id", "root": "root_run_id", "kind": "run_kind"}


def group(rows: Iterable[dict], by: str) -> list[dict]:
    key = GROUPS[by]
    acc: dict[Any, dict] = {}
    for r in rows:
        k = r.get(key) or "(none)"
        g = acc.setdefault(k, {by: k, "requests": 0, "ok": 0, "failed": 0, "retries": 0, "prompt_tokens": 0,
                               "completion_tokens": 0, "cost_usd": 0.0})
        g["requests"] += 1
        g["ok" if r["status"] == "success" else "failed"] += 1
        g["retries"] += 1 if (r["attempt"] or 1) > 1 else 0
        g["prompt_tokens"] += r["prompt_tokens"]
        g["completion_tokens"] += r["completion_tokens"]
        g["cost_usd"] += r["cost_usd"]
    return sorted(acc.values(), key=lambda g: -g["cost_usd"])


def build_trees(rows: list[dict]) -> list[dict]:
    """Run trees from the gateway rows. A run that made no gateway call itself (a tool that never called the
    model) appears only if a child points at it, and is marked `seen_at_gateway: false`."""
    runs: dict[str, dict] = {}

    def node(rid: str) -> dict:
        return runs.setdefault(rid, {"run_id": rid, "parent_run_id": None, "agent": None, "kind": None, "tool": None,
                                     "requests": 0, "attempts": set(), "models": set(), "providers": set(),
                                     "own_cost": 0.0, "tokens": 0, "failed": 0, "users": set(), "children": [],
                                     "seen_at_gateway": False})
    for r in sorted(rows, key=lambda x: x["ts"] or ""):
        if not r["run_id"]:
            continue
        n = node(r["run_id"])
        n.update(parent_run_id=r["parent_run_id"] or n["parent_run_id"], agent=r["agent"], kind=r["run_kind"] or n["kind"],
                 tool=r["tool"] or n["tool"], seen_at_gateway=True)
        n["requests"] += 1
        n["attempts"].add(r["attempt"] or 1)
        n["models"].add(r["model"])
        n["providers"].add(r["provider"])
        n["own_cost"] += r["cost_usd"]
        n["tokens"] += r["prompt_tokens"] + r["completion_tokens"]
        n["failed"] += 0 if r["status"] == "success" else 1
        if r["user"]:
            n["users"].add(r["user"])
    for n in list(runs.values()):
        if n["parent_run_id"]:
            node(n["parent_run_id"])
    for n in runs.values():
        if n["parent_run_id"]:
            runs[n["parent_run_id"]]["children"].append(n)

    def total(n: dict) -> float:
        n["total_cost"] = n["own_cost"] + sum(total(c) for c in n["children"])
        return n["total_cost"]
    roots = [n for n in runs.values() if not n["parent_run_id"]]
    for n in roots:
        total(n)
    return sorted(roots, key=lambda n: -n["total_cost"])


def tree_of(rows: list[dict], run_id: str) -> list[dict]:
    """The whole tree containing `run_id` (found through its root_run_id)."""
    root = next((r["root_run_id"] for r in rows if run_id in (r["run_id"], r["root_run_id"], r["parent_run_id"])
                 and r["root_run_id"]), run_id)
    return build_trees([r for r in rows if root in (r["root_run_id"], r["run_id"])])


# --------------------------------------------------------------------------- output
def _money(x: float) -> str:
    return f"${x:.6f}"


def print_table(rows: list[dict], cols: list[tuple[str, str]], out=sys.stdout) -> None:
    cells = [[("-" if r.get(k) in (None, "") else str(r[k])) if not isinstance(r.get(k), float) else _money(r[k]) for k, _ in cols] for r in rows]
    w = [max([len(h)] + [len(c[i]) for c in cells]) for i, (_, h) in enumerate(cols)]
    print("  ".join(h.ljust(w[i]) for i, (_, h) in enumerate(cols)), file=out)
    for c in cells:
        print("  ".join(v.ljust(w[i]) for i, v in enumerate(c)), file=out)


def print_tree(n: dict, depth: int = 0, out=sys.stdout) -> None:
    label = f"{n['kind'] or '?'}" + (f":{n['tool']}" if n["tool"] else "")
    seen = "" if n["seen_at_gateway"] else "  (no gateway call of its own)"
    attempts = f" attempts={sorted(n['attempts'])}" if n["seen_at_gateway"] and n["attempts"] != {1} else ""
    fails = f" failed={n['failed']}" if n["failed"] else ""
    users = f" user={','.join(sorted(n['users']))}" if n["users"] else ""
    print(f"{'  ' * depth}{n['run_id']}  {label}  agent={n['agent']}  reqs={n['requests']}{attempts}{fails}  "
          f"own={_money(n['own_cost'])}  subtree={_money(n['total_cost'])}  "
          f"{','.join(sorted(x for x in n['providers'] if x))}/{','.join(sorted(x for x in n['models'] if x))}{users}{seen}", file=out)
    for c in sorted(n["children"], key=lambda c: c["run_id"]):
        print_tree(c, depth + 1, out)


def _jsonable(o: Any) -> Any:
    if isinstance(o, set):
        return sorted(o, key=str)
    raise TypeError(type(o))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", default="1h", help="window, e.g. 30m, 2h, 1d (default 1h)")
    ap.add_argument("--until", default=None, help="window end, same format, relative to now (default now)")
    ap.add_argument("--by", choices=sorted(GROUPS), default="agent")
    ap.add_argument("--tree", action="store_true", help="print run trees with cost roll-up")
    ap.add_argument("--rows", action="store_true", help="print every request")
    ap.add_argument("--run", help="show the run tree containing this run id")
    ap.add_argument("--agent", help="only this agent (a delegated child matches by prefix: agent.<child>)")
    ap.add_argument("--check", action="store_true", help="exit 1 if any request is unattributed")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--from-json", help="read raw spend-log rows from a file instead of the gateway")
    ap.add_argument("--gateway", default=None)
    a = ap.parse_args(argv)

    if a.from_json:
        raw = json.loads(Path(a.from_json).read_text())
        raw = raw["data"] if isinstance(raw, dict) else raw
    else:
        env = _env()
        now = datetime.now(timezone.utc)
        end = now - parse_duration(a.until) if a.until else now + timedelta(minutes=1)
        raw = fetch_rows(a.gateway or env.get("GATEWAY_URL") or f"http://127.0.0.1:{env.get('GATEWAY_PORT', '4000')}",
                         env["LITELLM_MASTER_KEY"], now - parse_duration(a.since), end)
    rows = [normalise(r) for r in raw]
    if a.agent:
        rows = [r for r in rows if r["agent"] and (r["agent"] == a.agent or r["agent"].startswith(a.agent + "."))]
    comp = completeness(rows)

    if a.run:
        trees = tree_of(rows, a.run)
    elif a.tree:
        trees = build_trees(rows)
    else:
        trees = None

    if a.json:
        out: dict[str, Any] = {"completeness": comp}
        if trees is not None:
            out["trees"] = trees
        elif a.rows:
            out["rows"] = rows
        else:
            out["groups"] = group(rows, a.by)
        print(json.dumps(out, default=_jsonable, indent=2))
    elif trees is not None:
        for t in trees:
            print_tree(t)
            print()
    elif a.rows:
        print_table(rows, [("ts", "time"), ("agent", "agent"), ("run_id", "run"), ("parent_run_id", "parent"),
                           ("run_kind", "kind"), ("tool", "tool"), ("step", "step"), ("attempt", "try"), ("user", "user"),
                           ("team", "team"), ("provider", "provider"), ("model", "model"),
                           ("prompt_tokens", "in"), ("completion_tokens", "out"), ("cost_usd", "cost"),
                           ("status", "status")])
    else:
        print_table(group(rows, a.by), [(a.by, a.by), ("requests", "requests"), ("ok", "ok"), ("failed", "failed"),
                                        ("retries", "retries"), ("prompt_tokens", "in"), ("completion_tokens", "out"),
                                        ("cost_usd", "cost")])
    if not a.json:
        print(f"\ncompleteness: {comp['requests']} requests, {comp['attributed']} attributed, "
              f"{comp['rejected_before_spend']} rejected before any spend, {comp['unattributed']} unattributed "
              f"({_money(comp['unattributed_cost_usd'])})  -> {'COMPLETE' if comp['complete'] else 'HOLES'}")
    return 1 if a.check and not comp["complete"] else 0


if __name__ == "__main__":
    sys.exit(main())
