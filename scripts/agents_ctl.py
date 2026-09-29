#!/usr/bin/env python3
"""Operate the sample agents' loop rates (deploy/agents/config/rates.json) without restarting them.

  python scripts/agents_ctl.py status
  python scripts/agents_ctl.py rogue finance-recon-agent [--interval 0.05] [--concurrency 4] [--max-tokens 512]
  python scripts/agents_ctl.py calm  finance-recon-agent     # remove the override, back to the base rate
  python scripts/agents_ctl.py pause|resume <agent>
  python scripts/agents_ctl.py set <agent> interval_s=2 concurrency=2

Running agents re-read the file when it changes (within one loop tick, ~their interval). "Rogue" is just
a rate profile: many parallel requests per tick, optionally a fixed --max-tokens, and
`on_budget_exceeded: hammer`, so the agent keeps pushing when the gateway says no. The point of the demo is
that the per-key budget and the stop switch, not the agent's good manners, are what contain it.
Base rates live under the agent's own key; overrides under "<agent>@override" so `calm` restores exactly.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

RATES = Path(os.environ.get("AGENT_RATES_FILE") or Path(__file__).resolve().parents[1] / "deploy" / "agents" / "config" / "rates.json")
ROGUE = {"interval_s": 0.05, "jitter": 0.0, "concurrency": 4, "on_budget_exceeded": "hammer", "profile": "rogue"}


def load() -> dict:
    return json.loads(RATES.read_text())


def save(d: dict) -> None:
    tmp = RATES.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2) + "\n")
    os.replace(tmp, RATES)                  # atomic: an agent never reads a half-written file


def effective(d: dict, agent: str) -> dict:
    return {**(d.get("default") or {}), **(d.get(agent) or {})}


def coerce(v: str):
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    try:
        return int(v)
    except ValueError:
        try:
            return float(v)
        except ValueError:
            return v


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("status")
    r = sub.add_parser("rogue")
    r.add_argument("agent")
    r.add_argument("--interval", type=float, default=ROGUE["interval_s"])
    r.add_argument("--concurrency", type=int, default=ROGUE["concurrency"])
    r.add_argument("--max-tokens", type=int)
    for name in ("calm", "pause", "resume"):
        sub.add_parser(name).add_argument("agent")
    s = sub.add_parser("set")
    s.add_argument("agent")
    s.add_argument("pairs", nargs="+")
    a = ap.parse_args(argv)
    d = load()
    if a.cmd == "status":
        for k in sorted(k for k in d if not k.startswith("_") and k != "default" and "@" not in k):
            eff = effective(d, k)
            print(f"{k:24} {json.dumps(eff)}")
        return 0
    agent = a.agent
    if a.cmd == "rogue":
        d.setdefault(f"{agent}@base", dict(d.get(agent) or {}))     # remembered so calm restores exactly
        d[agent] = {**(d.get(agent) or {}), **ROGUE, "interval_s": a.interval, "concurrency": a.concurrency}
        if a.max_tokens:
            d[agent]["max_tokens"] = a.max_tokens
    elif a.cmd == "calm":
        d[agent] = d.pop(f"{agent}@base", {})
    elif a.cmd == "pause":
        d[agent] = {**(d.get(agent) or {}), "paused": True}
    elif a.cmd == "resume":
        d[agent] = {k: v for k, v in (d.get(agent) or {}).items() if k != "paused"}
    elif a.cmd == "set":
        d[agent] = {**(d.get(agent) or {}), **{p.split("=", 1)[0]: coerce(p.split("=", 1)[1]) for p in a.pairs}}
    save(d)
    print(f"{agent}: {json.dumps(effective(d, agent))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
