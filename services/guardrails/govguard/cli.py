"""guardctl: operate overrides and approvals (shares the file state dir with the gateway hook).

  guardctl override grant --agent hr-agent --rule pii.EMAIL_ADDRESS --ttl 1h --reason "..." --by alice
  guardctl override list [--agent A] [--all] | revoke ID --by alice
  guardctl approvals list [--state pending] | approve ID --by bob | deny ID --by bob
  guardctl audit tail [-n 20]
State dir: --state or GOVGUARD_STATE_DIR (default .local/guardrails).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

from .state import FileApprovalStore, FileOverrideStore, JsonlAuditSink, OverrideError


def parse_ttl(s: str) -> int:
    m = re.fullmatch(r"(\d+)([smhd]?)", s.strip())
    if not m:
        raise OverrideError(f"bad ttl {s!r} (use 90s, 15m, 2h, 1d)")
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="guardctl")
    ap.add_argument("--state", default=os.environ.get("GOVGUARD_STATE_DIR", ".local/guardrails"))
    ap.add_argument("--max-ttl", type=int, default=int(os.environ.get("GOVGUARD_MAX_OVERRIDE_TTL", 86400)))
    sub = ap.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("override").add_subparsers(dest="sub", required=True)
    g = o.add_parser("grant")
    g.add_argument("--agent", required=True); g.add_argument("--rule", required=True)
    g.add_argument("--ttl", required=True); g.add_argument("--reason", required=True); g.add_argument("--by", required=True)
    l = o.add_parser("list"); l.add_argument("--agent"); l.add_argument("--all", action="store_true")
    r = o.add_parser("revoke"); r.add_argument("id"); r.add_argument("--by", required=True)
    a = sub.add_parser("approvals").add_subparsers(dest="sub", required=True)
    al = a.add_parser("list"); al.add_argument("--state", dest="astate")
    for n in ("approve", "deny"):
        p = a.add_parser(n); p.add_argument("id"); p.add_argument("--by", required=True); p.add_argument("--note", default="")
    au = sub.add_parser("audit").add_subparsers(dest="sub", required=True)
    t = au.add_parser("tail"); t.add_argument("-n", type=int, default=20)
    ns = ap.parse_args(argv)
    state = Path(ns.state)
    audit = JsonlAuditSink(state / "audit.jsonl", also_log=False)
    try:
        if ns.cmd == "override":
            st = FileOverrideStore(state / "overrides", audit, ns.max_ttl)
            if ns.sub == "grant":
                res = st.grant(ns.agent, ns.rule, parse_ttl(ns.ttl), ns.reason, ns.by)
            elif ns.sub == "list":
                res = st.list(ns.agent, include_inactive=ns.all)
            else:
                res = st.revoke(ns.id, ns.by)
        elif ns.cmd == "approvals":
            st = FileApprovalStore(state / "approvals", audit)
            if ns.sub == "list":
                res = st.list(ns.astate)
            else:
                res = st.decide(ns.id, ns.sub == "approve", ns.by, ns.note)
        else:
            p = state / "audit.jsonl"
            res = [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines()[-ns.n:]] if p.exists() else []
    except OverrideError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    print(json.dumps(res, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
