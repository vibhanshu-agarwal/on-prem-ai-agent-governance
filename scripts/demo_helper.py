#!/usr/bin/env python3
"""Operator helper behind scripts/demo.sh: small, readable calls against the control plane and the gateway.
Standard library only; secrets are read from deploy/.env, .local/control-plane.env and .local/agents.env and are
never printed.

  demo_helper.py fleet [agent ...]                 one line per agent: status, spend / budget, keys, workloads
  demo_helper.py watch AGENT [--seconds 20]        poll live spend and draw it as a bar
  demo_helper.py stop AGENT [--reason TEXT]        the control plane's stop sequence, with its own timings
  demo_helper.py resume AGENT                      reverse a stop
  demo_helper.py probe AGENT                       one request with the agent's own gateway key: HTTP status + reason
  demo_helper.py clear-queue                       reject every pending discovery proposal (audited), for a clean demo queue
  demo_helper.py feeds-ok                          make sure today's discovery feed caps still have room (audited reset if not)
  demo_helper.py discovery NAME [--timeout 60]     wait until NAME shows up in the pending discovery queue
  demo_helper.py reject-discovery NAME             reject its proposal(s)
  demo_helper.py audit [--target T] [--limit N]    verify the hash chain, then list recent records
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PILOT = ["hr-agent", "finance-recon-agent", "coding-agent"]
KEY_VAR = {"hr-agent": "HR_AGENT_KEY", "coding-agent": "CODING_AGENT_KEY"}


def load_env() -> dict[str, str]:
    env: dict[str, str] = {}
    for f in ("deploy/.env", ".local/control-plane.env", ".local/agents.env"):
        p = ROOT / f
        if p.exists():
            for line in p.read_text().splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    k, v = line.split("=", 1)
                    env[k.strip()] = v.strip()
    return env


ENV = load_env()
CP_URL = f"http://127.0.0.1:{ENV.get('CP_PORT', '8100')}"
IDP_URL = f"http://127.0.0.1:{ENV.get('IDP_PORT', '8300')}"
GW_URL = f"http://127.0.0.1:{ENV.get('GATEWAY_PORT', '4000')}"
_token: dict[str, str] = {}


def http(method: str, url: str, body: dict | None = None, headers: dict | None = None, form: dict | None = None,
         timeout: float = 60.0) -> tuple[int, dict]:
    data = None
    h = dict(headers or {})
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    elif body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else {})
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except ValueError:
            return e.code, {"raw": raw[:300].decode("utf-8", "replace")}


def cp(method: str, path: str, body: dict | None = None, user: str = "alice") -> tuple[int, dict]:
    if user not in _token:
        st, d = http("POST", f"{IDP_URL}/token", form={
            "grant_type": "password", "username": user, "password": ENV[f"IDP_PASSWORD_{user.upper()}"],
            "audience": "govpilot-control-plane"})
        if st != 200:
            raise SystemExit(f"cannot log in to the IdP as {user}: HTTP {st}")
        _token[user] = d["access_token"]
    return http(method, CP_URL + path, body, {"Authorization": "Bearer " + _token[user]})


def bar(spend: float, budget: float, width: int = 30) -> str:
    frac = 0.0 if not budget else min(1.0, spend / budget)
    n = round(frac * width)
    return "[" + "#" * n + "." * (width - n) + f"] {frac * 100:5.1f}%"


def live(agent: str) -> dict:
    st, d = cp("GET", f"/v1/agents/{agent}/live")
    if st != 200:
        raise SystemExit(f"{agent}: HTTP {st} {d}")
    return d


def cmd_fleet(a) -> int:
    for ag in a.agents or PILOT:
        d = live(ag)
        blocked = [k for k in d["keys"] if k["blocked"]]
        running = [w["name"] for w in d["workloads"] if w["running"]]
        print(f"  {ag:<22} {d['status']:<12} ${d['spend_usd']:>8.4f} of ${d['max_budget_usd']:<5.2f} "
              f"{bar(d['spend_usd'], d['max_budget_usd'], 20)}  keys blocked {len(blocked)}/{len(d['keys'])}  "
              f"running: {', '.join(running) or 'none'}")
    return 0


def cmd_watch(a) -> int:
    t0 = time.time()
    prev = None
    while time.time() - t0 < a.seconds:
        d = live(a.agent)
        s = d["spend_usd"]
        delta = "" if prev is None else f"  +${s - prev:.4f}"
        print(f"  t+{time.time() - t0:4.0f}s  {a.agent}  ${s:8.4f} of ${d['max_budget_usd']:.2f}  "
              f"{bar(s, d['max_budget_usd'])}{delta}", flush=True)
        prev = s
        time.sleep(a.every)
    return 0


def cmd_stop(a) -> int:
    t0 = time.time()
    st, r = cp("POST", f"/v1/agents/{a.agent}/stop", {"reason": a.reason})
    wall = time.time() - t0
    if st != 200:
        print(f"  stop failed: HTTP {st} {r}")
        return 1
    t = r["timings_ms"]
    conns = sum(x.get("connections_before", 0) - x.get("connections_after", 0) for x in r["network"]["results"])
    print(f"  stop {r['stop_id']}: decision recorded, first gateway key blocked after {t['time_to_first_key_block']:.0f} ms")
    print(f"  contained (key blocked, network cut, restart disabled, credentials revoked) after {t['time_to_contained'] / 1000:.1f} s; "
          f"verified: {r['verify']['ok']} ({len(r['verify']['checks'])} checks) after {t['total'] / 1000:.1f} s "
          f"(target {r['target_s']} s, HTTP call took {wall:.1f} s)")
    print(f"  keys blocked {sum(1 for g in r['gateway']['keys'] if g['blocked'])}, workloads stopped "
          f"{sum(1 for w in r['workloads'] if w['stopped'])}, live connections cut {conns}, "
          f"credentials revoked {sum(1 for c in r['credentials'] if c['revoked'])}")
    return 0 if r["verify"]["ok"] else 1


def cmd_resume(a) -> int:
    st, r = cp("POST", f"/v1/agents/{a.agent}/resume", {"reason": a.reason})
    print(f"  resume {a.agent}: HTTP {st}; keys unblocked {sum(1 for k in r.get('keys', []) if k.get('unblocked'))}, "
          f"workloads started {sum(1 for w in r.get('workloads', []) if not w.get('error'))}")
    return 0 if st == 200 else 1


def cmd_probe(a) -> int:
    var = KEY_VAR.get(a.agent)
    key = ENV.get(var or "")
    if not key:
        print(f"  no key variable for {a.agent} (only key-auth agents: {', '.join(KEY_VAR)})")
        return 2
    st, r = http("POST", f"{GW_URL}/v1/chat/completions",
                 {"model": "mock-local", "max_tokens": 4, "messages": [{"role": "user", "content": "ping"}]},
                 {"Authorization": "Bearer " + key, "x-govpilot-run-id": "run-demo-probe-0001"})
    err = (r.get("error") or {})
    why = (err.get("message") or "")[:110] if isinstance(err, dict) else str(err)[:110]
    print(f"  {a.agent} calls the gateway with its own key: HTTP {st}" + (f"  ({why})" if st != 200 else ""))
    return 0


def _proposals(name: str) -> list[dict]:
    _, d = cp("GET", "/v1/discovery/proposals")
    return [p for p in d.get("proposals", []) if (p.get("observation") or {}).get("name") == name]


def cmd_clear_queue(a) -> int:
    _, d = cp("GET", "/v1/discovery/proposals")
    n = 0
    for p in d.get("proposals", []):
        if p["status"] == "pending":
            st, _ = cp("POST", f"/v1/discovery/proposals/{p['proposal_id']}/reject", {"reason": "demo: clearing stale proposals for a clean queue"})
            n += st == 200
    print(f"  rejected {n} stale pending proposal(s) (audited)")
    return 0


def cmd_feeds_ok(a) -> int:
    """Each discovery feed may file `daily_limit` proposals a day (a compromised feed must not flood the queue). Repeated
    test runs and demos on one day can use them up; the documented remedy is a human admin's audited reset."""
    _, d = cp("GET", "/v1/discovery/feeds")
    for f in d.get("feeds", []):
        if f["feed"] in ("docker-events", "gateway-logs") and f["count"] >= f["daily_limit"] - 2:
            st, _ = cp("POST", f"/v1/discovery/feeds/{f['feed']}/reset-count", {"reason": "demo run: daily proposal cap used up by earlier runs"})
            print(f"  feed {f['feed']} had used {f['count']} of {f['daily_limit']} proposals today: counter reset by alice (audited), HTTP {st}")
    return 0


def cmd_discovery(a) -> int:
    t0 = time.time()
    while time.time() - t0 < a.timeout:
        ps = [p for p in _proposals(a.name) if p["status"] == "pending"]
        if ps:
            p = ps[0]
            print(f"  proposal {p['proposal_id']} appeared after {time.time() - t0:.1f} s via feed '{p['feed']}': "
                  f"status {p['status']}, budget ${p['budget_usd']:.2f}, gateway key {p['gateway_key']}")
            ev = (p.get("observation") or {})
            print(f"  evidence: container {ev.get('name')}, image {ev.get('image')}, suggested owner {ev.get('suggested_owner')}")
            return 0
        time.sleep(1.0)
    print(f"  no proposal for {a.name} within {a.timeout} s")
    return 1


def cmd_reject(a) -> int:
    for p in _proposals(a.name):
        if p["status"] == "pending":
            st, _ = cp("POST", f"/v1/discovery/proposals/{p['proposal_id']}/reject", {"reason": "demo cleanup"})
            print(f"  rejected {p['proposal_id']}: HTTP {st}")
    return 0


def cmd_audit(a) -> int:
    st, v = cp("GET", "/v1/audit/verify")
    print(f"  audit hash chain: {'INTACT' if v.get('ok') else 'BROKEN'}: {v.get('count')} records, "
          f"head {str(v.get('head_hash'))[:16]}...")
    q = f"/v1/audit?limit={a.limit}" + (f"&target={a.target}" if a.target else "")
    _, d = cp("GET", q)
    for r in d.get("records", [])[-a.limit:]:
        print(f"   #{r['seq']:<5} {r['ts'][11:19]}  {r['severity']:<6} {r['actor']:<22} {r['action']:<28} {r['target']}")
    return 0 if v.get("ok") else 1


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("fleet")
    s.add_argument("agents", nargs="*")
    s = sub.add_parser("watch")
    s.add_argument("agent")
    s.add_argument("--seconds", type=float, default=20)
    s.add_argument("--every", type=float, default=2)
    s = sub.add_parser("stop")
    s.add_argument("agent")
    s.add_argument("--reason", default="demo: runaway spend")
    s = sub.add_parser("resume")
    s.add_argument("agent")
    s.add_argument("--reason", default="demo cleanup")
    sub.add_parser("probe").add_argument("agent")
    s = sub.add_parser("discovery")
    s.add_argument("name")
    s.add_argument("--timeout", type=float, default=60)
    sub.add_parser("reject-discovery").add_argument("name")
    sub.add_parser("feeds-ok")
    sub.add_parser("clear-queue")
    s = sub.add_parser("audit")
    s.add_argument("--target")
    s.add_argument("--limit", type=int, default=8)
    a = ap.parse_args(argv)
    fn = {"fleet": cmd_fleet, "watch": cmd_watch, "stop": cmd_stop, "resume": cmd_resume, "probe": cmd_probe,
          "discovery": cmd_discovery, "reject-discovery": cmd_reject, "audit": cmd_audit, "feeds-ok": cmd_feeds_ok,
          "clear-queue": cmd_clear_queue}[a.cmd]
    return fn(a)


if __name__ == "__main__":
    sys.exit(main())
