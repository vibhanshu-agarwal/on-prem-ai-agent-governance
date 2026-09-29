#!/usr/bin/env python3
"""Pilot-success simulation: a scripted, supervised run of >= 1,000 requests across the three sample agents,
with one rogue episode stopped by the control plane. Reports request counts, zero-overshoot evidence,
attribution completeness and the p95/p99 provider-free gateway overhead measured under that load.

    .venv/Scripts/python scripts/pilot_sim.py [--requests 1000] [--interval 2] [--max-minutes 40]

What it does (against the running stack, scripts/up.sh):
  1. speeds the three agents up (deploy/agents/config/rates.json, live-reloaded; restored at the end)
  2. samples gateway overhead in the background with scripts/overhead_probe.py (paired, provider-free)
  3. after ~40 % of the target, flips coding-agent to the "rogue" profile (4 parallel, 0.05 s, keeps hammering)
  4. a spend-rate watchdog reads the coding agent's live Redis spend counter every second; when the rate is
     > 5x its baseline it asks the control plane to stop the agent (operator alice) -- no human in the loop,
     the decision is logged with the numbers that triggered it
  5. after containment: calm profile, resume the agent through the control plane, keep running to the target
  6. checks every pilot key and team against its hard cap (Redis counter and DB), attribution completeness of
     the run window, and writes .local/acceptance/pilot_sim.json
Stdlib + httpx only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import subprocess
import sys
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import attribution_report as AR  # noqa: E402

PILOT = ("hr-agent", "finance-recon-agent", "coding-agent")
RATES = ROOT / "deploy" / "agents" / "config" / "rates.json"
OUT = ROOT / ".local" / "acceptance" / "pilot_sim.json"


def env_file(p: Path) -> dict:
    return dict(l.split("=", 1) for l in p.read_text().splitlines() if "=" in l and not l.startswith("#"))


ENV = {**env_file(ROOT / "deploy" / ".env"), **env_file(ROOT / ".local" / "control-plane.env")}
GW = f"http://127.0.0.1:{ENV.get('GATEWAY_PORT', '4000')}"
CP = f"http://127.0.0.1:{ENV.get('CP_PORT', '8100')}"
IDP = f"http://127.0.0.1:{ENV.get('IDP_PORT', '8300')}"
MASTER = {"Authorization": f"Bearer {ENV['LITELLM_MASTER_KEY']}"}


def log(*a):
    print(time.strftime("%H:%M:%S"), *a, flush=True)


def pct(v, p):
    s = sorted(v)
    if not s:
        return 0.0
    k = (len(s) - 1) * p / 100
    f = int(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


def cp_client(user="alice") -> httpx.Client:
    r = httpx.post(f"{IDP}/token", timeout=10, data={"grant_type": "password", "username": user,
                                                      "password": ENV[f"IDP_PASSWORD_{user.upper()}"],
                                                      "audience": "govpilot-control-plane"})
    r.raise_for_status()
    return httpx.Client(base_url=CP, timeout=120, headers={"Authorization": f"Bearer {r.json()['access_token']}"})


def redis_get(key: str) -> float:
    p = subprocess.run(["docker", "exec", "gov-redis", "sh", "-c",
                        f'redis-cli -a "$REDIS_PASSWORD" --no-auth-warning GET {key}'],
                       capture_output=True, text=True, timeout=20)
    try:
        return float(p.stdout.strip() or 0)
    except ValueError:
        return 0.0


def agents_ctl(*a):
    subprocess.run([sys.executable, str(ROOT / "scripts" / "agents_ctl.py"), *a], check=True, capture_output=True)


def pilot_rows(since: datetime) -> list[dict]:
    raw = AR.fetch_rows(GW, ENV["LITELLM_MASTER_KEY"], since, datetime.now(timezone.utc) + timedelta(minutes=1))
    rows = [AR.normalise(r) for r in raw]
    return [r for r in rows if r["agent"] and any(r["agent"] == a or r["agent"].startswith(a + ".") for a in PILOT)]


class Probe(threading.Thread):
    """Paired direct-vs-gateway overhead samples, taken while the pilot traffic runs."""

    def __init__(self, pairs: int, pace: float):
        super().__init__(daemon=True)
        self.pairs, self.pace, self.result, self.error = pairs, pace, None, None

    def run(self):
        k = httpx.post(f"{GW}/key/generate", headers=MASTER, timeout=30, json={
            "key_alias": f"pilot-probe-{int(time.time())}", "models": ["mock-local"], "max_budget": 5,
            "metadata": {"agent_id": "pilot-overhead-probe"}}).json()
        try:
            code = (ROOT / "scripts" / "overhead_probe.py").read_text(encoding="utf-8")
            p = subprocess.run(["docker", "run", "--rm", "--network", "govpilot_providers", "--label", "govpilot.t8test=1",
                                "-e", f"PKEY={ENV['MOCK_LOCAL_API_KEY']}", "--entrypoint", "python",
                                "govpilot/mock-provider:1", "-c", code, str(self.pairs), k["key"], str(self.pace)],
                               capture_output=True, text=True, timeout=3600)
            line = next((l for l in p.stdout.splitlines() if l.startswith("RESULT ")), None)
            self.result = json.loads(line[7:]) if line else None
            if not line:
                self.error = (p.stdout + p.stderr)[-800:]
        finally:
            httpx.post(f"{GW}/key/delete", headers=MASTER, json={"keys": [k["token"]]}, timeout=30)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--requests", type=int, default=1000)
    ap.add_argument("--interval", type=float, default=2.0, help="agent loop interval during the run (s)")
    ap.add_argument("--max-minutes", type=float, default=40)
    ap.add_argument("--probe-pairs", type=int, default=60, help="overhead pairs per prompt size")
    a = ap.parse_args(argv)

    cp = cp_client()
    keys = json.loads((ROOT / ".local" / "agent-keys.json").read_text())["agents"]
    coding_hash = hashlib.sha256(keys["coding-agent"]["key"].encode()).hexdigest()
    rates_backup = RATES.read_text(encoding="utf-8")
    t_start = datetime.now(timezone.utc) - timedelta(seconds=2)
    t0 = time.time()
    timeline: dict = {"started": t0}
    probe = Probe(a.probe_pairs, pace=0.5)
    try:
        # the coding agent may still be stopped by an earlier drill: make sure all three are running
        for ag in PILOT:
            st = cp.get(f"/v1/agents/{ag}").json()
            if st.get("desired_state") != "running":
                cp.post(f"/v1/agents/{ag}/resume", json={"reason": "pilot simulation start"})
        for ag in PILOT:
            agents_ctl("set", ag, f"interval_s={a.interval}")
        log(f"agents at {a.interval}s interval; overhead probe starting")
        probe.start()

        # ---- baseline spend rate of the coding agent
        rogue_at = int(a.requests * 0.4)
        base_samples, last = [], (time.time(), redis_get(f"spend:key:{coding_hash}"))
        n = 0
        while True:
            time.sleep(5)
            n = len(pilot_rows(t_start))
            now, sp = time.time(), redis_get(f"spend:key:{coding_hash}")
            base_samples.append((sp - last[1]) / max(now - last[0], 1e-6))
            last = (now, sp)
            log(f"requests so far: {n}  coding spend rate ${base_samples[-1]:.5f}/s")
            if n >= rogue_at and len(base_samples) >= 4:
                break
            if time.time() - t0 > a.max_minutes * 60:
                raise SystemExit("time budget exhausted before the rogue episode")
        baseline = max(statistics.median(base_samples), 1e-5)
        timeline["baseline_rate_usd_s"] = baseline

        # ---- rogue episode
        agents_ctl("rogue", "coding-agent")
        timeline["rogue_start"] = time.time()
        spend_at_rogue = redis_get(f"spend:key:{coding_hash}")
        log(f"coding-agent flipped to ROGUE; baseline ${baseline:.5f}/s, spend ${spend_at_rogue:.4f}")
        last = (time.time(), spend_at_rogue)
        trigger = None
        while time.time() - timeline["rogue_start"] < 120:
            time.sleep(1)
            now, sp = time.time(), redis_get(f"spend:key:{coding_hash}")
            rate = (sp - last[1]) / max(now - last[0], 1e-6)
            last = (now, sp)
            if rate > 5 * baseline and rate > 0.0005:
                trigger = {"rate_usd_s": round(rate, 6), "baseline_usd_s": round(baseline, 6),
                           "ratio": round(rate / baseline, 1), "at": now}
                break
        if trigger is None:
            raise SystemExit("watchdog never fired")
        timeline["detected"] = trigger["at"]
        log(f"watchdog: spend rate {trigger['ratio']}x baseline -> stop coding-agent")
        r = cp.post("/v1/agents/coding-agent/stop", json={
            "reason": f"pilot watchdog: spend rate ${trigger['rate_usd_s']}/s = {trigger['ratio']}x baseline"})
        rep = r.json()
        timeline["stop_decision"] = rep.get("started_at")
        timeline["stop_report"] = {"timings_ms": rep.get("timings_ms"), "verify_ok": (rep.get("verify") or {}).get("ok")}
        timeline["contained"] = (rep.get("phase_end_wall") or {}).get("credentials")
        time.sleep(3)
        spend_after_stop = redis_get(f"spend:key:{coding_hash}")
        timeline["rogue_spend_usd"] = round(spend_after_stop - spend_at_rogue, 6)
        time.sleep(5)
        timeline["spend_growth_after_stop_usd"] = round(redis_get(f"spend:key:{coding_hash}") - spend_after_stop, 6)
        agents_ctl("calm", "coding-agent")
        agents_ctl("set", "coding-agent", f"interval_s={a.interval}")
        res = cp.post("/v1/agents/coding-agent/resume", json={"reason": "pilot: rogue episode contained, resumed calm"})
        timeline["resumed"] = time.time()
        timeline["resume_ok"] = res.status_code == 200
        log(f"stopped in {rep.get('timings_ms', {}).get('total')} ms, resumed calm")

        # ---- run to the target
        while n < a.requests and time.time() - t0 < a.max_minutes * 60:
            time.sleep(10)
            n = len(pilot_rows(t_start))
            log(f"requests so far: {n}")
    finally:
        RATES.write_text(rates_backup, encoding="utf-8")
        log("rates.json restored")
    t_end = time.time()
    probe.join(timeout=900)
    time.sleep(8)                                     # past the spend-log batch write

    rows = pilot_rows(t_start)
    comp = AR.completeness(rows)
    by_agent = {ag: {"requests": sum(1 for r in rows if r["agent"] == ag or r["agent"].startswith(ag + ".")),
                     "success": sum(1 for r in rows if (r["agent"] == ag or r["agent"].startswith(ag + "."))
                                    and r["status"] == "success"),
                     "cost_usd": round(sum(r["cost_usd"] for r in rows if r["agent"] == ag
                                           or r["agent"].startswith(ag + ".")), 6)} for ag in PILOT}
    # ---- hard caps: every key and team that belongs to the pilot agents
    klist, page = [], 1
    while True:
        d = httpx.get(f"{GW}/key/list", headers=MASTER, timeout=60,
                      params={"return_full_object": "true", "size": 100, "page": page}).json()
        klist += d.get("keys", [])
        if page >= int(d.get("total_pages") or 1):
            break
        page += 1
    caps, over = [], []
    for k in klist:
        md = k.get("metadata") or {}
        aid = md.get("agent_id") or ""
        if not any(aid == p or aid.startswith(p + ".") for p in PILOT) or k.get("max_budget") is None:
            continue
        counter = redis_get(f"spend:key:{k['token']}")
        entry = {"alias": k.get("key_alias"), "agent_id": aid, "max_budget": k["max_budget"],
                 "db_spend": round(k.get("spend") or 0, 6), "redis_counter": round(counter, 6)}
        caps.append(entry)
        if max(entry["db_spend"], entry["redis_counter"]) > k["max_budget"] + 1e-9:
            over.append(entry)
    teams = []
    for tid in {k.get("team_id") for k in klist if k.get("team_id")}:
        t = httpx.get(f"{GW}/team/info", headers=MASTER, params={"team_id": tid}, timeout=30).json().get("team_info") or {}
        if t.get("max_budget") is not None and t.get("team_alias") in ("hr", "finance", "engineering"):
            c = redis_get(f"spend:team:{tid}")
            e = {"team": t.get("team_alias"), "max_budget": t["max_budget"], "db_spend": round(t.get("spend") or 0, 6),
                 "redis_counter": round(c, 6)}
            teams.append(e)
            if max(e["db_spend"], e["redis_counter"]) > t["max_budget"] + 1e-9:
                over.append(e)
    overhead = None
    if probe.result:
        allv = [x for v in probe.result.values() for x in v["overhead_ms"]]
        overhead = {"pairs": len(allv), "p50_ms": round(pct(allv, 50), 1), "p95_ms": round(pct(allv, 95), 1),
                    "p99_ms": round(pct(allv, 99), 1), "max_ms": round(max(allv), 1)}
    report = {
        "window": {"start": t_start.isoformat(), "minutes": round((t_end - t0) / 60, 1)},
        "requests": comp["requests"], "target_requests": a.requests, "by_agent": by_agent,
        "attribution": comp, "hard_caps": {"keys": caps, "teams": teams, "overshoots": over},
        "rogue_episode": {
            **{k: v for k, v in timeline.items() if k not in ("started",)},
            "trigger": trigger,
            "detect_after_rogue_s": round(timeline["detected"] - timeline["rogue_start"], 1),
            "stop_decision_after_detect_s": round((timeline["stop_decision"] or timeline["detected"]) - timeline["detected"], 2),
            "contained_after_rogue_start_s": round((timeline["contained"] or 0) - timeline["rogue_start"], 1)
            if timeline.get("contained") else None},
        "gateway_overhead_under_load": overhead, "probe_error": probe.error,
        "pass": {"requests_ge_target": comp["requests"] >= a.requests, "zero_overshoot": not over,
                 "attribution_complete": comp["complete"],
                 "p95_le_150ms": bool(overhead and overhead["p95_ms"] <= 150),
                 "p99_le_300ms": bool(overhead and overhead["p99_ms"] <= 300),
                 "rogue_stopped": bool(timeline.get("stop_report", {}).get("verify_ok"))},
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    log(json.dumps(report["pass"]))
    log(f"wrote {OUT}")
    return 0 if all(report["pass"].values()) else 1


if __name__ == "__main__":
    sys.exit(main())
