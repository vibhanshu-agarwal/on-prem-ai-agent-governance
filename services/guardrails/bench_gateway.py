"""A/B latency through two identical isolated gateways: guardrails hook ON (real Presidio) vs OFF.

Requests alternate ON/OFF with unique prompts (so no cache hits) against a provider-free mock model; the
paired difference is the end-to-end overhead added by the guardrail hook (pre-call + post-call), measured
from the client, plus the hook's own timing from its audit log. Started by tests/guardrails/stack/compose.down.yml
(gov-t5-gateway-on :4107, gov-t5-gateway-off :4106).
  python services/guardrails/bench_gateway.py [--n 30]
"""
from __future__ import annotations

import argparse
import json
import pathlib
import random
import statistics
import sys
import time
import uuid

import httpx

ROOT = pathlib.Path(__file__).resolve().parents[2]
WORDS = ("invoice ledger vendor payment transfer schedule audit review approval quarterly reconciliation report "
         "matched entries terms finance team before").split()


def load_env():
    return dict(l.split("=", 1) for l in (ROOT / "deploy" / ".env").read_text().splitlines()
                if "=" in l and not l.startswith("#"))


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(round(p / 100 * len(s) + 0.5)) - 1)]


def st(v):
    return {"n": len(v), "p50_ms": round(statistics.median(v), 1), "p95_ms": round(pct(v, 95), 1),
            "max_ms": round(max(v), 1)}


def run(n: int, on="http://127.0.0.1:4107", off="http://127.0.0.1:4106", agent="coding-agent", team="engineering"):
    env = load_env()
    master = {"Authorization": "Bearer " + env["LITELLM_MASTER_KEY"]}
    key = httpx.post(f"{on}/key/generate", headers=master, timeout=30, json={
        "key_alias": "t5-bench-" + uuid.uuid4().hex[:6], "models": ["mock-local"], "max_budget": 50,
        "metadata": {"agent_id": agent, "team": team}}).json()["key"]
    rng = random.Random(5)
    out: dict = {}
    try:
        with httpx.Client(timeout=60) as c:
            def call(base, content):
                t = time.perf_counter()
                r = c.post(f"{base}/v1/chat/completions", json={"model": "mock-local", "max_tokens": 4,
                           "messages": [{"role": "user", "content": content}]},
                           headers={"Authorization": f"Bearer {key}", "x-govpilot-run-id": "run-" + uuid.uuid4().hex[:16]})
                dt = (time.perf_counter() - t) * 1000
                assert r.status_code == 200, r.text[:300]
                return dt
            for label, tokens, pii in (("100_tokens_with_pii", 100, True), ("2000_tokens_with_pii", 2000, True),
                                       ("8000_tokens_with_pii", 8000, True), ("8000_tokens_clean", 8000, False)):
                words = int(tokens / 1.3)
                on_v, off_v, delta = [], [], []
                for i in range(n + 3):
                    body = " ".join(rng.choice(WORDS) for _ in range(words))
                    if pii:
                        at = rng.randrange(len(body))
                        body = body[:at] + " reach pat.lee@example.com, phone: 415-867-5309 " + body[at:]
                    a, b = (call(on, body), call(off, body)) if i % 2 else (call(off, body), call(on, body))
                    if i % 2 == 0:
                        a, b = b, a
                    if i < 3:
                        continue                                              # warm-up pairs
                    on_v.append(a); off_v.append(b); delta.append(a - b)
                out[label] = {"guard_on": st(on_v), "guard_off": st(off_v), "added_paired": st(delta)}
                print(label, json.dumps(out[label]), flush=True)
    finally:
        httpx.post(f"{on}/key/delete", headers=master, json={"keys": [key]}, timeout=30)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--out", default=str(ROOT / ".local" / "t5-results" / "latency-gateway.json"))
    a = ap.parse_args()
    res = run(a.n)
    p = pathlib.Path(a.out); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps(res, indent=1))
    print("wrote", p)
