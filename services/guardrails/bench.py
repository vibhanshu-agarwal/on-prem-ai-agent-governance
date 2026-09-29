"""Latency benchmark for the guardrail pipeline (T5).

Measures the ADDED latency of the guardrail request phase (pipeline.check_request) against the
Week-0 target (total gateway overhead p95 <= 150 ms for prompts <= 8K tokens), using the real
pipeline + real config + real Presidio containers. Provider-free by construction (no model call).

  python services/guardrails/bench.py [--n 30] [--out .local/t5-results/latency.json]
Requires Presidio reachable at GOVGUARD_PRESIDIO_ANALYZER_URL / _ANONYMIZER_URL
(default 127.0.0.1:5301/5302, published by tests/guardrails/stack/compose.echo.yml).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import pathlib
import random
import statistics
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "services" / "guardrails"))

from govguard import CallContext, GuardrailConfig, GuardrailPipeline, MemoryAuditSink, PresidioEngine  # noqa: E402

WORDS = ("the quarterly reconciliation report shows invoices matched against ledger entries for the vendor and "
         "payment terms were reviewed by the finance team before approval of transfer schedule audit trail").split()
TOK_PER_WORD = 1.3


def prose(rng: random.Random, tokens: int) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(int(tokens / TOK_PER_WORD)))


def pct(v, p):
    s = sorted(v)
    return s[min(len(s) - 1, int(round(p / 100 * len(s) + 0.5)) - 1)]


def stats(v):
    return {"n": len(v), "p50_ms": round(statistics.median(v), 1), "p95_ms": round(pct(v, 95), 1),
            "p99_ms": round(pct(v, 99), 1), "max_ms": round(max(v), 1)}


async def timed(pipe, agent, messages):
    t = time.perf_counter()
    await pipe.check_request(CallContext(agent_id=agent, request_id="bench"), {"messages": messages})
    return (time.perf_counter() - t) * 1000


async def main_async(n: int, agent: str, an: str, anon: str, workers_note: str) -> dict:
    cfg = GuardrailConfig.load(ROOT / "deploy" / "guardrails" / "guardrails.yaml")
    eng = cfg.engine_cfg
    engine = PresidioEngine(an, anon, timeout_ms=int(eng.get("timeout_ms", 800)), breaker_seconds=2,
                            chunk_chars=int(eng.get("chunk_chars", 6000)), chunk_overlap=int(eng.get("chunk_overlap", 96)),
                            windowed=bool(eng.get("windowed", False)), window_pad=int(eng.get("window_pad", 160)),
                            health_interval_s=float(eng.get("health_interval_s", 0)))
    pipe = GuardrailPipeline(cfg, engine, audit=MemoryAuditSink())
    rng = random.Random(7)
    res: dict = {"agent": agent, "config": {"chunk_chars": engine.chunk_chars, "windowed": engine.windowed,
                                             "window_pad": engine.window_pad, "analyzer_workers": workers_note}}
    await timed(pipe, agent, [{"role": "user", "content": "warm up " + prose(rng, 200)}])  # connections, imports

    async def scenario(name, make):
        v = []
        for _ in range(n):
            v.append(await timed(pipe, agent, make()))
        res[name] = stats(v)
        print(f"{name:52s} {res[name]}", flush=True)

    pii = " Contact: pat.lee@example.com, phone: 415-867-5309."
    for tokens in (500, 2000, 8000):
        await scenario(f"cold_{tokens}tok_single_message", lambda t=tokens: [{"role": "user", "content": prose(rng, t) + pii}])
    await scenario("cold_8000tok_no_pii", lambda: [{"role": "user", "content": prose(rng, 8000)}])

    # the realistic agent loop: a long conversation resent every turn, only the newest message is new
    history = [{"role": "user", "content": prose(rng, 3000)}, {"role": "assistant", "content": prose(rng, 2500)},
               {"role": "user", "content": prose(rng, 2000)}]
    await pipe.check_request(CallContext(agent_id=agent), {"messages": json.loads(json.dumps(history))})
    await scenario("agent_turn_8000tok_history_cached_plus_300new",
                   lambda: json.loads(json.dumps(history)) + [{"role": "user", "content": prose(rng, 300)}])
    await scenario("agent_turn_8000tok_history_cached_plus_300new_with_pii",
                   lambda: json.loads(json.dumps(history)) + [{"role": "user", "content": prose(rng, 300) + pii}])
    await scenario("tool_result_8000tok_injection_scan_only",
                   lambda: [{"role": "user", "content": "go"}, {"role": "tool", "tool_call_id": "1", "content": prose(rng, 8000)}])
    v = []
    for _ in range(n):
        t = time.perf_counter()
        await pipe.check_response(CallContext(agent_id=agent), prose(rng, 500) + " mail zed@example.com", [])
        v.append((time.perf_counter() - t) * 1000)
    res["response_500tok_with_pii"] = stats(v)
    print(f"{'response_500tok_with_pii':52s} {res['response_500tok_with_pii']}")
    await engine.aclose()
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--agent", default="coding-agent")
    ap.add_argument("--analyzer", default=os.environ.get("GOVGUARD_PRESIDIO_ANALYZER_URL", "http://127.0.0.1:5301"))
    ap.add_argument("--anonymizer", default=os.environ.get("GOVGUARD_PRESIDIO_ANONYMIZER_URL", "http://127.0.0.1:5302"))
    ap.add_argument("--workers-note", default="3")
    ap.add_argument("--out", default=str(ROOT / ".local" / "t5-results" / "latency.json"))
    a = ap.parse_args()
    res = asyncio.run(main_async(a.n, a.agent, a.analyzer, a.anonymizer, a.workers_note))
    res["target"] = {"p95_ms": 150, "note": "Week 0: total gateway overhead p95 <= 150 ms for prompts <= 8K tokens"}
    p = pathlib.Path(a.out)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(res, indent=1))
    print("wrote", p)


if __name__ == "__main__":
    main()
