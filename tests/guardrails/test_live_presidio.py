"""The pinned Presidio containers, through the adapter: detection, anonymization, windowed-vs-whole parity,
health-driven fail-closed, and the latency target. Needs the stack up (Presidio published on 127.0.0.1:5301/5302
by tests/guardrails/stack/compose.echo.yml; test_live_gateway.py brings that overlay up)."""
import asyncio
import json
import pathlib
import random
import statistics
import sys

import httpx
import pytest

from conftest import PRESIDIO_ANALYZER, PRESIDIO_ANONYMIZER, ROOT, run
from govguard import CallContext, EngineUnavailable, GuardrailBlocked, GuardrailConfig, GuardrailPipeline, PresidioEngine, Span
from govguard import MemoryAuditSink
from live import COMPOSE, sh, wait_healthy

ENTS = ["EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "IBAN_CODE", "IP_ADDRESS"]


@pytest.fixture(scope="module", autouse=True)
def presidio_up():
    sh(*COMPOSE, "up", "-d", "--no-deps", "presidio-analyzer", "presidio-anonymizer")
    wait_healthy("gov-presidio-analyzer")
    wait_healthy("gov-presidio-anonymizer")


def engine(**kw):
    return PresidioEngine(PRESIDIO_ANALYZER, PRESIDIO_ANONYMIZER, timeout_ms=3000, **kw)


def spans_of(text, **kw):
    e = engine(**kw)
    try:
        return run(e.analyze(text, ENTS, "en", 0.5))
    finally:
        run(e.aclose())


def test_detects_the_configured_entities_and_anonymizes():
    text = ("Contact pat.lee@example.com, phone: 415-867-5309, card 4111 1111 1111 1111, SSN 219-09-9999, "
            "IBAN DE89370400440532013000, server 192.168.1.10.")
    e = engine()
    spans = run(e.analyze(text, ENTS, "en", 0.5))
    assert {s.entity_type for s in spans} == set(ENTS)
    masked = run(e.anonymize(text, spans))
    for raw in ("pat.lee@example.com", "415-867-5309", "4111 1111", "219-09-9999", "DE89370400440532013000", "192.168.1.10"):
        assert raw not in masked
    assert masked.count("<") == len(spans)
    assert e.anonymizer_degraded == 0                           # the real anonymizer container did the masking
    run(e.aclose())


def test_trimmed_recognizer_registry_removes_a_measured_false_positive():
    # default Presidio labelled 123-45-6789 as UK_NHS; the pinned registry (deploy/guardrails/presidio-recognizers.yaml)
    # has no NHS recognizer, so it is not reported (and NHS cannot be requested).
    r = httpx.post(f"{PRESIDIO_ANALYZER}/analyze", json={"text": "ref 123-45-6789", "language": "en"})
    assert "UK_NHS" not in {x["entity_type"] for x in r.json()}
    entities = httpx.get(f"{PRESIDIO_ANALYZER}/supportedentities?language=en").json()
    assert "UK_NHS" not in entities and "EMAIL_ADDRESS" in entities


def _prompt(rng, n_words):
    w = "invoice ledger vendor payment transfer schedule audit review approval quarterly reconciliation report".split()
    return " ".join(rng.choice(w) for _ in range(n_words))


def test_windowed_analysis_matches_whole_text_analysis():
    rng = random.Random(11)
    pii = ["pat.lee@example.com", "phone: 415-867-5309", "card 4111 1111 1111 1111", "SSN 219-09-9999",
           "IBAN DE89370400440532013000", "host 10.20.30.40"]
    checked = 0
    for i in range(24):
        body = _prompt(rng, rng.choice([300, 1500, 5000]))
        for p in rng.sample(pii, rng.choice([1, 2, 3])):
            at = rng.choice([0, len(body) // 3, len(body) // 2, len(body) - 1, rng.randrange(len(body))])
            body = body[:at] + " " + p + " " + body[at:]
        whole = {(s.entity_type, s.start, s.end) for s in spans_of(body, windowed=False)}
        win = {(s.entity_type, s.start, s.end) for s in spans_of(body, windowed=True)}
        assert win == whole, (i, win ^ whole)
        checked += len(whole)
    assert checked >= 30


def test_clean_text_makes_no_analyzer_call_and_pii_text_makes_one():
    e = engine(windowed=True)
    assert run(e.analyze(_prompt(random.Random(1), 6000), ENTS, "en", 0.5)) == [] and e.calls == 0
    assert run(e.analyze(_prompt(random.Random(2), 6000) + " mail a.b@example.org", ENTS, "en", 0.5)) and e.calls == 1
    run(e.aclose())


def test_ner_entities_force_whole_text_analysis():
    e = engine(windowed=True)
    sp = run(e.analyze("Yesterday Angela Merkel visited Paris with pat.lee@example.com", ["PERSON", "EMAIL_ADDRESS"], "en", 0.5))
    assert {"PERSON", "EMAIL_ADDRESS"} <= {s.entity_type for s in sp}
    run(e.aclose())


def test_health_probe_makes_clean_prompts_fail_closed_when_the_engine_is_down():
    state = {"up": True}

    def handler(req):
        if req.url.path == "/health":
            return httpx.Response(200 if state["up"] else 503)
        return httpx.Response(200, json=[])

    async def scenario():
        e = PresidioEngine("http://a", "http://b", client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
                           windowed=True, health_interval_s=0.05)
        assert await e.analyze("clean text without candidates", ENTS, "en", 0.5) == []
        state["up"] = False
        await asyncio.sleep(0.25)
        with pytest.raises(EngineUnavailable, match="health"):
            await e.analyze("clean text without candidates", ENTS, "en", 0.5)     # no network call needed, still refuses
        state["up"] = True
        await asyncio.sleep(0.25)
        assert await e.analyze("clean text without candidates", ENTS, "en", 0.5) == []
        await e.aclose()
    asyncio.run(scenario())


def test_real_pipeline_with_real_presidio_end_to_end(tmp_path):
    cfg = GuardrailConfig.load(ROOT / "deploy" / "guardrails" / "guardrails.yaml")
    audit = MemoryAuditSink()
    e = engine(windowed=True, health_interval_s=1)
    pipe = GuardrailPipeline(cfg, e, audit=audit)
    d = {"messages": [{"role": "user", "content": "write to pat.lee@example.com about 10.0.0.7, phone: 415-867-5309"}]}
    out = run(pipe.check_request(CallContext("coding-agent"), d))
    assert d["messages"][0]["content"] == "write to <EMAIL_ADDRESS> about <IP_ADDRESS>, phone: <PHONE_NUMBER>"
    assert out.engine_ms > 0 and not out.degraded
    with pytest.raises(GuardrailBlocked):
        run(pipe.check_request(CallContext("hr-agent"), {"messages": [{"role": "user", "content": "SSN 219-09-9999"}]}))
    new, _ = run(pipe.check_response(CallContext("coding-agent"), "ping zed@example.com", []))
    assert new == "ping <EMAIL_ADDRESS>"
    run(e.aclose())


# --------------------------------------------------------------------------- latency vs Week 0 target
TARGET_P95_MS = 150


def test_pipeline_latency_from_the_host_side():
    """In-process pipeline + real Presidio over the Docker Desktop loopback proxy: this path adds a proxy hop and
    is very noisy on a busy shared host (same code measured p50 45 ms and 140 ms minutes apart), so it asserts only
    what is robust: the CPU-bound paths (no PII to send / cached history) inside the p95 target, and a loose
    sanity bound for the paths that call Presidio. The authoritative p95 <= 150 ms assertion is the paired
    gateway A/B in test_live_latency.py; all distributions are in docs/results/T5.md."""
    sys.path.insert(0, str(ROOT / "services" / "guardrails"))
    import bench

    runs = [asyncio.run(bench.main_async(20, "coding-agent", PRESIDIO_ANALYZER, PRESIDIO_ANONYMIZER, "3")) for _ in range(3)]
    for scenario in ("cold_500tok_single_message", "cold_2000tok_single_message", "cold_8000tok_single_message",
                     "cold_8000tok_no_pii", "tool_result_8000tok_injection_scan_only"):
        assert sorted(r[scenario]["p50_ms"] for r in runs)[1] <= 400, scenario
    for scenario in ("agent_turn_8000tok_history_cached_plus_300new", "cold_8000tok_no_pii"):
        assert sorted(r[scenario]["p95_ms"] for r in runs)[1] <= TARGET_P95_MS, scenario
