"""Presidio adapter: talks to the self-hosted presidio-analyzer and presidio-anonymizer
containers (pinned 2.2.362) over HTTP. Nothing leaves the host.

Latency design (measured in docs/results/T5.md): Presidio's cost is spaCy processing, linear in
text length (~0.1 ms/word) plus a fixed ~30-60 ms per call, so an 8K-token prompt analysed whole
costs 0.5-1 s. Two mitigations live here, both behaviour-preserving:

* Candidate windows (`windowed=True`). When every requested entity is pattern-based (email, phone,
  card, SSN, bank, IBAN, IP), a cheap superset regex finds the few places that COULD hold such a
  value; only +/- `window_pad` characters around them are sent to Presidio. Clean text costs no
  network call. If any NER entity (PERSON, LOCATION, ...) is requested the whole text is analysed.
  Parity with whole-text analysis is tested against the live analyzer.
* Chunking. Text that still exceeds `chunk_chars` is split into overlapping windows analysed
  concurrently (the analyzer runs several gunicorn workers).

Because a clean prompt can skip the network call, a background health probe (`health_interval_s`)
keeps "engine down" knowledge current, so fail-closed still triggers within seconds of an outage
even for prompts that would not have needed a call.
"""
from __future__ import annotations

import asyncio
import re
import time
from typing import Sequence

import httpx

from .engine import EngineUnavailable, Span, mask_spans

PATTERN_ENTITIES = {"EMAIL_ADDRESS", "PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "US_BANK_NUMBER", "IBAN_CODE",
                    "IP_ADDRESS"}
_DIGITS = r"\d(?:[\s().+\-/]?\d){6,}"                        # >= 7 digits, separators allowed
_SIGNATURES = {
    "EMAIL_ADDRESS": r"@",
    "IP_ADDRESS": r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9A-Fa-f]{0,4}:[0-9A-Fa-f]{0,4}:[0-9A-Fa-f:]*",
}
for _e in ("PHONE_NUMBER", "CREDIT_CARD", "US_SSN", "US_BANK_NUMBER", "IBAN_CODE"):
    _SIGNATURES[_e] = _DIGITS


class PresidioEngine:
    name = "presidio"

    def __init__(self, analyzer_url: str, anonymizer_url: str, timeout_ms: int = 600,
                 breaker_seconds: float = 2.0, client: httpx.AsyncClient | None = None,
                 chunk_chars: int = 6000, chunk_overlap: int = 96, windowed: bool = False,
                 window_pad: int = 160, health_interval_s: float = 0.0):
        self.analyzer_url = analyzer_url.rstrip("/")
        self.anonymizer_url = anonymizer_url.rstrip("/")
        self.timeout = timeout_ms / 1000.0
        self.breaker_seconds = breaker_seconds
        self._down_until = 0.0
        self._client = client or httpx.AsyncClient(
            timeout=httpx.Timeout(self.timeout, connect=min(self.timeout, 0.5)),
            limits=httpx.Limits(max_connections=64, max_keepalive_connections=16))
        self.anonymizer_degraded = 0
        self.chunk_chars, self.chunk_overlap = chunk_chars, chunk_overlap
        self.windowed, self.window_pad = windowed, window_pad
        self.health_interval_s = health_interval_s
        self._health_task: asyncio.Task | None = None
        self._health_ok: bool | None = None     # None = never probed yet
        self.calls = 0                     # analyzer HTTP calls made (observability / tests)

    # ------------------------------------------------------------------ availability
    def _trip(self) -> None:
        self._down_until = time.monotonic() + self.breaker_seconds

    def _ensure_health_task(self) -> None:
        if not self.health_interval_s:
            return
        loop = asyncio.get_running_loop()
        t = self._health_task
        if t is None or t.done() or t.get_loop() is not loop:
            self._health_task = loop.create_task(self._health_loop())

    async def _probe(self) -> None:
        try:
            r = await self._client.get(f"{self.analyzer_url}/health", timeout=min(self.timeout, 1.0))
            self._health_ok = r.status_code == 200
        except Exception:   # CancelledError is a BaseException: cancellation still propagates
            self._health_ok = False

    async def _health_loop(self) -> None:
        while True:
            await asyncio.sleep(self.health_interval_s)
            await self._probe()

    async def _check_alive(self) -> None:
        if time.monotonic() < self._down_until:  # circuit open: fail fast, no timeout per request
            raise EngineUnavailable("presidio analyzer circuit open")
        if self.health_interval_s:
            if self._health_ok is None:          # first use: know the engine's state before trusting a skipped call
                await self._probe()
            self._ensure_health_task()
            if not self._health_ok:
                raise EngineUnavailable("presidio analyzer health probe failing")

    # ------------------------------------------------------------------ analysis
    def _candidate_windows(self, text: str, entities: Sequence[str]) -> list[tuple[int, int]]:
        rx = re.compile("|".join(f"(?:{_SIGNATURES[e]})" for e in sorted(set(entities))))
        wins: list[tuple[int, int]] = []
        for m in rx.finditer(text):
            s, e = max(0, m.start() - self.window_pad), min(len(text), m.end() + self.window_pad)
            if wins and s <= wins[-1][1]:
                wins[-1] = (wins[-1][0], max(wins[-1][1], e))
            else:
                wins.append((s, e))
        return wins

    async def analyze(self, text: str, entities: Sequence[str], language: str = "en",
                      score_threshold: float = 0.5) -> list[Span]:
        await self._check_alive()
        if self.windowed and entities and set(entities) <= PATTERN_ENTITIES:
            wins = self._candidate_windows(text, entities)
            if not wins:
                return []                                            # nothing that could be PII: no call needed
            if sum(e - s for s, e in wins) < len(text) * 0.8:
                parts, offs, pos = [], [], 0
                for s, e in wins:
                    offs.append((pos, s, e))
                    parts.append(text[s:e])
                    pos += (e - s) + 2
                spans = await self._analyze_chunked("\n\n".join(parts), entities, language, score_threshold)
                out: list[Span] = []
                for x in spans:
                    for jp, s, e in offs:
                        if jp <= x.start and x.end <= jp + (e - s):
                            out.append(Span(x.entity_type, x.start - jp + s, x.end - jp + s, x.score))
                            break                                     # spans straddling windows are dropped
                return out
        return await self._analyze_chunked(text, entities, language, score_threshold)

    async def _analyze_chunked(self, text: str, entities: Sequence[str], language: str,
                               score_threshold: float) -> list[Span]:
        """Long texts are split into ~chunk_chars windows analysed concurrently. A window overlaps the
        next by chunk_overlap chars; a span is kept by the window in which it STARTS, so PII straddling a
        boundary is still found whole (PII values are shorter than the overlap)."""
        if len(text) <= self.chunk_chars * 1.25:
            return await self._analyze_one(text, entities, language, score_threshold)
        bounds, start = [], 0
        while start < len(text):
            end = min(len(text), start + self.chunk_chars)
            if end < len(text):  # cut at whitespace so we do not split a token
                ws = text.rfind(" ", start + self.chunk_chars // 2, end)
                end = ws + 1 if ws > 0 else end
            bounds.append((start, end))
            start = end
        parts = await asyncio.gather(*[
            self._analyze_one(text[s:min(len(text), e + self.chunk_overlap)], entities, language, score_threshold)
            for s, e in bounds])
        out: list[Span] = []
        for (s, e), spans in zip(bounds, parts):
            out += [Span(x.entity_type, x.start + s, x.end + s, x.score) for x in spans if x.start + s < e or e == len(text)]
        return out

    async def _analyze_one(self, text: str, entities: Sequence[str], language: str,
                           score_threshold: float) -> list[Span]:
        if time.monotonic() < self._down_until:
            raise EngineUnavailable("presidio analyzer circuit open")
        try:
            self.calls += 1
            r = await self._client.post(f"{self.analyzer_url}/analyze", json={
                "text": text, "language": language, "entities": list(entities),
                "score_threshold": score_threshold})
            r.raise_for_status()
            return [Span(x["entity_type"], int(x["start"]), int(x["end"]), float(x.get("score", 1.0)))
                    for x in r.json()]
        except (httpx.HTTPError, ValueError, KeyError, TypeError) as e:
            self._trip()
            raise EngineUnavailable(f"presidio analyzer: {type(e).__name__}: {e}") from e

    async def anonymize(self, text: str, spans: Sequence[Span]) -> str:
        if not spans:
            return text
        try:
            r = await self._client.post(f"{self.anonymizer_url}/anonymize", json={
                "text": text,
                "analyzer_results": [{"entity_type": s.entity_type, "start": s.start, "end": s.end,
                                      "score": s.score} for s in spans],
                "anonymizers": {"DEFAULT": {"type": "replace"}}})
            r.raise_for_status()
            return r.json()["text"]
        except (httpx.HTTPError, ValueError, KeyError, TypeError):
            # Masking is deterministic string surgery on spans the analyzer already found, so
            # falling back to local masking cannot leak more than the anonymizer would have.
            self.anonymizer_degraded += 1
            return mask_spans(text, spans)

    async def aclose(self) -> None:
        if self._health_task:
            self._health_task.cancel()
        await self._client.aclose()
