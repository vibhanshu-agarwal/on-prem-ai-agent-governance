"""Presidio adapter: talks to the self-hosted presidio-analyzer and presidio-anonymizer
containers (pinned 2.2.362) over HTTP. Nothing leaves the host."""
from __future__ import annotations

import asyncio
import time
from typing import Sequence

import httpx

from .engine import EngineUnavailable, Span, mask_spans


class PresidioEngine:
    name = "presidio"

    def __init__(self, analyzer_url: str, anonymizer_url: str, timeout_ms: int = 600,
                 breaker_seconds: float = 2.0, client: httpx.AsyncClient | None = None,
                 chunk_chars: int = 6000, chunk_overlap: int = 96):
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

    def _trip(self) -> None:
        self._down_until = time.monotonic() + self.breaker_seconds

    async def analyze(self, text: str, entities: Sequence[str], language: str = "en",
                      score_threshold: float = 0.5) -> list[Span]:
        """Long texts are split into ~chunk_chars windows analysed concurrently (spaCy cost is linear
        in text length; the analyzer runs several gunicorn workers). A window overlaps the next by
        chunk_overlap chars; a span is kept by the window in which it STARTS, so PII straddling a
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
        if time.monotonic() < self._down_until:  # circuit open: fail fast, no timeout per request
            raise EngineUnavailable("presidio analyzer circuit open")
        try:
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
        await self._client.aclose()
