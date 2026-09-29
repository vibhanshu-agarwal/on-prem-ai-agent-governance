"""GuardrailEngine port: the only thing the pipeline knows about PII detection.

A sponsor can swap Presidio for another detector (a commercial DLP API, a local
model, ...) by implementing this Protocol and naming it in guardrails.yaml
(`engine.type: package.module:factory`). Everything else (rules, overrides,
approvals, audit, fail modes) is engine-independent.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, Sequence, runtime_checkable


class EngineUnavailable(Exception):
    """The engine could not answer (down, timeout, bad response). Callers apply the fail mode."""


@dataclass(frozen=True)
class Span:
    entity_type: str
    start: int
    end: int
    score: float = 1.0


@runtime_checkable
class GuardrailEngine(Protocol):
    name: str

    async def analyze(self, text: str, entities: Sequence[str], language: str,
                      score_threshold: float) -> list[Span]:
        """Return PII spans of the requested entity types. Raise EngineUnavailable on failure."""

    async def anonymize(self, text: str, spans: Sequence[Span]) -> str:
        """Replace each span with `<ENTITY_TYPE>`."""

    async def aclose(self) -> None: ...


def mask_spans(text: str, spans: Sequence[Span]) -> str:
    """Deterministic local masking (builtin engine and anonymizer fallback).
    Overlapping spans: the earliest-starting/longest wins."""
    out, pos = [], 0
    for s in sorted(spans, key=lambda s: (s.start, -(s.end - s.start))):
        if s.start < pos:
            continue
        out.append(text[pos:s.start])
        out.append(f"<{s.entity_type}>")
        pos = s.end
    out.append(text[pos:])
    return "".join(out)
