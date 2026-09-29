"""Builtin regex PII engine: zero dependencies, deterministic, no NER (so no PERSON/LOCATION).
Used (a) as the `degrade` fallback when Presidio is unreachable, (b) as a reference second
GuardrailEngine implementation proving the port is swappable, (c) in unit tests."""
from __future__ import annotations

import re
from typing import Sequence

from .engine import Span, mask_spans

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_PHONE = re.compile(r"(?<![\w-])(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?![\w-])")
_SSN = re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")
_CARD = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
_IBAN = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,3})?\b")
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")


def luhn_ok(digits: str) -> bool:
    d = [int(c) for c in digits][::-1]
    return len(d) >= 13 and (sum(d[0::2]) + sum(sum(divmod(x * 2, 10)) for x in d[1::2])) % 10 == 0


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    n = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(n) % 97 == 1


class BuiltinEngine:
    name = "builtin"

    async def analyze(self, text: str, entities: Sequence[str], language: str = "en",
                      score_threshold: float = 0.5) -> list[Span]:
        want = set(entities)
        out: list[Span] = []

        def add(t, rx, ok=None, score=0.85):
            if t not in want:
                return
            for m in rx.finditer(text):
                if ok is None or ok(m.group(0)):
                    out.append(Span(t, m.start(), m.end(), score))

        add("EMAIL_ADDRESS", _EMAIL, score=1.0)
        add("US_SSN", _SSN)
        add("CREDIT_CARD", _CARD, lambda s: luhn_ok(re.sub(r"\D", "", s)), 1.0)
        add("IBAN_CODE", _IBAN, iban_ok, 1.0)
        add("IP_ADDRESS", _IPV4)
        add("PHONE_NUMBER", _PHONE, score=0.75)
        return [s for s in out if s.score >= score_threshold]

    async def anonymize(self, text: str, spans: Sequence[Span]) -> str:
        return mask_spans(text, spans)

    async def aclose(self) -> None:
        return None
