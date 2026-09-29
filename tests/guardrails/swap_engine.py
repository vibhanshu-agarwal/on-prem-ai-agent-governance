"""A deliberately different GuardrailEngine (a 'sponsor DLP' stand-in): detects internal employee ids.
Loaded by name via `engine.type: swap_engine:make` to prove the pipeline is engine-independent."""
import re

from govguard import Span


class KeywordEngine:
    name = "sponsor-dlp"

    async def analyze(self, text, entities, language="en", score_threshold=0.5):
        if "EMPLOYEE_ID" not in entities:
            return []
        return [Span("EMPLOYEE_ID", m.start(), m.end(), 0.99) for m in re.finditer(r"EMP-\d{5}", text)]

    async def anonymize(self, text, spans):
        out = text
        for s in sorted(spans, key=lambda s: -s.start):
            out = out[:s.start] + "[ID]" + out[s.end:]
        return out

    async def aclose(self):
        pass


def make(cfg):
    return KeywordEngine()
