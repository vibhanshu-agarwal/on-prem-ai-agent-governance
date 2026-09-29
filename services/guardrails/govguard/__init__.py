"""govguard: guardrail pipeline for the governance pilot (T5)."""
from .builtin_engine import BuiltinEngine
from .engine import EngineUnavailable, GuardrailEngine, Span, mask_spans
from .factory import build_pipeline, make_engine
from .pipeline import CallContext, GuardrailBlocked, GuardrailPipeline, Outcome
from .policy import EffectivePolicy, GovpolicyOverlay, GuardrailConfig, PolicyUnavailable
from .presidio_engine import PresidioEngine
from .state import (FileApprovalStore, FileOverrideStore, JsonlAuditSink, MemoryAuditSink, OverrideError)

__all__ = [
    "BuiltinEngine", "EngineUnavailable", "GuardrailEngine", "Span", "mask_spans", "build_pipeline", "make_engine",
    "CallContext", "GuardrailBlocked", "GuardrailPipeline", "Outcome", "EffectivePolicy", "GovpolicyOverlay",
    "GuardrailConfig", "PolicyUnavailable", "PresidioEngine", "FileApprovalStore", "FileOverrideStore",
    "JsonlAuditSink", "MemoryAuditSink", "OverrideError",
]
