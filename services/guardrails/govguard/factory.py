"""Build a GuardrailPipeline from config + environment (adapter selection is config, not code)."""
from __future__ import annotations

import importlib
import os
from pathlib import Path

from .builtin_engine import BuiltinEngine
from .engine import GuardrailEngine
from .pipeline import GuardrailPipeline
from .policy import GovpolicyOverlay, GuardrailConfig
from .presidio_engine import PresidioEngine
from .state import DEFAULT_MAX_OVERRIDE_TTL, FileApprovalStore, FileOverrideStore, JsonlAuditSink


def make_engine(cfg: dict, env: dict | None = None) -> GuardrailEngine:
    env = os.environ if env is None else env
    kind = env.get("GOVGUARD_ENGINE", cfg.get("type", "presidio"))
    if kind == "builtin":
        return BuiltinEngine()
    if kind == "presidio":
        return PresidioEngine(
            env.get("GOVGUARD_PRESIDIO_ANALYZER_URL", cfg.get("analyzer_url", "http://presidio-analyzer:3000")),
            env.get("GOVGUARD_PRESIDIO_ANONYMIZER_URL", cfg.get("anonymizer_url", "http://presidio-anonymizer:3000")),
            timeout_ms=int(cfg.get("timeout_ms", 600)), breaker_seconds=float(cfg.get("breaker_seconds", 2.0)),
            chunk_chars=int(cfg.get("chunk_chars", 6000)), chunk_overlap=int(cfg.get("chunk_overlap", 96)))
    if ":" in kind:  # package.module:factory(cfg) -> GuardrailEngine (a sponsor's own engine)
        mod, fn = kind.split(":", 1)
        return getattr(importlib.import_module(mod), fn)(cfg)
    raise ValueError(f"unknown guardrail engine {kind!r}")


def build_pipeline(config_path: str | os.PathLike | None = None, state_dir: str | os.PathLike | None = None,
                   env: dict | None = None) -> GuardrailPipeline:
    env = dict(os.environ) if env is None else env
    config_path = config_path or env.get("GOVGUARD_CONFIG", "/app/guardrails/guardrails.yaml")
    state = Path(state_dir or env.get("GOVGUARD_STATE_DIR", "/app/guardrails-state"))
    overlay = None
    if env.get("GOVGUARD_POLICY_STORE") and env.get("GOVGUARD_POLICY_TRUST"):
        overlay = GovpolicyOverlay(env["GOVGUARD_POLICY_STORE"], env["GOVGUARD_POLICY_TRUST"])
    cfg = GuardrailConfig.load(config_path, overlay)
    audit = JsonlAuditSink(cfg.audit_cfg.get("path") or state / "audit.jsonl")
    overrides = FileOverrideStore(state / "overrides", audit,
                                  int(cfg.overrides_cfg.get("max_ttl_seconds", DEFAULT_MAX_OVERRIDE_TTL)))
    approvals = FileApprovalStore(state / "approvals", audit)
    return GuardrailPipeline(cfg, make_engine(cfg.engine_cfg, env), overrides=overrides, approvals=approvals,
                             audit=audit)
