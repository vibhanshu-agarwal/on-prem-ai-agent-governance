"""Guardrail policy: config-driven, resolved per agent/team, optionally tightened by the
signed policy bundle (services/policy, package `govpolicy`).

Resolution: defaults <- teams[team] <- agents[agent]  (dicts deep-merge, lists replace).

Source split (documented in docs/results/T5.md):
  guardrails.yaml   PII actions, injection threshold, secrets, tool allowlists + catalog,
                    fail modes per data classification. (govpolicy's agent schema rejects unknown
                    fields, so guardrail-specific settings cannot live in the signed bundle yet.)
  signed bundle     agent `capabilities` and `require_human_approval` are read from the verified
                    bundle when configured, and can only TIGHTEN the YAML: a tool whose class
                    needs a capability the agent was not granted is denied; actions listed in
                    require_human_approval always need approval.
"""
from __future__ import annotations

import copy
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import yaml

log = logging.getLogger("govpilot.guardrails")

CLASS_CAPABILITY = {"external_send": "external_send", "payment": "calls_tools",
                    "destructive_write": "calls_tools"}
FAIL_MODES = ("closed", "degrade", "open")


class PolicyUnavailable(Exception):
    """A configured policy source could not be read/verified (fail closed)."""


def deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = deep_merge(out[k], v)
        else:
            out[k] = copy.deepcopy(v)
    return out


@dataclass(frozen=True)
class EffectivePolicy:
    agent_id: str
    team: str | None
    known_agent: bool
    data_classification: str
    fail_mode: str
    pii_input_default: str                 # mask | block | allow
    pii_entities: dict[str, str]           # entity -> mask | block
    pii_output: str                        # redact | block | allow
    pii_output_entities: tuple[str, ...]
    score_threshold: float
    injection_action: str                  # block | neutralize | flag | off
    injection_threshold: int
    injection_scan: str                    # untrusted | all
    secrets_input: str                     # mask | block | allow
    secrets_output: str                    # redact | block | allow
    tools_allow: frozenset[str]
    tools_catalog: dict[str, dict]
    tools_on_violation: str                # block | strip
    approval_classes: frozenset[str]
    approval_actions: frozenset[str]
    approval_bind_arguments: bool
    approval_ttl_seconds: int
    streaming: str                         # buffer | passthrough
    raw: dict = field(default_factory=dict, compare=False, hash=False)

    def tool_class(self, name: str) -> str | None:
        return (self.tools_catalog.get(name) or {}).get("class")

    def tool_action(self, name: str) -> str | None:
        return (self.tools_catalog.get(name) or {}).get("action")


class SignedPolicyOverlay(Protocol):
    def agent(self, agent_id: str) -> dict | None:
        """{'capabilities': [...], 'require_human_approval': [...]} from a verified bundle."""


class GovpolicyOverlay:
    """Reads the active signed bundle via govpolicy (signature verified on every reload)."""

    def __init__(self, store_dir: str, trust_dir: str, refresh_seconds: float = 5.0):
        from govpolicy import Ed25519Verifier, PolicyStore  # imported lazily: optional dependency
        self._store = PolicyStore(Path(store_dir), Ed25519Verifier.from_trust_dir(Path(trust_dir)))
        self._refresh = refresh_seconds
        self._loaded_at = 0.0
        self._policy = None

    def _load(self):
        now = time.monotonic()
        if self._policy is not None and now - self._loaded_at < self._refresh:
            return self._policy
        try:
            self._policy = self._store.load_active().policy
            self._loaded_at = now
        except Exception as e:  # unsigned / tampered / missing: never continue on stale trust silently
            if self._policy is None:
                raise PolicyUnavailable(f"signed policy unavailable: {e}") from e
            log.error("signed policy reload failed, keeping last verified bundle: %s", e)
            self._loaded_at = now
        return self._policy

    def agent(self, agent_id: str) -> dict | None:
        pol = self._load()
        a = pol.agent(agent_id)
        if a is None:
            return None
        return {"capabilities": list(a.capabilities), "require_human_approval": list(a.require_human_approval)}


class GuardrailConfig:
    def __init__(self, raw: dict, overlay: SignedPolicyOverlay | None = None):
        self.raw = raw
        self.overlay = overlay
        self.engine_cfg = raw.get("engine") or {}
        self.overrides_cfg = raw.get("overrides") or {}
        self.audit_cfg = raw.get("audit") or {}
        self.fail_modes = {"public": "open", "internal": "degrade",
                           "confidential": "closed", "restricted": "closed",
                           **(raw.get("fail_modes") or {})}
        for c, m in self.fail_modes.items():
            if m not in FAIL_MODES:
                raise ValueError(f"fail_modes.{c}: {m!r} not in {FAIL_MODES}")
        self.defaults = raw.get("defaults") or {}
        self.teams = raw.get("teams") or {}
        self.agents = raw.get("agents") or {}
        self._cache: dict[tuple, EffectivePolicy] = {}

    @classmethod
    def load(cls, path: str | os.PathLike, overlay: SignedPolicyOverlay | None = None) -> "GuardrailConfig":
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        return cls(raw, overlay)

    def resolve(self, agent_id: str | None, team: str | None) -> EffectivePolicy:
        known = bool(agent_id) and agent_id in self.agents
        key = (agent_id, team)
        merged = deep_merge(self.defaults, self.teams.get(team or "", {}))
        merged = deep_merge(merged, self.agents.get(agent_id or "", {}))
        cls_ = str(merged.get("data_classification", "restricted"))
        fail_mode = self.fail_modes.get(cls_, "closed")
        pii = merged.get("pii") or {}
        ent = pii.get("entities") or {}
        if isinstance(ent, list):
            ent = {e: "default" for e in ent}
        default_in = pii.get("input", "mask")
        ent = {e: (default_in if a == "default" else a) for e, a in ent.items()}
        inj = merged.get("injection") or {}
        sec = merged.get("secrets") or {}
        tools = merged.get("tools") or {}
        appr = merged.get("approval") or {}
        allow = set(tools.get("allow") or [])
        classes = set(appr.get("required_classes") or [])
        actions = set(appr.get("required_actions") or [])

        # signed-bundle tightening (fails closed if configured but unreadable)
        if self.overlay is not None and agent_id:
            ov = self.overlay.agent(agent_id)
            if ov is None:
                allow = set()  # not in the signed policy: no tools
            else:
                caps = set(ov["capabilities"])
                if "calls_tools" not in caps:
                    allow = set()
                catalog = tools.get("catalog") or {}
                for t in list(allow):
                    need = CLASS_CAPABILITY.get((catalog.get(t) or {}).get("class") or "")
                    if need and need not in caps:
                        allow.discard(t)
                actions |= set(ov["require_human_approval"])

        return EffectivePolicy(
            agent_id=agent_id or "", team=team, known_agent=known,
            data_classification=cls_, fail_mode=fail_mode,
            pii_input_default=default_in, pii_entities=ent,
            pii_output=pii.get("output", "redact"),
            pii_output_entities=tuple(pii.get("output_entities") or list(ent)),
            score_threshold=float(pii.get("score_threshold", self.engine_cfg.get("score_threshold", 0.5))),
            injection_action=inj.get("action", "block"),
            injection_threshold=int(inj.get("threshold", 3)),
            injection_scan=inj.get("scan", "untrusted"),
            secrets_input=sec.get("input", "mask"), secrets_output=sec.get("output", "redact"),
            tools_allow=frozenset(allow), tools_catalog=dict(tools.get("catalog") or {}),
            tools_on_violation=tools.get("on_violation", "block"),
            approval_classes=frozenset(classes), approval_actions=frozenset(actions),
            approval_bind_arguments=bool(appr.get("bind_arguments", True)),
            approval_ttl_seconds=int(appr.get("ttl_seconds", 900)),
            streaming=merged.get("streaming", "buffer"), raw=merged)
