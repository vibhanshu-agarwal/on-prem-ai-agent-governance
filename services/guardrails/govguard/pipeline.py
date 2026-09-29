"""The guardrail pipeline: engine-independent orchestration of PII handling, deterministic
rules, overrides, approvals, fail modes and audit. Works on plain OpenAI-format dicts so it
is unit-testable without LiteLLM; deploy/litellm/callbacks/guardrails_hook.py is the thin
LiteLLM adapter.

Request phase  (pre-call):  injection on untrusted content, secrets, PII (mask/block), tool
                            declarations vs the agent allowlist.
Response phase (post-call): tool calls (allowlist, then human approval for consequential
                            actions), secrets, PII redaction.
"""
from __future__ import annotations

import asyncio
import hashlib
import re
import time
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any, Callable

from .builtin_engine import BuiltinEngine
from .engine import EngineUnavailable, GuardrailEngine, Span
from .policy import EffectivePolicy, GuardrailConfig
from .rules import (args_digest, declared_tool_names, find_secrets, iter_text_parts, message_tool_calls,
                    redact_secrets, scan_injection)
from .state import AuditSink, FileApprovalStore, MemoryAuditSink, NullOverrideStore

NEUTRALISED = "[content removed by guardrail: suspected prompt injection]"
_TAG = re.compile(r"<(untrusted[\w-]*)(?:\s[^>]*)?>(.*?)</\1>", re.S | re.I)
JOIN = "\n\n"


class GuardrailBlocked(Exception):
    def __init__(self, status: int, etype: str, code: str, message: str, **extra: Any):
        super().__init__(message)
        self.status, self.etype, self.code, self.message, self.extra = status, etype, code, message, extra

    def body(self) -> dict:
        return {"error": {"message": self.message, "type": self.etype, "code": self.code, "param": None, **self.extra}}


@dataclass
class CallContext:
    agent_id: str
    team: str | None = None
    request_id: str | None = None
    approval_id: str | None = None


@dataclass
class Outcome:
    findings: list[dict] = field(default_factory=list)
    modified: bool = False
    degraded: bool = False
    total_ms: float = 0.0
    engine_ms: float = 0.0


@dataclass
class _Unit:
    mi: int
    pi: int | None
    role: str
    text: str
    untrusted: bool


class _LRU:
    def __init__(self, size: int):
        self.size, self.d = size, OrderedDict()

    def get(self, k):
        v = self.d.get(k)
        if v is not None:
            self.d.move_to_end(k)
        return v

    def put(self, k, v):
        self.d[k] = v
        self.d.move_to_end(k)
        while len(self.d) > self.size:
            self.d.popitem(last=False)


def _pct(vals: list[float], p: float) -> float:
    s = sorted(vals)
    return s[min(len(s) - 1, max(0, int(round(p / 100 * len(s) + 0.5)) - 1))] if s else 0.0


class GuardrailPipeline:
    def __init__(self, config: GuardrailConfig, engine: GuardrailEngine, *, fallback: GuardrailEngine | None = None,
                 overrides=None, approvals: FileApprovalStore | None = None, audit: AuditSink | None = None,
                 clock: Callable[[], float] = time.time):
        self.config, self.engine = config, engine
        self.fallback = fallback or BuiltinEngine()
        self.overrides = overrides or NullOverrideStore()
        self.audit = audit or MemoryAuditSink()
        self.approvals = approvals
        self.clock = clock
        self.cache = _LRU(int(config.engine_cfg.get("cache_size", 4096)))
        self.record_clean = bool((config.audit_cfg or {}).get("record_clean", False))
        self.latency: dict[str, deque] = {"request": deque(maxlen=20000), "response": deque(maxlen=20000)}

    # ------------------------------------------------------------------ helpers
    def latency_summary(self, phase: str = "request") -> dict:
        v = list(self.latency[phase])
        return {"n": len(v), "p50_ms": round(_pct(v, 50), 2), "p95_ms": round(_pct(v, 95), 2),
                "p99_ms": round(_pct(v, 99), 2), "max_ms": round(max(v), 2) if v else 0.0}

    def _evt(self, ctx: CallContext, event: str, **f: Any) -> None:
        self.audit.emit(event, agent_id=ctx.agent_id, team=ctx.team, request_id=ctx.request_id, **f)

    def _override(self, ctx: CallContext, active: dict, rule: str, **detail) -> dict | None:
        rec = active.get(rule)
        if rec is None and "." in rule:
            rec = active.get(rule.split(".", 1)[0])  # category override: `pii` covers `pii.X`
        if rec:
            self._evt(ctx, "override.used", override_id=rec["id"], rule=rule, granted_by=rec["granted_by"],
                      expires_at=rec["expires_at"], **detail)
        return rec

    def _blocked(self, ctx: CallContext, rule: str, e: GuardrailBlocked, **detail) -> GuardrailBlocked:
        self._evt(ctx, "guardrail.blocked", rule=rule, code=e.code, status=e.status, **detail)
        return e

    async def _engine_call(self, ctx: CallContext, pol: EffectivePolicy, out: Outcome, fn_name: str, *args):
        """Call the engine; on EngineUnavailable apply the fail mode of the agent's data classification."""
        t = time.perf_counter()
        try:
            return await getattr(self.engine, fn_name)(*args)
        except EngineUnavailable as e:
            mode = pol.fail_mode
            self._evt(ctx, "engine.unavailable", engine=self.engine.name, fail_mode=mode,
                      data_classification=pol.data_classification, error=str(e)[:200])
            if mode == "closed":
                # T8 break-glass: a time-limited, audited grant degrades (never opens) this agent to the builtin engine
                bg = self._override(ctx, self.overrides.active_rules(ctx.agent_id), "breakglass",
                                    engine=self.engine.name, data_classification=pol.data_classification)
                if bg:
                    self._evt(ctx, "guardrail.breakglass_degraded", override_id=bg["id"], granted_by=bg["granted_by"])
                    out.degraded = True
                    return await getattr(self.fallback, fn_name)(*args)
            if mode == "closed":
                raise self._blocked(ctx, "engine", GuardrailBlocked(
                    503, "guardrail_unavailable", "guardrail_engine_unavailable",
                    "The PII guardrail engine is unavailable and this agent's data classification "
                    f"({pol.data_classification}) requires fail-closed. Request rejected."), fail_mode=mode)
            out.degraded = True
            if mode == "degrade":
                return await getattr(self.fallback, fn_name)(*args)
            return None  # open: skip this check (audited above)
        finally:
            out.engine_ms += (time.perf_counter() - t) * 1000

    # ------------------------------------------------------------------ PII analysis
    async def _analyze_texts(self, ctx, pol, out, texts: list[str], entities: list[str]) -> list[list[Span]] | None:
        """Spans per text (None => skipped by fail-open). Cached per message hash; uncached texts
        are analysed in ONE engine call (joined) so a multi-message prompt costs one round trip."""
        thr = pol.engine_threshold()
        ekey = (tuple(sorted(entities)), thr)
        result: list[list[Span] | None] = [None] * len(texts)
        todo: list[int] = []
        for i, t in enumerate(texts):
            hit = self.cache.get((hashlib.sha256(t.encode()).hexdigest(), ekey))
            if hit is not None:
                result[i] = hit
            else:
                todo.append(i)
        if todo:
            joined, offs, pos = "", [], 0
            for i in todo:
                joined += (JOIN if offs else "") + texts[i]
                start = len(joined) - len(texts[i])
                offs.append((i, start, start + len(texts[i])))
            lang = self.config.engine_cfg.get("language", "en")
            spans = await self._engine_call(ctx, pol, out, "analyze", joined, entities, lang, thr)
            if spans is None:
                return None
            for i, s, e in offs:
                own = [Span(x.entity_type, x.start - s, x.end - s, x.score) for x in spans
                       if x.start >= s and x.end <= e]
                result[i] = own
                if not out.degraded:  # never cache fallback-engine answers as if they were the engine's
                    self.cache.put((hashlib.sha256(texts[i].encode()).hexdigest(), ekey), own)
        return [[x for x in r if x.score >= pol.min_score(x.entity_type)] for r in result]  # type: ignore[union-attr]

    async def _mask(self, ctx, pol, out, text: str, spans: list[Span]) -> str:
        r = await self._engine_call(ctx, pol, out, "anonymize", text, spans)
        return r if r is not None else text

    # ------------------------------------------------------------------ request phase
    @staticmethod
    def _set(messages: list, u: _Unit, text: str) -> None:
        m = messages[u.mi]
        if u.pi is None:
            m["content"] = text
        else:
            m["content"][u.pi] = {**m["content"][u.pi], "text": text}

    async def check_request(self, ctx: CallContext, data: dict) -> Outcome:
        t0 = time.perf_counter()
        out = Outcome()
        pol = self.config.resolve(ctx.agent_id, ctx.team)  # PolicyUnavailable propagates (fail closed)
        active = self.overrides.active_rules(ctx.agent_id)
        messages = data.get("messages")
        messages = messages if isinstance(messages, list) else []
        for m in messages:  # the `untrusted` marker is ours; never forward it to the provider
            if isinstance(m, dict) and "untrusted" in m:
                m["_govguard_untrusted"] = bool(m.pop("untrusted"))
        units = self._units_from_marked(messages)

        # 1. prompt-injection screen on untrusted content (deterministic, ~ms)
        if pol.injection_action != "off":
            for u in units:
                if pol.injection_scan == "all":
                    if u.role in ("system", "developer"):
                        continue
                    targets = [(u.text, None)]
                elif u.untrusted:
                    targets = [(u.text, None)]
                else:
                    targets = [(m.group(2), m) for m in _TAG.finditer(u.text)]
                for text, tag in targets:
                    res = scan_injection(text)
                    if res.score < pol.injection_threshold:
                        continue
                    detail = {"score": res.score, "patterns": list(res.matched), "role": u.role}
                    if self._override(ctx, active, "injection", **detail):
                        out.findings.append({"rule": "injection", "action": "overridden", **detail})
                        continue
                    if pol.injection_action == "block":
                        out.findings.append({"rule": "injection", "action": "block", **detail})
                        raise self._blocked(ctx, "injection", GuardrailBlocked(
                            400, "guardrail_violation", "prompt_injection_detected",
                            "Untrusted content looks like a prompt injection and was rejected.",
                            rule="injection", patterns=list(res.matched)), **detail)
                    if pol.injection_action == "neutralize":
                        new = u.text.replace(tag.group(0), NEUTRALISED) if tag else NEUTRALISED
                        self._set(messages, u, new)
                        u.text = new
                        out.modified = True
                    out.findings.append({"rule": "injection", "action": pol.injection_action, **detail})
                    self._evt(ctx, "guardrail.injection_" + pol.injection_action, **detail)

        # 2. secrets on input (every role: the calling agent writes its own system prompt, so a system
        #    message is not trusted operator config and must not be a channel around the check)
        if pol.secrets_input != "allow":
            for u in units:
                if not find_secrets(u.text):
                    continue
                red, kinds = redact_secrets(u.text)
                if self._override(ctx, active, "secrets", kinds=kinds):
                    out.findings.append({"rule": "secrets", "action": "overridden", "kinds": kinds})
                    continue
                if pol.secrets_input == "block":
                    out.findings.append({"rule": "secrets", "action": "block", "kinds": kinds})
                    raise self._blocked(ctx, "secrets", GuardrailBlocked(
                        400, "guardrail_violation", "secret_in_input",
                        "The prompt contains a credential/secret pattern and was rejected.",
                        rule="secrets", kinds=kinds), kinds=kinds)
                self._set(messages, u, red)
                u.text = red
                out.modified = True
                out.findings.append({"rule": "secrets", "action": "mask", "kinds": kinds})
                self._evt(ctx, "guardrail.secrets_masked", kinds=kinds, where="input")

        # 3. PII on input
        pii_units = [u for u in units if u.role in (pol.raw.get("pii") or {}).get("scan_roles",
                                                    ["system", "developer", "user", "tool", "function", "assistant"]) and len(u.text) >= 6]
        if pol.pii_entities and pii_units:
            spans_per = await self._analyze_texts(ctx, pol, out, [u.text for u in pii_units], list(pol.pii_entities))
            if spans_per is not None:
                blocked: dict[str, int] = {}
                masks: list[tuple[_Unit, list[Span]]] = []
                for u, spans in zip(pii_units, spans_per):
                    keep = []
                    for s in spans:
                        act = pol.pii_entities.get(s.entity_type, "allow")
                        if act == "allow":
                            continue
                        if self._override(ctx, active, f"pii.{s.entity_type}", entity=s.entity_type):
                            out.findings.append({"rule": f"pii.{s.entity_type}", "action": "overridden"})
                            continue
                        if act == "block":
                            blocked[s.entity_type] = blocked.get(s.entity_type, 0) + 1
                        keep.append(s)
                    if keep:
                        masks.append((u, keep))
                if blocked:
                    out.findings.append({"rule": "pii", "action": "block", "entities": blocked})
                    raise self._blocked(ctx, "pii", GuardrailBlocked(
                        400, "guardrail_violation", "pii_blocked",
                        "The prompt contains PII that this agent's policy does not allow to reach the model.",
                        rule="pii", entities=blocked), entities=blocked, direction="input")
                if masks:
                    new_texts = await asyncio.gather(*[self._mask(ctx, pol, out, u.text, sp) for u, sp in masks])
                    counts: dict[str, int] = {}
                    for (u, sp), new in zip(masks, new_texts):
                        self._set(messages, u, new)
                        u.text = new
                        for s in sp:
                            counts[s.entity_type] = counts.get(s.entity_type, 0) + 1
                    out.modified = True
                    out.findings.append({"rule": "pii", "action": "mask", "entities": counts})
                    self._evt(ctx, "guardrail.pii_masked", entities=counts, direction="input")
        for m in messages:
            if isinstance(m, dict):
                m.pop("_govguard_untrusted", None)

        # 4. tool authorization on what the request declares / replays
        names = declared_tool_names(data) + [c["name"] for m in messages if isinstance(m, dict)
                                              and m.get("role") == "assistant" for c in message_tool_calls(m)]
        bad = sorted({n for n in names if n not in pol.tools_allow})
        for n in bad:
            if self._override(ctx, active, f"tool.{n}", tool=n):
                out.findings.append({"rule": f"tool.{n}", "action": "overridden"})
                continue
            if pol.tools_on_violation == "strip" and n in declared_tool_names(data):
                self._strip_tool(data, n)
                out.modified = True
                out.findings.append({"rule": f"tool.{n}", "action": "strip"})
                self._evt(ctx, "guardrail.tool_stripped", tool=n)
                continue
            out.findings.append({"rule": f"tool.{n}", "action": "block"})
            raise self._blocked(ctx, f"tool.{n}", GuardrailBlocked(
                403, "guardrail_violation", "tool_not_authorized",
                f"Tool {n!r} is not in this agent's allowlist.", rule=f"tool.{n}", tool=n), tool=n, phase="request")

        out.total_ms = (time.perf_counter() - t0) * 1000
        self.latency["request"].append(out.total_ms)
        if out.findings or out.degraded or self.record_clean:
            self._evt(ctx, "guardrail.request", total_ms=round(out.total_ms, 2), engine_ms=round(out.engine_ms, 2),
                      engine=self.engine.name, degraded=out.degraded, known_agent=pol.known_agent,
                      findings=[{k: v for k, v in f.items() if k != "patterns"} for f in out.findings],
                      chars=sum(len(u.text) for u in units))
        return out

    def _units_from_marked(self, messages: list) -> list[_Unit]:
        units = []
        for mi, m in enumerate(messages):
            if not isinstance(m, dict):
                continue
            role = str(m.get("role", "")).strip().lower()   # "Tool" must not dodge the untrusted screen
            flagged = role in ("tool", "function") or bool(m.get("_govguard_untrusted"))
            for pi, text in iter_text_parts(m.get("content")):
                units.append(_Unit(mi, pi, role, text, flagged))
        return units

    @staticmethod
    def _strip_tool(data: dict, name: str) -> None:
        def nm(t):
            fn = t.get("function") if isinstance(t, dict) and isinstance(t.get("function"), dict) else t
            return fn.get("name") if isinstance(fn, dict) else None
        if data.get("tools"):
            data["tools"] = [t for t in data["tools"] if nm(t) != name]
            if not data["tools"]:
                data.pop("tools")
                data.pop("tool_choice", None)
        if data.get("functions"):
            data["functions"] = [f for f in data["functions"] if f.get("name") != name]
        tc = data.get("tool_choice")
        if isinstance(tc, dict) and (tc.get("function") or {}).get("name") == name:
            data.pop("tool_choice")

    # ------------------------------------------------------------------ response phase
    async def check_response(self, ctx: CallContext, content: str | None, tool_calls: list[dict] | None) -> tuple[str | None, Outcome]:
        """Returns (possibly redacted content, outcome). Raises GuardrailBlocked to withhold the response."""
        t0 = time.perf_counter()
        out = Outcome()
        pol = self.config.resolve(ctx.agent_id, ctx.team)
        active = self.overrides.active_rules(ctx.agent_id)

        # 1. tool calls: allowlist first, then human approval for consequential actions
        pending: list[dict] = []
        for c in tool_calls or []:
            n = c["name"]
            if n not in pol.tools_allow:
                if self._override(ctx, active, f"tool.{n}", tool=n):
                    out.findings.append({"rule": f"tool.{n}", "action": "overridden"})
                else:
                    out.findings.append({"rule": f"tool.{n}", "action": "block"})
                    raise self._blocked(ctx, f"tool.{n}", GuardrailBlocked(
                        403, "guardrail_violation", "tool_not_authorized",
                        f"The model requested tool {n!r}, which is not in this agent's allowlist. Response withheld.",
                        rule=f"tool.{n}", tool=n), tool=n, phase="response")
            klass, action = pol.tool_class(n), pol.tool_action(n)
            if klass in pol.approval_classes or n in pol.approval_actions or (action and action in pol.approval_actions):
                digest = args_digest(c.get("arguments"))
                if ctx.approval_id and self.approvals is not None:
                    ok, why = self.approvals.consume(ctx.approval_id, ctx.agent_id, n, digest)
                    if ok:
                        out.findings.append({"rule": f"approval.{n}", "action": "approved"})
                        continue
                    self._evt(ctx, "approval.rejected", approval_id=ctx.approval_id, tool=n, reason=why)
                if self.approvals is None:  # no approval store configured: consequential actions cannot proceed
                    raise self._blocked(ctx, f"approval.{n}", GuardrailBlocked(
                        503, "guardrail_unavailable", "approval_store_unavailable",
                        "Human approval is required but no approval store is configured."), tool=n)
                rec = self.approvals.create_pending(
                    agent_id=ctx.agent_id, tool=n, action=action, action_class=klass, args_digest=digest,
                    request_id=ctx.request_id, ttl_seconds=pol.approval_ttl_seconds,
                    bind_arguments=pol.approval_bind_arguments)
                pending.append({"approval_id": rec["id"], "tool": n, "action": action, "class": klass,
                                "arguments_digest": digest, "expires_at": rec["expires_at"]})
        if pending:
            out.findings.append({"rule": "approval", "action": "pending", "n": len(pending)})
            raise GuardrailBlocked(
                428, "approval_required", "pending_approval",
                "Consequential action(s) require human approval. The model response was withheld; "
                "approve via the approvals workflow, then retry with metadata.govguard_approval_id.",
                state="pending_approval", pending=pending)

        if content:
            # 2. secrets on output
            if pol.secrets_output != "allow" and find_secrets(content):
                red, kinds = redact_secrets(content)
                if self._override(ctx, active, "secrets", kinds=kinds):
                    out.findings.append({"rule": "secrets", "action": "overridden", "kinds": kinds})
                elif pol.secrets_output == "block":
                    out.findings.append({"rule": "secrets", "action": "block", "kinds": kinds})
                    raise self._blocked(ctx, "secrets", GuardrailBlocked(
                        403, "guardrail_violation", "secret_in_output",
                        "The model output contained a credential/secret pattern and was withheld.",
                        rule="secrets", kinds=kinds), kinds=kinds, direction="output")
                else:
                    content, out.modified = red, True
                    out.findings.append({"rule": "secrets", "action": "redact", "kinds": kinds})
                    self._evt(ctx, "guardrail.secrets_redacted", kinds=kinds, where="output")

            # 3. PII on output
            if pol.pii_output != "allow" and pol.pii_output_entities and len(content) >= 6:
                spans_per = await self._analyze_texts(ctx, pol, out, [content], list(pol.pii_output_entities))
                if spans_per is not None:
                    keep = []
                    for s in spans_per[0]:
                        if self._override(ctx, active, f"pii.{s.entity_type}", entity=s.entity_type):
                            out.findings.append({"rule": f"pii.{s.entity_type}", "action": "overridden"})
                        else:
                            keep.append(s)
                    if keep:
                        counts: dict[str, int] = {}
                        for s in keep:
                            counts[s.entity_type] = counts.get(s.entity_type, 0) + 1
                        if pol.pii_output == "block":
                            out.findings.append({"rule": "pii", "action": "block", "entities": counts})
                            raise self._blocked(ctx, "pii", GuardrailBlocked(
                                403, "guardrail_violation", "pii_in_output_blocked",
                                "The model output contained PII and was withheld.", rule="pii", entities=counts),
                                entities=counts, direction="output")
                        content = await self._mask(ctx, pol, out, content, keep)
                        out.modified = True
                        out.findings.append({"rule": "pii", "action": "redact", "entities": counts})
                        self._evt(ctx, "guardrail.pii_redacted", entities=counts, direction="output")

        out.total_ms = (time.perf_counter() - t0) * 1000
        self.latency["response"].append(out.total_ms)
        if out.findings or out.degraded or self.record_clean:
            self._evt(ctx, "guardrail.response", total_ms=round(out.total_ms, 2), engine_ms=round(out.engine_ms, 2),
                      engine=self.engine.name, degraded=out.degraded,
                      findings=[{k: v for k, v in f.items() if k != "patterns"} for f in out.findings])
        return content, out
