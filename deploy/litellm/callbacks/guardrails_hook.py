"""govpilot guardrails hook (T5): thin LiteLLM adapter over the engine-independent
`govguard` pipeline (services/guardrails/govguard, mounted at /opt/govguard).

  pre-call   async_pre_call_hook                       injection / secrets / PII (mask|block) / tool allowlist
  post-call  async_post_call_success_hook              tool allowlist + human approval, secrets, PII redaction
  streaming  async_post_call_streaming_iterator_hook   buffer -> same checks -> emit (see docs/results/T5.md)

Separate from budget_guard.py on purpose (different owner, different failure semantics).
Wired via deploy/litellm/config.yaml: callbacks: ["callbacks.guardrails_hook.guardrails_hook"].
Identity comes from the virtual key metadata (agent_id, team), never from request content.

Any unexpected error here FAILS CLOSED (request rejected, 500 guardrail_internal_error).
Set GOVGUARD_ENABLED=false to disable the hook entirely (e.g. a stack without the overlay).

Config (env): GOVGUARD_CONFIG (yaml), GOVGUARD_STATE_DIR (overrides/approvals/audit),
GOVGUARD_ENGINE (presidio|builtin|pkg:factory), GOVGUARD_PRESIDIO_*_URL,
GOVGUARD_POLICY_STORE + GOVGUARD_POLICY_TRUST (optional signed-bundle tightening).
NB: no `from __future__ import annotations` (module is loaded by path).
"""
import json
import logging
import os
import sys
import uuid

for _p in (os.environ.get("GOVGUARD_PATH", "/opt/govguard"), "/opt/govpolicy"):
    if _p and os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

from litellm.integrations.custom_logger import CustomLogger  # noqa: E402

log = logging.getLogger("govpilot.guardrails_hook")

GUARDED_CALL_TYPES = {"completion", "acompletion"}


def _reject(e):
    from litellm.proxy._types import ProxyException
    body = e.body()["error"]
    extra = {k: v for k, v in body.items() if k not in ("message", "type", "code", "param")}
    return ProxyException(message=e.message, type=e.etype, param=None, code=e.status, openai_code=e.code,
                          provider_specific_fields=extra or None)


class GuardrailsHook(CustomLogger):
    def __init__(self):
        super().__init__()
        self.enabled = os.environ.get("GOVGUARD_ENABLED", "true").lower() not in ("0", "false", "no")
        self._pipeline = None
        self._init_error = None

    # -- lazy build: the httpx client must be created inside the running event loop
    def pipeline(self):
        if self._pipeline is None:
            try:
                from govguard import build_pipeline
                self._pipeline = build_pipeline()
            except Exception as e:  # config/engine build failure: fail closed on every request
                self._init_error = e
                log.exception("guardrail pipeline could not be built")
                raise
        return self._pipeline

    @staticmethod
    def _ctx(user_api_key_dict, data):
        from govguard import CallContext
        md = getattr(user_api_key_dict, "metadata", None) or {}
        tmd = getattr(user_api_key_dict, "team_metadata", None) or {}
        agent = md.get("agent_id") or getattr(user_api_key_dict, "key_alias", None) or ""
        team = md.get("team") or tmd.get("team") or getattr(user_api_key_dict, "team_id", None)
        dmd = data.get("metadata") if isinstance(data.get("metadata"), dict) else {}
        approval = dmd.get("govguard_approval_id")
        if not approval:
            hdrs = ((data.get("proxy_server_request") or {}).get("headers")) or {}
            approval = hdrs.get("x-govguard-approval-id")
        rid = data.get("litellm_call_id") or uuid.uuid4().hex[:16]
        return CallContext(agent_id=str(agent), team=team, request_id=str(rid), approval_id=approval)

    def _fail_closed(self, exc):
        from govguard import GuardrailBlocked, PolicyUnavailable
        if isinstance(exc, GuardrailBlocked):
            return _reject(exc)
        if isinstance(exc, PolicyUnavailable):
            return _reject(GuardrailBlocked(503, "guardrail_unavailable", "policy_unavailable", str(exc)))
        log.exception("guardrail internal error (failing closed)")
        return _reject(GuardrailBlocked(500, "guardrail_error", "guardrail_internal_error",
                                        "Guardrail evaluation failed; request rejected (fail closed)."))

    # ------------------------------------------------------------------ pre-call
    async def async_pre_call_hook(self, user_api_key_dict, cache, data: dict, call_type):
        if not self.enabled or call_type not in GUARDED_CALL_TYPES:
            return data
        try:
            await self.pipeline().check_request(self._ctx(user_api_key_dict, data), data)
        except Exception as e:
            raise self._fail_closed(e)
        return data

    # ------------------------------------------------------------------ post-call (non-streaming)
    async def async_post_call_success_hook(self, data: dict, user_api_key_dict, response):
        if not self.enabled:
            return response
        choices = getattr(response, "choices", None)
        if not choices:
            return response
        try:
            from govguard.rules import message_tool_calls
            ctx = self._ctx(user_api_key_dict, data)
            for ch in choices:
                msg = getattr(ch, "message", None)
                if msg is None:
                    continue
                content = getattr(msg, "content", None)
                new, _ = await self.pipeline().check_response(ctx, content if isinstance(content, str) else None,
                                                              message_tool_calls(msg))
                if isinstance(content, str) and new != content:
                    msg.content = new
        except Exception as e:
            raise self._fail_closed(e)
        return response

    # ------------------------------------------------------------------ streaming
    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data: dict):
        if not self.enabled:
            async for c in response:
                yield c
            return
        try:
            ctx = self._ctx(user_api_key_dict, request_data)
            pol = self.pipeline().config.resolve(ctx.agent_id, ctx.team)
        except Exception as e:
            raise self._fail_closed(e)
        if pol.streaming == "passthrough":
            self.pipeline().audit.emit("guardrail.stream_passthrough", agent_id=ctx.agent_id,
                                       note="output guardrails NOT applied to this stream by policy")
            async for c in response:
                yield c
            return

        # buffer mode: hold the (max_tokens-bounded) stream, check the assembled message, then release.
        chunks = []
        async for c in response:
            chunks.append(c)
        text_parts, calls = [], {}
        for c in chunks:
            for ch in getattr(c, "choices", None) or []:
                d = getattr(ch, "delta", None)
                if d is None:
                    continue
                if getattr(d, "content", None):
                    text_parts.append(d.content)
                for tc in getattr(d, "tool_calls", None) or []:
                    slot = calls.setdefault(getattr(tc, "index", 0) or 0, {"name": "", "arguments": "", "id": None})
                    fn = getattr(tc, "function", None)
                    if fn is not None:
                        slot["name"] += getattr(fn, "name", None) or ""
                        slot["arguments"] += getattr(fn, "arguments", None) or ""
        content = "".join(text_parts)
        try:
            new, _ = await self.pipeline().check_response(ctx, content or None, list(calls.values()))
        except Exception as e:
            exc = self._fail_closed(e)
            for c in self._blocked_chunks(chunks, json.dumps({"error": {
                    "message": exc.message, "type": exc.type, "code": exc.openai_code,
                    **(exc.provider_specific_fields or {})}})):
                yield c
            return
        if content and new != content:
            done = False
            for c in chunks:
                mod = c
                for ch in getattr(c, "choices", None) or []:
                    d = getattr(ch, "delta", None)
                    if d is not None and getattr(d, "content", None):
                        mod = c
                        d.content = new if not done else ""
                        done = True
                yield mod
            return
        for c in chunks:
            yield c

    @staticmethod
    def _blocked_chunks(chunks, message: str):
        template = next((c for c in chunks if getattr(c, "choices", None)), None)
        if template is None:
            return []
        t = template.model_copy(deep=True)
        ch = t.choices[0]
        ch.delta.content = message
        ch.delta.tool_calls = None
        ch.finish_reason = "content_filter"
        return [t]


guardrails_hook = GuardrailsHook()
