"""Run attribution for the LiteLLM gateway (T4).

Every LLM request must be attributable to: agent, run, parent run, user, team,
provider, model, tokens and cost. LiteLLM already knows the key (agent), team,
provider, model, tokens and cost. What only the caller knows is the *run*, so
agents send it as request headers (see agents/govagent/context.py):

  x-govpilot-run-id         this unit of work                 (required when enforced)
  x-govpilot-parent-run-id  the run that caused it            (tool call, delegation)
  x-govpilot-root-run-id    the top of the run tree
  x-govpilot-run-kind       task | tool | delegation
  x-govpilot-step           1-based number of the LLM call within the run (a run may make several)
  x-govpilot-attempt        1-based attempt number of that call; retries KEEP the run id and the step
  x-govpilot-tool           tool name when kind == tool
  x-govpilot-user           the human/employee the work is done for (also the OpenAI `user` field)

This callback (a separate file from budget_guard, nothing shared but the hook API):

  pre-call   validates the run headers, then stamps the trusted identity of the caller
             (agent id and team come from the virtual key, never from the request) and the
             run fields into `metadata.spend_logs_metadata`, which LiteLLM persists in
             `LiteLLM_SpendLogs.metadata`. Also sets the spend-log session id to the run id.
             Missing/invalid run id: `enforce` rejects with 400 `run_id_required` (400 `run_fields_invalid` when the
             run id is fine but the tree fields are not); `audit` lets it through, stamps
             `attribution: missing_run_id` and emits an event.
  headers    echoes x-govpilot-run-id / x-govpilot-attribution on the response.
  post-call  one `GOVPILOT_ATTRIBUTION {json}` line per attempt, success or failure, so failed
             attempts (which never reach the spend table) are still attributable.

Policy (key metadata > team metadata > env), all optional:
  metadata.attribution: {"mode": "enforce" | "audit" | "off"}   (present but unreadable -> enforce)
  env GOVPILOT_ATTRIBUTION_MODE (default "audit")

Loose coupling: the only environment-specific things are the header names (constants
below) and the mode; the event sink is a port (`AttributionEventSink`) with one adapter (log).
"""
from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any, Protocol
from urllib.parse import urlparse

from fastapi import HTTPException
from litellm.integrations.custom_logger import CustomLogger

log = logging.getLogger("govpilot.run_attribution")

H_RUN, H_PARENT, H_ROOT = "x-govpilot-run-id", "x-govpilot-parent-run-id", "x-govpilot-root-run-id"
H_KIND, H_ATTEMPT, H_TOOL, H_USER = "x-govpilot-run-kind", "x-govpilot-attempt", "x-govpilot-tool", "x-govpilot-user"
H_STEP = "x-govpilot-step"
RUN_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{5,79}$")
KINDS = {"task", "tool", "delegation"}
MODES = ("enforce", "audit", "off")
# call types that spend money at a provider
LLM_CALL_TYPES = {"completion", "acompletion", "text_completion", "atext_completion", "responses", "aresponses",
                  "embeddings", "aembedding", "anthropic_messages", "generate_content", "agenerate_content"}
# call types that never reach a provider: left alone even in `enforce`. Every other call type (image,
# audio, rerank, pass-through, ones a future LiteLLM adds) is treated as spending, so `enforce` fails closed.
NON_SPEND_CALL_TYPES = {"list_models", "model_info", "health", "health_check", "token_counter", "count_tokens"}
# keys the caller may never set through spend_logs_metadata: they are stamped from trusted sources
RESERVED = {"agent_id", "team", "key_alias", "run_id", "parent_run_id", "root_run_id", "run_kind", "attempt",
            "tool", "attribution", "root_agent_id", "parent_agent_id", "user", "step"}


class AttributionEventSink(Protocol):
    def emit(self, event: dict) -> None: ...


class LogEventSink:
    """One `GOVPILOT_ATTRIBUTION {json}` line on gateway stdout (a log shipper or the T6 pipeline reads it)."""
    PREFIX = "GOVPILOT_ATTRIBUTION "

    def emit(self, event: dict) -> None:
        log.warning("%s%s", self.PREFIX, json.dumps(event, default=str, separators=(",", ":")))


SINKS = {"log": LogEventSink}


class RunFields:
    # plain class: this module is loaded by LiteLLM without a sys.modules entry, which breaks @dataclass
    __slots__ = ("run_id", "parent_run_id", "root_run_id", "kind", "attempt", "tool", "user", "problems", "step")

    def __init__(self, run_id, parent_run_id, root_run_id, kind, attempt, tool, user, problems, step=1):
        self.step = step
        self.run_id, self.parent_run_id, self.root_run_id = run_id, parent_run_id, root_run_id
        self.kind, self.attempt, self.tool, self.user, self.problems = kind, attempt, tool, user, problems


def _headers(data: dict) -> dict[str, str]:
    raw = ((data.get("proxy_server_request") or {}).get("headers")
           or (data.get("metadata") or {}).get("headers") or {})
    return {str(k).lower(): str(v) for k, v in raw.items()}


def _client_meta(data: dict, headers: dict[str, str]) -> dict:
    """Run fields a caller may also have put in `x-litellm-spend-logs-metadata` or the body."""
    out: dict = {}
    try:
        h = headers.get("x-litellm-spend-logs-metadata")
        if h:
            v = json.loads(h)
            if isinstance(v, dict):
                out.update(v)
    except ValueError:
        pass
    md = data.get("metadata") or {}
    v = md.get("spend_logs_metadata")
    if isinstance(v, dict):
        out.update(v)
    return out


def parse_run_fields(data: dict) -> tuple[RunFields, dict]:
    """Pure function (unit tested): request data -> validated run fields + the client's extra metadata."""
    h = _headers(data)
    cm = _client_meta(data, h)
    problems: list[str] = []

    def pick(header: str, key: str) -> str | None:
        v = h.get(header) or cm.get(key)
        return str(v).strip() if v not in (None, "") else None

    run_id, parent, root = pick(H_RUN, "run_id"), pick(H_PARENT, "parent_run_id"), pick(H_ROOT, "root_run_id")
    kind = pick(H_KIND, "run_kind") or "task"
    tool = pick(H_TOOL, "tool")
    user = pick(H_USER, "user") or (str(data["user"]) if data.get("user") else None)
    try:
        attempt = int(pick(H_ATTEMPT, "attempt") or 1)
    except ValueError:
        attempt, problems = 1, problems + ["attempt is not an integer"]
    try:
        step = int(pick(H_STEP, "step") or 1)
    except ValueError:
        step, problems = 1, problems + ["step is not an integer"]
    if not (1 <= step <= 100000):
        step, problems = 1, problems + ["step must be 1..100000"]
    if run_id is None:
        problems.append("missing run id (send x-govpilot-run-id)")
    elif not RUN_ID_RE.match(run_id):
        problems.append("run id must match " + RUN_ID_RE.pattern)
        run_id = None
    if parent is not None and not RUN_ID_RE.match(parent):
        problems.append("parent run id is malformed")
        parent = None
    if parent is not None and parent == run_id:
        problems.append("a run cannot be its own parent")
        parent = None
    if root is not None and not RUN_ID_RE.match(root):
        problems.append("root run id is malformed")
        root = None
    if kind not in KINDS:
        problems.append(f"run kind must be one of {sorted(KINDS)}")
        kind = "task"
    if not (1 <= attempt <= 999):
        problems.append("attempt must be 1..999")
        attempt = 1
    if run_id and parent is None and kind != "task":
        problems.append(f"a {kind} run needs a parent run id")
    if run_id and root is None:
        root = run_id if parent is None else None
    extra = {k: v for k, v in cm.items() if k not in RESERVED}
    return RunFields(run_id, parent, root, kind, attempt, tool, user, problems, step), extra


def _key_identity(u: Any) -> dict:
    md = getattr(u, "metadata", None) or {}
    return {"agent_id": md.get("agent_id") or getattr(u, "key_alias", None),
            "key_alias": getattr(u, "key_alias", None),
            "team": getattr(u, "team_alias", None) or md.get("team") or getattr(u, "team_id", None),
            "root_agent_id": md.get("root_agent_id"), "parent_agent_id": md.get("parent_agent_id")}


def resolve_mode(user_api_key_dict: Any, default: str) -> str:
    """Key metadata > team metadata > default. A policy that is present but unreadable (a typo such as
    "Enforce", a wrong type) resolves to `enforce`: a misconfigured key must fail closed, not silently audit."""
    for src in ("metadata", "team_metadata"):
        md = getattr(user_api_key_dict, src, None)
        if not isinstance(md, dict) or md.get("attribution") is None:
            continue
        pol = md["attribution"]
        mode = pol.get("mode") if isinstance(pol, dict) else pol
        return mode if mode in MODES else "enforce"
    return default


def _reject(status: int, etype: str, message: str) -> Exception:
    try:
        from litellm.proxy._types import ProxyException
        return ProxyException(message=message, type=etype, param=None, code=status)
    except Exception:  # pragma: no cover
        return HTTPException(status_code=status, detail={"error": message, "type": etype})


class RunAttribution(CustomLogger):
    def __init__(self, sink: AttributionEventSink | None = None, default_mode: str | None = None) -> None:
        super().__init__()
        self.sink = sink or SINKS[os.getenv("GOVPILOT_ATTRIBUTION_SINK", "log")]()
        self.default_mode = default_mode or os.getenv("GOVPILOT_ATTRIBUTION_MODE", "audit")
        if self.default_mode not in MODES:
            log.error("GOVPILOT_ATTRIBUTION_MODE=%r is not one of %s; using enforce", self.default_mode, MODES)
            self.default_mode = "enforce"

    def _emit(self, ev: dict) -> None:
        try:
            self.sink.emit(ev)
        except Exception:  # auditing must never break the request path
            log.exception("attribution sink failed")

    # ------------------------------------------------------------------ pre-call
    async def async_pre_call_hook(self, user_api_key_dict, cache, data: dict, call_type):
        ct = str(call_type).split(".")[-1]
        mode = resolve_mode(user_api_key_dict, self.default_mode)
        if mode == "off" or ct in NON_SPEND_CALL_TYPES:
            return data
        if ct not in LLM_CALL_TYPES and mode != "enforce":
            return data     # audit: only the known LLM routes are stamped; enforce covers every route
        rf, extra = parse_run_fields(data)
        ident = _key_identity(user_api_key_dict)
        if rf.run_id is None:
            self._emit({"event": "attribution.rejected" if mode == "enforce" else "attribution.missing_run_id",
                        "ts": time.time(), "mode": mode, "problems": rf.problems, "model": data.get("model"),
                        **ident})
            if mode == "enforce":
                raise _reject(400, "run_id_required",
                              "Every request must carry a valid run id (x-govpilot-run-id): " + "; ".join(rf.problems))
        elif rf.problems:
            # run id is fine but the run fields are not (a tool run with no parent, a bad attempt/step): the tree
            # would be wrong, so `enforce` refuses; `audit` keeps the request and records the problem
            self._emit({"event": "attribution.rejected" if mode == "enforce" else "attribution.warning",
                        "ts": time.time(), "mode": mode, "run_id": rf.run_id, "problems": rf.problems, **ident})
            if mode == "enforce":
                raise _reject(400, "run_fields_invalid", "Invalid run fields: " + "; ".join(rf.problems))
        md = data.setdefault("metadata", {})
        sl = dict(extra)
        sl.update({"agent_id": ident["agent_id"], "team": ident["team"], "key_alias": ident["key_alias"],
                   "root_agent_id": ident["root_agent_id"], "parent_agent_id": ident["parent_agent_id"],
                   "run_id": rf.run_id, "parent_run_id": rf.parent_run_id, "root_run_id": rf.root_run_id,
                   "run_kind": rf.kind, "step": rf.step, "attempt": rf.attempt, "tool": rf.tool,
                   "user": rf.user,
                   "attribution": "ok" if rf.run_id else "missing_run_id"})
        md["spend_logs_metadata"] = {k: v for k, v in sl.items() if v is not None}
        if rf.run_id:
            data["litellm_session_id"] = rf.run_id     # spend-log `session_id` column = run id
        if rf.user and not data.get("user"):
            data["user"] = rf.user                      # spend-log `end_user`
        tags = list(md.get("tags") or [])
        if ident["agent_id"]:
            tags.append(f"agent:{ident['agent_id']}")   # low cardinality only (never one tag per run)
        if tags:
            md["tags"] = tags
        return data

    # ------------------------------------------------------------------ response headers
    async def async_post_call_response_headers_hook(self, data, user_api_key_dict, response,
                                                    request_headers=None, litellm_call_info=None):
        sl = (data.get("metadata") or {}).get("spend_logs_metadata") or {}
        if not sl.get("run_id"):
            return None
        out = {"x-govpilot-run-id": str(sl["run_id"]), "x-govpilot-attribution": str(sl.get("attribution", "ok")),
               "x-govpilot-step": str(sl.get("step", 1)), "x-govpilot-attempt": str(sl.get("attempt", 1))}
        if sl.get("agent_id"):
            out["x-govpilot-agent"] = str(sl["agent_id"])
        return out

    # ------------------------------------------------------------------ per-attempt event
    def _event(self, kind: str, kwargs: dict, response_obj: Any, status: str, start, end) -> None:
        lp = kwargs.get("litellm_params") or {}
        md = lp.get("metadata") or {}
        sl = md.get("spend_logs_metadata") or {}
        if not sl.get("run_id") and not sl.get("attribution"):
            return
        usage = getattr(response_obj, "usage", None) if response_obj is not None else None
        api_base = lp.get("api_base") or (kwargs.get("model_info") or {}).get("api_base") or ""
        err = kwargs.get("exception")
        self._emit({
            "event": kind, "ts": time.time(), "status": status,
            "litellm_call_id": kwargs.get("litellm_call_id"), "agent_id": sl.get("agent_id"), "team": sl.get("team"),
            "run_id": sl.get("run_id"), "parent_run_id": sl.get("parent_run_id"), "root_run_id": sl.get("root_run_id"),
            "run_kind": sl.get("run_kind"), "step": sl.get("step"), "attempt": sl.get("attempt"), "tool": sl.get("tool"),
            "user": sl.get("user"), "model": md.get("model_group") or kwargs.get("model"),
            "provider": urlparse(str(api_base)).hostname or kwargs.get("custom_llm_provider"),
            "prompt_tokens": getattr(usage, "prompt_tokens", None),
            "completion_tokens": getattr(usage, "completion_tokens", None),
            "cost_usd": kwargs.get("response_cost"),
            "latency_ms": round((end - start).total_seconds() * 1000, 1) if start and end else None,
            "error": None if err is None else f"{type(err).__name__}: {str(err)[:160]}"})

    async def async_log_success_event(self, kwargs, response_obj, start_time, end_time):
        try:
            self._event("attribution.request", kwargs, response_obj, "success", start_time, end_time)
        except Exception:
            log.exception("attribution success event failed")

    async def async_log_failure_event(self, kwargs, response_obj, start_time, end_time):
        try:
            self._event("attribution.request", kwargs, response_obj, "failure", start_time, end_time)
        except Exception:
            log.exception("attribution failure event failed")


run_attribution = RunAttribution()
