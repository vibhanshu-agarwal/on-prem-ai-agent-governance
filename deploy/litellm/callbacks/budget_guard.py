"""govpilot budget guard: a LiteLLM proxy callback that closes the gaps T2 found in
native budget reservation (LiteLLM v1.100.3). See docs/results/T2.md.

Native reservation runs during auth, BEFORE this hook, and reserves
  input_estimate + min(max_tokens or 16384, model_info.max_output_tokens) * output_rate
for the *requested* model only. It can under-reserve in three ways, which this
hook fixes by shaping the request so that worst-case cost <= reserved cost:

1. max_tokens above the model ceiling (e.g. 100000) is forwarded unchanged while
   the reservation is clamped at max_output_tokens, so a request can spend far more
   than it reserved.  -> reject or clamp above the agent/model ceiling, and apply the
   agent default when max_tokens is absent.
2. When a budget is nearly exhausted, native reservation *resizes* the reservation
   down to the remaining budget and still admits the request, so the last request
   overshoots the cap.  -> reject (or clamp max_tokens to what the reservation affords).
3. Fallbacks can route to a pricier model than the one the reservation was priced
   on.  -> affordability is computed against every model the request can reach.

Streaming: a provider that ignores max_tokens is cut off once it exceeds the
enforced ceiling; the stream ends with finish_reason "length", the upstream is
closed, the partial output is billed (reservation reconciled) and an auditable
`budget.stream_terminated` event is emitted.

Fail closed on Postgres loss: a background `SELECT 1` probe; budgeted requests are
rejected (503) once the spend DB has not answered for GOVPILOT_BUDGET_GUARD_DB_STALE_SECONDS
(native LiteLLM keeps admitting cached keys for ~60 s with the DB down).

Spend-counter TTL: applies litellm_settings.default_redis_ttl to the Redis spend
counters (native keeps 60 s, then reseeds from DB columns that lose increments on a
gateway restart).

Configuration (loose coupling: everything comes from config, not code):
  key metadata  `token_policy`  > team metadata `token_policy` > env defaults
    token_policy:
      max_tokens_ceiling: int      # hard ceiling for this agent (<= model max_output_tokens)
      default_max_tokens: int      # applied when the request sends none
      on_exceed: reject | clamp    # request above ceiling (default reject)
      on_insufficient_reservation: reject | clamp   # budget nearly exhausted (default reject)
  env: GOVPILOT_BUDGET_GUARD_DEFAULT_CEILING, GOVPILOT_BUDGET_GUARD_DEFAULT_MAX_TOKENS,
       GOVPILOT_BUDGET_GUARD_ON_EXCEED, GOVPILOT_BUDGET_GUARD_ON_INSUFFICIENT,
       GOVPILOT_BUDGET_GUARD_INPUT_SAFETY (multiplier on the input-cost estimate, default 1.0),
       GOVPILOT_BUDGET_EVENT_SINK (adapter name; only "log" exists today),
       GOVPILOT_BUDGET_GUARD_REQUIRE_DB (default true), GOVPILOT_BUDGET_GUARD_DB_PROBE_SECONDS (2),
       GOVPILOT_BUDGET_GUARD_DB_STALE_SECONDS (5), GOVPILOT_SPEND_COUNTER_TTL_SECONDS
       (default: litellm_settings.default_redis_ttl).

Single file on purpose: LiteLLM loads it by path (callbacks.budget_guard.budget_guard),
so it cannot use package-relative imports. The two ports (PolicySource,
BudgetEventSink) are small Protocols so a sponsor can swap adapters.
"""

import json
import logging
import math
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Protocol

from fastapi import HTTPException

from litellm.integrations.custom_logger import CustomLogger

log = logging.getLogger("govpilot.budget_guard")

TOKEN_FIELDS = ("max_completion_tokens", "max_tokens", "max_output_tokens")
GUARDED_CALL_TYPES = {"completion", "acompletion", "text_completion", "atext_completion"}
ROUTE_FOR_ESTIMATE = "/chat/completions"
EPS = 1e-9


# ----------------------------------------------------------------------------- policy port
@dataclass(frozen=True)  # NB: no `from __future__ import annotations` (module is loaded by path)
class TokenPolicy:
    max_tokens_ceiling: int | None
    default_max_tokens: int | None
    on_exceed: str = "reject"
    on_insufficient_reservation: str = "reject"
    source: str = "default"


class PolicySource(Protocol):
    def resolve(self, user_api_key_dict: Any) -> TokenPolicy: ...


def _env_int(name: str) -> int | None:
    v = os.getenv(name)
    return int(v) if v not in (None, "") else None


class KeyMetadataPolicySource:
    """Adapter: policy from LiteLLM key metadata, then team metadata, then env."""

    def __init__(self) -> None:
        self.defaults = {
            "max_tokens_ceiling": _env_int("GOVPILOT_BUDGET_GUARD_DEFAULT_CEILING"),
            "default_max_tokens": _env_int("GOVPILOT_BUDGET_GUARD_DEFAULT_MAX_TOKENS"),
            "on_exceed": os.getenv("GOVPILOT_BUDGET_GUARD_ON_EXCEED", "reject"),
            "on_insufficient_reservation": os.getenv("GOVPILOT_BUDGET_GUARD_ON_INSUFFICIENT", "reject"),
        }

    def resolve(self, user_api_key_dict: Any) -> TokenPolicy:
        merged = dict(self.defaults)
        source = "default"
        for label, md in (("team", getattr(user_api_key_dict, "team_metadata", None)),
                          ("key", getattr(user_api_key_dict, "metadata", None))):
            tp = (md or {}).get("token_policy") if isinstance(md, dict) else None
            if isinstance(tp, dict):
                for k in merged:
                    if tp.get(k) is not None:
                        merged[k] = tp[k]
                source = label
        for k in ("on_exceed", "on_insufficient_reservation"):
            if merged[k] not in ("reject", "clamp"):
                merged[k] = "reject"
        return TokenPolicy(
            max_tokens_ceiling=int(merged["max_tokens_ceiling"]) if merged["max_tokens_ceiling"] else None,
            default_max_tokens=int(merged["default_max_tokens"]) if merged["default_max_tokens"] else None,
            on_exceed=merged["on_exceed"],
            on_insufficient_reservation=merged["on_insufficient_reservation"],
            source=source,
        )


# ----------------------------------------------------------------------------- event port
class BudgetEventSink(Protocol):
    def emit(self, event: dict) -> None: ...


class LogEventSink:
    """Adapter: one JSON line per event on the gateway's stdout (collected by the
    container log driver). T3's AuditSink (Postgres append-only -> SIEM) can replace it."""

    PREFIX = "GOVPILOT_BUDGET_EVENT "

    def emit(self, event: dict) -> None:
        line = self.PREFIX + json.dumps(event, sort_keys=True, default=str)
        print(line, file=sys.stdout, flush=True)


SINKS = {"log": LogEventSink}


# ----------------------------------------------------------------------------- helpers
def _reject(status: int, etype: str, message: str) -> Exception:
    try:
        from litellm.proxy._types import ProxyException  # OpenAI-shaped error: message/type/code
        return ProxyException(message=message, type=etype, param=None, code=status)
    except Exception:  # pragma: no cover - fallback if the proxy type moves
        return HTTPException(status_code=status, detail={"error": message, "type": etype})


def _router():
    from litellm.proxy.proxy_server import llm_router  # late import: proxy module state
    return llm_router


def _fallback_models(model: str, data: dict, router: Any) -> list[str]:
    """Every model group the request can end up on: the model itself, request-body
    fallbacks, and router fallbacks (incl. '*' wildcard, context-window and
    content-policy fallbacks), transitively."""
    maps: list = []
    if router is not None:
        for attr in ("fallbacks", "context_window_fallbacks", "content_policy_fallbacks"):
            maps.extend(getattr(router, attr, None) or [])
    body_fb = data.get("fallbacks")
    seen: list[str] = [model]
    queue = [model]
    first = True
    while queue:
        cur = queue.pop(0)
        nxt: list = []
        if first and isinstance(body_fb, list):
            for f in body_fb:
                if isinstance(f, str):
                    nxt.append(f)
                elif isinstance(f, dict) and isinstance(f.get("model"), str):
                    nxt.append(f["model"])
        first = False
        for m in maps:
            if isinstance(m, dict):
                for k, v in m.items():
                    if k in (cur, "*") and isinstance(v, list):
                        nxt.extend(x for x in v if isinstance(x, str))
        for x in nxt:
            if x not in seen:
                seen.append(x)
                queue.append(x)
    return seen


def _model_ceiling(model: str, router: Any) -> int | None:
    try:
        info = router.get_model_group_info(model_group=model) if router is not None else None
        v = getattr(info, "max_output_tokens", None) if info is not None else None
        return int(v) if v else None
    except Exception:
        return None


def _model_default_max_tokens(model: str, router: Any) -> int | None:
    try:
        for d in router.get_model_list(model_name=model) or []:
            v = (d.get("litellm_params") or {}).get("max_tokens")
            if v:
                return int(v)
    except Exception:
        pass
    return None


def _requested_tokens(data: dict) -> int | None:
    vals = []
    for f in TOKEN_FIELDS:
        v = data.get(f)
        if v is not None:
            try:
                vals.append(int(v))
            except (TypeError, ValueError):
                raise _reject(400, "invalid_request_error", f"{f} must be an integer")
    return max(vals) if vals else None


def _set_tokens(data: dict, value: int) -> None:
    present = [f for f in TOKEN_FIELDS if data.get(f) is not None]
    for f in present or ["max_tokens"]:
        data[f] = value


def _multiplier(data: dict) -> int:
    m = 1
    for k in ("n", "best_of"):
        try:
            m = max(m, int(data.get(k) or 1))
        except (TypeError, ValueError):
            pass
    return m


async def _cost_shape_async(data: dict, model: str, router: Any) -> tuple[float, float] | None:
    from litellm.proxy.spend_tracking.budget_reservation import (
        count_request_input_tokens, estimate_request_input_cost, estimate_request_max_cost)
    body = {k: data[k] for k in ("messages", "prompt", "tools", "tool_choice", "n", "best_of") if k in data}
    body["model"] = model
    body["max_tokens"] = 1
    counts = await count_request_input_tokens(request_body=body, route=ROUTE_FOR_ESTIMATE, llm_router=router)
    in_cost = estimate_request_input_cost(request_body=body, route=ROUTE_FOR_ESTIMATE, llm_router=router,
                                          input_token_counts=counts)
    one = estimate_request_max_cost(request_body=body, route=ROUTE_FOR_ESTIMATE, llm_router=router,
                                    input_token_counts=counts)
    if one is None:
        return None
    in_cost = float(in_cost or 0.0)
    return in_cost, max(0.0, float(one) - in_cost)


def _key_label(u: Any) -> dict:
    md = getattr(u, "metadata", None) or {}
    return {"key_hash": getattr(u, "token", None), "key_alias": getattr(u, "key_alias", None),
            "agent_id": md.get("agent_id") if isinstance(md, dict) else None,
            "team_id": getattr(u, "team_id", None)}


# ----------------------------------------------------------------------------- the callback
class BudgetGuard(CustomLogger):
    def __init__(self, policy_source: PolicySource | None = None, sink: BudgetEventSink | None = None) -> None:
        super().__init__()
        self.policy_source = policy_source or KeyMetadataPolicySource()
        self.sink = sink or SINKS[os.getenv("GOVPILOT_BUDGET_EVENT_SINK", "log")]()
        self.input_safety = float(os.getenv("GOVPILOT_BUDGET_GUARD_INPUT_SAFETY", "1.0"))
        # Fail closed on Postgres loss: native LiteLLM keeps admitting cached keys for
        # ~60 s with the spend DB down (spend logs cannot be persisted). A background
        # SELECT 1 probe marks the DB stale; budgeted requests are then rejected.
        self.require_db = os.getenv("GOVPILOT_BUDGET_GUARD_REQUIRE_DB", "true").lower() == "true"
        self.db_probe_interval = float(os.getenv("GOVPILOT_BUDGET_GUARD_DB_PROBE_SECONDS", "2"))
        self.db_stale_after = float(os.getenv("GOVPILOT_BUDGET_GUARD_DB_STALE_SECONDS", "5"))
        self._db_ok_at: float | None = None
        self._db_probe_task: Any = None
        self._ttl_pinned = False

    async def _probe_db_once(self) -> None:
        import asyncio
        from litellm.proxy.proxy_server import prisma_client
        if prisma_client is None:
            self._db_ok_at = time.monotonic()  # no DB configured: nothing to be stale
            return
        try:
            await asyncio.wait_for(prisma_client.db.query_raw("SELECT 1"), timeout=min(2.0, self.db_stale_after))
            self._db_ok_at = time.monotonic()
        except BaseException as e:  # noqa: BLE001  any failure = not healthy
            if isinstance(e, asyncio.CancelledError):
                raise

    async def _db_probe_loop(self) -> None:
        import asyncio
        while True:
            await self._probe_db_once()
            await asyncio.sleep(self.db_probe_interval)

    async def _db_fresh(self) -> bool:
        import asyncio
        if self._db_probe_task is None or self._db_probe_task.done():
            self._db_probe_task = asyncio.create_task(self._db_probe_loop())
        if self._db_ok_at is None:
            await self._probe_db_once()
        return self._db_ok_at is not None and time.monotonic() - self._db_ok_at <= self.db_stale_after

    def _event(self, kind: str, user_api_key_dict: Any, data: dict, **fields: Any) -> None:
        ev = {"event": kind, "ts": time.time(), "model": data.get("model"),
              "litellm_call_id": data.get("litellm_call_id"), **_key_label(user_api_key_dict), **fields}
        try:
            self.sink.emit(ev)
        except Exception:  # never let auditing break the request path
            log.exception("budget event sink failed")

    # ---------------------------------------------------------------- spend-counter TTL
    def _pin_spend_counter_ttl(self) -> None:
        """Apply litellm_settings.default_redis_ttl to the Redis spend counters.

        Native: counters live 60 s after their last write, then are reseeded from the
        Postgres key/team spend columns. Those columns lose any increments still queued
        in memory when the gateway restarts, so a reseed after a restart re-grants spend
        that was already used (T2 delayed-telemetry test). Keeping counters for the whole
        budget period makes Redis (AOF-persisted) the enforcement source until the budget
        resets (the reset job rewrites the counters itself)."""
        if self._ttl_pinned:
            return
        try:
            import litellm
            from litellm.proxy.proxy_server import spend_counter_cache
            ttl = int(os.getenv("GOVPILOT_SPEND_COUNTER_TTL_SECONDS") or litellm.default_redis_ttl or 0)
            rc = spend_counter_cache.redis_cache
            if ttl > 0 and rc is not None:
                rc.default_ttl = ttl
                self._ttl_pinned = True
        except Exception:
            log.exception("could not pin spend counter TTL")

    # ---------------------------------------------------------------- pre-call
    async def async_pre_call_hook(self, user_api_key_dict, cache, data: dict, call_type):
        self._pin_spend_counter_ttl()
        if str(call_type) not in GUARDED_CALL_TYPES and str(call_type).split(".")[-1] not in GUARDED_CALL_TYPES:
            return data
        model = data.get("model")
        if not isinstance(model, str):
            return data
        budgeted = any(getattr(user_api_key_dict, a, None) for a in ("max_budget", "team_max_budget"))
        if budgeted and self.require_db and not await self._db_fresh():
            self._event("budget.db_unavailable_rejected", user_api_key_dict, data,
                        db_last_ok_age_s=None if self._db_ok_at is None else time.monotonic() - self._db_ok_at)
            raise _reject(503, "budget_enforcement_unavailable",
                          "Budget enforcement unavailable: the spend database is unreachable, so this "
                          "budgeted request was rejected (fail closed). Retry shortly.")
        router = _router()
        policy = self.policy_source.resolve(user_api_key_dict)
        candidates = _fallback_models(model, data, router)

        # 1. ceiling = min(agent policy, every reachable model's max_output_tokens)
        ceilings = [c for c in [policy.max_tokens_ceiling] + [_model_ceiling(m, router) for m in candidates] if c]
        ceiling = min(ceilings) if ceilings else None
        requested = _requested_tokens(data)
        if requested is None:
            default = policy.default_max_tokens or _model_default_max_tokens(model, router) or ceiling
            enforced = min(x for x in (default, ceiling) if x) if (default or ceiling) else None
            action = "default_applied"
        elif ceiling is not None and requested > ceiling:
            if policy.on_exceed == "reject":
                self._event("budget.max_tokens_rejected", user_api_key_dict, data,
                            requested=requested, ceiling=ceiling, policy_source=policy.source)
                raise _reject(400, "max_tokens_exceeds_ceiling",
                              f"max_tokens={requested} exceeds this agent's ceiling of {ceiling} "
                              f"(policy source: {policy.source})")
            enforced, action = ceiling, "clamped_to_ceiling"
        else:
            enforced, action = requested, "unchanged"
        if enforced is None:
            return data  # unknown model limits and no policy: nothing to enforce against

        # 2. fit worst-case cost inside the native reservation
        reservation = getattr(user_api_key_dict, "budget_reservation", None)
        reserved = float(reservation["reserved_cost"]) if isinstance(reservation, dict) and \
            reservation.get("reserved_cost") is not None else None
        shapes = {}
        for m in candidates:
            s = await _cost_shape_async(data, m, router)
            if s is not None:
                shapes[m] = s
        worst = max((i * self.input_safety + enforced * o for i, o in shapes.values()), default=None)

        if reserved is None:
            if budgeted and worst and worst > 0:
                # A budgeted, priced request with no reservation would be enforced
                # read-time only (concurrent overshoot). Fail closed.
                self._event("budget.no_reservation_rejected", user_api_key_dict, data, worst_case_cost=worst)
                raise _reject(503, "budget_enforcement_unavailable",
                              "Budget reservation missing for a budgeted request; rejected (fail closed).")
        elif worst is not None and worst > reserved + EPS:
            affordable = min(
                (math.floor((reserved - i * self.input_safety) / o + EPS) if o > 0 else enforced)
                for i, o in shapes.values())
            if affordable >= 1 and policy.on_insufficient_reservation == "clamp":
                self._event("budget.max_tokens_clamped_to_reservation", user_api_key_dict, data,
                            requested=enforced, enforced=affordable, reserved_cost=reserved,
                            worst_case_cost=worst, candidates=list(shapes))
                enforced, action = affordable, "clamped_to_reservation"
            else:
                self._event("budget.insufficient_reservation_rejected", user_api_key_dict, data,
                            requested=enforced, affordable_tokens=affordable, reserved_cost=reserved,
                            worst_case_cost=worst, candidates=list(shapes))
                raise _reject(429, "budget_exceeded",
                              f"Budget has been exceeded! Remaining budget reservation ${reserved:.8f} "
                              f"cannot cover the worst-case cost ${worst:.8f} of this request "
                              f"(max_tokens={enforced}, models={list(shapes)}).")

        _set_tokens(data, enforced)
        md = data.setdefault("metadata", {}) if isinstance(data.get("metadata", {}), dict) else None
        if md is not None:
            md["govpilot_budget_guard"] = {"enforced_max_tokens": enforced, "action": action,
                                           "reserved_cost": reserved, "worst_case_cost": worst}
        return data

    # ---------------------------------------------------------------- streaming
    async def async_post_call_streaming_iterator_hook(self, user_api_key_dict, response, request_data: dict):
        limit = _requested_tokens(request_data)
        if limit is None:
            async for chunk in response:
                yield chunk
            return
        limit *= _multiplier(request_data)
        seen = 0
        last = None
        async for chunk in response:
            n = 0
            try:
                for ch in getattr(chunk, "choices", None) or []:
                    d = getattr(ch, "delta", None)
                    if d is not None and (getattr(d, "content", None) or getattr(d, "tool_calls", None)):
                        n += 1
            except Exception:
                n = 0
            if seen + n > limit:
                await self._terminate_stream(user_api_key_dict, response, request_data, seen, limit)
                if last is not None:
                    yield self._final_chunk(last)
                return
            seen += n
            last = chunk
            yield chunk

    @staticmethod
    def _final_chunk(template: Any) -> Any:
        try:
            c = template.model_copy(deep=True)
            for ch in c.choices:
                ch.delta.content = None
                ch.finish_reason = "length"
            return c
        except Exception:
            return template

    async def _terminate_stream(self, user_api_key_dict, response, request_data, seen, limit):
        reservation = getattr(user_api_key_dict, "budget_reservation", None)
        # Close the upstream first so the provider stops generating, then bill what was
        # actually produced (this reconciles the reservation and writes the spend log).
        try:
            if hasattr(response, "aclose"):
                await response.aclose()
        except BaseException:
            pass
        billed = False
        try:
            from litellm.proxy.common_request_processing import _bill_partial_streamed_spend_on_disconnect
            billed = await _bill_partial_streamed_spend_on_disconnect(request_data, response)
        except Exception:
            log.exception("partial stream billing failed")
        if not billed and isinstance(reservation, dict) and not reservation.get("finalized"):
            # fallback: keep the full reservation as spend (conservative, never under-records)
            try:
                from litellm.proxy.spend_tracking.budget_reservation import reconcile_budget_reservation
                await reconcile_budget_reservation(reservation, float(reservation.get("reserved_cost") or 0))
            except Exception:
                log.exception("reservation reconcile after stream termination failed")
        self._event("budget.stream_terminated", user_api_key_dict, request_data,
                    delivered_output_chunks=seen, enforced_max_tokens=limit,
                    reserved_cost=(reservation or {}).get("reserved_cost") if isinstance(reservation, dict) else None,
                    partial_billed=billed,
                    reason="provider exceeded enforced max_tokens; stream cut at the reservation boundary")

    # ---------------------------------------------------------------- non-streaming audit
    async def async_post_call_success_hook(self, data: dict, user_api_key_dict, response):
        try:
            limit = _requested_tokens(data)
            usage = getattr(response, "usage", None)
            out = getattr(usage, "completion_tokens", None) if usage is not None else None
            if limit is not None and out is not None and out > limit * _multiplier(data):
                self._event("budget.provider_exceeded_max_tokens", user_api_key_dict, data,
                            enforced_max_tokens=limit, completion_tokens=out,
                            note="non-streaming: cost already incurred at the provider; recorded as billed")
        except Exception:
            log.exception("post-call audit failed")
        return response


budget_guard = BudgetGuard()
