"""OpenAI-compatible chat client for the governed gateway.

Contract (tested in tests/agents/test_contract_*.py):
  * every request carries the run headers of the RunContext it was called with
  * a retry re-sends the SAME run_id / parent_run_id with attempt = n + 1
  * transient failures (connection errors, 408/425/429/5xx) are retried with backoff; a budget
    refusal, an auth refusal or any other 4xx is not (retrying would only burn attempts)
  * a 401 first invalidates the credential (an expired JWT is refreshed) and retries once
  * the caller always gets either a ChatResult or a GatewayError that names the run id and the
    number of attempts made
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Callable

from .auth import AuthError, AuthProvider
from .context import RunContext
from .events import EventSink, StdoutSink
from .transport import HttpResponse, Transport, TransportError, UrllibTransport

RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})


@dataclass
class RetryPolicy:
    max_attempts: int = 4
    base_delay_s: float = 0.4
    max_delay_s: float = 6.0
    retry_statuses: frozenset = RETRYABLE_STATUS

    def delay(self, attempt: int, retry_after: float | None) -> float:
        d = min(self.max_delay_s, self.base_delay_s * (2 ** (attempt - 1)))
        return max(d, min(retry_after or 0.0, self.max_delay_s))


class GatewayError(Exception):
    def __init__(self, message: str, *, status: int | None, etype: str | None, run_id: str, attempts: int,
                 body: str = "") -> None:
        super().__init__(message)
        self.message, self.status, self.etype = message, status, etype
        self.run_id, self.attempts, self.body = run_id, attempts, body

    @property
    def budget_exceeded(self) -> bool:
        return "budget" in (self.etype or "").lower() or "budget" in self.message.lower()

    @property
    def stopped(self) -> bool:
        """The gateway refused the credential itself (blocked key, revoked identity)."""
        return self.status in (401, 403)


@dataclass
class ChatResult:
    text: str
    model: str
    prompt_tokens: int
    completion_tokens: int
    cost_usd: float | None
    run_id: str
    attempts: int
    headers: dict = field(default_factory=dict)


def _error_parts(resp: HttpResponse) -> tuple[str | None, str]:
    try:
        e = json.loads(resp.body).get("error", {})
        if isinstance(e, dict):
            return e.get("type"), str(e.get("message", ""))[:300]
        return None, str(e)[:300]
    except (ValueError, AttributeError):
        return None, resp.body[:200].decode(errors="replace")


class GatewayClient:
    def __init__(self, base_url: str, auth: AuthProvider, *, transport: Transport | None = None,
                 sink: EventSink | None = None, retry: RetryPolicy | None = None, timeout_s: float = 60.0,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.base_url = base_url.rstrip("/")
        self.auth = auth
        self.transport = transport or UrllibTransport()
        self.sink = sink or StdoutSink()
        self.retry = retry or RetryPolicy()
        self.timeout_s = timeout_s
        self.sleep = sleep

    def chat(self, run: RunContext, model: str, messages: list[dict], *, max_tokens: int | None = None,
             temperature: float | None = None) -> ChatResult:
        body: dict = {"model": model, "messages": messages}
        if max_tokens is not None:
            body["max_tokens"] = int(max_tokens)
        if temperature is not None:
            body["temperature"] = temperature
        if run.user:
            body["user"] = run.user            # LiteLLM end-user attribution (spend-log `end_user`)
        payload = json.dumps(body).encode()
        run = run.next_step()                   # one logical call = one step; its retries reuse it
        attempts = 0
        refreshed = False
        last: GatewayError | None = None
        while attempts < self.retry.max_attempts:
            attempts += 1
            ctx = run.with_attempt(attempts)
            t0 = time.time()
            status: int | None = None
            retry_after: float | None = None
            try:
                headers = {"content-type": "application/json", **self.auth.headers(), **ctx.headers()}
                resp = self.transport.send("POST", f"{self.base_url}/v1/chat/completions", headers, payload,
                                           self.timeout_s)
                status = resp.status
            except TransportError as e:
                last = GatewayError(f"gateway unreachable: {e}", status=None, etype="transport_error",
                                    run_id=run.run_id, attempts=attempts)
                self._log(ctx, model, attempts, None, t0, str(e)[:160])
            except AuthError as e:
                # cannot even authenticate: not a gateway problem, and retrying immediately will not help
                self._log(ctx, model, attempts, None, t0, f"auth: {e}")
                raise GatewayError(str(e), status=401, etype="auth_error", run_id=run.run_id,
                                   attempts=attempts) from None
            else:
                if status == 200:
                    result = self._result(resp, run, model, attempts)
                    self._log(ctx, model, attempts, 200, t0, None, cost=result.cost_usd,
                              tokens=(result.prompt_tokens, result.completion_tokens))
                    return result
                etype, msg = _error_parts(resp)
                last = GatewayError(f"gateway returned {status}: {msg}", status=status, etype=etype,
                                    run_id=run.run_id, attempts=attempts, body=resp.body[:400].decode(errors="replace"))
                self._log(ctx, model, attempts, status, t0, f"{etype}: {msg}"[:160])
                try:
                    retry_after = float(resp.headers.get("retry-after", ""))
                except ValueError:
                    retry_after = None
                if status == 401 and not refreshed:
                    refreshed = True
                    self.auth.invalidate()             # expired JWT: fetch a new one and go again at once
                    continue
                if last.budget_exceeded or status not in self.retry.retry_statuses:
                    raise last
            if attempts >= self.retry.max_attempts:
                break
            self.sleep(self.retry.delay(attempts, retry_after))
        assert last is not None
        raise last

    # ------------------------------------------------------------------
    def _result(self, resp: HttpResponse, run: RunContext, model: str, attempts: int) -> ChatResult:
        d = json.loads(resp.body)
        usage = d.get("usage") or {}
        cost = resp.headers.get("x-litellm-response-cost")
        text = ((d.get("choices") or [{}])[0].get("message") or {}).get("content") or ""
        return ChatResult(text=text, model=d.get("model", model), prompt_tokens=int(usage.get("prompt_tokens", 0)),
                          completion_tokens=int(usage.get("completion_tokens", 0)),
                          cost_usd=float(cost) if cost else None, run_id=run.run_id, attempts=attempts,
                          headers={k: v for k, v in resp.headers.items() if k.startswith(("x-govpilot", "x-litellm-"))})

    def _log(self, ctx: RunContext, model: str, attempt: int, status: int | None, t0: float, error: str | None,
             cost: float | None = None, tokens: tuple[int, int] | None = None) -> None:
        self.sink.emit({"event": "llm.attempt", "agent_id": ctx.agent_id, "run_id": ctx.run_id,
                        "parent_run_id": ctx.parent_run_id, "root_run_id": ctx.root_run_id, "run_kind": ctx.kind,
                        "tool": ctx.tool, "step": ctx.step, "attempt": attempt, "model": model, "http_status": status,
                        "ok": status == 200, "latency_ms": round((time.time() - t0) * 1000, 1), "error": error,
                        "cost_usd": cost, "prompt_tokens": tokens[0] if tokens else None,
                        "completion_tokens": tokens[1] if tokens else None})
