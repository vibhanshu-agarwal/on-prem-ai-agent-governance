"""Deterministic OpenAI-compatible mock provider.

Env:
  PROVIDER_NAME          label echoed in responses (default "mock")
  FIRST_TOKEN_LATENCY_MS delay before first token/response (default 20)
  PER_TOKEN_LATENCY_MS   delay per generated token (default 5)
  SLOW_MODE              "1" => per-token latency multiplied by SLOW_FACTOR
  SLOW_FACTOR            multiplier for slow mode (default 100)
  DEFAULT_COMPLETION_TOKENS  tokens generated when max_tokens absent (default 32)
  MAX_COMPLETION_TOKENS  hard cap on generated tokens (default 4096)
  MODELS                 comma-separated model ids served
  API_KEY_SHA256         if set, requests must carry a Bearer key whose sha256 matches
                         (only the hash is stored here, never the credential itself)
Slow streams: any model id ending in "-slow" (e.g. mock-remote-slow) uses the
slow-mode per-token latency; so do all models when SLOW_MODE=1. Direct callers may
also send headers X-Mock-Slow: 1 or X-Mock-Token-Latency-Ms.

Determinism: prompt_tokens = whitespace-split word count of all message
contents (+ 3 per message overhead); completion_tokens = min(max_tokens or
default, cap). Completion text is "tok0 tok1 ..." words, one word per token.
"""
import asyncio
import hashlib
import hmac
import json
import os
import time
import uuid

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse

PROVIDER = os.getenv("PROVIDER_NAME", "mock")
FIRST_MS = float(os.getenv("FIRST_TOKEN_LATENCY_MS", "20"))
TOKEN_MS = float(os.getenv("PER_TOKEN_LATENCY_MS", "5"))
SLOW_MODE = os.getenv("SLOW_MODE", "0") == "1"
SLOW_FACTOR = float(os.getenv("SLOW_FACTOR", "100"))
DEFAULT_TOKENS = int(os.getenv("DEFAULT_COMPLETION_TOKENS", "32"))
MAX_TOKENS_CAP = int(os.getenv("MAX_COMPLETION_TOKENS", "4096"))
MODELS = [m.strip() for m in os.getenv("MODELS", f"{PROVIDER}-model").split(",") if m.strip()]
API_KEY_SHA256 = os.getenv("API_KEY_SHA256", "").lower()

app = FastAPI(title=f"mock-provider:{PROVIDER}")
_stats = {"requests": 0, "active_streams": 0}


def _check_auth(authorization: str | None):
    if not API_KEY_SHA256:
        return
    presented = (authorization or "").removeprefix("Bearer ")
    if not hmac.compare_digest(hashlib.sha256(presented.encode()).hexdigest(), API_KEY_SHA256):
        raise HTTPException(status_code=401, detail="invalid provider api key")


def _content_text(c) -> str:
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return " ".join(p.get("text", "") for p in c if isinstance(p, dict))
    return ""


def count_prompt_tokens(messages: list) -> int:
    return sum(len(_content_text(m.get("content", "")).split()) + 3 for m in messages)


def _completion_len(body: dict) -> int:
    mt = body.get("max_completion_tokens") or body.get("max_tokens")
    n = int(mt) if mt else DEFAULT_TOKENS
    return max(1, min(n, MAX_TOKENS_CAP))


def _token_delay(request: Request, model: str = "") -> float:
    ms = TOKEN_MS
    override = request.headers.get("x-mock-token-latency-ms")
    if override:
        ms = float(override)
    elif SLOW_MODE or model.endswith("-slow") or request.headers.get("x-mock-slow") == "1":
        ms = TOKEN_MS * SLOW_FACTOR
    return ms / 1000.0


@app.get("/health")
async def health():
    # unauthenticated on purpose (container healthcheck)
    return {"status": "ok", "provider": PROVIDER, **_stats}


@app.get("/v1/models")
async def models(authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    return {"object": "list", "data": [
        {"id": m, "object": "model", "created": 1700000000, "owned_by": PROVIDER} for m in MODELS]}


def _usage(p: int, c: int) -> dict:
    return {"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c}


@app.post("/v1/chat/completions")
async def chat(request: Request, authorization: str | None = Header(default=None)):
    _check_auth(authorization)
    body = await request.json()
    model = body.get("model", MODELS[0])
    if model not in MODELS:
        return JSONResponse(status_code=404, content={"error": {
            "message": f"model {model} not found", "type": "invalid_request_error", "code": "model_not_found"}})
    messages = body.get("messages") or []
    ptok = count_prompt_tokens(messages)
    n = _completion_len(body)
    delay = _token_delay(request, model)
    cid = "chatcmpl-" + uuid.uuid4().hex[:24]
    created = int(time.time())
    words = [f"tok{i}" for i in range(n)]
    _stats["requests"] += 1

    if not body.get("stream"):
        await asyncio.sleep((FIRST_MS + delay * 1000 * n) / 1000.0)
        return {
            "id": cid, "object": "chat.completion", "created": created, "model": model,
            "system_fingerprint": f"mock-{PROVIDER}",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": " ".join(words)},
                         "finish_reason": "length" if body.get("max_tokens") else "stop"}],
            "usage": _usage(ptok, n),
        }

    include_usage = bool((body.get("stream_options") or {}).get("include_usage", True))

    def chunk(delta: dict, finish=None, usage=None, choices=True):
        d = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model,
             "system_fingerprint": f"mock-{PROVIDER}",
             "choices": [{"index": 0, "delta": delta, "finish_reason": finish}] if choices else []}
        if usage is not None:
            d["usage"] = usage
        return f"data: {json.dumps(d)}\n\n"

    async def gen():
        _stats["active_streams"] += 1
        try:
            await asyncio.sleep(FIRST_MS / 1000.0)
            yield chunk({"role": "assistant", "content": ""})
            for i, w in enumerate(words):
                if i:
                    await asyncio.sleep(delay)
                yield chunk({"content": w if i == 0 else " " + w})
            yield chunk({}, finish="length" if body.get("max_tokens") else "stop")
            if include_usage:
                yield chunk({}, usage=_usage(ptok, n), choices=False)
            yield "data: [DONE]\n\n"
        finally:
            _stats["active_streams"] -= 1

    return StreamingResponse(gen(), media_type="text/event-stream")
