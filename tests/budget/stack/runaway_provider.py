"""Test-only NON-CONFORMING provider: ignores max_tokens and always generates
RUNAWAY_TOKENS tokens. Used only in the isolated T2 stack to prove the gateway's
stream guard cuts a provider that overruns the reserved output ceiling.

Tokens are the word " a", which tiktoken (LiteLLM's fallback tokenizer) counts as
exactly one token, so the gateway's own recount of a partial stream equals the
number of chunks the provider produced. Usage reports prompt_tokens as words + 3
per message (same rule as services/mock-provider).
"""
import asyncio
import json
import os
import time
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse

RUNAWAY_TOKENS = int(os.getenv("RUNAWAY_TOKENS", "600"))
PER_TOKEN_MS = float(os.getenv("PER_TOKEN_LATENCY_MS", "2"))
app = FastAPI(title="runaway-provider")
_stats = {"requests": 0, "chunks_sent": 0}


@app.get("/health")
async def health():
    return {"status": "ok", **_stats}


@app.get("/v1/models")
async def models():
    return {"object": "list", "data": [{"id": "mock-runaway", "object": "model", "owned_by": "runaway"}]}


@app.post("/v1/chat/completions")
async def chat(request: Request):
    body = await request.json()
    _stats["requests"] += 1
    msgs = body.get("messages") or []
    ptok = sum(len(str(m.get("content", "")).split()) + 3 for m in msgs)
    n = RUNAWAY_TOKENS  # deliberately ignores max_tokens
    cid, created, model = "chatcmpl-" + uuid.uuid4().hex[:24], int(time.time()), body.get("model", "mock-runaway")
    usage = {"prompt_tokens": ptok, "completion_tokens": n, "total_tokens": ptok + n}
    if not body.get("stream"):
        return {"id": cid, "object": "chat.completion", "created": created, "model": model,
                "choices": [{"index": 0, "message": {"role": "assistant", "content": " a" * n},
                             "finish_reason": "stop"}], "usage": usage}

    def chunk(delta, finish=None, usage_=None, choices=True):
        d = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model,
             "choices": [{"index": 0, "delta": delta, "finish_reason": finish}] if choices else []}
        if usage_:
            d["usage"] = usage_
        return f"data: {json.dumps(d)}\n\n"

    async def gen():
        yield chunk({"role": "assistant", "content": ""})
        for _ in range(n):
            await asyncio.sleep(PER_TOKEN_MS / 1000)
            _stats["chunks_sent"] += 1
            yield chunk({"content": " a"})
        yield chunk({}, finish="stop")
        yield chunk({}, usage_=usage, choices=False)
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")
