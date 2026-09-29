"""TEST FIXTURE (tests/guardrails): OpenAI-compatible provider that ECHOES the last message and can
emit tool calls, so output guardrails (PII/secret redaction, tool authorization, approval) can be
exercised end to end through the real gateway. It also records what it received
(GET /_received) so tests can prove what actually reached the model after input masking.

  content containing  [[tool_call:NAME:{"json":"args"}]]  => response is a tool call to NAME
  content containing  [[emit_b64:BASE64]]                 => response is "ECHO: " + the decoded text
                      (puts PII/secrets in the OUTPUT without them passing the input guardrails)
Runs inside the govpilot/mock-provider:1 image (FastAPI + uvicorn already there); never in a demo path.
"""
import base64
import json
import re
import time
import uuid
from collections import deque

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

app = FastAPI(title="mock-echo")
RECEIVED: deque = deque(maxlen=50)
TOOL = re.compile(r"\[\[tool_call:([A-Za-z0-9_.-]+):(\{.*?\})\]\]", re.S)
EMIT = re.compile(r"\[\[emit_b64:([A-Za-z0-9+/=]+)\]\]")


def _text(c):
    if isinstance(c, str):
        return c
    if isinstance(c, list):
        return " ".join(p.get("text", "") for p in c if isinstance(p, dict))
    return ""


@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/_received")
async def received():
    return list(RECEIVED)


@app.post("/_reset")
async def reset():
    RECEIVED.clear()
    return {"ok": True}


@app.post("/v1/chat/completions")
async def chat(request: Request):
    body = await request.json()
    RECEIVED.append(body)
    msgs = body.get("messages") or []
    last = _text(msgs[-1].get("content")) if msgs else ""
    ptok = sum(len(_text(m.get("content")).split()) + 3 for m in msgs)
    cid, created, model = "chatcmpl-" + uuid.uuid4().hex[:24], int(time.time()), body.get("model", "mock-echo")
    em = EMIT.search(last)
    if em:
        last = base64.b64decode(em.group(1)).decode("utf-8")
    m = TOOL.search(last)
    msg = {"role": "assistant", "content": None if m else "ECHO: " + last}
    if m:
        msg["tool_calls"] = [{"id": "call_" + uuid.uuid4().hex[:8], "type": "function",
                              "function": {"name": m.group(1), "arguments": m.group(2)}}]
    finish = "tool_calls" if m else "stop"
    ctok = len((msg["content"] or "x").split())
    usage = {"prompt_tokens": ptok, "completion_tokens": ctok, "total_tokens": ptok + ctok}
    if not body.get("stream"):
        return JSONResponse({"id": cid, "object": "chat.completion", "created": created, "model": model,
                             "choices": [{"index": 0, "message": msg, "finish_reason": finish}], "usage": usage})

    def chunk(delta, fin=None, usage=None, choices=True):
        d = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model,
             "choices": [{"index": 0, "delta": delta, "finish_reason": fin}] if choices else []}
        if usage:
            d["usage"] = usage
        return "data: " + json.dumps(d) + "\n\n"

    async def gen():
        yield chunk({"role": "assistant", "content": ""})
        if m:
            tc = msg["tool_calls"][0]
            yield chunk({"tool_calls": [{"index": 0, "id": tc["id"], "type": "function",
                                         "function": {"name": tc["function"]["name"], "arguments": ""}}]})
            yield chunk({"tool_calls": [{"index": 0, "function": {"arguments": tc["function"]["arguments"]}}]})
        else:
            words = msg["content"].split(" ")
            for i, w in enumerate(words):
                yield chunk({"content": w if i == 0 else " " + w})
        yield chunk({}, fin=finish)
        yield chunk({}, usage=usage, choices=False)
        yield "data: [DONE]\n\n"

    return StreamingResponse(gen(), media_type="text/event-stream")
