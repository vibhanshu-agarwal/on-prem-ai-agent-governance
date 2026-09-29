"""In-memory stand-ins used by the offline tests."""
from __future__ import annotations

import json
import time

from govagent import HttpResponse, TransportError


def chat_ok(model="mock-local", prompt=10, completion=5, cost="0.000012") -> HttpResponse:
    body = {"id": "chatcmpl-x", "model": model, "choices": [{"message": {"role": "assistant", "content": "tok0 tok1"},
                                                              "finish_reason": "length"}],
            "usage": {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion}}
    return HttpResponse(200, {"x-litellm-response-cost": cost}, json.dumps(body).encode())


def err(status: int, etype="error", message="boom", headers=None) -> HttpResponse:
    return HttpResponse(status, headers or {}, json.dumps({"error": {"type": etype, "message": message,
                                                                     "code": str(status)}}).encode())


class ScriptedTransport:
    """Returns scripted responses in order (an Exception instance is raised); records every request."""

    def __init__(self, script):
        self.script = list(script)
        self.requests: list[dict] = []

    def send(self, method, url, headers, body, timeout):
        self.requests.append({"method": method, "url": url, "headers": {k.lower(): v for k, v in headers.items()},
                              "body": json.loads(body) if body and body[:1] in (b"{", b"[") else body})
        item = self.script.pop(0) if self.script else chat_ok()
        if isinstance(item, Exception):
            raise item
        return item


class FakeGateway:
    """A tiny governed gateway: records requests, can require a run id, returns canned chat responses.

    Routes: POST .../v1/chat/completions, POST http://idp/token, POST .../v1/delegations (broker).
    """

    def __init__(self, require_run_id=True, allowed_models=None, clock=time.time):
        self.clock = clock
        self.requests: list[dict] = []
        self.require_run_id = require_run_id
        self.allowed_models = allowed_models
        self.delegations: list[dict] = []
        self.fail_next: list[HttpResponse | Exception] = []
        self.mint_deny: list[str] | None = None

    def send(self, method, url, headers, body, timeout):
        h = {k.lower(): v for k, v in headers.items()}
        if url.endswith("/token"):
            return HttpResponse(200, {}, json.dumps({"access_token": "jwt.fake.token", "expires_in": 900}).encode())
        payload = json.loads(body) if body else {}
        if url.endswith("/v1/delegations"):
            self.delegations.append(payload)
            if self.mint_deny:
                return HttpResponse(403, {}, json.dumps({"error": "delegation_denied", "message": "broader than parent",
                                                         "details": {"reasons": self.mint_deny}}).encode())
            n = len(self.delegations)
            rec = {"delegation_id": f"dg-{n}", "max_budget_usd": payload["max_budget_usd"], "models": payload["models"],
                   "expires": self.clock() + payload.get("ttl_s", 3600)}
            return HttpResponse(201, {}, json.dumps({"child_agent_id": f"parent.{payload['name']}",
                                                     "delegation_token": f"gpm1.child{n}.sig", "delegation": rec}).encode())
        self.requests.append({"url": url, "headers": h, "body": payload})
        if self.fail_next:
            f = self.fail_next.pop(0)
            if isinstance(f, Exception):
                raise f
            return f
        if self.require_run_id and not h.get("x-govpilot-run-id"):
            return err(400, "run_id_required", "missing run id")
        if self.allowed_models and payload.get("model") not in self.allowed_models:
            return err(401, "key_model_access_denied", "model not allowed")
        return chat_ok(payload.get("model", "mock-local"))

    # helpers
    def llm_requests(self):
        return [r for r in self.requests if r["url"].endswith("/v1/chat/completions")]


__all__ = ["chat_ok", "err", "ScriptedTransport", "FakeGateway", "TransportError"]
