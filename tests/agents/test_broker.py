"""The delegation broker forwards exactly one control-plane call and nothing else."""
from __future__ import annotations

import io
import json
import threading
from contextlib import redirect_stderr
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest

from govagent import broker


class Upstream(BaseHTTPRequestHandler):
    seen: list[dict] = []
    status = 201

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        Upstream.seen.append({"path": self.path, "body": body, "headers": dict(self.headers)})
        out = json.dumps({"child_agent_id": "p.kid", "gateway_key": "sk-raw-child", "echo": body}).encode() if Upstream.status == 201 else \
            json.dumps({"error": "delegation_denied", "message": "no", "details": {"reasons": ["budget"]}}).encode()
        self.send_response(Upstream.status)
        self.send_header("content-length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def log_message(self, *a):
        pass


@pytest.fixture
def stack():
    up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    Upstream.seen, Upstream.status = [], 201
    handler = type("H", (broker.Handler,), {"upstream": f"http://127.0.0.1:{up.server_port}"})
    br = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=br.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{br.server_port}"
    br.shutdown()
    up.shutdown()


def test_forwards_only_the_whitelisted_fields_to_the_delegation_endpoint(stack):
    r = httpx.post(stack + "/v1/delegations", json={"parent_token": "gpm1.a.b", "name": "w", "max_budget_usd": 0.1,
                                                     "models": ["m"], "ttl_s": 60, "agent_id": "hr-agent",
                                                     "role": "admin", "gateway_key": "sk-evil"})
    assert r.status_code == 201 and r.json()["child_agent_id"] == "p.kid"
    seen = Upstream.seen[0]
    assert seen["path"] == "/v1/delegations"
    assert set(seen["body"]) == {"parent_token", "name", "max_budget_usd", "models", "ttl_s"}
    assert "authorization" not in {k.lower() for k in seen["headers"]}          # the broker adds no authority
    # the raw child key would outlive the delegation token's expiry and skip the auth proxy's scope checks
    assert "gateway_key" not in r.json() and "sk-raw-child" not in r.text


def test_denials_are_relayed_unchanged(stack):
    Upstream.status = 403
    r = httpx.post(stack + "/v1/delegations", json={"parent_token": "t", "name": "w", "max_budget_usd": 9, "models": ["m"]})
    assert r.status_code == 403 and r.json()["details"]["reasons"] == ["budget"]


@pytest.mark.parametrize("method,path", [("POST", "/v1/agents"), ("POST", "/v1/agents/hr-agent/stop"),
                                          ("GET", "/v1/agents"), ("GET", "/v1/audit"), ("POST", "/v1/internal/resolve"),
                                          ("POST", "/"), ("GET", "/v1/delegations")])
def test_nothing_else_is_reachable(stack, method, path):
    r = httpx.request(method, stack + path, json={} if method == "POST" else None)
    assert r.status_code in (404, 400) and not Upstream.seen


def test_bad_bodies_are_refused_and_the_token_is_never_logged(stack):
    buf = io.StringIO()
    with redirect_stderr(buf):
        assert httpx.post(stack + "/v1/delegations", content=b"not json").status_code == 400
        assert httpx.post(stack + "/v1/delegations", content=b"").status_code == 400
        assert httpx.post(stack + "/v1/delegations", content=b"x" * 20000).status_code == 400
        httpx.post(stack + "/v1/delegations", json={"parent_token": "gpm1.SECRETTOKEN.sig", "name": "w",
                                                    "max_budget_usd": 1, "models": ["m"]})
    assert "SECRETTOKEN" not in buf.getvalue() and not Upstream.seen[1:]


def test_health(stack):
    assert httpx.get(stack + "/healthz").json() == {"ok": True}
