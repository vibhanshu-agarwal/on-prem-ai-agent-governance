"""Delegation broker: the ONE control-plane endpoint agents may reach.

Agents sit on internal networks that cannot reach the control plane (by design: an agent must
not be able to read the register or the audit log). Minting a sub-agent credential is the single
thing an agent legitimately needs from it, so this forwarder exposes exactly
`POST /v1/delegations` (the parent's delegation token is the credential; the control plane does all
the attenuation checks and alerting) and nothing else.

  python -m govagent.broker          env: CONTROL_PLANE_URL, BROKER_PORT (default 8090)

It adds no authority: it forwards a whitelist of body fields and relays status and body unchanged.
Deployed as `delegation-broker` in deploy/compose.agents.yml, attached to the SSO agents network and
to the control plane's internal network.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ALLOWED_FIELDS = ("parent_token", "name", "max_budget_usd", "models", "ttl_s", "capabilities")
MAX_BODY = 16 * 1024


class Handler(BaseHTTPRequestHandler):
    upstream = os.environ.get("CONTROL_PLANE_URL", "http://control-plane:8100").rstrip("/")

    def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            return self._send(200, b'{"ok":true}')
        self._send(404, b'{"error":"not_found"}')

    def do_POST(self):  # noqa: N802
        if self.path != "/v1/delegations":
            return self._send(404, b'{"error":"not_found","message":"only POST /v1/delegations is brokered"}')
        n = int(self.headers.get("content-length") or 0)
        if n <= 0 or n > MAX_BODY:
            return self._send(400, b'{"error":"bad_request","message":"body required, max 16 KiB"}')
        try:
            body = json.loads(self.rfile.read(n))
            payload = {k: body[k] for k in ALLOWED_FIELDS if k in body}
        except (ValueError, TypeError):
            return self._send(400, b'{"error":"bad_request","message":"invalid JSON"}')
        req = urllib.request.Request(self.upstream + "/v1/delegations", data=json.dumps(payload).encode(),
                                     method="POST", headers={"content-type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                self._send(r.status, r.read())
        except urllib.error.HTTPError as e:
            self._send(e.code, e.read() or b"{}")
        except (urllib.error.URLError, OSError) as e:
            self._send(502, json.dumps({"error": "control_plane_unreachable", "message": str(e)[:120]}).encode())

    def log_message(self, fmt, *args):  # one line per request, never the body (it holds a token)
        print("broker", self.command, self.path, args[1] if len(args) > 1 else "", file=sys.stderr, flush=True)


def main() -> int:
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("BROKER_PORT", "8090"))), Handler).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
