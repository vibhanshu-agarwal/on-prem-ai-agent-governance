"""Throwaway "rogue" agent for drills: streams slow completions in a loop, retrying forever.

Every line it prints is timestamped (epoch seconds) so a test can prove when the
stream stopped relative to the stop decision:
  START <t>             a streaming request began
  TOK <t>               one streamed chunk arrived
  END <t>               a stream finished normally
  ERR <t> <what>        the stream or request failed (connection reset, 401...)
  DENIED <t> <status>   the gateway refused the request

Auth modes (env AUTH_MODE):
  key      Authorization: Bearer $AGENT_KEY straight to $GATEWAY_URL (LiteLLM)
  oidc     client_credentials at $IDP_TOKEN_URL, then Bearer <JWT> to $GATEWAY_URL (the auth proxy)
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


def log(*a):
    print(*a, flush=True)


def jwt_token() -> str:
    data = urllib.parse.urlencode({"grant_type": "client_credentials", "client_id": os.environ["CLIENT_ID"],
                                   "client_secret": os.environ["CLIENT_SECRET"]}).encode()
    with urllib.request.urlopen(os.environ["IDP_TOKEN_URL"], data=data, timeout=10) as r:
        return json.loads(r.read())["access_token"]


def main() -> int:
    url = os.environ.get("GATEWAY_URL", "http://gateway:4000").rstrip("/") + "/v1/chat/completions"
    model = os.environ.get("MODEL", "mock-local-slow")
    max_tokens = int(os.environ.get("MAX_TOKENS", "200"))
    mode = os.environ.get("AUTH_MODE", "key")
    token = None
    while True:
        try:
            if mode == "oidc" and token is None:
                token = jwt_token()
                log("TOKEN", time.time())
            auth = f"Bearer {token}" if mode == "oidc" else f"Bearer {os.environ['AGENT_KEY']}"
            body = json.dumps({"model": model, "stream": True, "max_tokens": max_tokens,
                               "messages": [{"role": "user", "content": "keep going"}]}).encode()
            req = urllib.request.Request(url, data=body, headers={"Authorization": auth,
                                                                  "Content-Type": "application/json"})
            log("START", time.time())
            with urllib.request.urlopen(req, timeout=120) as r:
                for line in r:
                    if line.strip().startswith(b"data:") and b"[DONE]" not in line:
                        log("TOK", time.time())
            log("END", time.time())
        except urllib.error.HTTPError as e:
            log("DENIED", time.time(), e.code)
            time.sleep(0.5)
        except Exception as e:  # noqa: BLE001 - a rogue agent keeps retrying
            log("ERR", time.time(), type(e).__name__, str(e)[:80].replace("\n", " "))
            time.sleep(0.5)


if __name__ == "__main__":
    sys.exit(main())
