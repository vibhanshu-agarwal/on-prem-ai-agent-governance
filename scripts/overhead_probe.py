"""Provider-free gateway overhead probe (stdlib only). Runs INSIDE a container on govpilot_providers, so it can
call the mock provider directly and the gateway (gov-gateway:4000) with identical requests; the per-pair
difference is the gateway's overhead with every production callback loaded.

    docker run --rm --network govpilot_providers -e PKEY=<mock-local provider key> --entrypoint python \
        govpilot/mock-provider:1 -c "$(cat scripts/overhead_probe.py)" N GATEWAY_KEY [PACE_S]

N pairs per prompt size (100 / 2000 / 8000 tokens), 20 % with an e-mail address (so Presidio is called),
request order alternates. PACE_S sleeps between pairs (the pilot simulation uses it to sample under load).
Prints one line: RESULT {json} with the per-pair overhead and LiteLLM's own x-litellm-overhead-duration-ms.
Used by tests/acceptance (M-08) and scripts/pilot_sim.py.
"""
import json
import os
import random
import sys
import time
import urllib.request
import uuid

N = int(sys.argv[1])
KEY = sys.argv[2]
PACE = float(sys.argv[3]) if len(sys.argv) > 3 else 0.0
PKEY = os.environ["PKEY"]
W = "invoice ledger vendor payment transfer schedule audit review approval quarterly reconciliation report".split()
rng = random.Random(8)


def post(url, key, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + key,
                                          "x-govpilot-run-id": "run-" + uuid.uuid4().hex[:16]})
    t = time.perf_counter()
    with urllib.request.urlopen(req, timeout=60) as r:
        r.read()
        hdr = r.headers.get("x-litellm-overhead-duration-ms")
    return (time.perf_counter() - t) * 1000, hdr


out = {}
for label, tokens in (("100_tokens", 100), ("2000_tokens", 2000), ("8000_tokens", 8000)):
    d, gw_hdr = [], []
    for i in range(N + 3):
        body = " ".join(rng.choice(W) for _ in range(int(tokens / 1.3)))
        if i % 5 == 0:
            body += " contact pat.lee@example.com"
        req = {"model": "mock-local", "max_tokens": 16, "messages": [{"role": "user", "content": body}]}
        if i % 2:
            direct, _ = post("http://mock-local:8000/v1/chat/completions", PKEY, req)
            via, h = post("http://gov-gateway:4000/v1/chat/completions", KEY, req)
        else:
            via, h = post("http://gov-gateway:4000/v1/chat/completions", KEY, req)
            direct, _ = post("http://mock-local:8000/v1/chat/completions", PKEY, req)
        if i >= 3:
            d.append(via - direct)
            if h:
                gw_hdr.append(float(h))
        if PACE:
            time.sleep(PACE)
    out[label] = {"overhead_ms": d, "litellm_header_ms": gw_hdr}
print("RESULT " + json.dumps(out), flush=True)
