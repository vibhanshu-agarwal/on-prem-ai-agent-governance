"""Register the IdP clients the discovery feeds authenticate as (idempotent). Stdlib only.

The control plane names a proposal's feed after the authenticated subject, so each feed gets its own
client with role `feed`. `docker-events` is a static client in the control-plane config; the other two are
created here through the IdP admin API. Secrets are written once to .local/discovery.env (gitignored).
"""
import json
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLIENTS = {"gateway-logs": "IDP_CLIENT_SECRET_FEED_GATEWAY_LOGS",
           "openlit-controller": "IDP_CLIENT_SECRET_FEED_OPENLIT_CONTROLLER"}


def load(p):
    out = {}
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def main():
    cp = load(ROOT / ".local" / "control-plane.env")
    out_path = ROOT / ".local" / "discovery.env"
    have = load(out_path)
    url = f"http://127.0.0.1:{cp.get('IDP_PORT', '8300')}/admin/clients"
    for cid, env in CLIENTS.items():
        if env in have:
            continue
        req = urllib.request.Request(url, method="POST", data=json.dumps({"client_id": cid, "roles": ["feed"]}).encode(),
                                     headers={"Authorization": "Bearer " + cp["IDP_ADMIN_TOKEN"],
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                have[env] = json.loads(r.read())["client_secret"]
                print("registered IdP client", cid)
        except urllib.error.HTTPError as e:
            if e.code == 409:
                raise SystemExit(f"IdP client {cid!r} exists but its secret is not in {out_path}; "
                                 "delete the IdP client (or the idp volume) and re-run") from None
            raise
    out_path.write_text("".join(f"{k}={v}\n" for k, v in have.items()), encoding="utf-8")


if __name__ == "__main__":
    main()
