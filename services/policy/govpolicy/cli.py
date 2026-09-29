"""policyctl: build, sign, verify, activate, roll back and admit against policy bundles.

Configuration (flag > env > default):
  POLICY_DIR (policy/), POLICY_STORE (.local/policy/store), POLICY_SIGNING_KEY (.local/policy/signing.key),
  POLICY_TRUST_DIR (policy/trust), POLICY_SIGNER / POLICY_VERIFIER ("ed25519" or "pkg.mod:factory").
Exit codes: 0 ok / admitted, 1 denied, 2 error (fail closed).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .admission import AdmissionRequest, admit
from .bundle import BundleError, verify_bundle
from .schema import PolicyError, compile_policy_dir, json_schema
from .signing import Ed25519Signer, SignatureError, make_signer, make_verifier
from .store import PolicyLoadError, PolicyStore

REPO = Path(__file__).resolve().parents[3]


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="policyctl", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--policy-dir", default=_env("POLICY_DIR", str(REPO / "policy")))
    p.add_argument("--store", default=_env("POLICY_STORE", str(REPO / ".local/policy/store")))
    p.add_argument("--key", default=_env("POLICY_SIGNING_KEY", str(REPO / ".local/policy/signing.key")))
    p.add_argument("--trust-dir", default=_env("POLICY_TRUST_DIR", str(REPO / "policy/trust")))
    p.add_argument("--signer", default=_env("POLICY_SIGNER", "ed25519"))
    p.add_argument("--verifier", default=_env("POLICY_VERIFIER", "ed25519"))
    sub = p.add_subparsers(dest="cmd", required=True)
    k = sub.add_parser("keygen", help="generate the local Ed25519 signing key + committed public key")
    k.add_argument("--force", action="store_true")
    sub.add_parser("validate", help="validate policy files without signing")
    sub.add_parser("schema", help="print the JSON Schema of the compiled policy")
    b = sub.add_parser("build", help="validate, sign and store a new bundle version")
    b.add_argument("--activate", action="store_true")
    a = sub.add_parser("activate", help="verify and activate a stored bundle version")
    a.add_argument("version")
    a.add_argument("--reason", default="")
    r = sub.add_parser("rollback", help="activate the previous (or given) signed bundle version")
    r.add_argument("--to")
    r.add_argument("--reason", default="")
    sub.add_parser("status", help="show the active verified bundle")
    sub.add_parser("history", help="show the append-only history of effective versions")
    v = sub.add_parser("verify", help="verify a bundle file")
    v.add_argument("file")
    d = sub.add_parser("admit", help="admission check for a deployment request against the active bundle")
    d.add_argument("--agent", required=True)
    d.add_argument("--image", required=True)
    d.add_argument("--capability", action="append", default=[])
    d.add_argument("--tier", required=True)
    d.add_argument("--json", action="store_true")
    dr = sub.add_parser("drift", help="compare deploy/agents.json provisioning with the active policy")
    dr.add_argument("--agents-json", default=str(REPO / "deploy/agents.json"))
    return p


def _out(o) -> None:
    print(json.dumps(o, indent=2))


def run(argv=None) -> int:
    a = _parser().parse_args(argv)
    if a.cmd == "keygen":
        s = Ed25519Signer.generate(a.key, a.trust_dir, force=a.force)
        print(f"key_id={s.key_id}\nprivate key: {a.key} (keep local, gitignored)\n"
              f"public key : {a.trust_dir}/{s.key_id}.pub.json (commit via PR)")
        return 0
    if a.cmd == "validate":
        p = compile_policy_dir(a.policy_dir)
        print(f"ok: {len(p.teams)} teams, {len(p.agents)} agents")
        return 0
    if a.cmd == "schema":
        _out(json_schema())
        return 0
    verifier = make_verifier(a.verifier, a.trust_dir)
    if a.cmd == "verify":
        b = verify_bundle(Path(a.file).read_bytes(), verifier)
        _out({"verified": True, "manifest": b.manifest, "signature_key_id": b.signature.key_id})
        return 0
    store = PolicyStore(a.store, verifier)
    if a.cmd == "build":
        b = store.publish(a.policy_dir, make_signer(a.signer, a.key))
        if a.activate:
            store.activate(b.version, reason="build --activate")
        _out({"published": b.version, "active": store.active_version(), "manifest": b.manifest})
    elif a.cmd == "activate":
        b = store.activate(a.version, a.reason)
        _out({"active": b.version})
    elif a.cmd == "rollback":
        b = store.rollback(a.to, a.reason)
        _out({"active": b.version, "rolled_back": True})
    elif a.cmd == "status":
        b = store.load_active()
        _out({"active": b.version, "manifest": b.manifest, "agents": sorted(b.policy.agents)})
    elif a.cmd == "history":
        for e in store.history():
            print(json.dumps(e, sort_keys=True))
    elif a.cmd == "admit":
        b = store.load_active()
        dec = admit(b.policy, AdmissionRequest(a.agent, a.image, a.capability, a.tier), b.version)
        if a.json:
            _out(dec.to_dict())
        else:
            print(f"{'ADMIT' if dec.allowed else 'DENY'} {a.agent} (policy {b.version})")
            for r in dec.reasons:
                print(f"  - {r}")
        return 0 if dec.allowed else 1
    elif a.cmd == "drift":
        b = store.load_active()
        prov = json.loads(Path(a.agents_json).read_text(encoding="utf-8"))
        problems = []
        for name, cfg in prov.get("agents", {}).items():
            ap = b.policy.agent(name)
            if ap is None:
                problems.append(f"{name}: provisioned but not in policy")
                continue
            extra = set(cfg.get("models", [])) - set(ap.models)
            if extra:
                problems.append(f"{name}: provisioned models outside allowlist: {sorted(extra)}")
            if cfg.get("max_budget", 0) > ap.budget.max_usd:
                problems.append(f"{name}: provisioned budget {cfg['max_budget']} > policy {ap.budget.max_usd}")
        _out({"policy": b.version, "drift": problems})
        return 1 if problems else 0
    return 0


def main(argv=None) -> None:
    try:
        sys.exit(run(argv))
    except (PolicyError, PolicyLoadError, BundleError, SignatureError, OSError, ValueError) as e:
        print(f"ERROR (fail closed): {e}", file=sys.stderr)
        sys.exit(2)
