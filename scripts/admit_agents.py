#!/usr/bin/env python3
"""Deploy-time admission gate for agent containers (T8; the Docker stand-in for a k8s admission webhook).

Reads an agents compose file, and for every service that carries a `govpilot.agent_id` label runs the
T7 admission check (`govpolicy.admit`) against the ACTIVE signed policy bundle:
    agent in the signed policy, image allowed, requested capabilities declared,
    requested sandbox tier (`govpilot.sandbox_tier`) >= the tier its capabilities demand.
Exit 0 only when every agent service is admitted; 1 on any deny; 2 on error (no/invalid bundle = deny,
fail closed). scripts/agents-up.sh runs this BEFORE `docker compose up`, so a denied agent is never
created. Every decision is appended to .local/policy/admission.jsonl (evidence).

    python scripts/admit_agents.py [--compose deploy/compose.agents.yml] [--json]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "policy"))
from govpolicy import AdmissionRequest, Ed25519Verifier, PolicyStore, admit  # noqa: E402
from govpolicy.store import PolicyLoadError  # noqa: E402

STORE = Path(os.environ.get("POLICY_STORE", ROOT / ".local" / "policy" / "store"))
TRUST = Path(os.environ.get("POLICY_TRUST_DIR", ROOT / "policy" / "trust"))
LOG = ROOT / ".local" / "policy" / "admission.jsonl"


def agent_services(compose_file: Path) -> list[dict]:
    doc = yaml.safe_load(compose_file.read_text(encoding="utf-8"))   # resolves anchors and << merges
    out = []
    for name, svc in (doc.get("services") or {}).items():
        labels = svc.get("labels") or {}
        if isinstance(labels, list):
            labels = dict(l.split("=", 1) for l in labels)
        if "govpilot.agent_id" not in labels:
            continue
        caps = [c.strip() for c in str(labels.get("govpilot.capabilities", "")).split(",") if c.strip()]
        out.append({"service": name, "agent_id": labels["govpilot.agent_id"], "image": svc.get("image", ""),
                    "capabilities": caps, "tier": labels.get("govpilot.sandbox_tier", "container")})
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--compose", default=str(ROOT / "deploy" / "compose.agents.yml"))
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    try:
        bundle = PolicyStore(STORE, Ed25519Verifier.from_trust_dir(TRUST)).load_active()
    except (PolicyLoadError, OSError, ValueError) as e:
        print(f"ADMISSION ERROR (fail closed): no verified policy bundle: {e}", file=sys.stderr)
        return 2
    results, ok = [], True
    for s in agent_services(Path(a.compose)):
        d = admit(bundle.policy, AdmissionRequest(s["agent_id"], s["image"], s["capabilities"], s["tier"]),
                  bundle.version)
        ok &= d.allowed
        results.append({**s, **d.to_dict()})
    LOG.parent.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                "compose": str(a.compose), **r}, sort_keys=True) + "\n")
    if a.json:
        print(json.dumps({"admitted": ok, "policy_version": bundle.version, "results": results}, indent=2))
    else:
        for r in results:
            print(f"{'ADMIT' if r['allowed'] else 'DENY '} {r['agent_id']:<22} tier={r['tier']:<9} "
                  f"image={r['image']} (policy {bundle.version})")
            if not r["allowed"]:
                for why in r["reasons"]:
                    print(f"        - {why}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
