"""Emergency-stop CLI: runs anywhere with the gateway admin key and Docker access.

    python -m govcp.estop.cli agent <agent_id> --reason "..." --operator alice
    python -m govcp.estop.cli team  <team>     --reason "..." --operator alice

Env: GATEWAY_URL (default http://127.0.0.1:4000), LITELLM_MASTER_KEY, ESTOP_JOURNAL
(default ./.local/estop-journal.jsonl), ESTOP_HELPER_IMAGE, ESTOP_CHOKEPOINTS.
Works with the control plane, its database and the IdP all down.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from ..adapters.docker_orchestrator import DockerNetworkQuarantine, DockerOrchestrator
from ..adapters.jsonl_audit import JsonlAuditSink
from ..adapters.litellm_gateway import LiteLLMGatewayAdmin
from .core import EmergencyStop


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="estop")
    ap.add_argument("kind", choices=["agent", "team"])
    ap.add_argument("target")
    ap.add_argument("--reason", required=True)
    ap.add_argument("--operator", default=os.environ.get("USER") or os.environ.get("USERNAME") or "cli")
    args = ap.parse_args(argv)
    key = os.environ.get("LITELLM_MASTER_KEY")
    if not key:
        print("LITELLM_MASTER_KEY is required", file=sys.stderr)
        return 2
    es = EmergencyStop(
        gateway=LiteLLMGatewayAdmin(os.environ.get("GATEWAY_URL", "http://127.0.0.1:4000"), key),
        orchestrator=DockerOrchestrator(),
        network=DockerNetworkQuarantine(
            governed_networks=os.environ.get("ESTOP_GOVERNED_NETWORKS", "govpilot_agents,govpilot_agents_sso").split(","),
            chokepoints=[c for c in os.environ.get("ESTOP_CHOKEPOINTS", "gov-gateway,gov-gateway-edge,gov-authproxy").split(",") if c],
            helper_image=os.environ.get("ESTOP_HELPER_IMAGE", "govpilot/control-plane:1"),
            drain_timeout_s=float(os.environ.get("ESTOP_DRAIN_TIMEOUT_S", "3"))),
        journal=JsonlAuditSink(os.environ.get("ESTOP_JOURNAL", os.path.join(".local", "estop-journal.jsonl"))))
    fn = es.stop_agent if args.kind == "agent" else es.stop_team
    out = fn(args.target, args.operator, args.reason)
    print(json.dumps(out, indent=2))
    return 0 if out["verify"]["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
