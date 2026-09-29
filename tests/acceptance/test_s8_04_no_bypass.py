"""S8-04 No bypass: agents cannot reach model providers directly and hold no provider credentials."""
from __future__ import annotations

import subprocess

import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")

CONNECT = """
import socket, sys
host, port = sys.argv[1], int(sys.argv[2])
try:
    socket.create_connection((host, port), timeout=4).close(); print("CONNECTED")
except Exception as e:
    print("BLOCKED:" + type(e).__name__)
"""
TARGETS = [("mock-local", 8000), ("mock-remote", 8000), ("postgres", 5432), ("redis", 6379),
           ("presidio-analyzer", 3000), ("control-plane", 8100), ("1.1.1.1", 443), ("api.openai.com", 443)]


def _probe(network, host, port):
    p = subprocess.run(["docker", "run", "--rm", "--network", network, "--label", "govpilot.t8test=1",
                        "--entrypoint", "python", L.PROBE_IMAGE, "-c", CONNECT, host, str(port)],
                       capture_output=True, text=True, timeout=60)
    return (p.stdout.strip().splitlines() or ["NO-OUTPUT:" + p.stderr[-200:]])[-1]


@pytest.mark.accept(
    id="S8-04", title="No bypass",
    criterion="From both agent networks: providers, databases, Presidio, control plane and the internet are "
              "unreachable, only the gateway / auth proxy answer; no provider credential in any agent container "
              "(environment, mounts, filesystem scan as the agent's uid)",
    simplification="Docker internal networks stand in for Kubernetes NetworkPolicy + egress firewall; one host.")
def test_no_bypass(record):
    results = {}
    for net, gate in ((L.AGENTS_NET, ("gateway", 4000)), (L.SSO_NET, ("sso-gateway", 8080))):
        assert _probe(net, *gate) == "CONNECTED", f"positive control failed on {net}"
        for host, port in TARGETS + ([("gateway", 4000)] if net == L.SSO_NET else []):
            out = _probe(net, host, port)
            results[f"{net} -> {host}:{port}"] = out
            assert out.startswith("BLOCKED:"), (net, host, port, out)
    # no provider credential in any agent container: environment, mounted host paths, and the container filesystem
    # (a credential discovery an escaped agent would attempt; the agents run as non-root, so only readable files
    # count, which is exactly what such an agent could read)
    env = L.read_env_file(L.ROOT / "deploy" / ".env")
    secrets = [env["MOCK_LOCAL_API_KEY"], env["MOCK_REMOTE_API_KEY"], env["LITELLM_MASTER_KEY"]]
    checked, fs_scanned = [], {}
    for c in L.dclient().containers.list(filters={"label": "govpilot.agent_id"}):
        blob = "\n".join(c.attrs["Config"]["Env"] or [])
        assert not any(s in blob for s in secrets), f"{c.name} holds a provider/master credential in its environment"
        for m in c.attrs.get("Mounts") or []:
            src = (m.get("Source") or "").replace("\\", "/")
            assert not (src.endswith(".env") or "/.local" in src or src.endswith("/deploy")), \
                f"{c.name} mounts a host path that carries secrets: {src}"
        hits = c.exec_run(["grep", "-rIlsF", *(x for s in secrets for x in ("-e", s)), "/",
                           "--exclude-dir=proc", "--exclude-dir=sys", "--exclude-dir=dev"])
        found = [l for l in hits.output.decode(errors="replace").splitlines() if l.strip()]
        assert not found, f"{c.name} has a provider/master credential on its filesystem: {found[:5]}"
        fs_scanned[c.name] = "no credential found (grep -r over / as the agent's own uid)"
        checked.append(c.name)
    assert {"gov-agent-hr", "gov-agent-finance", "gov-agent-coding"} <= set(checked)
    record(probes=results, agent_containers_checked=checked, filesystem_scan=fs_scanned,
           positive_controls={"govpilot_agents": "gateway:4000 CONNECTED", "govpilot_agents_sso": "sso-gateway:8080 CONNECTED"})
