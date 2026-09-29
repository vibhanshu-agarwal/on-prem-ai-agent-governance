"""T9 hardening checks (report section 5, "the gateway itself gets attacked").

  1. an agent reaches inference routes only: admin/management/test routes are refused at the proxy
  2. the gateway container: read-only root fs, non-root, no capabilities, no-new-privileges, limits
  3. every platform container drops capabilities and blocks privilege escalation (documented exceptions listed)
  4. provider credentials exist only in the gateway; the master key only where the control plane needs it
  5. every third-party image and base image is pinned by digest and matches release/images.lock
"""
import json
import re
import time

import pytest

from conftest import EDGE, GATEWAY, ROOT, container_env, gov_containers, inspect, probe, sh

# -------------------------------------------------------------------------------------------------------------
# 1. admin routes are unreachable from the agents networks
# -------------------------------------------------------------------------------------------------------------
BLOCKED = [
    ("POST", "/key/generate"), ("POST", "/key/delete"), ("POST", "/key/block"), ("GET", "/key/list"),
    ("GET", "/key/info"), ("POST", "/key/update"), ("GET", "/key/health"),
    ("POST", "/team/new"), ("GET", "/team/list"), ("POST", "/team/update"),
    ("POST", "/user/new"), ("GET", "/user/list"), ("GET", "/user/info"),
    ("POST", "/organization/new"), ("GET", "/customer/list"),
    ("GET", "/mcp-rest/test/tools/list"), ("POST", "/mcp-rest/test/tools/call"), ("GET", "/mcp-rest/tools/list"),
    ("POST", "/model/new"), ("GET", "/model/info"), ("POST", "/model/delete"),
    ("GET", "/config/list"), ("POST", "/config/update"), ("GET", "/spend/logs"), ("GET", "/global/spend/report"),
    ("GET", "/health"), ("GET", "/health/readiness"), ("GET", "/health/services"),
    ("GET", "/metrics"), ("GET", "/openapi.json"), ("GET", "/docs"), ("GET", "/ui"), ("GET", "/routes"),
    ("GET", "/get/config/callbacks"), ("POST", "/v1/key/generate"), ("GET", "/v1/key/list"),
    ("POST", "/v1/messages"), ("POST", "/v1/responses"), ("POST", "/audio/transcriptions"),
    # smuggling attempts: traversal, encodings, slashes, case, trailing dots/semicolons
    ("GET", "/v1/models/../key/list"), ("GET", "/v1/models/%2e%2e/key/list"), ("GET", "/v1/chat/%2e%2e/key/list"),
    ("POST", "/v1/chat/completions/../../key/generate"), ("POST", "//key/generate"), ("POST", "/./key/generate"),
    ("GET", "/KEY/list"), ("GET", "/v1/models;/../key/list"), ("GET", "/v1/models%2f..%2fkey%2flist"),
    ("POST", "/%6bey/generate"), ("POST", "/key/generate/"), ("GET", "/v1/chat/completions/x"),
]

_PROBE = r"""
import json, sys, urllib.request as u, urllib.error as e
host, key = sys.argv[1], sys.argv[2]
out = {}
for method, path in json.loads(sys.argv[3]):
    req = u.Request(host + path, method=method, data=b"{}" if method == "POST" else None,
                    headers={"Content-Type": "application/json", **({"Authorization": "Bearer " + key} if key else {})})
    try:
        r = u.urlopen(req, timeout=8); out[method + " " + path] = [r.status, r.read()[:200].decode("latin1")]
    except e.HTTPError as x:
        out[method + " " + path] = [x.code, x.read()[:200].decode("latin1")]
    except Exception as x:
        out[method + " " + path] = ["ERR", type(x).__name__]
print(json.dumps(out))
"""


def _run_probe(host, key, routes, network):
    # `python -c` takes no extra argv, so the arguments are written into the script
    code = "import sys; sys.argv=['p'," + repr(host) + "," + repr(key) + "," + repr(json.dumps(routes)) + "]\n" + _PROBE
    r = probe(code, network=network)
    assert r.returncode == 0, r.stderr
    return json.loads(r.stdout.strip().splitlines()[-1])


@pytest.mark.parametrize("with_key", [False, True], ids=["anonymous", "with-agent-key"])
def test_agent_cannot_reach_admin_routes_through_the_edge(request, with_key):
    key = request.getfixturevalue("agent_key") if with_key else ""
    res = _run_probe("http://gateway:4000", key, BLOCKED, "govpilot_agents")
    # every one must be answered by the proxy itself: its 403 forbidden_route, or an nginx-generated error page
    # (400 for a path that climbs above the root). A 404/405 from LiteLLM would mean the request reached it.
    leaked = {k: v for k, v in res.items()
              if not (v[0] == 403 and "forbidden_route" in v[1]) and "<center>nginx</center>" not in v[1]}
    assert not leaked, f"routes that reached the gateway (or failed some other way): {leaked}"


_RAW = r'''
import json, socket
CRLF = "\r\n"
def send(lines, body=""):
    s = socket.create_connection(("gateway", 4000), timeout=8)
    s.sendall((CRLF.join(lines) + CRLF + CRLF + body).encode()); d = b""
    try:
        while len(d) < 20000:
            c = s.recv(65536)
            if not c: break
            d += c
    except OSError:
        pass
    s.close(); return d.decode("latin1")
H = ["Host: gateway", "Connection: close", "Authorization: Bearer " + KEY]
out = {}
out["absolute-uri"] = send(["GET http://gateway-core:4000/key/list HTTP/1.1"] + H)
for h in ("X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override", "X-Forwarded-Prefix"):
    v = "DELETE" if "Method" in h else "/key/list"
    out[h] = send(["GET /v1/models HTTP/1.1"] + H + [h + ": " + v])
out["websocket"] = send(["GET /v1/realtime?model=mock-local HTTP/1.1", "Host: gateway", "Upgrade: websocket",
                         "Connection: Upgrade", "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==",
                         "Sec-WebSocket-Version: 13"])
smuggled = "0" + CRLF + CRLF + "GET /key/list HTTP/1.1" + CRLF + "Host: x" + CRLF + CRLF
out["cl-te"] = send(["POST /v1/chat/completions HTTP/1.1", "Host: gateway", "Transfer-Encoding: chunked",
                     "Content-Length: %d" % len(smuggled)], smuggled)
out["pipelined"] = send(["GET /v1/models HTTP/1.1", "Host: gateway", "", "GET /key/list HTTP/1.1"] + H)
out["http09"] = send(["GET /key/list"])
print(json.dumps(out))
'''


def test_edge_ignores_rewrite_headers_absolute_uris_upgrades_and_smuggling(agent_key):
    """Raw-socket probes the urllib list above cannot express (with a real agent key). None may produce an admin
    answer; the rewrite headers must leave /v1/models answering with the model list."""
    r = probe(f"KEY = {agent_key!r}\n" + _RAW)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    for k, v in out.items():
        assert '"keys"' not in v and "user_api_key" not in v, (k, v[:400])
    assert "forbidden_route" in out["absolute-uri"] and "forbidden_route" in out["websocket"]
    assert not out["websocket"].startswith("HTTP/1.1 101"), out["websocket"][:300]
    for h in ("X-Original-URL", "X-Rewrite-URL", "X-HTTP-Method-Override", "X-Forwarded-Prefix"):
        assert '"object":"list"' in out[h], (h, out[h][-300:])        # still just the model list
    assert out["cl-te"].startswith("HTTP/1.1 400") and out["cl-te"].count("HTTP/1.1 ") == 1, out["cl-te"][:300]
    assert out["pipelined"].count("forbidden_route") == 1, out["pipelined"][-400:]
    assert "forbidden_route" in out["http09"]


def test_fail_closed_when_the_edge_proxy_is_down():
    """No fallback path: with gov-gateway-edge stopped, nothing on the agents network can resolve or reach any
    gateway address (the raw gateway is not on that network; the network is internal, so not the host port)."""
    ips = sh("docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}",
             GATEWAY).stdout.split()
    assert ips
    code = ("import socket\nout = []\n"
            "for h in ('gateway', 'gateway-core', 'gov-gateway', 'gov-gateway-edge', 'host.docker.internal'):\n"
            "    try:\n        socket.gethostbyname(h); out.append('RESOLVED ' + h)\n"
            "    except OSError:\n        pass\n"
            f"for ip in {ips!r}:\n"
            "    try:\n        socket.create_connection((ip, 4000), timeout=3); out.append('CONNECTED ' + ip)\n"
            "    except OSError:\n        pass\n"
            "print('LEAKS', out)\n")
    sh("docker", "stop", EDGE)
    try:
        r = probe(code)
    finally:
        sh("docker", "start", EDGE)
        for _ in range(60):
            if sh("docker", "inspect", "-f", "{{.State.Health.Status}}", EDGE, check=False).stdout.strip() == "healthy":
                break
            time.sleep(1)
    assert "LEAKS []" in r.stdout, r.stdout + r.stderr
    assert sh("docker", "inspect", "-f", "{{.State.Health.Status}}", EDGE).stdout.strip() == "healthy"


def test_edge_forwards_inference_routes(agent_key):
    routes = [("GET", "/v1/models"), ("GET", "/health/liveliness"), ("POST", "/v1/chat/completions")]
    res = _run_probe("http://gateway:4000", agent_key, routes, "govpilot_agents")
    assert res["GET /v1/models"][0] == 200
    assert res["GET /health/liveliness"][0] == 200
    # a real gateway answer (400 from the run-id / body checks), not the proxy's 403
    assert res["POST /v1/chat/completions"][0] in (200, 400, 422), res["POST /v1/chat/completions"]


def test_agents_network_cannot_reach_the_raw_gateway():
    # `gateway-core` only exists on the internal gwfront network; the raw gateway's backend IP is unrouted from agents
    code = ("import socket\nfor h in ('gateway-core','gov-gateway'):\n"
            "    try:\n        socket.gethostbyname(h); print('RESOLVED', h)\n    except OSError:\n        print('NX', h)\n")
    out = probe(code).stdout
    assert "RESOLVED" not in out, out
    ip = sh("docker", "inspect", "-f", '{{(index .NetworkSettings.Networks "govpilot_backend").IPAddress}}', GATEWAY).stdout.strip()
    r = probe(f"import socket\ntry:\n    socket.create_connection(({ip!r},4000),timeout=3); print('CONNECTED')\n"
              f"except OSError as x:\n    print('BLOCKED', type(x).__name__)\n")
    assert r.stdout.strip().startswith("BLOCKED"), r.stdout + r.stderr


def test_sso_agents_cannot_reach_admin_routes_through_the_auth_proxy():
    routes = [("POST", "/v1/key/generate"), ("GET", "/v1/key/list"), ("GET", "/v1/team/list"),
              ("POST", "/v1/mcp-rest/test/tools/call"), ("GET", "/v1/chat/completions/../key/list")]
    res = _run_probe("http://sso-gateway:8080", "", routes, "govpilot_agents_sso")
    # the route check comes before authentication: 403 forbidden_route (or 404/405), never a gateway answer
    assert all(v[0] in (403, 404, 405) for v in res.values()), res


def test_admin_path_still_works_for_the_control_plane(env):
    """The other side of the split: the operator port and the control plane reach admin routes."""
    import httpx
    r = httpx.get(f"http://127.0.0.1:{env.get('GATEWAY_PORT', '4000')}/key/list", timeout=10,
                  headers={"Authorization": f"Bearer {env['LITELLM_MASTER_KEY']}"})
    assert r.status_code == 200
    code = ("import os, urllib.request as u\n"
            "r = u.Request('http://gateway:4000/key/list', headers={'Authorization': 'Bearer ' + os.environ['LITELLM_MASTER_KEY']})\n"
            "print(u.urlopen(r, timeout=8).status)\n")
    out = sh("docker", "exec", "gov-control-plane", "python", "-c", code, check=False)
    assert out.stdout.strip() == "200", out.stdout + out.stderr


def test_nginx_config_is_an_allowlist():
    conf = (ROOT / "deploy" / "hardening" / "nginx.conf").read_text()
    locs = re.findall(r"location\s+(=\s+)?(\S+)\s*\{", conf)
    exact = {p for eq, p in locs if eq}
    assert exact == {"/v1/chat/completions", "/chat/completions", "/v1/completions", "/completions", "/v1/embeddings",
                     "/embeddings", "/v1/models", "/models", "/health/liveliness", "/health/liveness"}, exact
    fallback = [p for eq, p in locs if not eq]
    assert fallback == ["/"] and re.search(r"location / \{\s*return 403", conf), "the catch-all must deny"


# -------------------------------------------------------------------------------------------------------------
# 2. the gateway container
# -------------------------------------------------------------------------------------------------------------
def test_gateway_root_filesystem_is_read_only():
    assert inspect(GATEWAY)["HostConfig"]["ReadonlyRootfs"] is True
    for path in ("/app/x", "/etc/x", "/usr/x", "/app/litellm/x"):
        r = sh("docker", "exec", GATEWAY, "sh", "-c", f"touch {path}", check=False)
        assert r.returncode != 0 and ("Read-only" in r.stderr or "denied" in r.stderr), (path, r.stderr)
    assert sh("docker", "exec", GATEWAY, "sh", "-c", "touch /tmp/x && rm /tmp/x", check=False).returncode == 0  # tmpfs works


def test_gateway_runs_as_non_root():
    out = sh("docker", "exec", GATEWAY, "id", "-u").stdout.strip()
    assert out != "0", "gateway runs as root"
    assert inspect(GATEWAY)["Config"]["User"] not in ("", "root", "0")
    # and it can still write the state it must own (guardrail audit log, overrides, approvals)
    r = sh("docker", "exec", GATEWAY, "sh", "-c",
           "touch /app/guardrails-state/.hardening-probe && rm /app/guardrails-state/.hardening-probe", check=False)
    assert r.returncode == 0, r.stderr


@pytest.mark.parametrize("name", [GATEWAY, EDGE])
def test_gateway_and_edge_drop_all_capabilities(name):
    hc = inspect(name)["HostConfig"]
    assert hc["CapDrop"] == ["ALL"] and not hc.get("CapAdd"), (hc["CapDrop"], hc.get("CapAdd"))
    assert any(o.startswith("no-new-privileges") for o in hc["SecurityOpt"] or [])
    assert not hc["Privileged"]
    status = sh("docker", "exec", name, "cat", "/proc/1/status").stdout
    for field in ("CapEff", "CapPrm", "CapBnd"):
        assert re.search(rf"{field}:\s*0+\s*$", status, re.M), (field, status)


@pytest.mark.parametrize("name", [GATEWAY, EDGE])
def test_gateway_and_edge_have_resource_limits(name):
    hc = inspect(name)["HostConfig"]
    assert hc["Memory"] > 0 and (hc["PidsLimit"] or 0) > 0, hc


def test_edge_is_read_only_and_non_root():
    assert inspect(EDGE)["HostConfig"]["ReadonlyRootfs"] is True
    assert sh("docker", "exec", EDGE, "id", "-u").stdout.strip() != "0"


# -------------------------------------------------------------------------------------------------------------
# 3. the rest of the platform
# -------------------------------------------------------------------------------------------------------------
# Containers that legitimately keep something, with the reason. Everything else must drop ALL capabilities with
# nothing added. postgres/clickhouse keep the few capabilities their entrypoints need to chown a data directory and
# drop to their service user; the eBPF controller is privileged by design (opt-in profile).
CAP_ADD_ALLOWED = {
    "gov-postgres": {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"},
    "gov-cp-postgres": {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"},
    "gov-obs-clickhouse": {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID", "KILL"},
}
PRIVILEGED_BY_DESIGN = {"gov-obs-controller"}
NOT_READ_ONLY = {   # images that write to their root filesystem at run time; documented in docs/results/T9.md
    "gov-obs-clickhouse", "gov-obs-openlit", "gov-obs-grafana", "gov-obs-controller", "gov-presidio-analyzer",
    "gov-presidio-anonymizer",
}


def _platform():
    return [n for n in gov_containers() if n not in PRIVILEGED_BY_DESIGN]


def test_every_platform_container_drops_capabilities_and_blocks_escalation():
    bad = []
    for n in _platform():
        hc = inspect(n)["HostConfig"]
        added = {c.removeprefix("CAP_") for c in hc.get("CapAdd") or []}
        if hc["CapDrop"] != ["ALL"] or not added <= CAP_ADD_ALLOWED.get(n, set()) or hc["Privileged"]:
            bad.append((n, hc["CapDrop"], sorted(added), hc["Privileged"]))
        if not any(o.startswith("no-new-privileges") for o in hc["SecurityOpt"] or []):
            bad.append((n, "no-new-privileges missing"))
    assert not bad, bad


def test_every_platform_container_has_a_read_only_root_except_documented():
    bad = [n for n in _platform() if n not in NOT_READ_ONLY and not inspect(n)["HostConfig"]["ReadonlyRootfs"]]
    assert not bad, f"not read-only: {bad}"


def test_only_documented_containers_are_privileged_or_mount_the_docker_socket():
    socket_ok = {"gov-control-plane", "gov-estop", "gov-discovery", "gov-obs-controller"}
    for n in gov_containers():
        c = inspect(n)
        if any("docker.sock" in (m.get("Source") or "") for m in c["Mounts"]):
            assert n in socket_ok, f"{n} mounts the Docker socket"
        if c["HostConfig"]["Privileged"]:
            assert n in PRIVILEGED_BY_DESIGN, f"{n} is privileged"


# -------------------------------------------------------------------------------------------------------------
# 4. credentials
# -------------------------------------------------------------------------------------------------------------
def test_provider_credentials_only_in_the_gateway(env):
    secrets = {"provider-local": env["MOCK_LOCAL_API_KEY"], "provider-remote": env["MOCK_REMOTE_API_KEY"],
               "salt": env["LITELLM_SALT_KEY"]}
    for n in gov_containers():
        if n == GATEWAY:
            continue
        blob = json.dumps(container_env(n))
        for what, s in secrets.items():
            assert s not in blob, f"{n} holds the gateway's {what} secret"


def test_master_key_only_in_gateway_and_the_control_plane_side(env):
    allowed = {GATEWAY, "gov-control-plane", "gov-estop"}
    for n in gov_containers():
        if n in allowed:
            continue
        assert env["LITELLM_MASTER_KEY"] not in json.dumps(container_env(n)), f"{n} holds the gateway master key"


def test_no_agent_or_edge_container_has_credential_like_env():
    for n in gov_containers():
        if not (n.startswith("gov-agent-") or n in (EDGE, "gov-delegation-broker", "gov-status-page")):
            continue
        keys = [k for k in container_env(n) if re.search(r"MASTER_KEY|SALT_KEY|PROVIDER|MOCK_.*API_KEY", k)]
        assert not keys, f"{n}: {keys}"


def test_agent_containers_are_not_on_provider_or_backend_networks():
    for n in gov_containers():
        if not n.startswith("gov-agent-"):
            continue
        nets = set(inspect(n)["NetworkSettings"]["Networks"])
        assert not nets & {"govpilot_providers", "govpilot_backend", "govpilot_edge", "govpilot_gwfront"}, (n, nets)


# -------------------------------------------------------------------------------------------------------------
# 5. pinned digests
# -------------------------------------------------------------------------------------------------------------
def _lock():
    p = ROOT / "release" / "images.lock"
    assert p.exists(), "release/images.lock missing (scripts/release.sh)"
    out = {}
    for line in p.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            ref, digest = line.split()[:2]
            out[ref] = digest
    return out


def _compose_files():
    return (list((ROOT / "deploy").glob("*.yml")) + list((ROOT / "deploy" / "hardening").glob("*.yml"))
            + list((ROOT / "tests").glob("*/stack/*.yml")))


def test_every_third_party_image_in_compose_files_is_pinned_by_digest():
    refs = []
    for f in _compose_files():
        for m in re.finditer(r"^\s*image:\s*(\S+)", f.read_text(encoding="utf-8"), re.M):
            refs.append((f.name, m.group(1)))
    assert refs
    for fname, ref in refs:
        if ref.startswith("govpilot/"):
            continue      # built from this repo; its base image is pinned in the Dockerfile (checked below)
        assert re.search(r"@sha256:[0-9a-f]{64}$", ref), f"{fname}: {ref} is not pinned by digest"


def test_every_dockerfile_base_image_is_pinned_by_digest():
    files = list((ROOT / "services").glob("*/Dockerfile")) + [ROOT / "agents" / "Dockerfile"]
    assert len(files) >= 5
    for f in files:
        froms = re.findall(r"^FROM\s+(\S+)", f.read_text(encoding="utf-8"), re.M)
        assert froms, f
        for ref in froms:
            assert re.search(r"@sha256:[0-9a-f]{64}$", ref), f"{f.relative_to(ROOT)}: FROM {ref} is not pinned"


def test_lock_file_matches_the_pins_in_the_repo():
    lock = _lock()
    for f in _compose_files():
        for m in re.finditer(r"^\s*image:\s*(\S+?)@(sha256:[0-9a-f]{64})", f.read_text(encoding="utf-8"), re.M):
            assert lock.get(m.group(1)) == m.group(2), f"{f.name}: {m.group(1)} differs from release/images.lock"


def test_running_third_party_containers_use_the_locked_digests():
    lock = _lock()
    for n in gov_containers():
        c = inspect(n)
        ref = c["Config"]["Image"]
        if ref.startswith("govpilot/"):
            continue
        base, _, want = ref.partition("@")
        assert want, f"{n} was started from an unpinned reference {ref!r}"
        assert lock.get(base) == want, f"{n}: {base} is not in release/images.lock at {want}"


# -------------------------------------------------------------------------------------------------------------
# 6. hygiene: no leaked quarantine helper containers (network-cut helpers were left behind by failed starts)
# -------------------------------------------------------------------------------------------------------------
def test_no_leaked_network_cut_helper_containers():
    out = sh("docker", "ps", "-a", "--filter", "label=govpilot.role=quarantine-helper", "--format", "{{.Names}} {{.Status}}").stdout
    assert out.strip() == "", f"leaked helper containers: {out}"


def test_status_page_is_reachable_only_from_the_control_plane_side():
    """T3/T10 leftover: containers on the internal networks used to reach :8400 with a spoofed Host header."""
    nets = set(inspect("gov-status-page")["NetworkSettings"]["Networks"])
    assert nets == {"govpilot_statusnet", "govpilot_statuspub"}, nets
    members = set(sh("docker", "network", "inspect", "govpilot_statusnet", "-f",
                     "{{range .Containers}}{{.Name}} {{end}}").stdout.split())
    assert members == {"gov-status-page", "gov-control-plane", "gov-idp"}, members
    ip = sh("docker", "inspect", "-f", '{{(index .NetworkSettings.Networks "govpilot_statuspub").IPAddress}}',
            "gov-status-page").stdout.strip()
    # from the network the delegation broker (agent-facing) and the auth proxy share: no route to it
    for net in ("govpilot_cpinternal", "govpilot_agents_sso"):
        r = probe(f"import socket\ntry:\n    socket.create_connection(('gov-status-page',8400),timeout=3); print('CONNECTED')\n"
                  f"except OSError as x:\n    print('BLOCKED', type(x).__name__)\n", network=net)
        assert r.stdout.strip().startswith("BLOCKED"), (net, r.stdout, r.stderr)
    assert ip  # published through its private bridge only
