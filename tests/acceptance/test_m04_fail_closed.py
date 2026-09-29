"""M-04 Fail closed: gateway / policy / ledger / guardrail / control-plane outages reject new requests; an
evidence-plane outage does not bypass enforcement. M-05 break-glass is time-limited and audited.

Each drill stops a real component of the running stack and restores it in `finally` (waiting for health).
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import time

import httpx
import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")


def _msg():
    # unique text: the guardrail pipeline caches the analysis of a message it has already seen, and a cached
    # (genuine) result is served during an engine outage by design
    return [{"role": "user", "content": f"please reconcile invoice batch {L.uid('b')} for the vendor"}]


def _call(key, model="mock-local", timeout=60, **extra):
    try:
        r = httpx.post(f"{L.GW_URL}/v1/chat/completions", timeout=timeout, json={
            "model": model, "messages": _msg(), "max_tokens": 8, **extra},
            headers={"Authorization": f"Bearer {key}", "x-govpilot-run-id": "run-" + L.uid("m04").replace("-", "")})
        return r.status_code, r
    except httpx.HTTPError as e:
        return type(e).__name__, None


def _code(r):
    try:
        e = r.json()["error"]
        return (e.get("provider_specific_fields") or {}).get("guardrail_code") or e.get("code") or e.get("type")
    except Exception:  # noqa: BLE001
        return None


def _stop(name):
    L.dclient().containers.get(name).stop(timeout=5)


def _start(*names, timeout=240):
    for n in names:
        L.dclient().containers.get(n).start()
    L.wait_healthy(*names, timeout=timeout)


def _wait_served(key, timeout=240):
    return L.wait_until(lambda: _call(key)[0] == 200, timeout=timeout, interval=3.0)


# ------------------------------------------------------------------------------------------ guardrail engine
@pytest.mark.accept(
    id="M-04a", title="Fail closed: guardrail engine outage",
    criterion="Presidio analyzer down: a confidential agent's request gets 503 guardrail_engine_unavailable; "
              "an internal agent degrades to the builtin engine (audited); service resumes after recovery",
    simplification="Fail modes by data classification from deploy/guardrails/guardrails.yaml; one analyzer "
                   "instance (no HA pair).")
def test_guardrail_engine_outage(record):
    fin = L.mint_key(budget=0.05, models=["mock-local"], metadata={"agent_id": "finance-recon-agent", "team": "finance",
                                                                   "t8": "m04a"})
    cod = L.mint_key(budget=0.05, models=["mock-local"], metadata={"agent_id": "coding-agent", "team": "engineering",
                                                                   "t8": "m04a"})
    try:
        assert _call(fin["key"])[0] == 200
        _stop("gov-presidio-analyzer")
        try:
            t0 = time.time()
            got = L.wait_until(lambda: (lambda s: s if s[0] == 503 else None)(_call(fin["key"])), timeout=30)
            assert got, "confidential agent was not refused while the engine was down"
            closed_after_s = time.time() - t0
            s_int, r_int = _call(cod["key"])
            record(confidential_status=503, confidential_code=_code(got[1]), refused_after_s=round(closed_after_s, 1),
                   internal_status=s_int)
            assert _code(got[1]) == "guardrail_engine_unavailable"
            assert s_int == 200                                   # degrade (builtin engine), audited
            # M-05 break-glass during the same outage
            _breakglass(fin["key"])
        finally:
            _start("gov-presidio-analyzer")
        assert L.wait_until(lambda: _call(fin["key"])[0] == 200, timeout=60)
    finally:
        L.delete_keys(fin["token"], cod["token"])


_BG = {}


def _guardctl(*args):
    env = {**os.environ, "PYTHONPATH": str(L.ROOT / "services" / "guardrails"),
           "GOVGUARD_STATE_DIR": str(L.ROOT / ".local" / "guardrails")}
    return subprocess.run([sys.executable, "-m", "govguard", *args], capture_output=True, text=True, env=env,
                          cwd=L.ROOT, timeout=60)


def _breakglass(fin_key):
    too_long = _guardctl("override", "grant", "--agent", "finance-recon-agent", "--rule", "breakglass", "--ttl", "2h",
                         "--reason", "presidio outage during month-end close", "--by", "alice")
    g = _guardctl("override", "grant", "--agent", "finance-recon-agent", "--rule", "breakglass", "--ttl", "25s",
                  "--reason", "presidio outage during month-end close", "--by", "alice")
    assert g.returncode == 0, g.stdout + g.stderr
    t0 = time.time()
    ok = L.wait_until(lambda: _call(fin_key)[0] == 200, timeout=10, interval=0.5)
    used_after = time.time() - t0
    t_exp = t0 + 25
    time.sleep(max(0.0, t_exp - time.time()) + 3)
    after = _call(fin_key)
    audit = (L.ROOT / ".local" / "guardrails" / "audit.jsonl").read_text(encoding="utf-8").splitlines()[-4000:]
    evs = [json.loads(l) for l in audit if 'breakglass' in l or '"override.' in l]
    _BG.update(grant_over_1h_refused=too_long.returncode != 0, served_with_breakglass=bool(ok),
               breakglass_effective_after_s=round(used_after, 1), status_after_expiry=after[0],
               code_after_expiry=_code(after[1]) if after[1] is not None else None,
               audit_events=sorted({e.get("event") for e in evs}))
    assert too_long.returncode != 0 and ok and after[0] == 503


@pytest.mark.accept(
    id="M-05", title="Break-glass is time-limited and audited",
    criterion="During a guardrail-engine outage an operator grant (reason, named approver, TTL <= 1 h) lets a "
              "fail-closed agent through on the builtin engine (never fail-open); it expires by itself; grant and "
              "every use are audit events",
    simplification="Break-glass exists for the guardrail engine only (CLI + file store, like T5 overrides); budget "
                   "enforcement and identity have no break-glass by design (report: never cut budget enforcement); "
                   "no second-person approval or paging.")
def test_breakglass_recorded(record):
    if not _BG:
        pytest.skip("runs inside M-04a (needs the engine outage)")
    record(**_BG)
    assert {"override.granted", "override.used", "guardrail.breakglass_degraded"} <= set(_BG["audit_events"])


# ------------------------------------------------------------------------------------------ ledger: Redis
@pytest.mark.accept(
    id="M-04b", title="Fail closed: ledger (Redis spend counters) outage",
    criterion="Redis down: budgeted requests are refused (5xx), never served unmetered; enforcement resumes "
              "after Redis returns, with the persisted counter",
    simplification="Single Redis with AOF persistence; no Sentinel/cluster failover. Unbudgeted keys keep working "
                   "(nothing to enforce), as in native LiteLLM.")
def test_redis_outage(record):
    k = L.mint_key(budget=0.05, metadata={"agent_id": L.uid("t8redis")})
    try:
        assert _call(k["key"])[0] == 200
        _stop("gov-redis")
        try:
            t0 = time.time()
            statuses = []
            for _ in range(4):
                s, _r = _call(k["key"], timeout=90)
                statuses.append(s)
            first_s = time.time() - t0
            record(statuses_while_down=statuses, seconds_for_4_requests=round(first_s, 1))
            assert 200 not in statuses, statuses
        finally:
            _start("gov-redis")
        t1 = time.time()
        assert _wait_served(k["key"], timeout=300), "budget enforcement did not come back"
        record(recovery_after_redis_back_s=round(time.time() - t1, 1))
    finally:
        L.delete_keys(k["token"])


# ------------------------------------------------------------------------------------------ spend DB: Postgres
@pytest.mark.accept(
    id="M-04c", title="Fail closed: spend DB (Postgres) outage",
    criterion="LiteLLM's Postgres down: budgeted requests are refused within seconds (budget guard DB gate), "
              "service resumes after recovery",
    simplification="Single Postgres, no replica/failover; spend written during the outage window relies on the "
                   "Redis counter (see T2 residual risks).")
def test_postgres_outage(record):
    k = L.mint_key(budget=0.05, metadata={"agent_id": L.uid("t8pg")})
    try:
        assert _call(k["key"])[0] == 200
        _stop("gov-postgres")
        t0 = time.time()
        try:
            got = L.wait_until(lambda: (lambda s: s if s[0] != 200 else None)(_call(k["key"], timeout=30)),
                               timeout=60, interval=0.5)
            refused_after = time.time() - t0
            assert got, "budgeted requests kept being served with the spend DB down"
            later = [_call(k["key"], timeout=30)[0] for _ in range(3)]
            record(first_refusal_after_s=round(refused_after, 1), refusal_status=got[0],
                   refusal_code=_code(got[1]) if got[1] is not None else None, later_statuses=later)
            assert 200 not in later
        finally:
            _start("gov-postgres")
        t1 = time.time()
        assert _wait_served(k["key"], timeout=300)
        record(recovery_s=round(time.time() - t1, 1))
    finally:
        L.delete_keys(k["token"])


# ------------------------------------------------------------------------------------------ control plane
@pytest.mark.accept(
    id="M-04d", title="Fail closed: control-plane outage (SSO route)",
    criterion="Control plane down: the auth proxy refuses SSO agents (it cannot map the JWT to a key) instead "
              "of passing them through; service resumes after recovery",
    simplification="Auth-proxy mapping cache 5 s (config); key-route agents keep working through a control-plane "
                   "outage by design (the gateway key is the enforcement point).")
def test_control_plane_outage(drill, record):
    client_id = L.uid("t8-cpo")
    r = L.cpclient.idp_admin("POST", "/admin/clients", json={"client_id": client_id, "roles": ["agent"]})
    secret = r.json()["client_secret"]
    drill.agent(L.uid("t8cpo"), oidc_subjects=[client_id], passthrough=False)
    tok = L.cpclient.client_token(client_id, secret).json()["access_token"]
    assert L.chat(tok, base=L.AUTHPROXY_URL).status_code == 200
    _stop("gov-control-plane")
    try:
        time.sleep(6)                                          # past the proxy's resolve cache
        s = L.chat(tok, base=L.AUTHPROXY_URL, timeout=30).status_code
        record(status_with_control_plane_down=s)
        assert s != 200 and s >= 400
    finally:
        _start("gov-control-plane")
    assert L.wait_until(lambda: L.chat(tok, base=L.AUTHPROXY_URL).status_code == 200, timeout=60)


# ------------------------------------------------------------------------------------------ gateway
@pytest.mark.accept(
    id="M-04e", title="Fail closed: gateway outage",
    criterion="Gateway down: an agent-network container can reach neither the gateway nor any provider (no "
              "route around it); service resumes after the gateway restarts",
    simplification="One gateway replica: its outage is a full stop of AI traffic (HA is out of pilot scope).")
def test_gateway_outage(record):
    code = ("import socket,sys\nfor h,p in (('gateway',4000),('mock-local',8000),('mock-remote',8000)):\n"
            "  try: socket.create_connection((h,p),timeout=4).close(); print(h,'CONNECTED')\n"
            "  except Exception as e: print(h,'BLOCKED',type(e).__name__)\n")
    _stop("gov-gateway")
    try:
        p = subprocess.run(["docker", "run", "--rm", "--network", L.AGENTS_NET, "--label", "govpilot.t8test=1",
                            "--entrypoint", "python", L.PROBE_IMAGE, "-c", code], capture_output=True, text=True,
                           timeout=60)
        lines = p.stdout.strip().splitlines()
        record(probe_while_gateway_down=lines)
        assert lines and all("BLOCKED" in l for l in lines), p.stdout + p.stderr
    finally:
        t0 = time.time()
        _start("gov-gateway", timeout=300)
        record(gateway_back_after_s=round(time.time() - t0, 1))


# ------------------------------------------------------------------------------------------ evidence plane
async def _burst(key, n):
    async with httpx.AsyncClient(timeout=120) as c:
        async def one(i):
            r = await c.post(f"{L.GW_URL}/v1/chat/completions", json={
                "model": "mock-local", "messages": [{"role": "user", "content": "one two three four"}],
                "max_tokens": 100}, headers={"Authorization": f"Bearer {key}"})
            return r.status_code
        return await asyncio.gather(*(one(i) for i in range(n)))


@pytest.mark.accept(
    id="M-04f", title="Evidence-plane outage does not bypass enforcement",
    criterion="OpenLIT + ClickHouse down: requests are still served AND still capped (parallel burst on a $0.002 "
              "key: zero overshoot); gateway latency unaffected; telemetry resumes after recovery",
    simplification="Telemetry spans emitted during the outage are dropped (OTel batch exporter), not buffered; the "
                   "authoritative spend record is the gateway's Postgres + Redis, which stay up.")
def test_evidence_plane_outage(record):
    probe = L.mint_key(budget=0.05, metadata={"agent_id": L.uid("t8ev")})
    capped = L.mint_key(budget=0.002, metadata={"agent_id": L.uid("t8ev")})
    try:
        def lat(n=15):
            v = []
            for _ in range(n):
                t = time.time()
                s, _r = _call(probe["key"])
                if s == 200:
                    v.append((time.time() - t) * 1000)
            return round(L.pct(v, 50), 1)
        before = lat()
        _stop("gov-obs-openlit")
        _stop("gov-obs-clickhouse")
        try:
            during = lat()
            statuses = asyncio.run(_burst(capped["key"], 40))
            time.sleep(6)
            rows = [r for r in L.spend_rows(capped["token"], since_s=300) if float(r.get("spend") or 0) > 0]
            spent = sum(float(r["spend"]) for r in rows)
            counter = float(L.redis_cli("GET", f"spend:key:{capped['token']}") or 0)
            record(p50_ms_before=before, p50_ms_during=during, burst_admitted=statuses.count(200),
                   burst_refused=len(statuses) - statuses.count(200), spend_logs_usd=round(spent, 6),
                   redis_counter_usd=round(counter, 6), cap_usd=0.002)
            assert statuses.count(200) >= 1 and spent <= 0.002 + 1e-9 and counter <= 0.002 + 1e-9
            assert during < before + 150, (before, during)
        finally:
            _start("gov-obs-clickhouse", "gov-obs-openlit", timeout=300)
        # telemetry resumes: a new call shows up in ClickHouse
        obs = L.read_env_file(L.ROOT / ".local" / "observability.env")
        t_back = time.time()
        _call(probe["key"])

        def seen():
            try:
                q = ("SELECT count() FROM openlit.otel_traces WHERE SpanName='litellm_request' AND "
                     f"SpanAttributes['metadata.user_api_key_hash']='{probe['token']}' AND Timestamp > now() - 120")
                r = httpx.post("http://127.0.0.1:8124/", params={"query": q},
                               auth=(obs["OBS_CH_USER"], obs["OBS_CH_PASSWORD"]), timeout=10)
                return r.status_code == 200 and int(r.text.strip() or 0) > 0
            except Exception:  # noqa: BLE001
                return False
        ok = L.wait_until(lambda: (_call(probe["key"]), seen())[1], timeout=120, interval=5.0)
        record(telemetry_resumed=bool(ok), telemetry_resumed_after_s=round(time.time() - t_back, 1))
        assert ok
    finally:
        L.delete_keys(probe["token"], capped["token"])


# ------------------------------------------------------------------------------------------ policy
@pytest.mark.accept(
    id="M-04g", title="Fail closed: policy outage",
    criterion="No active bundle, or a tampered stored bundle: the admission gate refuses every deployment "
              "(exit 2), the previous state is never used unverified",
    simplification="Local file policy store; the gateway budget hook does not read the signed bundle (token "
                   "policy comes from key metadata provisioned from deploy/agents.json, drift-checked).")
def test_policy_outage(record, tmp_path):
    store = L.ROOT / ".local" / "policy" / "store"
    cp = tmp_path / "store"
    shutil.copytree(store, cp)
    act = json.loads((cp / "active.json").read_text())
    bundles = list((cp / "bundles").glob("*"))
    target = next(b for b in bundles if act.get("version", "") in b.name) if act.get("version") else bundles[-1]
    data = bytearray(target.read_bytes())
    i = data.find(b"mock-local")
    data[i:i + 10] = b"mock-remot"                               # one-byte-class edit inside the signed payload
    target.write_bytes(bytes(data))
    run = lambda st: subprocess.run([sys.executable, str(L.ROOT / "scripts" / "admit_agents.py")],  # noqa: E731
                                    env={**os.environ, "POLICY_STORE": str(st)}, capture_output=True, text=True,
                                    cwd=L.ROOT, timeout=60)
    tampered, missing = run(cp), run(tmp_path / "nothing")
    record(tampered_bundle_exit=tampered.returncode, missing_bundle_exit=missing.returncode,
           tampered_message=(tampered.stderr or tampered.stdout).strip()[-200:])
    assert tampered.returncode == 2 and missing.returncode == 2
