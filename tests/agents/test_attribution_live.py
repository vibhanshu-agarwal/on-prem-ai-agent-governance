"""Attribution completeness over REAL agent runs (Docker stack): the sample agents run as containers on the
governed networks, and every request the gateway saw is compared with what the agent says it sent.

Needs: base stack, control plane, `scripts/agents-up.sh` (image + .local/agents.env) and a gateway with the
run_attribution callback loaded (the tests refuse to run otherwise, they do not weaken themselves).
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from urllib.parse import urlparse

import httpx
import pytest

import attribution_report as rep
import livelib as L
from govagent import (DelegationDenied, Delegator, GatewayClient, GatewayError, HttpResponse, MemorySink, RetryPolicy,
                      RunContext, StaticKeyAuth, TransportError, UrllibTransport)

pytestmark = pytest.mark.usefixtures("live")

PROVIDER_OF = {"mock-local": "mock-local", "mock-remote": "mock-remote"}


@pytest.fixture(scope="module")
def live():
    why = L.stack_ready()
    if why:
        pytest.skip(why)
    yield
    L.cleanup()


def compare(events: list[dict], rows: list[dict], *, team: str, expect_agents: set[str] | None = None) -> dict:
    """The agent's own account (llm.attempt events that reached the gateway) versus the gateway's spend rows."""
    sent = {(e["run_id"], e["step"], e["attempt"]): e for e in events
            if e["event"] == "llm.attempt" and e["http_status"] is not None}
    seen = {(r["run_id"], r["step"], r["attempt"]): r for r in rows if r["run_id"]}
    assert sent, "the agent made no gateway request"
    assert set(sent) == set(seen), {"missing_at_gateway": sorted(set(sent) - set(seen)),
                                    "unknown_to_agent": sorted(set(seen) - set(sent))}
    assert len(rows) == len(seen), "a gateway row without a run id or a duplicated (run, step, attempt)"
    for key, e in sent.items():
        r = seen[key]
        ctx = f"{key} {e['tool'] or e['run_kind']}"
        assert r["agent"] == e["agent_id"], ctx
        assert r["team"] == team, ctx
        assert r["parent_run_id"] == e["parent_run_id"], ctx
        assert r["root_run_id"] == e["root_run_id"], ctx
        assert r["run_kind"] == e["run_kind"] and r["tool"] == e["tool"], ctx
        assert r["model"] == e["model"] and r["provider"] == PROVIDER_OF[e["model"]] or r["status"] == "failure", ctx
        assert (r["status"] == "success") == e["ok"], (ctx, r["status"], r["error"])
        if e["ok"]:
            assert (r["prompt_tokens"], r["completion_tokens"]) == (e["prompt_tokens"], e["completion_tokens"]), ctx
            assert r["cost_usd"] == pytest.approx(e["cost_usd"], rel=1e-6, abs=1e-12), ctx
            assert r["provider"] == PROVIDER_OF[e["model"]], ctx
        else:
            assert r["cost_usd"] == 0 and r["error"], ctx          # a refused attempt is attributed, costs nothing, says why
    if expect_agents is not None:
        assert {r["agent"] for r in rows} == expect_agents
    # the run tree in the agent log is closed: every parent is a run the agent started
    started = {e["run_id"] for e in events if e["event"] == "run.start"}
    for e in events:
        if e.get("parent_run_id"):
            assert e["parent_run_id"] in started, e
    return {"requests": len(rows), "attempts": sorted({k[2] for k in seen}), "ok": sum(1 for r in rows if r["status"] == "success")}


def key_env(agent_id: str, key: str, iterations=3) -> dict:
    return {"AGENT_ID": agent_id, "AUTH_MODE": "key", "AGENT_KEY": key, "GATEWAY_URL": "http://gateway:4000",
            "AGENT_MAX_ITERATIONS": str(iterations), "AGENT_INTERVAL_S": "0.3", "AGENT_JITTER": "0"}


def roots_of(events) -> set[str]:
    return {e["run_id"] for e in events if e["event"] == "run.start" and e.get("parent_run_id") is None}


# ------------------------------------------------------------------ key route: HR and Coding
@pytest.mark.parametrize("module,agent,team,var,tools", [
    ("samples.hr_agent", "hr-agent", "hr", "HR_AGENT_KEY", {"rewrite_query"}),
    ("samples.coding_agent", "coding-agent", "engineering", "CODING_AGENT_KEY", {"plan_change", "generate_code"}),
])
@L.resilient
def test_key_agents_every_request_is_attributed(module, agent, team, var, tools):
    since = L.utcnow()
    c = L.run_container(module, agent, key_env(agent, L.ENV[var]), L.AGENTS_NET)
    ev = L.events_of(c)
    c.reload()
    assert c.attrs["State"]["ExitCode"] == 0, c.logs().decode()[-800:]
    roots = roots_of(ev)
    assert len(roots) == 3
    reached = [e for e in ev if e["event"] == "llm.attempt" and e["http_status"] is not None]
    rows = L.rows_for_roots(roots, since, expected=len(reached))
    summary = compare(ev, rows, team=team, expect_agents={agent})
    # tool calls really are child runs seen by the gateway; the agent's own LLM call sits on the root run
    assert tools <= {r["tool"] for r in rows if r["tool"]}
    assert {r["run_kind"] for r in rows} == {"task", "tool"}
    assert all(r["parent_run_id"] is None for r in rows if r["run_kind"] == "task")
    assert all(r["parent_run_id"] in roots for r in rows if r["run_kind"] == "tool")
    assert rep.completeness(rows)["complete"]
    L.record("attribution_" + agent, {**summary, "roots": len(roots)})


@L.resilient
def test_hr_pii_prompt_is_blocked_by_guardrails_but_the_blocked_request_is_still_attributed():
    since = L.utcnow()
    c = L.run_container("samples.hr_agent", "hr-agent", key_env("hr-agent", L.ENV["HR_AGENT_KEY"], iterations=2), L.AGENTS_NET)
    ev = L.events_of(c)
    rows = L.rows_for_roots(roots_of(ev), since, expected=len([e for e in ev if e["event"] == "llm.attempt" and e["http_status"]]))
    blocked = [r for r in rows if r["status"] == "failure" and r["run_kind"] == "task"]
    if not blocked:
        pytest.skip("no guardrail is blocking the HR prompt on this gateway (T5 not loaded); nothing to assert")
    assert all(r["run_id"] and r["agent"] == "hr-agent" and r["user"] and r["error"] for r in blocked)


# ------------------------------------------------------------------ SSO route + delegation: Finance
@L.resilient
def test_finance_sso_agent_and_its_delegated_child_are_attributed_end_to_end():
    since = L.utcnow()
    env = {"AGENT_ID": "finance-recon-agent", "AUTH_MODE": "oidc", "GATEWAY_URL": "http://sso-gateway:8080",
           "IDP_TOKEN_URL": "http://idp:8300/token", "CLIENT_ID": L.ENV["FINANCE_CLIENT_ID"],
           "CLIENT_SECRET": L.ENV["FINANCE_CLIENT_SECRET"], "DELEGATION_TOKEN": L.ENV["FINANCE_DELEGATION_TOKEN"],
           "BROKER_URL": "http://delegation-broker:8090", "FIN_DELEGATE_THRESHOLD_USD": "0", "FIN_BATCH_SIZE": "8",
           "FIN_CHILD_BUDGET_USD": "0.005", "AGENT_MAX_ITERATIONS": "2", "AGENT_INTERVAL_S": "0.3", "AGENT_JITTER": "0"}
    c = L.run_container("samples.finance_agent", "finance-recon-agent", env, L.SSO_NET, timeout=180)
    ev = L.events_of(c)
    roots = roots_of(ev)
    assert len(roots) == 2
    minted = [e for e in ev if e["event"] == "delegation.minted"]
    assert minted, [e for e in ev if e["event"].startswith("delegation")]
    child_id = minted[0]["child_agent_id"]
    reached = [e for e in ev if e["event"] == "llm.attempt" and e["http_status"] is not None]
    rows = L.rows_for_roots(roots, since, expected=len(reached))
    try:
        summary = compare(ev, rows, team="finance", expect_agents={"finance-recon-agent", child_id})
        deleg = [r for r in rows if r["run_kind"] == "delegation"]
        assert deleg and all(r["agent"] == child_id and r["parent_run_id"] in roots for r in deleg)
        assert {r["tool"] for r in rows if r["run_kind"] == "tool"} == {"classify_exception"}
        assert all(r["agent"] == "finance-recon-agent" for r in rows if r["run_kind"] != "delegation")
        assert rep.completeness(rows)["complete"]
        # the child spent under its OWN key (own budget, own stop switch), the parent under its own
        tree = rep.build_trees(rows)
        assert len(tree) == 2 and all(any(ch["kind"] == "delegation" for ch in t["children"]) for t in tree)
        L.record("attribution_finance_sso", {**summary, "child_agent": child_id})
    finally:
        L.admin().post("/key/delete", json={"key_aliases": [child_id]})


# ------------------------------------------------------------------ the report script over the same data
@L.resilient
def test_attribution_report_cli_prints_the_run_tree_and_flags_holes():
    since = L.utcnow()
    c = L.run_container("samples.coding_agent", "coding-agent", key_env("coding-agent", L.ENV["CODING_AGENT_KEY"], 1), L.AGENTS_NET)
    root = next(iter(roots_of(L.events_of(c))))
    L.rows_for_roots({root}, since, expected=4)
    # T8: --agent scopes the completeness check to this agent; on the integrated stack other suites' throwaway
    # test keys (attribution mode audit) send run-id-less requests in the same window, which are holes by definition
    out = subprocess.run([sys.executable, str(L.ROOT / "scripts" / "attribution_report.py"), "--since", "10m", "--run", root,
                          "--agent", "coding-agent", "--json"], capture_output=True, text=True, timeout=90, cwd=L.ROOT)
    assert out.returncode == 0, out.stderr
    d = json.loads(out.stdout)
    tree = d["trees"][0]
    assert tree["run_id"] == root and tree["agent"] == "coding-agent" and len(tree["children"]) == 2
    assert {c["tool"] for c in tree["children"]} == {"plan_change", "generate_code"}
    assert tree["total_cost"] == pytest.approx(tree["own_cost"] + sum(c["own_cost"] for c in tree["children"]))
    assert d["completeness"]["complete"]
    txt = subprocess.run([sys.executable, str(L.ROOT / "scripts" / "attribution_report.py"), "--since", "10m", "--run", root],
                         capture_output=True, text=True, timeout=90, cwd=L.ROOT).stdout
    assert root in txt and "tool:plan_change" in txt and "COMPLETE" in txt


# ------------------------------------------------------------------ enforcement and spoofing at the gateway
def _chat(key, headers=None, user=None, model="mock-local"):
    return httpx.post(L.GW + "/v1/chat/completions", timeout=30,
                      headers={"Authorization": f"Bearer {key}", **(headers or {})},
                      json={"model": model, "max_tokens": 3, "user": user, "messages": [{"role": "user", "content": "hi"}]})


@L.resilient
def test_request_without_a_valid_run_id_is_rejected_and_shows_up_as_rejected_not_as_a_hole():
    key = L.ENV["CODING_AGENT_KEY"]
    marker = L.uid("t4-nopid")
    since = L.utcnow()
    for hdrs, etype in (({}, "run_id_required"), ({"x-govpilot-run-id": "no"}, "run_id_required"),
                        ({"x-govpilot-run-id": "run-abcdef12", "x-govpilot-run-kind": "tool"}, "run_fields_invalid")):
        r = _chat(key, hdrs, user=marker)
        assert r.status_code == 400 and r.json()["error"]["type"] == etype, r.text
    time.sleep(12)
    rows = [r for r in L.fetch_rows(since) if r["user"] == marker]
    assert len(rows) == 3 and {rep.classify(r) for r in rows} == {"rejected"} and all(r["cost_usd"] == 0 for r in rows)


@L.resilient
def test_agent_cannot_claim_another_agents_identity_in_the_spend_log():
    marker, run = L.uid("t4-spoof"), f"run-{L.uid('sp')}"
    since = L.utcnow()
    forged = {"x-govpilot-run-id": run, "x-litellm-spend-logs-metadata": json.dumps(
        {"agent_id": "finance-recon-agent", "team": "finance", "key_alias": "finance-recon-agent", "run_id": run})}
    r = _chat(L.ENV["HR_AGENT_KEY"], forged, user=marker)
    assert r.status_code == 200 and r.headers["x-govpilot-agent"] == "hr-agent" and r.headers["x-govpilot-run-id"] == run
    rows = L.rows_for_roots({run}, since, expected=1)
    assert len(rows) == 1 and rows[0]["agent"] == "hr-agent" and rows[0]["team"] == "hr"


@L.resilient
def test_refusal_at_the_auth_stage_is_logged_to_the_agent_without_a_run_and_is_not_a_hole():
    """Known limit, asserted so it stays visible: LiteLLM refuses an off-allowlist model during auth, before any
    hook runs, so the failure row names the key (agent) and the error but cannot carry the run. It cost nothing."""
    marker = L.uid("t4-authrefuse")
    since = L.utcnow()
    r = _chat(L.ENV["HR_AGENT_KEY"], RunContext.root("hr-agent").next_step().headers(), user=marker, model="mock-remote")
    assert r.status_code in (400, 401, 403), r.text
    time.sleep(12)
    rows = [x for x in L.fetch_rows(since) if x["user"] == marker or (x["agent"] == "hr-agent" and x["status"] == "failure"
                                                                      and "not allowed to access model" in (x["error"] or ""))]
    assert rows and all(x["agent"] == "hr-agent" and x["cost_usd"] == 0 and rep.classify(x) == "rejected" for x in rows)


@L.resilient
def test_refusal_inside_the_gateway_hooks_keeps_the_run_fields():
    """A refusal raised by a pre-call hook (here the token ceiling) is still tied to the run: the run headers are on the request."""
    since = L.utcnow()
    run = RunContext.root("hr-agent")
    call = run.next_step()
    r = httpx.post(L.GW + "/v1/chat/completions", timeout=30, headers={"Authorization": f"Bearer {L.ENV['HR_AGENT_KEY']}",
                                                                        **call.headers()},
                   json={"model": "mock-local", "max_tokens": 100000, "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 400 and "max_tokens" in r.text, r.text
    rows = L.rows_for_roots({run.run_id}, since, expected=1)
    assert len(rows) == 1 and (rows[0]["status"], rows[0]["step"], rows[0]["attempt"], rows[0]["agent"]) == ("failure", 1, 1, "hr-agent")
    assert rows[0]["cost_usd"] == 0 and "max_tokens" in rows[0]["error"]


# ------------------------------------------------------------------ retries against the real gateway
class ChaosTransport:
    """Fails the first N attempts on the client side (connection reset, then a 503), then talks to the real gateway."""

    def __init__(self, fail_first: list):
        self.fail_first, self.real, self.sent = list(fail_first), UrllibTransport(), []

    def send(self, method, url, headers, body, timeout):
        self.sent.append({k.lower(): v for k, v in headers.items()})
        if self.fail_first:
            f = self.fail_first.pop(0)
            if isinstance(f, Exception):
                raise f
            return f
        return self.real.send(method, url, headers, body, timeout)


@L.resilient
def test_retried_request_reaches_the_gateway_with_the_same_run_id_and_a_higher_attempt():
    since = L.utcnow()
    sink = MemorySink()
    t = ChaosTransport([TransportError("connection reset"), HttpResponse(503, {}, b'{"error":{"type":"service_unavailable"}}')])
    gw = GatewayClient(L.GW, StaticKeyAuth(L.ENV["CODING_AGENT_KEY"]), transport=t, sink=sink,
                       retry=RetryPolicy(max_attempts=4, base_delay_s=0.05), sleep=lambda s: None)
    root = RunContext.root("coding-agent")
    tool = root.child("tool", "tool:generate_code", tool="generate_code")
    res = gw.chat(tool, "mock-local", [{"role": "user", "content": "write a function"}], max_tokens=8)
    assert res.attempts == 3 and res.headers["x-govpilot-attempt"] == "3" and res.headers["x-govpilot-run-id"] == tool.run_id
    assert {h["x-govpilot-run-id"] for h in t.sent} == {tool.run_id}
    rows = L.rows_for_roots({root.run_id}, since, expected=1)
    assert len(rows) == 1                                               # the two failed attempts never reached the gateway
    r = rows[0]
    assert (r["run_id"], r["parent_run_id"], r["root_run_id"], r["attempt"], r["tool"], r["run_kind"], r["agent"]) == \
           (tool.run_id, root.run_id, root.run_id, 3, "generate_code", "tool", "coding-agent")
    assert r["cost_usd"] == pytest.approx(res.cost_usd, rel=1e-6)


@L.resilient
def test_gateway_side_refusal_then_success_is_one_run_two_rows():
    """A real gateway-side refusal (token ceiling) followed by a corrected retry: same run, same step, attempts 1 and 2."""
    since = L.utcnow()
    run = RunContext.root("hr-agent")
    call = run.next_step()                                                # one logical call, two attempts
    for attempt, max_tokens in ((1, 100000), (2, 16)):                    # hr-agent's ceiling is 512
        r = httpx.post(L.GW + "/v1/chat/completions", timeout=30,
                       headers={"Authorization": f"Bearer {L.ENV['HR_AGENT_KEY']}", **call.with_attempt(attempt).headers()},
                       json={"model": "mock-local", "max_tokens": max_tokens, "messages": [{"role": "user", "content": "hi"}]})
        assert (r.status_code == 200) == (attempt == 2), r.text
    rows = L.rows_for_roots({run.run_id}, since, expected=2)
    assert sorted((r["step"], r["attempt"], r["status"]) for r in rows) == [(1, 1, "failure"), (1, 2, "success")]
    assert {r["run_id"] for r in rows} == {run.run_id} and sum(r["cost_usd"] for r in rows) > 0


# ------------------------------------------------------------------ delegation, in-process against the real control plane
@L.resilient
def test_delegated_child_uses_an_attenuated_token_and_broadening_is_refused():
    since = L.utcnow()
    sink = MemorySink()
    tok = L.ENV["FINANCE_DELEGATION_TOKEN"]
    d = Delegator("finance-recon-agent", L.CP, tok, L.AUTHPROXY, sink, budget_usd=0.004, models=["mock-local"], ttl_s=600)
    root = RunContext.root("finance-recon-agent")
    got = {}

    def sub(child_run, child_gw):
        got["run"] = child_run
        return child_gw.chat(child_run, "mock-local", [{"role": "user", "content": "explain the variance"}], max_tokens=8)
    res = d.delegate(root, "t4-live", "variance", sub)
    child = sink.of("delegation.minted")[0]["child_agent_id"]
    try:
        assert child.startswith("finance-recon-agent.t4-live-") and res.attempts == 1
        rows = L.rows_for_roots({root.run_id}, since, expected=1)
        assert len(rows) == 1
        r = rows[0]
        assert (r["agent"], r["run_kind"], r["parent_run_id"], r["run_id"]) == (child, "delegation", root.run_id, got["run"].run_id)
        # the child is bound to its narrow scope: a model outside the delegation is refused at the auth proxy
        with pytest.raises(GatewayError) as ei:
            d.child("t4-live")[1].chat(got["run"], "mock-remote", [{"role": "user", "content": "x"}], max_tokens=4)
        assert ei.value.status in (401, 403)
        # broadening is denied and reported to the caller
        wide = Delegator("finance-recon-agent", L.CP, tok, L.AUTHPROXY, sink, budget_usd=50.0, models=["mock-local"])
        with pytest.raises(DelegationDenied) as di:
            wide.mint("t4-wide")
        assert any("budget" in x for x in di.value.reasons)
        wide2 = Delegator("finance-recon-agent", L.CP, tok, L.AUTHPROXY, sink, budget_usd=0.001,
                          models=["mock-local", "mock-remote", "mock-remote-slow"])
        with pytest.raises(DelegationDenied):
            wide2.mint("t4-wide2")
    finally:
        L.admin().post("/key/delete", json={"key_aliases": [child]})


# ------------------------------------------------------------------ demo: one agent goes rogue, the budget contains it
@L.resilient
def test_rogue_rate_profile_burns_the_budget_and_the_gateway_refuses_the_rest(tmp_path):
    import docker
    alias = L.uid("t4-rogue")
    cap = 0.004
    teams = json.loads((L.ROOT / ".local" / "agent-keys.json").read_text())["teams"]
    r = L.admin().post("/key/generate", json={
        "key_alias": alias, "team_id": teams["engineering"], "models": ["mock-local", "mock-remote"], "max_budget": cap,
        "metadata": {"agent_id": alias, "team": "engineering", "attribution": {"mode": "enforce"},
                     "token_policy": {"max_tokens_ceiling": 512, "default_max_tokens": 96}}})
    assert r.status_code == 200, r.text
    key = r.json()["key"]
    rates = tmp_path / "rates.json"
    rates.write_text(json.dumps({"default": {}, alias: {"interval_s": 1, "jitter": 0}}))
    since = L.utcnow()
    c = None
    try:
        c = L.run_container("samples.coding_agent", alias, {**key_env(alias, key, iterations=0), "AGENT_MAX_ITERATIONS": "",
                                                            "AGENT_RATES_FILE": "/etc/agents/rates.json"},
                            L.AGENTS_NET, detach=True,
                            mounts=[docker.types.Mount("/etc/agents", str(tmp_path), type="bind", read_only=True)])
        time.sleep(4)
        calm = [e for e in L.events_of(c) if e["event"] == "run.start" and e.get("parent_run_id") is None]
        assert 1 <= len(calm) <= 6, "the calm agent works at its base rate"
        out = subprocess.run([sys.executable, str(L.ROOT / "scripts" / "agents_ctl.py"), "rogue", alias, "--interval", "0.05",
                              "--concurrency", "4"], capture_output=True, text=True,
                             env={**__import__("os").environ, "AGENT_RATES_FILE": str(rates)})
        assert out.returncode == 0, out.stderr
        deadline = time.time() + 60
        refused = []
        while time.time() < deadline:
            time.sleep(2)
            ev = L.events_of(c)
            refused = [e for e in ev if e["event"] == "llm.attempt" and e["http_status"] in (400, 429) and "udget" in (e["error"] or "")]
            if len(refused) >= 10:
                break
        assert any(e["event"] == "loop.settings" and e["profile"] == "rogue" for e in ev), "live rate change was not picked up"
        assert len(refused) >= 10, "the gateway did not refuse the rogue agent"
        c.stop(timeout=3)
        ev = L.events_of(c)
        reached = [e for e in ev if e["event"] == "llm.attempt" and e["http_status"] is not None]
        deadline = time.time() + 90
        rows: list[dict] = []
        while time.time() < deadline:                       # every request of this agent, refused ones included
            rows = [r for r in L.fetch_rows(since) if r["agent"] == alias]
            if len(rows) >= len(reached):
                break
            time.sleep(3)
        assert len(rows) == len(reached), (len(rows), len(reached))
        spent = sum(r["cost_usd"] for r in rows)
        info = L.admin().get("/key/info", params={"key": key}).json()["info"]
        ok_rows = sorted((r for r in rows if r["status"] == "success"), key=lambda r: r["ts"])
        assert spent <= cap + 1e-9, (f"overshoot: spent {spent} > cap {cap}; key spend {info.get('spend')}; "
                                     f"{len(ok_rows)} ok rows; last: " + "; ".join(
            f"{r['ts'][11:23]} {r['model']} in={r['prompt_tokens']} out={r['completion_tokens']} ${r['cost_usd']:.6f} "
            f"{r['tool'] or r['run_kind']}" for r in ok_rows[-6:]))
        # everything that spent money is attributed to a run; refusals are attributed to the agent (some, raised by
        # LiteLLM's auth stage before any hook runs, cannot carry the run: see T4.md finding 1)
        assert all(r["run_id"] and r["parent_run_id"] is None or r["run_kind"] in ("task", "tool") for r in ok_rows)
        assert all(r["run_id"] for r in ok_rows)
        refused_rows = [r for r in rows if r["status"] == "failure"]
        assert len(refused_rows) >= 10 and all(rep.classify(r) in ("attributed", "rejected") for r in refused_rows)
        assert all("udget" in (r["error"] or "") for r in refused_rows)
        assert not any(rep.classify(r) == "unattributed" for r in rows)
        with_run = sum(1 for r in refused_rows if r["run_id"])
        L.record("rogue_demo", {"cap_usd": cap, "spent_usd": spent, "requests": len(rows),
                                "refused": len(refused_rows), "refused_rows_carrying_the_run": with_run,
                                "key_spend_reported": info.get("spend"), "hammer_attempts_after_refusal": len(refused)})
    finally:
        if c is not None:
            c.remove(force=True)
        L.admin().post("/key/delete", json={"key_aliases": [alias]})
