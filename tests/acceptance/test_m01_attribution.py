"""M-01 Attribution completeness: every pilot request is attributed to agent, run, user/team, provider, model,
tokens and cost, including retries, tools and delegation."""
from __future__ import annotations

import sys
import time
from datetime import datetime, timedelta, timezone

import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")
sys.path.insert(0, str(L.ROOT / "scripts"))
import attribution_report as AR  # noqa: E402
import run_journal as RJ  # noqa: E402

PILOT = ("hr-agent", "finance-recon-agent", "coding-agent")
WINDOW_MIN = 30
LOOKBACK_MIN = 10       # rows before the window are read only to find parents that started just before it


@pytest.mark.accept(
    id="M-01", title="Attribution completeness",
    criterion=f"Over the last {WINDOW_MIN} min of the three pilot agents' traffic (incl. delegated children): "
              "0 unattributed requests; every spending request carries agent, team, run, provider, model, tokens, "
              "cost; task, tool and delegation runs present; run trees close: every parent run has a gateway row or "
              "a recorded terminal state in the agents' run journal (no tolerance by count)",
    simplification="Retry attribution is proven by the T4 contract tests (tests/agents) rather than by live "
                   "provider faults; a refusal during LiteLLM auth carries the agent but not the run (T4 finding 1); "
                   "the run journal is the agent's own account (it explains a dangling parent link, it does not "
                   "authenticate it: the spend attribution itself comes from the gateway's key, never the agent).")
def test_attribution_completeness(record):
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=WINDOW_MIN)
    raw = AR.fetch_rows(L.GW_URL, L.ENV["LITELLM_MASTER_KEY"], start - timedelta(minutes=LOOKBACK_MIN),
                        now + timedelta(minutes=1))
    # a pilot agent's rows: its agent id, a delegated child (<agent>.<child>) or a rotated key's alias (<agent>-<n>,
    # which is all a request refused during LiteLLM's own auth carries)
    pilot = lambda r: any(RJ.same_agent(a, r["agent"]) for a in PILOT)  # noqa: E731
    known = [r for r in map(AR.normalise, raw) if pilot(r)]
    ours = [r for r in known if (RJ.parse_ts(r["ts"]) or 0) >= start.timestamp()]
    assert len(ours) >= 30, f"too little pilot traffic in the window ({len(ours)} rows); are the agents running?"
    comp = AR.completeness(ours)
    spending = [r for r in ours if r["cost_usd"] > 0]
    missing = [r for r in spending if not all([r["agent"], r["team"], r["run_id"], r["provider"], r["model"],
                                              r["prompt_tokens"], r["cost_usd"]])]
    kinds = sorted({r["run_kind"] for r in ours if r["run_kind"]})
    by_agent = {a: sum(1 for r in ours if RJ.same_agent(a, r["agent"])) for a in PILOT}

    # Run trees close. A parent that started before the window has its own rows in the lookback; a parent that
    # never made an LLM call of its own (its first tool call was refused by a fail-closed control, or the run was
    # killed) has none, and is looked up in the agents' run journal instead.
    orphans = RJ.orphan_parents(ours, known)
    evidence = RJ.account_orphans(orphans, RJ.journal_records((WINDOW_MIN + LOOKBACK_MIN) * 60 + 600), now=time.time())
    summary = RJ.summarise(evidence)
    record(window_min=WINDOW_MIN, requests=comp["requests"], attributed=comp["attributed"],
           rejected_before_spend=comp["rejected_before_spend"], unattributed=comp["unattributed"],
           spending_requests=len(spending), spending_missing_fields=len(missing), run_kinds=kinds,
           orphan_parent_runs=len(orphans), orphans_by_state=summary["by_state"],
           orphans_aborted_causes=summary["aborted_causes"], orphans_unaccounted=summary["unaccounted"],
           orphan_evidence_sources=sorted({e.get("source", "journal") for e in evidence}),
           requests_by_agent=by_agent, attributed_cost_usd=round(sum(r["cost_usd"] for r in ours), 6))
    assert comp["complete"], comp
    assert not missing, missing[:3]
    assert {"task", "tool"} <= set(kinds)
    assert "delegation" in kinds, "no delegated run in the window (the finance agent delegates every iteration)"
    assert not summary["unaccounted"], summary["unaccounted"][:5]
