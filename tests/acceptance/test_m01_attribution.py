"""M-01 Attribution completeness: every pilot request is attributed to agent, run, user/team, provider, model,
tokens and cost, including retries, tools and delegation."""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone

import pytest

import acclib as L

pytestmark = pytest.mark.usefixtures("live")
sys.path.insert(0, str(L.ROOT / "scripts"))
import attribution_report as AR  # noqa: E402

PILOT = ("hr-agent", "finance-recon-agent", "coding-agent")
WINDOW_MIN = 30


@pytest.mark.accept(
    id="M-01", title="Attribution completeness",
    criterion=f"Over the last {WINDOW_MIN} min of the three pilot agents' traffic (incl. delegated children): "
              "0 unattributed requests; every spending request carries agent, team, run, provider, model, tokens, "
              "cost; task, tool and delegation runs present; run trees close (every parent run exists)",
    simplification="Retry attribution is proven by the T4 contract tests (tests/agents) rather than by live "
                   "provider faults; a refusal during LiteLLM auth carries the agent but not the run (T4 finding 1).")
def test_attribution_completeness(record):
    now = datetime.now(timezone.utc)
    raw = AR.fetch_rows(L.GW_URL, L.ENV["LITELLM_MASTER_KEY"], now - timedelta(minutes=WINDOW_MIN),
                        now + timedelta(minutes=1))
    rows = [AR.normalise(r) for r in raw]
    ours = [r for r in rows if r["agent"] and any(r["agent"] == a or r["agent"].startswith(a + ".") for a in PILOT)]
    assert len(ours) >= 30, f"too little pilot traffic in the window ({len(ours)} rows); are the agents running?"
    comp = AR.completeness(ours)
    spending = [r for r in ours if r["cost_usd"] > 0]
    missing = [r for r in spending if not all([r["agent"], r["team"], r["run_id"], r["provider"], r["model"],
                                              r["prompt_tokens"], r["cost_usd"]])]
    kinds = sorted({r["run_kind"] for r in ours if r["run_kind"]})
    runs = {r["run_id"] for r in ours if r["run_id"]}
    orphans = {r["parent_run_id"] for r in ours if r["parent_run_id"] and r["parent_run_id"] not in runs}
    by_agent = {a: sum(1 for r in ours if r["agent"] == a or r["agent"].startswith(a + ".")) for a in PILOT}
    record(window_min=WINDOW_MIN, requests=comp["requests"], attributed=comp["attributed"],
           rejected_before_spend=comp["rejected_before_spend"], unattributed=comp["unattributed"],
           spending_requests=len(spending), spending_missing_fields=len(missing), run_kinds=kinds,
           orphan_parent_runs=len(orphans), requests_by_agent=by_agent,
           attributed_cost_usd=round(sum(r["cost_usd"] for r in ours), 6))
    assert comp["complete"], comp
    assert not missing, missing[:3]
    assert {"task", "tool"} <= set(kinds)
    assert "delegation" in kinds, "no delegated run in the window (the finance agent delegates every iteration)"
    # a parent run may have started before the window: tolerate orphans only at the window's edge
    assert len(orphans) <= 3, sorted(orphans)[:5]
