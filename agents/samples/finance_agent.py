"""Finance reconciliation agent (team finance, JWT auth through the auth proxy).

Identity route: this is the SSO agent. It gets a short-lived JWT from the corporate IdP (client
credentials) and calls the gateway THROUGH the auth proxy, which maps the JWT to the agent's own
LiteLLM key. Stopping the agent blocks that key, so the still-valid JWT stops working at once.

One iteration reconciles a batch of ledger lines against a bank statement:
  fetch_ledger / fetch_bank_statement   tools (local)
  classify_exception                    tool (model) once per unmatched or mismatching line
  variance analysis                     DELEGATED to a child agent when a variance is >= the threshold:
                                        the child holds an attenuated token (small budget, one model,
                                        short life) and its spend lands on its own key
  summary                               the run's own LLM call on the larger model
"""
from __future__ import annotations

import random
from typing import Any

from govagent import DelegationDenied, Delegator

from . import fixtures
from .common import SampleAgent, need


def reconcile(ledger: list[dict], bank: list[dict]) -> list[dict]:
    """Pure matching logic: returns the exceptions (missing at bank, amount variance, timing)."""
    by_id = {b["txn_id"]: b for b in bank}
    out = []
    for row in ledger:
        b = by_id.get(row["txn_id"])
        if b is None:
            out.append({"kind": "missing_at_bank", "txn_id": row["txn_id"], "vendor": row["vendor"],
                        "amount": row["amount"], "variance": row["amount"]})
        elif abs(b["amount"] - row["amount"]) > 0.005:
            out.append({"kind": "amount_variance", "txn_id": row["txn_id"], "vendor": row["vendor"],
                        "amount": row["amount"], "variance": round(b["amount"] - row["amount"], 2)})
        elif b["date"] != row["date"]:
            out.append({"kind": "timing", "txn_id": row["txn_id"], "vendor": row["vendor"],
                        "amount": row["amount"], "variance": 0.0})
    return out


class FinanceReconAgent(SampleAgent):
    agent_id = "finance-recon-agent"
    tools = {"fetch_ledger", "fetch_bank_statement", "classify_exception"}

    def __init__(self, *a: Any, delegator: Delegator | None = None, **kw: Any) -> None:
        super().__init__(*a, **kw)
        self.batch = int(self.env.get("FIN_BATCH_SIZE", "6"))
        self.delegate_threshold = float(self.env.get("FIN_DELEGATE_THRESHOLD_USD", "100"))
        if delegator is None and self.env.get("DELEGATION_TOKEN") and self.env.get("BROKER_URL"):
            delegator = Delegator(self.agent_id, need(self.env, "BROKER_URL"), need(self.env, "DELEGATION_TOKEN"),
                                  self.env.get("GATEWAY_URL", "http://sso-gateway:8080"), self.sink,
                                  budget_usd=float(self.env.get("FIN_CHILD_BUDGET_USD", "0.2")),
                                  models=[self.small], ttl_s=float(self.env.get("FIN_CHILD_TTL_S", "3600")),
                                  transport=self.transport)
        self.delegator = delegator

    # ---- tools ---------------------------------------------------------------
    def fetch_ledger(self, run, seed: int) -> list[dict]:
        return fixtures.ledger_and_bank(seed, self.batch)[0]

    def fetch_bank_statement(self, run, seed: int) -> list[dict]:
        return fixtures.ledger_and_bank(seed, self.batch)[1]

    def classify_exception(self, run, exception: dict) -> str:
        r = self.gw.chat(run, self.small, [
            {"role": "system", "content": "Classify this reconciliation exception: timing, fx, duplicate, error, fraud-risk."},
            {"role": "user", "content": f"{exception['kind']} on {exception['vendor']} ({exception['txn_id']}), "
                                        f"ledger {exception['amount']} USD, variance {exception['variance']} USD"}],
            max_tokens=self.tokens(24))
        return r.text

    # ---- one iteration ---------------------------------------------------------
    def work(self, run) -> None:
        seed = random.randint(0, 10 ** 6)
        ledger = self.toolbox.call(run, "fetch_ledger", self.fetch_ledger, seed=seed)
        bank = self.toolbox.call(run, "fetch_bank_statement", self.fetch_bank_statement, seed=seed)
        exceptions = reconcile(ledger, bank)
        for ex in exceptions:
            ex["class"] = self.toolbox.call(run, "classify_exception", self.classify_exception, exception=ex)[:40]
        big = [e for e in exceptions if abs(e["variance"]) >= self.delegate_threshold]
        if big and self.delegator is not None:
            try:
                self.delegator.delegate(run, "variance-analyst", "variance_analysis",
                                        lambda child_run, child_gw: self._analyse(child_run, child_gw, big))
            except DelegationDenied as e:
                self.sink.emit({"event": "delegation.skipped", "agent_id": self.agent_id, "reason": str(e)[:160]})
        res = self.gw.chat(run, self.large, [
            {"role": "system", "content": "Summarise this reconciliation batch for the controller in two sentences."},
            {"role": "user", "content": f"{len(ledger)} ledger lines, {len(exceptions)} exceptions, "
                                        f"{len(big)} above {self.delegate_threshold} USD."}],
            max_tokens=self.tokens(48))
        self.sink.emit({"event": "finance.batch_done", "agent_id": self.agent_id, "run_id": run.run_id,
                        "lines": len(ledger), "exceptions": len(exceptions), "delegated": len(big),
                        "attempts": res.attempts})

    def _analyse(self, child_run, child_gw, big: list[dict]) -> None:
        """Runs as the CHILD agent (its own key via the delegation token)."""
        for ex in big[:2]:
            child_gw.chat(child_run, self.small, [
                {"role": "system", "content": "You are a variance analyst. Explain the likely cause in one line."},
                {"role": "user", "content": f"{ex['vendor']} {ex['txn_id']}: variance {ex['variance']} USD"}],
                max_tokens=self.tokens(32))


if __name__ == "__main__":
    raise SystemExit(FinanceReconAgent().main())
