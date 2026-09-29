"""HR policy Q&A agent (team hr, key auth straight to the gateway).

A realistic small RAG agent. One iteration answers one employee question:
  1. rewrite_query     (tool, calls the model)  expand the question into search terms
  2. search_policies   (tool, local)             top policy passages
  3. lookup_employee   (tool, local)             the employee's HR record, PII included
  4. answer            (the run's own LLM call)  prompt = policy passages + the WHOLE employee record

Step 4 is the deliberate weakness: the agent pastes the raw record (name, e-mail, SSN, salary,
address) into the model prompt, which is exactly what the guardrail layer (T5) must catch.
"""
from __future__ import annotations

import json
import random
from dataclasses import replace

from . import fixtures
from .common import SampleAgent


class HRAgent(SampleAgent):
    agent_id = "hr-agent"
    tools = {"rewrite_query", "search_policies", "lookup_employee"}

    # ---- tools ---------------------------------------------------------------
    def rewrite_query(self, run, question: str) -> str:
        r = self.gw.chat(run, self.small, [
            {"role": "system", "content": "Rewrite the employee question as a short keyword search query."},
            {"role": "user", "content": question}], max_tokens=self.tokens(16))
        return question + " " + r.text            # the mock model returns filler tokens; keep the original terms

    def search_policies(self, run, query: str) -> list[dict]:
        return fixtures.search_policies(query)

    def lookup_employee(self, run, emp_id: str) -> dict:
        return fixtures.EMPLOYEES[emp_id]

    # ---- one iteration ---------------------------------------------------------
    def work(self, run) -> None:
        emp_id, question = random.choice(fixtures.HR_QUESTIONS)
        run = replace(run, user=emp_id, name="hr.policy_qa")
        expanded = self.toolbox.call(run, "rewrite_query", self.rewrite_query, question=question)
        passages = self.toolbox.call(run, "search_policies", self.search_policies, query=expanded)
        record = self.toolbox.call(run, "lookup_employee", self.lookup_employee, emp_id=emp_id)
        context = "\n".join(f"[{p['id']}] {p['title']}: {p['text']}" for p in passages)
        res = self.gw.chat(run, self.small, [
            {"role": "system", "content": "You are the HR assistant. Answer using only the policy excerpts."},
            {"role": "user", "content": f"Policies:\n{context}\n\nEmployee record: {json.dumps(record)}\n\n"
                                        f"Question from {record['name']} ({emp_id}): {question}"}],
            max_tokens=self.tokens(128))
        self.sink.emit({"event": "hr.answered", "agent_id": self.agent_id, "run_id": run.run_id, "employee": emp_id,
                        "policies": [p["id"] for p in passages], "answer_tokens": res.completion_tokens,
                        "attempts": res.attempts})


if __name__ == "__main__":
    raise SystemExit(HRAgent().main())
