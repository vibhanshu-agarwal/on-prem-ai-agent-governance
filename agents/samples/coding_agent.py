"""Coding agent (team engineering, key auth; declared capability `executes_model_code`).

One iteration takes a coding task:
  plan_change      tool (model)  outline the change
  generate_code    tool (model)  ask the larger model for the implementation
  sandbox_check    tool (local)  syntax-check the candidate in the "sandbox"
  review           the run's own LLM call

Honesty note: the mock provider cannot write code (it returns filler tokens), so the candidate
program comes from a fixture. `sandbox_check` only COMPILES it (ast.parse/compile, never exec).
The capability is still declared, in the register and on the container, because that declaration
is what drives the sandbox-tier admission rule (executes_model_code needs tier microvm, T7): a
real deployment would execute the candidate inside that microVM. Here the tier is a label plus a
hardened container, clearly a simplification.
"""
from __future__ import annotations

import ast
import hashlib
import random

from . import fixtures
from .common import SampleAgent

CAPABILITIES = ["calls_tools", "executes_model_code"]


class CodingAgent(SampleAgent):
    agent_id = "coding-agent"
    tools = {"plan_change", "generate_code", "sandbox_check"}

    def plan_change(self, run, title: str) -> str:
        return self.gw.chat(run, self.small, [
            {"role": "system", "content": "Outline the change as three short steps."},
            {"role": "user", "content": f"Task: {title}"}], max_tokens=self.tokens(48)).text

    def generate_code(self, run, title: str, plan: str) -> str:
        return self.gw.chat(run, self.large, [
            {"role": "system", "content": "Write a small, tested Python function. Return code only."},
            {"role": "user", "content": f"Task: {title}\nPlan: {plan}"}], max_tokens=self.tokens(96)).text

    def sandbox_check(self, run, code: str) -> dict:
        try:
            tree = ast.parse(code)
            compile(tree, "<candidate>", "exec")          # compiled, never executed
            return {"ok": True, "functions": [n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)],
                    "executed": False}
        except SyntaxError as e:
            return {"ok": False, "error": str(e)[:100], "executed": False}

    def work(self, run) -> None:
        task = random.choice(fixtures.CODE_TASKS)
        plan = self.toolbox.call(run, "plan_change", self.plan_change, title=task["title"])
        model_text = self.toolbox.call(run, "generate_code", self.generate_code, title=task["title"], plan=plan)
        candidate = task["code"]                                # see module docstring
        check = self.toolbox.call(run, "sandbox_check", self.sandbox_check, code=candidate)
        res = self.gw.chat(run, self.small, [
            {"role": "system", "content": "Review this change in one sentence."},
            {"role": "user", "content": candidate}], max_tokens=self.tokens(32))
        self.sink.emit({"event": "coding.candidate", "agent_id": self.agent_id, "run_id": run.run_id,
                        "task": task["name"], "sha256": hashlib.sha256(candidate.encode()).hexdigest()[:16],
                        "sandbox": check, "model_output_tokens": len(model_text.split()), "attempts": res.attempts})


if __name__ == "__main__":
    raise SystemExit(CodingAgent().main())
