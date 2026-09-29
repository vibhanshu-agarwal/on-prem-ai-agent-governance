# HANDOFF (read first when resuming)

Project: On-prem AI governance and cost control pilot (LiteLLM + OpenLIT + thin custom control plane), run locally on Docker Desktop.
Plan: `docs/PILOT-PLAN.md`. Sources: `docs/source/*.txt`.
Agent structure: `.claude/agents/` (impl-sonnet -> review-opus for low/med; impl-opus -> review-fable for high).
Rules: local git only, no push, no credentials, no paid providers, ask the user before anything outward-facing or irreversible.

## Status
| Task | State | Notes |
|---|---|---|
| Week 0 defaults | done | see PILOT-PLAN.md table |
| T1 foundation | done, review PASS (9438b3b) | LiteLLM pinned v1.100.3; see docs/results/T1.md |
| T2 budget | in progress (Opus) | gap: no per-key max_tokens ceiling -> pre-call hook |
| T3 control plane | in progress (Opus) | incl. OIDC stand-in + JWT->key auth layer |
| T4 agents | todo | |
| T5 guardrails | todo | |
| T6 observability/discovery | todo | |
| T7 policy | done, review PASS (d105228), 58 tests | 52 tests; admission not yet wired to container start (T3/T8) |
| T8 acceptance | todo | |
| T9 hardening/release | todo | |
| T10 showcase packaging | todo | README, demo script |

## Log
- 2026-09-29: repo initialised, sources extracted, plan and agent defs written.
- 2026-09-29: user context: portfolio showcase, no sponsor; build simplified versions where company knowledge needed (see PILOT-PLAN context update).
- T1 review follow-ups: agent admin-route exposure -> T9; provisioning does not update budgets on existing keys (minor).
