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
| T2 budget | done, Fable review PASS (43bf3e3), 37 tests | native overshoots found (up to 4.1x-10.9x); budget_guard callback closes them, 36 tests zero overshoot |
| T3 control plane | done, Fable review PASS (0eb7f5c), 101 tests | 97 tests; stop 5-6 s, key refused ~0.1 s; see T3.md deviations (iptables RST, per-key block, sso network, port 4180) |
| T4 agents | in progress (Sonnet) | |
| T5 guardrails | in progress (Sonnet) | |
| T6 observability/discovery | implemented, in Opus review | 37 tests; Grafana :3400; eBPF works but OpenLIT OSS rejects controller; real gateway otel wiring pending (see T6.md) |
| T7 policy | done, review PASS (d105228), 58 tests | 52 tests; admission not yet wired to container start (T3/T8) |
| T8 acceptance | todo | |
| T9 hardening/release | todo | |
| T10 showcase packaging | todo | README, demo script |

## Log
- 2026-09-29: repo initialised, sources extracted, plan and agent defs written.
- 2026-09-29: user context: portfolio showcase, no sponsor; build simplified versions where company knowledge needed (see PILOT-PLAN context update).
- T1 review follow-ups: agent admin-route exposure -> T9; provisioning does not update budgets on existing keys (minor).
- T3 review leftovers (T9/T8 candidates): oidc_subject uniqueness (register.py:49); JWKS cache serves removed kid 300 s (oidc_identity.py:35); estop only finds default-labelled workloads (estop/core.py:76); /v1/delegations not rate-limited; authproxy hard-codes OIDC adapter.
- T2 review: shared gov-gateway must be recreated to load reviewed budget_guard before T8 runs. Leftover: stream cut counts chunks not tokens (budget_guard.py:481).
- Integration debt for T8: tests/foundation shows 4 failures from concurrent T2/T4/T5/T6 containers; wire otel into real gateway per T6.md; recreate gov-gateway.
