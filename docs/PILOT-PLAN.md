# Pilot build plan (local execution)

Source of truth: `docs/source/*.txt` (extracted from the project library). Precedence when sources conflict:
**Consolidated Report rev 2 (26 Aug 2026)** > Validated Business Brief / Follow-up (22 Aug) > On-Prem report (25 Jul) > CXO deck.

## Week 0 gate: defaults chosen (no customer yet, so these stand in until a real customer signs off)

| Gate item | Default for this local pilot | Why |
|---|---|---|
| Deployment shape | Docker Compose on Docker Desktop (one host). Kubernetes (kind) is a later phase. | Docker available, no k8s cluster; plan allows "Kubernetes or Docker". |
| Providers | Two OpenAI-compatible **mock providers** in-stack: `mock-local` (the "local model") and `mock-remote` (the "approved remote"). Deterministic tokens, configurable latency and streaming. Real Ollama optional later. | No spend, no credentials, reproducible tests. |
| Gateway | LiteLLM OSS proxy, pinned to a release **>= 1.83.7** (2026 CVE fix set). No Enterprise code or features. | Consolidated report §5/§6. |
| Identity route | **OSS route**: one LiteLLM virtual key per agent, keys grouped under a team per business unit; control plane is the identity register. JWT/OIDC custom auth layer deferred (no SSO agents in local pilot). | Report §2 licensing decision. |
| Budget enforcement | **Native LiteLLM budget reservation first** (default-on, plus `fail_closed_budget_enforcement`). Build custom ledger pieces only where acceptance tests prove a gap. | Rev 2 supersedes Jul "ledger first". |
| Streaming | Every request bounded by `max_tokens` or an agent default ceiling; unbounded rejected. | Jul §9 critical path. |
| Agents | Three sample agents: HR, Finance Reconciliation, Coding. Python, propagate `run_id` / `parent_run_id`. | Jul pilot boundary. |
| Guardrails | Presidio analyzer (self-hosted PII) + deterministic injection / tool-authorization / output rules. | Jul pilot boundary. |
| Observability | OpenLIT (+ ClickHouse) and its Grafana views; OpenLIT Controller eBPF discovery attempted, with docker-events + gateway-log discovery as the guaranteed feed. | Report §3. |
| Policy | Policy-as-code YAML in `policy/`, Ed25519-signed bundles, Git history is the approval trail. | Jul pilot boundary. |
| Latency SLO | Provider-free gateway overhead p95 <= 150 ms, p99 <= 300 ms (prompts <= 8K tokens). | Jul §9. |
| Network egress | Docker internal networks: agents can reach only the gateway; only the gateway reaches providers. | Report §5 #1 risk. |

## Task board (complexity -> implementer -> reviewer)

Low/medium: `impl-sonnet` (Sonnet 5.5 xhigh) -> `review-opus`. High: `impl-opus` (Opus 5.5 high) -> `review-fable`.

| ID | Task | Cx | Dirs owned | Acceptance (what "done" means) |
|---|---|---|---|---|
| T1 | Foundation stack: mock providers, Postgres, Redis, LiteLLM pinned + config, internal networks, per-agent keys bootstrap script, `make`-style scripts (`scripts/`) | Med | `deploy/`, `services/mock-provider/`, `scripts/` | `docker compose up` healthy; a keyed call through gateway to each mock works; an agent container cannot reach mock providers directly; no provider creds outside gateway. |
| T2 | Budget enforcement proof: native reservation under concurrency, retries, fallbacks, streaming, delayed telemetry; max_tokens default ceiling; fail-closed when DB/Redis down; build gap-fill only if tests fail | High | `tests/budget/`, `services/ledger/` (only if needed) | Zero overshoot in all tests; results documented in `docs/results/T2.md`. |
| T3 | Control plane: agent identity register, stop sequence (block keys -> tear down live connections -> scale desired state to 0 / disable restart -> revoke other creds -> verify), bulk quarantine by selector with blast-radius preview, separate emergency-stop path, append-only audit log, pending discovery queue (zero budget until approved), attenuated delegation tokens | High | `services/control-plane/`, `tests/control/` | Single stop < 30 s measured; bulk stop by selector; stopped agents do not restart; delegation broadening denied + alerted; emergency path works with main API down. |
| T4 | Agent adapters: HR, Finance, Coding sample agents with run_id/parent_run_id through LLM calls, retries, tools, delegation; attribution callback in gateway | Med | `agents/`, `deploy/litellm/callbacks/` | Every request attributed to agent, run, team, provider, model, tokens, cost (queryable). |
| T5 | Guardrails: Presidio + deterministic rules via LiteLLM guardrail hooks; false-positive/override handling | Med | `services/guardrails/`, `tests/guardrails/` | PII redacted/blocked per policy; injection rules fire; latency measured. |
| T6 | Observability + discovery: OpenLIT/ClickHouse/Grafana, docker-events discovery feed -> pending queue, rate-limited per feed | Med | `deploy/observability/`, `services/discovery/` | Unregistered service making an AI call appears in pending queue and can spend nothing. |
| T7 | Policy-as-code: signed bundles, model allowlist, sandbox-tier admission check, rollback | Med | `policy/`, `services/policy/` | Unsigned/tampered bundle rejected; capability/tier mismatch rejected at deploy; rollback works. |
| T8 | Acceptance suite + drills + latency bench mapped to the 12 tests of report §8 and Jul minimum criteria | High | `tests/acceptance/`, `docs/results/` | Each test runs, pass/fail recorded honestly. |
| T9 | Hardening + release: read-only gateway container, admin/test routes blocked, SBOM (if tool available), runbook, backup/restore | Low | `deploy/hardening/`, `docs/runbook/` | Hardening checks scripted; runbook written. |

Order: T1 -> (T2, T3) -> (T4, T5, T6, T7) -> T8 -> T9. Midpoint gate after T2+T3+T4: budget + correlation must work, else replan.

## Context update (2026-09-29, from the user)
No sponsoring company: this is a **portfolio showcase**. Where company-specific knowledge (network, auth structure) would be needed, make a sensible choice and build a simplified but working version rather than skipping it. Consequences:
- Identity: add a small self-hosted OIDC issuer (simulated corporate IdP) plus the **custom auth layer** that validates JWTs and maps each caller to its per-agent LiteLLM key (the OSS route from report §2), so the "authenticated-agent stop" test is demonstrable. Folded into T3.
- Kubernetes-only items (NetworkPolicy + conntrack, admission control, microVM tiers) get Docker equivalents (network disconnect + connection kill, deploy-time admission check, tier labels) and are clearly labelled as simplified.
- Audience is recruiters: favour a polished, visual demo (clean agent-status page with live spend and a big stop button, Grafana cost view, recorded demo GIF) and a README that leads with the problem, architecture, and proof results.
- **Loose coupling (design rule for every task):** a future sponsor should be able to adopt this repo by swapping adapters and config, not rewriting. The control plane talks to the outside world only through small interfaces (ports) with one adapter each for now:
  `IdentityProvider` (local OIDC -> corporate OIDC/LDAP), `Orchestrator` (Docker -> Kubernetes), `NetworkQuarantine` (docker network disconnect -> NetworkPolicy/Cilium), `GatewayAdmin` (LiteLLM API), `SecretStore` (env/file -> Vault), `DiscoveryFeed` (docker events -> k8s watch/OpenLIT Controller), `CredentialRevoker` (tool/MCP/DB creds), `AuditSink` (Postgres append-only -> SIEM).
  Adapter choice comes from config (env/YAML), never hard-coded; environment-specific values (hosts, teams, budgets, providers) live in config files, not code. Each adapter has a contract test so a new one can be validated the same way.
- T10 (new, Low): showcase packaging: top-level README with architecture diagram, one-command demo script walking through the 12 acceptance tests, results summary.

## Out of scope for local pilot
Real remote provider spend, SSO/JWT, Kubernetes NetworkPolicy/conntrack, microVM tiers (tier rule enforced at admission only), HA/DR, cloud billing.
