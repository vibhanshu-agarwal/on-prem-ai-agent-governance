# Operator runbook: on-prem AI governance pilot

Audience: the on-call operator. Every procedure below was written against the stack in this repository and uses only
commands that exist in it. The Docker-specific steps are the local-pilot implementation; the Kubernetes equivalents
(NetworkPolicy instead of `docker network disconnect`, `kubectl scale` instead of `docker stop`) are noted where they
differ. Shell: Git Bash on Windows or any POSIX shell from the repository root. Secrets live in `deploy/.env`,
`.local/control-plane.env`, `.local/agents.env` (all gitignored); treat them like the vault they stand in for.

Contents

1. [Map of the system and where the brakes are](#1-map)
2. [Bring-up, health check, shutdown](#2-bring-up)
3. [Stop one agent](#3-stop-one-agent)
4. [Bulk quarantine](#4-bulk-quarantine)
5. [Emergency stop when the control plane is down](#5-emergency-stop)
6. [Break-glass](#6-break-glass)
7. [Backup and restore](#7-backup-and-restore)
8. [Rollback](#8-rollback)
9. [Incident response: suspected gateway compromise](#9-gateway-compromise)
10. [Patch SLA for gateway advisories](#10-patch-sla)

<a id="1-map"></a>
## 1. Map of the system and where the brakes are

```
 agents (govpilot_agents, internal)          SSO agents (govpilot_agents_sso, internal)
        |  gateway:4000                              |  sso-gateway:8080
        v                                            v
 gov-gateway-edge  (nginx allowlist:          gov-authproxy (JWT -> per-agent key;
  inference routes only, else 403)             same route allowlist)
        |  gwfront (internal)                        |  backend (internal)
        v                                            v
 gov-gateway (LiteLLM, read-only, non-root, no caps) <---- admin API on `backend`: control plane, estop
        |  providers (internal)   |  backend: Postgres, Redis, Presidio
        v
 mock-local / mock-remote (stand-ins for model providers; the only holders of provider-side auth checks)
```

| Brake | What it does | Needs |
|---|---|---|
| Per-key budget (LiteLLM + `budget_guard`) | Refuses calls over budget, cuts streams | Gateway, Postgres, Redis |
| Stop (`POST /v1/agents/{id}/stop`) | Block key, cut network, stop workload, revoke credentials, disable IdP subject; ~5 s | Control plane, its Postgres, IdP |
| Bulk quarantine (`/v1/quarantine/*`) | Same, by selector, with blast-radius preview and dual control for fleet-wide | Control plane |
| Emergency stop (`:8190` or CLI) | Keys + network + workloads, no register, no IdP, hash-chained local journal | Gateway admin API + Docker only |
| Edge kill (`docker stop gov-gateway-edge gov-authproxy`) | Every agent loses model access at once | Docker only |

Ports (localhost only): gateway admin/operator 4000, control plane 8100, IdP 8300, auth proxy 4180, estop 8190,
OpenLIT 3300, Grafana 3400, status page 8400.

**Agents reach only the edge (`gateway:4000`) and the auth proxy.** The edge forwards exactly: `POST
/v1/chat/completions`, `/v1/completions`, `/v1/embeddings` (and the same without `/v1`), `GET /v1/models`, `/models`,
`GET /health/liveliness|liveness`. Everything else is a 403 from nginx and never reaches LiteLLM. If an agent needs
another route, add it to `deploy/hardening/nginx.conf` AND `ALLOWED_ROUTES` in `services/control-plane/govcp/authproxy/app.py`,
extend `tests/hardening`, and review it as a change to the attack surface.

<a id="2-bring-up"></a>
## 2. Bring-up, health check, shutdown

**First time / after code changes**

```bash
python -m venv .venv && .venv/Scripts/pip install -r tests/control/requirements.txt pytest   # once (test + tooling deps)
bash scripts/up.sh              # idempotent: secrets, observability, base stack (+hardening overlay), control plane,
                                # signed policy bundle, discovery feeds, agents, status page (~10 min cold, ~2 min warm)
bash scripts/up.sh --recreate   # also force-recreate gateway, edge, control plane and agents (after code/config edits)
UP_EBPF=0 bash scripts/up.sh    # skip the privileged OpenLIT eBPF controller
```

`up.sh` applies `deploy/hardening/compose.hardening.yml` on top of the base compose file (read-only rootfs, non-root
gateway, cap_drop ALL, edge proxy). Do not start the base file alone in production: it is the unhardened variant.

**Verify (each takes under a minute)**

```bash
docker ps --format 'table {{.Names}}\t{{.Status}}' | grep gov-      # everything "healthy" (controller has no healthcheck)
.venv/Scripts/python -m pytest tests/hardening -q                   # the hardening invariants hold on the running stack
.venv/Scripts/python -m pytest tests/foundation -q                  # network isolation, credentials, keyed calls
curl -s localhost:8100/healthz; curl -s localhost:8190/healthz      # control plane, estop
```

Full proof (about 80 min): `bash scripts/acceptance.sh` (writes `docs/results/ACCEPTANCE.md`).

**Linux hosts.** The gateway runs as uid/gid 65532 and nginx as 101. `state-init` (a one-shot in the overlay) chowns
`.local/guardrails` and the Redis volume for you; if you replace bind mounts, make the guardrail state directory
writable by 65532.

**Shutdown**

```bash
bash scripts/down.sh             # remove containers and networks, keep data volumes and secrets
bash scripts/down.sh --volumes   # ALSO delete keys, spend, register, audit, telemetry: destructive, back up first
bash scripts/control-plane-down.sh   # only the control-plane services (agents keep running, keys still enforced)
```

<a id="3-stop-one-agent"></a>
## 3. Stop one agent

Pick the first path that works; all of them end with the same verified state (key blocked, network cut, workload
stopped and pinned, credentials revoked).

1. **Status page** (`http://127.0.0.1:8400`), the "Stop" button of that agent (demo persona picker; production would
   put this behind SSO).
2. **Control-plane API** as an operator (IdP user with the `operator` role; passwords in `.local/control-plane.env`):

```bash
set -a; . .local/control-plane.env; set +a
TOK=$(curl -s localhost:8300/token -d grant_type=password -d username=alice -d "password=$IDP_PASSWORD_ALICE" \
        -d audience=govpilot-control-plane | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')
curl -s -X POST localhost:8100/v1/agents/finance-recon-agent/stop -H "Authorization: Bearer $TOK" \
     -H 'content-type: application/json' -d '{"reason":"INC-123 spend anomaly"}' | python -m json.tool | head -40
```

   The response is the stop report; `verify.ok` must be `true`. Reverse with `POST /v1/agents/{id}/resume`
   (credentials stay revoked: re-issue with `POST /v1/agents/{id}/rotate-secrets`, a human action).
3. **Emergency stop** (section 5) if the API fails or the control plane is down.

Check that it worked: the agent's key returns 401, `docker ps` shows the container exited, audit has `stop.completed`
(`GET /v1/audit?action_prefix=stop.`). A stop that reports `verify.ok=false` is an incident: go to section 5 and finish by
hand.

`rotate-secrets` returns **HTTP 502** (with the per-key results in the body) when an old key could be neither deleted nor
blocked, i.e. it is still live. Treat that as a failed rotation: block the key at the gateway by hand (section 5, step 3)
and retry.

<a id="4-bulk-quarantine"></a>
## 4. Bulk quarantine

Use when a whole class of workloads is suspect (a host, an image, a team). Always preview first.

```bash
# selector fields (ANDed): team, image, labels{}, host, agent_ids[], all
curl -s -X POST localhost:8100/v1/quarantine/preview -H "Authorization: Bearer $TOK" -H 'content-type: application/json' \
     -d '{"host":"docker-host-3"}' | python -m json.tool          # blast radius: agents, workloads, keys, credentials
curl -s -X POST localhost:8100/v1/quarantine/actions -H "Authorization: Bearer $TOK" -H 'content-type: application/json' \
     -d '{"preview_id":"<from preview>","reason":"INC-124 suspected escape on host 3"}'
```

* The action is refused as **stale** if the population changed since the preview: re-preview.
* **Fleet-wide** selections (`all` or above the dual-control thresholds in `deploy/control-plane/config.yaml`) need
  approvals from other operators: `POST /v1/quarantine/actions/{id}/approve` as each approver.
* Only humans can fire it (`kind=user` tokens); an agent's credential cannot.
* Lift: `POST /v1/quarantine/actions/{id}/lift` with `{"resume_agents": true}`. Keys of agents whose secrets were
  rotated stay dead.
* Host-compromise pattern (drill S8-07): quarantine the host, `docker export` the containers and save logs before
  removing anything, rotate secrets per agent (`rotate-secrets`), rebuild from the recorded known-good image id, lift.

<a id="5-emergency-stop"></a>
## 5. Emergency stop when the control plane is down

The estop path shares nothing with the control plane: no register, no Postgres, no IdP. Levels, least to most drastic.

**Level 1: estop service** (works if `gov-estop` is up; token in `.local/control-plane.env`)

```bash
set -a; . .local/control-plane.env; set +a
curl -s -X POST localhost:8190/estop/agents/hr-agent -H "Authorization: Bearer $ESTOP_TOKEN" \
     -H 'X-Estop-Operator: alice' -H 'content-type: application/json' -d '{"reason":"control plane down, INC-125"}'
curl -s -X POST localhost:8190/estop/teams/finance ...            # whole team
curl -s localhost:8190/estop/journal -H "Authorization: Bearer $ESTOP_TOKEN" -H 'X-Estop-Operator: alice'   # hash-chained
```

Agents are found by key metadata (`agent_id`, `root_agent_id`) and by workload labels (`govpilot.agent_id`,
`govpilot.root_agent_id`, `govpilot.team`, and for agents registered with a custom selector, the selector stored in the
key's `workload_labels` metadata). The journal is ingested into the control-plane audit chain when it returns.

**Level 2: estop CLI** (estop container also down; needs only Docker and the gateway master key)

```bash
set -a; . deploy/.env; set +a
docker run --rm --network govpilot_backend -v /var/run/docker.sock:/var/run/docker.sock \
  -e LITELLM_MASTER_KEY -e GATEWAY_URL=http://gateway:4000 -e ESTOP_JOURNAL=/tmp/estop.jsonl \
  govpilot/control-plane:1 python -m govcp.estop.cli agent hr-agent --reason "INC-125" --operator alice
```

**Level 3: by hand** (no platform code at all)

```bash
# 1. block the agent's key at the gateway (operator port; master key from deploy/.env)
curl -s -X POST localhost:4000/key/block -H "Authorization: Bearer $LITELLM_MASTER_KEY" \
     -H 'content-type: application/json' -d '{"key":"<key hash or raw key>"}'      # find hashes: GET /key/list?key_alias=hr-agent
# 2. stop and pin the workload
for c in $(docker ps -q --filter label=govpilot.agent_id=hr-agent); do docker update --restart=no $c; docker kill $c; done
# 3. optional network cut (an agent that ignores everything else)
docker network disconnect -f govpilot_agents gov-agent-hr
```

**Level 4: cut every agent at once** (fleet incident, or the gateway itself is suspect)

```bash
docker stop gov-gateway-edge gov-authproxy          # agents lose model access; nothing else changes
# undo:  bash scripts/up.sh   (or: docker start gov-gateway-edge gov-authproxy)
```

Prove afterwards: `curl -s -o /dev/null -w '%{http_code}' -H "Authorization: Bearer <agent key>" localhost:4000/v1/models`
returns 401 for a blocked key; the container is `Exited`; `docker ps -a --filter label=govpilot.role=quarantine-helper`
is empty (helper containers are removed automatically; `scripts/up.sh` sweeps stragglers).

The emergency-stop path is drilled in the acceptance suite (S8-08, kill-plane outage; S8-01 and S8-09 for the stop and the connection cut): repeat the drill after any change to the
gateway, the edge, Docker or the network layout.

<a id="6-break-glass"></a>
## 6. Break-glass

Break-glass exists for the guardrail engine only, by design. **Budget enforcement and identity have no break-glass**
(the report's rule: never cut budget enforcement to restore service).

*Situation:* Presidio (the PII engine) is down and agents with `restricted`/`confidential` data classes are failing
closed (HTTP 503 `guardrail_engine_unavailable`); the business needs them back before Presidio is fixed.

```bash
export PYTHONPATH=services/guardrails GOVGUARD_STATE_DIR=.local/guardrails
.venv/Scripts/python -m govguard.cli override grant --agent hr-agent --rule breakglass --ttl 15m \
    --reason "INC-126 presidio down, payroll run" --by alice
.venv/Scripts/python -m govguard.cli override list --agent hr-agent       # shows the active grant
.venv/Scripts/python -m govguard.cli override revoke <id> --by alice      # end it early
```

* Maximum TTL is **1 hour** (longer is refused); it expires by itself; every grant, use and revoke is audited
  (`override.granted`, `guardrail.breakglass_degraded`, `override.used`, `override.revoked` in
  `.local/guardrails/audit.jsonl`).
* Effect: the agent is served on the built-in regex engine (still masks e-mail, phone, card, IBAN, SSN patterns);
  it **degrades, it never opens**.
* Afterwards: fix Presidio (`docker restart gov-presidio-analyzer gov-presidio-anonymizer`), confirm
  `docker inspect -f '{{.State.Health.Status}}'` is healthy, review the audit for the window, file the post-incident note.

*Other emergency credentials (protect and audit):* the gateway master key (`deploy/.env` `LITELLM_MASTER_KEY`), the
estop token, the IdP admin token. Store sealed copies outside the host; rotate all after any use in anger.

<a id="7-backup-and-restore"></a>
## 7. Backup and restore

```bash
bash scripts/backup.sh                       # .local/backups/<UTC>/ : litellm.dump, controlplane.dump, redis.rdb, MANIFEST.sha256
bash scripts/restore.sh .local/backups/<UTC> # RESTORE TEST into a scratch Postgres (never the live one); prints row counts
```

Take a backup **before every upgrade and every rollback**, nightly otherwise, and copy it off the host. A backup does
not contain secrets: back up `deploy/.env`, `.local/*.env`, `.local/policy/signing.key` and the control-plane secret
volume (`govpilot_cpsecrets`) through your secret manager. Run the restore test after each backup job and after every
schema-changing upgrade (drill M-09 does this in the acceptance suite).

**In-place disaster recovery** (destructive; agents are down for the duration)

```bash
export MSYS_NO_PATHCONV=1
B=.local/backups/<UTC>; ( cd $B && sha256sum -c MANIFEST.sha256 )
# 1. quiesce: nothing may hold connections
docker stop gov-gateway-edge gov-authproxy gov-control-plane gov-estop gov-idp gov-gateway gov-discovery
# 2. LiteLLM database
# (streamed through stdin: the hardened Postgres containers have a tmpfs /tmp that `docker cp` cannot write to)
docker exec gov-postgres sh -c 'dropdb -U litellm --if-exists litellm && createdb -U litellm litellm'
docker exec -i gov-postgres pg_restore -U litellm -d litellm --no-owner < $B/litellm.dump
# 3. control-plane database (roles cp_owner / cp_app already exist from db-init; keep ownership)
docker exec gov-cp-postgres sh -c 'dropdb -U cp_super --if-exists controlplane && createdb -U cp_super controlplane'
docker exec -i gov-cp-postgres pg_restore -U cp_super -d controlplane < $B/controlplane.dump
# 4. Redis: DO NOT restore the snapshot over a newer append-only file. Spend counters are re-seeded from Postgres
#    (key spend columns) on first use; the budget guard reserves against the Postgres value, so the safe direction is
#    "counters too low for a moment, never too high". Only if you must: stop gov-redis, empty the volume, copy redis.rdb
#    to /data/dump.rdb, start with appendonly no once, then set it back.
bash scripts/up.sh --recreate
.venv/Scripts/python -m pytest tests/foundation tests/hardening -q       # then the section 9 checks of audit continuity
curl -s localhost:8100/v1/audit/verify -H "Authorization: Bearer $TOK"     # hash chain intact after restore
```

Spend recorded after the backup and before the failure is lost (LiteLLM flushes spend logs every 5 s, so the window is
the backup age). Budgets therefore under-count by at most that window: lower the affected agents' budgets or raise
nothing until the next budget period if that matters.

<a id="8-rollback"></a>
## 8. Rollback

The unit of release is a git commit plus `release/images.lock` (digests). Rollback = go back to the previous pair.

1. Back up first (section 7). Note the running versions: `docker ps --format '{{.Names}} {{.Image}}'`.
2. `git checkout <previous tag or commit>` (compose files, Dockerfiles, `release/images.lock` and the policy bundle
   sources move together).
3. `bash scripts/up.sh --recreate` (rebuilds the local images, recreates the gateway, edge, control plane and agents at
   the previous pinned digests).
4. `python -m pytest tests/hardening tests/foundation -q`, then the affected acceptance tests.

Component notes

* **Gateway (LiteLLM) version**: LiteLLM applies forward-only Prisma migrations at start. Rolling the image back
  across a schema change needs the pre-upgrade `litellm.dump` restored (section 7) or the old image will refuse or
  misbehave. That is why every upgrade starts with a backup and a restore test.
* **Policy bundle**: independent of code. `PYTHONPATH=services/policy python -c "from govpolicy.cli import main; main(['history'])"`
  lists versions; `main(['rollback'])` (or `['rollback','--to','<version>']`) re-activates the previous signed bundle;
  `main(['drift'])` compares provisioning with the active policy.
* **Guardrail config** (`deploy/guardrails/guardrails.yaml`) and `deploy/litellm/config.yaml` are bind-mounted: revert the
  file, `docker restart gov-gateway` (the edge keeps serving 502 for the ~30 s the gateway takes to start; agents retry).
* **Control-plane schema**: `cp-migrate` runs on every `up.sh`; restore `controlplane.dump` before running an older
  image against a newer schema.
* **Hardening overlay**: to diagnose whether the overlay causes a problem, start the base file only
  (`docker compose -f deploy/docker-compose.yml --env-file deploy/.env up -d gateway`); this re-attaches the raw
  gateway to the agents network and removes the allowlist, so use it for minutes, not days.

<a id="9-gateway-compromise"></a>
## 9. Incident response: suspected gateway compromise

Indicators: unexpected process or file in `docker exec gov-gateway ...` output; `docker diff gov-gateway` not empty
(the root filesystem is read-only, so any change there is alarming); hits on `deploy/hardening` routes in the edge log
that succeeded; provider-side usage that does not match gateway spend; unknown keys/teams in `GET /key/list` or
`/team/list`; new outbound connections from the gateway; a published advisory that matches the running version.

The gateway holds the provider credentials, the master key and salt, every agent key hash and the guardrail state, so
**assume all of them are exposed** until shown otherwise. Stay calm, keep evidence, work in this order.

1. **Contain (minutes).** `docker stop gov-gateway-edge gov-authproxy` (agents lose model access, nothing is deleted).
   If the compromise may extend beyond the gateway, also quarantine by selector (section 4). Do **not** restart or
   `docker rm` the gateway yet.
2. **Preserve evidence.**
   ```bash
   D=.local/incident-$(date -u +%Y%m%dT%H%M%SZ); mkdir -p $D
   docker inspect gov-gateway gov-gateway-edge > $D/inspect.json
   docker logs gov-gateway > $D/gateway.log 2>&1; docker logs gov-gateway-edge > $D/edge.log 2>&1
   docker diff gov-gateway > $D/diff.txt
   docker exec gov-gateway sh -c 'ls -laR /tmp /home/nonroot 2>/dev/null' > $D/tmp-listing.txt   # tmpfs is lost on stop
   docker export gov-gateway -o $D/gateway-fs.tar
   cp -r .local/guardrails $D/guardrails-state; bash scripts/backup.sh $D/backup
   ( cd $D && sha256sum * > MANIFEST.sha256 )
   ```
3. **Scope.** `curl -s localhost:8100/v1/audit/verify` (control-plane chain intact?); compare provider-side usage with
   gateway spend (`scripts/attribution_report.py`); `guardctl audit tail`; review `edge.log` for admin routes that were
   answered 200; check `LiteLLM_VerificationToken` for keys you did not create.
4. **Eradicate and rebuild.** Verify the image is the pinned one: `docker inspect -f '{{.Config.Image}}' gov-gateway`
   must equal the digest in `release/images.lock`. Remove the container and start a fresh one from the locked digest:
   `docker rm -f gov-gateway gov-gateway-edge && bash scripts/up.sh --recreate`. If the advisory is fixed in a newer
   version, upgrade first (section 10) rather than rebuilding the vulnerable one.
5. **Rotate everything the gateway held**, in this order:
   * provider credentials (the real providers' consoles; here `MOCK_*_API_KEY` in `deploy/.env` via `scripts/gen-env.sh`
     after deleting the old value, and the provider-side hash);
   * `LITELLM_MASTER_KEY` (also used by control plane and estop) and `LITELLM_SALT_KEY` (**salt rotation invalidates
     values LiteLLM encrypted in its DB, so re-enter any DB-stored model credentials; this pilot keeps models in config**);
   * every agent key: `POST /v1/agents/{id}/rotate-secrets` per agent (new key, old deleted at the gateway; 502 means an
     old key is still live), or `scripts/agents-up.sh` to redistribute;
   * Redis and Postgres passwords if the gateway's env was read (`gen-env.sh` regenerates; expect a full restart);
   * the IdP admin and estop tokens if the master key was used from a host that shared them.
6. **Return to service** only after `tests/hardening` and `tests/foundation` pass on the rebuilt stack and the agents'
   next calls succeed on the new keys. Lift quarantines (`lift` with `resume_agents`).
7. **Learn.** Timeline from the evidence bundle; which control failed (admin route exposure, patch delay, credential
   in env); file the change; add a regression check to `tests/hardening`.

Design facts that limit the blast radius (and that this drill relies on): agents never see provider credentials; the
gateway process is unprivileged with a read-only filesystem and no capabilities; only inference routes are reachable
from agents; the control plane's audit chain lives in a different database from the gateway's.

<a id="10-patch-sla"></a>
## 10. Patch SLA for gateway advisories

LiteLLM had actively exploited vulnerabilities in 2026 (report sections 5 and 6). The gateway is treated as top-tier
infrastructure. "Advisory" means a security advisory or CVE for LiteLLM, nginx, Presidio, Postgres, Redis or their base
images; the clock starts when it is **published** or when you learn of it, whichever is first.

| Severity / condition | Triage | Mitigate (contain exposure) | Patched and verified in production |
|---|---|---|---|
| Actively exploited (CISA KEV listed, public exploit against this component) | 4 h | 24 h (block the route at the edge, stop the edge, or disable the feature) | 72 h |
| Critical (CVSS >= 9) or pre-auth RCE / auth bypass on the gateway | 1 business day | 3 days | 7 days |
| High (CVSS 7.0-8.9) | 3 business days | 7 days | 14 days |
| Medium | 5 business days | not required | 30 days |
| Low / hardening advice | next review | not required | next scheduled release |

Because agents can reach only the edge's inference routes, most gateway advisories about admin, MCP-test, SSO or UI
routes are mitigated on day 0 by the allowlist; still patch on the schedule, and record that the exposure was
mitigated in the ticket.

**Watching.** Subscribe to GitHub security advisories for `BerriAI/litellm` (Watch > Custom > Security alerts), CISA
KEV, and the vendors' feeds. Scan the SBOMs weekly: `docker run --rm -v "$PWD/release/sbom:/s" anchore/grype
sbom:/s/ghcr.io_berriai_litellm.cdx.json` (grype is not part of the pilot; any SBOM-consuming scanner works).

**Patch procedure** (same for the gateway and every other pinned image)

1. Read the advisory: affected/fixed versions, which routes/features, whether the pilot enables them (only OSS proxy
   features are enabled; `enterprise/` is unused).
2. Back up (section 7). Pull the fixed image; note its digest: `docker pull <ref> && docker image inspect <ref> --format '{{index .RepoDigests 0}}'`.
3. Replace the reference in `deploy/docker-compose.yml` (and in `tests/*/stack/*.yml` where repeated), run
   `python scripts/release_artifacts.py` (updates `release/images.lock`, regenerates the SBOMs), review
   `git diff release/`.
4. `bash scripts/up.sh --recreate`.
5. **Revalidate on every upgrade** (report section 5): `pytest tests/hardening tests/foundation tests/control tests/guardrails`
   and the acceptance tests touching the gateway (`tests/acceptance`: budget overshoot, stop, no-bypass, latency). For a
   LiteLLM upgrade also re-run `tests/budget` (the budget guard patches version-specific behaviour) and read the
   release notes for changes to reservation, callbacks and custom-auth hooks.
6. Record: advisory id, dates for each SLA column, the digest before and after, the test run.

Missed SLA: page the platform owner, add a compensating control (edge block, quarantine the exposed capability,
or stop the edge), and record the exception with an expiry date.
