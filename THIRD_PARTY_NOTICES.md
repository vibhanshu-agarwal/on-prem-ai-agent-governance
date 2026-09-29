# Third-party notices

This repository's own code (control plane, guardrails, policy, agents, status page, scripts, tests, docs) is the
pilot's work. Everything below is third-party software that the pilot **runs as unmodified container images or
installs as Python packages**; none of it is vendored into this repository. Exact versions and digests are in
[`release/images.lock`](release/images.lock); the complete component lists (every package inside every image, with
declared licenses) are the CycloneDX SBOMs in [`release/sbom/`](release/sbom/) (index: `release/sbom/INDEX.md`).

This file is an engineering summary, not legal advice. Licenses were read from each project's published terms for
the pinned version (checked 2026-09-29). Before any use beyond this internal pilot (redistribution, offering the
stack to third parties as a service), have counsel review the "Implications" column and the SBOMs.

## Main components

| Component (pinned) | Role | License | Implications for this pilot |
|---|---|---|---|
| **LiteLLM** `ghcr.io/berriai/litellm:v1.100.3` | AI gateway (budgets, virtual keys, routing) | MIT for everything **outside** the `enterprise/` directory; files under `enterprise/` are under BerriAI's separate commercial license | The pilot uses **only** the open-source proxy. The image ships an `enterprise/` directory; none of its features (SSO/JWT auth, SCIM, audit-log export, ...) is enabled or relied on. That is why identity is a custom OIDC + auth-proxy layer (report section 2). Using enterprise features would require a license from BerriAI. |
| **OpenLIT** `ghcr.io/openlit/openlit:2.1.0` and `openlit-controller:0.10.0` | Telemetry receiver/UI, eBPF discovery controller | Apache-2.0 | Permissive: keep the license and NOTICE text if redistributed. The controller runs privileged (opt-in profile, `UP_EBPF=0` disables it). |
| **Presidio** analyzer + anonymizer `mcr.microsoft.com/presidio-*:2.2.362` | PII detection for the guardrail hook | MIT (spaCy MIT and its `en_core_web_*` models MIT / CC-BY-SA depending on the model; see the analyzer SBOM) | Permissive. Check the model licenses in the SBOM before redistributing the image. |
| **Grafana OSS** `grafana/grafana-oss:11.6.1` | Cost dashboards | **AGPL-3.0** (Grafana Labs, since v8.0) | See "Grafana and the AGPL" below. |
| Grafana ClickHouse datasource plugin 4.11.2 | Grafana to ClickHouse | Apache-2.0 | Downloaded at container start from grafana.com (`GF_INSTALL_PLUGINS`), so first start needs internet egress; an air-gapped deployment must bake the plugin into an image. |
| **ClickHouse** `clickhouse/clickhouse-server:24.4.1` | OpenLIT's store | Apache-2.0 | Permissive. |
| **PostgreSQL** `postgres:16.14-alpine` (x2: LiteLLM DB, control-plane DB) | State stores | PostgreSQL License (BSD-style) | Permissive. |
| **Redis** `redis:7.4.8-alpine` | Shared spend counters, rate limits | **RSALv2 / SSPLv1** (dual-licensed; Redis 7.4.x is source-available, not OSI open source) | Fine for internal use. Neither license lets you offer Redis itself as a managed service. If that matters to a sponsor: Valkey (BSD-3-Clause, wire-compatible) is a drop-in candidate; re-run the acceptance suite after swapping. Redis 8 adds an AGPLv3 option. |
| **nginx** (`nginxinc/nginx-unprivileged:1.27-alpine`) | Agent-facing allowlist proxy | BSD-2-Clause | Permissive. |
| Debian / Alpine base layers, `python:3.12-slim` | Base images | Mixed (GPL/LGPL/BSD/MIT... per package) | Standard distribution packages, unmodified. Per-package licenses are in the SBOMs. Redistributing an image means honouring those (source offers for GPL packages). |

## Python packages in this repository's own images

Declared in `services/*/requirements.txt` and `agents/requirements.txt`, installed from PyPI at image build time:

| Package | License |
|---|---|
| FastAPI, Starlette | MIT |
| Uvicorn | BSD-3-Clause |
| httpx | BSD-3-Clause |
| PyJWT, PyYAML, python-multipart | MIT |
| cryptography | Apache-2.0 OR BSD-3-Clause |
| docker (docker-py) | Apache-2.0 |
| psycopg 3, psycopg-pool | **LGPL-3.0** | 

`psycopg` is LGPL-3.0: it is used as an unmodified library (dynamic import from site-packages), which the LGPL
permits without affecting this project's own license. If the control-plane image is redistributed, ship the LGPL text
and keep the package replaceable (it is: `pip install` in the Dockerfile).

## Grafana and the AGPL

Grafana OSS is AGPL-3.0. What that means here:

* **Internal use, unmodified image (the pilot's case):** no source-disclosure duty is triggered. We run the
  official image as a separate container, provision dashboards/datasources as data files, and talk to it over HTTP.
  The AGPL does not reach this repository's own code through that separation.
* **Network-use clause (section 13):** if you **modify** Grafana's source and let users interact with it over a
  network, you must offer those users the modified source. Do not patch Grafana in this stack without planning for it;
  configuration and provisioning files are not modifications of the program.
* **Redistribution:** shipping a Grafana image (or a tarball of the stack that includes it) to others obliges you to
  provide the corresponding source and the license text. `release/images.lock` pins the exact upstream image so the
  matching source is unambiguous (github.com/grafana/grafana at v11.6.1).
* **Dashboards** in `deploy/observability/grafana/dashboards/` are this pilot's own JSON and are not derivative
  works of Grafana by virtue of being loaded by it.
* **Alternatives if the AGPL is a blocker for a sponsor:** OpenLIT's own dashboards (Apache-2.0) already show the
  same data; a commercial Grafana Enterprise/Cloud license removes the AGPL terms.

## Tooling used to produce release artifacts (not run by the stack)

| Tool | License | Use |
|---|---|---|
| Syft (`anchore/syft`, pinned by digest in `scripts/release_artifacts.py`) | Apache-2.0 | SBOM generation |

## How to keep this current

1. Upgrade an image: change the digest in the compose file / Dockerfile, run `python scripts/release_artifacts.py`,
   commit `release/images.lock` and `release/sbom/` together.
2. Read `release/sbom/INDEX.md` for new license names (anything not permissive, or `(none declared)`, needs a look).
3. Update the table above if a project changes its license (Redis, Grafana and Elastic-style relicensing has
   happened to several components in this stack's category; pinning by digest keeps the version you audited).
