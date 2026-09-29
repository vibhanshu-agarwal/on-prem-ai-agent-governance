# Policy-as-code

Policy lives in `policy/` (YAML), is compiled into a **signed, versioned bundle** by `services/policy/` (`policyctl`),
and is enforced at deploy time by an admission check. **Git pull-request review is the approval workflow.**

## What a policy says
| File | Content |
|---|---|
| `policy/global.yaml` | sandbox tier ladder (`container < gvisor < microvm`), capability -> minimum tier (`executes_model_code` -> microvm, `external_send` -> gvisor, `calls_tools` -> container), default `max_tokens` ceiling |
| `policy/teams/<team>.yaml` | team budget and model allowlist |
| `policy/agents/<agent>.yaml` | model allowlist (subset of team), budget, `max_tokens_ceiling`, declared `capabilities`, `required_sandbox_tier`, `allowed_images`, `require_human_approval` (consequential actions) |
| `policy/trust/*.pub.json` | public signing keys the verifier trusts (the trust anchor) |
| `policy/CODEOWNERS` | who must approve changes to which files |
| `policy/schema.json` | JSON Schema of the compiled policy (`policyctl schema`) |

Validation (pydantic, unknown fields rejected) also cross-checks: agent models within the team allowlist, agent budgets within the team budget,
and the declared tier is not weaker than what its capabilities need.

## Flow
1. Open a PR that edits `policy/**`. CI (or you) runs `policyctl validate` and the tests in `tests/policy/`.
2. CODEOWNERS reviewers approve; merge. The Git history (author, reviewer, commit) is the approval trail.
3. A release job with access to the signing key runs `policyctl build --activate`. The bundle records content hash,
   git commit (+ dirty flag), timestamp and an effective version `v<seq>-<hash12>`, and is signed with Ed25519.
4. Consumers call `PolicyStore.load_active()` (or `policyctl status/admit`). The signature is verified on **every** load;
   unsigned, tampered, wrong-key or unknown-key bundles are rejected and the loader fails closed (no policy = deny).
5. Bad change? `policyctl rollback [--to VERSION]` re-verifies and activates a previous signed bundle. `policyctl history`
   is the append-only record of published/activated/rolled-back versions.

## Commands
```
pip install -e services/policy            # or: PYTHONPATH=services/policy python -m govpolicy
policyctl keygen                          # .local/policy/signing.key (gitignored) + policy/trust/<id>.pub.json (commit via PR)
policyctl validate | schema
policyctl build [--activate]              # validate + sign + store; identical content is not re-published
policyctl activate VERSION | rollback [--to VERSION] | status | history | verify FILE
policyctl admit --agent coding-agent --image govpilot/coding-agent:1 \
    --capability executes_model_code --tier microvm      # exit 0 admit, 1 deny, 2 error (fail closed)
policyctl drift                           # deploy/agents.json vs active policy
```
Config via flags or env: `POLICY_DIR`, `POLICY_STORE` (default `.local/policy/store`), `POLICY_SIGNING_KEY`, `POLICY_TRUST_DIR`,
`POLICY_SIGNER`, `POLICY_VERIFIER`.

## Swapping the signing backend
`Signer`/`Verifier` (in `govpolicy/signing.py`) are the only crypto touchpoints. Set `POLICY_SIGNER` / `POLICY_VERIFIER` to
`package.module:factory` (called with the key path / trust dir) to use cosign/Sigstore, a KMS or an HSM. Key rotation:
add the new public key to `policy/trust/` (PR), sign with it, remove the old one later.

## Library use (control plane)
```python
from govpolicy import PolicyStore, Ed25519Verifier, AdmissionRequest, admit
store = PolicyStore(store_dir, Ed25519Verifier.from_trust_dir("policy/trust"))
b = store.load_active()                    # raises PolicyLoadError -> deny
b.policy.model_allowed("hr-agent", "mock-local"); b.policy.max_tokens_ceiling("hr-agent")
admit(b.policy, AdmissionRequest("coding-agent", image, ["executes_model_code"], "microvm"), b.version)
```
