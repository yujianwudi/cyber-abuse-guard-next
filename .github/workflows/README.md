# GitHub Actions workflows

Eleven YAML files in this directory are executable workflows. Verification, static
analysis, candidate construction, attestation, and publication are separated
by trust boundary; a successful build or CodeQL scan is not by itself
permission to publish.

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | Pull requests to `main`; pushes to `main` | Core quality, long fuzzing, Linux artifacts, the fixed CPA v7.2.95 source/compile contract, and reproducibility |
| `codeql.yml` | Pull requests and pushes to `main`; weekly schedule; manual dispatch | Minimal-permission CodeQL analysis for Go on Ubuntu, using the same sparse restricted-data boundary and a pinned manual Go build; produces code-scanning results only |
| `candidate.yml` | Manual dispatch from exact `main` | Produce a private clean candidate artifact; never creates a GitHub Release |
| `attested-prerelease.yml` | Manual dispatch from annotated `v0.15-dev.round6[.N]` | Bind candidate, Host, audit, and evaluation attestations into a blocked prerelease |
| `release-rc.yml` | Repository-disabled historical dispatch for annotated exact-main `v0.16-rc.2` | Immutable Round 8 identity only; workflow ID `315644586` must remain `disabled_manually` and is not a Round 9 lane |
| `round8-host-validation.yml` | Repository-disabled historical dispatch for annotated exact-main `v0.16-rc.2` | Immutable Round 8 Host identity only; workflow ID `318443961` must remain `disabled_manually` and is not accepted as Round 9 evidence |
| `round9-gate.yml` | Pull requests to `main`; pushes to `main` | Linux-only Round 9 policy, Safe Gate, development-corpus, and public-corpus verification; explicitly does not execute either independent corpus |
| `round9-host-validation.yml` | Manual dispatch from annotated exact-main `v0.16-rc.3` | Protected Linux x64, no-checkout external evaluation through a fixed root-owned broker; emits only the signed privacy-bounded evaluation and protected-ledger proof |
| `round9-release-rc.yml` | Manual dispatch from annotated exact-main `v0.16-rc.3` | Admit exact-main CI plus the exact-main Round 9 gate run, build/attest/upload only a private 17-asset candidate, and retain a fail-closed exact-19-asset independent-audit verifier; all public publication and existing-Release paths remain disabled |
| `release.yml` | Exact `v0.15` tag | Rebuild and verify the formal bytes, then create a draft Release |
| `release-promote.yml` | Manual dispatch from exact `v0.15` | Publish the already verified, unchanged formal draft |

`codeql.yml` grants `contents: read` globally and `security-events: write` only
to its analysis job. It does not receive `contents: write`; its pinned
Go 1.26.4 command
`go build -mod=readonly -tags=sqlite_omit_load_extension ./cmd/cyber-abuse-guard ./internal/... ./rules`
compiles only the reviewed source for CodeQL tracing and does not upload release
artifacts. It is not a substitute for the exact-main CI, signed external
evaluation and ledger proof, or release admission. Repository branch protection and
required-status settings remain external GitHub configuration; adding this file
does not enable them automatically. The desired post-green-merge settings and
read-only verification commands are recorded in
[`docs/REPOSITORY_GOVERNANCE.md`](../../docs/REPOSITORY_GOVERNANCE.md).

PR #21 CodeQL run
[`29815201426`](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29815201426)
confirmed that Go does not support `build-mode: none`. The active workflow now
uses the reviewed pinned manual build instead of treating that failed mode as
valid evidence.

GitHub currently accepts at most 25 top-level `workflow_dispatch` inputs. This
repository deliberately retains a stricter reviewed cap of 10 and keeps the
attested-prerelease interface at eight identity/authorization inputs plus one
`external_attestations_json` string so the external evidence is admitted as one
exact-schema object. Admission rejects non-object JSON, extra or missing keys,
non-string evidence values, non-PASS decisions, malformed hashes, and evaluation
identities older than `evaluation-v11`; the repository safe gate also rejects
any manual workflow that exceeds the repository's 10-input cap.

The nine inputs are `tag`, `expected_commit`, `expected_tree`, `ci_run_id`,
`candidate_run_id`, `expected_so_sha256`, `expected_store_zip_sha256`,
`external_attestations_json`, and `authorize_blocked_prerelease`. The JSON input
must have exactly the following shape; replace the example hashes with the
independently verified lowercase SHA-256 values:

```json
{"host_evidence_sha256":"0000000000000000000000000000000000000000000000000000000000000000","host_validation":"PASS","independent_audit_sha256":"1111111111111111111111111111111111111111111111111111111111111111","independent_audit_validation":"PASS","independent_evaluation_id":"evaluation-v11","independent_evaluation_sha256":"2222222222222222222222222222222222222222222222222222222222222222","independent_evaluation_validation":"PASS"}
```

The earlier exact-main v0.16 CI run
[`29799561002`](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29799561002)
failed twice on 2026-07-21. Attempt 1 failed in `fuzz-smoke` when
`FuzzExtractText` exceeded its context deadline. Attempt 2 passed that fuzz
step, then failed in `operational-script-security` because the Round 6 document
consistency fixture rejected an unreviewed document mutation. Both attempts
created zero Actions artifacts. This is current failure evidence, not an absent
workflow run and not Round 8 release authorization.

## Current Round 9 lane

The current engineering chain is `round9-gate.yml` → the private-candidate phase
of `round9-release-rc.yml` → `round9-host-validation.yml`. There is no enabled
public-release phase. RC admission requires both successful exact-main push CI
and a successful exact-main push run of `Round 9 policy gate`, including exact
run attempts and the candidate commit. It also fails unless historical workflow
IDs `315644586` and `318443961` remain `disabled_manually`, and it rejects every
existing `v0.16-rc.3` Release instead of treating one as recovery success. The
ordinary gate uses the restricted source boundary and never executes an
independent corpus. The protected Host workflow deliberately performs no source
checkout. Its ten dispatch inputs carry only the exact tag/tree/Phase 1
identities, one canonical candidate-identity object, and a fresh challenge to
the preinstalled command
`sudo -n /usr/local/libexec/cag-round9-eval-broker evaluate`. The separately
reviewed root-owned installation owns the encrypted corpus, evaluator, CPA
sandbox adapter, fixed image identities, PAT, signing keys, and result directory;
none of those paths or secrets is supplied by the candidate repository.

The job runs on `self-hosted`, `linux`, `x64`, `cag-round9-sandbox` in the
protected `round9-host-validation` environment. The broker fixes CPA to
`v7.2.95@f71ec0eb6776854457892452cf28c47f0d658251`, permits only
`127.0.0.1:18394 -> 8317/tcp`, and drives one authenticated CPA container in
Audit, Balanced, then Strict order. Missing Audit/phase-status evidence,
SQLite v6 `quick_check`/WAL/restart recovery, panic/lifecycle checks, usage-queue
accounting, or default-disabled Raw Capture observations prevents a publishable
`PASS`; required checks cannot be hidden in a `not_observed` list.
The workflow additionally binds `github.ref`, `github.sha`,
`github.workflow_ref`, and `github.workflow_sha` to the exact
`refs/tags/v0.16-rc.3` candidate and forwards all four values to the root-owned
broker. A branch dispatch, a different workflow revision, or a substituted
broker argument fails before evaluation.

The active machine contracts are:

| Evidence object | Exact identity |
|---|---|
| Signed evaluation payload | `round9-external-evaluation/v2` |
| Evaluator aggregate | `round9-external-evaluator-aggregate/v2` |
| Protected ledger event | `round9-external-evaluation-ledger-event/v2` |
| Protected ledger proof | `round9-protected-git-ledger-proof/v1` |
| Mechanically derived counted-Mock evidence | `round9-external-counted-mock/v1` |
| CPA sandbox descriptor | `round9-external-cpa-sandbox/v2` |
| Independent-audit signed evidence | `round9-independent-audit-evidence/v1` |
| Independent-audit ledger event | `round9-independent-audit-ledger-event/v1` |
| Independent-audit ledger proof | `round9-independent-audit-ledger-proof/v1` |
| Visible development-only public corpus | `round9-public-adversarial-v10` / 183,752 bytes / `bda9f4e70b9e3a050e7e40d025024fa8a9ebb1ffa2fb46f9f7ac47d27691526d` |

The Host workflow attests and uploads exactly
`round9-external-evaluation.json` and
`round9-external-ledger-proof.json`. Visible development paired-malicious
evidence must block 100% overall and in every category; independent malicious
evidence remains a separate gate at at least 95% overall and per category. The
RC lane currently uses neither Host evidence nor release-title text as public
publication authority. It only retains the private 17-asset Actions candidate.
The `publish`, `publication_blocked`, and legacy `verify_published` jobs are all
gated on the admission output `publication_permitted`; the only reviewed
  admission step writes that output as the literal string `false`, the Safe Gate
  binds the output and all three exact conditions, the workflow has no
  `contents: write`, and any existing Round 9 Release fails admission. The
  independent-audit step now mechanically checks canonical signed evidence,
  exact 19-asset bytes/SHA-256/provenance, independent signer/run/challenge, and
  the protected one-shot ledger; no such external package or trust configuration
  is currently provided, so it returns `NOT_PROVIDED`. Neither a green workflow
  nor external counted-Mock evidence is production approval; independent audit
  remains required. See
  [`docs/ROUND9_INDEPENDENT_AUDIT_CONTRACT.md`](../../docs/ROUND9_INDEPENDENT_AUDIT_CONTRACT.md).

## Historical Round 8 lane

The historical `release-rc.yml` admits only `v0.16-rc.2` and has exactly ten
dispatch inputs. `ci_run` and `host_run` each bind a positive run ID and attempt
as `RUN_ID:RUN_ATTEMPT`; `publish_rc_release=false` requires all four top-level
protected-Host inputs to be empty, performs the complete
Linux and the single-profile CPA v7.2.95 source/compile gate, reproduces all 17 final assets
across two independent clean clones, and uploads only a private Actions artifact.
It does not create or modify a GitHub Release.

Historical Phase 2 admission dispatches `round8-host-validation.yml` with the
exact successful Phase 1 run/attempt,
artifact ID/digest, tag identity, and a fresh 64-hex challenge. That protected
workflow is fixed to the `self-hosted`, `linux`, `x64`, and
`cag-round8-sandbox` labels. It verifies the 17-file candidate and every Phase 1
GitHub attestation, proves the configured daemon/sandbox/probe identity plus a
bind-mount locality challenge, runs the v7.2.95 counted-Mock lane, and creates a GitHub
attestation for exactly `round8-host-evidence.json` and its sidecar.

`publish_rc_release=true` accepts only the exact successful Host workflow
run/attempt and two-file artifact ID/digest plus the same one-time challenge. It
downloads that artifact from GitHub, verifies its digest and signer workflow,
source ref, source commit, Host run identity, Phase 1 artifact identity, runner
identity, and schema-v2 sandbox locality binding. The evidence still binds the
tag, commit, tree, Linux amd64 candidate SO hash, the CPA v7.2.95 identity,
counted-Mock `PASS`, the full closed numeric/boolean
matrix, and the no-Provider/no-production safety assertions. Duplicate keys,
extra nested fields, type drift, identity drift, malformed hashes, or a bare
self-reported `PASS` fail closed. The evidence and sidecar enter
`checksums.txt`, the audit bundle, manifest, private transfer artifact, and the
final 19-asset Release allowlist.

The Round 8 repository files alone did not activate that trust boundary. GitHub had to
separately configure protected environments `round8-host-validation` and
`round8-rc-publication`, required reviewers with self-review and admin bypass
disabled, exact deployment policies, a dedicated protected runner, and the
`ROUND8_SANDBOX_ID`, `ROUND8_DAEMON_ID`, and `ROUND8_PROBE_IMAGE_ID` environment
variables. Until that external configuration exists, Phase 2 is not publishable.

Manifest schema 4 distinguishes `candidate` from `publish`. A publish-stage
manifest says only `VERIFIED / COUNTED_MOCK_ONLY`; real Provider and production
validation remain `NOT_RUN / PROHIBITED`. Independent audit and independent
evaluation remain `NOT_PROVIDED` and `required`, production approval remains
absent, and no stable v0.16 release is claimed.

If publication succeeds but the publish job loses its terminal response,
**Re-run failed jobs** on that same workflow run reuses the successful build
artifact and checks the already-public immutable Release without mutation.
A new dispatch or **Re-run all jobs** takes a separate path: admission emits
`already_public=true`, the write-capable build and publish jobs are skipped, and
the read-only `verify_published` job downloads the existing 19 assets. Under the
same pinned builder container it performs the restricted checkout, uses
`setup-go` with `cache:false`, reruns the complete Linux gates, rebuilds the
canonical 19-asset candidate, and compares every rebuilt byte with the public
asset. It also checks the exact tag, commit, tree, CI run/attempt, canonical
title/body, prerelease and non-latest state, GitHub asset digests, sidecars,
manifest hashes, and signed attestations. That path requests no write permission
and performs no Actions cache write, artifact upload, attestation generation, or
Release mutation; any mismatch fails for manual investigation.

The retired one-off `v0.15-rc.2` workflow definition is retained under
[`docs/archive/workflows/`](../../docs/archive/workflows/) and is not executable
by GitHub Actions. Its recorded runs failed; the public RC was an explicitly
disclosed direct owner-authorized release and was not produced by a successful
run of that workflow. The protected `v0.15-rc.3` tag is also retained as failed,
unpublished evidence: run 29728286559 passed admission, failed before packaging,
published no Actions artifact, and created no GitHub Release. Those v0.15 RC
records are historical. The historical `release-rc.yml` is independently
hashed, fixed to v0.16-rc.2 and the reviewed CPA pin, and does not reuse or
mutate the archived RC2 file. It is not a substitute for the current Round 9
workflow identities.

When changing a release workflow, update its path/name bindings, manifest
validators, release documentation, and `scripts/round6_safe_gate_contract.py`
in the same pull request. The fail-closed identity checks intentionally reject
partial renames.
