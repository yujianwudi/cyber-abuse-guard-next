# Historical v0.16 Round 9 release admission policy

> [!IMPORTANT]
> This publication design was retired by the workflow cleanup. The default
> branch now
> contains only `ci.yml`, `codeql.yml`, and `policy-gate.yml`; none can create
> or modify a GitHub Release. Owner-run server diagnostics occur outside GitHub
> Actions and are not independent evidence. The remainder of this document is a
> point-in-time audit record, not an executable or current publication plan.
> Current Round 12 status is defined in [ROUND12_STATUS.md](ROUND12_STATUS.md):
> final-candidate second-machine execution remains pending, and this round does
> not create a tag or Release.

Field names beginning with `current_` below are preserved verbatim from that
historical snapshot; they do not describe the active workflow inventory.

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: 6cd7296bee90b9352a9cf1745b7760c0ff1b18a265da4af498c5877d4b542f87
```

```text
current_ruleset_version: 1.0.10
current_ruleset_sha256: e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0
current_identity_freeze_status: PENDING_FINAL_SOURCE_FREEZE
```

This source file historically defined the release process; it does not claim that external
Host, audit, or publication gates have passed. A source commit becomes an
official stable release only when the GitHub Release is non-draft and carries
the attestations named below. A non-draft RC prerelease is still not a stable
release or deployment authorization. Pull requests and source snapshots are
never deployment authorization by themselves.

## Historical Round 9 prerelease lane

```text
current_round: 9
current_source_version: 0.16
current_formal_tag_reserved: v0.16
current_version_alias_policy: reject-v0.16.0
current_candidate_tag: v0.16-rc.4
current_candidate_status: PENDING_FINAL_SOURCE_FREEZE_HOST_AND_INDEPENDENT_EVIDENCE_NOT_PROVIDED
historical_failed_candidate_tag: v0.16-rc.3
historical_failed_candidate_tag_object: a70e30fe5b66a6060e0358efd084edfbb60722e1
historical_failed_candidate_commit: 77cf2de50f89af12a4a1e7c651a2ac0074cabcdd
historical_failed_candidate_phase1_run: 30118817188
historical_failed_candidate_reason: missing-pyyaml-at-safe-gate-import
historical_failed_candidate_actions_artifact_count: 0
historical_failed_candidate_release: ABSENT
current_platform: linux-amd64
current_go_contract: 1.26.4
current_cpa_version: v7.2.113
current_cpa_commit: bc71c77f5cc42f3fbe1bf040cf14d4f166894835
current_gate_workflow: .github/workflows/round9-gate.yml
current_host_workflow: .github/workflows/round9-host-validation.yml
current_rc_workflow: .github/workflows/round9-release-rc.yml
current_host_environment: round9-host-validation
current_host_runner_label: cag-round9-sandbox
current_publication_environment: round9-rc-publication
current_rc_manifest_schema: 6
current_rc_build_metadata_schema: 4
current_audit_schema: 6
current_raw_capture_schema: 4
current_development_evidence_schema: round9-development-evidence/v1
current_external_evaluation_schema: round9-external-evaluation/v3
current_external_evaluator_aggregate_schema: round9-external-evaluator-aggregate/v3
current_external_ledger_event_schema: round9-external-evaluation-ledger-event/v3
current_external_ledger_proof_schema: round9-protected-git-ledger-proof/v1
current_independent_audit_evidence_schema: round9-independent-audit-evidence/v1
current_independent_audit_ledger_event_schema: round9-independent-audit-ledger-event/v1
current_independent_audit_ledger_proof_schema: round9-independent-audit-ledger-proof/v1
current_counted_mock_schema: round9-external-counted-mock/v1
current_public_counted_mock_schema: round9-public-counted-mock/v1
current_public_counted_mock_transport_schema: round9-public-counted-mock-transport/v1
current_public_decision_audit_schema: round9-public-cpa-decision-audit/v1
current_external_decision_audit_schema: round9-external-decision-audit/v3
current_cpa_audit_expectations_schema: round9-cpa-audit-expectations/v3
current_cpa_sandbox_finalize_schema: round9-cpa-sandbox-finalize/v2
current_cpa_sandbox_descriptor_schema: round9-external-cpa-sandbox/v2
current_external_evaluator_identity: cag-round9-external-evaluator-v3
current_cpa_host_listener: 127.0.0.1:18394->8317/tcp
current_external_evaluation_asset: round9-external-evaluation.json
current_external_ledger_proof_asset: round9-external-ledger-proof.json
current_candidate_asset_count: 17
current_private_candidate_artifact: actions-only-17-assets
current_private_candidate_capability: build-attest-upload-actions-only
current_legacy_verifier_asset_count: 19
current_legacy_verifier_reachability: disabled-if-false
current_new_public_prerelease_creation: BLOCKED_FAIL_CLOSED
current_exact_candidate_independent_audit_evidence_status: NOT_PROVIDED
current_exact_candidate_independent_audit_mechanical_gate: IMPLEMENTED_FAIL_CLOSED_EVIDENCE_NOT_PROVIDED
current_host_evaluation_publication_sufficiency: false
current_release_title_publication_sufficiency: false
current_publication_write_permission: absent
current_round9_gate_admission: workflow=Round 9 policy gate,path=.github/workflows/round9-gate.yml,event=push,branch=main,exact-commit,completed-success
current_historical_workflow_disable_requirement: 315644586:release-rc.yml=disabled_manually,318443961:round8-host-validation.yml=disabled_manually
current_paired_corpus: round9-development-paired-malicious-v3
current_paired_corpus_manifest_version: 2
current_paired_cases_sha256: 2a30da8d4872029d9b070a7b8bd8fb72a132994a21975f64b49cd56ecf4b2b3d
current_paired_label_audit_sha256: a2d34853f20ae1c0b18690a4f58f100fe0014c53232457d5084aa90407e2ab8f
current_paired_label_audit_status: PRE_EXECUTION_PASS_120_OF_120
current_paired_source_report_schema: round9-development-paired-malicious-report/v3
current_paired_machine_report_schema: round9-development-paired-malicious-machine-report/v1
current_public_adversarial_corpus: round9-public-adversarial-v13
current_public_adversarial_manifest_schema: round9-public-adversarial-corpus/v13
current_public_adversarial_machine_report_schema: round9-public-adversarial-report/v13
current_public_adversarial_counts: payloads-24_formal-unique-23_historical-8_branch-head-1_prompt-like-14_unmerged-carriers-1_nondefault-branches-5_release-assets-16_release-assets-with-prompt-entries-4_release-asset-metadata-records-199_executed-1_not-provided-0_scenario-payloads-24_serialized-routes-120_direct-blocked-12_direct-allowed-12
current_public_adversarial_manifest_bytes: 481448
current_public_adversarial_manifest_sha256: 91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6
current_public_counted_mock_matrix: unique-10_routes-120_audit-allow-40_enforcement-block-80_upstream-40_usage-40
current_independent_benign_requirement: 600-unique-zero-block-zero-hard-policy
current_development_paired_recall_requirement: aggregate-and-each-category-exactly-10000-basis-points
current_independent_malicious_recall_requirement: aggregate-and-each-category-at-least-9500-basis-points
current_release_kind: private-candidate-only-public-prerelease-blocked
current_release_latest: false
current_legacy_verifier_identity_contract: release-object,tag=v0.16-rc.4,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true
current_legacy_verifier_asset_contract: exact-count=19,download-count=19,byte-compare-each=rebuilt-candidate,attestation-check=17-release-workflow-plus-2-host-workflow
current_release_recovery: fail-only-existing-release-rejected-no-automatic-verifier
current_release_new_dispatch_or_rerun_all: admission-existing-release-fail-only-otherwise-private-candidate-only
current_release_draft_recovery: fail-only-manual-review-no-automatic-mutation
current_release_recovery_access_policy: no-recovery-path-no-state-mutation
current_release_forbidden_public_release_mutations: release-create,release-edit,release-upload,release-delete
current_release_permitted_private_candidate_writes: actions-artifact-upload,build-provenance-attestation
current_release_forbidden_cache_mutation: cache-write
current_release_latest_stable: v0.15
current_release_mismatch_policy: fail-only-no-automatic-repair
current_independent_audit_status: NOT_PROVIDED
current_production_approval_status: NOT_GRANTED
```

The Round 9 lane is separate from the Round 8 workflows and identities. It is
Linux amd64 only, uses the exact Go 1.26.4 builder contract, and fixes CPA to
`v7.2.113@bc71c77f5cc42f3fbe1bf040cf14d4f166894835`. The policy gate is an
ordinary push/pull-request engineering gate. It does not run either independent
corpus. The protected Host workflow is the only lane allowed to request the
one-shot independent benign and independent malicious evaluation. It performs
no source checkout: a separately reviewed, root-owned broker controls the
encrypted corpus, evaluator, keys, fixed images, protected ledger, and result
directory. The workflow receives only the signed privacy-bounded result and
ledger proof. It must not contact a real Provider or production.

The protected Host runner is documented in `docs/ROUND9_HOST_RUNNER.md`. CPA
must publish exactly `127.0.0.1:18394 -> 8317/tcp`; preflight fails if that
listener is unavailable, Docker configured/runtime bindings are checked
byte-for-byte, and the exact binding is retained in Host evidence and the RC
manifest. No wildcard, random CPA Host port, or additional listener is
admissible.

The RC workflow accepts exactly ten dispatch inputs, including a successful
exact-main `Round 9 policy gate` run ID and attempt. It also requires the
historical workflow IDs `315644586` (`release-rc.yml`) and `318443961`
(`round8-host-validation.yml`) to report `disabled_manually`. After admission it
produces self-contained development evidence, embeds it in the schema-6
manifest, attests exactly 17 assets, and uploads only a private Actions candidate
artifact for protected Host evaluation. There is no publication boolean or
successful public-recovery state. The publish, publication-blocker, and legacy
existing-Release verifier jobs all require
`needs.admission.outputs.publication_permitted == 'true'`; the reviewed
admission step emits exactly `publication_permitted=false`, and both Safe Gate
and document consistency bind that output plus all three conditions. The
workflow has no `contents: write` and exposes no Release-create, upload, edit,
delete, or other mutation path.

The Host result is necessary evaluation evidence, but it is not sufficient
publication authorization.
Release title/body text such as `independent audit required` is also not evidence.
The exact-candidate independent-audit evidence and ledger schemas, independent
signer identity, 19-asset digest/provenance binding, replay/freshness checks,
and offline/remote mechanical verifier now exist. They are implemented in
`scripts/round9_independent_audit_contract.py` and documented in
`docs/ROUND9_INDEPENDENT_AUDIT_CONTRACT.md`. No independently signed evidence
package, pinned auditor trust configuration, auditor run/artifact, or protected
audit-ledger events have been provided. The verifier therefore returns
`NOT_PROVIDED`, and no new public `v0.16-rc.4` prerelease can be created by this
workflow.

The verifier does not create, sign, repair, or infer any of those external records.

The prospective 19-asset shape adds
`round9-external-evaluation.json` and `round9-external-ledger-proof.json` to the
17 candidate-built assets, but that shape is documentation for the read-only
verifier and independent audit contract only; it is not a current write
authority. The audit evidence package remains outside the 19 Release assets and
binds them without creating a circular self-attestation.

The disabled legacy verifier documents the prospective signer split: the 17
candidate-built assets would require the Round 9 RC-workflow attestation, while
the two external assets would require the protected Round 9 Host-workflow
attestation. It retains byte and stable-latest checks for future review, but no
execution path can enter it. Admission rejects any existing `v0.16-rc.4`
Release, whether draft or public, and never deletes, edits, uploads to, repairs,
or treats that Release as success. A new dispatch or `Re-run all jobs` therefore
either creates a fresh private 17-asset candidate after all admission checks or
fails closed.

Manifest schema 6 binds `classifier-policy-v9`, ruleset `1.0.10`, audit schema
v6, Raw Capture schema v4, canonical Phase 1 development evidence, paired-v3
and public-v13 machine reports, independent benign zero-block/zero-hard-policy
results, exact 100% visible-development paired recall, independent malicious
aggregate and per-category recall of at least 95%, per-category Wilson
intervals, the closed decision-kind set, the fixed loopback CPA listener, and
authenticated mode-transition evidence. The external evaluation payload is
schema v3 and its counted-Mock object is a closed mechanical derivation of the
validated execution and metrics; a hand-filled `state=PASS` is rejected.
Private-candidate manifests leave external evaluation, protected ledger, and
counted-Mock results as `NOT_PROVIDED / EXTERNAL_EVALUATION_REQUIRED`.

The paired-v3 corpus uses corpus manifest version 2. It binds the exact
`cases.jsonl` identity and the external pre-execution `LABEL_AUDIT.md` identity;
the audit report in turn binds the same cases SHA-256 and records 120/120 PASS
without candidate output or classifier/project-test execution. A future
publication path must mechanically bind the independently audited exact
candidate to the canonical title, body, and 19-name allowlist; the current
workflow cannot substitute title text or a Host `PASS` for that missing audit.

Before any public writer may be restored, an independent authority must provide
all of the following, and the implemented contract must reject missing, extra,
stale, replayed, or mismatched data:

- a canonical `round9-independent-audit-evidence/v1` envelope signed by the
  separately pinned independent-auditor key and workflow identity;
- tag, tag-object, commit, tree, canonical manifest, exact sorted 19-name
  allowlist, byte length, SHA-256, and expected provenance for every asset;
- the exact independent auditor workflow run/artifact attestation and one-time
  challenge;
- signed, hash-chained `reserved`, `started`, and `result` events under the
  protected audit-ledger namespace, with no `aborted` event;
- an active no-bypass tag ruleset that prohibits both deletion and update; and
- a complete verifier PASS against the external package and remote identities.

The test suite mutation-checks title-only approval, Host-only approval, Boolean
`PASS`, asset substitution, signer/key drift, unknown fields, digest/chain drift,
aborted ledgers, and malformed or incomplete ruleset protection. The verifier
does not create, sign, repair, or infer any of those external records.

Only after a real external package passes that verifier may a separately
reviewed change consider restoring `contents: write` or any Release mutation
API. The current Safe Gate enforces both the verifier wiring and the fail-only,
private-candidate boundary described above; it does not treat verifier source or
tests as audit evidence.

The current public adversarial corpus is development-only v13 evidence under
`round9-public-adversarial-corpus/v13`. The original v8 manifest remains frozen
byte-for-byte as superseded invalid evidence at 105,299 bytes with SHA-256
`5def53300bad07c65717ed8f8a32d2da49952528275df77ea55703713f9e330f`.
The rejected attempt to rebind corrected bytes to the same v8 identity is also
retained separately at 105,298 bytes with SHA-256
`2f953da42d3bb485b08562e4011f20fdeae6ebe76be02da31c27bb3b151e727d`.
The corrected corpus was admitted only under the new v9 dataset/schema; its
manifest is exactly 105,888 bytes with SHA-256
`dd22068b452cb4183405bfe7697d52a1b7dd272de25ebef0790add46a71c9c38`.
V9 remains frozen byte-for-byte as valid history. V10, v11, and v12 remain valid
immutable history. V11 records the later Codex-X default-head advance,
separates Git
repository archive entries from GitHub Release asset entries, and records five
active non-default branches without treating them as formal payload sources.
Its manifest is exactly 476,165 bytes with SHA-256
`297c01072eb8bea3c6102b957c741722e621860c1116b65450b68a8704e75038`.
V12 records the later MDX default-head advance from
`334f8cd2ec132aa4317b62bd2a3228ed827cbb87` to
`cccbfae8a75c948bde22407dd07de7af88731d9b`. Its eight changed-or-added
files are classified as documentation, workflow configuration, maintenance
source, or test source; no standalone prompt payload changed. The v12 manifest
is exactly 485,221 bytes with SHA-256
`eb72fd7b88c052c6af98c97636c18aba96f499597741bcba262dda59de3c2387`.
V13 records the subsequent MDX default-head advance from
`cccbfae8a75c948bde22407dd07de7af88731d9b` to
`61feb6a1940bd1d58163c2550869a0a9aed2ddc1`. Five changed-or-added Star
History data/source/workflow/test files are classified as non-payload material;
two removed source paths are recorded path-only. The v13 manifest is exactly
481,448 bytes with SHA-256
`91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6`.
It binds 24 payload records, 23 formal unique payloads (eight historical, one
branch-head, and fourteen current prompt-like), one unmerged candidate carrier
with one execution and zero `NOT_PROVIDED`, five behind non-default branch
candidates, 16 reviewed historical Release assets of which four contain prompt
entries, and 199 GitHub Release asset metadata/digest records. No binary Release
asset was downloaded or opened. It retains 24 scenario-payload executions and 120 serialized context
routes. Direct-current-user ground truth remains split 12 block and 12
allow/audit. Ground truth is enforced by the validator rather than inferred
from candidate output. No third-party repository code is executed, and this
visible corpus is not an independent holdout.

Neither internal gates, development-corpus results, counted-Mock evidence, nor a
public RC authorizes production Balanced mode. Until the protected Host run and
an exact-candidate independent audit are both supplied and mechanically bound,
the only valid overall conclusion is:

```text
BLOCKED / NOT PROVIDED / REQUIRES INDEPENDENT AUDIT
```

## Historical Round 8 read-only policy record

The legacy values and prose below are retained as the fail-only Round 8
release-document regression contract. Every key is explicitly historical so it
cannot be mistaken for the active lane. They describe the historical
`v0.16-rc.2` lane in its own then-current tense. They are not an active candidate
definition, may not satisfy a Round 9 gate, and must never be used to overwrite,
repair, relabel, or republish an existing Round 8 tag, Release, attestation, SO,
checksum, manifest, or Host evidence asset.

```text
historical_round8_release_version: 0.16
historical_round8_formal_tag: v0.16
historical_round8_version_alias_policy: reject-v0.16.0
historical_round8_platform: linux-amd64
historical_round8_local_rc_artifact_version: 0.16-rc.2
historical_round8_local_rc_artifact_scope: two-stage-linux-amd64-private-candidate-or-prerelease
historical_round8_local_rc_evidence_policy: phase1-no-host-evidence-phase2-strict-counted-mock-evidence
historical_round8_v016_candidate_workflow_status: NOT_MIGRATED/NOT_AVAILABLE
historical_round8_v016_rc_workflow_status: ACTIVE/PRERELEASE_ONLY/NO_PRODUCTION_APPROVAL
historical_round8_v016_formal_workflow_status: NOT_MIGRATED/NOT_AVAILABLE
historical_round8_v016_promotion_workflow_status: NOT_MIGRATED/NOT_AVAILABLE
historical_round8_candidate_workflow: .github/workflows/candidate.yml
historical_round8_candidate_attestation: candidate-manifest.json
historical_round8_attested_prerelease_workflow: .github/workflows/attested-prerelease.yml
historical_round8_rc_workflow: .github/workflows/release-rc.yml
historical_round8_rc_workflow_archive: docs/archive/workflows/release-rc-v0.15-rc.2.yml
historical_round8_rc_artifact_version: 0.16-rc.2
historical_round8_rc_artifact_history: active-v0.16-rc2-prerelease-only
historical_round8_rc_status: two-stage-private-candidate-or-counted-mock-verified-prerelease-independent-audit-required-production-not-approved
historical_round8_rc_manifest_schema: 4
historical_round8_rc_build_metadata_schema: 4
historical_round8_rc_builder_reference: docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b
historical_round8_rc_runner_label: ubuntu-24.04
historical_round8_rc_runner_os_arch_environment: Linux/X64/github-hosted
historical_round8_rc_runner_image_identity: UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER
historical_round8_rc_candidate_asset_count: 17
historical_round8_rc_publish_asset_count: 19
historical_round8_rc_publish_host_evidence: round8-host-evidence.json
historical_round8_rc_publish_host_evidence_sidecar: round8-host-evidence.json.sha256
historical_round8_host_audit_attestation: round6-prerelease-attestation.json
historical_round8_formal_gate_attestation: formal-release-attestation.json
historical_round8_promotion_workflow: .github/workflows/release-promote.yml
historical_round8_v015_stable_release: PUBLISHED_MANUALLY/2026-07-20/TEN_ASSETS
historical_round8_v015_independent_attestation: NOT_ATTACHED
historical_round8_host_matrix: v7.2.95
historical_round8_host_matrix_commit: f71ec0eb6776854457892452cf28c47f0d658251
historical_round8_candidate_manifest_schema: 3
historical_round8_host_attestation_schema: 2
historical_round8_host_evidence_fields: schema_version,validation_scope,candidate,cpa,mock,safety
historical_round8_upstream_version_policy: no-automatic-follow
historical_round8_independent_audit_status: required-not-provided
historical_round8_production_approval_status: not-granted
historical_round8_stable_v0.16_status: not-released
historical_round8_external_admission: required
historical_round8_minimum_independent_evaluation: evaluation-v11
historical_round8_independent_evaluation_required_status: CONSUMED/PASS
historical_round8_evaluation_v10_policy: immutable-consumed-fail-not-formal-input
historical_round8_formal_bundle_content_policy: exclude-evaluation-holdout-consumed-private-blind-retired
```

The `historical_round8_release_version`, `historical_round8_formal_tag`, and
`historical_round8_local_rc_*` keys record the former v0.16 source and
`v0.16-rc.2` prerelease target. The historical Round 8 RC workflow was
Linux amd64 only and requires an annotated exact-main tag, successful exact-main
CI, complete internal gates, reproducible assets, and the fixed CPA v7.2.95
source contract. It has two explicit stages. The build job records its
`runner.os`, `runner.arch`, and `runner.environment` context and requires the
declared `ubuntu-24.04` label. Ephemeral `runner.name` and release-workflow
run/attempt identifiers are intentionally represented by stable
`UNRECORDED_EPHEMERAL_*` sentinels so independently repeated builds can produce
the same bytes without pretending that those ephemeral values were observed in
the artifact identity. A pinned job container cannot
reliably observe the host runner image's `ImageOS` or `ImageVersion`, so both
metadata fields intentionally contain
`UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER`; the immutable builder reference above,
not a fabricated host-image version, is the compiler-environment identity.

With `publish_rc_release=false`, all four top-level protected-Host inputs must be
empty. `host_run` binds the positive Host run ID and attempt as
`RUN_ID:RUN_ATTEMPT`; the remaining Host inputs bind the artifact ID, artifact
digest, and one-time challenge. The workflow
reproduces exactly 17 final assets, uploads them as a private Actions artifact
for Host testing, and cannot create or modify a GitHub Release. The manifest
records Host and counted-Mock validation as `NOT_RUN / HOST_TEST_REQUIRED`.

The only publication-admissible Host evidence is schema v2 produced by
`round8-host-validation.yml` on the protected self-hosted Linux x64
`cag-round8-sandbox` runner. That workflow downloads the exact Phase 1 artifact
by run/attempt and artifact ID/digest, verifies every Phase 1 GitHub attestation,
checks the protected daemon ID, sandbox/production labels, immutable probe image,
and bind-mount nonce locality challenge, then signs exactly the canonical Host
JSON and sidecar with GitHub artifact attestation.

With `publish_rc_release=true`, the release workflow requires the exact
successful Host run ID/attempt, Host artifact ID/digest, and the same one-time
64-hex challenge. It fetches the two-file Host artifact directly from GitHub and
rejects it before download unless GitHub reports a positive integral
`size_in_bytes` no larger than 1 MiB. After download, the compressed byte count
must equal that API value and remain within the same cap. A bounded Python ZIP
reader then requires exactly two unique, top-level expected regular files,
rejects directories, links, path traversal, encryption, unreviewed compression,
and per-entry or aggregate expansion beyond the reviewed limits, and writes the
files without overwrite semantics. No generic `unzip` extraction is permitted.
The workflow then verifies the signer workflow, signer commit, source ref/commit,
Host run identity, Phase 1 artifact binding, protected runner identity, and exact
nested execution schema. The evidence must bind the exact tag, commit, tree, Linux amd64 SO
SHA-256, the CPA v7.2.95 primary identity, and counted-Mock `PASS` for that
single target. It must also contain the fixed safety
assertions that no real Provider was contacted, production was not accessed,
unexpected restart count is zero, OOM is false, and panic/fatal/plugin error
counts are all zero. The primary CPA result must additionally provide the closed
numeric/boolean matrix:
Chat and Responses benign/malicious upstream deltas `1/0`, 42 benign cases all
passed, 42 paired malicious cases all blocked, stream/nonstream plus
audit/balanced/strict coverage, SQLite quick-check/WAL success, and a restart
cycle with zero unexpected restarts. It also locks Balanced-incomplete allow,
Strict-incomplete block, usage-queue allow/blocked deltas, and Raw Capture
only-blocked, TTL dedup, schema-v3 redaction metadata, and purge/WAL results.
A bare `counted_mock_validation=PASS` is not sufficient. JSON scalar types are
exact: count fields are integers and cannot be replaced by booleans or
floating-point lookalikes. Extra fields in `execution`, `workflow`, `phase1`,
`runner`, or `sandbox` fail closed. The evidence and sidecar are included in both clean-clone builds,
`checksums.txt`, the audit bundle, manifest, transfer artifact, and the exact
19-asset Release allowlist. Only this stage may publish, and the result must be
`prerelease=true` and non-latest; the stable latest release must remain exactly
`v0.15`.

This workflow design does not itself create its trust root. Repository
administrators must configure protected `round8-host-validation` and
`round8-rc-publication` environments, required reviewers, disabled self-review
and admin bypass, exact deployment policies, the dedicated runner, and the three
protected sandbox identity variables. Until those external controls are present,
the RC publication path is not authorized. GitHub-attested counted-Mock evidence
is still not real-Provider validation, production validation, an independent
audit, or stable-release approval.

If the exact `v0.16-rc.2` Release becomes public (`draft=false`) before the
publishing job records its terminal verification, **Re-run failed jobs** on that
same workflow run can reuse the exact 19-file transfer artifact and enter the
existing fail-only, no-mutation verification branch. A new dispatch or
**Re-run all jobs** reruns admission instead. Admission emits
`already_public=true`; the write-capable build and publish jobs are skipped
before their setup, cache, provenance generation, or artifact upload, and the
separate `verify_published` job runs with only `actions: read`,
`attestations: read`, and `contents: read`. That verifier uses the same pinned
builder container, restricted checkout, and complete Linux gate sequence, but
sets `setup-go` to `cache:false` and has no artifact- or attestation-write step.

Both read-only paths verify the Release/tag/annotated-tag target/exact commit,
canonical title and body, `draft=false`, `immutable=true`, `prerelease=true`,
and non-latest state, and reconfirm that latest remains exactly `v0.15`. The
dedicated public verifier downloads exactly the 19 existing Release assets,
checks every GitHub SHA-256 digest, checksum sidecar, manifest-bound hash,
canonical timing-free test summary, and signed build attestation. In both the
publication transfer and read-only public verifier, each of the 17 ordinary
assets must be attested by the exact `release-rc.yml` signer workflow at the
exact tag and commit; the two Host evidence assets must separately verify the
exact protected `round8-host-validation.yml` signer at that same tag and commit.
Repository-only attestation verification is not sufficient. The verifier then rebuilds
the exact 19-asset publish candidate from the annotated tag and byte-compares
every local artifact with the downloaded public artifact. It does not upload
replacement bytes or mutate remote state. Any mismatch is fail-only and
requires manual investigation rather than repair.

```text
historical_round8_immutable_published_rc_identity_verification: release-object,tag=v0.16-rc.2,annotated-tag-target=exact-commit,target-commitish=exact-commit,title=exact,body=exact,prerelease=true,latest=false,draft=false,immutable=true
historical_round8_immutable_published_rc_asset_verification: exact-count=19,download-count=19,byte-compare-each=rebuilt-candidate,release-digest-and-attestation-check=each
historical_round8_immutable_published_rc_recovery: same-run-re-run-failed-or-admission-read-only-verifier
historical_round8_immutable_published_rc_new_dispatch_or_rerun_all: admission-already-public-skip-write-capable-build-and-publish
historical_round8_immutable_published_rc_recovery_access_policy: read-only-no-state-mutation
historical_round8_immutable_published_rc_forbidden_mutations: release-create,release-edit,release-upload,release-delete,artifact-upload,attestation-write,cache-write
historical_round8_immutable_published_rc_latest_release: v0.15
historical_round8_immutable_published_rc_mismatch_policy: fail-only-no-automatic-repair
```

Counted-Mock Host evidence is not real Provider or production validation.
Manifest schema 4 keeps both independent audit and independent evaluation at
`NOT_PROVIDED` with requirement `required`; production authorization and a
stable `v0.16` release remain absent.

The earlier local `v0.16-rc.1` package and its failed exact-main CI are
historical incident evidence only. They cannot satisfy any `v0.16-rc.2` gate,
and no old artifact may be overwritten or silently relabeled.

The candidate, attested-prerelease, formal, and promotion workflows still
describe the historical v0.15 chain. Only `release-rc.yml` has been migrated to
the v0.16-rc.2 prerelease lane. No stable-v0.16 workflow is admitted by this
policy.

## Historical v0.15 workflow record

The candidate workflow creates a private, untagged, clean `0.15` SO and CPA
Store ZIP bound to an exact commit and tree. The Host and independent-audit
workflow may later attach an external attestation to an annotated development
tag at the same commit. The formal `v0.15` workflow rebuilds and byte-compares
the Host-tested SO and Store ZIP, creates a draft, and the separate promotion
workflow publishes that unchanged draft only after another protected approval.

The historical `v0.15-rc.4` workflow is a Linux-only side lane. It requires an
annotated tag at the exact `main` tip, a successful exact-main push CI, the
complete internal Linux gate set, its then-pinned CPA source contract, RC-versioned
integration, two independent clean-clone rebuilds, and byte verification of a
17-asset formal-structure package. Its evidence and manifest explicitly state
`RC_INTERNAL_GATES_PASS / SANDBOX_ONLY / SERVER_VALIDATION_REQUIRED /
NOT_FORMAL / NOT_ROUND6_CANDIDATE`; real CPA Host validation, independent audit,
and independent evaluation remain absent.

The later `v0.15` stable Release was published manually on 2026-07-20 with ten
assets. Its Release Notes disclose the GitHub Billing limitation, manual build,
and owner-reported production sandbox result. That publication did not complete
the protected draft/promotion chain and does not supply independent Host,
audit, or evaluation attestation.

The archived `v0.15-rc.2` workflow remains immutable historical evidence. Its
recorded attempts failed; the public RC2 assets were published separately
through the disclosed direct owner override. The protected `v0.15-rc.3` tag
records failed workflow run 29728286559: admission passed, build failed before
packaging, publish was skipped, and no Actions artifact or GitHub Release was
created. RC2, RC3, and RC4 assets are never
accepted as the private Round 6 candidate, external Host/audit/evaluation
evidence, or formal `v0.15` input.

The consumed v10 evaluation remains historical FAIL evidence. It is never
rerun, upgraded, or treated as a formal-build input. A release candidate needs
a separately authored, previously unseen v11-or-later evaluation whose
low-sensitivity report is bound by SHA-256 in the Host/audit prerelease
attestation. Raw evaluation, holdout, consumed, private, blind, and retired
materials are not copied into formal source or audit bundles.

`0.16` is the current source version and `v0.16-rc.4` is the only admitted
Round 9 publication target. A stable `v0.16` has not been approved or
released. If a future independent process admits it, the project version remains
two-component and must not publish a `v0.16.0` alias. The historical v0.15
workflow record above retains its original identity and does not become a
v0.16 release path.
