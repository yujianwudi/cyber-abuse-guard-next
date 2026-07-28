# Round 6 v0.15 CI, candidate, and release gate

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: f9529ada85dee7e35267c70da54aa74e266e88b4ed2703924f352c2cb0cb4333
```

> **Frozen historical snapshot.** The classifier identity above is the
> repository's current Round 9 identity. The body below preserves the Round 6 /
> v0.15 release gate, including any CPA v7.2.95 wording such as "current real
> Host state"; those statements are historical only and are not the active
> repository release identity. The current formal CPA identity is
> `v7.2.103@cade44b9cdee6b9328ea2648fd119129fdf11e2d` (RPC schema 2).

Status: **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**.

The exact project version is `0.15`; the only formal tag is `v0.15`, never
`v0.15.0`. This document authorizes neither deployment nor publication. All
current execution evidence is Linux amd64-only. Windows, macOS, and musl/Alpine
are outside this round.

Historical v0.15 classifier policy identity is `classifier-policy-v5` /
`0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b`;
scanner identity is `streaming-scanner-v1`.

The release chain is deliberately ordered:

```text
final PR head + PR CI
  -> merge to main
  -> exact post-merge main push CI
  -> private untagged clean-candidate Actions artifact
  -> CPA v7.2.95 Host + Mock evidence
  -> independent source/artifact/Host audit
  -> candidate-bound external evaluation-v11+ CONSUMED / PASS
  -> optional annotated development prerelease
  -> annotated formal v0.15 tag and verified draft
  -> protected promotion of that unchanged draft
```

An isolated side lane may publish the annotated `v0.15-rc.4` Linux amd64
formal-structure package after exact-main CI and the complete internal Linux
gate set succeed. It emits exactly 17 assets: RC-versioned SO and Store ZIP,
audit bundle, source archive, SBOM, checksums, internal test summary, RC-only
evidence, and exact manifest with sidecars. Two independent clean-clone builds
must reproduce the 11 source-derived assets byte-for-byte before publication.
The lane is explicitly **not** the private Round 6 candidate or a formal-release
attestation. It does not alter, satisfy, or bypass the ordered formal chain
above. Real CPA Host validation remains pending in the owner's server sandbox.

The protected `v0.15-rc.3` tag remains immutable failed evidence. Workflow run
29728286559 passed admission, failed in the internal gate step before packaging,
skipped publish, uploaded no Actions artifact, and created no GitHub Release.
RC4 uses a new exact-main commit, tree, annotated tag object, CI run, workflow
run, and complete set of generated hashes.

Clean candidate bytes are still **unreleased**. A successful candidate build,
Host matrix, optional development prerelease, or ordinary CI run cannot convert
the historical v10 `CONSUMED / FAIL` into a release PASS. Evaluation-v10 cannot
be rerun and is never a formal-build input.

## Passed pre-version-migration checkpoint

Commit `21ceb57e6b6030e56d7820c9a67a8eecd068c669`, tree
`e55437442f30bdb1b6b748b9611c6760172784cd`, passed:

- push CI run [29578024185](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29578024185);
- PR CI run [29578025961](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29578025961).

This is a passed engineering checkpoint before the 0.15 version and candidate
release-chain migration. It is not the final v0.15 commit/tree, candidate
artifact, Host result, independent audit, tag, or Release evidence. Final v0.15
evidence must come from the later final PR head/PR CI, the resulting `main`
commit/tree, and that exact main commit's successful push CI.

The final PR head must have no unresolved, non-outdated actionable review
threads before merge. Automated review is advisory and is not an independent
audit.

## Ordinary CI

The public CI uses explicit Round 6 safe targets and a sparse source boundary.
It verifies named suites for:

- full-envelope and streaming extraction, including long JSON, chunk, Unicode,
  media, raw multipart, CPA-transformed multipart JSON, role, and budget cases;
- classifier overlap, boundary reconstruction, negation, role isolation,
  coverage, and bounded composition;
- Router/disposition and the Linux long-text ladder at 64 KiB, 255 KiB,
  256 KiB, 256 KiB + 1, 270 KiB, 512 KiB, 1 MiB, 4 MiB, and near the
  effective RPC limit;
- management status, audit privacy, and legacy `max_scan_bytes` migration;
- source/compile compatibility with the fixed CPA v7.2.95 release target.

The safety checker inspects the reachable Make/script graph. Ordinary Round 6
entrypoints must not reach formal release, consumed evaluation, Holdout, or
unreviewed dynamic Make/shell paths. Consumed evaluation/Holdout gate tests
remain isolated behind the `consumed_evaluation` build tag. Broad `go test ./...`
or `go vet ./...` is not an accepted substitute for the allowlist.

The final PR head must pass PR CI and then be merged to `main`. The resulting
exact main commit must have a completed successful `push` run of
`.github/workflows/ci.yml` whose `head_sha` is the candidate commit. PR CI is a
prerequisite but cannot substitute for post-merge main push CI; neither can the
earlier `21ceb57` checkpoint.

## Private untagged clean candidate

`.github/workflows/candidate.yml` is the only authorized candidate-byte
producer. A `workflow_dispatch` workflow is callable only after it exists on the
default branch, so the final PR must already be merged. It is manual-only and
runs on `ubuntu-24.04`. Admission requires:

- the exact 40-character candidate commit and tree;
- the run ID of the successful exact post-merge `main` push CI run;
- dispatch from `refs/heads/main` at that exact commit/tree;
- an explicit authorization boolean;
- absence of the formal tag `v0.15`.

The workflow checks out the exact `main` commit without persisted credentials, applies
the restricted-data gate, rechecks source identity and CPA compatibility, and
builds with candidate mode rather than `ALLOW_DIRTY_BUILD=1`. Candidate mode
requires a clean worktree, exact commit/tree, the commit timestamp, and forbids
formal-release operations. Two clean clones must reproduce the same bytes.

The private Actions artifact is named for the exact commit and contains:

```text
cyber-abuse-guard-v0.15.so
cyber-abuse-guard-v0.15.so.sha256
cyber-abuse-guard_0.15_linux_amd64.zip
build-metadata.json
checksums.txt
ruleset-manifest.json
ruleset.sha256
sbom.cdx.json
candidate-manifest.json
```

`candidate-manifest.json` binds version `0.15`, commit, tree, commit timestamp,
repository, workflow/ref/SHA, run ID/attempt, SO SHA-256, Store ZIP SHA-256,
metadata hash, ruleset hash, and SBOM hash. Its status is
`UNRELEASED / HOST AND INDEPENDENT AUDIT REQUIRED`.

This artifact is private, expiring Actions evidence. It is not associated with a
tag or GitHub Release. The Store ZIP contains exactly one root `.so`. It does not
contain an audit bundle, source archive, evaluation/Holdout material, private
payloads, production requests, audit databases, credentials, or Provider data.

## Required Host and independent evidence

The candidate SO from the private Actions artifact must be tested in isolated
Linux amd64 CPA Hosts with a Mock upstream and no real auth pool or Provider:

| Target | Exact source identity | Current real Host state |
|---|---|---|
| CPA v7.2.95 | `f71ec0eb6776854457892452cf28c47f0d658251` | **NOT RUN / PENDING** |

Earlier v7.2.85/v7.2.84/v7.2.83/v7.2.82/v7.2.81 source/compile checks are historical engineering
context only. They are not current v0.15 Host or release requirements.

Each Host record and the independent audit must cite the same candidate commit,
tree, candidate workflow run ID, and Linux SO SHA-256. For every locally blocked
request, evidence must show zero before/after deltas at all four layers:

1. Auth Selector;
2. Provider execution;
3. usage accounting;
4. Mock-upstream requests.

The records must also cover Store install/load, registration, Router order,
executor readiness, stream/non-stream formats, privacy canaries, SQLite v3
migration/quick-check/rollback, and sandbox rollback. Source/compile contracts
do not substitute for this exact-artifact Host evidence.

The independent auditor must obtain and hash the records independently and
review the exact source and candidate bytes. A dispatcher-provided `PASS` value
or 64-character string is not proof by itself. Repository Environment review
must prohibit self-approval.

The same exact candidate must then receive an externally authored unseen
evaluation with identity `evaluation-v11` or later. It must be the candidate's
first-and-only consumed run and the low-sensitivity report must declare
`CONSUMED / PASS`. The prerelease admission accepts only the evaluation ID and
report SHA-256 as external fields; it does not check in or package the evaluation
corpus. Evaluation-v10 remains immutable `CONSUMED / FAIL`, is not rerun, and is
rejected as a formal input.

Protected reviewers must independently obtain that low-sensitivity report,
verify its exact-candidate binding, `evaluation-v11`-or-later identity,
first-and-only `CONSUMED / PASS` status, and SHA-256. Dispatcher fields alone do
not prove the evaluation gate.

These results are external attestation fields. The reusable source documents do
not hardcode future PASS hashes or claim that a future merge/tag/Release exists.
Stable v0.15 eligibility is decided only from the Round 6 candidate/Host/audit
attestations and the later formal-release attestation assets.

The neutral machine-readable source policy is
[RELEASE_POLICY.md](RELEASE_POLICY.md). The external decision assets are named
`round6-prerelease-attestation.json` and `formal-release-attestation.json`.

## Optional annotated development prerelease

An optional durable development handoff may be created only after the v7.2.95
Host record, the independent audit, and the candidate-bound external evaluation-v11+
`CONSUMED / PASS` attestation pass. It uses an existing annotated tag:

```text
v0.15-dev.round6
v0.15-dev.round6.N
```

`.github/workflows/attested-prerelease.yml` binds that tag to the exact
candidate `main` commit/tree, successful main push CI run, successful clean-candidate run,
candidate SO and Store ZIP SHA-256 values, the v7.2.95 Host-record hash, and
independent-audit hash.
It rebuilds the same clean exact-source bytes, proves reproducibility, and
rechecks the SO hash before and after Actions artifact transfer.

GitHub allows at most 25 top-level `workflow_dispatch` inputs. This repository
retains a stricter reviewed cap of 10, keeps this manual dispatcher at exactly
nine inputs, and carries the
Host, audit, and evaluation decisions and evidence in one required
`external_attestations_json` object. That object must contain exactly
`host_validation`, `host_evidence_sha256`, `independent_audit_validation`,
`independent_audit_sha256`, `independent_evaluation_validation`,
`independent_evaluation_id`, and `independent_evaluation_sha256`. Admission
requires every value to be a string, all three decisions to be `PASS`, both
evidence hashes and the evaluation hash to be lowercase SHA-256 values, and the
evaluation identity to be `evaluation-v11` or later.

The prerelease attaches schema-v2 `round6-prerelease-attestation.json` and its
SHA-256 sidecar. That external record binds the candidate workflow, source
identity, CPA Host identity and evidence through `cpa_version`, `cpa_commit`,
and `cpa_host_sha256`, independent-audit hash, candidate artifact hashes,
`independent_evaluation_id`, and `independent_evaluation_sha256`; the source tree
does not predeclare its future values.

The GitHub Environment `round6-independent-audit` must have required independent
reviewers with self-review disabled. Repository rules must prohibit development
tag modification and deletion without a participant bypass. YAML declarations
and peeled-tag checks narrow risk but do not replace repository settings.

If created, the GitHub Release must remain:

```text
draft: true
prerelease: true
latest: false
title/status: BLOCKED / NOT A FORMAL RELEASE
```

It is not production admission and does not authorize a real Provider, account
pool, production Host, or `observe -> balanced` change.

## Formal v0.15 tag and Release

The formal path is separate from candidate and development-prerelease paths. It
requires a clean source state at an annotated exact tag `v0.15`, completed Host
and independent evidence, final release documents, and the candidate-bound
external `evaluation-v11` or later first-and-only `CONSUMED / PASS` fields in
`round6-prerelease-attestation.json`. The historical v10 result stays
`CONSUMED / FAIL` and cannot be rerun, renamed, used for tuning, or passed into
the formal build.

Until that candidate-level external evaluation attestation exists, do not create `v0.15`
or invoke the formal release path. The formal workflow consumes exactly one
matching blocked development prerelease and its
`round6-prerelease-attestation.json`, rebuilds the SO and Store ZIP, and requires
byte identity with the Host-tested candidate. Formal artifacts add the audit
bundle, source archive, release test summary, and final release evidence to the
verified SO, Store ZIP, metadata, ruleset identity, and SBOM. It also emits
`formal-release-attestation.json` plus a SHA-256 sidecar and creates a draft
non-prerelease `v0.15` GitHub Release.

The formal source archive and audit bundle exclude evaluation, Holdout, private,
blind, and retired material. Only low-sensitivity evaluation identity/hash and
release-attestation records may cross the release boundary; no underlying
evaluation or Holdout payload is packaged.

`.github/workflows/release-promote.yml` is a separate protected step. It
reverifies the annotated tag, unchanged draft assets, both attestation files,
and candidate/formal byte bindings before publishing the existing draft as the
stable/latest v0.15 Release. Creating the formal draft is not publication.

## Safe commands and prohibited shortcuts

Repository-only checks that do not deploy a Host or open consumed evaluation
data include:

```bash
python3 -B scripts/round6_safe_gate_contract_test.py
python3 -B scripts/round6_safe_gate_contract.py --root .
make round6-regression
make round6-script-test
```

Do not locally deploy the plugin, start a real CPA Host, connect a real Provider,
run consumed v10, execute third-party jailbreak repositories, or locally create
candidate bytes. Candidate creation belongs only to the dedicated GitHub Actions
workflow; Host validation belongs only to the authorized Linux sandbox.
