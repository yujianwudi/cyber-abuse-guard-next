# GitHub Actions

This directory intentionally contains only the workflows required to validate
the current `main` branch. A workflow is executable by GitHub Actions only when
its YAML file is present here.

| File | Display name | Trigger | Responsibility |
|---|---|---|---|
| `ci.yml` | `CI` | Pushes and pull requests targeting `main` | Linux quality gates, CPA v7.2.125 compatibility, tests, fuzzing, candidate `.so` loading, development artifacts, and reproducibility |
| `codeql.yml` | `CodeQL` | Pushes and pull requests targeting `main`, weekly schedule, manual dispatch | Minimal-permission Go code scanning |
| `policy-gate.yml` | `Policy and Corpus Gate` | Pushes and pull requests targeting `main` | Benign/malicious policy, corpus, performance, and bounded-fuzz acceptance gates |
| `release-rc.yml` | `RC Release` | Manual dispatch from the existing annotated `v1.0.0-rc.1` tag | Admission against exact protected-main checks and staged owner evidence, byte-for-byte candidate sealing, provenance attestation, and non-latest prerelease publication |

`release-rc.yml` is the only active publication workflow. It is fixed to plugin
version `1.0.0`, tag `v1.0.0-rc.1`, CPA `v7.2.125`, and Linux amd64. It does
not generalize or reactivate any historical candidate, Host, promotion, Round 8,
or Round 9 release lane; those definitions remain non-executable and
recoverable from Git history.

## Fixed RC admission and publication

The workflow must be dispatched with the GitHub UI or API while the selected
ref is the existing annotated `v1.0.0-rc.1` tag. The only evidence coordinates
the operator supplies are the successful push-run IDs for `CI`, `CodeQL`, and
`Policy and Corpus Gate`, plus a numeric draft Release ID, numeric asset ID,
and lowercase SHA-256 for its fixed
`second-machine-release-admission.json` asset. The old status, report-hash,
commit, tree, and `.so` self-report strings are not inputs. The operator must
also explicitly enable `authorize_prerelease`.

Admission fails unless GitHub verifies the annotated tag signature, the tag
and workflow both resolve to the current protected `main` commit, the formal
`v1.0.0` tag is absent, no Release already uses the RC tag, and all five
protected-main check contexts succeeded on that exact commit:

- `quality-and-artifacts`
- `fuzz-long`
- `reproducibility`
- `Analyze Go on Linux`
- `round9-policy-and-corpus`

Repository-side branch protection remains the authority for `main`; the
workflow mechanically binds the Release to the exact successful runs rather
than attempting to mutate or replace branch protection.

The evidence draft uses tag name
`v1.0.0-rc.1-second-machine-admission`, remains `draft=true`, and targets the
same exact commit. GitHub API responses must prove that the fixed-name,
uploaded, size-bounded asset belongs to that Release and that its API digest
equals the dispatch SHA-256. The workflow downloads the actual bytes, recomputes
their SHA-256 and size, rejects the report after its fixed 24-hour validity
window, and runs the validator from the exact tag checkout. Status, commit,
tree, `.so`, CPA/corpus identities, all three semantic-mode summaries,
zero-false-positive/100%-malicious-recall results, side effects, cleanup, and
the current Host-performance gates are derived only from the closed report.
The status is `SECOND_MACHINE_OWNER_RELEASE_ADMISSION_PASS` only when those
details recompute to PASS.

The report is produced server-side only after the original path/inode-bound
machine evidence and Host-performance measurements pass their full validators.
It omits third-party text and is portable release admission, not a substitute
for the non-portable full bundle. This remains owner-run corroboration on a
second machine, not an independent audit or independent proof. This RC is not
a stable release or production approval.

The `CI` run must contain exactly one live artifact named
`cyber-abuse-guard-linux-amd64-audit-candidate`. Admission records its artifact
ID, API digest, size, retention expiry, and run ID. The seal job uses the
immutable-SHA `actions/download-artifact` action with that run ID, verifies the
exact nine-file set and every manifest/file hash, and reuses those bytes. It
does not invoke the Go compiler, regenerate metadata/SBOM, or rename the
audited binary. Source and binary version remain `1.0.0`; only the tag, source
archive, Release metadata, and release manifest carry artifact version
`1.0.0-rc.1`.

The exact assets before transfer are:

- the original `cyber-abuse-guard-v1.0.0.so` and its original SHA-256 sidecar
- the original `cyber-abuse-guard_1.0.0_linux_amd64.zip`
- the original `audit-candidate-manifest.json`
- the original `audit-candidate-checksums.txt`, `build-metadata.json`, ruleset
  files, and CycloneDX SBOM, all preserved byte-for-byte
- deterministic `cyber-abuse-guard_1.0.0-rc.1_linux_amd64.zip`, containing
  exactly one root `cyber-abuse-guard.so` whose payload equals the audited SO,
  plus CPA-facing `checksums.txt`
- the downloaded `second-machine-release-admission.json`
- `cyber-abuse-guard-v1.0.0-rc.1-source.tar.gz` and its SHA-256 sidecar
- `release-evidence.md`, `release-provenance.json`, `release-manifest.json`,
  and `release-checksums.txt`
- `release-attestation.intoto.jsonl`, copied from the signed GitHub attestation bundle

Publication is draft-first. The publish job verifies the transferred artifact
digest, exact 19-asset allowlist, every local checksum, and GitHub's signed SLSA
provenance for each of the 18 pre-attestation assets before a Release is
created. The attested release evidence/provenance/manifest bind both the CI
artifact ID/digest/size and second-machine draft Release/asset ID/digest/size.
The job then verifies every server-reported Release asset digest before changing
the draft to a prerelease. Both creation and publication set Latest to false,
and the job fails if the repository's Latest Release identity changes.

## Naming and governance

- Workflow filenames use short lowercase kebab-case names.
- Display names use concise title case and do not contain version or round
  identifiers unless the workflow is truly version-specific.
- Job IDs remain stable when they are required status-check contexts. In
  particular, `round9-policy-and-corpus` is retained as a compatibility context
  while the workflow itself uses the version-neutral `Policy and Corpus Gate`
  name.
- Active workflows have no implicit write permissions. CodeQL grants
  `security-events: write` only to its analysis job. The RC seal grants only
  `id-token: write` and `attestations: write`; only its final publication job
  grants `contents: write`.
- No active workflow uses a self-hosted runner. The fixed RC workflow is manual
  and tag-bound; it does not run on a floating release or tag pattern.

The expected required checks for `main` are documented in
[`docs/REPOSITORY_GOVERNANCE.md`](../../docs/REPOSITORY_GOVERNANCE.md).
