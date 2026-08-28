# Documentation index

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: f98ee38cea5b38b60130b98bd3ca6100cb6aeeee223128311235469af40ec9e3
```

The root [English README](../README.md) and [Chinese README](../README_CN.md)
are the shortest current-status entry points. The previously documented old
repository and `v0.15` Release both returned GitHub API `404` on 2026-08-04;
legacy availability is `UNAVAILABLE` and security support is `SUSPENDED`.
The current project target is source `1.0.0` and planned prerelease
`v1.0.0-rc.3`, pinned to CPA v7.2.144 at
`d36b776c790a4d58027fd4fb434800fb5334bceb`; C ABI 1 and RPC schema 4 are the
active contract. The module sum is
`h1:ZNLmwkaMZ+4KbR8BqLHUUDdDzWsQKpXZQbLYesh4ttk=` and the go.mod sum is
`h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=`. The upstream Linux amd64
archive SHA-256 is
`02be1ad96791f1d2b7e6574bb0f68a3d75622e42cba07fecd012e575ba4b2a96`
(21,223,927 bytes); its
binary SHA-256 is
`eef73e578f5d272173aadcdf52137390363cd7e4bf0da8651d4c0acd3c0c4f09`.
The active workflow directory contains exactly four repository workflows:
`ci.yml`, `codeql.yml`, `policy-gate.yml`, and the gated `release-rc.yml`.
GitHub-owned Dependabot `dynamic/` entries are separately bounded by an exact
platform allowlist and are not repository YAML files. RC publication is allowed
only after every applicable Round 16 acceptance gate passes; before
that point tags, prereleases, GitHub Releases, provenance attestations, and
release-asset uploads remain forbidden.
Owner-run server diagnostics are not independent evidence; production approval
and release readiness are `NOT_PROVIDED`, and no stable `v0.16` exists.

Commit `21267e742b624b29a75bd3683fd6914f76c764b5` is a confirmed green
historical v7.2.116 engineering baseline. The supplied v7.2.116 second-machine
report and any five-repository data are historical diagnostic evidence only;
they do not transfer to v7.2.144/schema 4. Round 15 v7.2.142/schema 3 results
also retain their old identity and transfer no PASS. The exact Round 16
candidate still requires its own second-machine execution. The current feature branch also requires
its own PR checks. Engineering CI validates source and development artifacts
only; it does not establish a protected Host, independent-audit, release, or
production PASS.

CPA v7.2.144 Multi-Agent v2 rewrites `/v1/responses` tool definitions before
`RequestInterceptor`. The active lane therefore requires a new regression for
the rewritten tool-schema/tool-payload boundary; no v7.2.116 report may be
relabelled to satisfy it. Documents under `docs/reports/` retain their recorded
point-in-time identities and are historical whenever they describe v7.2.116.

All `/v1/realtime*` routes currently bypass CAG `RequestInterceptor`,
`ModelRouter`, and request lifecycle. They are **OUT_OF_SCOPE / UNPROTECTED /
CAG_NOT_VISIBLE**. Only registered callback paths such as chat and Responses
are protected; there is no all-traffic coverage claim.

This cleanup adds navigation without relocating frozen evaluation or Holdout
evidence. Those files keep their existing paths so historical hashes and
references remain stable.

## Current Round 16 navigation

- [Active Round 16 status and evidence boundary](ROUND16_STATUS.md)
- [Active CPA v7.2.144 / RPC schema 4 task book](ROUND16_CPA_V7_2_144_TASK_BOOK.md)
- [Blocked-request review capture operator guide](RAW_CAPTURE.md)
- [Release policy](RELEASE_POLICY.md)

## Superseded historical Round 13 navigation

- [Round 13 status and evidence boundary](ROUND13_STATUS.md)
- [Round 13 CPA v7.2.125 / v1.0.0-rc.1 task book](ROUND13_CPA_V7_2_125_V1_RC1_TASK_BOOK.md)
- [Blocked-request review capture operator guide](RAW_CAPTURE.md)
- [Release policy](RELEASE_POLICY.md)
- [Active CPA integration overlay plus frozen history](reports/CPA_INTEGRATION.md)
- [Active test overlay plus frozen history](reports/TEST_REPORT.md)
- [Active release overlay plus frozen history](reports/RELEASE_EVIDENCE.md)

## Historical v0.16 navigation

The following entries preserve the Round 12 and earlier point-in-time identity;
they do not define the active v7.2.144 implementation:

- [Historical Round 12 v7.2.124 status and evidence boundary](ROUND12_STATUS.md)
- [Historical Round 12 v7.2.124 production-hardening task book](ROUND12_PRODUCTION_HARDENING_TASK_BOOK.md)
- [Historical Round 12 GitHub governance read-only snapshot](reports/ROUND12_GITHUB_GOVERNANCE_SNAPSHOT.md)
- [Round 9 execution record and traceability matrix](reports/ROUND9_EXECUTION_RECORD.md)
- [Round 9 audit schema v6](ROUND9_AUDIT_SCHEMA_V6.md)
- [Round 9 Linux old-SO rollback gate](ROUND9_OLD_SO_ROLLBACK_GATE.md)
- [Round 9 operator-owned rollout and rollback](ROUND9_OPERATOR_ROLLOUT.md)
- [Round 11 runtime-assurance task book](ROUND11_RUNTIME_ASSURANCE_TASK_BOOK.md)
- [Historical performance evidence and v0.16 acceptance table](reports/PERFORMANCE.md)

Round 8 readiness, calibration, and Host documents are immutable historical
regression evidence. They do not define the active Round 16 boundary:

- [Historical Round 8 v0.16-rc.2 release readiness](reports/ROUND8_RELEASE_READINESS.md)
- [Historical Round 8 synthetic score calibration](reports/ROUND8_CALIBRATION.md)
- [Historical Round 8 Linux Host contract](ROUND8_HOST_RUNNER.md)

The local package manifest and checksums are delivery artifacts under the
ignored local `dist/` path, not tracked documentation and not GitHub release
evidence.

## Historical, non-executable Round 9 workflow designs

These documents preserve contracts for the deleted
`round9-host-validation.yml` and `round9-release-rc.yml` workflows. They are
historical design records, not current Actions entry points, gates, runbooks, or
evidence that Host or independent-audit execution occurred:

- [Historical, non-executable Round 9 Host runner design](ROUND9_HOST_RUNNER.md)
- [Historical, non-executable Round 9 independent-audit design](ROUND9_INDEPENDENT_AUDIT_CONTRACT.md)

## Architecture and security model

- [Design](DESIGN.md)
- [Threat model](THREAT_MODEL.md)
- [Rule system](RULES.md)
- [Round 6 streaming scanner design](ROUND6_STREAMING_SCANNER_DESIGN.md)

## Operations and configuration

- [Docker installation, rollout, rollback, and cleanup](INSTALL_DOCKER.md)
- [Round 9 operator-owned rollout and rollback](ROUND9_OPERATOR_ROLLOUT.md)
- [Blocked-request review capture](RAW_CAPTURE.md)
- [General known limitations](LIMITATIONS.md)
- [Round 6 configuration migration](ROUND6_CONFIG_MIGRATION.md)
- [Round 6 limitations and blockers](ROUND6_LIMITATIONS.md)

## Release policy and workflow boundaries

- [Release admission policy](RELEASE_POLICY.md)
- [Round 6 CI, candidate, and release gate](ROUND6_RELEASE_GATE.md)
- [Repository governance and desired `main` protection](REPOSITORY_GOVERNANCE.md)
- [Contribution guide](../CONTRIBUTING.md)
- [Security policy](../SECURITY.md)

The repository-governance document records the expected GitHub settings and
the commands used to verify them. Its snapshot is not a substitute for a fresh
read-only API check after workflow or branch-protection changes.

Current GitHub Actions entry points are intentionally limited to:

- `.github/workflows/ci.yml` for Linux verification, CPA compatibility,
  development artifacts, and reproducibility;
- `.github/workflows/codeql.yml` for minimal-permission Linux Go static
  analysis within the reviewed sparse source boundary;
- `.github/workflows/policy-gate.yml` for benign/malicious policy, corpus,
  performance, and bounded-fuzz acceptance;
- `.github/workflows/release-rc.yml` for manual, fail-closed RC admission and
  publication only after every applicable acceptance gate passes.

CodeQL creates code-scanning evidence only. The RC lane is the sole workflow
that may publish a prerelease, create its signed tag and provenance, or upload
release assets, and only after its complete admission contract succeeds. None
uses a self-hosted runner. Retired Round 8, Host, formal-release, and promotion
definitions remain recoverable from Git history.

The retired attempted `v0.15-rc.2` workflow definition is archived under
[`archive/workflows/`](archive/workflows/) and cannot be dispatched by GitHub
Actions. Its recorded runs failed and did not produce the public RC, which was
published separately through the disclosed direct owner override. It remains
historical evidence and is separate from the retired v0.16-rc.4 design recorded
in the historical release-policy documents.

The protected `v0.15-rc.3` tag is separate failed evidence. Workflow run
29728286559 passed admission, failed before packaging, published no Actions
artifact, and created no GitHub Release. It is not moved or reused by RC4.

## Historical v0.15 / Round 6 handoff

- [Independent-audit handoff](AUDIT_HANDOFF.md)
- [Round 6 development handoff](ROUND6_DEVELOPMENT_HANDOFF.md)

These handoff documents contain point-in-time evidence. They remain at their
original paths for audit continuity and must not be read as current v0.16
release evidence. Use the root READMEs plus `DESIGN.md`, `LIMITATIONS.md`, and
the operator guides above for the active state.

## Engineering and historical evidence reports

Project baselines and engineering evidence:

- [Classifier redesign baseline](reports/CLASSIFIER_REDESIGN_BASELINE.md)
- [Regression corpus report](reports/CORPUS_REPORT.md)
- [Active v7.2.144 CPA integration overlay plus frozen history](reports/CPA_INTEGRATION.md)
- [CPA packaging and contract baseline](reports/PHASE0_CPA_CONTRACT.md)
- [Performance report and v0.16 acceptance table](reports/PERFORMANCE.md)
- [Privacy report](reports/PRIVACY.md)
- [Prompt-injection defensive review](reports/PROMPT_INJECTION_REVIEW.md)
- [Public jailbreak repository review](reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md)
- [Release evidence](reports/RELEASE_EVIDENCE.md) — active v7.2.144 boundary
  plus retained historical records
- [Test report](reports/TEST_REPORT.md) — active v7.2.144 boundary plus retained
  historical records

Frozen evaluation reports:

- [Evaluation v4](reports/EVALUATION_V4_REPORT.md)
- [Evaluation v5](reports/EVALUATION_V5_REPORT.md)
- [Evaluation v6](reports/EVALUATION_V6_REPORT.md)
- [Evaluation v7](reports/EVALUATION_V7_REPORT.md)
- [Evaluation v8](reports/EVALUATION_V8_REPORT.md)
- [Evaluation v9](reports/EVALUATION_V9_REPORT.md)
- [Evaluation v10](reports/EVALUATION_V10_REPORT.md)

Retired or historical Holdout reports:

- [Holdout v1](reports/HOLDOUT_REPORT.md)
- [Holdout v2](reports/HOLDOUT_V2_REPORT.md)
- [Holdout v3](reports/HOLDOUT_V3_REPORT.md)

## Archive

- [Retired workflow evidence](archive/workflows/) - retained outside the
  executable GitHub Actions directory.

- [v0.1.2 next-version recommendations](archive/v0.1.2/NEXT_VERSION.md) —
  retained for historical context; it is not the current v0.15 roadmap.
