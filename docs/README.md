# Documentation index

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: e0cbc975c126a12649a1b8e309e4e2a95efc64e46346467771ecae61b3e14971
```

The root [English README](../README.md) and [Chinese README](../README_CN.md)
are the shortest current-status entry points. `v0.15` is the manually published
[historical stable release](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.15).
The active repository target is source verification on `main` with CPA
v7.2.104. Candidate, protected-Host, and publication workflows are archived and
not executable. External audit, deployment, production approval, and any future
release remain operator-owned; no stable `v0.16` exists.

Restricted evaluation and Holdout reports are absent from this repository by
the clean-history policy. Do not restore, link, or infer their contents from
public source history.

## Current v0.16 documents

Use these files for the current implementation and evidence state:

- [Blocked-request review capture operator guide](RAW_CAPTURE.md)
- [v0.16 release admission policy](RELEASE_POLICY.md)
- [Round 9 execution record and traceability matrix](reports/ROUND9_EXECUTION_RECORD.md)
- [Round 9 audit schema v6](ROUND9_AUDIT_SCHEMA_V6.md)
- [Round 9 Linux old-SO rollback gate](ROUND9_OLD_SO_ROLLBACK_GATE.md)
- [Round 9 exact-candidate independent-audit verifier contract](ROUND9_INDEPENDENT_AUDIT_CONTRACT.md)
- [Round 9 Linux Host runner and counted-Mock contract](ROUND9_HOST_RUNNER.md)
- [Round 9 operator-owned rollout and rollback](ROUND9_OPERATOR_ROLLOUT.md)
- [Current test status and exact-main CI failures](reports/TEST_REPORT.md)
- [Local-package and publication evidence](reports/RELEASE_EVIDENCE.md)
- [Historical performance evidence and v0.16 acceptance table](reports/PERFORMANCE.md)
- [Privacy boundary](reports/PRIVACY.md)
- [Repository security-support policy](../SECURITY.md)

Round 8 readiness, calibration, and Host documents are immutable historical
regression evidence. They do not define the active Round 9 candidate:

- [Historical Round 8 v0.16-rc.2 release readiness](reports/ROUND8_RELEASE_READINESS.md)
- [Historical Round 8 synthetic score calibration](reports/ROUND8_CALIBRATION.md)
- [Historical Round 8 Linux Host contract](ROUND8_HOST_RUNNER.md)

The local package manifest and checksums are delivery artifacts under the
ignored local `dist/` path, not tracked documentation and not GitHub release
evidence.

## Architecture and security model

- [Design](DESIGN.md)
- [Threat model](THREAT_MODEL.md)
- [Rule system](RULES.md)
- [Round 6 streaming scanner design](ROUND6_STREAMING_SCANNER_DESIGN.md)

## Operations and configuration

- [Docker installation, rollout, rollback, and cleanup](INSTALL_DOCKER.md)
- [Round 9 operator-owned rollout and rollback](ROUND9_OPERATOR_ROLLOUT.md)
- [Round 9 isolated counted-Mock Host runner](ROUND9_HOST_RUNNER.md)
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

The repository-governance document records desired GitHub settings, not proof
that they are already enabled. The `main` controls are applied and API-verified
only after the current hardening pull request and all named checks are green.

Current GitHub Actions entry points are intentionally limited to:

- `.github/workflows/ci.yml` for ordinary verification;
- `.github/workflows/codeql.yml` for minimal-permission Linux Go static
  analysis within the reviewed sparse source boundary;
- `.github/workflows/round9-gate.yml` for ordinary Round 9 policy/corpus
  verification without independent-corpus execution.

CodeQL creates code-scanning evidence only. It does not create package bytes or
authorize publication. Candidate, attestation, protected-Host, Round 8, RC,
formal-release, and promotion definitions are version-locked, non-executable
audit snapshots under [`archive/workflows/`](archive/workflows/). They do not
authorize deployment or publication.

The retired attempted `v0.15-rc.2` workflow definition is archived under
[`archive/workflows/`](archive/workflows/) and cannot be dispatched by GitHub
Actions. Its recorded runs failed and did not produce the public RC, which was
published separately through the disclosed direct owner override. It remains
historical evidence and is separate from the active engineering gates.

The protected `v0.15-rc.3` tag is separate failed evidence. Workflow run
29728286559 passed admission, failed before packaging, published no Actions
artifact, and created no GitHub Release. It is not moved or reused by RC4.

## Historical v0.15 / Round 6 handoff

- [Independent-audit handoff](AUDIT_HANDOFF.md)
- [Round 6 development handoff](ROUND6_DEVELOPMENT_HANDOFF.md)

These handoff documents contain point-in-time evidence. They remain at their
original paths for audit continuity and must not be read as current v0.16
release evidence. Use the root READMEs and the current-document list above for
the active state.

## Engineering and historical evidence reports

Project baselines and engineering evidence:

- [Classifier redesign baseline](reports/CLASSIFIER_REDESIGN_BASELINE.md)
- [Regression corpus report](reports/CORPUS_REPORT.md)
- [CPA integration report](reports/CPA_INTEGRATION.md)
- [CPA packaging and contract baseline](reports/PHASE0_CPA_CONTRACT.md)
- [Performance report and v0.16 acceptance table](reports/PERFORMANCE.md)
- [Privacy report](reports/PRIVACY.md)
- [Prompt-injection defensive review](reports/PROMPT_INJECTION_REVIEW.md)
- [Public jailbreak repository review](reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md)
- [Release evidence](reports/RELEASE_EVIDENCE.md) — current v0.16 section plus
  retained historical records
- [Test report](reports/TEST_REPORT.md) — current v0.16 section plus retained
  historical records

Restricted evaluation and Holdout reports (`EVALUATION_V4_REPORT.md` through
`EVALUATION_V10_REPORT.md`, plus `HOLDOUT_REPORT.md` through
`HOLDOUT_V3_REPORT.md`) are **ABSENT BY CLEAN-HISTORY POLICY**. Public aggregate
status belongs in the current reports above; restricted source material must
remain outside the repository.

## Archive

- [Retired workflow evidence](archive/workflows/) - retained outside the
  executable GitHub Actions directory.

- [v0.1.2 next-version recommendations](archive/v0.1.2/NEXT_VERSION.md) —
  retained for historical context; it is not the current v0.15 roadmap.
