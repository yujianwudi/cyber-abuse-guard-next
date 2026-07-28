# Archived GitHub Actions evidence

YAML files in this directory are historical source snapshots, not executable
GitHub Actions entrypoints. GitHub executes repository workflows only from
`.github/workflows/`.

| Snapshot | Historical role | Current status |
|---|---|---|
| `candidate-v0.15.yml` | Private v0.15 candidate builder | Archived; never run in this repository |
| `attested-prerelease-v0.15.yml` | Blocked v0.15 attested prerelease lane | Archived; never run in this repository |
| `release-v0.15.yml` | v0.15 draft Release builder | Archived; never run in this repository |
| `release-promote-v0.15.yml` | v0.15 draft promotion lane | Archived; never run in this repository |
| `release-rc-v0.15-rc.2.yml` | Original failed v0.15-rc.2 publication definition | Previously archived; immutable historical evidence |
| `release-rc-v0.16-rc.2.yml` | Round 8 RC lane | Archived after being repository-disabled |
| `round8-host-validation-v0.16-rc.2.yml` | Round 8 protected Host lane | Archived after being repository-disabled |
| `round9-release-rc-v0.16-rc.4.yml` | Round 9 private-candidate and blocked-publication design | Archived; its only recorded dispatch failed before asset construction |
| `round9-host-validation-v0.16-rc.4.yml` | Round 9 protected Host evaluation design | Archived without a recorded repository run |

The snapshots retain original workflow names, signer paths, tag identities, and
fail-closed validation text so old attestations and regression tests remain
auditable. They must not be copied back into `.github/workflows/` or treated as
current execution, deployment, production, or publication authorization.

The executable inventory is intentionally small and documented in
[`.github/workflows/README.md`](../../../.github/workflows/README.md).
