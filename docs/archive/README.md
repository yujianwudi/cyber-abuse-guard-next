# Archive index

This directory contains retired documentation and workflow definitions only. It
is not an executable entry point, is not included in the active release build,
and must not be used to infer a current compatibility or release result.

## Archived items

| Path | Reason for archival | Current replacement |
|---|---|---|
| `workflows/release-rc-v0.15-rc.2.yml` | Superseded RC workflow from an older release line | `.github/workflows/release-rc.yml` |
| `workflows/README.md` | Historical workflow inventory and cleanup record | `.github/workflows/README.md` |
| `v0.1.2/NEXT_VERSION.md` | Old planning note, not a build or runtime contract | `CHANGELOG.md` and the active Round 16 task book |

## Why the old tests remain outside this directory

The repository contains versioned `testdata/` fixtures and `*_test.go`/
`test_*.py` files that are still referenced by the Linux CI, rollback checks,
identity validators, evidence-boundary tests or release-document gates. They
are not disposable cache files: removing or moving one can make a historical
identity appear to pass under a different source tree. Such fixtures remain at
their canonical paths until a new contract version deliberately replaces them.

In particular, the following classes remain intentionally traceable:

- the active `round9-public-adversarial-v13` corpus and its v9-v12 transition
  identities;
- the historical old-source capsule used by the rollback gate;
- development benign/malicious paired corpora used to check false-positive and
  recall boundaries;
- current CPA Host, schema, native-host, CSAM and supplemental-ZIP contract tests.

## Cleanup rules

- Do not commit `_cag_*` run helpers, generated reports, credentials, request
  bodies, provider data, or local caches.
- Do not delete a fixture solely because its directory name contains `old`,
  `historical`, `vN` or `rejected`; first search all code, CI and documentation
  references and preserve its digest contract.
- Archive retired workflow YAML as inert documentation, not as a second active
  workflow source.
- Any future removal must include a migration note, a replacement contract and
  a passing Linux clean-check/reproducibility run.
