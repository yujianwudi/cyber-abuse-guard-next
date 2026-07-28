# Active GitHub Actions workflows

Only the three YAML files listed below are executable GitHub Actions workflows.
Release, prerelease, candidate, and protected-Host definitions are retained as
non-executable audit snapshots under
[`docs/archive/workflows/`](../../docs/archive/workflows/).

| Workflow | Trigger | Required check or purpose |
|---|---|---|
| `ci.yml` | Pull requests to `main`; pushes to `main` | `quality-and-artifacts`, `fuzz-long`, and `reproducibility`; Linux-only build, test, CPA v7.2.104 schema-2 contract, candidate `.so` Host load, artifact integrity, and reproducibility |
| `codeql.yml` | Pull requests and pushes to `main`; weekly schedule; manual dispatch | `Analyze Go on Linux`; minimal-permission Go CodeQL analysis |
| `round9-gate.yml` | Pull requests to `main`; pushes to `main` | `round9-policy-and-corpus`; policy, Safe Gate, development-corpus, and public-corpus checks without private or independent corpus access |

These five job names are the exact required status checks configured for
`main`. Renaming a job requires updating branch protection and
[`docs/REPOSITORY_GOVERNANCE.md`](../../docs/REPOSITORY_GOVERNANCE.md) in the
same change.

No file in this directory can create a GitHub Release, publish a prerelease, or
dispatch the retired protected-Host evaluation chain. Source changes are merged
to `main` and verified by the three workflows above; deployment, production
validation, independent audit, and publication remain operator-owned external
actions.

`codeql.yml` grants `contents: read` globally and `security-events: write` only
to its analysis job. It does not receive `contents: write` and cannot publish
artifacts or Releases.

The Safe Gate enforces an exact executable-workflow allowlist. Adding another
workflow requires an explicit contract, documentation, branch-protection, and
security review rather than merely placing YAML in this directory.

Historical workflow snapshots intentionally preserve their original embedded
`.github/workflows/...` signer paths. Those strings describe past provenance;
they do not make archived YAML dispatchable and must not be rewritten as new
execution evidence.
