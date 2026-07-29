# GitHub Actions

This directory intentionally contains only the workflows required to validate
the current `main` branch. A workflow is executable by GitHub Actions only when
its YAML file is present here.

| File | Display name | Trigger | Responsibility |
|---|---|---|---|
| `ci.yml` | `CI` | Pushes and pull requests targeting `main` | Linux quality gates, CPA v7.2.104 compatibility, tests, fuzzing, candidate `.so` loading, development artifacts, and reproducibility |
| `codeql.yml` | `CodeQL` | Pushes and pull requests targeting `main`, weekly schedule, manual dispatch | Minimal-permission Go code scanning |
| `policy-gate.yml` | `Policy and Corpus Gate` | Pushes and pull requests targeting `main` | Benign/malicious policy, corpus, performance, and bounded-fuzz acceptance gates |

The repository does not use an Actions workflow to create or publish a plugin
Release. The owner performs independent server-side sandbox review separately.
Historical candidate, prerelease, Round 8, RC, Host, promotion, and release
workflows were removed from this executable directory on 2026-07-30; their
definitions and run evidence remain recoverable from Git history.

## Naming and governance

- Workflow filenames use short lowercase kebab-case names.
- Display names use concise title case and do not contain version or round
  identifiers unless the workflow is truly version-specific.
- Job IDs remain stable when they are required status-check contexts. In
  particular, `round9-policy-and-corpus` is retained as a compatibility context
  while the workflow itself uses the version-neutral `Policy and Corpus Gate`
  name.
- Active workflows have read-only repository permissions by default. CodeQL
  grants `security-events: write` only to its analysis job.
- No active workflow uses a self-hosted runner, release/tag trigger,
  `contents: write`, or deployment environment.

The expected required checks for `main` are documented in
[`docs/REPOSITORY_GOVERNANCE.md`](../../docs/REPOSITORY_GOVERNANCE.md).
