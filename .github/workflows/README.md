# GitHub Actions

This directory contains the three validation workflows required for the
current `main` branch and one manually dispatched RC publication workflow. A
workflow is executable by GitHub Actions only while its YAML file is present
here.

| File | Display name | Trigger | Responsibility |
|---|---|---|---|
| `ci.yml` | `CI` | Pushes and pull requests targeting `main` | Linux quality gates, CPA v7.2.137 / C ABI 1 / RPC schema 3 compatibility, tests, fuzzing, development artifacts, and reproducibility |
| `codeql.yml` | `CodeQL` | Pushes and pull requests targeting `main`, weekly schedule, manual dispatch | Minimal-permission Linux Go code scanning |
| `policy-gate.yml` | `Policy and Corpus Gate` | Pushes and pull requests targeting `main` | Benign/malicious policy, corpus, performance, and bounded-fuzz acceptance gates |
| `release-rc.yml` | `RC Release` | Manual dispatch from the fixed signed `v1.0.0-rc.1` annotated tag | Revalidate protected-main checks and second-machine admission, seal the exact audited Linux assets, attest them, and publish a non-latest prerelease |

## RC publication boundary

`release-rc.yml` is an executable publication path, but it is deliberately not
a build path and it cannot run on a push or pull request. Publication is
allowed only after all Round 14 acceptance gates have passed. In particular:

- dispatch must target the existing GitHub-verified signed annotated
  `v1.0.0-rc.1` tag, peeled to the exact protected `main` commit;
- the exact CI, CodeQL and Policy and Corpus Gate push runs and all five
  required checks must already be successful;
- the exact nine-file CI candidate and a non-expired second-machine admission
  v3 report must close before assets are sealed;
- the workflow reuses the audited SO bytes and only derives the deterministic
  CPA Store RC ZIP; it does not recompile or move the tag;
- write permissions exist only on the attestation and final publication jobs;
  the admission job is read-only, and no workflow grants `packages: write`;
- the resulting GitHub Release must be non-draft, prerelease, and not latest.

Any missing identity, signature, required check, artifact, second-machine gate,
asset digest, or final release-state assertion fails closed. A failed fixed RC
tag is never deleted, moved, or replaced; a later attempt requires a new RC
version and a separately reviewed workflow change.

## Naming and governance

- Workflow filenames use short lowercase kebab-case names.
- Display names use concise title case.
- Job IDs remain stable when they are required status-check contexts. In
  particular, `round9-policy-and-corpus` remains a compatibility context.
- Active workflows have no implicit write permissions. CodeQL grants
  `security-events: write` only to its analysis job; RC publication grants
  narrowly scoped write permissions only to its attestation and publication
  jobs after admission succeeds.
- No active workflow uses a self-hosted runner.

The expected required checks for `main` are documented in
[`docs/REPOSITORY_GOVERNANCE.md`](../../docs/REPOSITORY_GOVERNANCE.md).
