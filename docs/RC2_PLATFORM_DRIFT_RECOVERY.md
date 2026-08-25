# v1.0.0-rc.2 platform-workflow drift recovery

## Decision record

The signed annotated `v1.0.0-rc.1` tag points to protected
`main@3b77ccb4fe8faeecd9dcf601d548e4f31fd43a4c`. Its main-push CI, CodeQL,
Policy/Corpus, fuzz and reproducibility checks passed, but no RC1 GitHub Release
or release asset was created. Admission failed closed because GitHub now returns
platform-owned Dependabot workflows from the repository Actions workflow API.
The RC1 contract treated every API workflow record as repository YAML and
required the complete active set to contain exactly four paths.

The RC1 tag is protected by the active `v1.0.0-rc-series-immutable` ruleset and
must not be deleted, updated or reused. Recovery therefore uses a new reviewed
candidate, `v1.0.0-rc.2`.

## Implementation boundary

RC2 preserves the exact four repository-controlled workflow paths:

```text
.github/workflows/ci.yml
.github/workflows/codeql.yml
.github/workflows/policy-gate.yml
.github/workflows/release-rc.yml
```

The GitHub API may additionally return a subset of this closed platform list:

```text
dynamic/dependabot/dependabot-updates
dynamic/dependabot/update-graph
```

No `dynamic/` entry is treated as a repository workflow or source file. Any
other active path, any missing repository workflow, or any extra repository
workflow fails admission. The same check is repeated immediately before final
publication. This change does not weaken branch protection, required checks,
signed-tag verification, immutable Releases, action SHA pinning, candidate-byte
identity, attestations, or provenance.

## Acceptance standard

RC2 is accepted only when all of the following are true:

1. CPA remains fixed at
   `v7.2.137@85d2faddd17e6f4f8675a84ee28b131f702e8eaa`, C ABI 1, RPC schema 3,
   Linux amd64 and Go 1.26.6.
2. Workflow lint, ShellCheck, the Round 6 safe-gate contract, release-document
   mutation suite, RC contract suite and GitHub admission unit tests pass.
   Candidate SBOM normalization must also accept only the exact pseudo-version
   derived from the immutable annotated RC1 ancestor and bind the resulting
   normalized component to the current RC2 candidate commit/tree.
3. Tests reject an unknown active repository or platform workflow path while
   accepting zero, one or both known GitHub Dependabot dynamic paths.
4. A signed PR commit passes `quality-and-artifacts`, `fuzz-long`,
   `reproducibility`, `Analyze Go on Linux`, and
   `round9-policy-and-corpus` before squash merge.
5. The exact protected-main squash commit passes the same main-push checks and
   produces the unique live nine-file audit-candidate artifact.
6. `v1.0.0-rc.2` is a GitHub-verified signed annotated tag pointing to that
   exact protected-main commit; it is never moved or deleted.
7. Publication uses only `release-rc.yml`. The maintainer may use the explicit
   second-machine waiver with `I_ACK_SECOND_MACHINE_NOT_RUN`; the resulting
   Release must state that no second-machine execution, independent Host audit,
   or production approval is claimed.
8. The published GitHub Release is immutable, non-draft, prerelease, not latest,
   contains the exact verified Linux assets and checksums, and has valid GitHub
   build-provenance attestations.

No local deployment or second-machine execution is required for this recovery.
