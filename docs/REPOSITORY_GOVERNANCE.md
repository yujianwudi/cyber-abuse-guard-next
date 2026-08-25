# Repository governance

This document records the desired repository-side controls for `main`. GitHub
settings must be verified through the API; this checked-in document is not
evidence that remote settings are currently enabled.

## Round 14 gated RC publication policy

Tag creation, prereleases, GitHub Releases, provenance attestations, package
publication, and release-asset uploads remain forbidden until every applicable
Round 14 acceptance gate passes. The executable workflow directory contains
exactly these four repository-owned workflow files:

| Workflow file | Display name | Required-check contexts |
|---|---|---|
| `.github/workflows/ci.yml` | `CI` | `quality-and-artifacts`, `fuzz-long`, `reproducibility` |
| `.github/workflows/codeql.yml` | `CodeQL` | `Analyze Go on Linux` |
| `.github/workflows/policy-gate.yml` | `Policy and Corpus Gate` | `round9-policy-and-corpus` |
| `.github/workflows/release-rc.yml` | `RC Release` | Manual post-acceptance publication lane; not a required PR context |

GitHub's Actions API may also expose platform-owned records at
`dynamic/dependabot/dependabot-updates` and
`dynamic/dependabot/update-graph`. They are not repository YAML files. RC
admission keeps the four paths above exact, permits only a subset of those two
GitHub dynamic paths, and fails closed on every other active path.

Only `.github/workflows/release-rc.yml` may obtain the narrowly scoped write
permissions or run tag, Release, attestation, and Release-asset operations, and
only in its post-admission publication jobs. Manual `gh release`, altered job
conditions, or any other workflow may not bypass that lane.

CodeQL and RC Release are the two manually dispatchable active workflows.
CodeQL keeps top-level `contents: read`; the analysis job adds only
`security-events: write`, which uploads code-scanning results and is not a
publication permission. RC Release remains inert unless its complete,
exact-candidate admission succeeds. CI and Policy Gate remain push/pull-request
validation workflows with `contents: read`.

The active compatibility boundary is CPA `v7.2.137` at commit
`85d2faddd17e6f4f8675a84ee28b131f702e8eaa`, C ABI `1`, RPC schema `3`, Linux
amd64 only. This identity alone is not release authorization; the full
acceptance and RC admission contracts remain mandatory.

## Desired `main` protection

| Control | Desired value |
|---|---|
| Changes enter through a pull request | Required |
| Required approving reviews | `0` while the repository has one maintainer |
| Required status checks are up to date | Strict / required |
| Required status checks | `quality-and-artifacts`, `fuzz-long`, `reproducibility`, `Analyze Go on Linux`, `round9-policy-and-corpus` |
| All review conversations resolved | Required |
| Force pushes | Prohibited |
| Branch deletion | Prohibited |
| Enforce the rule for administrators | Required / enabled |
| Required signatures | Required / enabled |
| Merge methods | Squash merge only; merge commits and rebase merges disabled |
| Delete merged head branch | Enabled; release admission binds protected `main`, not the deleted PR branch |
| Repository action admission | Allowlisted actions only; full commit SHA required |
| Default workflow token | Read-only |
| Workflow token PR approval | Disabled |
| Persistent public-repository self-hosted runner | Prohibited |
| RC tag ruleset | `v1.0.0-rc-series-immutable`; active tag target; exact `refs/tags/v1.0.0-rc.*`; deletion/update prohibited; no bypass |
| Immutable Releases | Enabled before any RC workflow dispatch |

Zero required approvals avoids deadlocking a single-maintainer repository. The
pull-request requirement, required checks, conversation resolution,
administrator enforcement, and signatures remain authoritative controls.
The RC workflow is owner-only (`yujianwudi`, actor ID `153849069`) and repeats
the repository, `main`, Actions-policy, immutable-release, and tag-ruleset
checks before draft creation and again immediately before publication.

Those Administration and Actions metadata reads cannot use the built-in
`GITHUB_TOKEN`: GitHub does not expose a repository `administration: read`
workflow permission. Before RC dispatch, configure
`CAG_RELEASE_GOVERNANCE_TOKEN` as a separately managed GitHub App installation
token or fine-grained PAT with read-only access to repository Administration
and Actions metadata. It must not have Contents write, Releases write, or tag
mutation authority. The admission job is the only consumer and fails closed
when the secret is absent. Publication continues to use its job-scoped
`GITHUB_TOKEN`; never place the governance credential in source, logs, assets,
or second-machine evidence.

The second-machine runner is temporary admission infrastructure, not a
persistent public-repository runner. Register it only for the bounded run and
unregister/uninstall it after the final post-main evidence is collected. Never
leave `cag-round9-tencent-2` or a replacement online after acceptance.

## Merge and branch cleanup order

1. Close superseded PRs without merging them.
2. Squash-merge the final reviewed PR through protected `main`; do not use an
   administrator bypass, merge commit, rebase merge, or force push.
3. Verify the GitHub-signed main commit, exact reviewed tree, and main-push
   required checks. Automatic deletion of the merged head branch is expected.
4. Complete post-main second-machine admission and preserve only bounded,
   non-content evidence.
5. Delete every remaining non-`main` local and remote development branch, then
   prune local tracking refs. Tags and immutable evidence refs are not branches
   and are never moved or deleted as branch cleanup.

The RC admission independently enumerates remote branches and registered
self-hosted runners. It accepts exactly one branch (`main`) and zero registered
runners; this prevents a forgotten development branch or persistent second-
machine runner from being silently carried into publication.

## Artifact retention

Active workflows may upload finite-retention development and validation
artifacts. These are not Release assets, rollback sources, independent
attestations, or production authorization.

| Artifact class | Retention |
|---|---:|
| Performance and development verification artifacts | 14 days |
| Fuzz failure corpus | 7 days |
| Policy-gate summaries | 14 days |

## Read-only verification

After workflow or governance changes, inspect the current remote state without
mutating it:

```bash
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection/required_status_checks
gh api repos/yujianwudi/cyber-abuse-guard-next/rulesets --paginate
gh api repos/yujianwudi/cyber-abuse-guard-next/immutable-releases
gh api repos/yujianwudi/cyber-abuse-guard-next/actions/permissions
gh api repos/yujianwudi/cyber-abuse-guard-next/actions/permissions/workflow
gh api repos/yujianwudi/cyber-abuse-guard-next/actions/permissions/selected-actions
gh api 'repos/yujianwudi/cyber-abuse-guard-next/actions/workflows?per_page=100'
gh api 'repos/yujianwudi/cyber-abuse-guard-next/actions/runners?per_page=100'
```

The expected branch result is strict required checks, the five exact contexts
above, zero approvals, conversations/admin/signatures enabled, and force
pushes/deletion disabled. Compare the Actions workflows response against the
exact four repository-owned paths and the separate two-path GitHub Dependabot
dynamic allowlist. Verify Dependency Graph enablement through its repository
settings/API surface; its dynamic Actions record is platform metadata, not a
fifth repository workflow.

Run the checked-in local governance contracts with:

```bash
python3 -B scripts/round6_safe_gate_contract.py --root .
bash scripts/release-rc-contract-test.sh
```

When a workflow or job name changes, update required-check configuration and
this document together. Never rename a required check without a safe migration
for the existing branch-protection context.
