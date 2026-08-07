# Repository governance

This document records the desired repository-side controls for `main`. These
settings live in GitHub rather than in the Git tree, so their presence must be
verified through the GitHub API. They are **not claimed to be enabled merely
because this document exists**.

The branch-protection controls below were observed on 2026-08-04, but several
Round 12 Actions and runner controls remain open. All settings must be
reverified after workflow or governance changes. Creating a required check
before its successful context exists can lock the default branch.

A final pre-merge read on 2026-08-08 additionally observed administrator
enforcement and required signatures enabled. This later observation updates
the active desired-state rows below; it does not rewrite the dated 2026-08-04
snapshot or transfer a PASS to any candidate commit.

## Round 12 observed state

The normalized read-only REST result and reproduction commands are saved in the
[Round 12 GitHub governance snapshot](reports/ROUND12_GITHUB_GOVERNANCE_SNAPSHOT.md).
The observation distinguishes repository-owned workflow YAML from GitHub's
generated workflow records:

| Surface | Observed state | Round 12 interpretation |
|---|---|---|
| Repository-owned executable workflow YAML | `3`: `ci.yml`, `codeql.yml`, `policy-gate.yml` | Expected inventory |
| Actions workflows API | `4` active records: the three files plus `dynamic/dependabot/update-graph` | GitHub's generated Dependency Graph is not a fourth checked-in workflow |
| `main` protection | Strict, five required checks, conversations required, approvals `0`, administrator enforcement and required signatures enabled, force-push/delete disabled | Matches the single-maintainer branch contract; zero approvals is not independent review |
| Actions admission | Initial observation: `allowed_actions=all`, `sha_pinning_required=false`; applied/read back at `2026-08-04T11:37:07Z`: GitHub-owned only, `sha_pinning_required=true` | Configuration gate closed; final PR must prove the selected-action policy executes the five required contexts |
| Workflow token | Applied/read back: default `read`, `can_approve_pull_request_reviews=false` | Configuration gate closed |
| Self-hosted runners | `cag-round9-tencent-2`, Linux, online | **OPEN**: final-candidate work is pending; deregistration/shutdown is not claimed |
| Repository secrets | Actions `0`, Dependabot `0`, Codespaces `0` | Observed acceptance value |
| Open security alerts | Code scanning `0`, Dependabot `0`, secret scanning `0` | Observed acceptance value |

This is a time-bound API snapshot, not a declaration that RT12-07 has passed.
The Actions settings must be rechecked after the final PR run, and runner
retirement remains open until the second-machine work finishes.

## Active workflow inventory

| Workflow file | Display name | Required-check contexts |
|---|---|---|
| `.github/workflows/ci.yml` | `CI` | `quality-and-artifacts`, `fuzz-long`, `reproducibility` |
| `.github/workflows/codeql.yml` | `CodeQL` | `Analyze Go on Linux` |
| `.github/workflows/policy-gate.yml` | `Policy and Corpus Gate` | `round9-policy-and-corpus` |

No active workflow publishes Releases or uses a self-hosted runner. Historical
release and Host workflow definitions remain available through Git history but
are not executable from the default branch.

The live API also exposes GitHub's generated `Dependency Graph` workflow. It
does not change the three-file repository inventory and must not be omitted when
reporting the raw API count.

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
| Repository action admission | Allowlisted actions only; full commit SHA required |
| Workflow token PR approval | Disabled |
| Persistent public-repository self-hosted runner | Deregistered and stopped after final-candidate verification |

Zero required approvals avoids deadlocking a single-maintainer repository. The
pull request requirement, required checks, and conversation-resolution gate
still apply. `CODEOWNERS` routes review attention but does not create an
independent approval and must not be treated as one.

Administrator bypass is not an admitted merge path while administrator
enforcement remains enabled. Any emergency settings change must be recorded
with its reason, exact affected commit, verification performed, restoration of
the protected state, and corrective follow-up.

## Development and policy artifact retention

The active workflows use finite retention and do not create durable Release
evidence:

| Artifact | Retention |
|---|---:|
| Round 10 performance JSON | 14 days |
| Linux amd64 development verification artifacts | 14 days |
| Go fuzz failure corpus | 7 days |
| Round 9 policy-gate summary and output | 14 days |

Expiry is intentional. None of these Actions artifacts is a stable plugin
asset, rollback source, independent attestation, or production authorization.

## Verification

Run these read-only commands after enabling or changing protection:

```bash
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection/required_status_checks
gh api repos/yujianwudi/cyber-abuse-guard-next/rulesets --paginate
gh api repos/yujianwudi/cyber-abuse-guard-next/actions/permissions
gh api repos/yujianwudi/cyber-abuse-guard-next/actions/permissions/workflow
gh api 'repos/yujianwudi/cyber-abuse-guard-next/actions/workflows?per_page=100'
gh api 'repos/yujianwudi/cyber-abuse-guard-next/actions/runners?per_page=100'
```

For a compact protection audit:

```bash
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection \
  --jq '{strict: .required_status_checks.strict,
         checks: [.required_status_checks.checks[].context],
         approvals: .required_pull_request_reviews.required_approving_review_count,
         conversations: .required_conversation_resolution.enabled,
         admins: .enforce_admins.enabled,
         signatures: .required_signatures.enabled,
         force_pushes: .allow_force_pushes.enabled,
         deletions: .allow_deletions.enabled}'
```

The expected result is `strict: true`, the five exact check names above,
`approvals: 0`, `conversations: true`, `admins: true`, `signatures: true`,
`force_pushes: false`, and `deletions: false`. Also inspect branch-targeting
rulesets for conflicting or broader rules. Tag governance is separate from
`main` protection and must not be inferred from the branch result.

The successor repository protection was enabled on 2026-07-24 with those five
contexts, observed again on 2026-08-04, and re-read with administrator
enforcement plus required signatures enabled on 2026-08-08. This statement is
a configuration snapshot, not a substitute for the read-only API verification
commands above.

When a workflow or job name changes, update the required-check configuration
and this document together. Never rename a required check without first
planning how the old protection entry will be removed safely.
