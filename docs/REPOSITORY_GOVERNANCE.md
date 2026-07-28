# Repository governance

This document records the desired repository-side controls for `main`. These
settings live in GitHub rather than in the Git tree, so their presence must be
verified through the GitHub API. They are **not claimed to be enabled merely
because this document exists**.

The controls below are to be enabled only after the current hardening pull
request has passed all five named checks, has been merged, and the corresponding
checks have appeared successfully for the repository. Creating required checks
before their successful contexts exist can lock the default branch.

## Desired `main` protection

| Control | Desired value |
|---|---|
| Changes enter through a pull request | Required |
| Required approving reviews | `0` while the repository has one maintainer |
| Required status checks are up to date | Strict / required |
| Required status checks | `quality-and-artifacts`, `fuzz-long`, `reproducibility`, `Analyze Go on Linux`, `round9-policy-and-corpus` |
| All review conversations resolved | Required |
| Require signed commits | Required |
| Force pushes | Prohibited |
| Branch deletion | Prohibited |
| Delete merged pull-request branches | Enabled |
| Enforce the rule for administrators | Disabled for documented break-glass recovery |

Zero required approvals avoids deadlocking a single-maintainer repository. The
pull request requirement, required checks, and conversation-resolution gate
still apply. `CODEOWNERS` routes review attention but does not create an
independent approval and must not be treated as one.

Administrator bypass is an emergency recovery path, not an ordinary merge
method. Any use should be followed by a normal pull request or repository note
that records the reason, exact commit, verification performed, and corrective
follow-up.

## Verification

Run these read-only commands after enabling or changing protection:

```bash
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection/required_status_checks
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection/required_signatures
gh api repos/yujianwudi/cyber-abuse-guard-next --jq '{delete_branch_on_merge}'
gh api repos/yujianwudi/cyber-abuse-guard-next/rulesets --paginate
```

For a compact protection audit, run the branch-protection query together with
the two repository controls that GitHub exposes through separate endpoints:

```bash
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection \
  --jq '{strict: .required_status_checks.strict,
         checks: [.required_status_checks.checks[].context],
         approvals: .required_pull_request_reviews.required_approving_review_count,
         conversations: .required_conversation_resolution.enabled,
         admins: .enforce_admins.enabled,
         force_pushes: .allow_force_pushes.enabled,
         deletions: .allow_deletions.enabled}'
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection/required_signatures \
  --jq '{required_signatures: .enabled}'
gh api repos/yujianwudi/cyber-abuse-guard-next \
  --jq '{delete_branch_on_merge}'
```

The expected result is `strict: true`, the five exact check names above,
`approvals: 0`, `conversations: true`, `admins: false`, `force_pushes: false`,
`deletions: false`, `required_signatures.enabled: true`, and
`delete_branch_on_merge: true`. Also inspect branch-targeting rulesets for
conflicting or broader rules. Tag governance is separate from `main` protection
and must not be inferred from the branch result.

The successor repository protection was enabled on 2026-07-24 with those five
contexts. On 2026-07-28 the live configuration was reconciled to prohibit force
pushes and deletion of `main`, while preserving strict checks, signed commits,
conversation resolution, zero required approvals, and the documented admin
break-glass path. Automatic deletion of merged pull-request head branches is
enabled to prevent stale `agent/*` branches from accumulating. This statement
is a configuration snapshot, not a substitute for the read-only API
verification commands above.

When a workflow or job name changes, update the required-check configuration
and this document together. Never rename a required check without first
planning how the old protection entry will be removed safely.
