# Repository governance

This document records the desired repository-side controls for `main`. These
settings live in GitHub rather than in the Git tree, so their presence must be
verified through the GitHub API. They are **not claimed to be enabled merely
because this document exists**.

The controls below are to be enabled only after the current hardening pull
request has passed all four named checks, has been merged, and the corresponding
checks have appeared successfully for the repository. Creating required checks
before their successful contexts exist can lock the default branch.

## Desired `main` protection

| Control | Desired value |
|---|---|
| Changes enter through a pull request | Required |
| Required approving reviews | `0` while the repository has one maintainer |
| Required status checks are up to date | Strict / required |
| Required status checks | `quality-and-artifacts`, `fuzz-long`, `reproducibility`, `Analyze Go on Linux` |
| All review conversations resolved | Required |
| Force pushes | Prohibited |
| Branch deletion | Prohibited |
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
gh api repos/yujianwudi/cyber-abuse-guard/branches/main/protection
gh api repos/yujianwudi/cyber-abuse-guard/branches/main/protection/required_status_checks
gh api repos/yujianwudi/cyber-abuse-guard/rulesets --paginate
```

For a compact protection audit:

```bash
gh api repos/yujianwudi/cyber-abuse-guard/branches/main/protection \
  --jq '{strict: .required_status_checks.strict,
         checks: [.required_status_checks.checks[].context],
         approvals: .required_pull_request_reviews.required_approving_review_count,
         conversations: .required_conversation_resolution.enabled,
         admins: .enforce_admins.enabled,
         force_pushes: .allow_force_pushes.enabled,
         deletions: .allow_deletions.enabled}'
```

The expected result is `strict: true`, the four exact check names above,
`approvals: 0`, `conversations: true`, `admins: false`, `force_pushes: false`,
and `deletions: false`. Also inspect branch-targeting rulesets for conflicting
or broader rules. Tag governance is separate from `main` protection and must
not be inferred from the branch result.

When a workflow or job name changes, update the required-check configuration
and this document together. Never rename a required check without first
planning how the old protection entry will be removed safely.
