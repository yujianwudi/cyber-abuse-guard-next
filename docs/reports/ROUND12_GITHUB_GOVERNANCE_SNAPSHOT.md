# Round 12 GitHub governance read-only snapshot

Observed at: `2026-08-04T11:03:25Z`
Repository: `yujianwudi/cyber-abuse-guard-next`
Observation mode: GitHub REST API through authenticated `gh api`; no repository
or settings mutation was performed.

This is a point-in-time normalized result, not a promise that GitHub settings
remain unchanged. Re-run the listed queries after any governance change and
again immediately before the final merge decision.

## Normalized result

```text
legacy_repository_api: HTTP_404
legacy_v0.15_release_api: HTTP_404
repository_owned_workflow_yaml_count: 3
actions_api_active_workflow_count: 4
github_dynamic_dependency_graph_workflow_count: 1
main_protection_strict: true
main_required_check_count: 5
main_required_approvals: 0
main_conversation_resolution: true
main_admin_enforcement: false
main_force_pushes: false
main_deletions: false
actions_allowed_actions: all
actions_sha_pinning_required: false
workflow_token_default_permission: read
workflow_token_can_approve_pull_request_reviews: true
self_hosted_runner_count: 1
self_hosted_runner_name: cag-round9-tencent-2
self_hosted_runner_status: online
repository_actions_secrets: 0
repository_dependabot_secrets: 0
repository_codespaces_secrets: 0
open_code_scanning_alerts: 0
open_dependabot_alerts: 0
open_secret_scanning_alerts: 0
```

The three repository-owned executable workflow files are `ci.yml`, `codeql.yml`,
and `policy-gate.yml`. The fourth active record returned by the Actions workflows
API is GitHub's generated `Dependency Graph` entry at
`dynamic/dependabot/update-graph`; it is not a fourth checked-in workflow YAML.
Documents must state both counts when describing the live API so that “three
repository workflows” is not misreported as “three API records.”

The five required contexts are `quality-and-artifacts`, `fuzz-long`,
`reproducibility`, `Analyze Go on Linux`, and `round9-policy-and-corpus`.
Requiring zero approvals prevents a single-maintainer deadlock and does not
constitute an independent approval.

## RT12-07 gates at the initial read-only observation

The observation does **not** satisfy all RT12-07 governance requirements:

- Actions still allows all actions and does not require full-SHA pinning at the
  repository setting (`allowed_actions=all`, `sha_pinning_required=false`).
- The default workflow token is read-only, but it can still approve pull-request
  reviews (`can_approve_pull_request_reviews=true`).
- The persistent public-repository self-hosted runner
  `cag-round9-tencent-2` remains online. It must remain available only as long as
  the authorized final-candidate second-machine work requires it, then be
  deregistered and stopped. This snapshot does not claim that retirement is
  complete.

The zero secret and open-alert counts are observed API results, not a substitute
for the still-open Actions and runner gates.

## Applied Actions controls

At `2026-08-04T11:37:07Z`, after the read-only inventory above, the repository
owner applied the two reversible Actions controls required by RT12-07 and read
them back through the REST API:

```text
actions_allowed_actions: selected
actions_github_owned_allowed: true
actions_verified_allowed: false
actions_patterns_allowed: []
actions_sha_pinning_required: true
workflow_token_default_permission: read
workflow_token_can_approve_pull_request_reviews: false
```

The checked-in workflows use only full-commit-SHA references to GitHub-owned
actions, so this allowlist does not authorize marketplace or tag-based actions.
The final candidate PR must still prove that all five required contexts execute
successfully under the effective settings. Runner retirement remains open until
the authorized second-machine work is complete.

## Development and policy artifact retention

The checked-in workflows currently declare these finite retention periods:

| Artifact | Workflow | Retention |
|---|---|---:|
| Round 10 performance JSON | `ci.yml` | 14 days |
| Linux amd64 development verification artifacts | `ci.yml` | 14 days |
| Go fuzz failure corpus | `ci.yml` | 7 days |
| Round 9 policy-gate summary and output | `policy-gate.yml` | 14 days |

These are expiring development/policy artifacts, not Release assets or durable
independent evidence. The repository does not promise recovery after expiry.

## Read-only reproduction commands

```bash
gh api repos/yujianwudi/cyber-abuse-guard --include
gh api repos/yujianwudi/cyber-abuse-guard/releases/tags/v0.15 --include
gh api 'repos/yujianwudi/cyber-abuse-guard-next/actions/workflows?per_page=100'
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection
gh api 'repos/yujianwudi/cyber-abuse-guard-next/rulesets?includes_parents=false&per_page=100'
gh api 'repos/yujianwudi/cyber-abuse-guard-next/actions/runners?per_page=100'
gh api repos/yujianwudi/cyber-abuse-guard-next/actions/permissions
gh api repos/yujianwudi/cyber-abuse-guard-next/actions/permissions/workflow
gh api 'repos/yujianwudi/cyber-abuse-guard-next/actions/secrets?per_page=100'
gh api 'repos/yujianwudi/cyber-abuse-guard-next/dependabot/secrets?per_page=100'
gh api 'repos/yujianwudi/cyber-abuse-guard-next/codespaces/secrets?per_page=100'
gh api 'repos/yujianwudi/cyber-abuse-guard-next/code-scanning/alerts?state=open&per_page=100'
gh api 'repos/yujianwudi/cyber-abuse-guard-next/dependabot/alerts?state=open&per_page=100'
gh api 'repos/yujianwudi/cyber-abuse-guard-next/secret-scanning/alerts?state=open&per_page=100'
```
