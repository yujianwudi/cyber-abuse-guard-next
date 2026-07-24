# Contributing

Contributions are welcome through pull requests. This project is a Linux amd64
CPA plugin and currently targets Go 1.26.4 and CPA v7.2.95 as the only active
source/compile and Host contract.
Windows, macOS, musl/Alpine, local deployment, and production deployment are
outside the ordinary contribution and validation scope.

## Restricted-data boundary

Ordinary development must not open, read, print, copy, transform, or execute
evaluation, Holdout, consumed, private, blind, or retired fixtures and reports.
Do not use those materials for implementation, tuning, tests, documentation, or
review conclusions. Use the repository's safe development targets, synthetic
fixtures, and public development corpora only.

Do not commit credentials, production prompts, raw request captures, audit
databases or WAL/SHM files, account identifiers, or real Provider data. Report
security issues through [SECURITY.md](SECURITY.md), not through a public issue
or pull request.

## Linux development checks

Use a Linux amd64 environment with Go 1.26.4. For an ordinary change, run the
relevant subset and report every skipped or failed check in the pull request:

```bash
make test
make round6-vet
make round6-format-check
make round6-module-verify
python3 -B scripts/round6_safe_gate_contract_test.py
python3 -B scripts/round6_safe_gate_contract.py --root .
make round6-script-test
```

Run `make round6-benchmark` for classifier, extraction, audit, queueing,
management-response, or other performance-sensitive changes. Changes to CPA
integration must update the exact v7.2.95 pin deliberately. Do not claim
Windows, macOS, production,
real-Host, or release validation from these checks.

## Pull requests

- Keep the change focused and explain its security, compatibility, privacy,
  performance, and rollback impact where relevant.
- Add or update tests and documentation with the implementation.
- Preserve full-SHA pinning and least privilege in GitHub Actions changes.
- Resolve all actionable review conversations.
- Before merge, the required checks must pass: `quality-and-artifacts`,
  `fuzz-long`, `reproducibility`, and `Analyze Go on Linux`.
- Follow the desired default-branch controls in
  [docs/REPOSITORY_GOVERNANCE.md](docs/REPOSITORY_GOVERNANCE.md).

## Release authority

A merged pull request, successful CI run, locally built package, or code-owner
route does not authorize a tag, GitHub Release, CPA deployment, or production
rollout. Unless the maintainer explicitly authorizes release work, contributors
must not push release tags, dispatch publication workflows, publish artifacts,
or change release evidence to claim external Host, audit, evaluation, or
production approval.
