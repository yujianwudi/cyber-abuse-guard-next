# Contributing

Contributions are welcome through pull requests. This project is a Linux amd64
CPA plugin and currently targets Go 1.26.6 and CPA v7.2.137 at
`85d2faddd17e6f4f8675a84ee28b131f702e8eaa` as the only active source/compile
and Host contract, with C ABI 1 and RPC schema 3.
Windows, macOS, musl/Alpine, local deployment, and production deployment are
outside the ordinary contribution and validation scope.

Round 14 is the active compatibility/admission round and does not authorize a
release. Round 13 v7.2.125/schema 2 and all older green results retain their
original historical identities and cannot transfer a PASS. The green
historical `main@21267e742b624b29a75bd3683fd6914f76c764b5` engineering baseline does not
transfer to a later pull-request commit; the final candidate requires its own
GitHub checks and second-machine execution. Protected Host, independent
attestation, production approval, and release readiness remain `NOT_PROVIDED`.
The root README status block and
[Round 14 status](docs/ROUND14_STATUS.md) are the active v7.2.137 boundary;
all v7.2.124 and earlier results are explicitly historical and non-transferable.

Every `/v1/realtime*` route currently bypasses CAG `RequestInterceptor`,
`ModelRouter`, and request lifecycle. Treat it as **OUT_OF_SCOPE /
UNPROTECTED**; contribution claims may cover only registered callback paths
such as chat and Responses, never all CPA traffic.

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

Use a Linux amd64 environment with Go 1.26.6. For an ordinary change, run the
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
integration must update the exact v7.2.137 pin deliberately. CPA v7.2.137
Multi-Agent v2 rewrites `/v1/responses` tool definitions before
`RequestInterceptor`, so integration changes must include a regression for the
rewritten tool-schema/tool-payload boundary. Historical v7.2.124 and earlier
CI, second-machine, and five-repository data cannot satisfy that check. Do not claim
Windows, macOS, production,
real-Host, or release validation from these checks.

## Pull requests

- Keep the change focused and explain its security, compatibility, privacy,
  performance, and rollback impact where relevant.
- Add or update tests and documentation with the implementation.
- Preserve full-SHA pinning and least privilege in GitHub Actions changes.
- Resolve all actionable review conversations.
- Before merge, the required checks must pass: `quality-and-artifacts`,
  `fuzz-long`, `reproducibility`, `Analyze Go on Linux`, and
  `round9-policy-and-corpus`.
- Follow the desired default-branch controls in
  [docs/REPOSITORY_GOVERNANCE.md](docs/REPOSITORY_GOVERNANCE.md).

## Release authority

A merged pull request, successful CI run, locally built package, or code-owner
route does not authorize a tag, GitHub Release, CPA deployment, or production
rollout. Unless the maintainer explicitly authorizes release work, contributors
must not push release tags, dispatch publication workflows, publish artifacts,
or change release evidence to claim external Host, audit, evaluation, or
production approval.

The current Round 14 scope is compatibility/admission only and authorizes no
tag or Release. It does not authorize `v1.0.0-rc.1`, stable `v1.0.0`, production
deployment, or an independent-attestation claim. The owner-run input diagnostic is not an independent
attestation and must not be relabelled as the pending final-candidate
second-machine result.
