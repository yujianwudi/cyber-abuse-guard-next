## Summary

Describe the change, why it is needed, and the affected trust boundary.

## Validation

- [ ] Linux amd64 validation is reported; Windows and macOS are not claimed.
- [ ] `make test` passed, or the reason it was not applicable is documented.
- [ ] Vet, format, module, script, and safe-gate checks relevant to this change passed.
- [ ] Performance-sensitive changes include `make round6-benchmark` results.
- [ ] CPA integration changes retain the single pinned v7.2.95 contract.

## Security and restricted data

- [ ] No evaluation, Holdout, consumed, private, blind, or retired data was opened, read, copied, executed, or used for tuning.
- [ ] No credential, production prompt, raw capture, audit database, account identifier, or real Provider data is included.
- [ ] Security, privacy, permission, logging, and rollback impacts are described where relevant.
- [ ] Workflow actions remain pinned to full commit SHAs and use least privilege.

## Documentation and governance

- [ ] Tests and documentation were updated with the implementation.
- [ ] Workflow names, required-check names, contracts, and governance documentation remain synchronized.
- [ ] All actionable review conversations will be resolved before merge.

## Release boundary

- [ ] This pull request does not claim tag, release, deployment, Host, audit, evaluation, or production authorization.
- [ ] Any release-related action has explicit maintainer authorization and preserves the documented attestation gates.
