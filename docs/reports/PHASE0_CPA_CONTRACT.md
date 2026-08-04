# CPA v7.2.116 Packaging and Contract Baseline

```text
current_classifier_policy_version: classifier-policy-v10
current_classifier_policy_sha256: 7934e15f95b8bb617f683507c7739d62c12b508961d0b2c3f3e39ead19cda3c2
```

This path is retained by the audit-bundle contract, but its contents describe
only the current CPA target. Historical Phase 0 version matrices are available
in Git history and are not shipped here as active validation guidance.

The root module and both isolated integration modules pin CPA v7.2.116 at commit
`a88197f845c979132c8978ea223c6af05cc81536`. Current validation paths are:

- the official Host source and fail-open fixture contract;
- pinned-source compile, Interactions, and Store contracts;
- the Linux native Host and Router fixture targets;
- the CPA Store archive naming, root-layout, checksum, install, and overwrite
  contract.

See [CPA_INTEGRATION.md](CPA_INTEGRATION.md) for the active commands, exact
module checksums, last fully verified source baseline, and evidence boundary.
The owner-operated isolated CPA v7.2.116 Host + Mock-upstream record remains a
separate release requirement; source or CI compile checks do not authorize
production deployment.

This release line does not automatically follow later upstream CPA versions.
Host evidence uses prerelease attestation schema v2 fields `cpa_version`,
`cpa_commit`, and `cpa_host_sha256`.
