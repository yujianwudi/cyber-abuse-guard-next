# CPA v7.2.109 Packaging and Contract Baseline

```text
current_classifier_policy_version: classifier-policy-v10
current_classifier_policy_sha256: b2b7905ace913bef793271df9cd1f3f731bfb0c4254b86bc7127a876cb322d67
```

This path is retained by the audit-bundle contract, but its contents describe
only the current CPA target. Historical Phase 0 version matrices are available
in Git history and are not shipped here as active validation guidance.

The root module and both isolated integration modules pin CPA v7.2.109 at commit
`928478e4b91533cec05a763bfac3edad9c3e76cf`. Current validation paths are:

- the official Host source and fail-open fixture contract;
- pinned-source compile, Interactions, and Store contracts;
- the Linux native Host and Router fixture targets;
- the CPA Store archive naming, root-layout, checksum, install, and overwrite
  contract.

See [CPA_INTEGRATION.md](CPA_INTEGRATION.md) for the active commands, exact
module checksums, last fully verified source baseline, and evidence boundary.
The owner-operated isolated CPA v7.2.109 Host + Mock-upstream record remains a
separate release requirement; source or CI compile checks do not authorize
production deployment.

This release line does not automatically follow later upstream CPA versions.
Host evidence uses prerelease attestation schema v2 fields `cpa_version`,
`cpa_commit`, and `cpa_host_sha256`.
