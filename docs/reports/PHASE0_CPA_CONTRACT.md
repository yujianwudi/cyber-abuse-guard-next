# CPA v7.2.125 Packaging and Contract Baseline

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: 888cfe509f77b1321f4f16a70e5e2558c270cac57d3447a831737261fb1188fd
```

This path is retained by the audit-bundle contract, but its contents describe
only the current CPA target. Historical Phase 0 version matrices are available
in Git history and are not shipped here as active validation guidance.

The root module and both isolated integration modules pin CPA v7.2.125 at commit
`2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e`, module sum
`h1:jz3yxTI7mp+ej2kI1T4OPs+QhIgP6Mmu5BGvipjQWRg=`, and go.mod sum
`h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=`. The official Linux amd64
archive SHA-256 is
`4e940b7dc5bdf867b5c58ca30f1b368fae6dc2e041e8a351d5c2c07f3f610233` and
the extracted binary SHA-256 is
`656cde7bfd966dbcaaa9d9260dd1de75716c0b9dead66d91ceb2d8d55f6d623a`.
Current validation paths are:

- the official Host source and fail-open fixture contract;
- pinned-source compile, Interactions, and Store contracts;
- the Linux native Host and Router fixture targets;
- the CPA Store archive naming, root-layout, checksum, install, and overwrite
  contract.

See [CPA_INTEGRATION.md](CPA_INTEGRATION.md) for the active commands, exact
module checksums, last fully verified source baseline, and evidence boundary.
The owner-operated isolated CPA v7.2.125 Host + Mock-upstream record remains a
separate release requirement; source or CI compile checks do not authorize
production deployment.

The active CAG source is `1.0.0`, with planned prerelease tag `v1.0.0-rc.1` on
Linux amd64. This release line does not automatically follow later upstream CPA versions.
Host evidence uses prerelease attestation schema v2 fields `cpa_version`,
`cpa_commit`, and `cpa_host_sha256`.
