# CPA v7.2.144 Packaging and Contract Baseline

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: f98ee38cea5b38b60130b98bd3ca6100cb6aeeee223128311235469af40ec9e3
```

This path is retained by the audit-bundle contract, but its contents describe
only the current CPA target. Historical Phase 0 version matrices are available
in Git history and are not shipped here as active validation guidance.

The root module and both isolated integration modules pin CPA v7.2.144 at commit
`d36b776c790a4d58027fd4fb434800fb5334bceb`, module sum
`h1:ZNLmwkaMZ+4KbR8BqLHUUDdDzWsQKpXZQbLYesh4ttk=`, and go.mod sum
`h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=`. The official Linux amd64
archive is 21,223,927 bytes with SHA-256
`02be1ad96791f1d2b7e6574bb0f68a3d75622e42cba07fecd012e575ba4b2a96`;
the checksums file SHA-256 is
`1cd243af209cc8f7dac36b3785f9ff2d06a81518f409611a3c674ce2190a4331`.
The extracted binary is 64,203,432 bytes with SHA-256
`eef73e578f5d272173aadcdf52137390363cd7e4bf0da8651d4c0acd3c0c4f09`.
This target uses C ABI 1 / RPC schema 4.
Current validation paths are:

- the official Host source and fail-open fixture contract;
- pinned-source compile, Interactions, and Store contracts;
- the Linux native Host and Router fixture targets;
- the CPA Store archive naming, root-layout, checksum, install, and overwrite
  contract.

See [CPA_INTEGRATION.md](CPA_INTEGRATION.md) for the active commands, exact
module checksums, last fully verified source baseline, and evidence boundary.
The owner-operated isolated CPA v7.2.144 Host + Mock-upstream record remains a
separate release requirement; source or CI compile checks do not authorize
production deployment.

The active CAG source is `1.0.0`, with planned prerelease tag `v1.0.0-rc.3` on
Linux amd64. This release line does not automatically follow later upstream CPA versions.
Host evidence uses prerelease attestation schema v2 fields `cpa_version`,
`cpa_commit`, and `cpa_host_sha256`.

Current Round 16 evidence is development-only. The repository-owned receipt
now records Linux `315/315 PASS` with zero skips for the audit-tool closure;
the prior 283-test receipt remains immutable historical evidence. Five targeted
schema-4 Host fixture tests, the targeted CAG RPC schema test in WSL, and one
upstream hook/no-copy/auth/realtime source-contract test remain separately
recorded development checks. The prior `f663ea6` / `0eaed101` candidate's
semantic, CSAM and native-Host PASS records remain bound to its old collector
bytes and do not
transfer to the current fix. All complete Linux project, exact-fix candidate,
second-machine, five-repository/ZIP, false-positive, Host performance, and
release gates remain `NOT_RUN / PENDING`; no Release is authorized.
`/v1/realtime*` bypasses CAG and is `OUT_OF_SCOPE / UNPROTECTED`.

The former v7.2.125/schema-2 Phase 0 baseline and all Round 13 or earlier PASS
records are frozen `HISTORICAL / SUPERSEDED` evidence and are not transferred
to this target.
