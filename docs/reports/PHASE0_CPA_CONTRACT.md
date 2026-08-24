# CPA v7.2.137 Packaging and Contract Baseline

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: 1580f71d77cbb4bf58d3a734ae3a3994dfe2472478ed5f2dc1f18c86fa004b2d
```

This path is retained by the audit-bundle contract, but its contents describe
only the current CPA target. Historical Phase 0 version matrices are available
in Git history and are not shipped here as active validation guidance.

The root module and both isolated integration modules pin CPA v7.2.137 at commit
`85d2faddd17e6f4f8675a84ee28b131f702e8eaa`, module sum
`h1:CYYByMn7/NwnsCJEMiLI2F8kIJMTb5jRrLaIK6H0c0w=`, and go.mod sum
`h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=`. The official Linux amd64
archive is 21,072,175 bytes with SHA-256
`ae68c776e124dbc8c8c5b86c501fc6906efa180cc5e35383adb26d05c2c91401`;
the checksums file SHA-256 is
`9ae7dee90cd717a373acb58fad0163264891d5a76b27fb15d4c88bd10467012e`.
The extracted binary is 63,738,088 bytes with SHA-256
`aac02193aee085542f2452e02606a0ab0e3c3c65ace6216bd39bc48e733c37fa`.
This target uses C ABI 1 / RPC schema 3.
Current validation paths are:

- the official Host source and fail-open fixture contract;
- pinned-source compile, Interactions, and Store contracts;
- the Linux native Host and Router fixture targets;
- the CPA Store archive naming, root-layout, checksum, install, and overwrite
  contract.

See [CPA_INTEGRATION.md](CPA_INTEGRATION.md) for the active commands, exact
module checksums, last fully verified source baseline, and evidence boundary.
The owner-operated isolated CPA v7.2.137 Host + Mock-upstream record remains a
separate release requirement; source or CI compile checks do not authorize
production deployment.

The active CAG source is `1.0.0`, with planned prerelease tag `v1.0.0-rc.1` on
Linux amd64. This release line does not automatically follow later upstream CPA versions.
Host evidence uses prerelease attestation schema v2 fields `cpa_version`,
`cpa_commit`, and `cpa_host_sha256`.

Current Round 14 evidence is development-only. The repository-owned receipt
now records Linux `315/315 PASS` with zero skips for the audit-tool closure;
the prior 283-test receipt remains immutable historical evidence. Five targeted
schema-3 Host fixture tests, the targeted CAG RPC schema test in WSL, and one
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
