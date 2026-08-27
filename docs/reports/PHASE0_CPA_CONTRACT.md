# CPA v7.2.142 Packaging and Contract Baseline

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: a25cd83ea9a6d409a09a4bdd9aa75357ff989757272a006a4f60a32d77ad76db
```

This path is retained by the audit-bundle contract, but its contents describe
only the current CPA target. Historical Phase 0 version matrices are available
in Git history and are not shipped here as active validation guidance.

The root module and both isolated integration modules pin CPA v7.2.142 at commit
`1f53b2eb03b9e963bac647e5566ca2b304239116`, module sum
`h1:30twcgoSCSjBtc4tgZBKPC4sQpsEWwgu4d9r7tIDpQQ=`, and go.mod sum
`h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=`. The official Linux amd64
archive is 21,193,314 bytes with SHA-256
`a7cccc8f94b07660303c1874fb6bedae6d573a0f3c4c0b17ad8cf7885dd7a051`;
the checksums file SHA-256 is
`2a04364707aa7e8922c7ee35ad3b90437659c08fa4dbaa962f02b274993a0a6c`.
The extracted binary is 64,088,616 bytes with SHA-256
`e0df04ae5e632649c36230533d9608058dd09689113947809e4824f598f36a9b`.
This target uses C ABI 1 / RPC schema 3.
Current validation paths are:

- the official Host source and fail-open fixture contract;
- pinned-source compile, Interactions, and Store contracts;
- the Linux native Host and Router fixture targets;
- the CPA Store archive naming, root-layout, checksum, install, and overwrite
  contract.

See [CPA_INTEGRATION.md](CPA_INTEGRATION.md) for the active commands, exact
module checksums, last fully verified source baseline, and evidence boundary.
The owner-operated isolated CPA v7.2.142 Host + Mock-upstream record remains a
separate release requirement; source or CI compile checks do not authorize
production deployment.

The active CAG source is `1.0.0`, with planned prerelease tag `v1.0.0-rc.3` on
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
