# CPA v7.2.159 Packaging and Contract Baseline

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: 974f05d1109bde75847b0063c3110c81944ddef249d9fdf8c374ddcd8c218683
```

This path is retained by the audit-bundle contract, but its contents describe
only the current CPA target. Historical Phase 0 version matrices are available
in Git history and are not shipped here as active validation guidance.

The root module and both isolated integration modules pin CPA v7.2.159 at commit
`ac02da6c05e18f465aa7e3ed5b0a65a2f060917d`, module sum
`h1:zDH2YS1ulYMyxIzUymJgvIAN+v9QUYaVvP8HKsiUmcA=`, and go.mod sum
`h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=`. The official Linux amd64
archive `CLIProxyAPI_7.2.159_linux_amd64.tar.gz` is 21,733,175 bytes with
SHA-256 `942d567a525d0f8dd0e78c2843cfefae7f553c0a385c859c20951b12d8a48218`;
the checksums file is `c3eb1364394232f933d74c9fa6855e49b7deb7eec3610d44ec45741f2c744f23`,
and the extracted binary is 65,704,424 bytes with SHA-256
`2acd787308dd9b67030157b82f05493ff5fd53f34cce2bfe159a8039d75a23b7`.
Historical v7.2.145 asset hashes are retained for audit comparison only
(`ffb59d406af9b849ec9174154d96642a1d3ccb315f8687c56ac55202816e9b37`,
`df71c910a0ceb83f67ada7c193a1b2d87f1bae955929d4a1d18fb4cf7f4b9d7c`,
`576a0555e5180c48a5cdf51ee92047a6ab78c363dfe612ea75925ba7f1ae1713`).
This target uses C ABI 1 / RPC schema 6.
Current validation paths are:

- the official Host source and fail-open fixture contract;
- pinned-source compile, Interactions, and Store contracts;
- the Linux native Host and Router fixture targets;
- the CPA Store archive naming, root-layout, checksum, install, and overwrite
  contract.

See [CPA_INTEGRATION.md](CPA_INTEGRATION.md) for the active commands, exact
module checksums, last fully verified source baseline, and evidence boundary.
The owner-operated isolated CPA v7.2.159 Host + Mock-upstream record remains a
separate release requirement; source or CI compile checks do not authorize
production deployment.

The active CAG source is `1.0.0`, with planned prerelease tag `v1.0.0-rc.3` on
Linux amd64. This release line does not automatically follow later upstream CPA versions.
Host evidence uses prerelease attestation schema v2 fields `cpa_version`,
`cpa_commit`, and `cpa_host_sha256`.

Current Round 17 evidence is development-only. The repository-owned receipt
now records Linux `320/320 PASS` with zero skips for the audit-tool closure;
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
