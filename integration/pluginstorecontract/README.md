# CPA v7.2.125 schema-2 plugin-store source contracts

This isolated Go module exists because the repository's main module cannot
legally import CPA's `internal/pluginstore` package. Its module path is under
the CPA v7 import prefix and its dependency is pinned exactly to `v7.2.125`
(`2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e`).

It contains source-level contract suites and checksum-pinned overlays:

- `archive_contract_test.go` exercises the official
  `pluginstore.InstallArchive` naming, ZIP-root layout, checksum, install,
  overwrite, and repeat-install behavior with opaque plugin bytes.
- `schema2_contract_test.go` binds ABI 1 / RPC schema 2, the three schema-2 RPC
  methods, termination response fields, and all four completion outcomes.
- `host_source_contract_test.go` runs CPA's official Host Router and schema-2
  RequestInterceptor/lifecycle tests after listing and pinning every required
  test name, and records the resolved tag commit, module checksum, and go.mod
  checksum. The current Guard combines schema-2 interception with a
  `codex-alpha-search`-only ModelRouter; the pure schema-1 Router tests remain a
  separate legacy compatibility contract.
- `testfixtures/host_failopen_overlay_test.go.txt` is copied into an ephemeral,
  checksum-verified CPA source tree. It exercises the real Host's priority,
  plugin-ID tie break, termination, missing/failed/disabled registration,
  interceptor error/panic fail-open, fuse, metadata sanitization, and request
  completion paths for a schema-2 RequestInterceptor + RequestLifecyclePlugin,
  and proves the current Guard can also register a narrowly gated Alpha Search
  ModelRouter without changing CPA production source. Its separately named
  legacy Router subtest is explicitly a schema-1 compatibility fixture.
- `testfixtures/release_rc_install_overlay_test.go.txt` binds the exact
  `v1.0.0-rc.1` tag/version/archive name, rejects stable-only assets and
  candidate-style root names for an RC install, proves both the unversioned
  root and exact RC-versioned root forms accepted by CPA, and performs a
  checksum-verified mocked `InstallVersion` whose installed bytes equal the
  audited payload.

The exact audited behaviors and limitations are recorded in
  [CPA_HOST_SOURCE_CONTRACT.md](CPA_HOST_SOURCE_CONTRACT.md).

These source suites never load or execute this project's `.so`. The repository
root is also pinned to CPA v7.2.125; native-host evidence is produced separately
by the integration-tagged Store-installed Host tests in GitHub CI. The pure-C
multi-Router test remains schema-1 compatibility evidence. Source-contract PASS
must not be reported as native-load PASS.

Run the source-level contract tests:

```bash
go test ./... -count=1
```

After release packaging has populated a distribution directory, verify the
real store ZIP, `checksums.txt`, standalone library, official install path, and
repeat-install behavior:

```bash
DIST_DIR=/absolute/path/to/dist go test ./... -run '^TestPublishedStoreArchive$' -count=1 -v
```
