# CPA v7.2.144 schema-4 plugin-store source contracts

This isolated Go module exists because the repository's main module cannot
legally import CPA's `internal/pluginstore` package. Its module path is under
the CPA v7 import prefix and its dependency is pinned exactly to `v7.2.144`
(`d36b776c790a4d58027fd4fb434800fb5334bceb`).

It contains source-level contract suites and checksum-pinned overlays:

- `archive_contract_test.go` exercises the official
  `pluginstore.InstallArchive` naming, ZIP-root layout, checksum, install,
  overwrite, and repeat-install behavior with opaque plugin bytes.
- `schema4_contract_test.go` binds ABI 1 / RPC schema 4, the request lifecycle
  RPC methods, stream-chunk interception fields, termination response fields,
  and all four completion outcomes.
- `host_source_contract_test.go` runs CPA's official Host Router and schema-4
  RequestInterceptor/lifecycle tests after listing and pinning every required
  test name, and records the resolved tag commit, module checksum, and go.mod
  checksum. The current Guard combines schema-4 interception with a
  `codex-alpha-search`-only ModelRouter; the pure schema-1 Router tests remain a
  separate legacy compatibility contract.
- `testfixtures/host_failopen_overlay_test.go.txt` is copied into an ephemeral,
  checksum-verified CPA source tree. It exercises the real Host's priority,
  plugin-ID tie break, termination, missing/failed/disabled registration,
  interceptor error/panic fail-open, fuse, metadata sanitization, and request
  completion paths for a schema-4 RequestInterceptor + RequestLifecyclePlugin,
  and drives a CAG-shaped raw RPC double through two official Host
  `ApplyConfig` calls to prove a rejected legacy-schema reconfigure must return
  the retained registration instead of an error envelope or a fail-open
  snapshot removal. A paired production CAG unit contract owns the actual
  legacy-schema rejection response,
  and proves the current Guard can also register a narrowly gated Alpha Search
  ModelRouter without changing CPA production source. Its separately named
  legacy Router subtest is explicitly a schema-1 compatibility fixture.
- `testfixtures/release_rc_install_overlay_test.go.txt` binds the exact
  `v1.0.0-rc.3` tag/version/archive name, rejects stable-only assets and
  candidate-style root names for an RC install, proves both the unversioned
  root and exact RC-versioned root forms accepted by CPA, and performs a
  checksum-verified mocked `InstallVersion` whose installed bytes equal the
  audited payload.

The exact audited behaviors and limitations are recorded in
  [CPA_HOST_SOURCE_CONTRACT.md](CPA_HOST_SOURCE_CONTRACT.md).

These source suites never load or execute this project's `.so`. The repository
root is also pinned to CPA v7.2.144; native-host evidence is produced separately
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
