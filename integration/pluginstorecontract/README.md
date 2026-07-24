# CPA v7.2.95 plugin-store source contracts

This isolated Go module exists because the repository's main module cannot
legally import CPA's `internal/pluginstore` package. Its module path is under
the CPA v7 import prefix and its dependency is pinned exactly to `v7.2.95`
(`f71ec0eb6776854457892452cf28c47f0d658251`).

It contains three source-level contract suites:

- `archive_contract_test.go` exercises the official
  `pluginstore.InstallArchive` naming, ZIP-root layout, checksum, install,
  overwrite, and repeat-install behavior with opaque plugin bytes.
- `host_source_contract_test.go` runs CPA's official Host Router
  ordering/fallback tests after listing and pinning every required test name,
  and records the resolved tag commit, module checksum, and go.mod checksum.
- `testfixtures/host_failopen_overlay_test.go.txt` is copied into an ephemeral,
  checksum-verified CPA source tree. It exercises the real Host's priority,
  plugin-ID tie break, missing/failed/disabled registration, fuse, Router
  error/panic, invalid target, executor readiness, and native fallback paths
  without changing CPA production source.

The exact audited behaviors and limitations are recorded in
  [CPA_HOST_SOURCE_CONTRACT.md](CPA_HOST_SOURCE_CONTRACT.md).

These source suites never load or execute this project's `.so`. The repository
root is also pinned to CPA v7.2.95; native-host evidence is produced separately
by the integration-tagged Store-installed Host and pure-C multi-Router tests in
GitHub CI. Source-contract PASS must not be reported as native-load PASS.

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
