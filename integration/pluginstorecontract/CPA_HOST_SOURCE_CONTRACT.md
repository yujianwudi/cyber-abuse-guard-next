# CPA v7.2.95 host routing source contract

This isolated module pins `github.com/router-for-me/CLIProxyAPI/v7` to
`v7.2.95` at commit `f71ec0eb6776854457892452cf28c47f0d658251`.
`host_source_contract_test.go` verifies the resolved module version, tag commit,
and both module checksums, lists the official `internal/pluginhost` tests,
requires a fixed set of critical names, and then runs only those exact tests.

Run only this contract:

```bash
go test -run TestOfficialCPAHostRoutingSourceContract -count=1 -v .
```

Run every contract in this isolated module:

```bash
go test -count=1 -v ./...
```

The upstream selection is intentionally broad enough to cover:

- descending Router priority and first handled match;
- same-priority ordering by ascending plugin ID;
- continuation after an unhandled response or Router error;
- panic recovery, plugin fuse, and fallback to the next Router;
- invalid, missing, or unavailable executor targets;
- executor readiness failures caused by a missing identifier, unsupported
  formats, or an OAuth-only scope.

`TestCPAHostFailOpenFixtureContract` then adds a test-only fixture to an
ephemeral copy of the checksum-verified upstream source. It covers guard-first
and competing-Router priority, plugin-ID tie breaks, guard load/register/enable
failure, fuse, Router error/panic, invalid targets, missing identifiers,
unsupported formats, disabled executors, and continuation to another Router or
native routing. No Host algorithm is copied into this repository.

This is source-level evidence only. It does not build, load, or execute a
Cyber Abuse Guard shared object, and it does not replace server-sandbox tests
of the compiled plugin, HTTP responses, Auth Selector, Usage, or upstream
isolation.

The separate `make cpa-router-fixture-blackbox` CI target builds
`integration/testfixtures/router_fixture.c` as a minimal second dynamic
Router/executor and exercises the public native ABI. That target is CI-only in
this handoff. Panic and fuse remain source-overlay evidence because a C plugin
cannot safely manufacture a recoverable Go panic or mutate the Host's private
fuse state.
