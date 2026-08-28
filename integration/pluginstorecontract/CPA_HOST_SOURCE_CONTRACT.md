# CPA v7.2.144 schema-4 Host source contract

This isolated module pins `github.com/router-for-me/CLIProxyAPI/v7` to
`v7.2.144` at commit `d36b776c790a4d58027fd4fb434800fb5334bceb`.
`host_source_contract_test.go` verifies the resolved module version, tag commit,
and both module checksums, lists the official `internal/pluginhost` tests,
requires a fixed set of critical names, and then runs the complete upstream
Host test suite for the current Linux platform. The fixed set includes schema-4
RequestInterceptor/lifecycle behavior, the current Guard's narrow Alpha Search
ModelRouter registration, and explicit schema-1 ModelRouter compatibility.

Run only this contract:

```bash
go test -run TestOfficialCPAHostRoutingSourceContract -count=1 -v .
```

Run every contract in this isolated module:

```bash
go test -count=1 -v ./...
```

The upstream selection is intentionally broad enough to cover:

- schema-4 RPC negotiation, RequestInterceptor priority/termination,
  error/panic fail-open, metadata sanitization, and completion lifecycle;
- descending Router priority and first handled match;
- same-priority ordering by ascending plugin ID;
- continuation after an unhandled response or Router error;
- panic recovery, plugin fuse, and fallback to the next Router;
- invalid, missing, or unavailable executor targets;
- executor readiness failures caused by a missing identifier, unsupported
  formats, or an OAuth-only scope;
- canceled load/register/unload/shutdown cleanup, blocked-call context
  detachment, retained load-token ownership, and `OwnsExecutor` adapter
  separation.

`TestCPAHostFailOpenFixtureContract` then adds a test-only fixture to an
ephemeral copy of the checksum-verified upstream source. The current Guard path
registers schema-4 RequestInterceptor and RequestLifecyclePlugin capabilities
plus a ModelRouter that handles only `codex-alpha-search`.
The fixture covers Guard/competing-interceptor priority, plugin-ID tie breaks,
termination, load/register/enable failure, fuse, interceptor error/panic
fail-open, metadata sanitization, and all four completion outcomes. Its official
Host `ApplyConfig` regression uses a CAG-shaped raw RPC double: after an initial
schema-4 activation, the simulated CAG lifecycle handler receives a
legacy-schema reconfigure and returns an OK envelope containing the retained
schema-4 RequestInterceptor and RequestLifecyclePlugin registration. The next
Host snapshot must still contain and invoke both capabilities. A paired negative
control returns an error envelope on the same Host path and proves that the
official Host then drops CAG from the next snapshot, so changing the retained
response to an error makes the positive contract fail. Production CAG's actual
legacy-schema response is independently pinned by
`internal/plugin.TestSchemaNegotiationRejectsLegacyAndAcceptsFutureHost`. A separately
named subtest preserves only the legacy schema-1 ModelRouter compatibility
contract. No Host algorithm is copied into this repository.

This is source-level evidence only. It does not build, load, or execute a
Cyber Abuse Guard shared object, and it does not replace server-sandbox tests
of the compiled plugin, HTTP responses, Auth Selector, Usage, or upstream
isolation.

The separate `make cpa-router-fixture-blackbox` CI target builds
`integration/testfixtures/router_fixture.c` as a minimal second dynamic
Router/executor and exercises the public native ABI. It remains a schema-1
compatibility fixture and is not evidence of the current Guard's schema-4
registration path. That target is CI-only in this handoff. Panic and fuse remain
source-overlay evidence because a C plugin cannot safely manufacture a
recoverable Go panic or mutate the Host's private fuse state.
