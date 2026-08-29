# CPA v7.2.145 schema-4 source and compatibility contract

This isolated module is the source-contract half of the CPA compatibility gate.
The active contract has one exact, reviewed target:

| Profile | CPA | Commit | Module sum | `go.mod` sum |
|---|---|---|---|---|
| `primary` | `v7.2.145` | `d9cea8904b14fbbebb77ef26e98ef08f6b48a724` | `h1:5AG1q4MhRK+IU5oP5PPvm04AJYvEkj60br85jiBan5o=` | `h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=` |

The checked-in root, latest-contract, and plugin-store contract modules all use
this same pin. `CPA_COMPAT_PROFILE` defaults to `primary`; every other value
fails closed. There is no active legacy CPA lane.

The tests require a fixed set of named critical Host routing, schema-4 request
interception/lifecycle, cancellation, cleanup, ownership, status, and
metadata-sanitization contracts and then run
the complete upstream `internal/pluginhost` test suite for Linux. They also run
the official Responses namespace/custom `additional_tools` conversion contract,
two official Codex Responses Lite `additional_tools` role/shape contracts, and
15 official internal API/Interactions route and handler contracts, including
the current Codex Alpha Search routes, plus nine official Home unauthorized-
refresh/retry contracts from `sdk/cliproxy/auth`, then apply four
checksum-pinned fixture overlays only to ephemeral copies of the selected
official CPA module: schema-4 fail-open request interception/lifecycle plus the
narrow Alpha Search ModelRouter capability, Interactions handler/translator,
Interactions request-lifecycle format, and a non-streaming Home 401 handler
contract that proves one after-auth callback and one completion around two
executor attempts sharing the same logical lifecycle. Stream retry mechanics
remain covered by the named official upstream tests. A fifth source-controlled
Raw Capture schema-4 transport and response-budget
management overlay is compiled from this test module. The Raw Capture contract
resolves the selected CPA source through the same checked-in module identity as
every other contract. `scripts/cpa-latest-compat.sh` compiles the Guard and
integration packages against v7.2.145, explicitly tests schema-4
`sdk/pluginabi` and `sdk/pluginapi`, and runs the real Guard registration and
focused behavior tests. Official
upstream test graphs use ephemeral modfiles; checked-in module
files are never rewritten.

The production-watchdog request-log proof is a separate source-only contract.
It resolves the checksum-pinned v7.2.145 module with `GOPROXY=off`, parses the
upstream Go syntax without compiling or executing upstream packages, and locks
the startup-only commercial-mode middleware installation, reload-time
`RequestLog` toggle behavior, disabled-logger error-only body capture,
management-path exclusion, request-error-log route and inventory fields, and
the management build-identity response headers.
With `CPA_COMPAT_VERIFY_REMOTE=1`, it verifies the exact Tag-to-Commit identity
through the official Git origin, the official Go module `Origin`, and both Go
sums. It needs no repository token. A PASS applies only to the fixed v7.2.145
identity. `CPA_COMPAT_REQUIRE_LATEST=1` is a separate, explicit upstream-drift
monitor that also queries the official unauthenticated GitHub `releases/latest`
endpoint; it is not part of the pinned compatibility claim.

`CPA_COMPAT_PROFILE=primary` is the only supported selection and is also the
default. Every external Go command is bounded by `CPA_COMPAT_COMMAND_TIMEOUT`
(default `5m`, accepted range `1s`–`10m`); the complete cpalatest/pluginstore
command uses the explicit `CPA_COMPAT_FULL_COMMAND_TIMEOUT` budget (default
`10m`, accepted range `1s`–`10m`); the complete cpalatest/pluginstore lane is
separately bounded by `CPA_COMPAT_LANE_TIMEOUT` (default `25m`,
accepted range `1m`–`45m`). The lane also requires Linux
amd64 and clears Git repository-routing variables before resolving the pinned source.
It also forces `GOENV=off` and the public `GOPROXY` value so caller Go settings
cannot redirect the compatibility lookup.
When invoked by the shell lane, `CPA_COMPAT_GO_BINARY` carries the already
validated absolute Go tool path into every child command; a missing value falls back
to the local `PATH` only for standalone development runs.
CPA_COMPAT_GOSUMDB=off is permitted only for an explicitly offline local
development run with a warm, checksum-verified module cache; CI and release checks
must leave it unset so sum.golang.org verification remains active.

No CPA process is started, no Guard `.so` is loaded, and no Provider or account
is contacted. The lane does execute the checksum-pinned official CPA test
packages in the isolated Linux build environment; it never executes files from
the five untrusted jailbreak repositories. A PASS proves source and compile compatibility only; native Host,
Store installation, request reconstruction, logging, counted Mock behavior, and
upstream/usage isolation remain server-sandbox work. No profile is real Host or
counted Mock evidence. Independent audit is still required, production approval
has not been granted, and this source contract alone does not authorize planned
`v1.0.0-rc.3` or any stable release.
