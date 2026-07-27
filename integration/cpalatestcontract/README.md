# CPA v7.2.102 source and compatibility contract

This isolated module is the source-contract half of the CPA compatibility gate.
The active contract has one exact, reviewed target:

| Profile | CPA | Commit | Module sum | `go.mod` sum |
|---|---|---|---|---|
| `primary` | `v7.2.102` | `8423cce2d1004e80948a9e2c60ee69354c0aabc3` | `h1:YimLZX/B4X5KA9v3Ss2afTmZtORYfT6UNMMteUKo+XA=` | `h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=` |

The checked-in root, latest-contract, and plugin-store contract modules all use
this same pin. `CPA_COMPAT_PROFILE` defaults to `primary`; every other value
fails closed. There is no active legacy CPA lane.

The tests require 28 named critical Host routing, lifecycle, cancellation,
cleanup, ownership, status, and metadata-sanitization contracts and then run
the complete upstream `internal/pluginhost` test suite for Linux. They also run
the official Responses namespace/custom `additional_tools` conversion contract,
two official Codex Responses Lite `additional_tools` role/shape contracts, and
14 official internal API/Interactions route and handler contracts, including
the current Codex Alpha Search routes, then apply three
checksum-pinned fixture overlays only to ephemeral copies of the selected
official CPA module: fail-open routing, Interactions handler/translator, and
Interactions direct-executor format. A fourth source-controlled Raw Capture
management overlay is compiled from this test module. The Raw Capture contract
resolves the selected CPA source through the same checked-in module identity as
every other contract. `scripts/cpa-latest-compat.sh` compiles the Guard and
integration packages against v7.2.102, explicitly tests `sdk/pluginabi` and
`sdk/pluginapi`, and runs the real Guard registration/route tests. Official
upstream test graphs use ephemeral modfiles; checked-in module
files are never rewritten.
With `CPA_COMPAT_VERIFY_REMOTE=1`, it verifies the exact Tag-to-Commit identity
through the official Git origin, the official Go module `Origin`, and both Go
sums. It needs no repository token. A PASS applies only to the fixed v7.2.102
identity. `CPA_COMPAT_REQUIRE_LATEST=1` is a separate, explicit upstream-drift
monitor that also queries the official unauthenticated GitHub `releases/latest`
endpoint; it is not part of the pinned compatibility claim.

`CPA_COMPAT_PROFILE=primary` is the only supported selection and is also the
default.

No CPA process is started, no Guard `.so` is loaded, and no Provider or account
is contacted. A PASS proves source and compile compatibility only; native Host,
Store installation, request reconstruction, logging, counted Mock behavior, and
upstream/usage isolation remain server-sandbox work. No profile is real Host or
counted Mock evidence. Independent audit is still required, production approval
has not been granted, and this contract does not authorize a stable `v0.16`.
