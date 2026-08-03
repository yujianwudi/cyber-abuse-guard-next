# CPA v7.2.116 schema-2 active contract and frozen v7.2.113/v7.2.109/v7.2.104/v7.2.103/v7.2.102 validation

```text
current_classifier_policy_version: classifier-policy-v10
current_classifier_policy_sha256: 7934e15f95b8bb617f683507c7739d62c12b508961d0b2c3f3e39ead19cda3c2
```

## Active compatibility target

Cyber Abuse Guard pins the current source/compile lane to one exact
identity of `github.com/router-for-me/CLIProxyAPI/v7`:

- formal target: `v7.2.116` at
  `a88197f845c979132c8978ea223c6af05cc81536`, C ABI 1 / RPC schema 2.

The checked-in module layout is:

- root `go.mod`: v7.2.116 primary;
- `integration/cpalatestcontract/go.mod`: v7.2.116;
- `integration/pluginstorecontract/go.mod`: v7.2.116 Store reference.

The reviewed module identities are:

```text
primary_module_sum: h1:dGGI/CeEQTyKkFNeeqMoIyK/mWx5hVaQlZLDiHPoBTU=
primary_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
upstream_linux_amd64_asset: CLIProxyAPI_7.2.116_linux_amd64.tar.gz
upstream_linux_amd64_sha256: 469adcf760936764781687cfc7057f8ca0db3a685d418dd3d9d84cb1910bde3b
```

`CPA_COMPAT_PROFILE=primary` is the only accepted profile and is the release
default. Old observations remain historical and are not current Host evidence.
The upstream asset hash records the standard release input identity only; this
documentation update did not download or execute it and does not turn it into a
CAG artifact, Host result, watchdog result, or release PASS. The working-tree
Linux amd64 / Go 1.26.4 pinned source/compile matrix now passes with the fixed
module Origin and sums, including the Home retry lifecycle overlay and the
no-UsagePlugin registration check. The latest-Release and tag-ref APIs observed
v7.2.116 at `a88197f845c979132c8978ea223c6af05cc81536`, whose commit verification is
valid; the official Git endpoint timed out in two bounded local runs, so the
script's exact remote Git gate remains a GitHub CI requirement. Exact-commit
CI, Host, watchdog, sandbox, and production results remain **PENDING**.
The top `current_classifier_policy_*` prologue identifies the active working
tree; it does not replace the frozen v7.2.113 classifier identity below.

## Reviewed v7.2.113-to-v7.2.116 compatibility delta

The reviewed upstream range leaves C ABI 1, RPC schema 2, and all 235 scoped
plugin blobs byte-identical. The relevant behavior changes sit outside that
frozen plugin surface:

- Home may handle an OAuth 401 by refreshing the selected credential and
  retrying at most once within the same logical request. The retry reuses the
  request after its request-interceptor pass; it is not a second CAG request
  lifecycle.
- CPA invokes request interceptors before executor translation. Claude derives
  its final upstream wire headers afterward, so those generated headers are not
  part of the representation CAG fingerprints at the interceptor boundary.
- CAG advertises RequestInterceptor and request-lifecycle capabilities but does
  not register `UsagePlugin`. Home's result-only zero-token usage record is an
  upstream accounting event and does not add a CAG callback.

These observations explain the integration boundary; they are not a v7.2.116
test PASS. The checked-in contract names the new upstream Home-401 tests so the
future compatibility run fails closed if that behavior disappears.

## Frozen 2026-07-29 validation status — engineering PASS, safety FAIL

The last committed isolated-audit baseline is the exact audited commit
`150c25e6352cb237cb3956bd66c83c3278c3fe33`, classifier
historical classifier digest `e0cbc975...`,
and CPA `v7.2.104@c9417c8ae9b16fabc0386ca35d36f13bf8b1d678`. GitHub Actions
run `30353591705` passed the engineering matrix for that exact baseline. It did
not pass the safety gate: the isolated audit returned `FAIL / BLOCKED` with
287 complete malicious fail-open cases, 36 malicious incomplete HTTP 403
cases, and 2 complete benign false positives.

Historical 2026-07-29 evidence identified the remediation source as
`classifier-policy-v10` /
`db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594`.
No commit-bound CI or second-machine retest was then available for that
remediation. That historical CPA integration and release state therefore
remained
`BLOCKED`; the engineering PASS for `150c25e6` cannot be relabeled as a safety,
Host-release, or production PASS.

## Active validation commands

Only the following CPA validation paths are supported:

```bash
make cpa-host-fixture-contract
CPA_COMPAT_PROFILE=primary CPA_COMPAT_VERIFY_REMOTE=1 make cpa-latest-compat
make cpa-host-blackbox
make cpa-router-fixture-blackbox
make round6-cpa-store-contract
```

With `CPA_COMPAT_VERIFY_REMOTE=1`, the compatibility contract verifies the
fixed Git tag-to-commit identity directly against the official Git origin and
binds the Go module Origin plus both checksums. All checked-in modules use the
same v7.2.116 identity. No repository token is used. The target is intentionally
pinned, so a later upstream Release does not silently change the supported
source or Host target. Upstream-latest monitoring is separate and explicit:
the required CI compatibility lane uses `CPA_COMPAT_VERIFY_REMOTE=1` with
`CPA_COMPAT_REQUIRE_LATEST=0`, preserving exact tag/commit verification without
coupling the supported pin to GitHub's moving latest Release.
`CPA_COMPAT_REQUIRE_LATEST=1` additionally queries the official unauthenticated
GitHub `releases/latest` endpoint and fails when the fixed target is no longer
latest; that monitoring result does not invalidate compatibility with the
reviewed v7.2.116 pin.
`ALLOW_DIRTY_BUILD=1` is a development-only override and is not release
evidence.

## Frozen v7.2.113 final exact-main engineering baseline

The final v7.2.113 baseline is
`main@a9fba4e32bfa8f7ce4b5db35e69183400c3de5b4`, pinned to
`v7.2.113@bc71c77f5cc42f3fbe1bf040cf14d4f166894835` with module sum
`h1:Aj3J7zI5VxyKpsHbG6+ChVpeW4QGkcJ+ZwWWnWmuChA=`. The retained repository
record marks its pinned local Linux source/ABI/RPC schema-2 compatibility as
**HISTORICAL PASS** and the candidate `.so` Host/container lifecycle plus
counted-Mock routing as **NOT_PROVIDED**. GitHub's exact-commit checks are frozen
as engineering PASS:

- [CI `30851294941`](https://github.com/yujianwudi/cyber-abuse-guard-next/actions/runs/30851294941);
- [Policy and Corpus Gate `30851294902`](https://github.com/yujianwudi/cyber-abuse-guard-next/actions/runs/30851294902);
- [CodeQL `30851294956`](https://github.com/yujianwudi/cyber-abuse-guard-next/actions/runs/30851294956).

Those results remain bound to v7.2.113, that exact main commit, and the bytes
produced by its CI. They are not v7.2.116 evidence and do not establish an
independent audit, protected sandbox, or production approval. No checked-in
report or GitHub-attested artifact in this repository binds a second-machine
watchdog execution to `a9fba4e`; that item remains **NOT_PROVIDED** and is not
called PASS here.

## Frozen v7.2.109 exact-main engineering baseline

The immediately preceding active contract was
`v7.2.109@928478e4b91533cec05a763bfac3edad9c3e76cf`. Exact-main commit
`2b9762f80ca60b721ddda523cdc54b9a14fdc9e3` passed CI, Policy Gate, and
CodeQL for that identity. Its later owner-run second-machine diagnostic matrix
remained a safety FAIL and is not v7.2.113 evidence. The v7.2.113 lane must
rebuild and rerun independently.

## Frozen v7.2.104 exact-main engineering baseline

Before v7.2.109 was published, exact main commit
`46f26f9f822683aebb14b2c812ced2246d680fc2` completed GitHub Actions CI run
[`30482492205`](https://github.com/yujianwudi/cyber-abuse-guard-next/actions/runs/30482492205)
against `v7.2.104@c9417c8ae9b16fabc0386ca35d36f13bf8b1d678` and policy identity
`e7a00b02d7e0e4ca837204cfed476b4f371f599facbf546e342362370111ec14`.
Policy run `30482486027` and CodeQL run `30482486178` also passed. This is
engineering source, SDK/API, Linux Host-load, and test evidence only for that
exact CPA v7.2.104 identity. It is not protected counted-Mock, independent
audit, external evaluation, production, or Release evidence, and it is not
promoted to a v7.2.109 PASS. The v7.2.109 lane must rebuild and rerun
independently.

## Frozen v7.2.103 exact-main baseline

Before v7.2.104 was published, exact main commit
`1a64639c0bac7a157d8201c1593bd68cf6e7fe11` completed GitHub Actions CI run
[`30327322793`](https://github.com/yujianwudi/cyber-abuse-guard-next/actions/runs/30327322793)
against `v7.2.103@cade44b9cdee6b9328ea2648fd119129fdf11e2d`.
The run passed the pinned source/SDK contracts, real Linux Host candidate `.so`
load and registration, Router fixture matrix, artifact checks, clean-tree gate,
and clean-clone reproducibility; Round 9 policy run `30327322810` and CodeQL run
`30327322801` also passed. The candidate `.so` SHA-256 was
`27bb6cc378b315e0d80c4ed3f31b70db64ce6ce49459a2dda17bfa8429bc268b`;
Actions artifact ID `8676831297` had upload digest
`sha256:e2140b0d3e6a20aff866838aa3ddbda89a23fca7ebd8937e0607cb4aa15e2370`.
This is admissible evidence only for the exact v7.2.103 identity and candidate
bytes produced by that run. It is not protected counted-Mock, independent audit,
external evaluation, production, or Release evidence, and must not be relabeled
as a v7.2.104 PASS. The later v7.2.104 baseline passed engineering CI at
`150c25e6` but failed the isolated safety audit described above; the current
remediation still requires a new exact-commit CI and second-machine retest.

## Historical v7.2.102 development validation

On 2026-07-27, Linux amd64 validation under WSL Ubuntu 26.04 and Go 1.26.4
completed against the then-current `v7.2.102` target at
`8423cce2d1004e80948a9e2c60ee69354c0aabc3`. A remote-enabled attempt verified
that GitHub `releases/latest` and the official tag both resolved to that identity
before the local Git transport later became unavailable. The complete
compatibility matrix was then rerun to success with the same historical module
Origin, module checksum, and go.mod checksum while using the reachable
`goproxy.cn` SumDB mirror and skipping only the already-proven live Git checks.
Both nested compatibility modules asserted the named critical Host tests and
each executed the complete upstream `internal/pluginhost` package; this
intentionally overlapping coverage is not a pair of non-duplicative exact-name
runs. SDK `pluginabi`/`pluginapi`, Interactions, Raw Capture, and Store contracts
also passed. This is split local development evidence, not one uninterrupted
remote-enabled run or exact-main CI evidence.

`GOTOOLCHAIN=go1.26.4 ALLOW_DIRTY_BUILD=1 make integration-test` then exited 0.
It built a development-only `0.16-dirty` Linux amd64 `.so`, installed it through
the real CPA v7.2.102 Store, loaded it through the real Host, and passed
`TestCPAPluginHostBlocksBeforeUpstream` in 33.359 seconds. The matrix covered
safe and blocked stream/nonstream requests, encoded current-user carriers,
inert historical assistant tool-call payloads, explicit current-user harmful
restatements, incident-response safe-review controls, independently complete
request-local system/terminal-tool malicious candidates, opaque audio, usage
accounting, and pre-upstream side-effect assertions. Those system/tool results
are direct candidate evaluation, not bare-referent promotion: only the newest
eligible trusted RoleUser review may be reactivated by a bare current-user
referent, while assistant/system/tool/unknown history, tool schemas, and assistant
tool-call arguments remain ineligible. Every checked-in isolated Router fixture
scenario also passed, and the combined Make target returned success.

These are local working-tree development results tied to a dirty development
artifact. They are real CPA Host execution with loopback fixtures and a Mock
upstream, but they are not clean exact-main CI, a protected external evaluation,
an independently audited artifact, a release candidate, or production approval.

## Frozen v7.2.95 development snapshot

The following 2026-07-24 Linux development run is a frozen historical snapshot.
It used Go 1.26.4 and `CPA_COMPAT_VERIFY_REMOTE=1`. It verified the exact
v7.2.95 tag commit, the official module Origin, and the then-pinned module/go.mod
sums before completing the primary source/compile matrix. The historical
upstream delta to v7.2.95 did not change
`sdk/pluginabi` or `sdk/pluginapi`, and the Guard required no API adaptation.
The primary module's
transitive dependency graph did move `github.com/tiktoken-go/tokenizer` from
v0.7.0 to v0.8.1 and `github.com/dlclark/regexp2` v1 to
`github.com/dlclark/regexp2/v2` v2.5.1; the checked-in root module files reflect
that reviewed upstream change. These results remain frozen development
self-checks, not current v7.2.113, exact-main, or Host evidence.

The pinned compatibility rerun is retained as
`dist/round9-worklogs/cpa-v7.2.95-pinned-compat-go1.26.4-20260724.log`
(59657 bytes, SHA-256
`748eb1ecdaa79c2b2ccfd07c5b55be3bf9a56ab8ecd1e19b152d12bc43ed8eae`).
The separate `CPA_COMPAT_REQUIRE_LATEST=1` monitoring probe observed the
official latest Release as v7.2.97 and therefore failed as designed. That
result did not invalidate the then-selected v7.2.95 compatibility pin; neither
historical observation overrides the then-current formal v7.2.113 identity.

## Coverage

The current single-primary-profile matrix covers:

- Guard compilation, schema-2 registration, request interception, direct
  termination, and request lifecycle contracts;
- official Host RequestInterceptor priority/header chaining, before/after-auth
  termination, error skip, panic fuse, completion, and metadata-sanitization
  contracts, plus an explicit legacy schema-1 Router compatibility lane;
- official Home 401 refresh/retry contracts for one same-selection retry,
  concurrent newer-token reuse, no replay after a stream has started, and
  same-logical-request lifecycle ownership;
- Claude final upstream wire-header construction after the request-interceptor
  boundary, plus the explicit fact that CAG does not register `UsagePlugin`;
- checksum-pinned fail-open overlays applied only to an ephemeral CPA source
  copy;
- Interactions route, handler, translator, auth-selection, and direct-executor
  format contracts;
- Raw Capture management-response transport and HTML-sanitization contracts on
  the pinned CPA v7.2.116 source;
- official v7.2.116 Responses continuation selectors for
  `previous_response_id`, Gemini interactions function calls and response-name
  backfill, and Gemini-to-OpenAI FIFO/fallback/explicit-ID translation paths;
- CPA Store archive naming, root layout, checksum, installation, repeat-install,
  overwrite, and published-artifact identity;
- a native Linux integration target for plugin load and pre-upstream blocking;
  the frozen v7.2.113 final baseline passed exact-main engineering checks, but
  v7.2.116 must rebuild and rerun independently;
- a second pure-C Router/executor fixture for priority, tie-break, fallback, and
  target-readiness scenarios; the frozen v7.2.113 final baseline remains
  historical, and v7.2.116 exact-commit evidence is pending.

The shared test fixtures under `integration/pluginstorecontract/testfixtures/`
remain the current v7.2.116 contract inputs. The pure-C schema-1 Router fixture
is deliberately retained as a named legacy compatibility lane; it is not the
production Guard enforcement path.

For the historical 2026-07-27 v7.2.102 working tree, the nested `integration/cpalatestcontract`
module and the complete remote-enabled compatibility matrix passed with Linux
Go 1.26.4. The official tag, commit, module Origin, and checksums were verified;
the initial timeout is retained only as failed-attempt history. A clean
exact-main rerun is still required because working-tree results cannot be
transferred to a future commit.

## Historical pre-cleanup baseline (not the current RC target)

The merged Round 6 source is:

```text
main_commit: 6782dfaffd4da3f09604113c7d38675f331dc759
source_tree: a8edbe2e6d19fa725fb962cdd6aaad5b416d4b85
public_source_only_prerelease_tag: v0.15-rc.1
attached_release_assets: none
private_untagged_clean_candidate: not created
formal_tag_v0.15: absent / blocked
historical_classifier_policy_version: classifier-policy-v3
historical_classifier_policy_sha256: 1294c6fd587522829d07220d5a6f4214092eba6ce1837636da5b3e3d461ba2a3
```

GitHub Actions validation for that exact commit passed:

- main push CI `29630844605`;
- tag push CI `29630926354`.

Both runs passed the quality/artifact job, long fuzz job, and clean-clone
reproducibility job. The matrix included v7.2.86 latest-source compatibility,
Host source/fail-open contracts, Round 4/5/6 regressions, unit and race tests,
vet, fuzz, benchmarks, vulnerability checks, Linux build, artifact hashing,
Store validation, integration compilation, and clean-tree verification. It did
not run the native Host black-box or pure-C Router fixture targets.

These commit, asset, and older CPA statements are retained only as historical
baseline evidence. The current contract is fixed to CPA v7.2.116; exact
tag/commit/tree, current CI, 17 asset hashes, and RC-versioned integration
results are recorded at runtime in `rc-release-evidence.md` and
`rc-release-manifest.json` rather than self-recorded in this source file.
The immutable RC3 attempt (run 29728286559) failed before packaging and produced
no Actions artifact or GitHub Release; it is not reused as RC4 evidence.

## Evidence boundary

Source contracts, fixture contracts, and local real-Host dirty-development PASS
do not replace the owner-operated isolated server sandbox. No local validation in
this report is a claim that a production CPA process, real Provider, account
pool, or production traffic was used.

The remaining protected server evidence must load the clean exact Linux artifact
in CPA v7.2.116 with a counted Mock upstream and reproduce zero deltas for
locally blocked requests at Auth Selector, Provider execution, usage accounting,
and Mock-upstream request layers. The local development blackbox proves a
narrower boundary for its dirty `.so`: safe requests carry a CPA
credential-selection trace and cross Provider/Mock execution, while blocked
requests have no such trace and leave Provider, Usage, and Mock Upstream
unchanged. It does not supply the protected counted Auth
Selector delta and cannot be promoted to the future clean commit or external
evaluation.

The v0.16-rc.2 manifest schema 4 records both source identities and the explicit
release phase. Phase 1 packages a private 17-asset Host-test candidate with both
counted-Mock states still `NOT_RUN / HOST_TEST_REQUIRED`. Phase 2 accepts only a
closed-schema `round8-host-evidence.json` bound to the same reproduced candidate
SO hash, records counted-Mock `PASS` for each CPA identity, and packages the
evidence plus sidecar in the exact 19-asset prerelease. This evidence must also
carry per-lane Chat/Responses 1/0 upstream deltas, 42/42 benign and paired
malicious matrices, stream/nonstream and audit/balanced/strict coverage,
quick-check/WAL and restart-cycle facts, plus zero unexpected restart/OOM/error
counters. The same closed object covers Balanced-incomplete allow,
Strict-incomplete block, usage-queue allow/blocked deltas, and Raw Capture
only-blocked, TTL dedup, schema-v3 redaction metadata, and purge/WAL checks. A
bare `PASS` is rejected. It must also state that no real Provider was contacted
and production was not accessed.

The supported platform for this release line is Linux amd64. Windows, macOS,
and musl/Alpine validation are outside scope. Local dirty-development Host PASS
is not protected external Host evidence; independent audit is still required,
production approval has not been granted, and no stable v0.16 exists.
