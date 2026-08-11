# CPA Cyber Abuse Guard

## Current v1.0.0-rc.1 candidate

```text
current_source_version: 1.0.0
current_rc_tag: v1.0.0-rc.1
current_rc_plugin_store_asset: cyber-abuse-guard_1.0.0-rc.1_linux_amd64.zip / root cyber-abuse-guard.so / audited payload reuse
current_cpa_target: v7.2.125 / 2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e
current_cpa_contract: C_ABI_1 / RPC_SCHEMA_2
current_platform: linux-amd64
current_classifier_policy_version: classifier-policy-v18
current_classifier_policy_sha256: 64da89df5f207893b45d4d7a32100d76025483ef3dc4003fbfe295b4e4c7ba82
current_status: IMPLEMENTATION_IN_PROGRESS / ACCEPTANCE_INCOMPLETE / NO_MERGE / NO_RELEASE
```

Cyber-Abuse-Guard Next is a native policy and audit plugin for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI). The active work is
defined by the [Round 13 task book](docs/ROUND13_CPA_V7_2_125_V1_RC1_TASK_BOOK.md)
and [status overlay](docs/ROUND13_STATUS.md). It prioritizes zero false blocks
for normal, defensive and authorized requests while blocking explicit,
unambiguously unauthorized harmful execution. `v1.0.0-rc.1` is a planned
prerelease, not a stable production approval.

The Round 12 block retained below is historical v7.2.124 evidence. It does not
override the Round 13 identity or transfer a PASS to CPA v7.2.125.

<!-- round12-status:start -->
```text
round12_status: IMPLEMENTATION_IN_PROGRESS / ACCEPTANCE_INCOMPLETE / NO_RELEASE
round12_baseline_main: 21267e742b624b29a75bd3683fd6914f76c764b5
round12_baseline_tree: 6272ac0ba818d39b89481db1f8e360e9b262fde6
round12_cpa_target: v7.2.124 / 197f520426374e514218ed155933ac546c98d345
round12_cpa_linux_asset_sha256: bb1597e5faa19bd67f4cecb88e14d6306f7f54bffdeedf2d0b973d7cfb5dc176
round12_cpa_contract: C_ABI_1 / RPC_SCHEMA_2 / UNCHANGED_FROM_V7.2.116
round12_go_platform: go1.26.4 / linux-amd64
round12_baseline_engineering_ci: PASS / HISTORICAL_V7.2.116_EXACT_MAIN_ONLY / NOT_TRANSFERABLE
round12_working_candidate_engineering_ci: PENDING_EXACT_V7.2.124_CANDIDATE
round12_input_second_machine_report: HISTORICAL_V7.2.116_DIAGNOSTIC_ONLY / NOT_TRANSFERABLE
round12_final_candidate_second_machine: PENDING_EXACT_V7.2.124_CANDIDATE_EXECUTION
round12_multi_agent_v2_responses_regression: PENDING
round12_protected_host: NOT_PROVIDED
round12_independent_attestation: NOT_PROVIDED
round12_production_approved: NOT_PROVIDED
round12_release_ready: NOT_PROVIDED
round12_tag_and_release: NOT_CREATED / NOT_AUTHORIZED
legacy_v0.15_availability: UNAVAILABLE
legacy_v0.15_support: SUSPENDED
```
<!-- round12-status:end -->

The Round 12 block above and [Round 12 status](docs/ROUND12_STATUS.md) are a
frozen historical snapshot. Only the Round 13 identity at the top of this file
and [Round 13 status](docs/ROUND13_STATUS.md) define the current boundary.

> **Repository lineage:** this is the clean-history successor project. The
> previously documented legacy repository
> [`yujianwudi/cyber-abuse-guard`](https://github.com/yujianwudi/cyber-abuse-guard)
> and its `v0.15` Release are currently unavailable (GitHub API `404`, verified
> 2026-08-04). Historical identities remain records, but their assets are not
> claimed to be downloadable or independently verifiable until a read-only
> repository or signed immutable archive is restored.

> **Current development state:** `main` is the sole maintained source line. The
> fixed source/compile target is CPA `v7.2.125` at
> `2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e` with C ABI 1 and RPC schema 2
> only. GitHub
> Actions performs CI, CodeQL, policy/corpus validation, and an explicitly
> gated Linux RC publication path. Server-side sandbox diagnostics remain owner-run
> and are not independent evidence.
> Production approval has not been granted, and production Balanced must remain
> gated.
>
> Historical exact `main@21267e742b624b29a75bd3683fd6914f76c764b5` passed CI
> `30880739397`, Policy and Corpus Gate `30880739368`, and CodeQL
> `30880739360` for CPA v7.2.116. A later owner-run 1,320-execution CPA v7.2.116 second-machine
> run is retained only as `SECOND-MACHINE DIAGNOSTIC / NOT INDEPENDENT
> ATTESTATION`; it does not close protected-Host, independent-audit, release, or
> production gates. Those CI and second-machine results are historical v7.2.116
> evidence and are not relabelled as v7.2.124. RT12-05/06 execution against an
> exact v7.2.124 final candidate is still `PENDING_FINAL_CANDIDATE_EXECUTION`.
>
> The frozen CPA v7.2.113 Round 11 line started at exact `main` commit
> `aaa71d9924bef935196790976c838968408dcdeb` and ended at
> `a9fba4e32bfa8f7ce4b5db35e69183400c3de5b4`. Exact-final CI
> `30851294941`, Policy and Corpus Gate `30851294902`, and CodeQL
> `30851294956` succeeded. Those engineering results remain v7.2.113 history;
> v7.2.116 required its own checks; those results are now historical, and no
> v7.2.124 second-machine watchdog PASS is claimed.
> Engineering CI is not a Host, independent-audit, sandbox, or production PASS.

> [!CAUTION]
> The exact committed baseline `150c25e6352cb237cb3956bd66c83c3278c3fe33`
> with classifier `classifier-policy-v9` /
> historical digest `e0cbc975...`
> and CPA `v7.2.104@c9417c8ae9b16fabc0386ca35d36f13bf8b1d678` passed engineering
> CI run `30353591705`, but the isolated safety audit **FAILED / BLOCKED**:
> 287 complete malicious cases failed open, 36 malicious incomplete cases
> returned HTTP 403, and 2 complete benign cases were false positives. The
> last CPA v7.2.104 remediation identity was `classifier-policy-v9` /
> `e7a00b02d7e0e4ca837204cfed476b4f371f599facbf546e342362370111ec14`;
> exact-commit GitHub checks passed, while the second-machine retest remained
> **PENDING**. Round 10 added bounded historical-tool activation, persistent
> audit readiness, atomic coverage attribution, and direct-compaction boundary
> fixes on the CPA v7.2.113 target. Those behavior changes bind
> `db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594` and
> exact `main` commit `aaa71d9924bef935196790976c838968408dcdeb`; engineering
> runs `30697468074`, `30697468078`, and `30697468079` succeeded. Isolated
> sandbox revalidation remains **PENDING**. The later Round 11 runtime-assurance
> work is frozen at CPA v7.2.113 / `main@a9fba4e`; it is not v7.2.124 evidence.

[![CI](https://github.com/yujianwudi/cyber-abuse-guard-next/actions/workflows/ci.yml/badge.svg)](https://github.com/yujianwudi/cyber-abuse-guard-next/actions/workflows/ci.yml)
[![Policy Gate](https://github.com/yujianwudi/cyber-abuse-guard-next/actions/workflows/policy-gate.yml/badge.svg)](https://github.com/yujianwudi/cyber-abuse-guard-next/actions/workflows/policy-gate.yml)
[![CodeQL](https://github.com/yujianwudi/cyber-abuse-guard-next/actions/workflows/codeql.yml/badge.svg)](https://github.com/yujianwudi/cyber-abuse-guard-next/actions/workflows/codeql.yml)
[![Go](https://img.shields.io/badge/Go-1.26.4-00ADD8?logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64-lightgrey)](docs/ROUND6_LIMITATIONS.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**A local, deterministic, pre-routing cyber-abuse request guard for
[CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (CPA).**

English | [简体中文](README_CN.md)

> [!WARNING]
> [`v0.15`](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.15)
> was historically reported as a manually published stable release on
> 2026-07-20, but the repository, Release and ten assets now return `404`.
> Security support and rollback claims are therefore **SUSPENDED / UNAVAILABLE**
> until the original bytes and digests are restored in a verifiable read-only
> location. Retained Round 6 and `v0.15-rc.*` text is historical engineering
> evidence, not a substitute for those missing assets.

When CPA has loaded and registered the plugin, the schema-2 before-auth request
interceptor inspects supported model requests before authentication scheduling,
provider execution, usage accounting, SSE establishment, and upstream work.
Blocked requests terminate directly with HTTP 403; the legacy self-executor is
retained only as defense in depth. Request content is evaluated in process and
is not sent to a public classifier.

## Historical v0.16 / Round 12 snapshot

The following table is retained for audit continuity. Its uses of "current" or
"active" refer only to the frozen Round 12 snapshot and do not override the
Round 13 status at the top of this file.

| Item | State |
|---|---|
| Source version / publication model | `0.16` development on `main`; the repository no longer contains an automated RC or Release workflow |
| Historical candidates | `v0.16-rc.1`, immutable Round 8 `v0.16-rc.2`, and immutable failed Phase 1 `v0.16-rc.3` identities are historical evidence only and must not be overwritten, relabeled, or reused as Round 12 output |
| GitHub publication | The documented legacy `v0.15` repository/Release is unavailable; current Actions validate source and expiring development artifacts only and cannot create or modify a Release |
| Historical green baseline | `main@21267e742b624b29a75bd3683fd6914f76c764b5`; classifier `classifier-policy-v10` / `7934e15f...`; CPA v7.2.116. This identity is not the active v7.2.124 target |
| Historical engineering CI | CI `30880739397`, Policy and Corpus Gate `30880739368`, and CodeQL `30880739360` **PASS** only for exact `main@21267e7` on CPA v7.2.116; the active v7.2.124 candidate requires its own checks, and this is not production approval |
| Historical failed audit | Exact `150c25e6` / CPA v7.2.104 remains **FAIL / BLOCKED**: 287 complete malicious fail-open cases, 36 malicious incomplete HTTP 403 cases, and 2 complete benign false positives |
| Historical input second-machine diagnostic | The supplied CPA v7.2.116 report records 1,320 transport executions. It is `HISTORICAL_ONLY / DIAGNOSTIC_ONLY / NOT_FINAL_CANDIDATE / NOT_INDEPENDENT_ATTESTATION`; transport permutations do not become independent semantic samples, close any Round 12 gate, or transfer to v7.2.124 |
| Round 12 final-candidate second machine | **PENDING_FINAL_CANDIDATE_EXECUTION**. RT12-05/06 has not yet run against the exact v7.2.124 final-candidate commit/tree/SO, so no Round 12 second-machine PASS is claimed |
| CPA source/compile target | Pinned target `v7.2.124` (`197f520426374e514218ed155933ac546c98d345`), C ABI 1 / RPC schema 2. The ABI/schema versions are unchanged, but the active candidate must obtain its own exact-commit results. The upstream Linux amd64 asset SHA-256 is `bb1597e5faa19bd67f4cecb88e14d6306f7f54bffdeedf2d0b973d7cfb5dc176` |
| Historical Round 9 protected evaluator | Frozen CPA v7.2.113 regression contract only. Its no-checkout root-owned broker uses a Docker 29-compatible internal-only bridge and publishes no CPA or counted-Mock ports to the Host; evaluator aggregate v3, ledger event v3, protected Git ledger proof v1, external counted-Mock v1, and CPA sandbox descriptor v2 remain historical schemas, not a v7.2.124 lane |
| CPA v7.2.124 protected Host/evaluation | **NOT_PROVIDED**. Historical v7.2.116 CI, second-machine, and five-repository data do not supply a signed v7.2.124 protected lane, independent evaluator, or ledger proof. Any future protected lane must use an internal-only bridge that publishes no CPA or counted-Mock ports to the Host and records `host_ip=internal-only, host_port=0, container_port=8317`; the Host may reach only the exact two Docker-inspect-verified, distinct RFC1918 bridge IPv4 addresses, and any Host binding, additional container, or non-internal network is inadmissible |
| Public adversarial corpus | `round9-public-adversarial-v13` / 481,448 bytes / SHA-256 `91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6`; visible development regression only. All 199 GitHub Release assets are recorded as metadata/digests only and were neither downloaded nor opened. Valid v12/v11/v10/v9, immutable-invalid v8, rejected v8 rebind, valid v7, and frozen-invalid v6 remain historical; no third-party repository code is executed |
| Independent audit | The 2026-07-29 isolated audit of exact baseline `150c25e6` remains **FAIL / BLOCKED**. The current `21267e7` diagnostic was owner-run and is explicitly not an independent re-audit |
| Independent attestation / production approval / release readiness | **NOT_PROVIDED**; there is no stable `v0.16`, no automatic Balanced re-admission, and this round does not create a tag or Release |
| Active workflows | `ci.yml`, `codeql.yml`, and `policy-gate.yml` are the only repository-owned executable workflow YAML files. The live Actions API also returns GitHub's generated `dynamic/dependabot/update-graph` record; see the [governance snapshot](docs/reports/ROUND12_GITHUB_GOVERNANCE_SNAPSHOT.md) |
| Static analysis governance | `.github/workflows/codeql.yml` performs minimal-permission Go analysis on Ubuntu within the reviewed sparse source boundary; CodeQL results do not authorize a release |
| Validation platform | Linux amd64 only; emitted numeric GLIBC ABI versions must be `<= 2.34` |
| Out of scope | Windows, macOS, musl/Alpine, real Provider traffic, production deployment/validation |
| CPA Host matrix | Active target CPA v7.2.124, Linux amd64, isolated counted Mock upstream only. The v7.2.116 exact-main engineering `.so` load, owner-run diagnostic, and any five-repository data are historical and non-transferable; RT12-05/06 protected Audit→Balanced→Strict, signed external evaluation, special-path closure, Multi-Agent v2 `/v1/responses` tool-definition regression, and protected-ledger proof remain **NOT RUN / PENDING** |
| Production | Not accessed or modified; no production request, audit database, credential, HMAC key, account pool, or real Provider was used |
| Scanner identity | `streaming-scanner-v1` |
| Classifier policy | Frozen Round 12 working-source snapshot: `classifier-policy-v12` / `2e9d02371c2ff18d6f5efe7765db45517471603ea9d772c73664bf92c7625a5b`; Round 12 changed role/streaming defensive-owner behavior as well as the CPA-bound source identity. Exact-commit GitHub and final-candidate second-machine binding remained pending |
| Embedded YAML ruleset | Frozen Round 12 main snapshot: `1.0.10` / `e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0`; final-candidate binding remained pending |
| Audit schema | v6; decision kinds and explanation variants are closed, v5→v6 migration creates a mandatory pre-v6 backup, Raw Capture remains default-off, and `audit.max_db_mb` is enforced after each bounded write batch and inside subject-snapshot replacement transactions, with raw-first cleanup, explicit capacity status, and storage-write rejection that does not change classification |
| Code review | Automated review is advisory; no independent approval is claimed |

### Frozen CPA v7.2.113 remediation and historical v7.2.116/v7.2.124 evidence

The behavior and test statements below are frozen Round 10-12 evidence. They
are not relabelled as v7.2.125 results.

- Round 10 requires a current trusted-user instruction to contain both an
  execution act and an explicit referent before it can activate a uniquely
  associated historical tool result. Terse or unrelated continuations such as
  `Proceed` or `Provide code` remain complete allows. Coverage early returns
  now enter one atomic request/reason/disposition ledger, with bounded
  reason-by-role/content-kind/position attribution. Production audit storage
  can require an explicitly verified persistent Linux volume and exposes live
  readiness reasons without leaking the database path to unauthenticated
  callers.
- The frozen Round 12 compatibility target was official CPA `v7.2.124` at
  `197f520426374e514218ed155933ac546c98d345`, module sum
  `h1:ozPCuG4uOPBDre5LEF68eZYwPOYttcOe5L6flkW5boM=`. C ABI 1 and RPC
  schema 2 are unchanged from v7.2.116. The standard upstream Linux amd64 asset
  `CLIProxyAPI_7.2.124_linux_amd64.tar.gz` has SHA-256
  `bb1597e5faa19bd67f4cecb88e14d6306f7f54bffdeedf2d0b973d7cfb5dc176`;
  this records the upstream input identity only and is not a CAG artifact or
  Host PASS. Historical v7.2.116 CI, second-machine, and five-repository data
  keep their original identity and do not transfer. Linux CI must freshly run
  the complete upstream Host suite and public plugin ABI/API, verify the exact
  immutable tag/commit and module checksums, and load the built candidate `.so` through
  CPA's real Host path. CPA v7.2.124 Multi-Agent v2 rewrites `/v1/responses`
  tool definitions before `RequestInterceptor`; the rewritten tool-schema and
  tool-payload boundary therefore requires a new exact-target regression.
  Moving `releases/latest` verification remains an
  explicit optional drift monitor. Frozen Round 6/8 and v0.15/v0.16-rc.2
  records retain their original CPA v7.2.95 identity.
- The historical CPA v7.2.116 compatibility review found that CPA can handle a
  Home OAuth 401 by refreshing the selected credential and retrying at most once
  inside the same logical request. The
  retry reuses the already-intercepted request rather than creating a second
  CAG request lifecycle. For Claude, CPA runs request interceptors before
  executor translation; the Claude executor derives the final upstream wire
  headers afterward, so those generated headers are outside CAG's
  interceptor-visible fingerprint. CAG registers RequestInterceptor and
  request-lifecycle capabilities but does not register `UsagePlugin`; Home's
  result-only usage record therefore does not invoke CAG. These observations
  are v7.2.116 evidence and require fresh v7.2.124 regression before admission.
- The production registration now uses RPC schema 2 request interception and
  request lifecycle callbacks as the ordinary model-request enforcement chain.
  One before-auth scan can terminate batch or streaming requests with a direct
  403 before Auth, Provider, Usage, Executor, Mock upstream, or SSE side
  effects. The stable `RequestID` plus a per-process, request-ID-bound
  HMAC-SHA256 fingerprint of canonical
  source format, body, case-normalized header names with exact ordered values,
  and stream lets an unchanged after-auth callback skip duplicate
  classification and side effects; any
  mutation is reclassified. The asynchronous completion callback removes the
  bounded, TTL-limited ID/fingerprint entry. The frozen CPA v7.2.113 lane did
  not invoke that chain for either
  Alpha Search URL, so CAG also registers a narrowly gated ModelRouter only for
  `codex-alpha-search`: safe search falls through, while a malicious search is
  rejected before Codex auth/upstream as HTTP 503 because the frozen CPA
  handler cannot express a plugin-local 403 on this route.
- Training telemetry can no longer hide real credential solicitation using
  `prompt`, `induce`, `receive`, or `solicit`; four-role batch/stream
  regressions require complete phishing blocks. Duplicate intrusion-alert
  suppression and other defensive monitoring maintenance remain nonblocking
  unless the request explicitly ties the control change to hiding malware,
  unauthorized access, or another hostile purpose.
- The four public Keysmith `system`/terminal-`tool` middle/back carrier cases
  now require and receive a unique same-scope request-local META owner; nearby
  historical, assistant, nonterminal, or inert material cannot borrow that
  authority. This source result still requires a fresh protected Host audit.
- Streaming now selects profiled ownership semantics once per request rather
  than once per field, matching batch normalization for legacy-shaped fields
  and eliminating the long-fuzz role-boundary drift.
- Structurally proven active `system`/`developer`/Responses `instructions` and
  terminal provider-native tool results now have request-local enforcement
  authority without being attributed to the authenticated user or entering
  cross-request subject state.
- Tool-result authority is transaction-closed: OpenAI Chat, Responses, Claude,
  and Gemini require their native call/result shape and owner. Gemini accepts
  only one adjacent terminal transaction whose whole group is either explicit-
  ID matched or ID-free name+ordinal matched; all strings below its exact
  `functionResponse.response` object, including CPA v7.2.113 `result` and
  `output`, are scanned, but outer siblings remain inert. Claude permits the
  CPA-preserved `cache_control` object on a text block without treating its
  metadata as result text. A Responses
  `previous_response_id` continuation alone remains non-authoritative because
  the plugin cannot prove Host pending-call, consumption, or replay state.
- Disarmed NERV regressions now cover credential/session theft,
  persistence/C2/evasion, ransomware, phishing, covert keylogging,
  unauthorized exploitation, and post-exploitation exfiltration. Four-provider
  roughly 7 KiB front/middle/back system and terminal-tool routes are exercised,
  while repository references and bounded defensive/authorized neighbors remain
  nonblocking. This is source-only coverage; any v7.2.116 five-repository data
  is historical, and an exact-v7.2.124-candidate five-repository counted-Mock
  rerun is still required.
- Earlier assistant/tool history, tool schemas and descriptions, and nonterminal
  tool results remain inert unless a trusted current user explicitly reactivates
  a bounded referent. Batch and streaming paths use the same terminal
  conversation boundary.
- Defensive quoted reviews now use a bounded quote span, an adjacent analytical
  governor, an explicit non-execution boundary, and an independent-tail check.
  Variants in quotes, fenced blocks, colons, and newlines can remain review-only,
  while an appended execution clause still blocks.
- The enumerated governor now also accepts narrowly bounded defensive
  incident-response training/analysis introductions. This fixes the independent
  audit's safe-review false positive without treating generic defensive words as
  permission and without changing malicious-carrier or multilingual fail-closed
  handling.
- These changes are source-only. They do not create a Tag, Release, plugin
  binary, CPA Host result, independent audit, or production approval.

## Historical v0.15 release record — currently unavailable

| Item | Historical fact |
|---|---|
| Historical publication claim | `v0.15` was reported as manually published on 2026-07-20 as non-draft, non-prerelease, latest stable |
| Current availability/support | **UNAVAILABLE / SUPPORT SUSPENDED**; the documented repository and Release now return GitHub API `404` |
| Assets | Historical metadata says ten manually built assets; their bytes are not currently reachable or verified |
| Validation claim | The historical production sandbox PASS was owner-reported in Release notes that are now unavailable; no supporting independent Host evidence is attached here |
| Independent evidence | No `formal-release-attestation.json` or `round6-prerelease-attestation.json` asset |
| Source identities | classifier `v5`, ruleset `1.0.7`, audit schema v3 |

The historical v10 evaluation remains `CONSUMED / FAIL` and cannot be rerun or
used for tuning. Engineering checks do not override that methodology result or
authorize production enforcement.

## What Round 6 changes

- Removes production use of `body[:max_scan_bytes]`. Supported JSON requests
  are structurally traversed across the complete CPA-visible body.
- Changes legacy `max_scan_bytes` into a compatibility alias for the retained
  classifier window. It no longer means “inspect only the first 256 KiB”.
- Adds bounded `max_total_text_bytes` and
  `max_classification_chunks` limits so cumulative coverage and retained
  memory are separate controls.
- Streams JSON strings, multipart text, roles, provenance, and logical field
  boundaries into a bounded classifier session.
- Uses transactional media, metadata, tool-schema, and role decisions before
  committing text to classification. Unknown or ambiguous roles cannot
  impersonate a trusted user role.
- Preserves cross-window matching and bounded role-aware composition without
  retaining the full prompt.
- Adds audit schema v3 fields `decision`, `coverage`,
  `incomplete_reason`, and `scanner` plus fixed low-cardinality counters.
- Clears every partial category, score, rule, evidence, and behavior result
  when envelope or text coverage is incomplete.

The optional “verified local hard finding under incomplete coverage” exception
is deliberately disabled. Its counter remains for compatibility and is
expected to stay zero.

## Inspection and disposition contract

Envelope completeness and text coverage are separate:

- `complete`: the full visible structure and all model-visible decoded text
  were inspected;
- `budget_exhausted`: a configured cumulative text or classification-work
  bound was reached;
- `unavailable`: malformed input, unsupported encoding/schema, ambiguous role,
  or an RPC boundary prevented full coverage.

| Mode | Complete harmful request | Incomplete inspection |
|---|---|---|
| `off` | allow | allow |
| `observe` | observe only | allow + observe |
| `audit` | audit only | allow + audit |
| `balanced` | local block at the balanced threshold | allow + audit |
| `strict` | local block at the strict threshold | local block + audit |

The safe startup defaults are `mode: observe` and
`subject_control.enabled: false`. Observe updates bounded counters only: it
does not block, accumulate subject risk, persist per-request SQLite events, or
hash the full request body for audit correlation.

Incomplete requests never update subject risk. A partial prefix cannot produce
a policy block in `balanced`.
Malicious-text blocking requires one closed request-authority proof: either
`current_user` ownership or structurally proven `request_local_system` /
`request_local_tool` authority for an independently complete harmful candidate.
Only `current_user` findings may accumulate rolling subject risk; request-local
system/tool blocks are never attributed to the authenticated user. Unknown or
future fields, assistant history, tool schemas, and nonterminal tool results
remain inspectable and auditable but cannot directly block. A later current user
may reactivate a bounded historical carrier only through the complete referent
proof and the same candidate eligibility gate.
The proof is bound to the CPA `SourceFormat`: only a matching root provider
history or Responses scalar `input` can establish user authorship. Nested or
cross-provider histories, developer/system/tool content, unknown content types,
function responses, and opaque Responses reasoning state remain untrusted.
Nested history/content arrays, scalar members of provider content arrays, and
unknown or non-string Responses item `type` values are likewise scanned without
receiving trusted-user attribution. The exact Responses `type` discriminator is
transport metadata, not model-visible prompt text.

With audit enabled, a complete category-free wrapper-only finding attributed
to non-user or untrusted wrapper traffic stays visible through the bounded
`audited` and
`control_plane_meta_override` counters but does not create a per-request SQLite
event or request/subject correlation hash by default. Set
`audit.persist_wrapper_only: true` to restore those events. Cyber Abuse base
findings, trusted-user wrapper findings, blocks, incomplete inspections, and
opaque-media dispositions keep the full configured audit path.

Repository-neutral regressions derived from four public prompt-override source
pins cover high-authority `instructions`, Chat and Responses tool descriptions,
CPA v7.2.113 Codex Desktop `additional_tools`, assistant/tool history, defensive
domain catalogs, 1,397-17,166 decoded-byte templates, and the 16 KiB boundary
without adding repository-name signatures or complete third-party prompts. See the
[public jailbreak repository review](docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md).

## Effective default limits

| Control | Default / boundary |
|---|---|
| Runtime mode | `observe` |
| Subject control | disabled; explicit opt-in |
| CPA-visible RPC envelope | 8 MiB |
| Retained classifier window | 256 KiB through the legacy alias; valid range 16 KiB–1 MiB |
| Total model-visible text | 8 MiB |
| Logical text fields | 512 |
| Classification work | computed minimum with a floor of 2048 chunks |
| JSON depth | 32 |
| Derived decoding | at most 2 layers, 8 variants, 128 KiB encoded source, and 64 KiB aggregate retained decoded text |

`text_bytes_scanned_total` is cumulative and may exceed
`max_scan_bytes`. Peak retained text is governed by the effective window and
bounded classifier state.

Dense encoded text whose derived view exceeds the 128 KiB encoded-source bound
still becomes incomplete. This is deliberate: long plain text is streamed, but
the implementation does not claim complete coverage for an oversized derived
decoded view.

The compact shadow planner retains closed semantic representatives, short
markers, and bounded span metadata rather than caller-controlled long keys or
semantic values. Residual allocation still grows with JSON token/node and
logical-field counts, under explicit hard limits. Allocation, RSS, and
concurrency claims remain pending authoritative Linux CI and sandbox evidence.

The legacy `ExtractText` API remains for source compatibility and preserves
its materialized `Parts` segmentation semantics. Production routing uses the
streaming request APIs and does not materialize the complete prompt.

See:

- [Streaming scanner design](docs/ROUND6_STREAMING_SCANNER_DESIGN.md)
- [Configuration migration](docs/ROUND6_CONFIG_MIGRATION.md)
- [Known limitations](docs/ROUND6_LIMITATIONS.md)
- [CI, candidate, and release gates](docs/ROUND6_RELEASE_GATE.md)
- [Documentation and workflow index](docs/README.md)
- [Development handoff](docs/ROUND6_DEVELOPMENT_HANDOFF.md)

## Supported request surfaces

The request path covers OpenAI Chat, OpenAI Responses, Interactions, Anthropic
Claude, Google Gemini, OpenAI image/video profiles, bounded
`multipart/form-data`, tool definitions and payloads, metadata exclusion, and
opaque media classification.

Images, audio, video, and documents are opaque. Their bytes are not decoded,
fetched, or sent elsewhere. `allow` for opaque media means “not inspected”, not
“safe”.

The deterministic policy covers credential theft, phishing, malware,
ransomware, exploitation, data exfiltration, service disruption, and defense
evasion. It is not a general content moderator or a replacement for provider
policy.

## Security and privacy boundary

- By default the Guard does not persist raw prompts, tool payloads,
  authorization headers, plaintext credentials, uploaded code, or provider
  account identity. The explicit `audit.raw_capture.enabled` exception below
  stores only redacted, bounded previews of requests whose final disposition
  prevented upstream routing (`block`, including subject cooldown).
- This is a Guard-local guarantee, not an end-to-end Host guarantee. CPA may
  temporarily spool non-multipart request bodies and may persist raw bodies in
  Host HTTP error logs; see [Decision output and privacy](docs/RULES.md#decision-output-and-privacy).
- The frozen admitted production deployment contract requires CPA v7.2.113 to use an
  absolute `WRITABLE_PATH`, a dedicated empty log bind mount, and a direct CPA
  listener; the watchdog enforces the observable parts of that contract. It
  binds initial/final status, both classifier health probes,
  challenge issue, ResourceRoute response, and confirmation to one random
  256-bit plugin process identity. Applying this contract to v7.2.125 requires
  a fresh exact-target watchdog and Host run.
  A same-host proxy that rewrites that identity, preserves hop-by-hop headers,
  or normalizes lowercase `get` remains outside the plugin ABI boundary; see
  [Docker installation](docs/INSTALL_DOCKER.md#7-restart-and-baseline-checks).
- Ordinary audit, metrics, and management status expose fixed fields, counters,
  and identities rather than prompt fragments or offsets. Only the
  authenticated `/raw-captures` route can return an enabled review preview.
- Media URLs are never fetched. No request-supplied code is executed.
- The Round 6 work did not connect to a real Provider or account pool and did
  not read production requests or audit data.
- No code, workflow, installer, hook, dependency, application, or binary from
  the four public adversarial repositories was executed. Selected public text
  bytes are replayed only as inert local development regressions. The immutable
  v5 snapshot remains historical. The exact v6 snapshot is also retained as a
  frozen-invalid review-digest identity, and version 7 remains the prior valid
  freeze. The exact announced v8 is immutable-invalid at 105,299 bytes /
  SHA-256 `5def53300bad07c65717ed8f8a32d2da49952528275df77ea55703713f9e330f`;
  the corrected in-place 105,298-byte / `2f953da4…` v8 rebind is retained only
as rejected evidence. Active evidence is `round9-public-adversarial-v13` at
481,448 bytes / SHA-256
`91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6`;
its 199 GitHub Release assets are metadata/digest records only and no binary
asset was downloaded or opened. V12, v11, v10, and v9 remain immutable history; v9 is
105,888 bytes / SHA-256
`dd22068b452cb4183405bfe7697d52a1b7dd272de25ebef0790add46a71c9c38`.
  This visible corpus is not an independent holdout or production approval.
- CPA can still fail open in Host conditions outside the plugin's control,
  including failed loading or registration, interceptor fuse/RPC errors, an
  earlier interceptor terminating the chain before Guard, or a later
  interceptor rewriting the request after Guard inspected it. Production must
  attest the loaded interceptor inventory and effective order; real Host
  validation is therefore mandatory.

The Round 6 restricted-data disclosure is recorded in the
[development handoff](docs/ROUND6_DEVELOPMENT_HANDOFF.md). It does not claim
zero source-level contact where an over-broad search or mechanical build-tag
edit occurred, but no restricted corpus payload or production data was used
for implementation or conclusions.

## Blocked-request review capture

`audit.raw_capture` is an operator-only false-positive review feature. It is
**disabled by default**, requires ordinary audit storage, and is hard-limited
to blocking decisions (`block` or subject `cooldown`). It does not record
allowed, observed, or audit-only requests. Each stored preview is best-effort
secret-redacted over a bounded `max_bytes + 64 KiB` prefix/overlap, then
truncated on a valid UTF-8 boundary; SHA-256 still covers the complete request.
The defaults are 8 KiB per capture and a 72-hour TTL. Redaction is not a
complete DLP guarantee, so the SQLite data directory and CPA Management Key
must be treated as sensitive production secrets.

Schema-v6 migration backups are exact rollback snapshots and can retain
sensitive previews. Turning Raw Capture off purges only the active database;
it does not delete those backups. Authenticated `/status` exposes their
path-free inventory, while deletion requires the separate
`POST /migration-backups/purge` route and two exact confirmations documented in
[Raw Capture](docs/RAW_CAPTURE.md#migration-backup-inventory-and-explicit-cleanup).

Enable it explicitly:

```yaml
audit:
  enabled: true
  data_dir: /plugin-data/cyber-abuse-guard
  require_persistent_storage: true
  raw_capture:
    enabled: true
    only_blocked: true
    redact_secrets: true
    max_bytes: 8192
    ttl_hours: 72
```

`only_blocked: false` and `redact_secrets: false` are rejected. Query through
CPA's authenticated management API with `event_id`, `request_hash`, and/or
`limit` (default 20, maximum 100):

```bash
curl -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  "http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/raw-captures?limit=20"
```

The frozen CPA v7.2.113 lane HTML-escapes the legacy `raw_preview` string. The
v7.2.125 target must revalidate that transport behavior. The field remains
available for compatibility but is explicitly deprecated. New consumers should
use the canonical `raw_preview_b64` field when byte-stable review text is
required. Base64 is transport encoding, not encryption or redaction: decoded
content remains sensitive and must be rendered as plain text only, never through
`innerHTML` or another HTML-capable renderer. The management response applies a
fixed 8 MiB budget to the complete Host-visible JSON body. A requested `limit`
of 100 is still valid, but the endpoint may return fewer rows; check
`response_truncated`, `returned_count`, and `cpa_host_response_bytes`.

When a live disable transition succeeds while audit storage remains enabled,
the endpoint returns an empty list only after the capture table is purged and
the WAL checkpoint completes. If the whole audit subsystem is disabled across
a restart, the old database is not opened or cleaned automatically. See the
[operator guide](docs/RAW_CAPTURE.md) for the response contract and handling
warnings.

## Historical v0.15 pre-publication verification record

The table and process below describe the reviewed v0.15 admission design before
the historically reported manual stable publication. The old repository and
Release now return `404`; all links and states below are retained historical
records, not claims that the source, runs, tags, Releases, or assets remain
reachable. They do not describe an available v0.16 workflow.

| Gate | Current state |
|---|---|
| Round 6 implementation PR | [PR #9](https://github.com/yujianwudi/cyber-abuse-guard/pull/9) merged; its PR runner did not start because of the recorded GitHub billing limit, so it is not claimed as a PR-CI PASS |
| Last fully verified pre-cleanup `main` push CI | [29630844605](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630844605) **SUCCESS** for `6782dfa` / tree `a8edbe2` |
| RC4 exact-main CI | Must be a completed successful `push` run of `ci.yml` for the exact tagged `main` commit and is revalidated before checkout |
| Source-only `v0.15-rc.1` tag CI | [29630926354](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630926354) **SUCCESS** for `6782dfa` / tree `a8edbe2` |
| Private untagged clean candidate Actions artifact | **NOT CREATED / PENDING**; must bind one final commit/tree and emit `candidate-manifest.json` |
| CPA v7.2.95 Host + Mock upstream | **NOT RUN / PENDING** |
| Independent source/artifact/Host audit | **NOT RUN / PENDING** |
| Candidate-bound external evaluation-v11 or later | **NOT RUN / PENDING**; must be first-and-only `CONSUMED / PASS` for the exact candidate |
| Annotated `v0.15-dev.round6[.N]` prerelease | Optional and blocked until Host, independent audit, and candidate-level evaluation pass; never a formal release |
| Public source-only `v0.15-rc.1` prerelease | Exists with no attached assets; not the private candidate, Host evidence, or formal release |
| Historical asset-bearing `v0.15-rc.2` prerelease | **PUBLIC / PRERELEASE / SANDBOX ONLY**; ten Linux amd64 assets were published by direct owner override with tests skipped |
| Protected `v0.15-rc.3` attempt | **FAILED / UNPUBLISHED / ZERO ASSETS**; run [29728286559](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29728286559) passed admission, failed before packaging, skipped publish, and created no Release |
| Formal-structure `v0.15-rc.4` prerelease | Exactly 17 Linux amd64 assets; internal gates and reproducibility must pass, while real CPA Host, independent audit/evaluation, formal release, and production authorization remain absent |
| Annotated `v0.15` formal tag | Manually published as stable on 2026-07-20; the protected draft/promotion chain was not used |
| Protected promotion of the unchanged draft | Not used for the actual v0.15 publication |

Windows and macOS are intentionally absent from this matrix. Their absence is
not a failed gate for this Linux-only round and must not be represented as test
coverage.

Safe Round 6 entry points are documented in
[ROUND6_RELEASE_GATE.md](docs/ROUND6_RELEASE_GATE.md). Do not replace the
allowlisted gates with broad `go test ./...` or `go vet ./...` commands that
could compile or open consumed evaluation packages.

Before the reported manual publication, the reviewed process prohibited creating
`v0.15` until its external gates passed. That instruction is now historical;
the unavailable v0.15 assets must not be inferred or reused as v0.16 evidence. Consumed
v10 remains immutable and must not be rerun.

## Artifact contract

The historical v0.15 pre-publication evidence chain was designed as follows:

1. Freeze the final PR head, pass PR CI, merge it to `main`, and pass push CI on
   the exact resulting main commit/tree. Merge is a candidate prerequisite, not
   deployment or release approval.
2. A manual, private, **untagged** GitHub Actions dispatch from `main` builds clean exact-source
   Linux amd64 candidate bytes. Its artifact is not a GitHub Release and expires.
3. The CPA v7.2.95 Host + Mock record, the independent
   audit, and a candidate-bound external `evaluation-v11` or later
   `CONSUMED / PASS` report must all bind the same candidate identity.
   The Host identity and evidence hash are carried by attestation schema v2 as
   `cpa_version`, `cpa_commit`, and `cpa_host_sha256`.
4. If a durable development handoff is needed after those gates, an existing
   annotated `v0.15-dev.round6` (or numbered suffix) may produce a draft prerelease only
   after those external gates pass. It remains `BLOCKED / NOT A FORMAL RELEASE`.
5. Only that candidate-level external evaluation attestation may admit the
   annotated formal tag `v0.15`. Its workflow
   rebuilds and byte-compares the Host-tested candidate, emits
   `formal-release-attestation.json`, and creates a draft formal Release; a
   separate protected promotion publishes that unchanged draft.

The private candidate contains `cyber-abuse-guard-v0.15.so`, its sidecar,
`cyber-abuse-guard_0.15_linux_amd64.zip`, metadata, checksums, ruleset identity,
SBOM, and `candidate-manifest.json`. The Store ZIP contains exactly one root
`.so`. Audit bundles and source archives belong only to the later formal release
path and must exclude evaluation, Holdout, private, blind, and retired material.
They carry only the approved low-sensitivity attestation identities/hashes.
Clean candidate bytes are still unreleased and provide no deployment
authorization.

This source tree intentionally does not self-record future Host/audit PASS
hashes, merge identity, or Release state. Stable v0.15 eligibility is determined
only by external Round 6/formal attestation assets that bind the final source,
candidate workflow run, candidate bytes, Host records, independent audit, and
release evaluation.

The historically reported 2026-07-20 v0.15 publication did not complete that
protected chain. Its owner-reported sandbox result and manual-build disclosure
were attributed to Release notes that are now unavailable and are not upgraded
here into independent evidence.

The Round 9 prerelease development target is pinned to CPA v7.2.113 at
`bc71c77f5cc42f3fbe1bf040cf14d4f166894835`. Later upstream
versions do not automatically change the supported or release-admitted target.
Older observations remain non-executable historical records and are not current
release or Host evidence.

Historical evaluation-v10 remains `CONSUMED / FAIL`, cannot be rerun, and is
not accepted as a formal-build input.

The neutral source policy is [RELEASE_POLICY.md](docs/RELEASE_POLICY.md). The
external decision records are `round6-prerelease-attestation.json` and
`formal-release-attestation.json`; neither is self-authored as a future PASS by
this source tree.

## Repository map

| Path | Purpose |
|---|---|
| `cmd/cyber-abuse-guard/` | Native plugin entry point and CPA ABI bridge |
| `internal/classifier/` | Deterministic policy and streaming classifier |
| `internal/extract/` | Transactional request traversal, streaming text replay, decoding, roles, multipart, and media handling |
| `internal/plugin/` | Router, executor, disposition, management, health, and reconfiguration |
| `internal/audit/` | Privacy-minimal SQLite events, schema migrations, retention, and subject state |
| `integration/` | CPA source/compile and Host contract modules |
| `scripts/` | Safe gates, Linux build, packaging, verification, and reproducibility tooling |
| [`docs/README.md`](docs/README.md) | Documentation index for architecture, operations, policy, current release handoff, and historical reports |

Historical Round 5.2 evidence remains available in
[AUDIT_HANDOFF.md](docs/AUDIT_HANDOFF.md),
[TEST_REPORT.md](docs/reports/TEST_REPORT.md), and
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md). It does not validate
the Round 6 candidate.

## Security reporting

Follow [SECURITY.md](SECURITY.md). Do not include live credentials, private
prompts, OAuth material, production request content, or account identifiers in
an issue.

## License

[MIT](LICENSE)
