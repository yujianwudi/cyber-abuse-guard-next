# Test Report — CPA v7.2.116 active validation and frozen historical evidence

```text
current_classifier_policy_version: classifier-policy-v11
current_classifier_policy_sha256: f1b4665c751306a1a30c96a58ddb84714541e6e476c66db8ad436480e4c98f55
```

Last updated: 2026-08-05 (Asia/Shanghai)

## CPA v7.2.116 active target — baseline PASS, superseded candidate fail-closed, remediation pending

The current source/compile target is
`v7.2.116@a88197f845c979132c8978ea223c6af05cc81536`, C ABI 1 / RPC schema 2,
with module sum `h1:dGGI/CeEQTyKkFNeeqMoIyK/mWx5hVaQlZLDiHPoBTU=`. The standard upstream
Linux amd64 asset `CLIProxyAPI_7.2.116_linux_amd64.tar.gz` is identified by
SHA-256 `469adcf760936764781687cfc7057f8ca0db3a685d418dd3d9d84cb1910bde3b`.
That asset identity is an upstream input record only; it was not downloaded or
executed for this documentation update and is not CAG Host evidence.
The top `current_classifier_policy_*` prologue identifies the active working
tree; it is not metadata for the frozen v7.2.113 evidence sections below.

The canonical current boundary is
[Round 12 active status](../ROUND12_STATUS.md). Exact baseline
`main@21267e742b624b29a75bd3683fd6914f76c764b5` passed the five required
GitHub engineering contexts through CI `30880739397`, Policy and Corpus Gate
`30880739368`, and CodeQL `30880739360`. These are exact-main baseline results,
not results for the Round 12 working candidate and not protected Host,
independent, release, or production evidence.

The supplied 1,320-transport second-machine report is an owner-run input
diagnostic only. It is not the RT12-05/06 final-candidate run and is not an
independent attestation. Final-candidate execution remains
`PENDING_REMEDIATED_HEAD_EXECUTION`.

Superseded PR head `9782eaf9da37d466ffc0b644b052d3c842f7f1ca` passed CI
`31016759352`, Policy and Corpus Gate `31016760807`, and CodeQL `31016759262`.
Linux artifact `8936474093` carried an SO with SHA-256
`4fdd0914328b63f585187b970a0dc8f4501c3f6dece7819cd414d4fb3179a4ad`.
The exact second-machine run then failed closed before counted-Mock traffic:
Docker/runc rejected the proc-fd magic-link bind source with
`error_id=32a64d93ec0f3ed9`. No `machine-evidence.json` was emitted,
`third_party_code_executions` remained zero, and private corpus text was
removed. The failed evidence is retained at
`/opt/cag-audit-rt12-9782eaf-20260805-1615`; it is not a PASS and is not
overwritten by the local remediation.

A separate, uniquely named, `--network none` second-machine Docker preflight
then started the pinned Python image successfully with a normal host bind path.
Inspect reported that bind with the exact source, `RW=false`, and
`Propagation=rprivate`; `HostConfig.Tmpfs` contained exactly
`/tmp=rw,noexec,nosuid,nodev,size=64m`, while `.Mounts` omitted the tmpfs entry.
The container and its empty private directories were removed immediately. This
is real runc/inspect compatibility evidence for the handoff shape, not a final
candidate, CPA/CAG, semantic, performance, or side-effect PASS.

The reviewed v7.2.113-to-v7.2.116 range retains C ABI 1, RPC schema 2, and all
235 scoped plugin blobs byte-identically. It adds Home's at-most-once OAuth 401
refresh/retry within the same logical request and changes Claude executor
behavior outside the interceptor ABI; Claude's final upstream wire headers are
generated after request interceptors. CAG does not register `UsagePlugin`, so
Home's result-only usage record is not a new CAG callback. These are reviewed
delta facts, not executed v7.2.116 results.

```text
cpa_v7.2.116_local_source_compile: PASS / LINUX_AMD64 / GO1.26.4 / PINNED_MODULE_ORIGIN_AND_SUMS
cpa_v7.2.116_remote_latest_release_api: PASS / v7.2.116
cpa_v7.2.116_remote_tag_ref_api: PASS / a88197f845c979132c8978ea223c6af05cc81536 / COMMIT_VERIFIED
cpa_v7.2.116_remote_git_tag_gate: NOT_COMPLETED_LOCAL_NETWORK / TWO_BOUNDED_TIMEOUT_RUNS / GITHUB_CI_REQUIRED
cpa_v7.2.116_exact_main_baseline_ci: PASS / EXACT_MAIN_ONLY / 21267e742b624b29a75bd3683fd6914f76c764b5
cpa_v7.2.116_superseded_candidate_ci: PASS / 9782eaf9da37d466ffc0b644b052d3c842f7f1ca / SUPERSEDED
cpa_v7.2.116_superseded_candidate_second_machine: FAIL_CLOSED / ERROR_32a64d93ec0f3ed9 / NO_MACHINE_EVIDENCE
cpa_v7.2.116_round12_candidate_ci: PENDING_REMEDIATED_HEAD
cpa_v7.2.116_second_machine_bind_preflight: PASS / NORMAL_BIND_RUNC_START / RPRIVATE / HOSTCONFIG_TMPFS_CLOSED / MOUNTS_TMPFS_OMITTED / NOT_FINAL_CANDIDATE
cpa_v7.2.116_input_second_machine_report: DIAGNOSTIC_ONLY / NOT_FINAL_CANDIDATE / NOT_INDEPENDENT_ATTESTATION
cpa_v7.2.116_final_candidate_second_machine: PENDING_REMEDIATED_HEAD_EXECUTION
cpa_v7.2.116_protected_host: NOT_PROVIDED
cpa_v7.2.116_independent_attestation: NOT_PROVIDED
cpa_v7.2.116_production_approval: NOT_PROVIDED
cpa_v7.2.116_release_ready: NOT_PROVIDED
cpa_v7.2.116_tag_and_release: NOT_CREATED / NOT_AUTHORIZED
```

## Round 12 working-tree pre-final Linux validation

The current working tree implements the Round 12 capacity, subject-admission,
classifier, repository-governance, and five-repository audit-tool changes. Its
classifier identity is exactly `classifier-policy-v11` /
`f1b4665c751306a1a30c96a58ddb84714541e6e476c66db8ad436480e4c98f55`.
The current approved five-repository source policy and runner identities are:

```text
reviewed_repositories: 5
reviewed_sources: 11
reviewed_semantic_cases: 19
source_policy_sha256: d457374f193db13fd43422104f760997c935de057ae3add7a0faf56a5260ad89
runner_bundle_sha256: 46ca04f8e39922f5023dd60082bea2ff96c79660118b46b57c20f749159fca6c
audit_contract_sha256: 830d914f904cdc934bfa4b029ef2d069c01f1cf3e0ae489296a2f3dfc8877087
run_source_sha256: 083f03dbe599434ae4b40300d90d792659e43dec734fb551421393b35cbc339b
machine_schema_sha256: a30a2f6c710eb80a4c8be582e69cc38652c1cfd9e31f0a5087ac2510f7cd9427
```

| Working-tree check | Result and evidence boundary |
|---|---|
| Current CPA audit tool | **PASS**, Linux 68/68. Includes pending/approved review separation, exact source pins, hardlink/directory-swap/rename cleanup, closed evidence schemas, concatenated-ZIP prefix rejection, non-object evidence CLI normalization, stopped-image Mock source/Entrypoint verification before execution, full absolute evidence-path dev/inode snapshots, private parent/root mode continuity, symlink and ancestor/evidence/subdirectory replacement failures, normal-path Docker handoff, and exact Source/Destination/RW/rprivate closure for five binds. `HostConfig.Tmpfs` must contain only the hardened `/tmp`; Docker's observed real-host behavior omits that tmpfs from `.Mounts`, so tests accept zero or one matching `/tmp` entry there while rejecting duplicates, extra binds, volumes, and other non-bind mounts. Evidence writes remain on the runner-PID fd path. The runner uses a dedicated UID and does not claim protection from a hostile process sharing that UID during the non-atomic create/bind or daemon-handoff intervals. No third-party repository code was executed by these unit tests. |
| Audit database capacity | **PASS**: subject-snapshot replacement streams bounded rows inside the transaction, measures tentative live pages, and rejects overflow without replacing prior state or deleting audit events. Committed event deletion, Raw Capture purge, and subject-state deletion remeasure capacity without evicting evidence outside the requested maintenance scope. |
| Safe development inventory | **PASS**, `packages=20`, `classifier_entries=576`, `round12_entries=8`. |
| Complete unit lane | **PASS** with exact Go 1.26.4 on Linux: the safe packages passed, the classifier then passed separately in 398.508 seconds under a constrained two-core WSL lane, and the counted-Mock module passed. This is functional development evidence only and is not a performance baseline. |
| Format/diff/module/vet | **PASS** on Linux; all root and integration module sums verified and the closed package set passed vet. |
| Script and policy contracts | **PASS**: repository secret scan, actionlint, ShellCheck, Host/evaluation contracts, current audit tool tests, production-health isolation, Store archive, HMAC generation, and Safe Gate all passed. Safe Gate ran 209 tests with 91 retired-workflow skips and closed 3 entrypoints, 38 Make targets, and 47 scripts. |
| Release-document consistency | **PASS**, including all negative mutation fixtures, for version 0.16 and the exact current classifier identity. |
| Fuzz seeds and repository corpora | **PASS**: extract/classifier/config fuzz seeds, bounded one-second classifier/extract/audit fuzz runs, Balanced corpus contract, development public-jailbreak corpus, Round 9 corpus contract, and public corpus v13 gates. |
| Historical 142-case Balanced benign corpus | **UNCHANGED FROM `main@21267e7`**: B028, B062, and B075 remain 3/142 historical false positives. The exact baseline rerun produced the same IDs, scores, and category; this is not a Round 12 regression and is not presented as zero global false positives. Round 12's named defensive critical controls remain complete non-blocks. |
| Local race | **INCOMPLETE / NOT PASS**. The desktop tool session interrupted the WSL process after partial package output. No race failure was observed, but partial output is not accepted as evidence. |
| Exact Go 1.26.4 race, CPA v7.2.116 compatibility, build/reproducibility, and long fuzz | **PENDING REMEDIATED-HEAD GITHUB CI**. The exact local Go 1.26.4 functional checks and superseded-head green runs do not satisfy these candidate-bound CI gates. |
| RT12-05/06 second-machine run | **SUPERSEDED HEAD FAIL_CLOSED / REMEDIATED HEAD PENDING**. `9782eaf` failed before traffic because runc rejected the proc-fd bind source; it emitted no machine evidence. No working-tree unit result is relabelled as CPA Host, side-effect, performance, or independent evidence. |

The latest-head check on 2026-08-05 found four reviewed repositories unchanged
and MDX advanced by two documentation-only commits to
`7588d25d8cb67f88a75d168fcb6ca8fc357bc492`. The only changed paths are
`README.md` and `README_EN.md`; both selected MDX blobs retain their reviewed
Git blob and content hashes. The policy therefore updates the repository
commit/tree binding without changing either selected payload or its semantic
labels.

The audit tool's final ZIP regression closes a review-boundary flaw found
during the pre-final read-only audit: two complete ZIP archives could be
concatenated and Python's `zipfile` would silently treat only the last archive
as authoritative. Acquisition now binds the central-directory offset to the
actual start of the byte stream, requires the sole local entry at offset zero,
and rejects rebased or unreferenced prefix payloads while preserving the exact
reviewed MDX archive layout.

No v7.2.113 source, CI, Host, watchdog, sandbox, performance, or audit result is
relabelled as v7.2.116 evidence.

The previously documented old repository and `v0.15` Release returned GitHub
API `404` on 2026-08-04. Legacy availability is `UNAVAILABLE` and support is
`SUSPENDED`; retained Round 6 test history does not establish current asset
availability or support.

## Frozen CPA v7.2.113 final baseline

The final historical v7.2.113 baseline is
`main@a9fba4e32bfa8f7ce4b5db35e69183400c3de5b4`, with CPA
`v7.2.113@bc71c77f5cc42f3fbe1bf040cf14d4f166894835`. Its pinned local Linux
source/ABI/RPC schema-2 compatibility result remains **HISTORICAL PASS**, with
the exact boundaries recorded in the retained table below: the candidate Host,
container lifecycle, counted-Mock route, and protected sandbox were
`NOT_PROVIDED` by that source-only result.

GitHub records CI `30851294941`, Policy and Corpus Gate `30851294902`, and
CodeQL `30851294956` as successful for exact `main@a9fba4e`. Those are frozen
engineering checks only. The repository contains no checked-in report or
GitHub-attested artifact binding a second-machine watchdog PASS to this commit,
so no such PASS is claimed. None of this evidence transfers to v7.2.116.

## Frozen pre-final CPA v7.2.113 Round 10 source-tree snapshot verification

This retained section predates the final `main@a9fba4e` baseline. References to
“current” below describe that historical snapshot, not the active v7.2.116
target.

The historical target at that time was Linux amd64 `v0.16-rc.4`, classifier-policy-v10, ruleset
1.0.10, audit schema v6, and CPA
`v7.2.113@bc71c77f5cc42f3fbe1bf040cf14d4f166894835` with RPC schema 2. The protected Host contract
uses only `127.0.0.1:18394 -> 8317/tcp`. The historical development
identity was classifier-policy-v10 /
`db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594`
and ruleset 1.0.10 /
`e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0`.
The policy snapshot is frozen pending an exact repository commit, and evidence
is partitioned across that remediation identity and two frozen
historical identities:

- The historical production-hardening source snapshot was `classifier-policy-v10` /
  `db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594`.
  It pins CPA v7.2.113 and changes bounded historical-tool activation,
  direct-compaction overflow handling, persistent-audit readiness, and coverage
  accounting. Only the local policy-identity, document/safe-gate, and CPA
  v7.2.113 pinned-source compatibility results recorded below are source-local
  evidence. The package/race/corpus/fuzz/benchmark results remain bound to the
  historical pre-v7.2.113 `b2b7905a...` identity. Exact-commit CI, complete
  package/race revalidation, Linux Host/container loading, counted-Mock routing,
  the protected 4,424-request matrix, and independent audit remain **PENDING**
  or **`NOT_PROVIDED`**; no predecessor result is relabeled as later evidence.
- The dependency-only CPA v7.2.109 rebind at `main@08bbc34c` used historical
  policy digest
  `6cd7296bee90b9352a9cf1745b7760c0ff1b18a265da4af498c5877d4b542f87`.
  Its results remain predecessor evidence and are not rebound to the current
  behavior-changing policy identity.
- Historical `main@150c25e6352cb237cb3956bd66c83c3278c3fe33` used exact
  policy digest
  `e0cbc975c126a12649a1b8e309e4e2a95efc64e46346467771ecae61b3e14971`.
  Exact-HEAD CI run `30353591705` was an engineering PASS, but the isolated
  Tencent Cloud #2 audit was **FAIL BLOCKED**: 287 complete malicious requests
  failed open to upstream, 36 malicious incomplete cases returned 403 only by
  fail-close, and 2 complete benign requests were false positives. CI success
  does not override that security result.
- Historical frozen main `1a64639c0bac7a157d8201c1593bd68cf6e7fe11` used exact
  policy digest
  `f9529ada85dee7e35267c70da54aa74e266e88b4ed2703924f352c2cb0cb4333`.
  Its source, race, visible benign, visible paired, classifier-gate, local CPA
  v7.2.102 Host/Router, and exact-main CI results remain valid historical PASS
  evidence only for that commit/digest pair; none is rebound to `e0cbc975...`
  or the later historical
  `db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594`
  identity.

The predecessor main snapshot `d23c94ffb7ac3812b2799f0e0cf49dff1da74cde`
ran exact-main Round 9 gate `30223734797` and failed at 112/120 paired malicious
semantic samples. The immutable rc.3 attempt passed exact-main CI at `77cf2de`
and then failed before asset creation because PyYAML was undeclared in the fixed
builder container; both remain failure history rather than current evidence.
A user-supplied external CPA v7.2.95 counted-Mock report for historical commit
`aea54c8c3b357b085fb8c37d06eb4b501dcd29bb` found 20/20 Chinese, Japanese,
Korean, and mixed-language long defensive frames returning complete allow with
an upstream call. The later user-supplied report for
`f37a25dd1ef7f64677282f154372cf2b4cb0ad7b`
confirmed that multilingual repair but found one complete-inspection false
positive: an explicitly non-executing defensive incident-response analysis of a
quoted credential-theft carrier was blocked in Balanced and Strict. The later
historical `1a64639c` / `f9529ada...` source and local CPA v7.2.102 checks
addressed that false positive. Neither external file is checked into or
cryptographically bound by this repository, and neither supplied historical
`db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594`
evidence.
The visible development-only active corpus is `round9-public-adversarial-v13` (481448 bytes,
SHA-256 `91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6`);
it is frozen public development evidence, not independent evidence. The exact
v9 remains immutable history at 105888 bytes / `dd22068b…`. The exact announced
v8 remains immutable-invalid at 105299 bytes / `5def5330…`, while the
105298-byte / `2f953da4…` corrected in-place rebind is retained separately as
rejected evidence. The exact v6 bytes also remain immutable but frozen-invalid.
The frozen CPA v7.2.104 /
`e7a00b02d7e0e4ca837204cfed476b4f371f599facbf546e342362370111ec14`
tree passed the public-corpus contract and both visible development runners:
benign remained 0/1200 semantic blocks and 0/7200 route
blocks, while paired malicious remained 120/120 semantic blocks and 960/960
passing routes. No result is independent or transferable across the three
identities above.

Unless a row explicitly names an older snapshot, the v7.2.102 remediation and
Host rows below are retained as historical `1a64639c` / `f9529ada...` evidence.

| Frozen Round 10 evidence identity/check | Result |
|---|---|
| Source version / candidate | `0.16` / `v0.16-rc.4`, Linux amd64 prerelease, `latest=false` |
| Historical classifier policy | `classifier-policy-v10` / `db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594` / **LOCAL IDENTITY CONTRACT AND CPA v7.2.113 SOURCE CONTRACT PASS; COMPLETE PACKAGE/RACE AND EXACT-COMMIT REVALIDATION PENDING** |
| Historical ruleset | `1.0.10` / `e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0` / **HISTORICAL DEVELOPMENT IDENTITY; FINAL SOURCE FREEZE PENDING** |
| Historical pre-v7.2.113 `b2b7905a...` policy-v10 package and race gates | **HISTORICAL LOCAL LINUX SOURCE-ONLY PASS; NOT REBOUND.** Unit/package runs completed in classifier `139.693s` and plugin `130.048s`. Full race runs completed in plugin `587.147s` and classifier `391.498s`, with no data race reported. No CPA Host or container was exercised by these runs. |
| Historical pre-v7.2.113 `b2b7905a...` source, script, and fuzz gates | **HISTORICAL LOCAL LINUX SOURCE-ONLY PASS; NOT REBOUND.** Module verification, vet, format, diff, script, and fuzz-smoke gates passed. The safe-gate mutation suite contained 207 cases: 116 active contracts executed and 91 retired release/Host workflow cases were explicitly archived as skips; closed inventory was `classifier_entries=568` / `round10_entries=104`. Bounded real fuzz completed classifier `3,161`, request extraction `19,498`, and audit `14` executions. These counts are local development evidence, not request counts from the protected external corpus. |
| CPA v7.2.113 pinned compatibility | **LOCAL LINUX PINNED SOURCE/ABI/RPC SCHEMA-2 PASS; HOST NOT PROVIDED.** `make round6-module-verify` and the remote-enabled compatibility matrix passed for `v7.2.113@bc71c77f5cc42f3fbe1bf040cf14d4f166894835`, module sum `h1:Aj3J7zI5VxyKpsHbG6+ChVpeW4QGkcJ+ZwWWnWmuChA=`, and the unchanged go.mod sum. The official lightweight tag, module Origin/checksums, `releases/latest`, SDK ABI/API, schema-2 lifecycle, Host source, Interactions, Raw Capture management, and Store contracts passed. No v7.2.109 result was rebound. Exact candidate `.so` load, CPA Host/container lifecycle, and counted-Mock routing remain `NOT_PROVIDED`. |
| Historical pre-v7.2.113 `b2b7905a...` repository-owned ordinary, paired, and public corpora | **HISTORICAL LOCAL DETERMINISTIC PASS; NOT REBOUND OR INDEPENDENT EXTERNAL EVIDENCE.** Ordinary traffic recorded 0 / 1,200 semantic false-positive blocks and 0 / 7,200 route blocks. Paired malicious recorded 120 / 120 semantic blocks and 960 / 960 passing routes. Public direct cases recorded 12 / 12 semantic blocks and the inert-context set recorded 108 / 108 complete allows. The protected 4,424-request matrix remains `NOT_PROVIDED`. |
| Historical pre-v7.2.113 `b2b7905a...` regressions and benchmark recipe | **HISTORICAL LOCAL LINUX SOURCE/FIXTURE PASS; NOT REBOUND.** Round 5, the complete Round 6 regression recipe, the independent Round 8 counted-Mock historical target, the Management proxy 413 fixture, and the Round 6 benchmark recipe passed. The oversized Management request returned 413 before the counted upstream stub, and the small request reached it. This fixture does not establish CPA Host or container behavior. |
| Historical pre-v7.2.113 `b2b7905a...` Round 10 surrogate performance | **HISTORICAL LOCAL SOURCE/SURROGATE PASS; NOT REBOUND.** The 20-effective-CPU Linux amd64 / Go 1.26.4 runner recorded ordinary p95 `2.589708 ms`, five-repository surrogate p95 `112.310521 ms`, Codex-all surrogate p95 `49.690010 ms`, public p95/p99 `9.306253/9.847559 ms`, and SQLite c=16 p95 `1.169612 ms`. All 2,304 bounded operations completed with zero failures and zero recovered panics. Exact-tree GitHub run `30662744941` exposed that schema v1 incorrectly applied the same absolute limit to over-subscribed c=8/c=16 matrices on a 4-CPU runner: five-repository c=4 p95 was `108.795494 ms`, c=16 raw p95 was `572.674185 ms`, and throughput had plateaued. Schema `round10-performance-v2` keeps the limits unchanged, fails closed on matrix coverage, gates only through the largest non-over-subscribed matrix, preserves raw higher-concurrency observations, and marks the uncalibrated saturation profile `NOT_PROVIDED`. The fixed-workload p99 baseline and CPA Host/container performance remain `NOT_PROVIDED` for the current identity. |
| Frozen CPA v7.2.104 / `e7a00b02d7e0e4ca837204cfed476b4f371f599facbf546e342362370111ec14` source checks | **HISTORICAL LOCAL LINUX SOURCE-ONLY PASS.** The targeted percent-decoding, phishing-relation, request-interceptor, request-local carrier, proof-budget, and long benign-text regressions passed. Package tests and module/format/diff/vet gates passed. `scripts/go-safe-development-test.sh test` passed with classifier `149.855s` and plugin `170.503s`. The safe-gate mutation suite passed 207 tests in `73.505s` standalone and `71.386s` inside `make round6-script-test`; the main contract passed with 11 entrypoints, 39 Make targets, and 60 scripts. `make round9-corpus-contract`, `make round9-public-corpus`, the 13-test evaluator core suite, and the 20-test CPA sandbox adapter suite passed. The full safe-development race closure passed with classifier `399.952s` and plugin `797.676s`. Both visible corpus runners, `make benchmark`, and the pinned CPA v7.2.104 source/compile compatibility matrix passed. These results are not current v7.2.113 evidence. |
| Historical `150c25e6...` / `e0cbc975...` exact-main and isolated audit | **ENGINEERING CI PASS / SECURITY AUDIT FAIL BLOCKED.** Exact-HEAD CI run `30353591705` passed. The Tencent Cloud #2 isolated audit nevertheless found 287 complete malicious fail-open requests reaching upstream, 36 malicious incomplete cases returning 403 only by fail-close, and 2 complete benign false positives. This result is bound only to `main@150c25e6352cb237cb3956bd66c83c3278c3fe33`; it is not evidence for the later historical `db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594` snapshot. |
| Historical `1a64639c...` / `f9529ada...` Linux source and race gates | **HISTORICAL PASS / SOURCE ONLY.** Under WSL Ubuntu 26.04 and Go 1.26.4, that frozen generation passed `make unit-test`, `make round6-vet`, `make round6-module-verify`, `make round6-script-test`, `make round9-corpus-contract`, and `go test -race ./internal/classifier -count=1`; the race run completed in 281.834 seconds with no data race. These results remain bound to `1a64639c0bac7a157d8201c1593bd68cf6e7fe11` and `f9529ada85dee7e35267c70da54aa74e266e88b4ed2703924f352c2cb0cb4333`. |
| CPA v7.2.104 source/API/SDK compatibility | **LOCAL LINUX SOURCE/COMPILE CONTRACT PASS; HOST PENDING.** `make cpa-latest-compat` passed under exact Go 1.26.4 for `v7.2.104@c9417c8ae9b16fabc0386ca35d36f13bf8b1d678`, module sum `h1:59vZ1rtgxs6etE0Z3iFsLWgZ/MrcIi4mhXLt0XLSNcY=`, and go.mod sum `h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=`. The isolated direct-cache Origin proof, root/plugin compile probes, C ABI 1, RPC schema 2 RequestInterceptor/request-lifecycle contracts, before/after-auth termination tests, Interactions overlays, Raw Capture management, SDK `pluginabi`/`pluginapi`, and Store contracts passed. Explicit remote tag and latest-release API checks were skipped by the local pinned profile, so this is not an exact-main CI, live Host, `.so` load, or latest-release drift PASS. |
| CPA v7.2.102 local development Host/Router | **PASS / REAL LOCAL HOST FOR DIRTY DEVELOPMENT BYTES; NOT RELEASE EVIDENCE.** `GOTOOLCHAIN=go1.26.4 ALLOW_DIRTY_BUILD=1 make integration-test` exited 0. CPA Store installed the generated Linux amd64 `0.16-dirty` `.so`; the real Host test passed in 33.359 s and every checked-in isolated Router scenario passed. Safe requests carried a valid CPA credential-selection trace and reached provider execution plus Mock upstream; blocked requests returned 403 with no credential-selection trace and no provider, usage, or upstream side effects. This local harness does not claim a counted Auth Selector delta. Encoded carriers, inert historical assistant tool-call payloads, explicit current-user harmful restatements, safe incident-response reviews, and independently complete current request-local system/terminal-tool malicious candidates were covered. The latter are direct candidate evaluations, not bare-referent promotion: only the newest eligible trusted RoleUser review may be reactivated by a bare current-user referent; assistant/system/tool/unknown history, tool schemas, and assistant tool-call arguments remain ineligible. Clean exact-main CI, a clean exact-candidate `.so`, protected external evaluation, and independent artifact audit remain pending |
| Multilingual defensive-frame remediation | **TARGETED LINUX SOURCE/FULL-ROUTE SELF-CHECK PASS; HOST PENDING.** Chinese, Japanese, Korean, and mixed frames at 511/512/513 bytes, 1 KiB, and 16 KiB block a credential-theft carrier in Balanced and Strict; OpenAI Chat, OpenAI Responses, Claude, and Gemini routes assert complete/block counters, and 16 KiB benign carriers remain complete/nonblocking. Targeted classifier/plugin race checks pass. No CPA process, `.so`, or counted-Mock result is inferred |
| Defensive incident-response false-positive remediation | **TARGETED LINUX SOURCE/FULL-ROUTE AND LOCAL DIRTY CPA HOST PASS; PROTECTED RE-AUDIT PENDING.** The enumerated English incident-response training/analysis introductions pass the existing exact quoted-review proof in Balanced and Strict. Profiled whole/halves/bytewise content-kind splits and OpenAI Chat/Responses, Claude, and Gemini simulated routes remain complete/nonblocking. The real local CPA v7.2.102 Host safe-review cases allow; an explicit current-user harmful restatement blocks independently, and a complete malicious candidate placed directly in a current request-local system or terminal-tool carrier blocks only that carrier's candidate. Neither case permits assistant/system/tool/unknown history, tool schemas, or assistant tool-call arguments to be promoted by a bare referent. Protected exact-candidate evaluation and independent re-audit remain pending |
| Supplemental NERV and provider-tool authority remediation | **TARGETED LINUX SOURCE/FULL-ROUTE SELF-CHECK PASS; FIVE-REPOSITORY COUNTED-MOCK PENDING.** Repository-neutral credential/session theft, persistence/C2/evasion, ransomware, phishing, covert keylogging, unauthorized exploitation, and post-exploitation exfiltration requests block across user/system/developer/provider-native terminal tool-result carriers in Balanced/Strict and batch/stream. OpenAI Chat, Responses, Claude, and Gemini roughly 7 KiB front/middle/back system and terminal-tool routes plus benign repository/documentation/authorized-operation/consented-telemetry/incident-response neighbors are covered. Cross-provider IDs, wrong result owners, orphaned/malformed/partial/mixed-ID groups, and nonterminal results cannot gain request-local tool authority. A valid Gemini all-ID-free adjacent terminal transaction may gain authority only when call/result counts are equal and every item matches by name+ordinal; Responses `previous_response_id` continuations remain non-authoritative because Host pending/consumed/replay state is unavailable. One routed OpenAI Responses block is persisted and queried with canonical audit fields. The supplied NERV report tested older CAG `fdb47a99` with CPA `7.2.100`, so no current five-repository or CPA v7.2.102 Host PASS is inferred |
| CPA v7.2.102 provider-native result shapes | **TARGETED LINUX BATCH/STREAM AND BALANCED/STRICT PASS; HOST PENDING.** Gemini string leaves below the exact, transaction-proven `functionResponse.response` object include both `result` and `output`; siblings outside `response` remain non-authoritative. Claude text blocks accept the CPA-preserved `cache_control` object, reject aliases/scalars/arbitrary block siblings, and never authorize cache metadata strings |
| Audit database | schema v6; closed decision/explanation contract; mandatory pre-v6 backup and old-SO rollback |
| Audit unavailable management semantics | **TARGETED LINUX SELF-CHECK PASS** — audit disabled remains a schema-correct empty/no-op result; audit enabled with nil store returns `503 audit_unavailable` for `/events`, `/stats`, and `DELETE /events` |
| Public adversarial development corpus | **FROZEN CPA v7.2.104 / `e7a00b02...` SOURCE-ONLY CONTRACT PASS.** `make round9-corpus-contract` and `make round9-public-corpus` passed. Active: `round9-public-adversarial-v13` / 481448 bytes / `91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6`; v12/v11/v10/v9 retained as prior valid history, exact v8 retained as immutable-invalid history, its corrected in-place rebind retained as rejected evidence, v7 retained as earlier valid history, and v6 as frozen-invalid history; v13 records the later MDX Star History storage/source/workflow/test-only default-head advance while retaining five behind non-default branches, 16 reviewed historical Release assets (four with prompt entries), and 199 metadata/digest-only Release assets that were neither downloaded nor opened; public text only, no third-party code execution, not an independent Holdout. Current policy-v10 public direct/allow results are recorded separately above and do not convert this frozen corpus into independent evidence. |
| Frozen CPA v7.2.104 / `e7a00b02...` visible benign corpus | **HISTORICAL LOCAL LINUX DEVELOPMENT PASS / NOT INDEPENDENT EVIDENCE.** On 2026-07-29 under Linux amd64 / Go 1.26.4, the frozen v1 runner recorded 0/1200 semantic blocks, 0/7200 route blocks, 166 audit routes, 7034 allow routes, balanced/strict 6000/1200, stream false/true 3600/3600, and an empty failure set. |
| Frozen CPA v7.2.104 / `e7a00b02...` visible paired-malicious v3 | **HISTORICAL LOCAL LINUX DEVELOPMENT PASS / NOT INDEPENDENT EVIDENCE.** On 2026-07-29 under Linux amd64 / Go 1.26.4, the runner recorded 120/120 semantic blocks and 960/960 passing routes across Balanced/Strict and batch/stream; failures were empty and the overall Wilson 95% interval was 96.8981%-100%. |
| Historical `1a64639c...` / `f9529ada...` visible benign corpus | **HISTORICAL DEVELOPMENT PASS / NOT INDEPENDENT EVIDENCE.** Linux amd64 Go 1.26.4 directly ran the frozen v1 runner on 2026-07-27: 0/1200 semantic requests and 0/7200 serialized routes blocked; 166 audit and 7034 allow routes; stream false/true 3600/3600; failures empty. The transient 2,515-byte JSON hashed to `e9fa8fb39e8c9bdefb5d0f198d8684d6b7cb39139b4284fe7efc39eb7008bb10`; it is not checked in and remains bound only to the historical commit/digest pair. |
| Historical `1a64639c...` / `f9529ada...` visible paired-malicious v3 | **HISTORICAL DEVELOPMENT PASS / NOT INDEPENDENT EVIDENCE.** Linux amd64 Go 1.26.4 ran the frozen v3 runner on 2026-07-27: 120/120 semantic samples blocked and 960/960 routes passed; stream false/true 480/480; failures empty; overall Wilson 95% interval 96.8981%-100%. The transient 7,150-byte JSON hashed to `9b5d893df4a459614118664fa8bd55ea0c3a2da1c3fa46fb87bc21d20c7a8f1a`; it is not checked in and remains bound only to the historical commit/digest pair. |
| Frozen CPA v7.2.104 / `e7a00b02...` classifier performance acceptance | **HISTORICAL LOCAL LINUX SOURCE-ONLY PASS.** Isolated `make round6-benchmark` passed under WSL Ubuntu 26.04 / Linux amd64 / Go 1.26.4. Classifier P50/P95/P99 were `328.852/412.093/558.688 us`; candidate-rich/near-budget were `35.943486/16.983200 ms/op`; long META was `113.071336 ms/op`; the 1,024-unique-prohibition boundary was `80.469498 ms/op`. The 1 MiB profiled defensive-quote path measured `198.164561-211.251020 ms/op`, below the external `<250 ms/op` optimization target. No current v7.2.113, exact-commit, CPA Host, or independent performance PASS is inferred. |
| Historical `1a64639c...` / `f9529ada...` classifier performance acceptance | **HISTORICAL SOURCE-ONLY GATE PASS.** `go test ./internal/classifier -count=1` passed on that policy, including its enforced latency and directive-overflow budgets. The complete `make round6-benchmark` recipe remained pending, and no result transfers to the current working tree. |
| Pre-refresh Round 6 benchmark recipe | **HISTORICAL SOURCE-ONLY PASS; LONG-PROMPT OPTIMIZATION REMAINS OPEN.** `make round6-benchmark` exited 0 for predecessor digest `2c968f70cfe12e136c07e2856b589f220d464b2284f93e05f368cbb7c927848f` under WSL Ubuntu 26.04 and Go 1.26.4. Classifier P50/P95/P99 were `551.254 us / 957.089 us / 1.266960 ms`; candidate-rich/near-budget were `41.335816/23.460676 ms/op` with near-budget `288,121 B/op`; long META was `160.790024 ms/op`, `6,337,260 B/op`, 103 allocs; negated-prohibition flood was `38.648832 ms/op`, `4,358,501 B/op`, 6,003 allocs. At 64 complete tool pairs, OpenAI Chat/Responses, Claude, and Gemini association planning measured `1.663277/1.447810/1.299558/1.290847 ms/op`, `845,978/784,565/568,114/736,402 B/op`, and `16,981/15,552/14,046/15,007 allocs/op`. Extract long-scale, raw-capture, and plugin full-route acceptance lanes passed. The separate 1 MiB profiled defensive-quote microbenchmark was `344.061658-366.730649 ms/op`, above the external `<250 ms/op` target; no current-source, CPA Host, final artifact, or independent performance PASS is inferred. |
| Previous working-tree benchmark (`5012c101...`) | **HISTORICAL DEVELOPMENT SELF-CHECK PASS.** The preceding policy snapshot recorded P50/P95/P99 `459.731/563.714/765.255 us`, candidate-rich/near-budget `41.898827/21.298198 ms/op`, long META `152.808023 ms/op`, and transient log SHA-256 `a0a2ae3ce885ca4c64bde47578bda0a8ec67534c73849a4ee65c6dcc7329249b`; it is not current-identity evidence |
| Historical pre-fix Round 6 benchmark recipe | **HISTORICAL DEVELOPMENT SELF-CHECK PASS.** `make round6-benchmark` exited successfully for the earlier snapshot; log: `dist/round9-worklogs/round6-benchmark-post-perf-20260724.log`, 26441 bytes, SHA-256 `ec603a4b437820f579d69340feba76bd63752ab5a63cf63998b6e87873d6c063`. Three `BenchmarkClassifierCandidateRichMaxParts` samples recorded 37.311769-39.621583 ms/op, 6,622,070-6,624,038 B/op, and 700-706 allocs/op. It remains predecessor history and is not substituted for the current source-only recipe above |
| Independent benign/malicious corpus | **NOT_PROVIDED**; the active contract requires an age-encrypted root-owned bundle outside Git and outside the candidate checkout |
| Protected Host execution boundary | **NO SOURCE CHECKOUT**; a fixed root-owned broker owns corpus decryption, evaluator/adapter paths, keys, image identities, result directory, and protected one-shot ledger |
| External evidence schemas | evaluation v3, evaluator aggregate v3, ledger event v3, ledger proof v1, external counted-Mock v1, CPA sandbox descriptor v2 |
| CPA external evaluation | **NOT RUN / PENDING** for the exact v7.2.113 RPC schema-2 loopback lane; Audit→Balanced→Strict plus database/restart/panic/usage/Raw Capture runtime checks are required for `PASS` |
| Historical `db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594` exact-commit CI / tag / Release | **PENDING AT THAT SNAPSHOT.** No commit-bound CI, tag, artifact, or Release result was claimed by that source snapshot. |
| Historical `1a64639c...` / `f9529ada...` exact-main CI | **HISTORICAL ENGINEERING PASS.** Frozen commit `1a64639c0bac7a157d8201c1593bd68cf6e7fe11` passed CI `30327322793`, Round 9 gate `30327322810`, and CodeQL `30327322801`. Those runs are bound to that commit and policy digest only. |
| Independent audit | Historical `150c25e6...` / `e0cbc975...` Tencent Cloud #2 audit: **FAIL BLOCKED** with 287 complete malicious fail-open, 36 malicious incomplete 403, and 2 complete benign false positives. The later historical `db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594` matrix/re-audit remained **PENDING**. The older user-supplied `f37a25dd` report remains remediation input but is not repository-attested. |
| Production approval | **NOT_GRANTED** |
| Overall | **BLOCKED / NOT PROVIDED / REQUIRES INDEPENDENT AUDIT** |

### 2026-07-26 incident-response source-only remediation

This block is retained as historical `1a64639c` / `f9529ada...` evidence. It
does not bind any PASS to the later historical
`db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594`
working tree.

The exact false-positive fixture failed before the production grammar change
with `structured audit no longer satisfies the bounded quoted-review proof`.
After the narrow introduction update, the batch structured-audit regression,
profiled whole/halves/bytewise parity, and four-provider plugin-route regression
pass under Go 1.26.4 Linux amd64 with `GOFLAGS=-mod=readonly`. The route tests
assert Balanced/Strict allow and complete-coverage counters for the safe review
and block counters after explicit execution reactivation. These are simulated
source routes only; no CPA process, plugin `.so`, counted Mock, or real Provider
was invoked.

The profiled suite also exercises a gap larger than one minimum scanner window
plus required overlap. A distant qualifier-only window stays `0b000`; combining
reference/boundary `0b101` with a later reference/qualifier `0b011` produces
fail-active `0b111`, independently blocks a malicious credential carrier, keeps
a benign educational carrier nonblocking, and cannot cross `FieldPathHash` or
`ScopeID`. Whole, halves, and bytewise delivery agree in Balanced and Strict.

| 2026-07-26 Linux source check | Result |
|---|---|
| Full package tests | **PASS**; `go test ./internal/classifier -count=1` in 63.065 s and `go test ./internal/plugin -count=1` in 92.691 s |
| Exact structured/profiled/four-provider regressions | **PASS**; classifier structured review, profiled parity including distant-signal boundaries, and plugin route counters |
| Targeted race checks | **PASS**; profiled classifier regression in 5.533 s and four-provider plugin route in 7.476 s with `sqlite_omit_load_extension` |
| Policy/document/source gates | **PASS**; policy identity and source-inventory closure, 205 safe-gate contract tests, safe-gate inventory, release-document consistency fixtures/current tree, format/diff checks, and module verification |

Only normal `go-sqlite3` discarded-`const` compiler warnings appeared in the
plugin checks. They do not change the source-only evidence boundary.

### 2026-07-25 classifier-policy-v9 source-only verification

The runtime remediation was validated only as Linux source. The local WSL
toolchain was the GitHub workflow pin `go1.26.4 linux/amd64` with
`GOFLAGS=-mod=readonly`.
No CPA process, plugin `.so`, counted Mock Host, real Provider, Tag, or Release
was created or executed.

This 2026-07-25 block binds the pre-incident-response-fix `f37a25dd` source
snapshot. Its package, race, fuzz, and benchmark results are retained as
historical development evidence and are not relabeled as performance or Host
evidence for the working-tree policy identity stated above. The 2026-07-26
section above records only the newly rerun incident-response source checks.

| Check | Result |
|---|---|
| Safe development boundary | **PASS**; 20 packages, 419 classifier entries, 104 Round 8 entries, 154 Round 9 entries, and the Round 9 counted-Mock module test |
| Profiled defensive-quote plugin-route regression | **PASS / SOURCE ONLY**; OpenAI Chat, OpenAI Responses, Claude, and Gemini envelopes in Balanced and Strict block second/missing-governor/split-carrier/clause-overflow/513-byte malicious frames; Chinese, Japanese, Korean, and mixed frames cover 511/512/513 bytes, 1 KiB, and 16 KiB with malicious block and 16 KiB benign nonblock controls; malicious 65-scope and both 65-unit eviction orders cannot complete-allow; 64 valid reviews or 64 malformed frames with benign carriers plus a 65th ordinary scope remain complete nonblocking; full-width and zero-width overlong frames match batch behavior; qualifier-only English/CJK windows remain `0b000`; fixed independent bitmask oracles assert `0b111`, `0b101`, and `0b000`; simulated router counter deltas are asserted |
| Normalized multilingual long-frame signal microbenchmark | **PASS / SOURCE ONLY**; three isolated Go 1.26.4 runs measured direct normalize+match at 0.355-0.363 ms/op for 16 KiB and 22.230-22.564 ms/op for 1 MiB with 2 allocs/op; the full profiled path measured 7.873-8.598 ms/op and 250.230-259.302 ms/op respectively; three directive-overflow runs measured the 1,024-unique case at 93.324-97.670 ms/op under the 175 ms ceiling; no CPA Host performance is inferred |
| Safe package tests with `sqlite_omit_load_extension` | **PASS** |
| Race detector | **HISTORICAL `f37a25dd` SOURCE-ONLY PASS**; full Go 1.26.4 classifier race passed in 109.842 s, and the multilingual four-provider plugin route passed its targeted race in 7.903 s. A full plugin-package race was not rerun for that snapshot and remained an exact-main CI gate |
| `make round6-vet` | **PASS** |
| `scripts/round6_safe_gate_contract_test.py` | **PASS**; 205 tests |
| `scripts/round6_safe_gate_contract.py --root .` | **PASS**; 11 entrypoints, 40 Make targets, and 60 scripts |
| Defensive-quote differential fuzz | **PASS**; 30 s, 18,158 executions, 20 new interesting inputs; arbitrary byte cuts and UTF-8 boundary seeds included |
| Round 9 fuzz gate | **PASS**; 10 s each for classifier, request content-type extraction, and audit decision explanation |
| Round 5 / Round 6 regressions and public corpus contracts | **PASS** |
| Modified Round 9 Python contract/evaluator tests | **PASS** |
| Format, shell syntax, diff, and release-document consistency | **PASS** |

The predecessor development corpus reports were produced on Linux amd64 with Go 1.26.4 and
`GOFLAGS=-mod=readonly` using the two checked-in Round 9 runner commands. The
complete benchmark log was produced through
`GO=/home/yujian/.cache/codex-go/go1.26.4/bin/go make round6-benchmark` under
the same module-readonly boundary. These files bind `classifier-policy-v8`,
not the current v9 source identity, a final commit/tree, or a reproducible plugin artifact.
No repository-local or Tencent Cloud #2 counted-Mock, protected external
evaluation, independent benign/malicious corpus, exact-candidate independent
audit, final Linux `.so`, exact-main CI, tag, or Release evidence was provided.

## Historical Round 8 source-tree snapshot verification

The historical target was the Linux amd64 `v0.16-rc.2` prerelease contract. This
retained source-tree snapshot contains the Round 8 classifier/provenance, audit schema
and aggregation, counted-Mock, Host-runner, and release-contract changes. The
final local Go 1.26.4 Linux development gates, race run, allocation acceptance,
same-machine benchmark comparison, dual-CPA source/compile checks, and
Host-evidence assembler contract tests have completed. This is not yet
exact-commit CI, tag, artifact, Host, or Release evidence. Exact-main GitHub CI,
the annotated tag, both historical isolated CPA counted-Mock Host lanes, and the final
17/19-asset publication sequence remain pending. No production, real Provider,
private evaluation, evaluation-v10, or retired holdout evidence is claimed.

Methodology deviation: eight additional over-broad read-only searches
cumulatively displayed evaluation/holdout test or historical-report filenames,
historical ruleset SHA-256 references, a small number of caller-path lines, and
a few historical aggregate count/summary lines. The sixth accidentally matched
`HOLDOUT_REPORT.md` and `HOLDOUT_V3_REPORT.md`; the seventh matched two
operator-local command-path lines in `HOLDOUT_V2_REPORT.md`. The eighth search
displayed several single request lines from retired holdout fixtures. None of
that output was used for classifier, rule, or threshold calibration, and the
classifier issue under review had already been identified before that search.
This work therefore does not claim that no fixture or request body was seen. A separate over-broad
`go test ./internal/classifier` may have compiled or run the restricted gate;
that result is excluded from every current release-evidence claim. Consequently
this work does not claim zero access, blindness, or independent evaluation;
those statuses remain `NOT_PROVIDED`.

| Historical Round 8 identity/check | Result |
|---|---|
| Source version / candidate | `0.16` / `v0.16-rc.2`, Linux amd64 prerelease, `latest=false` |
| Ruleset | `1.0.9` / `a3de344d3f6dc8eea86d946a823996494d4d297c41efcc6346a6ef757f263a7d` |
| Classifier policy | `classifier-policy-v7` / `ea8c4dcfacacc6478f86fd2ca5de96d667ae98f2fc6ff0c83d8e6092e9f6a82d` |
| Round 8 synthetic calibration | **DEVELOPMENT SELF-CHECK PASS** — [336 benign + 336 paired malicious](ROUND8_CALIBRATION.md); benign block `0/336`, malicious block `336/336`; exact score histogram and score-only 80/85/90 per-rule operating points recorded; **NOT BLIND OR HOLDOUT EVIDENCE** |
| Audit database | schema v5; retry aggregation uses 300-second windows; raw capture remains default-off and TTL-deduplicated |
| Host-evidence assembler contract | **44/44 DEVELOPMENT SELF-TESTS PASS**; this is not CPA Host execution evidence |
| Linux unit / race | **DEVELOPMENT SELF-CHECK PASS** — `make unit-test`; `make race` reported no data race |
| Race package durations | plugin 379.920 s; classifier 69.762 s |
| Linux vet / modules / vulnerabilities | **DEVELOPMENT SELF-CHECK PASS** — `make round6-vet`, `make round6-module-verify`, `make round6-vulncheck`; 0 reachable vulnerabilities |
| Benchmark / allocation acceptance | **DEVELOPMENT SELF-CHECK PASS** — complete `make round6-benchmark`; allocation debt and same-machine comparisons are disclosed in `PERFORMANCE.md` |
| Workflow / release-document contracts | **DEVELOPMENT SELF-CHECK PASS** — the SHA-256-verified official Linux actionlint v1.7.12 release binary passed all eight active workflows using `.github/actionlint.yaml` with the reviewed `cag-round8-sandbox` label; the first `go run` attempt was excluded because `proxy.golang.org` timed out before actionlint started; release-document fixtures and the real-tree gate also passed; source-release exclusion passed against the current `HEAD` and is rerun after commit because it archives `HEAD` |
| Safe-gate contracts | **DEVELOPMENT SELF-CHECK PASS** — `Ran 178 tests`, `OK`; real-tree audit passed with `entrypoints=8 make_targets=33 scripts=33` |
| Fuzz | **DEVELOPMENT SELF-CHECK PASS** — deterministic fuzz smoke plus all 13 configured fuzz targets for 5 seconds each |
| CPA tag identity | **REMOTE TAG IDENTITY PASS** — official latest metadata remained `v7.2.95`; the exact tag commit is `v7.2.95@f71ec0eb6776854457892452cf28c47f0d658251` |
| CPA v7.2.95 source/compile/contract matrix | **DEVELOPMENT SELF-CHECK PASS** — pluginhost routing, Responses `additional_tools`, Interactions, fail-open, Raw Capture management, and the `v0.16-rc.2` Store contract |
| CPA remote latest/tag verification | **REMOTE-ENABLED CONTRACT PASS** — `CPA_COMPAT_VERIFY_REMOTE=1` verified official `releases/latest == v7.2.95`, the exact Git tag commit, module Origin, and module/go.mod sums, then completed the source/compile/contract matrix. |
| CPA counted-Mock Host execution | **NOT RUN / PENDING** for the pinned v7.2.95 lane; source/compile PASS is not Host evidence |
| Exact-main GitHub CI / tag / Release | **NOT RUN / PENDING** for this source snapshot; no `v0.16-rc.2` publication claim |
| Independent audit/evaluation | **NOT_PROVIDED / REQUIRED** |
| Production approval | **NOT_GRANTED** |
| Stable `v0.16` | **NOT_RELEASED** |

The final isolated classifier acceptance recheck improved short-request
p50/p95/p99 from the `d540eaa` baseline
173.973/282.720/406.484 us to 105.272/146.139/263.117 us. The single-clause
path recorded 132.119 us/op, 35,667 B/op, and 76 allocs/op; the candidate-rich
maximum-parts path recorded 45.245564 ms/op. Final paired long-text observations
ranged from 4.180488 ms for SemanticRich 1 MiB to 163.926518 ms for Text
Near-8 MiB. Paired standalone test binaries recorded 46,132 KiB baseline and
46,616 KiB Round 8 maximum RSS. Raw Capture
prepare/composite/queue-full/management and the wrapper audit fast path also
passed the checked-in latency/allocation ceilings; their exact values are
recorded in `PERFORMANCE.md`. These are in-process/standalone source-tree
results, not CPA Host performance.

## Historical v0.16-rc.1 local package baseline

Exact source version is `0.16`; the local Linux amd64 RC target is the exact
annotated tag `v0.16-rc.1`. A local package exists, but the tag has not been
pushed and no GitHub Release exists. This section describes the package baseline
at `7b2422e`, not the newer P1-P2 hardening branch. It does not claim
a successful GitHub Actions run, Actions artifact, real CPA Host load,
production deployment, independent audit, or formal attestation.

| Local package baseline evidence | Result |
|---|---|
| Classifier identity | `classifier-policy-v6` / `ece497210db938528cb166a34f2ce3013324b792a7eedf276a96fa5d256001d4` |
| Ruleset | `1.0.8` / `1d908c8c631bc6f72e7ec6b098bea49c4923580766859393d0be48c8c00c6d7d` |
| Audit schema | v4 with default-off `raw_request_captures` |
| Linux safe tests at package time | **PASS** — `make test`, including audit, config, extract, plugin and classifier |
| Linux vet / format / modules at package time | **PASS** — `make round6-vet`, `round6-format-check`, `round6-module-verify` |
| Local release-document and safe-gate contracts | **PASS at local package time** — release-document consistency and 154 Python contract tests are recorded in `local-rc-manifest.json`; this does not override the remote CI failures below |
| CPA v7.2.95 local source contract | **PASS** — pinned module/checksums, compile probes, registration, role-aware routing, integration compile and Store contracts |
| CPA official Git Origin repeat check | **NETWORK BLOCKED / NOT A PASS** — isolated direct refresh timed out after 60 seconds; an earlier direct Origin result identified the official repository, tag and commit, but the final repeated remote refresh was not completed |
| Local RC package | **CREATED / LOCAL ONLY** — manifest binds tag object `4c04e465ba10815e6ee7261e86807556c2e86102`, commit `7b2422ed30c11d405d05bcb6b46a2527eed6471b`, tree `d586824ed7f273e9f7f49f82d5ea0eb24bdd2da9`; SO SHA-256 `9d0ee747491dedeb83f3b3e98137d879dbaba5818e7a6922f9cf1f61d407e685`; Store ZIP SHA-256 `86e9eba5265d5f2bb737ec41d5ed8ada51bf352b3833c2d985d3f754963540f7` |
| Exact-main GitHub CI | **FAILED — run 29799561002, two attempts, zero Actions artifacts.** Attempt 1 failed in `fuzz-smoke` with `FuzzExtractText: context deadline exceeded`; attempt 2 passed fuzz-smoke and failed in `operational-script-security` when `round6-doc-consistency-fixture-test.sh` rejected a document mutation. Reproducibility was skipped both times |
| GitHub v0.16 publication | **NOT CREATED** — no remote `v0.16-rc.1` tag and no corresponding GitHub Release |

The raw-capture privacy review additionally verifies that a live disable must
drain and purge before runtime swap, and that cold startup rejects a disabled
runtime when an existing audit database cannot be opened/purged. If audit is
enabled but a new empty store is unavailable, enforcement may remain degraded,
while the raw-capture management endpoint returns HTTP 503 instead of an
authoritative empty list.

## Historical post-package P1-P2 development-branch self-check

These P1-P2 changes are not present in the local `v0.16-rc.1` package, its
manifest, or its checksums. They predate and are superseded by Round 8. All
results in this section remain **HISTORICAL DEVELOPMENT SELF-CHECK / NOT CURRENT
RELEASE EVIDENCE**.

| Current working-tree check | Result |
|---|---|
| Source identity | Branch `fix/p1-p2-hardening-v016`, based on `7b2422ed30c11d405d05bcb6b46a2527eed6471b`; no artifact binding |
| P2 long-JSON Text scaling | **SELF-CHECK PASS**, including Near-8 MiB `ns/byte <= 2.5x` 1 MiB gate — 1 MiB: 20.0 ms, 342,036 B/op, 45 allocs/op; Near-8 MiB: 155.7 ms, 341,997 B/op, 45 allocs/op |
| P2 long-JSON KeyRich scaling | **SELF-CHECK PASS**, including slope gate — 1 MiB: 4.89 ms, 372,029 B/op, 17,205 allocs/op; Near-8 MiB: 41.8 ms, 2,409,686 B/op, 137,464 allocs/op |
| P2 long-JSON SemanticRich scaling | **SELF-CHECK PASS**, including slope gate — 1 MiB: 4.33 ms, 160,400 B/op, 5,473 allocs/op; Near-8 MiB: 32.9 ms, 717,366 B/op, 43,553 allocs/op |
| Near-8 MiB raw-capture prepare acceptance | **SELF-CHECK PASS** — threshold <= 1.2 s, <= 4 MiB/op, <= 160 allocs/op; observed 457,790,105 ns/op, 3,355,125 B/op, 43 allocs/op |
| Near-8 MiB composite admission acceptance | **SELF-CHECK PASS** — threshold <= 1.5 s, <= 5 MiB/op, <= 200 allocs/op; observed 454,296,686 ns/op, 3,360,418 B/op, 68 allocs/op |
| Queue-full early rejection acceptance | **SELF-CHECK PASS** — threshold <= 50 us and zero allocation; observed 46 ns/op, 0 B/op, 0 allocs/op |
| Worst-case raw-capture management-response acceptance | **SELF-CHECK PASS** — threshold <= 500 ms, <= 16 MiB/op, <= 1,600 allocs/op; observed 54,596,462 ns/op, 8,529,000 B/op, 1,329 allocs/op |
| p50 / p95 / p99 / peak RSS | **NOT MEASURED / UNAVAILABLE** — the targeted `testing.Benchmark` acceptance checks do not collect these metrics |
| Full post-hardening Linux test, race, vet, script, 157-test safe-gate, 13-target fuzz seed, complete `round6-benchmark`, and CPA v7.2.95 Host source-overlay set | **DEVELOPMENT SELF-CHECK PASS** |
| Superseding Round 8 workflow-governance follow-up | **HISTORICAL DEVELOPMENT SELF-CHECK PASS** — 174 safe-gate mutation tests, the eight-entrypoint repository safe gate, actionlint v1.7.12 on all eight active workflows with the reviewed custom-runner-label config, release-document consistency, and final `git diff --check` |
| Exact-working-tree GitHub Actions / package / real CPA Host | **NOT AVAILABLE / NOT RUN** |
| P0 client-controlled assistant-history bypass | **UNRESOLVED / RELEASE BLOCKER** |

Passing these development checks does not retroactively repair exact-main run
`29799561002`, authorize a tag or release, or prove production performance.

## Historical Round 6 v0.15 test status

The section below is a frozen pre-publication record. It is not current v0.16
evidence. The later `v0.15` stable Release was manually published on 2026-07-20
with ten assets and an owner-reported sandbox result; no independent attestation
was attached.

Historical project version is `0.15`; its formal tag is `v0.15`, never
`v0.15.0`. Active validation and the supported release target are fixed at
CPA v7.2.95 at `f71ec0eb6776854457892452cf28c47f0d658251`.
Later upstream versions are not followed automatically.
Legacy version-specific profiles and Make aliases have been removed.

| Current Round 6 evidence | Result |
|---|---|
| Last fully verified pre-cleanup main baseline | `6782dfaffd4da3f09604113c7d38675f331dc759`, tree `a8edbe2e6d19fa725fb962cdd6aaad5b416d4b85` |
| Round 6 implementation PR | [#9](https://github.com/yujianwudi/cyber-abuse-guard/pull/9) **MERGED**; head `d0b63c67e099d403be1a8ad0a3183c9474ac5b9a` |
| PR CI | [29620335143](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29620335143) jobs did not start because of GitHub billing; **NOT A PASS** |
| Exact post-merge main CI | [29630844605](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630844605) **SUCCESS** |
| Source-only prerelease tag CI | [29630926354](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630926354) **SUCCESS** for the same commit/tree |
| Public `v0.15-rc.1` prerelease | Exists with no attached release assets; not the private clean candidate or formal release |
| Classifier identity | `classifier-policy-v5` / `0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b` |
| Historical hardening PR | [#18](https://github.com/yujianwudi/cyber-abuse-guard/pull/18) was merged; this frozen row does not establish v0.16 source or release evidence |
| Quoted-review reactivation and long-streaming delta | **PASS / LOCAL DEVELOPMENT EVIDENCE**: direct referent-result equivalence, rule and semantic categories, multi-action and multi-cancellation family ordering, alternative-branch controls, narrow `follow`/`obey`/quoted-request imperatives, defensive neighbors, `just`/`simply`/`let's`/`let us` governors, active/inert/unrecognized parsing, mixed-trust origin, newest-user-review binding, non-user provenance isolation, wrapper-safe adjacent suppression, long current/previous fields, dual cross-window degradation, and `MaxChunks` accounting |
| Linux safe unit and race checks | **PASS / LOCAL DEVELOPMENT EVIDENCE**: full `make unit-test`; classifier and plugin `-race`; OpenAI Chat/Responses long quoted-review routing; 64 KiB through near-effective-RPC-limit position/coverage ladders |
| Release-document and formal-package contracts | **PASS / LOCAL DEVELOPMENT EVIDENCE**: real-tree identity gate, mutation fixture, 152 safe-gate contract tests, formal environment-override rejection, and required/install/verify binding for the public jailbreak audit report |
| `make round6-script-test` | **PASS / LOCAL LINUX DEVELOPMENT EVIDENCE** in a WSL-native exact source snapshot; candidate/attestation/source-exclusion/frozen-v10 contracts, safe gate, archive/HMAC/privacy, document mutation fixture, and real-tree document gate all passed |
| Subject-admission and four-repository Linux self-check | **PASS / LOCAL DEVELOPMENT EVIDENCE**: safe allowlist, vet, targeted race, 36-case sanitized corpus, repository-neutral four-family carrier matrix, and pinned CPA v7.2.95 module/source/compile contracts; real Host remains pending |
| Private untagged clean candidate artifact / manifest | **NOT CREATED / PENDING** |
| CPA v7.2.95 Host + Mock | **NOT RUN / PENDING** |
| Four-layer Auth/Provider/Usage/Mock zero-call proof | **NOT RUN / PENDING** |
| Independent source/artifact/Host audit | **NOT RUN / PENDING** |
| Candidate-bound external evaluation-v11 or later | **NOT RUN / PENDING**; must be first-and-only `CONSUMED / PASS` |
| `round6-prerelease-attestation.json` | **NOT CREATED / PENDING** |
| `formal-release-attestation.json` and protected promotion | **NOT CREATED / NOT RUN / BLOCKED** |

The merged implementation baseline and its exact main/tag CI are engineering
evidence only. The PR jobs that did not start are not retrospectively called a
PASS. Any later source cleanup must pass its own CI before it can supersede this
baseline. The current subject-admission self-check is not push/PR CI, native Host
evidence, or release approval. The private candidate workflow has not been dispatched; when used, it
must produce a private, untagged, clean exact-source Actions artifact whose
`candidate-manifest.json`, `build-metadata.json`, SO, and Store ZIP bind that
exact post-merge main commit/tree. Clean candidate bytes are unreleased. The
v7.2.95 Host record and the independent audit must cite the same SO SHA-256;
schema v2 binds it with `cpa_version`, `cpa_commit`, and `cpa_host_sha256`.

After Host/audit and candidate-level evaluation PASS, an optional annotated
`v0.15-dev.round6[.N]` draft prerelease may preserve the evidence but remains
`BLOCKED / NOT A FORMAL RELEASE`. Its prerelease attestation records the
evaluation ID and report SHA-256; the annotated formal `v0.15` tag and verified
draft consume that same attestation. Protected promotion may publish only the
unchanged draft.

The final PR head must have no unresolved, non-outdated actionable review
threads before merge. Automated review is advisory; no independent approval is
claimed.

The quoted-review hardening reclassifies only the unique quote when the newest
eligible trusted RoleUser safety review receives an affirmative referential
directive. It does
not reuse the safety wrapper's signals or context. Mixed-trust RoleUser pairs
retain conservative direct disposition with `non_user_or_untrusted` origin but
cannot accumulate subject risk. Complete long fields retain only privacy-safe
results and bounded follow-up facts; an unprovable
cross-window relationship becomes `classifier_window_incomplete`, while an
insufficient extra classification budget remains `classification_chunk_limit`.
The Linux checks above are source-level development evidence only and do not
replace exact-head GitHub CI, the candidate artifact, CPA v7.2.95 Host + Mock,
or independent source/artifact/Host review.

The neutral admission policy is [RELEASE_POLICY.md](../RELEASE_POLICY.md).
Future decisions are external `round6-prerelease-attestation.json` and
`formal-release-attestation.json` assets, not source-report self-claims.

Historical evaluation-v10 remains `CONSUMED / FAIL`, cannot be rerun, and is
not a formal-build input. Formal source/audit bundles exclude evaluation,
Holdout, private, blind, and retired material.

The v7.2.80 PASS rows below are retained as frozen historical Round5.2
source/compile evidence only. Historical 0.1.2 hashes, tags, assets, and v10
facts are not rewritten.

## Frozen Round5.2 source-freeze / pre-merge evidence status

This section records only evidence that can be frozen before merge: source
identity, safe local gates, exact-source branch push CI, the PR synthetic
merge-result gate, and review state. It deliberately does
not self-reference a future merge commit. Post-merge main CI, the exact-main
artifact, tag, release flags, and release asset hashes are authoritative only
through GitHub API metadata; the corresponding Release notes link those records
and preserve per-asset hashes and incomplete gates. The repair
branch starts from historical
`main@89b62b341278073e7b6518b85e41cd7f7c6b682c`; the pre-merge fields below are
backfilled from actual local and GitHub evidence. Tencent Cloud isolated
Host validation and independent source/artifact review remain separate gates.

```text
ROUND5.2 SOURCE FREEZE, LOCAL GATES, PUSH/PR CI, AND REVIEW PASS /
MERGE, MAIN CI, ARTIFACT, TAG, AND RELEASE PENDING /
REAL HOST AND INDEPENDENT REVIEW NOT RUN /
METHODOLOGY HANDOFF BLOCKED
```

| Round5.2 evidence | Result |
|---|---|
| Source fixes | **COMPLETE / SOURCE FREEZE READY** |
| Source-freeze commit | `170de7f324c2bdf9a473b1866bdfc1e097182301` |
| Source-bound classifier identity | `classifier-policy-v2` / `e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec`; identity test **PASS** |
| CPA v7.2.80 latest source/compile lane | **DEVELOPMENT SELF-CHECK AND EXACT-SOURCE PUSH/PR CI PASS**; `CPA_LATEST_VERIFY_REMOTE=1 make cpa-latest-compat` verified GitHub `releases/latest` and Tag-to-Commit; pinned checksums, Guard/integration compile probes, real Guard registration/route tests, 17 official Host routing/status tests, 11 official Interactions route/handler tests, and three checksum-pinned overlays passed; no Host or `.so` load |
| Public-reference sanitized corpus | **PASS**; 36 cases = 18 allow + 18 audit, 34 role-aware + 2 conservative-untrusted; development-only and future-Holdout-ineligible |
| Safe local gate record | **PASS** — format/diff/module, Round5, safe test/vet, sanitized public corpus, scripts, and CPA latest remote identity/contracts |
| Exact-source branch push CI and PR synthetic merge-result CI | Push [29467936241](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29467936241) attempt 1 **SUCCESS**; PR [29467938359](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29467938359) attempt 1 **SUCCESS** for base `89b62b341278073e7b6518b85e41cd7f7c6b682c`, head `170de7f324c2bdf9a473b1866bdfc1e097182301`, synthetic merge `fc8b5649505662e47bedbd85a41fbea306a2df7c`; `quality-and-artifacts`, `fuzz-long`, and `reproducibility` passed in both runs |
| Exact-source development artifact | Push artifact `8363874523`, `cyber-abuse-guard-linux-amd64-dirty`, `10827848` bytes, digest `sha256:fdec405e991498d4b7fb16557796a22736456c01fb1bd0e31d8eac5800438176`, expiry `2026-10-14T03:00:42Z`; binds freeze `170de7f324c2bdf9a473b1866bdfc1e097182301`; not a release artifact or native Host load |
| PR and CodeRabbit follow-up | PR [#8](https://github.com/yujianwudi/cyber-abuse-guard/pull/8); CodeRabbit CLI `0.6.5` final source-delta review **PASS / 0 issues**; GitHub check **SUCCESS**; 10 of 10 current PR review threads resolved (9 source-freeze + 1 documentation wording) |
| Post-merge main CI and exact-main artifact | **EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES** |
| Tag, release flags, and release asset hashes | **EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES** |

Targeted round5.2 checks already completed before the final broad safe-gate
rerun are recorded below. They supplement, but do not replace, the exact
source-freeze identity, full local gate record, branch/PR CI, or CodeRabbit follow-up.

| Targeted command | Exit | Scope |
|---|---:|---|
| `go test ./internal/classifier -run='^TestClassifierPolicyIdentity$' -count=1` | 0 | Source-bound policy identity `e9b87f7e...` matched the reviewed source list |
| `go test ./internal/classifier -run='^TestRound5(RepeatedIntentYInflectionsFailActive\|NegatedProhibitionModalBridgeFailsActive)$' -count=1` | 0 | Sanitized CANARY regressions preserved active EXFIL-003 risk across `copy/copies/copied` and negated prohibition modal/contraction variants |
| `GOMAXPROCS=1 go test ./internal/classifier -run='^TestMetaOverrideClauseBudget' -count=1 -v` | 0 | Period/semicolon/newline `8 x 32 KiB` inputs rejected defensive credit; about 7-10 ms, 1.36 MiB/op, 40 allocs/op after the bounded-clause fix |
| `go test ./internal/classifier -run='^TestRound5RefusalScopeOutputAndCompoundIntentHardening$' -count=1` | 0 | Concealed override and filter-boundary/long-padding regressions passed with benign neighbors |
| `go test ./internal/extract -run='^TestExtractRawPartsToolTransactionSharesPartBudget$' -count=1` | 0 | Shared part budget retained `content=first`, excluded tool argument `second`, and reported truncation |
| `go test ./cmd/development-public-jailbreak-patterns-v1-validator -count=1` | 0 | 36 sanitized cases: 18 allow, 18 audit, 34 role-aware, 2 conservative-untrusted |
| `CPA_LATEST_VERIFY_REMOTE=1 make cpa-latest-compat` | 0 | CPA v7.2.80 `releases/latest`, Tag-to-Commit, checksums, Guard/integration compile probes, real Guard registration/route tests, 17 official Host routing/status tests, 11 official Interactions route/handler tests, and three checksum-pinned overlays; no Host or `.so` load |
| `ALLOW_DIRTY_BUILD=1 make release-preflight` | 0 | Every tracked shell script has Git mode `100755`; dirty development preflight passed without creating a formal release |

## Historical round5.1 release evidence

Historical `v0.1.2-dev.round5.1` is treated as a project-policy snapshot, while
GitHub reports `isImmutable=false`; it remains a `BLOCKED / NOT FOR DEPLOYMENT`
prerelease. Its tag must remain at
`89b62b341278073e7b6518b85e41cd7f7c6b682c` and must not be moved to round5.2.

| Evidence | Historical result |
|---|---|
| PR #7 | Merged as `89b62b341278073e7b6518b85e41cd7f7c6b682c` |
| Main CI | [29409182748](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29409182748): attempt 1 failed at a fuzz timer-boundary `context deadline exceeded`; attempt 2 passed `quality-and-artifacts`, `fuzz-long`, and `reproducibility` |
| Canonical exact-main artifact | ID `8340894661`, `cyber-abuse-guard-linux-amd64-dirty`, `10691298` bytes, container digest `sha256:7419fcf0c0745472728d6e9c73d99aa01737930ccf25e26501e17ae4d453db61`, expiry `2026-10-13T10:54:12Z` |
| Build identity | `build-metadata.json` binds commit `89b62b341278073e7b6518b85e41cd7f7c6b682c`; SO SHA-256 `3176d2af23963a2768672034af02fc1ca9ebe0c3f29a3654aa802ce0f822b6be` |
| Release flags | `prerelease=true`, `latest=false`; stable `v0.1.2` tag absent |
| CodeRabbit | Local CLI follow-up recorded 0 issues, but the GitHub Bot comment later ended `Review failed — pull request is closed`; no CodeRabbit approval is claimed |

The following local results are historical round5.1 `DEVELOPMENT SELF-CHECK`
evidence only. They do not validate the current round5.2 working tree and do not
replace Tencent Cloud Host validation or independent review. General gates were
rerun with the repository CI toolchain (`GOTOOLCHAIN=go1.26.4`) after the final
Tool-schema test change; the earlier full safe race and fuzz runs used the
installed Go 1.26.0 toolchain. No command below started CPA, loaded the real
Guard `.so`, ran `make integration-test`, or selected a holdout/evaluation test.

| Command | Exit | Result |
|---|---:|---|
| `GOTOOLCHAIN=go1.26.4 make format-check git-diff-check module-verify round5-regression development-public-jailbreak-corpus` | 0 | Final pre-freeze rerun passed. Round 5 covered scalar media, multipart schema precedence, all five Tool-schema boolean mappings plus false controls, meta families, negation reversal, plugin counters/privacy, and the canonical development corpus validator. |
| `GOTOOLCHAIN=go1.26.4 make test vet` | 0 | Safe-package unit tests, explicitly allowlisted classifier tests, and vet passed. Historical/evaluation author packages were compile-only with `-run='^$'`; no consumed/holdout test was selected. |
| `make race` | 0 | Full safe allowlist race gate passed, including extract, plugin, classifier, audit, subject, and validator packages. |
| `GOTOOLCHAIN=go1.26.4 go test -race ./internal/extract -run='^TestToolSchemaKnownBooleanControlIsMapped$' -count=1` | 0 | Final added Tool-schema true/false mapping test passed under race instrumentation. |
| `make fuzz-smoke` | 0 | Eleven bounded fuzz targets passed: six extract, four classifier/meta, and one config target. |
| `make benchmark` | 0 | Quiet rerun passed all acceptance gates and benchmarks. Candidate-rich classifier `135.042168ms/op` (<250ms), near-budget `19.833569ms/op` (<50ms), near-budget allocation `302962 B/op`; meta long/many-parts/bilingual `22.002828ms` / `11.591201ms` / `41.129us`; negation flood `616.791us`, `259295 B/op`, 309 allocs; multipart unknown-file 1/8 MiB remained `44946 B/op`, 61 allocs. |
| Privacy command shown below | 0 | Route/audit/SQLite/management/export/multipart privacy canaries passed with no reported canary leakage. |
| `make script-test` | 0 | Safe-development script syntax, mock production-health isolation, Store archive layout, HMAC-key generation, release-evidence privacy, and release-document consistency tests passed. |
| `make integration-compile` | 0 | Integration-tagged package compiled with no tests selected; CPA was not started and no `.so` was loaded. |
| `GOTOOLCHAIN=go1.26.4 make cpa-host-fixture-contract` | 0 | Pinned CPA v7.2.75 source-contract and temporary source-fixture fail-open tests passed. This is source evidence, not a real Guard artifact/Host run. |
| `GOTOOLCHAIN=go1.26.4 make vulncheck` | 0 | `No vulnerabilities found`; zero called vulnerabilities on the pinned CI Go version. |

Exact privacy command:

```bash
go test -tags=sqlite_omit_load_extension \
  ./internal/plugin ./internal/audit ./internal/extract \
  -run='^(TestManagementEventDeletionWritesPrivacySafeAuditMarker|TestCallerControlledAuditMetadataIsPrivateAcrossEventsSQLiteAndManagementAPI|TestMultipartSchemaAuditIsFixedAndPrivate|TestOversizedRouteWritesPrivacyMinimalAuditEvent|TestEndToEndPrivacyCanariesStayOutOfAllowedOutputs|TestMultipartUnknownFileFieldAuditIsFixedAndPrivate|TestStrictUnknownSourceFormatPersistsPrivacyMinimalAudit|TestMigrationRejectsPrivacyUnsafeLegacyRowsBeforePublishingBackup|TestStoreRoundTripPrivacyAndSafeExports|TestExtractRequestMultipartUnknownFieldIsIncompleteAndPrivate|TestExtractRequestMultipartJSONLikeUnknownFieldsAreSchemaIncompleteAndPrivate)$' \
  -count=1 -v
```

Two non-PASS first attempts are retained for audit transparency:

- The first `make benchmark` exited 1 while an unrelated WSL benchmark process
  consumed a CPU core: candidate-rich `402.684538ms/op` and near-budget
  `60.416452ms/op`. After that process ended, the isolated acceptance rerun was
  `152.461093ms/op` / `23.804648ms/op` (exit 0), followed by the full quiet
  `make benchmark` PASS recorded above. No source change was made to obtain the
  performance PASS.
- The first `make vulncheck` exited 3 under local Go 1.26.0 because three
  standard-library findings were already fixed in Go 1.26.1/1.26.4. The exact
  CI toolchain rerun under Go 1.26.4 exited 0 as recorded above.

Historical round5.1 exact-freeze coverage and remaining remote gates were:

| Gate | Executed evidence / remaining status |
|---|---|
| HIGH-A scalar `source`/`uri`/`url`/`image_url` order invariance | **PASS** — `round5-regression`, permutation fuzz, privacy assertions, and bounded benchmark passed locally and in exact-source CI |
| HIGH-B multipart unknown-field precedence | **PASS** — fixed `multipart_unknown_field` disposition, plugin privacy/counter tests, evidence-order fuzz, and 1/8 MiB allocation benchmarks passed |
| Meta-override families and benign neighbors | **PASS** — fixed family evidence, wrapper-only allow/audit, persistent injection, compound intent, quoted analysis, bilingual cases, fuzz, and benchmarks passed |
| Tool key-only control | **PASS** — `meta_override_control/v1` maps all five approved booleans only in tool provenance; false controls remain inert and unknown known-schema controls become `tool_schema` incomplete |
| Sanitized public-taxonomy corpus | **PASS** — strict validator passed; manifest remains development-only, future-Holdout-ineligible, and contains no live payloads |
| General quality | **PASS** — module verify/tidy-diff, safe unit/race, vet, fuzz-smoke/long fuzz, benchmark, privacy, scripts, vulncheck, SBOM, package verification, and reproducibility |
| Integration | **PASS AT COMPILE/SOURCE-CONTRACT LEVEL ONLY** — ordinary CI ran `make integration-compile` and CPA v7.2.75 source contracts; it did not start CPA or load `.so` |
| Artifact | **VERIFIED HISTORICAL DEVELOPMENT EVIDENCE** — exact-main artifact `8340894661` has an archive-level digest; release assets have individual SHA-256 records, but no retained member-to-asset equivalence map; audit bundle body was not opened |
| Host/independent review | **NOT RUN** — reserved for Tencent Cloud CPA v7.2.75 isolated container with Mock upstream, followed by separate source/artifact review |

No PASS in this table transfers to the current round5.2 working tree. Round5.2
must establish a new freeze and rerun every applicable gate.

Ordinary CI deliberately excludes `make consumed-boundary-test` and every
evaluation-v10/retired-Holdout content path. The target remains only as an
explicit, separately authorized manual audit entry. Ordinary CI also no longer
runs `make integration-test`; the real CPA Host targets remain explicit/manual
and the fifth-round Tencent Cloud Host matrix is pending.

Fifth-round methodology deviation: one over-broad read-only `git grep`
unexpectedly emitted content from the restricted
`testdata/holdout/malicious-operational.jsonl` file. No holdout test ran; the
output was not redirected, copied into source/tests/docs, analyzed, or used for
tuning or conclusions. During the later release audit, one classifier source
search also unintentionally matched historical holdout gate-test source lines;
it opened no `testdata` corpus, selected no holdout/evaluation test, and did not
influence the fixes. All remaining commands explicitly exclude holdout,
evaluation-v10, and retired/historical paths. The final report must not claim
zero restricted-corpus access, and methodology handoff remains blocked.

During the post-release round5.2 re-audit, a case-insensitive path exclusion
failed and a read-only status search printed exactly one status line from each
of `EVALUATION_V5_REPORT.md` through `EVALUATION_V10_REPORT.md`. No evaluation
corpus or sample row was opened, printed, classified, extracted, or used for a
source, test, documentation, or release decision. This additional disclosure
does not change v10 `CONSUMED / FAIL` and keeps methodology handoff blocked.

During the same re-audit, a classifier sub-agent mistakenly started
`go test -shuffle=on -count=20 ./...`. The root process interrupted it after
about 23 seconds and sent `TERM` to PID `265343`. The same command then
reappeared as PID `266741` with WSL `/init` as its parent, consistent with an
orphaned CodeRabbit/tool session. The root interrupted the classifier agent
again, terminated every matching process, and verified that none remained. It
is unknown whether a consumed evaluation or Holdout test selected or read a
restricted fixture before termination. The command and every partial result
are permanently excluded and did not inform source, tests, documentation, or
release decisions. All subsequent validation is constrained to the explicit
safe allowlist. This round cannot claim no restricted access; v10 remains
`CONSUMED / FAIL`, and methodology handoff remains blocked.

During the final independent diff audit, an overly broad read-only
`cmd/**/*.go` search printed evaluation/holdout author-source snippets and a
few synthetic examples. It did not open restricted `testdata`, execute an
author/evaluation/holdout tool, or influence source, tests, documentation, or
release conclusions. The output is permanently excluded; the methodology
handoff remains blocked.

The Router cannot attest to local `model_instructions_file`, `AGENTS.md`, or
remote-template integrity before CPA receives a request. Provider
`safetySettings`, `generationConfig`, `options`, and equivalent controls require
a host-side versioned schema allowlist with rejection or forced-safe-value
overrides. Embedded ruleset `1.0.7` covers YAML assets only and excludes the Go
`META-OVERRIDE-001` overlay and related extractor/tool-schema/control-plane
logic. The historical round5.1 policy identity is `classifier-policy-v2` /
`c2092d0949fcaa1d0f085dfe31a668d45cc4d14efc10427d0f3ebcf3e821a112`.
The round5.2 source-bound identity is `classifier-policy-v2` /
`e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec`;
the exact source-freeze Commit remains a separate pre-merge field.

Two P2 items remain explicit review scope. First, role-aware classification
does not compose base taxonomy from system/assistant text into a later user
message; host validation of high-priority instruction provenance,
owner/mode/hash/signature, and reload state is therefore mandatory. Second,
`Segments` currently performs a second bounded JSON parse after the primary
extractor walk. Existing differential/race/fuzz tests have not reproduced a
leak, but a single shared semantic parse product is still the intended future
hardening.

One historical round5.1 task-book evidence gap also remains: base `67b2470` to
pre-audit freeze `1466b2e7` is a single composite implementation commit. Exact
post-fix regressions are green, but no independently preserved pre-fix red-test
commit or command log exists for the two HIGH cases. This report does not infer
historical red status from the final green result.

Unit or CI success is not production admission. The engineering evidence package
can be inspected independently, but the recorded methodology incident keeps the
formal handoff `BLOCKED FOR HANDOFF`; it must never be labeled
`PRODUCTION APPROVED`.

---

## Historical prior-round report

## Historical current status

**BLOCKED FOR HANDOFF.** The actual starting baseline is
`a121a444cb0d82cba4e27754914a1f88258e1d7b`. Classifier reference commit
`a1be19f` is followed by idempotency/reliability commits `b84ed2a` and
`573def2`, Host/isolation commit `1973083`, review-closure commit `8814dbf`,
provider-probe lifecycle commit `9c8114e`, evidence reconciliation commit
`8719c7f`, and final review-correctness implementation freeze
`61536f9f02c47a4d79031a47dc8a284f040e41c1`. Evidence documents are
committed separately and identify themselves through their containing commit.

The root dependency is CLIProxyAPI v7.2.72 at upstream tag commit
`6279bb8a4c2835ff6ed99c6b85083b2afbefa681`. Module checksums are:

```text
module_sum: h1:ppce0MLsz2xJi2yi3/A60zu03cM7bMWBAEJ6eC29E5Y=
go_mod_sum: h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=
```

The classifier identity is `classifier-policy-v2` /
`dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2`.
Ruleset `1.0.7` remains separate YAML identity.

No consumed v10 sample was opened, printed, classified, extracted, inspected
through Git history, or emitted by a helper. Only the frozen aggregate report
was used. v10 remains `CONSUMED / FAIL`.

Methodology incident: three incorrectly scoped WSL source-search commands
unexpectedly emitted several rows from the retired `testdata/holdout-v3`
corpus. All three searches were stopped immediately; those rows were not
analyzed or used for tuning or conclusions. Evaluation v10 content was not accessed.
The retired holdout-v3 corpus is no longer eligible as independent evidence,
and this incident independently keeps the handoff `BLOCKED FOR HANDOFF`.

## Evidence vocabulary

| Label | Meaning |
|---|---|
| `DEVELOPMENT SELF-CHECK` | A named local command ran on a development tree; useful but not final evidence. |
| `SOURCE IMPLEMENTED` | Code/tests exist; no execution result is implied. |
| `SOURCE OVERLAY PASS` | A pinned upstream source/contract test ran; this is not a native Guard Host run. |
| `GITHUB CI` | A remote check on the exact pushed commit. Older/main checks are not transferable. |
| `REAL HOST` | The real Guard `.so` loaded by CPA v7.2.72 and exercised through HTTP. |
| `LOCAL MIS-EXECUTION / EXCLUDED` | The command ran outside the authorized evidence path; its result is permanently excluded and any GitHub CI or Leo result must be cited separately. |
| `NOT RUN` | No result exists for the named tree/environment. |
| `BLOCKED` | A prerequisite or final freeze is missing; never equivalent to PASS. |

Three WSL commands were mistakenly executed outside the authorized evidence
path:

```text
make cpa-router-fixture-blackbox
# removed historical command: make cpa-v7272-host-blackbox
scripts/management-proxy-413-test.sh
```

They used random loopback ports and Mock components only, contacted no real
provider or production service, and cleanup left no fixture process running.
Their results are excluded and must never be reported as PASS:

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

## Classifier and development-corpus checks

| Evidence class | Command | Result |
|---|---|---|
| DEVELOPMENT SELF-CHECK | `go test ./internal/classifier -run '^(TestWrapper\|TestBehaviorGraph\|TestMetaOverride\|TestAssistant\|TestSystem\|TestNoPermission\|TestExplicitNoPermission\|TestNegativeAuthorization\|TestMaliciousSystemPolicy\|TestClassifierPolicyIdentity\|TestEvaluationV10)' -count=1` | **PASS**; v10 cases here are aggregate/consumed-boundary checks only, not sample classification |
| DEVELOPMENT SELF-CHECK | `go test ./cmd/development-adversarial-v11-prep-validator -run '^TestDevelopmentAdversarialV11PrepCorpus$' -count=1` | **PASS — 35 visible development cases** |
| DEVELOPMENT SELF-CHECK | `CGO_ENABLED=0 go test ./internal/plugin -run '^TestPromptInjection(ControlPlaneRegression\|NestedToolAndSplitEncodingRegression)$' -count=1` | **PASS** |
| DEVELOPMENT SELF-CHECK | `go vet ./internal/classifier ./cmd/development-adversarial-v11-prep-validator` | **PASS** |
| DEVELOPMENT SELF-CHECK | classifier-related `gofmt -l` | **PASS — empty output** |
| DEVELOPMENT SELF-CHECK | `git diff --check` at time of classifier review | **PASS** |
| DEVELOPMENT SELF-CHECK | root `go mod verify` | **PASS — all modules verified** |
| DEVELOPMENT SELF-CHECK | root `go mod tidy -diff` | **PASS — empty output** |
| Safe broad Go test/race/boundary | `scripts/go-safe-development-test.sh test`, `scripts/go-safe-development-test.sh race`, `scripts/go-safe-development-test.sh boundary` | **DEVELOPMENT SELF-CHECK PASS** on WSL Ubuntu 26.04 / Go 1.26.4; test/race ran no Evaluation/Holdout test name; boundary ran only 3 v10 aggregate/report-marker/rerun-rejection tests and logged fixture not accessed |
| GITHUB CI | implementation freeze `61536f9` | **PASS** — push run [29312969925](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312969925), PR run [29312971717](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29312971717); push long fuzz PASS, both reproducibility jobs PASS |
| CodeRabbit Ready review | Initial review of `8719c7f`, followed by delta review through `61536f9` | Initial review posted 8 actionable threads and 2 nitpicks; valid findings were fixed in `61536f9`, the missing `cmd` symbols finding was disproved by targeted compilation, and the follow-up review reported no actionable comments |

The development corpus contains 16 block, 14 allow, 2 audit, and 3 resource-
boundary fixtures. It covers all eight taxonomies, four protocols, English,
Chinese, mixed language, wrapper contrasts, defensive/remediation/CTF/lab/
authorized contexts, role and multi-turn composition, tool payload/output,
bounded encodings, placeholders, max parts, near scan budget, and truncation.
It is permanently `development_only=true` and
`future_holdout_eligible=false`; Leo must not reuse it as a future v11.

## Reliability, idempotency, lifecycle, and privacy

Executed on WSL/ext4 with Go 1.26.4, CGO enabled, and `-race` where shown:

| Evidence class | Command/scope | Result |
|---|---|---|
| DEVELOPMENT SELF-CHECK | `go test -race ./internal/subject ./internal/config -count=1 -v` | **PASS** |
| DEVELOPMENT SELF-CHECK | `go test -race ./internal/audit -count=1 -v` | **PASS** |
| DEVELOPMENT SELF-CHECK | plugin tests for subject idempotency, concurrent duplicate/shutdown, register/reconfigure/shutdown, privacy canaries, caller metadata, production status, persistence restore, pending/logger race | **PASS** |
| DEVELOPMENT SELF-CHECK | `go vet ./internal/audit ./internal/config ./internal/plugin ./internal/subject` | **PASS** |
| DEVELOPMENT SELF-CHECK | `scripts/check-production-health-test.sh` | **PASS** |
| DEVELOPMENT SELF-CHECK | `scripts/release-evidence-privacy-test.sh` | **PASS** |
| DEVELOPMENT SELF-CHECK, Windows | targeted idempotency, pending-cache, and lifecycle tests | **PASS** |
| Windows native SQLite/race | release-equivalent CGO/NTFS path | **NOT RUN / unsupported release path** |

The idempotency checks cover execute, execute_stream, count_tokens, retry,
same request hash, concurrent duplicate, pending miss/expiry, enabled
reconfigure, persistence restore, and shutdown race. HMAC/SQLite checks cover
owner/mode, symlink/FIFO/device, empty/short keys, key-ID change, migration
backup collision/rollback, audit flush/close, and coarse error privacy.

## CPA v7.2.72 source and Host matrix

Local WSL native runs were mistakenly executed and remain excluded; they are
not converted into PASS. Separately authorized GitHub CI on the exact
implementation freeze passed the real Host and artifact paths. Leo independent
verification remains not run.
One exception cannot be closed by that CI: Guard returns an RPC status error
carrying 405, while CPA v7.2.72's provider-specific public
`POST /v1/alpha/search` consumer normally selects `codex` and maps every
executor error to final HTTP 502. No current official route maps Guard's error
to final client HTTP 405.

| Gate | Evidence class | Result |
|---|---|---|
| Root `go.mod` pins CPA v7.2.72 | source inspection/module verify | **PASS** |
| Exact set of 16 official Host tests exists and runs by name | SOURCE OVERLAY | **PASS on Windows/source-contract path** |
| Official `InstallArchive` source contract | SOURCE OVERLAY | **PASS with synthetic bytes** |
| Real Guard `.so` first install and Host load through `InstallManifest` | REAL HOST | **GITHUB CI PASS**; local mis-execution remains excluded |
| Same-Dist repeat-skip and tamper-repair through `TestPublishedStoreArchive` | REAL ARTIFACT | **GITHUB CI PASS** with required real Dist artifacts; synthetic fallback was disabled |
| OpenAI Chat allow/block, stream pre-SSE, token-count | REAL HOST | **GITHUB CI PASS** |
| OpenAI Responses allow/block, stream pre-SSE, token-count | REAL HOST | **GITHUB CI PASS** |
| Anthropic allow/block, stream pre-SSE, token-count 403 | REAL HOST | **GITHUB CI PASS** |
| Gemini allow/block, stream pre-SSE, token-count 403 | REAL HOST | **GITHUB CI PASS** |
| `executor.http_request` unsupported status at official `ProviderExecutor.HttpRequest` adapter | SOURCE / ADAPTER | **CHECKED — nil response + 405 status error** |
| Final official CPA handler/client HTTP 405 for Guard `http_request` | OFFICIAL HOST | **NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF; project `httptest.Server` is not official Host evidence** |
| Blocked Auth Selector/Provider/Usage/Mock Upstream all zero | REAL HOST | **GITHUB CI PASS** |
| Safe allow path increments native counters and preserves model/body/tools | REAL HOST | **GITHUB CI PASS** |
| Router priority, equal-ID ordering, route error, invalid target, identifier/format/scope not-ready, guard missing/register-fail/disabled, native fallback | REAL HOST fixture | **GITHUB CI PASS — 15 isolated scenarios** |
| Fuse and pre-result panic | official source overlay | **SOURCE OVERLAY ONLY**; no safe native C-ABI seam exists |
| Management proxy >1 MiB returns 413 before CPA `io.ReadAll` | proxy fixture | **GITHUB CI PASS** — counted CPA-handler stub remained at zero |

CI must set `REQUIRE_DIST_ARTIFACTS=1` for `cpa-store-contract`: missing real
`.so`, Store ZIP, metadata, or checksums must fail. The Host Blackbox first
install/load and the published-archive repeat/tamper checks must use the same
Dist identity to form one install-lifecycle-plus-load evidence chain.

## Performance

Same-machine Windows classifier medians improved in every measured latency case
from `a121a44` to `a1be19f`; ordinary classifier was 165,552→103,190 ns/op and
candidate-rich max-parts was 119,484,917→97,126,983 ns/op. Allocations increased
on the ordinary, candidate-rich, and role-aware paths. Pending-cache full insert
measured hundreds of nanoseconds instead of the previous linear hundreds of
microseconds, and duplicate subject requests remained zero-allocation. Full
tables are in `PERFORMANCE.md`.

Status: **IMPLEMENTATION-FREEZE DEVELOPMENT SELF-CHECK PASS / NOT FINAL
EVIDENCE**. Leo independent rerun: **NOT RUN**.

## Frozen v10 conclusion

The methodologically valid first-and-only v10 run remains immutable:

| Aggregate | Frozen result |
|---|---:|
| Benign false positives | 28 / 320 (8.75%) |
| Policy blocked | 49 / 320 (15.31%) |
| Policy exact taxonomy | 33 / 320 (10.31%) |

All release floors failed. This development work does not rewrite that result,
and no visible regression corpus can prove that the new classifier generalizes.

## Required full development gates

The following task-book gates record the implementation-freeze development
self-check. An item may be skipped only by marking it `NOT RUN`/`BLOCKED`; no
`|| true`, waiver, or inherited result is acceptable.

| Command/gate | Final-commit status |
|---|---|
| `make format-check` | **DEVELOPMENT SELF-CHECK PASS** |
| `make git-diff-check` | **DEVELOPMENT SELF-CHECK PASS** |
| `make module-verify` equivalent root/isolated verify + tidy-diff commands | **DEVELOPMENT SELF-CHECK PASS** |
| `scripts/go-safe-development-test.sh test` / `make unit-test` mapping | **DEVELOPMENT SELF-CHECK PASS** |
| `scripts/go-safe-development-test.sh race` / `make race` mapping | **DEVELOPMENT SELF-CHECK PASS; no race found** |
| `scripts/go-safe-development-test.sh boundary` / `make consumed-boundary-test` mapping | **DEVELOPMENT SELF-CHECK PASS; fixture not accessed** |
| `make vet` equivalent command | **DEVELOPMENT SELF-CHECK PASS** |
| `make fuzz-smoke` | **DEVELOPMENT SELF-CHECK PASS** |
| `make script-test` | **DEVELOPMENT SELF-CHECK PASS** |
| `make corpus-regression` | **DEVELOPMENT SELF-CHECK PASS** |
| `make benchmark` | **DEVELOPMENT SELF-CHECK PASS** |
| `make vulncheck` | **DEVELOPMENT SELF-CHECK PASS — 0 reachable vulnerabilities** |
| `make build-linux-amd64` | **GITHUB CI PASS** for the implementation freeze |
| `make cpa-host-fixture-contract` (source-only) | **SOURCE OVERLAY PASS; not native Host evidence** |
| Authorized CI `make integration-test` | **GITHUB CI PASS** — 32 Host subtests and 15 Router scenarios |
| Authorized CI `REQUIRE_DIST_ARTIFACTS=1 make cpa-store-contract` | **GITHUB CI PASS** |
| Authorized CI `make management-proxy-413-test` | **GITHUB CI PASS** |
| GitHub Actions CI | **PASS** for exact implementation freeze in push and PR runs |
| Final official CPA client HTTP 405 for `executor.http_request` | **NOT AVAILABLE / NOT RUN — current public consumer maps the error to 502; BLOCKER** |

Do not execute consumed v10 classification. Any future blind quality check must
use a new independently authored isolated set and must not reuse the 35 visible
development cases.

## Evidence block

```text
starting_baseline: a121a444cb0d82cba4e27754914a1f88258e1d7b
reliability_checkpoint_commit: 573def2649d164161e2dfdfeb3f59b1e1b38ebbc
implementation_freeze_commit: 61536f9f02c47a4d79031a47dc8a284f040e41c1
evidence_document_commit: a2d30fc63fca4fba020cda282474aaca15a47d8f
branch: agent/complete-classifier-cpa-v7272-handoff
root_cpa_version: v7.2.72
cpa_upstream_tag_commit: 6279bb8a4c2835ff6ed99c6b85083b2afbefa681
go_version_used_for_wsl_checks: go1.26.4 linux/amd64
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
historical_classifier_policy_version: classifier-policy-v2
historical_classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
development_corpus: 35 visible cases; never future holdout
github_ci: PASS — push 29312969925; pull_request 29312971717
real_host_matrix: GITHUB CI PASS — 32 Host subtests; 15 Router scenarios
http_request_adapter_405: SOURCE / ADAPTER STATUS-ERROR CHECK (response=nil)
official_cpa_final_client_http_405: NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF
development_candidate_artifacts: CREATED / HASHED / VERIFIED IN GITHUB CI; see RELEASE_EVIDENCE.md
formal_blind_result: v10 CONSUMED / FAIL; unchanged
handoff_status: BLOCKED FOR HANDOFF
```

## v0.16-rc.1 local verification target

```text
source_version: 0.16
local_rc_artifact_version: 0.16-rc.1
platform: linux-amd64
cpa_contract: v7.2.95
ruleset_sha256: 1d908c8c631bc6f72e7ec6b098bea49c4923580766859393d0be48c8c00c6d7d
verification_status: LOCAL PACKAGE SOURCE GATES PASS / REMOTE EXACT-MAIN CI FAILED
local_package_status: CREATED / CHECKSUM-BOUND / LOCAL ONLY
github_actions_run: 29799561002 / ATTEMPT_1_FAILED / ATTEMPT_2_FAILED
github_actions_artifacts: 0
github_release_evidence: NOT CREATED
```

## Historical Round 8 identity footer

The declarations below intentionally follow all frozen historical sections so
the release-document gate cannot mistake an older evidence hash for the current
source-tree identity.

```text
ruleset_version: 1.0.9
ruleset_sha256: a3de344d3f6dc8eea86d946a823996494d4d297c41efcc6346a6ef757f263a7d
historical_round8_classifier_policy_version: classifier-policy-v7
historical_round8_classifier_policy_sha256: ea8c4dcfacacc6478f86fd2ca5de96d667ae98f2fc6ff0c83d8e6092e9f6a82d
verification_status: LOCAL LINUX DEVELOPMENT GATES PASS / EXACT-MAIN CI, HOST, AND INDEPENDENT AUDIT NOT_PROVIDED
```

## Historical Round 10 identity footer

The Round 10 policy snapshot is frozen pending an exact repository commit. The
declarations below bind the historical Round 10 classifier and embedded rules
identities while preserving every historical test section above. They do not
claim that final commit/tree or `.so` freeze, the no-checkout external CPA
evaluation, protected ledger proof, exact-main CI, or independent audit has
passed.

```text
historical snapshot: frozen pre-final v7.2.113 source identity
historical_formal_cpa: v7.2.113@bc71c77f5cc42f3fbe1bf040cf14d4f166894835
ruleset_version: 1.0.10
ruleset_sha256: e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0
historical snapshot: classifier source identity follows
historical_working_tree_classifier_policy_version: classifier-policy-v10
historical_working_tree_classifier_policy_sha256: db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594
classifier_policy_freeze: SOURCE_FROZEN_PENDING_EXACT_COMMIT
historical_completed_checks: LOCAL_POLICY_IDENTITY_RELEASE_DOC_SAFE_GATE_CPA_PINNED_SOURCE_ABI_SCHEMA2_PASS
historical_pending_checks: FULL_UNIT_RACE_FUZZ_CORPUS_PERFORMANCE_EXACT_COMMIT_CI_CPA_HOST_CONTAINER_EXTERNAL_4424_FIXED_P99_BASELINE_AND_INDEPENDENT_AUDIT
verification_status: BLOCKED / NOT PROVIDED / REQUIRES INDEPENDENT AUDIT
```
