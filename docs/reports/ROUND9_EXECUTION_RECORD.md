# Round 9 execution record and traceability matrix

```text
current_classifier_policy_version: classifier-policy-v10
current_classifier_policy_sha256: b2b7905ace913bef793271df9cd1f3f731bfb0c4254b86bc7127a876cb322d67
```

This document is the single working record for the Round 9 Balanced redesign.
It records development evidence only. It is not production authorization,
independent audit evidence, or a claim of zero false positives.

## Immutable predecessor execution baseline

```text
task_document_sha256: 389f2ac88672c6cc6dc4bdfa39f10419ad8b62eacf130395b2b6dd32826780b8
repository: https://github.com/yujianwudi/cyber-abuse-guard
base_commit: 9665fdd1aacab0d79b8790d68c87c6c8c80f8911
base_tree: 84c6636b2012c825627bad34f922dfa0329d0a1e
branch: feat/round9-balanced-eligibility
source_version: 0.16
cpa_target: v7.2.95@f71ec0eb6776854457892452cf28c47f0d658251
round8_classifier: classifier-policy-v7
round8_ruleset: 1.0.9
round9_classifier: classifier-policy-v8 / b3f1e751bf648d426023e4207b8b562fe3aac91d48fa74c1462c79e08fa49dde / PREDECESSOR_WORKING_TREE_DEVELOPMENT_IDENTITY
round9_ruleset: 1.0.10 / e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0 / PREDECESSOR_WORKING_TREE_DEVELOPMENT_IDENTITY

round9_public_adversarial: v13 / 481448 bytes / 91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6
round9_candidate: v0.16-rc.3 (confirmed unoccupied by tag and Release API at start)
final_source_commit: PENDING_FINAL_SOURCE_FREEZE
exact_candidate_independent_audit_evidence_status: NOT_PROVIDED
exact_candidate_independent_audit_mechanical_gate: IMPLEMENTED_FAIL_CLOSED_EVIDENCE_NOT_PROVIDED
new_public_release_creation: BLOCKED_FAIL_CLOSED
cpa_host_listener: 127.0.0.1:18394->8317/tcp
latest_release_at_start: v0.15
open_pull_requests_at_start: 0
production_mode_required_by_task: audit
production_mode_live_verified: false
production_mode_change_authorized: false
real_provider_contact_authorized: false
restricted_material_zero-access_claim: false
restricted_evaluation_gate_metadata_incident: true
```

## Successor repository continuation snapshot

```text
successor_repository: https://github.com/yujianwudi/cyber-abuse-guard-next
successor_main_snapshot_commit: 77cf2de50f89af12a4a1e7c651a2ac0074cabcdd
successor_main_snapshot_tree: ef5f35086ece6fcd415db1d5578ad89d4df55929
successor_round9_policy_gate: PASS / run 30116119599
successor_codeql: PASS / run 30116119625
successor_full_ci: PASS / run 30116119718
successor_rc3_tag: v0.16-rc.3 / ANNOTATED_IMMUTABLE / object a70e30fe5b66a6060e0358efd084edfbb60722e1
successor_rc3_phase1: PROVIDED_FAIL / run 30118817188 / missing-pyyaml-at-safe-gate-import / zero-artifacts
successor_candidate_tag: v0.16-rc.4 / NOT_CREATED
successor_release: NOT_CREATED
successor_rc4_pr3_initial_checks: PROVIDED_FAIL / head edde8f7aee1bb264e07915b0992adff1914caa46 / CI 30122937438 + Round9 30122937432 + CodeQL 30122937442 / dynamic-python-read-only-contract / superseded-by-source-fix
successor_rc4_pr3_followup_checks: PROVIDED_FAIL / head 78ea624c118d145119bd16653a93424a95dfc408 / CI 30123493758 + Round9 30123493678 + CodeQL 30123493698 / safe-gate-tests-204-PASS + contract-PASS + README_CN-prologue-position-FAIL / superseded-by-doc-fix
successor_final_candidate_freeze: NOT_ESTABLISHED
successor_independent_evidence: NOT_PROVIDED
successor_external_ledger_ruleset: 19669641 / round9-eval-ledger-immutable / active / no-bypass
successor_independent_audit_ledger_ruleset: 19669780 / round9-independent-audit-ledger-immutable / active / no-bypass
successor_host_environment: round9-host-validation / current-policy-tag=v0.16-rc.3 / rc4-policy-migration-and-independent-reviewer=PENDING
successor_publication_environment: round9-rc-publication / current-policy-tag=v0.16-rc.3 / rc4-policy-migration-and-independent-reviewer=PENDING
successor_self_hosted_runner: REGISTERED_ONLINE / cag-round9-tencent-2 / Linux X64 / cag-round9-sandbox / observed 2026-07-24 / NOT_HOST_EVIDENCE
successor_main_protection: ENABLED / strict / pull-request-required / five-required-checks
```

The successor continuation passed exact-main CI, Round 9 policy, and CodeQL at
`77cf2de50f89af12a4a1e7c651a2ac0074cabcdd`. The first immutable Round 9 Tag
then exposed a deterministic container dependency gap before any candidate
asset was built. The active identity therefore advances to `v0.16-rc.4`; the
failed `v0.16-rc.3` identity remains immutable historical evidence.

The rc.4 source correction pins both the missing `libyaml-0-2=0.2.5-1`
dependency and `python3-yaml=6.0-3+b2` before checkout, then runs the reviewed
contract and its hash-bound test runner through isolated `/usr/bin/python3 -I -B`.
This is a source correction only until GitHub Linux checks pass.

The pre-existing uncommitted Round 8 RC workflow repair was isolated without
publication in Git stash
`stash@{0}: wip/round8-rc3-container-shell-before-round9`. Round 9 starts from
the exact `origin/main` baseline above and does not reuse or move the protected
`v0.16-rc.2` tag.

## Safety boundary

- Production services, modes, databases, account pools, and plugins are out of
  scope.
- Real Provider traffic and real user traffic are out of scope.
- Evaluation, Holdout, consumed, private, blind, and retired fixtures and
  reports are excluded from implementation and tuning.
- The ordinary source gate does not execute an independent corpus. The protected
  Host job performs no source checkout; only its separately reviewed root-owned
  broker may decrypt the external corpus and operate the evaluator, adapter,
  fixed images, signing keys, result directory, and protected one-shot ledger.
- Public adversarial repositories are read as untrusted bytes only. Their code,
  scripts, installers, hooks, dependencies, applications, and binaries are not
  executed.
- Subject control remains disabled for all Round 9 development and external
  evaluation evidence.

## Runtime evidence boundaries

The following are three different evidence classes. Source compilation,
integration contracts, Docker/broker code, or a run from one boundary cannot be
used as evidence for another boundary.

| Evidence boundary | Required identity | Evidence path | Current status |
|---|---|---|---|
| Repository-local counted-Mock | Final source commit/tree and exact Linux candidate SHA-256 | No admissible result asset exists | `NOT_PROVIDED` |
| Tencent Cloud #2 isolated counted-Mock | Same exact candidate, isolated loopback CPA v7.2.113 RPC schema-2 sandbox, no production/Provider/account/user contact | No admissible result asset exists | `NOT_PROVIDED` |
| Protected external evaluation and one-shot ledger | Same exact candidate, signed external-evaluation/counts, ledger event v3, and protected ledger proof v1 | No signed evaluation or ledger asset exists | `NOT_PROVIDED` |

The task requires production to remain `mode=audit` and subject control to
remain disabled. This is a requested safety constraint only. Production was not
inspected or modified, so its live state is `NOT_PROVIDED` rather than verified.

## Current requirement traceability matrix

Statuses describe the current final-candidate position. `PASS` is used only for
an immutable development identity or a reproducible result that is not invalidated
by later source changes. `PENDING_FINAL_SOURCE_FREEZE` and `PENDING_RERUN` are
not synonyms for `PASS`. `PENDING_LINUX_RERUN` specifically means the required
Linux validator/CI rerun has not completed; it is also not a `PASS`. Early
failures remain disclosed in the Stage log, but are not presented as the current
final result after subsequent classifier edits.

| Task clause | Source location | Test location | Source snapshot / freeze | Evidence path and SHA-256 | Current result | Status |
|---|---|---|---|---|---|---|
| Candidate/clause/scope/referent-bound eligibility | `internal/classifier/eligibility.go`, `ownership.go`, `classifier.go` | `round9_eligibility_gate_test.go`, `eligibility_winner_invariant_test.go`, `round9_carrier_boundary_test.go` | Final classifier source not frozen | No final invariant log | Implementation exists on the shared working tree; final invariant result is not claimed | `PENDING_FINAL_SOURCE_FREEZE` |
| One eligibility gate for every malicious-text producer | `internal/classifier/malicious_text_producer_inventory_test.go`, `classifier.go`, `eligibility.go`, `roles.go`, `internal/plugin/disposition.go`, `management.go` | `TestRound9MaliciousTextProducerInventoryClosure`, Safe Gate hash-drift regression | Current working tree only; final commit/tree not frozen | `docs/reports/ROUND9_MALICIOUS_TEXT_PRODUCER_INVENTORY.json`, 11337 bytes, SHA-256 `def42b49e18fd373dbaa2730af9fc5006ba8c2c5a83e42984e78fa9c241e34aa`; contract test, 26766 bytes, SHA-256 `e11969e711fc5a5c84fd0a7b5ba5317ba2bf6c2f4bf0aa33c5e4e8ac9d65ef88` | Tracked static closure enumerates 20 production/call sites and 5 gate functions, scans package-level initializers and function literals, and does not read corpus text; the targeted Linux test passed on the current tree. Final-tree rerun, runtime/Host proof, and independent audit remain pending | `DEVELOPMENT_STATIC_CLOSURE_PASS / PENDING_FINAL_SOURCE_FREEZE` |
| Score and hard floor cannot create eligibility | `eligibility.go`, classifier score/hard-floor paths | `hard_floor_reason_test.go`, `round9_eligibility_gate_test.go`, `eligibility_winner_invariant_test.go` | Final classifier source not frozen | No final log | Intermediate tests exist; no final-tree result | `PENDING_RERUN` |
| Balanced and Strict share malicious-text eligibility; incomplete/opaque/subject remain distinct | `internal/plugin/disposition.go`, `router.go`, classifier eligibility | `internal/plugin/disposition_test.go`, `round8_decision_audit_contract_test.go`, `subject_admission_test.go` | Classifier/plugin source not frozen | No final package log | Final mode matrix not rerun | `PENDING_RERUN` |
| Defensive, analytical, quoted, credential-lifecycle, code/log/fixture, and mixed-trust requests are audit/allow unless independently eligible | classifier ownership/role/referent code | `defensive_quote_regression_test.go`, `finding_origin_test.go`, Round 9 current-user/meta-control tests | Predecessor development-report identity `classifier-policy-v8` / `b3f1e751bf648d426023e4207b8b562fe3aac91d48fa74c1462c79e08fa49dde`; not the current working tree; final commit/tree not frozen | `dist/round9-worklogs/development-benign-post-perf-20260724.json`, 2515 bytes, SHA-256 `607b751defeebd9681170a558528aa1a4827c1c176bce2886a1929b59193af01`; frozen cases `36d7f4dd635710f7ee81d02f9f62502c6276e554c80fc852f3d40acbfa70688d`; manifest `d33e4ff8954741a2fe9c24c0d34b239c649c7e0a6d31463cddba84dc6b6580b8` | Development snapshot: 0/1200 semantic blocks and 0/7200 route blocks; 166 audit and 7034 allow routes; stream false/true 3600/3600. This is visible candidate-owned evidence, not independent evidence | `DEVELOPMENT_SELF_CHECK_PASS / PENDING_FINAL_SOURCE_FREEZE` |
| Historical carrier reactivation requires complete trusted referent proof | `roles.go`, `streaming.go`, `eligibility.go` | referent and streaming sections of `defensive_quote_regression_test.go`, `round9_role_referent_test.go` | Final classifier source not frozen | No final referent log | Mixed-trust direct and streaming cases specify audit-only/untrusted ownership; final package result pending | `PENDING_RERUN` |
| Category-specific malicious predicates retain high-confidence recall | `eligibility.go`, `semantic.go`, `rules/*.yaml` | `round9_explicit_malicious_relation_test.go`, paired-malicious runner/tests | Predecessor development-report identity `classifier-policy-v8` / `b3f1e751bf648d426023e4207b8b562fe3aac91d48fa74c1462c79e08fa49dde`; not the current working tree; final commit/tree not frozen | `dist/round9-worklogs/paired-malicious-post-perf-20260724.json`, 7150 bytes, SHA-256 `ba9733503985195204c0bc1eef95f936951ab8947c67ce4d316abcb8c6ab3276`; paired v3 cases `2a30da8d4872029d9b070a7b8bd8fb72a132994a21975f64b49cd56ecf4b2b3d`; manifest `29d84900edeec8fceceee9ccd2640571f1e962643931f388dcc842b058c6a2c2`; label audit `a2d34853f20ae1c0b18690a4f58f100fe0014c53232457d5084aa90407e2ab8f` | Development snapshot: 120/120 semantic samples blocked and 960/960 routes passed; stream false/true 480/480; overall Wilson 95% interval 96.8981%-100%, with per-category intervals recorded in the report. This is paired candidate-owned evidence, not independent malicious evidence | `DEVELOPMENT_SELF_CHECK_PASS / INDEPENDENT_EVIDENCE_NOT_PROVIDED` |
| Bounded text-free eligibility explanation | classifier explanation, `internal/plugin/decision_explanation.go`, `internal/audit/event.go` | classifier explanation tests, `internal/audit/round9_audit_test.go`, plugin decision-audit tests | Final classifier/plugin source not frozen | Audit package log `dist/round9-worklogs/audit-schema-v6.log`, SHA-256 `2fa6ebaf6baad0de384a20bc063cb9e7fb4f0734f8660596df89fcf17d593805` | Intermediate Linux audit package passed; final cross-package mapping rerun pending | `PENDING_RERUN` |
| Audit schema v5→v6 migration, backup, compatibility, query/export, and old-SO rollback | `internal/audit/migrations.go`, `event.go`, `sqlite.go`, `query.go` | `internal/audit/*_test.go`, especially `round9_audit_test.go` and migration/query tests | Audit log binds an intermediate uncommitted tree, not a final commit | Same audit log, 44528 bytes, SHA-256 `2fa6ebaf6baad0de384a20bc063cb9e7fb4f0734f8660596df89fcf17d593805` | Intermediate Linux package result PASS; final-source freeze and rerun required | `PENDING_RERUN` |
| 1200 semantically unique benign development requests and 7200 routes | `cmd/round9-development-benign-corpus-runner`, `internal/round9corpus`, frozen corpus | corpus identity tests and runner | Corpus frozen; working-tree classifier identity recorded; final commit/tree not frozen | `dist/round9-worklogs/development-benign-post-perf-20260724.json`, 2515 bytes, SHA-256 `607b751defeebd9681170a558528aa1a4827c1c176bce2886a1929b59193af01` | Latest development snapshot is 1200 semantic / 7200 routes / 0 blocked; earlier 2/1200 and 12/7200 failures remain disclosed in the Stage log | `DEVELOPMENT_SELF_CHECK_PASS / PENDING_FINAL_SOURCE_FREEZE` |
| Unique semantic samples separated from route executions | Round 9 corpus runner/report schema | `internal/round9corpus`, machine-report tests | Runner/report source and final commit/tree not frozen | Benign report SHA-256 `607b751defeebd9681170a558528aa1a4827c1c176bce2886a1929b59193af01`; paired report SHA-256 `ba9733503985195204c0bc1eef95f936951ab8947c67ce4d316abcb8c6ab3276` | Development accounting records 1200 vs 7200 and 120 vs 960 separately; benign stream false/true 3600/3600 and malicious stream false/true 480/480 | `DEVELOPMENT_SELF_CHECK_PASS / PENDING_FINAL_SOURCE_FREEZE` |
| 600 independently authored benign holdout requests | External encrypted root-owned bundle only | Protected external evaluator | No candidate freeze; no admissible bundle/result identity in this record | No signed external evaluation | Zero-block result and Wilson upper bound absent | `NOT_PROVIDED` |
| Independent malicious ground truth, paired/independent recall, and per-category Wilson intervals | External bundle/evaluator plus frozen paired v3 development set | Protected evaluator and development runner | No exact candidate freeze | No signed independent result | Independent malicious evidence absent | `NOT_PROVIDED` |
| Four public repositories frozen by repo/ref/commit/path/bytes/SHA-256 | `testdata/round9-public-adversarial-v13/manifest.json`, public corpus validator | `cmd/round9-public-corpus-validator`, `internal/round9corpus` static identity tests | V13 manifest frozen; validator source not final | 481448 bytes; SHA-256 `91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6` | 2026-07-24 23:47 +08 live freeze with 2026-07-25 00:00 +08 metadata recheck; MDX default-head commit provenance advanced while all 19 frozen payload-source paths retained the same bytes/SHA-256/Git blob; five changed-or-added files are excluded as non-payload data/source/workflow/test material and two removals are path-only; the other three repository snapshots and all 199 metadata-only Release asset records remain unchanged; no third-party code executed; final Linux validator rerun pending | `PENDING_LINUX_RERUN` |
| Public-v13 classifier scenarios and per-payload counted-Mock | classifier plus public corpus runner/Host boundary | public scenario tests and counted-Mock runner | Classifier/candidate not frozen | No final scenario log; no counted-Mock asset | Static identity does not prove classification or upstream counters | `PENDING_LINUX_RERUN` / `NOT_PROVIDED` |
| Repository-local counted-Mock | `integration/round9countedmock`, local isolated runner | Exact-candidate Audit→Balanced→Strict matrix | No exact candidate freeze | No admissible result asset | Not run as final evidence | `NOT_PROVIDED` |
| Tencent Cloud #2 isolated counted-Mock | `scripts/round9-host-evidence*`, isolated operator sandbox contract | Exact-candidate Host/runtime matrix | No exact candidate freeze | No admissible result asset; 2026-07-24 read-only connectivity/preflight metadata is not counted-Mock evidence | SSH preflight succeeded, but the root-owned broker and independent bundle are absent; no CPA/container/runtime test was performed | `NOT_PROVIDED` |
| Protected external CPA/count-Mock evaluation | root-owned broker contract, external evaluator/adapter contracts | Signed external evaluation v3 admission and runtime checks | No exact candidate freeze | No signed evaluation/counts | No protected external run | `NOT_PROVIDED` |
| Protected one-shot Git ledger | external ledger contract | Reserved/started/result event and proof verification | No exact candidate freeze | No ledger event/proof asset | No one-shot ledger evidence | `NOT_PROVIDED` |
| Performance, RSS, panic, queue, WAL, restart, Raw Capture defaults | classifier/plugin/audit source plus runtime harness | final benchmark gate and three named runtime boundaries | Working-tree development benchmark only; final performance-sensitive source, commit/tree, and exact `.so` are not frozen | `dist/round9-worklogs/round6-benchmark-post-perf-20260724.log`, 26441 bytes, SHA-256 `ec603a4b437820f579d69340feba76bd63752ab5a63cf63998b6e87873d6c063`; pre-fix diagnostic CPU/memory profiles `6eb5ec36955f30df460a64111ebbeea5b9b9ed32e5394ee04b78e1b0f1834d69` / `fdc111fca573a32701fdee9abd206c680481f1247998a394578cbdd7fcd17eb6` | Complete `make round6-benchmark` recipe and explicit profiled maximum-parts hard bound passed. Three candidate-rich samples recorded 37.311769-39.621583 ms/op, 6,622,070-6,624,038 B/op, and 700-706 allocs/op. Exact-candidate RSS/Host/runtime evidence remains absent | `DEVELOPMENT_SELF_CHECK_PASS / NOT_PROVIDED_FOR_FINAL_CANDIDATE` |
| New Round 9 CI/Release/Host identity | `.github/workflows/round9-*.yml`, release/Host scripts | actionlint, ShellCheck, Safe Gate, exact-main, reproducibility, admission contracts | Shared workflow tree still converging; no final commit | No exact-main final run | Engineering lanes are not final-source evidence yet | `PENDING_FINAL_SOURCE_FREEZE` |
| Checksum, SBOM, manifest, provenance, annotated tag, non-latest prerelease | Round 9 release lane | release asset allowlist and byte/attestation verification | No final commit/tag/candidate | No release assets | Publication remains blocked | `NOT_PROVIDED` |
| Operator-owned canary, circuit breaker, migration backup, and rollback runbook | `docs/ROUND9_OPERATOR_ROLLOUT.md`, audit schema guide | Clause review and operator rehearsal | Documentation source not final | No operator rehearsal evidence | Design only; no production action authorized | `PENDING_FINAL_SOURCE_FREEZE` |
| Production remains audit | External operator configuration, outside repository authority | Live production inspection by authorized operator | Not inspected | No production-state evidence | Task/request says audit; live state not verified | `NOT_PROVIDED` |
| Independent audit | Outside this development context | Independent reviewer | No final candidate | No independent report | Not performed | `NOT_PROVIDED` |

## Stage log

### 2026-07-23 - restricted-path static-search incident

- A repository-wide static producer search was scoped too broadly and printed
  a small number of source-code lines from the checked-in
  `evaluation_v10_gate_test.go`, limited to gate metadata/constants and generic
  `ActionBlock` assertions. No evaluation corpus file, fixture payload, or
  historical evaluation report body was opened, copied, classified, or used
  for implementation or tuning.
- All subsequent source searches explicitly exclude evaluation, holdout,
  consumed, private, retired, and blind paths. Because the task requires a
  strict no-access statement, the corresponding final compliance item cannot
  be represented as an unconditional PASS and must disclose this incident.
- A later classifier test-helper search used `Select-String` across
  `internal/classifier/*_test.go` without first excluding restricted-named test
  files. It printed only a small number of helper/function and error-string
  lines, not corpus or fixture bodies, and none of the output was used for
  classifier tuning. This is an additional occurrence of the same methodology
  incident; `restricted_material_zero-access_claim` remains `false`, and all
  subsequent classifier searches are restricted to explicit non-sensitive file
  allowlists.

### 2026-07-23 - additional overbroad recovery searches

- During recovery of the frozen public-v6 manifest identity, three recursive
  repository searches were insufficiently allowlisted. Two root-thread
  commands searched the three public-v6 identity strings across files below a
  size limit, and hashed matching `manifest.json` candidates; a release-lane
  agent later ran this exact text search at approximately 18:37 Asia/Shanghai:

  ```powershell
  Get-ChildItem -LiteralPath . -Recurse -Force -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\.git\\objects\\' } |
    Select-String -SimpleMatch -Pattern
      '74096af7ac49578e0ca82105563cac83e7541e2505d9943f0569a148240ce34c',
      '101408',
      'eb7b1350059a7f2f1a07fd246522f18287e4c47c9712b97e7b6f9dfcf6723abe'
  ```

- These commands did not exclude every independent, evaluation, holdout,
  retired, private, blind, or consumed path before the filesystem walk.
  Consequently the processes may have read restricted files while searching
  or hashing, even though no restricted match, line, fixture body, prompt,
  report body, or hash was printed. There was no output redirection or saved
  copy, and no result from these searches was used for implementation, tuning,
  classification, or an evidence claim.
- The searches were stopped when discovered. Public-v6 recovery is now limited
  to explicit public-corpus paths, known Git objects, and Codex operation logs.
  This is an additional reason that `restricted_material_zero-access_claim`
  remains false and the affected compliance item cannot be marked PASS.

### 2026-07-23 - intake and baseline

- Verified the authoritative task document SHA-256.
- Read the complete authoritative task document and repository contribution
  and governance rules.
- Confirmed current `origin/main`, CI, Releases, open PRs, and that
  `v0.16-rc.3` is not occupied by a tag or Release.
- Created a clean Round 9 branch from exact `origin/main`.
- Started source-call-chain, audit-schema, and evidence-lane reviews. No
  production or restricted-data access occurred.

### 2026-07-23 - superseded repository-local independent-benign proposal

- An earlier design proposed a candidate-worktree independent-benign fixture.
  That proposal is retired and is not publication-admissible Round 9 evidence.
- The active contract accepts only a separately authored, signed, age-encrypted,
  root-owned bundle outside Git and outside the candidate checkout. Its author
  key is separate from the evaluator execution key, and the protected workflow
  never receives a plaintext corpus path.
- No external bundle identity, one-shot execution, zero-block result, Wilson
  interval, or independent benign `PASS` is provided by this development record.

### 2026-07-23 - candidate eligibility implementation started

- Added the first candidate-bound eligibility data contract and began moving
  ordinary, semantic, composed, and meta producers behind it.
- Added a plugin-side fail-closed guard: a bare `ActionBlock` without a complete
  eligible malicious winner cannot become `block_malicious_text` or enter
  subject accumulation.
- Began the independent audit schema v6 migration and top-level decision-kind
  separation. These changes are still in progress and are not yet test evidence.

### 2026-07-23 - development benign corpus freeze and provisional execution

- Frozen 1,200 semantically unique visible development requests across 15
  categories, with 600 Chinese and 600 English records. Protocol, streaming,
  and wrapper variants are counted separately as 7,200 route executions.
- `cases.jsonl`: 359154 bytes; SHA-256
  `36d7f4dd635710f7ee81d02f9f62502c6276e554c80fc852f3d40acbfa70688d`.
- `manifest.json`: 2949 bytes; SHA-256
  `d33e4ff8954741a2fe9c24c0d34b239c649c7e0a6d31463cddba84dc6b6580b8`.
- The first visible-candidate run found one semantic EDR/SIEM false positive.
  A candidate-local analytical-owner fix subsequently produced a provisional
  `0/1200` semantic and `0/7200` route result. This remains `IN_PROGRESS` until
  the classifier is frozen and the command is repeated into persistent logs.

### 2026-07-23 - paired malicious authoring incidents

- Rejected v1 is retained under
  `testdata/round9-development-paired-malicious-rejected-v1`; its cases SHA-256
  is `42b9b88c7ac1ca396357abef52bacc72164aac994d65503392508f8514dcecf8`.
- Rejected v2 was not executed. Its frozen cases remain 54714 bytes with
  SHA-256
  `012b07e4853fdcc85bd5e56c86b30d6fa3ed6281ca178635b54744d94373f2c9`.
  Pre-execution review rejected all 15 referent records for lacking an actual
  quoted carrier, rejected five deployment records as dual-use, and found 48
  duplicated post-colon action-clause pairs. Its cases and manifest remain
  unchanged historical evidence.
- A new v3 corpus was independently authored as visible development data. A
  label-only reviewer that did not observe candidate output or run classifier
  or project tests re-read all 120 records and their benign references. The
  final result was 120 passed, 0 failed.
- The accepted v3 corpus was then frozen at
  `2026-07-23T09:41:08+08:00`. `cases.jsonl` is 58543 bytes with SHA-256
  `2a30da8d4872029d9b070a7b8bd8fb72a132994a21975f64b49cd56ecf4b2b3d`;
  `manifest.json` is 3798 bytes with SHA-256
  `29d84900edeec8fceceee9ccd2640571f1e962643931f388dcc842b058c6a2c2`;
  and the bound `LABEL_AUDIT.md` is 5261 bytes with SHA-256
  `a2d34853f20ae1c0b18690a4f58f100fe0014c53232457d5084aa90407e2ab8f`.
- A repository identity test loads the exact frozen benign and paired-v3
  bytes without invoking the classifier. The complete `internal/round9corpus`
  Linux package passed with Go 1.26.4. Persistent log:
  `dist/round9-worklogs/round9-corpus-contract.log`, 5499 bytes, 80 lines,
  SHA-256
  `a03d1ac4e5d31fc586c912498066b227ca62dfd7b45467096fc4d51cb9ecac8a`.
  Candidate execution of paired-v3 remains pending until the active classifier
  edits settle.

### 2026-07-23 - visible candidate execution exposed release-blocking regressions

- The first complete execution of the frozen 1,200-request benign development
  corpus disproved the earlier provisional zero-block result: 2 semantic
  requests and 12 serialized routes were blocked. The immutable failing base
  IDs are `r9dev-education-zh-006` (`credential_theft`, score 80) and
  `r9dev-education-zh-019` (`ransomware_deployment`, score 85). They request a
  compliant-refusal rewrite and a board-facing incident-report summary,
  respectively; neither may be removed, relabeled, or waived.
- The frozen paired-malicious v3 execution blocked only 3/120 semantic samples
  and 24/960 serialized routes, for 2.5% visible-development recall. Per-category
  semantic blocking was credential theft 0/16, data exfiltration 0/16, defense
  evasion 0/16, malware deployment 0/8, phishing deployment 0/16, prompt
  injection evasion 0/16, ransomware deployment 3/8, service disruption 0/8,
  and unauthorized exploitation 0/16.
- These are candidate failures, not admissible release evidence. The benign
  gate remains `FAIL`, the paired-malicious recall gate remains `FAIL`, and the
  implementation must repair clause-local analytical ownership plus typed
  execution, hostile-scope, and category-specific outcome predicates without
  exact-sentence allowlists or post-output relabeling.

### 2026-07-23 - superseded repository-local independent-malicious proposal

- An earlier design proposed a candidate-worktree independent-malicious fixture.
  That proposal is retired and is not an external evaluation input.
- The active evaluator accepts only the separately signed encrypted bundle
  selected by the root-owned broker and protected one-shot ledger. Neither the
  candidate workflow nor this document supplies or validates plaintext cases.
- Independent malicious aggregate/per-category recall and Wilson evidence remain
  `NOT_PROVIDED` until the exact candidate receives the protected external run.

### 2026-07-23 - audit schema v6 Linux verification

- Re-ran the complete Linux audit package with Go 1.26.4 and
  `sqlite_omit_load_extension`; exit code 0 and package result `PASS`.
- Command:
  `GOTOOLCHAIN=go1.26.4 GOFLAGS=-mod=readonly go test -tags=sqlite_omit_load_extension ./internal/audit -count=1 -v`.
- Persistent local work log:
  `dist/round9-worklogs/audit-schema-v6.log`, 44528 bytes, 561 lines, SHA-256
  `2fa6ebaf6baad0de384a20bc063cb9e7fb4f0734f8660596df89fcf17d593805`.
- The passing package covers v5-to-v6 atomic migration, pre-migration backup,
  legacy-row compatibility, the closed decision explanation union,
  unknown/contradictory field rejection, WAL/restart/quick-check, old-SO schema
  gating, and Raw Capture privacy and metadata contracts.

### 2026-07-23 - public adversarial repository refresh v2

- A fresh read-only GitHub inventory found upstream drift, so the immutable
  `testdata/round9-public-adversarial-v1` corpus was retained and a new
  `testdata/round9-public-adversarial-v2` identity was created. No third-party
  script, installer, hook, dependency, application, or binary was executed.
- The v2 manifest contains 10 payload records representing nine unique payload
  bytes, two unmerged candidate carriers, one candidate-carrier execution, one
  explicitly `NOT_PROVIDED` carrier, and 10 route executions. The manifest is
  27194 bytes with SHA-256
  `06625e48f0cd7ae8e43ebfb82da266e9b98061a3411262c305277a6ec2fdfe8e`.
- `Jia-Ethan/codex-keysmith` main is now
  `d8335f99a557403f3ef919c8601502e5a8362414`; the former PR #3 is merged and
  closed, so the 7038-byte payload is no longer described as an unmerged
  carrier. The historical 7899-byte payload remains a separate unique identity.
- `MDX-Tom/gpt-5.6-instruct` main is
  `82a3957533435f6e98111174dbfb41de2a2227f5`; its v5 and v35 payload bytes are
  unchanged. The Codex-X and Codex-5.5 default heads remain unchanged; their
  open candidate carriers remain distinct from default-branch provenance.
- Linux static identity, duplicate-key rejection, provenance-drift rejection,
  and v1-retention tests passed. Classifier scenarios remain pending until the
  candidate implementation settles.

### 2026-07-23 - public adversarial repository refresh v4

- Later upstream drift required another immutable identity; v1, v2, and v3
  remain byte-for-byte unchanged. The v4 GitHub-only collection completed at
  `2026-07-23T11:36:32.638961+08:00` after matching pre- and post-collection
  snapshots. No third-party repository code, workflow, installer, hook,
  dependency, test, application, or binary was executed.
- Exact default heads are keysmith
  `700f1be22446af4dc2c362080cbde669e215094d`, MDX
  `bcda62e3bcb509c8c9170f332725b6763416910f`, Codex-X
  `7d0e0064d54f860d4bf12b557fd9f8c489043a35`, and Codex-5.5
  `ed0b6dc37d1994e93788d92f7af63f58bf0b9e2d`; Codex-5.5 PR #9 remains open at
  `3b64052a7706626b47bd66fde74d43f8b80e020d`. Keysmith PR #4 and MDX PR #15
  are closed and merged, so neither is an unmerged candidate carrier.
- Relative to MDX `82a3957533435f6e98111174dbfb41de2a2227f5`, the reviewed 23-path delta is
  closed as twelve frozen `SKILL.md`, matrix, cookbook, and reference payloads
  plus eleven byte-identified exclusions with explicit classifications and
  reasons. The twelve defensive or dual-use texts have direct-current-user
  ground truth `allow_or_audit`; repository origin alone cannot force a block.
- The v4 manifest contains 22 payload records, 21 formal unique payloads, one
  unmerged candidate carrier, 22 scenario-payload executions, and 110
  serialized context routes. It is 51815 bytes with SHA-256
  `080d50d83debbffdd1496973ab88d8a2bcb2d0020cadf67c7fefe882bf3691d5`.
- Linux static identity, v1/v2/v3 manifest retention, first-nine encoded-byte
  retention, duplicate-key rejection, candidate/source/exclusion provenance
  mutation, and ground-truth mutation tests pass with Go 1.26.4. The classifier
  scenario gate currently fails because direct `keysmith-main` is audited
  instead of satisfying its frozen `block_malicious_text` ground truth; the
  label was not changed after observing candidate output.

### 2026-07-23 - public adversarial repository refresh v5

- A later immutable v5 freeze retained every v1-through-v4 payload identity and
  rechecked the four public repositories without executing their code,
  installers, hooks, dependencies, applications, or binaries.
- The frozen v5 manifest is 150645 bytes with SHA-256
  `7ea0dfefde513f973da5f0a85df5e0ac19c09b0f6eb8caf0b035af327b548c43`.
  It records 24 payload records, 23 formal unique payloads, eight historical
  payloads, one branch-head payload, 14 current prompt-like payloads, one
  unmerged candidate carrier, 24 scenario payload executions, and 120
  serialized route executions.
- Frozen direct-current-user ground truth is split 12
  `block_malicious_text` and 12 `allow_or_audit`; repository origin never
  creates block eligibility by itself.
- The first-party Linux static corpus package remains PASS. Final classifier
  scenario evidence is still pending the classifier source freeze and must not
  be inferred from the static manifest result.

### 2026-07-23 - upstream drift requires public adversarial v6

- A later live identity refresh found that the MDX default branch had advanced
  after PR #17 merged. The immutable v5 bytes and report above remain historical
  evidence and are not relabeled as the current corpus.
- No third-party repository code, workflow, installer, hook, dependency,
  application, or binary was executed during the identity check.
- The interim corpus identity at that point was `round9-public-adversarial-v6` with
  `PENDING_FINAL_FREEZE`. Final bytes, counts, SHA-256, classifier scenarios,
  and current-corpus `PASS` must wait for the new freeze and rerun.

### 2026-07-23 - immutable v6 recovery and corrective public adversarial v7

- Recovered the exact frozen v6 manifest from the original Codex operation
  record. The accidental patch had changed both the review digest and the
  leading indentation of that line from 37 spaces to 8, explaining the exact
  29-byte loss. The restored v6 identity is 101408 bytes with SHA-256
  `74096af7ac49578e0ca82105563cac83e7541e2505d9943f0569a148240ce34c`.
- V6 is retained byte-for-byte, but deterministic validation proves that its
  declared prompt-like review digest
  `eb7b1350059a7f2f1a07fd246522f18287e4c47c9712b97e7b6f9dfcf6723abe`
  differs from the computed digest
  `4efc428894f048fe3474ddbe4c47a17dc618932e710f7f6de6cb3c6aaf89af30`.
  It is therefore a frozen-invalid historical identity and is not active
  release evidence.
- Created immutable `round9-public-adversarial-v7` under a new schema/dataset.
  It retains all 24 encoded payload files byte-for-byte, records v6 in its
  refresh history, and binds the computed review digest. Its manifest is
  101925 bytes with SHA-256
  `74716fd006490b7f2b57448ac1c87922d2c91f1eaabfb929fac15acaf184f500`.
- A read-only GitHub metadata refresh completed between 19:06:09 and 19:06:30
  Asia/Shanghai. Default heads remained keysmith
  `700f1be22446af4dc2c362080cbde669e215094d`, MDX
  `d1face34885e3c24972d7b959e120e9acc546202`, Codex-X
  `7d0e0064d54f860d4bf12b557fd9f8c489043a35`, and Codex-5.5
  `ed0b6dc37d1994e93788d92f7af63f58bf0b9e2d`; only Codex-5.5 PR #9 remained
  open at `3b64052a7706626b47bd66fde74d43f8b80e020d`. No third-party code was
  executed.
- Linux static v7 identity, historical retention, duplicate-key, provenance,
  ground-truth mutation, and frozen-invalid-v6 tests passed. Persistent log:
  `dist/round9-worklogs/round9-public-v7-static-20260723.log`.
- `.gitattributes` now stores all Round 9 frozen development/public corpus
  artifacts with `-text`. This prevents Git's global JSON/JSONL LF policy from
  silently rewriting the mixed-line-ending historical manifests at `git add`
  or clean checkout. Filtered and no-filter Git blob hashes are identical for
  public v5, v6, and v7 manifests.
- Round 9 machine-report tests passed 15/15 after binding public report schema
  v7 and the exact v7 manifest identity. Persistent log:
  `dist/round9-worklogs/round9-machine-reports-test-20260723.log`.
- Classifier scenario results remain pending the classifier source freeze; the
  static corpus result alone is not a recall or production claim.

### 2026-07-23 - later MDX architecture-only drift and public adversarial v8

- A new read-only GitHub refresh at approximately 20:05 Asia/Shanghai found
  that `MDX-Tom/gpt-5.6-instruct` default `main` advanced one commit from
  `d1face34885e3c24972d7b959e120e9acc546202` to
  `a2476cd2ba6fac605348f06b621e5e1d7d4f74fe`. The other three repository
  default heads, branch lists, releases/tags, and the sole open Codex-5.5 PR #9
  carrier were unchanged.
- The compare contains only two README architecture-image references, one
  Draw.io architecture source update, four added light/dark WebP images, and
  removal of the two superseded PNG images. No instruction or prompt-like blob
  changed, and no third-party repository code was executed.
- The task contract requires a new corpus identity whenever a live default head
  changes. V7 remains immutable at 101925 bytes / SHA-256
  `74716fd006490b7f2b57448ac1c87922d2c91f1eaabfb929fac15acaf184f500`.
- The previously announced v8 identity was restored exactly at 105299 bytes /
  SHA-256 `5def53300bad07c65717ed8f8a32d2da49952528275df77ea55703713f9e330f`.
  Its declared review digest is `52b1e97c…`, while deterministic recomputation
  yields `6772278f…`; v8 is therefore immutable-invalid. The only line-ending
  delta is the required CR on that `review_sha256` line.
- The 105298-byte / SHA-256
  `2f953da42d3bb485b08562e4011f20fdeae6ebe76be02da31c27bb3b151e727d`
  corrected in-place v8 rebind is retained at
  `testdata/round9-public-adversarial-v8-rejected-rebind` as rejected recovery
  evidence and is not active.
- Frozen v9 preserves all 24 encoded payload files byte-for-byte, records the
  exact announced v8 identity in refresh history, binds the corrected review
  digest under schema v9, and has manifest identity 105888 bytes / SHA-256
  `dd22068b452cb4183405bfe7697d52a1b7dd272de25ebef0790add46a71c9c38`.
- V10 preserves v9 and records the later read-only refresh under a new identity;
  static v10 validation and classifier scenarios remain to be rerun after the
  classifier source freezes. Neither provenance repair is independent or
  production evidence.

### 2026-07-23 - protected external-evaluation contract migration

- The active Host design no longer checks out candidate source or repository
  plaintext independent fixtures. A fixed root-owned broker owns the encrypted
  bundle, evaluator, CPA sandbox adapter, keys, images, result state, and
  protected Git one-shot ledger.
- The active identities are external evaluation v3, evaluator aggregate v3,
  ledger event v3, protected ledger proof v1, external counted-Mock v1, CPA
  sandbox descriptor v2, and CPA runtime-checks v1.
- A publishable counted-Mock result must be mechanically derived from the signed
  execution and metrics, use Audit→Balanced→Strict with authenticated mode
  changes and per-phase status verification, include all required database,
  restart, panic, usage-queue, Raw Capture, and lifecycle observations, and have
  `not_observed=[]`.
- This records the fail-closed contract only. No protected external run, signed
  result, ledger proof, publication, or independent audit is provided here.

### 2026-07-23 - continuation Linux package recheck

- Revalidated the authoritative task document SHA-256 and refreshed
  `origin/main`; the Round 9 base remains
  `9665fdd1aacab0d79b8790d68c87c6c8c80f8911` and `v0.16-rc.3` remains absent
  from both tag and Release APIs.
- On WSL `Ubuntu-26.04`, with `GOTOOLCHAIN=go1.26.4` and
  `GOFLAGS=-mod=readonly`, `go test ./internal/audit -count=1`,
  `go test ./internal/extract -count=1`, and
  `go test ./internal/round9corpus -count=1` passed.
- `go test ./internal/plugin -count=1` failed because the still-changing
  classifier no longer satisfied several Round 8 wrapper/fenced/referent
  expectations. These failures are not waived: each fixture must either be
  migrated with an explicit Round 9 semantic justification or fixed in the
  implementation, then the complete package must pass again.
- The latest complete classifier debugging run has 35 top-level failures.
  Therefore no current classifier, plugin, performance, development-corpus, or
  release-readiness claim is PASS.

### 2026-07-24 to 2026-07-25 - live repository recheck and evidence-boundary correction

- Read-only GitHub metadata was rechecked without executing any third-party
  repository code, workflow, installer, hook, dependency, application, binary,
  or embedded instruction.
- `origin/main` remains
  `9665fdd1aacab0d79b8790d68c87c6c8c80f8911`; open repository PRs remain zero;
  Git ref lookup for `v0.16-rc.3` remains absent; Release enumeration has no
  matching `v0.16-rc.3`; latest Release remains `v0.15`.
- The four public repositories were refreshed into a new v11 manifest after a
  Codex-X default-head advance; no new standalone prompt payload was found:

  | Repository | Default HEAD | Branches / open PRs / tags / releases |
  |---|---|---|
  | `Jia-Ethan/codex-keysmith` | `700f1be22446af4dc2c362080cbde669e215094d` | 5 / 0 / 2 / 2 |
  | `MDX-Tom/gpt-5.6-instruct` | `334f8cd2ec132aa4317b62bd2a3228ed827cbb87` | 1 / 0 / 2 / 2 |
  | `yynxxxxx/Codex-X` | `e8b0e5b73c508484cfb636339c82d70360487442` | 2 / 0 / 36 / 35 |
  | `yynxxxxx/Codex-5.5-codex-instruct-5.5` | `ed0b6dc37d1994e93788d92f7af63f58bf0b9e2d` | 1 / 1 / 0 / 0 |

- The sole open public-repository PR remains Codex-5.5 PR #9 at
  `3b64052a7706626b47bd66fde74d43f8b80e020d`. It remains an
  `unmerged_candidate_carrier`, not default-branch provenance.
- Result: `live rechecked; new v11 identity`. V10 and v9 remain byte-for-byte history.
  V11 is 476165 bytes with SHA-256
  `297c01072eb8bea3c6102b957c741722e621860c1116b65450b68a8704e75038`.
  Its Codex-X delta review records no standalone prompt payload, five behind
  non-default branches remain separate candidates, and all 199 Release assets
  are retained as metadata/digest-only records; none was downloaded or opened.
- A later authenticated read-only recheck at `2026-07-24T22:49:00+08:00`
  found that MDX main had advanced from `334f8cd2ec132aa4317b62bd2a3228ed827cbb87`
  to `cccbfae8a75c948bde22407dd07de7af88731d9b`. Per the immutable-corpus
  rule, this produced v12 rather than modifying v11. V12 is 485221 bytes with
  SHA-256 `eb72fd7b88c052c6af98c97636c18aba96f499597741bcba262dda59de3c2387`.
  All 19 frozen MDX payload-source paths retain the same bytes/SHA-256/Git blob
  while commit provenance moves to the v12 head; all 24 encoded payload files
  are byte-identical to v11. Eight changed-or-added documentation, workflow,
  maintenance-source, and test files are recorded as excluded non-payloads with
  review digest `913889465add03bbe2980dceb6e059b67f9113cbc3d4752f4347e60e1d706028`;
  the other three repository snapshots and 199 metadata-only Release assets did
  not drift. No third-party code or Release asset was executed or opened.
- The final pre-commit recheck found another direct MDX main advance from
  `cccbfae8a75c948bde22407dd07de7af88731d9b` to
  `61feb6a1940bd1d58163c2550869a0a9aed2ddc1`, so v12 remained immutable and
  v13 was created. V13 is 481448 bytes with SHA-256
  `91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6`.
  The 19 MDX payload-source paths retain the same bytes/SHA-256/Git blob while
  commit provenance moves to the v13 head; all 24 encoded payload files remain
  byte-identical to v12. Five changed-or-added Star History data/source/workflow/
  test blobs are excluded as non-payloads with review digest
  `56d4bfcdfa4bfa0b4b74b4229b4dd7d71fa6b0ebef58cd4417438209f45dd1cd`;
  two removed source paths are recorded path-only. A post-midnight second full
  metadata check was performed at `2026-07-25T00:00:54+08:00` and remained
  exact-equal to the v13 manifest.
- Documentation now separates repository-local counted-Mock, Tencent Cloud #2
  isolated counted-Mock, and protected external evaluation/one-shot-ledger
  evidence. All three remain `NOT_PROVIDED`.
- Production `mode=audit` is recorded only as the task's required/requested
  state. No live production inspection or mutation was performed.
- The final classifier/source snapshot remains unfrozen. Historical
  `2/1200`, `12/7200`, and `3/120` failures above remain disclosed as early
  Stage-log results, but no later edit is represented as a final PASS. Current
  candidate-dependent results are `PENDING_FINAL_SOURCE_FREEZE` or
  `PENDING_RERUN`.

### 2026-07-24 - Tencent Cloud #2 read-only preflight

- A read-only preflight to the operator-designated isolated host confirmed
  basic Linux and container-runtime reachability. Identifying host, account,
  inventory, capacity, filesystem, and credential details are intentionally
  excluded from repository evidence.
- The required protected evaluator, independent external bundle, and counted-
  Mock prerequisites were not provided or configured. The preflight therefore
  did not establish any runtime acceptance result.
- No container or CPA process was started, stopped, restarted, or changed. No
  production configuration/database/plugin, Provider, account pool, or user
  traffic was accessed.
- SSH reachability, sudo availability, Docker version, and host inventory do
  not prove that the final candidate loaded or that counters behaved correctly.
  Tencent Cloud #2 isolated/protected counted-Mock remains `NOT_PROVIDED`.

### 2026-07-24 - Round 9 release-gate closure and remote safety state

- Release admission now binds the exact annotated `v0.16-rc.3` tag target,
  exact `main` commit/tree, successful exact-main `CI` push run, and successful
  exact-main `Round 9 policy gate` push run. Any existing `v0.16-rc.3` Release
  is fail-only. The public publish, publication-blocked, and legacy verification
  jobs require `needs.admission.outputs.publication_permitted == 'true'`, while
  the sole admission producer is fixed to `publication_permitted=false`; those
  jobs therefore remain unreachable.
- The protected Host lane and broker now bind all four GitHub identities:
  `DISPATCH_REF`, `DISPATCH_SHA`, `WORKFLOW_REF`, and `WORKFLOW_SHA`.
  Development paired-malicious recall is exactly 10000 basis points overall
  and in every category; independently authored malicious recall remains at
  least 9500 basis points overall and in every category.
- The active RC build lane may create only the private Actions candidate that
  contains 17 assets and their build-provenance attestations. It has no public
  Release writer. Actions artifact upload and provenance attestation are
  therefore permitted private-candidate writes, not public Release mutations;
  cache writes remain disabled.
- Immediately before the authorized repository-safety change, GitHub's workflow
  API returned
  `.github/workflows/release-rc.yml` / ID `315644586` as `active` and
  `.github/workflows/round8-host-validation.yml` / ID `318443961` as `active`.
  Both workflow IDs were disabled through the GitHub workflow-disable API
  without dispatching or rerunning either workflow. Immediate post-change API
  reads returned `disabled_manually` for both exact IDs and paths.
- The remote namespace remained unused after that change: the
  `v0.16-rc.3` tag was absent; the complete Release list contained zero
  `v0.16-rc.2` or `v0.16-rc.3` Releases; and all 119 Actions artifacts, checked
  over both API pages, contained zero names matching `round9` or
  `v0.16-rc.3`. No tag, Release, release asset, or workflow run was created.
- The immutable historical `v0.16-rc.2` annotated-tag object remains
  `58bd9b78886da04c03b2c6d8f28e8cd7f2436e84`, targeting commit
  `9665fdd1aacab0d79b8790d68c87c6c8c80f8911`. That target supports audit
  schema v5. Because no `v0.16-rc.2` Release exists, there is no historical
  Release SO asset to download or verify.
- Exact-tag old-SO rebuild plus pre-v6 backup rollback verification is
  `NOT_PROVIDED`. The repository has no independent, read-only, purpose-built
  script or admission gate for that operation. The disabled Round 8 workflows
  contain historical build/publication capability and are not a safe recovery
  tool; they must remain disabled pending a separately reviewed recovery
  design.

### 2026-07-24 - post-performance-fix working-tree development rerun

- At that historical checkpoint, the report-producing classifier was
  `classifier-policy-v8` /
  `b3f1e751bf648d426023e4207b8b562fe3aac91d48fa74c1462c79e08fa49dde`
  with ruleset `1.0.10` /
  `e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0`.
  It is not a final source commit/tree or exact Linux plugin identity.
- On Linux amd64 with Go
  `/home/yujian/.cache/codex-go/go1.26.4/bin/go` and
  `GOFLAGS=-mod=readonly`, the development runners were invoked in the form:

  ```bash
  GOFLAGS=-mod=readonly /home/yujian/.cache/codex-go/go1.26.4/bin/go run \
    ./cmd/round9-development-benign-corpus-runner --root .
  GOFLAGS=-mod=readonly /home/yujian/.cache/codex-go/go1.26.4/bin/go run \
    ./cmd/round9-paired-malicious-corpus-runner --root .
  GOFLAGS=-mod=readonly \
    GO=/home/yujian/.cache/codex-go/go1.26.4/bin/go make round6-benchmark
  ```

- The latest benign development report is
  `dist/round9-worklogs/development-benign-post-perf-20260724.json`, 2515 bytes,
  SHA-256
  `607b751defeebd9681170a558528aa1a4827c1c176bce2886a1929b59193af01`.
  It records 1200 semantic samples, 7200 serialized routes, zero semantic or
  route blocks, 166 audit routes, 7034 allow routes, and an empty failure set.
  Streaming coverage is exactly 3600 non-streaming and 3600 streaming routes.
  The report's zero-block Wilson 95% upper bound is 0.3191000603%. This remains
  visible, candidate-owned development evidence and cannot authorize release.
- The latest paired-malicious development report is
  `dist/round9-worklogs/paired-malicious-post-perf-20260724.json`, 7150 bytes,
  SHA-256
  `ba9733503985195204c0bc1eef95f936951ab8947c67ce4d316abcb8c6ab3276`.
  It records 120/120 semantic samples blocked and 960/960 serialized routes
  passed, with 480 non-streaming and 480 streaming routes, an empty failure
  set, and an overall Wilson 95% interval of 96.8980833581%-100%. Per-category
  counts and Wilson intervals are present in the report. This is paired
  development evidence, not independently authored malicious evidence.
- The complete post-fix `make round6-benchmark` output is
  `dist/round9-worklogs/round6-benchmark-post-perf-20260724.log`, 26441 bytes,
  SHA-256
  `ec603a4b437820f579d69340feba76bd63752ab5a63cf63998b6e87873d6c063`.
  All commands in the recipe exited successfully. Three
  `BenchmarkClassifierCandidateRichMaxParts` samples recorded
  37.311769-39.621583 ms/op, 6,622,070-6,624,038 B/op, and 700-706 allocs/op.
  `TestCandidateRichProfiledMaxPartsPerformanceBound` enforces <=2 s/op,
  <=16 MiB/op, and <=2048 allocs/op while retaining the eligible current-user
  malicious-block proof; the roleless maximum-parts allocation gate is <=256.
- The performance repair deduplicates only byte-identical fields within a
  profiled group, assigns physical evidence one-to-one from the newest field
  backward, preserves cross-field split evidence, and stops only after a
  complete safe assignment. This removes the combinatorial regression without
  weakening the current-user ownership and malicious eligibility proofs.
- The pre-fix snapshot used classifier SHA
  `881e238858de1d8f5c636c12fb713bb01b7092736209f12bf32f7fef2680ea04`.
  Its historical log (`round6-benchmark-final-20260724.log`) recorded
  14.948-16.418 s/op, approximately 397 MB/op, and about 1.077 million
  allocs/op. CPU and memory profiles remain retained as diagnostic chronology;
  those results must not be attributed to the current classifier identity.
- The early 2/1200 benign, 12/7200 route, and 3/120 paired-malicious failures
  remain immutable in the earlier Stage log. The latest development rerun does
  not erase that chronology and does not become independent evidence.
- Final commit/tree, reproducible Linux `.so`, exact-candidate RSS/Host runtime,
  repository-local counted-Mock, Tencent Cloud #2 Host, protected external
  evaluation, independently authored benign/malicious evidence, exact-candidate
  independent audit, exact-main CI, tag, and Release evidence remain
  `NOT_PROVIDED`.

### 2026-07-24 - final pre-PR Linux development verification

- Verification used WSL `Ubuntu-26.04` on Linux amd64. Go gates that require the
  frozen runtime used `GOTOOLCHAIN=go1.26.4`; this did not change the system Go
  installation. The source baseline remained
  `main@98b32ab5d9e7d1fdd4a5bd457cbf3dfb3dc29c35` while the candidate was still an
  uncommitted review tree.
- The real-tree Safe Gate passed with 11 entrypoints, 40 reachable Make targets,
  and 60 reviewed scripts. Its negative/fixture suite passed 202/202 tests.
- The final evaluator contract set passed 62/62 tests: core 11, external
  evaluator 5, CPA adapter 20, and broker 26. These include pre-request ground-
  truth freezing, malicious all-allow rejection, Docker-daemon cleanup failure,
  evaluator/author SPKI separation, and ZIP/tar traversal/link/duplicate/size
  rejection cases.
- `make round6-vet`, `make race`, and `make round9-fuzz` passed. The bounded fuzz
  run exercised the classifier, request content-type extractor, and audit
  DecisionExplanationV2 targets for five seconds each with one worker.
- `GOTOOLCHAIN=go1.26.4 GOFLAGS=-mod=readonly make unit-test` passed across all
  first-party packages, including `internal/classifier` and the isolated Round 9
  counted-Mock integration package.
- Actionlint (`make workflow-lint`), ShellCheck 0.10.0, v11 public-corpus and
  retained-corpus identity gates, machine-report 24/24, external-evaluation 6/6,
  independent-audit 12/12, Host-evidence 20/20, release-document consistency,
  and `git diff --check` passed.
- These are working-tree Linux development results, not exact-main CI, an exact
  candidate build, Host counted-Mock evidence, independent holdout evidence, or
  an independent audit. The source-archive contract intentionally uses
  `git archive HEAD` and is therefore rerun only after the reviewed tree is
  committed; it is not represented here as a pre-commit PASS.

### 2026-07-25 - immutable rc.3 Phase 1 failure and rc.4 migration

- Created annotated Tag `v0.16-rc.3` at exact-main commit
  `77cf2de50f89af12a4a1e7c651a2ac0074cabcdd`; Tag object
  `a70e30fe5b66a6060e0358efd084edfbb60722e1` is protected by no-bypass
  update/deletion ruleset `19698669` and must not be moved, deleted, or reused.
- Exact-main CI `30116119718`, Round 9 gate `30116119599`, and CodeQL
  `30116119625` all passed before dispatch.
- Phase 1 run `30118817188` admitted the exact Tag, commit, tree, and successful
  exact-main runs. Build job `89566080301` then failed in the first Safe Gate
  command because the pinned `golang:1.26.4-bookworm` container did not provide
  the undeclared Python `yaml` module.
- The failure occurred before dependency setup, Linux quality gates, evidence
  generation, candidate assembly, attestations, or upload. The run has zero
  Actions artifacts; no draft or public GitHub Release exists for the Tag.
- Re-running the same immutable Tag and fixed container would reproduce the
  failure. The active workflow, Host, evaluator, audit, artifact, test, and
  documentation identity moves to the unused `v0.16-rc.4` namespace through a
  new pull request. Both containerized Safe Gate paths install and verify exact
  Debian package `python3-yaml=6.0-3+b2` before importing the reviewed gate.
- `v0.16-rc.4` remains `NOT_CREATED` until its source is merged, all exact-main
  checks pass, a no-bypass Tag ruleset exists, and the protected Environment
  policies have been migrated. Public publication remains mechanically blocked.

## Current conclusion

```text
BLOCKED / NOT PROVIDED / REQUIRES INDEPENDENT AUDIT
```

This conclusion remains mandatory until every required gate has reproducible
evidence.
