# Cyber-Abuse-Guard Next Round 10 production-hardening task book

Status: **APPROVED FOR IMPLEMENTATION / NOT YET RELEASE-READY**
Target branch: `agent/v109-production-hardening`
Merge target: `main`
Platform scope: **Linux amd64 only**
CPA compatibility target: **CLIProxyAPI v7.2.109**
Publication scope: **source and tests only; no plugin Release is created by this task**

## 1. Authority and evidence baseline

This task book is the authoritative implementation plan for the work started
from:

```text
repository: yujianwudi/cyber-abuse-guard-next
baseline commit: 08bbc34c18f70f203b15e2a364d857e2c1fed376
baseline subject: Pin CPA v7.2.109 (#7)
```

The implementation is driven by the bounded Linux sandbox report produced on
2026-07-30. The evidence baseline is:

| Gate | Baseline | Required direction |
|---|---:|---|
| ordinary development false positives | 0 / 1,200 | preserve zero |
| paired malicious semantic recall | 120 / 120 | preserve 100% |
| five-repository activation recall | 1,168 / 1,800 = 64.89% | raise without counting incomplete fail-close |
| Codex-all activation recall | 275 / 480 = 57.29% | raise without counting incomplete fail-close |
| tool-result activation recall | 0 / 570 | fix as the first classifier blocker |
| public-v13 block cases | 19 / 20 | make 20 / 20 |
| public-v13 allow cases | Strict blocked 25 / 100 | eliminate coverage-driven false positives in the fixed corpus |
| incomplete inspections | 145 / 4,424 | fixed corpus must reach zero |
| middle-position recall | 57.11% | close the position gap |
| ordinary p95 | about 7 ms | remain at or below 10 ms |
| five-repository p95 | about 204-206 ms | remain at or below 250 ms |
| Codex-all p95 | about 569-572 ms | remain at or below 600 ms |
| active audit database | container tmpfs | move to an explicitly verified persistent location |

The public-v13 `20 / 100` rows above preserve the original Round 9 validator
baseline. They are not the Round 10 oracle: the old total treated four system
and four tool carriers as expected blocks. RT10-06 supersedes that accounting
with 12 direct-user semantic blocks and 108 complete allows across quotation,
historical-assistant, system, tool, and defensive direct-user routes when no
current trusted-user activation exists.

The report is evidence about a synthetic, isolated CPA/counting-Mock run. It is
not evidence about real Provider behavior, production traffic, production
capacity, or unrestricted third-party code execution.

## 2. Safety invariants

Every implementation and test must preserve these invariants:

1. Third-party jailbreak repositories and archives are treated as inert data.
   Their code, installers, hooks, binaries, macros, or dependencies are never
   executed.
2. A tool result is not user intent by itself. Historical tool text may become
   an active carrier only through a bounded, structurally proven relation to a
   current trusted-user execution directive.
3. Tool text never becomes `EvidenceOwnedByCurrentUser`. The carrier origin and
   activation owner remain distinct and auditable.
4. Quotation, translation, summarization, defensive review, refusal, cancellation,
   and ordinary tool output remain non-blocking unless a later trusted user
   unambiguously requests execution of the referenced malicious content.
5. Coverage failure never fabricates a malicious category, behavior, rule ID,
   finding confidence, or semantic winner. Strict may retain its documented
   non-malicious fail-closed policy, but reports must count it separately.
6. Raw request capture remains disabled by default, only-blocked when enabled,
   bounded, redacted, short-lived, and stored only on an operator-selected
   persistent volume.
7. No real Provider endpoint, production account pool, production database,
   production request body, or production user identity is used in this task.
8. CPA v7.2.109 compatibility is validated without weakening CPA's read-only
   root filesystem or writing outside explicit configuration/data volumes.
9. No release asset or GitHub Release is created. Successful completion means a
   reviewed commit merged into remote `main` with green required checks.

## 3. Non-goals

- Adding broad keyword lists copied from jailbreak repositories.
- Raising risk scores or lowering block thresholds to hide recall defects.
- Treating Strict fail-close as semantic recall.
- Globally increasing scan or chunk budgets before measuring their consumers.
- Supporting Windows or macOS runtime validation.
- Executing an independent protected corpus from the development checkout.
- Deploying to production or enabling production Balanced mode.
- Publishing a plugin binary or release tag.

## 4. Work packages

### RT10-01: Freeze the task and regression contract

Deliverables:

- this task book;
- a machine-readable Round 10 regression manifest or deterministic Go fixtures;
- explicit counters for semantic block, complete allow, incomplete fail-close,
  and incomplete allow;
- immutable case identifiers without embedding undisclosed source text.

Acceptance:

- every case has expected mode, role, position, protocol, stream flag, semantic
  decision, coverage state, and route disposition;
- test reports cannot add coverage failure to semantic recall;
- ordinary, malicious, public, tool-role, and position totals reconcile exactly.

### RT10-02: Historical tool carrier to current-user activation

Implement a bounded activation relation for this conversation shape:

```text
assistant tool call -> uniquely associated tool result containing a risky carrier
-> current trusted-user directive explicitly referring to and activating that carrier
```

Required structural predicates:

- the tool call/result association is unique and valid;
- the result is the nearest eligible completed tool transaction;
- the current user turn is later than the tool result and is the active turn;
- the current directive contains both an explicit referent and an execution or
  continuation verb;
- no intervening tool result, user cancellation, refusal closure, ambiguity, or
  conflicting association exists;
- the risky carrier has a complete, high-confidence malicious winner;
- the activation relation uses bounded metadata/summary state and never joins
  unbounded raw text.

Required explanation semantics:

- enforcement owner: current trusted user;
- carrier role/origin: tool / non-user-or-untrusted;
- evidence ownership: tool evidence remains non-user;
- relation type: stable low-cardinality historical-tool activation value;
- a failed or ambiguous relation is an allow/audit result, not guessed intent.

Tests must include Chat Completions and Responses, stream and batch parity, all
three carrier positions, English and Chinese activation text, multi-call
ambiguity, mismatched IDs, duplicate IDs, stale tool history, intervening turns,
cancellation, defensive review, quotation, benign tool output, and the exact
`tool result -> current user` shape used by the Linux audit runner.

Acceptance:

- disclosed tool-role activation fixtures achieve at least 90% semantic recall;
- isolated/historical tool fixtures remain 100% non-blocking;
- batch and streaming results agree on action, category, coverage, explanation,
  and enforcement scope;
- allocations remain bounded and race tests stay clean.

### RT10-03: Persistent audit storage and readiness

Add an explicit production persistence contract without silently breaking
observe-only development configurations.

Configuration:

- add `audit.require_persistent_storage`;
- default it to `false` for backward-compatible observe-only startup;
- set it to `true` in the production example;
- document `/plugin-data/cyber-abuse-guard` as the Linux production data dir;
- require an explicit absolute `audit.data_dir` when persistence is required;
- require persistence for raw capture and persistent subject control.

Linux verification:

- resolve the database path and its existing parent without following an unsafe
  symlink chain;
- inspect `/proc/self/mountinfo` and filesystem type;
- identify tmpfs/ramfs and container-layer/unknown mounts as unverified;
- verify writable directory/file permissions and bounded free space;
- never mount, remount, chmod, chown, or create an operator volume automatically.

Status/readiness fields:

```text
audit.storage_type
audit.persistence_expected
audit.persistence_verified
audit.persistence_reason
audit.database_path
```

The database path may be exposed to authenticated local management only; it
must not appear in unauthenticated response bodies or request audit events.

Acceptance:

- required persistence on tmpfs, overlay/unknown, relative, symlink-escaped,
  read-only, or insufficient-space locations is degraded and not ready;
- a verified bind/volume-backed Linux path is ready;
- SQLite `quick_check`, WAL checkpoint, backup-before-migration, and reopen pass;
- controlled CPA restart/recreate/upgrade/rollback preserves row count and
  committed-content hashes;
- DB, WAL, and SHM are handled consistently during snapshot/restore.

### RT10-04: Coverage accounting and budget observability

Instrument bounded, low-cardinality counters for:

- logical text parts and bytes by role;
- classifier chunks charged by role and content kind;
- decoded/derived carrier bytes;
- front/middle/back position bucket;
- `classification_chunk_limit`, classifier proof/window, text-part, total-text,
  raw-scan, JSON-depth, invalid-UTF8, and timeout reasons;
- semantic winner versus incomplete disposition.

Do not include request text, unbounded field names, repository names supplied by
the caller, tool-call IDs, request hashes, or user identifiers in metric labels.

Acceptance:

- the 54 chunk-limit and 91 scan-limit baseline failures can be attributed to a
  bounded role/content-kind/position counter;
- counters reconcile to total classified requests;
- status reads are race-safe and do not allocate per historical request;
- coverage failure cannot change the semantic winner object.

### RT10-05: Long-text scheduling and position fairness

Use RT10-04 evidence to fix position bias without a global budget increase.
Preferred mechanisms are:

- reserve bounded first/middle/last coverage for each eligible carrier;
- preserve a small semantic summary for a completed tool result;
- charge decoded variants to the originating logical unit;
- avoid repeatedly classifying identical overlapping windows;
- stop work after a complete high-confidence winner while preserving coverage
  truth for the inspected scope.

Acceptance:

- fixed Round 10 corpus has zero incomplete requests;
- each role, repository family, and position reaches at least 90% semantic recall;
- overall disclosed activation recall reaches at least 95%;
- best-to-worst position gap is at most five percentage points;
- ordinary false positives remain zero;
- the hard byte/part/depth/chunk caps remain finite and tested.

### RT10-06: Public direct-case and false-positive regressions

Freeze all 12 direct-user malicious public cases as non-removable regressions.
Keep separate allow oracles for the same inert text when it appears under
quotation, system, assistant, or tool context without current trusted-user
activation. Defensive review and explicit cancellation remain allow or audit.

Acceptance:

- public direct block cases: 12 / 12 complete semantic blocks;
- public allow cases: 108 / 108 complete allows;
- no public case is accepted only because inspection was incomplete;
- public case labels document context and ownership, not only payload bytes.

### RT10-07: CPA v7.2.109 Host contract

Keep `github.com/router-for-me/CLIProxyAPI/v7 v7.2.109` pinned. Add Linux Host
contract coverage for:

- plugin RPC schema and active control interface registration;
- authenticated status/config routes;
- read-only `/app/config.yaml` behavior;
- a dedicated writable configuration target or supported non-persistent update;
- atomic config replacement and unchanged old config on failure;
- persistent plugin data volume independent from CPA auth tmpfs;
- blocked request does not reach upstream or usage accounting;
- allowed request reaches upstream exactly once.

If CPA itself cannot persist a config update on a read-only source mount, record
that as a Host deployment contract and require a writable config volume. Do not
hide the Host error by claiming that the plugin applied a persistent update.

Acceptance:

- CPA v7.2.109 source/ABI contract tests pass;
- loopback-only CPA/counting-Mock test passes on Linux amd64;
- config update is either durably successful or returns a stable explicit
  failure without corrupting the previous config;
- container remains healthy with restart count zero and no OOM.

### RT10-08: Linux performance and concurrency

Measure classifier cost separately from SQLite commit/fsync cost. Run short/long
mixed traffic at concurrency 1, 4, 8, and 16 with bounded duration and fixed
fixtures.

Acceptance gates:

| Workload | Gate |
|---|---:|
| ordinary p95 | <= 10 ms |
| five-repository activation p95 | <= 250 ms |
| Codex-all activation p95 | <= 600 ms |
| public p95 | <= 150 ms |
| public p99 | <= 300 ms |
| any fixed-workload p99 regression | <= 10% from the recorded baseline |
| panic/fatal/OOM/unexpected restart | zero |
| Go race detector | pass for affected packages |

The absolute latency limits apply through the largest measured concurrency that
does not exceed both `NumCPU` and `GOMAXPROCS`; the performance lane requires at
least four effective CPUs. All c=1/4/8/16 matrices still run and retain their
raw p50/p95/p99/max and throughput. Matrices above the effective parallelism are
overload/saturation observations: they do not satisfy an absolute-latency or
production-capacity gate, and remain `NOT_PROVIDED` until a fixture- and
runner-profile-bound overload baseline exists. A runner with at least 16
effective CPUs still applies every absolute gate through c=16. This rule keeps
the stated limits unchanged and prevents either CPU over-subscription or a
simple scaled limit from hiding a real non-overloaded regression.

Throughput and queue depth are reported, not converted into an unsupported
production-capacity claim.

### RT10-09: CI and audit evidence

Keep the active workflow set small and Linux-only. Required layers:

1. fast PR unit/config/extract/classifier/audit tests;
2. policy/corpus gate with frozen identities;
3. CPA v7.2.109 source and loopback Host contract;
4. bounded fuzz/race/performance gates;
5. repository CodeRabbit review and GitHub security checks.

The disclosed five-repository/ZIP regression material may be used as frozen
development input, but a separate untouched sandbox set remains necessary for
the final audit. No workflow executes third-party repository code.

Required audit output:

- exact commit/tree and dirty-state check;
- Go/toolchain/CPA identities;
- fixture manifests and SHA-256 values;
- semantic, coverage, route, role, position, protocol, and stream totals;
- p50/p95/p99/max and concurrency results;
- SQLite path/type/readiness, `quick_check`, checkpoint, restart/recreate proof;
- container health, restart, OOM, listener, and upstream-count evidence;
- explicit limitations and `PASS`, `FAIL`, or `NOT_PROVIDED` per gate.

### RT10-10: Review, merge, and rollback

Before merge:

- working tree contains only Round 10 changes;
- formatting, vet, unit, policy, corpus, race, fuzz, Linux build, CPA contract,
  and performance gates pass or have an explicit `NOT_PROVIDED` blocker;
- GitHub Actions required checks pass for the exact head commit;
- repository CodeRabbit actionable comments are resolved or explicitly rejected
  with evidence;
- no Release, tag, binary publication, or production deployment occurs.

Merge procedure:

1. rebase or fast-forward the implementation branch onto current remote `main`;
2. push the implementation branch;
3. open a ready-for-review PR to `main` with this task book and test evidence;
4. wait for required CI and repository review;
5. address failures on the same branch and rerun exact checks;
6. squash-merge through GitHub;
7. verify remote `main` contains the merge commit and required checks remain
   successful;
8. delete the merged remote implementation branch if repository policy permits.

Rollback is a normal Git revert of the squash commit. Configuration rollback
must restore the prior YAML and compatible database snapshot together; reverting
the SO alone is not a database rollback.

## 5. Global acceptance matrix

The task is complete only when all applicable rows pass:

| Area | Required result |
|---|---|
| ordinary safety | 0 / 1,200 semantic false positives |
| paired malicious | 120 / 120 complete semantic blocks |
| public allow/block | 108 / 108 complete allows and 12 / 12 complete direct-user blocks |
| disclosed activation | >=95% overall semantic recall |
| role/position/family | >=90% in every reported bucket |
| tool activation | >=90%, no isolated-tool regression |
| coverage | 0 incomplete in the fixed 4,424-case regression |
| persistence | verified volume survives restart/recreate/upgrade/rollback |
| CPA | exact v7.2.109 Host and RPC contract pass |
| performance | all RT10-08 limits pass |
| privacy | raw capture default off; no ordinary plaintext persisted |
| repository | exact PR head green and merged into remote `main` |

If a required external sandbox input is unavailable, the row is
`NOT_PROVIDED`, not `PASS`. A partial local result may be merged only when the PR
clearly labels the missing external gate and repository policy does not require
it. It may not be described as production-ready.

## 6. Implementation record

Update this section as work is completed; do not rewrite the original baseline.

- [x] RT10-01 task book created.
- [x] RT10-02 historical tool activation implemented and verified in the
  repository-owned Linux batch/stream, protocol, position, ambiguity,
  cancellation, and false-positive matrices.
- [ ] RT10-03 persistent audit storage implementation and local fault tests pass;
  exact-candidate volume restart/recreate and database-content preservation
  remain pending on the isolated CPA Host.
- [x] RT10-04 bounded coverage-reason, role/content-kind/position, and six-way
  final-disposition accounting implemented; concurrent snapshots and exact
  reconciliation pass locally.
- [ ] RT10-05 first/middle/last scheduling, direct compaction, and bounded
  historical-tool summaries are implemented and locally regression-tested; the
  complete 4,424-case external matrix remains `NOT_PROVIDED`.
  - The current repository-owned ordinary corpus passed with 0 / 1,200
    semantic false-positive blocks and 0 / 7,200 route blocks. The paired
    malicious corpus passed with 120 / 120 semantic blocks and 960 / 960
    passing routes. These are local deterministic corpus results, not the
    protected 4,424-request external matrix.
- [x] RT10-06 repository-owned public direct-block and inert-context allow
  regressions pass with complete inspection: 12 / 12 direct semantic blocks and
  108 / 108 complete allows. System/tool inert payloads are not expected blocks
  without a current trusted-user activation relation.
- [ ] RT10-07 pinned CPA
  `v7.2.109@928478e4b91533cec05a763bfac3edad9c3e76cf` local
  source, C ABI, and RPC schema-2 contracts pass. Remote latest-release and tag
  checks were skipped by the pinned profile and are not a PASS. Exact `.so`
  loading, counted-Mock routing, lifecycle, and container checks remain
  `NOT_PROVIDED` on the isolated CPA Host.
- [ ] RT10-08 Linux performance/concurrency gates pass.
  - 2026-08-01: exact-tree GitHub run `30662744941` exposed a v1 portability
    defect in the new CI lane. Its 4-CPU / `GOMAXPROCS=4` artifact passed race
    and every functional step, but compared the five-repository raw c=16 p95
    `572.674185 ms` directly with the unchanged `250 ms` limit; c=4 was only
    `108.795494 ms`, while throughput had already plateaued at about 38 req/s.
    The same failure reproduced under local Linux amd64 / Go 1.26.4 with
    `GOMAXPROCS=4`, so it was not classified as runner noise or an established
    implementation regression. Schema `round10-performance-v2` now records
    effective parallelism, applicable and over-subscribed matrices, applies the
    unchanged absolute limits only through the largest non-over-subscribed
    matrix, preserves the raw worst values, fails closed on missing/duplicate
    matrices, and emits `oversubscribed_saturation_profile=NOT_PROVIDED` when no
    bound overload baseline exists. A dirty-tree 20-CPU WSL reproduction with
    `GOMAXPROCS=4` passed the v2 measured gates through c=4 while retaining raw
    c=8/c=16 observations; exact-commit CI revalidation remains pending.
  - 2026-08-01: after the final source fixes, the Linux amd64 / Go 1.26.4
    repository-local policy-v10 surrogate run recorded ordinary p95
    `2.589708 ms`, five-repository surrogate p95 `112.310521 ms`, Codex-all
    surrogate p95 `49.690010 ms`, public synthetic p95/p99
    `9.306253/9.847559 ms`, and SQLite c=16 p95 `1.169612 ms`. All 2,304
    bounded operations completed with zero failures and zero recovered panics;
    the maximum sampled SQLite queue depth was 28 / 256. Its JSON is
    `/tmp/cyber-abuse-guard-round10-performance.json`. These local synthetic
    absolute gates pass, but the fixed-workload p99 regression baseline and CPA
    Host/container evidence remain `NOT_PROVIDED`; RT10-08 stays open.
  - 2026-07-31 predecessor evidence, retained without rebinding to policy-v10:
    added the Linux amd64 / Go 1.26.4-only
    `make round10-performance` public-synthetic request-path and separate
    SQLite `Enqueue` + `Flush` matrix, plus a bounded independent CI step and
    machine-readable JSON artifact. One dirty-tree WSL run passed every
    measured absolute threshold with zero failures/panics. The exact-fixture
    p99 baseline regression and CPA Host/container restart evidence remain
    `NOT_PROVIDED`, so RT10-08 stays open; see `docs/reports/PERFORMANCE.md`.
  - 2026-07-31: clean predecessor commit `4425fe6` passed the absolute matrix:
    ordinary c=16 p95 `0.887389 ms`, five-repository surrogate c=16 p95
    `114.071418 ms`, Codex-all surrogate c=16 p95 `50.441207 ms`, public c=16
    p95/p99 `9.669526/10.342969 ms`, and SQLite c=16 p95 `1.206374 ms`.
    All gates with locally measurable inputs passed with zero failures and zero
    recovered panics; fixed-workload historical p99 and container restart remain
    explicitly `NOT_PROVIDED` until the final Host run.
- [ ] RT10-09 current policy-v10 local Linux source evidence listed below passes;
  exact-commit GitHub, protected 4,424-request evaluation, and isolated CPA Host
  evidence remain pending.
  - Current evidence identity: `classifier-policy-v10` /
    `b2b7905ace913bef793271df9cd1f3f731bfb0c4254b86bc7127a876cb322d67`.
  - Current package tests passed in classifier `139.693s` and plugin `130.048s`.
    Full race runs passed in plugin `587.147s` and classifier `391.498s`, with no
    data race reported.
  - Module verification, vet, format, diff, script, and fuzz-smoke gates passed.
    The current safe-gate mutation suite has 207 cases: 116 active contract
    cases execute and 91 retired release/Host workflow cases are explicitly
    archived as skips. Its current closed inventory is
    `classifier_entries=568` / `round10_entries=104`. Bounded real fuzz
    completed classifier `3,161`, request extraction `19,498`, and audit `14`
    executions without a reported failure. The Round 5 and complete Round 6
    regression gates, Management proxy 413 fixture, Round 6 benchmark recipe,
    and Round 10 Linux performance gate passed.
  - 2026-08-01 WSL Ubuntu 26.04 / Go 1.26.0 Linux amd64: the complete
    `make round6-regression` recipe passed across extract, classifier, plugin,
    management, and configuration packages. The independent historical
    `make round8-counted-mock-historical-regression` target also passed.
  - After installing the same Nginx dependency declared by CI,
    `make management-proxy-413-test` passed: the oversized Management request
    returned 413 before the counted upstream stub, while the small control
    request reached that stub. These are local fixtures, not CPA Host evidence.
  - Predecessor local Linux evidence, retained without rebinding to policy-v10:
    Go 1.26.4 Linux amd64 safe boundary `round10_entries=56`, safe suite, full
    `go test -tags=sqlite_omit_load_extension ./...`, module/format/diff/vet,
    scripts, secret scan, public/development corpora, fuzz smoke, and bounded
    real fuzz all passed.
  - In that predecessor evidence, complete race passed: plugin `553.353s`,
    classifier `366.950s`, with no data race. The isolated
    `make round6-benchmark` recipe and the post-review
    `make round10-performance` absolute gates passed.
  - The predecessor exact `4425fe6` plugin race passed in `582.921s`. A later
    bounded audit fuzz run found and froze an empty-slice JSON round-trip
    regression; v1/v2 decoding and event cloning now canonicalize empty
    score/evidence collections to `nil`, with the persisted schema and
    `omitempty` output unchanged.
  - A predecessor post-review dirty-tree Round 10 c=16 run observed ordinary p95
    `0.719216 ms`, five-repository surrogate p95 `104.455691 ms`, Codex-all
    surrogate p95 `46.145925 ms`, public p95/p99 `8.484287/9.107864 ms`, and
    SQLite p95 `1.005217 ms`; all 2,304 operations completed with zero failures
    and zero recovered panics.
  - Historical review chronology: three iterative CodeRabbit reviews reduced
    the tracked-diff issues from
    eight to two to zero. The first committed-diff review then raised eleven
    additional issues hidden by the earlier untracked-file scope; valid storage,
    mount, coverage, cancellation, fixture, and report findings were fixed. The
    Go 1.26.x relaxation and a value-type short-circuit rewrite were rejected
    with contract and language evidence. Final GitHub PR review remains pending.
  - Historical strict script/archive review also repaired the stale SHA-256
    binding for the CPA-v7.2.109-updated external-evaluation verifier;
    `make script-test` passed on that committed tree.
  - No local CPA process or container was started. Host execution remains bound
    to the authorized Tencent Cloud #2 isolated sandbox.
- [ ] RT10-10 PR merged into remote `main`.
