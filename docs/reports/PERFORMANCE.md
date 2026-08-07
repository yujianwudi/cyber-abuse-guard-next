# Performance Report — Round 10 source status and historical development evidence

```text
current_classifier_policy_version: classifier-policy-v12
current_classifier_policy_sha256: bc5656109362bc149e51afbfc58bf33ffc197c5cb04bd1a230e534a3eb1def73
```

Last updated: 2026-08-08 (Asia/Shanghai)

## Round 10 bounded Linux concurrency runner

`make round10-performance` is the dedicated Round 10 wall-clock lane. It
refuses any platform other than Linux amd64 with Go 1.26.4 and runs separately
from unit, race, and fuzz steps. The runner uses only repository-owned public
synthetic fixtures: ordinary traffic, a 32 KiB five-profile surrogate with a
historical-tool activation, a 64 KiB Codex-all long surrogate with a
historical-tool activation, and a compact direct public synthetic case. It
never executes code or fixture/artifact content from an untrusted third-party
repository, archive, installer, hook, or binary. The runner does execute the
project's pinned Go dependency code, including SQLite during the separate
`Enqueue` plus `Flush` phase.

Each request-path matrix performs eight unmeasured warmups followed by 128
fixed requests at concurrency 1, 4, 8, and 16. Audit and subject control are
disabled so the percentiles cover the in-process request-interceptor ABI,
extraction, classifier, disposition, and response validation path without
SQLite. A separate temporary SQLite phase performs 64 fixed `Enqueue` plus
`Flush` operations at each concurrency and samples queue depth every 1 ms. The
whole measured run has an eight-minute internal budget and the Go test has a
ten-minute hard timeout. Its JSON contains every matrix's count, p50, p95,
p99, max, throughput, failure count, panic count, fixture SHA-256, environment,
gate status, and SQLite queue observations.

Schema `round10-performance-v2` makes the CPU applicability contract explicit.
It records `effective_parallelism=min(NumCPU,GOMAXPROCS)`, requires at least four
effective CPUs, and evaluates the unchanged absolute latency limits only through
the largest configured concurrency that does not exceed that value. Higher
matrices still run and retain their raw percentiles and throughput, but are
reported as saturation observations with
`oversubscribed_saturation_profile=NOT_PROVIDED` until a fixture- and
runner-profile-bound overload baseline exists. Missing, duplicate, or unexpected
workload matrices fail closed. On a runner with at least 16 effective CPUs, all
absolute gates still include c=16. This development runner remains explicitly
non-equivalent to a production-capacity SLO.

### Frozen pre-v7.2.113 classifier-policy-v10 local source result

The historical 2026-08-01 repository-local run is bound to
`classifier-policy-v10` /
`b2b7905ace913bef793271df9cd1f3f731bfb0c4254b86bc7127a876cb322d67`.
It used Linux amd64 / Go 1.26.4 with 20 logical CPUs and `GOMAXPROCS=20`.
The machine report records source commit
`f036bcefaf179f777c25258723c88bd9cb7fb25a`, head tree
`a0819500aa1f49ea2a585414b1dd64d7fb853727`, and an explicitly dirty
worktree, so it is source-development evidence rather than exact-commit
evidence. It wrote `/tmp/cyber-abuse-guard-round10-performance.json` and
reported:

| Repository-owned synthetic workload | Latest percentile | Absolute gate |
|---|---:|---|
| ordinary | p95 `2.589708 ms` | p95 <= 10 ms: `PASS` |
| five-repository surrogate activation | p95 `112.310521 ms` | p95 <= 250 ms: `PASS` |
| Codex-all surrogate long | p95 `49.690010 ms` | p95 <= 600 ms: `PASS` |
| public synthetic | p95/p99 `9.306253/9.847559 ms` | p95 <= 150 ms and p99 <= 300 ms: `PASS` |
| SQLite `Enqueue` + `Flush` at c=16 | p95 `1.169612 ms`; sampled queue max `28/256` | failure/panic count 0: `PASS` |

All 2,304 bounded operations completed with zero failures and zero recovered
panics. These are
repository-owned in-process surrogate measurements, not five live repositories,
a CPA process, a container, a Provider path, or production traffic. The fixed
workload p99 regression baseline, CPA Host/container measurements, and protected
4,424-request external evaluation remain **`NOT_PROVIDED`**. Therefore the local
absolute thresholds pass, but the release-level RT10-08 gate remains open.

### Four-effective-CPU CI portability finding

Exact-tree GitHub run `30662744941` used 4 CPUs and `GOMAXPROCS=4`. Its original
v1 evaluator passed race and all earlier functional/performance steps, then
failed only because it compared the over-subscribed five-repository c=16 raw
p95 `572.674185 ms` with the unchanged `250 ms` absolute limit. The same
workload measured c=1/4/8/16 p95
`72.124095/108.795494/252.484294/572.674185 ms`; throughput plateaued at
`37.569/37.832/37.983 req/s` from c=4 onward. This is evidence of 4-CPU
saturation, not proof that the implementation regressed. The artifact still
marks the fixture-bound p99 regression baseline as `NOT_PROVIDED`.

The v2 contract was then reproduced under Linux amd64 / Go 1.26.4 on a dirty
working tree with 20 visible CPUs and `GOMAXPROCS=4`. It applied the absolute
gate through c=4, preserved raw c=8/c=16 results, and reported the saturation
profile as `NOT_PROVIDED`; the measured source gates passed and the release gate
remained `NOT_PROVIDED`. This is development validation only. Exact-commit
GitHub revalidation is pending, and no 4-vCPU/c=16 production SLO is inferred.

### Earlier Round 10 local development run

The 2026-07-31 local WSL run used Linux amd64, Go 1.26.4, 20 logical CPUs,
`GOMAXPROCS=20`, commit `08bbc34c18f70f203b15e2a364d857e2c1fed376`, and an
explicitly recorded **dirty** Round 10 worktree. The command completed in
17.506 seconds and wrote `/tmp/cag-round10-performance-final.json`. This run
predates the frozen policy-v10 identity below and is retained without rebinding.
These values are development self-check evidence only:

| Audit-disabled workload | p95 ms at c=1/4/8/16 | p99 ms at c=1/4/8/16 | throughput req/s at c=1/4/8/16 | Checked worst gate |
|---|---|---|---|---|
| ordinary | 0.576 / 0.863 / 0.960 / 1.906 | 0.982 / 1.141 / 1.434 / 2.797 | 2,223 / 7,737 / 13,078 / 16,569 | p95 1.906 ms <= 10 ms: `PASS` |
| five-repository surrogate activation | 51.061 / 61.814 / 87.132 / 103.770 | 52.105 / 64.514 / 89.003 / 107.467 | 20.7 / 71.3 / 104.6 / 159.5 | p95 103.770 ms <= 250 ms: `PASS` |
| Codex-all surrogate long | 21.371 / 23.812 / 35.351 / 44.714 | 22.261 / 25.256 / 40.888 / 47.687 | 51.9 / 183.8 / 283.2 / 397.1 | p95 44.714 ms <= 600 ms: `PASS` |
| public synthetic | 4.464 / 4.717 / 6.453 / 8.908 | 5.048 / 5.095 / 6.935 / 10.485 | 266.7 / 941.3 / 1,626.0 / 2,215.3 | p95 8.908 ms <= 150 ms and p99 10.485 ms <= 300 ms: `PASS` |

| SQLite `Enqueue` + `Flush` | c=1 | c=4 | c=8 | c=16 |
|---|---:|---:|---:|---:|
| p50 / p95 / p99 / max ms | 0.082 / 0.108 / 0.207 / 0.207 | 0.290 / 0.298 / 0.364 / 0.364 | 0.505 / 0.575 / 0.608 / 0.608 | 1.043 / 1.114 / 1.140 / 1.140 |
| throughput operations/s | 11,998 | 14,700 | 16,024 | 15,110 |
| queue depth before / sampled max / after (capacity 256) | 0 / 0 / 0 | 0 / 4 / 0 | 0 / 14 / 0 | 0 / 30 / 0 |

All 2,304 measured operations completed with zero reported failures and zero
recovered panics. The measured absolute gates are `PASS`. The fixed-workload
p99 regression gate remains **`NOT_PROVIDED`** because there is no recorded
Round 10 p99 baseline bound to these exact fixture hashes and source identity;
historical p95 or microbenchmark values are not substituted. CPA Host/container
restart, network/Provider latency, RSS, exact-clean-tree CI, and production
capacity also remain **`NOT_PROVIDED`**. Race remains a separate CI gate and is
not mixed into these wall-clock measurements. Therefore this result does not
close the release-level RT10-08 gate.

## Historical Round 10 status

The Round 10 classifier/source snapshot is frozen pending an exact commit. Its
historical source identity is `classifier-policy-v10` /
`db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594`
and ruleset `1.0.10` /
`e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0`.
The Round 10 working tree changes classifier behavior for bounded historical
tool-result activation, direct-current-user compaction, and long-text coverage;
the CPA v7.2.113 dependency pin is therefore not the only identity input.
Exact-commit performance, CPA Host resource measurements, and the Tencent
Cloud #2 matrix remain **PENDING** for
`db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594`.
The complete isolated benchmark results below remain frozen to the predecessor
CPA v7.2.104 identity `e7a00b02...` and are not reattributed.

Evidence from the two immediate predecessors is retained without rebinding.
Historical frozen main `1a64639c0bac7a157d8201c1593bd68cf6e7fe11` used exact
policy digest
`f9529ada85dee7e35267c70da54aa74e266e88b4ed2703924f352c2cb0cb4333` and
passed its source-only classifier gate, including the isolated P95 and
directive-overflow acceptance below. Historical main
`150c25e6352cb237cb3956bd66c83c3278c3fe33` used exact policy digest
`e0cbc975c126a12649a1b8e309e4e2a95efc64e46346467771ecae61b3e14971` and
passed engineering CI run `30353591705`, but its Tencent Cloud #2 isolated
audit was **FAIL BLOCKED** with 287 complete malicious fail-open cases, 36
malicious incomplete 403 cases, and 2 complete benign false positives. Neither
predecessor supplies current-identity performance evidence.

The nearest older complete comparison is predecessor-only development evidence
bound to digest
`2c968f70cfe12e136c07e2856b589f220d464b2284f93e05f368cbb7c927848f`.
That WSL Ubuntu 26.04 / Go 1.26.4 / GNU Make 4.4.1 run recorded classifier
P50/P95/P99 `551.254 us / 957.089 us / 1.266960 ms`, candidate-rich and
near-budget adversarial cases `41.335816/23.460676 ms/op`, the approximately
1 MiB META wrapper at `160.790024 ms/op`, `6,337,260 B/op`, and 103
allocations, and the 1,024-clause negated-prohibition flood at
`38.648832 ms/op`, `4,358,501 B/op`, and 6,003 allocations. At 64 complete
call/result pairs, the request-local association planner measured OpenAI
Chat/Responses, Claude, and Gemini at
`1.663277/1.447810/1.299558/1.290847 ms/op`,
`845,978/784,565/568,114/736,402 B/op`, and
`16,981/15,552/14,046/15,007 allocs/op`. The separate 1 MiB profiled
defensive-quote microbenchmark measured `344.061658-366.730649 ms/op`, above
the external `<250 ms/op` optimization target. Those measurements remain
historical and are not relabeled as current-source evidence. On historical
`1a64639c` / `f9529ada...`, isolated classifier performance acceptance passed
with P95 `1.5067 ms` against `<2 ms`, and the directive-overflow boundary
reached at most `153.72 ms` against `<175 ms`; its complete benchmark recipe
remained pending. No result here is final current commit/tree, CPA Host,
reproducible Linux
`.so`, release, or independent performance evidence.

| Current and historical evidence | Status |
|---|---|
| Historical policy-v10 repository-local performance | **HISTORICAL LOCAL SOURCE/SURROGATE PASS; HOST AND EXTERNAL EVIDENCE NOT PROVIDED.** `make round6-benchmark` and the Go 1.26.4-only `make round10-performance` gate passed for the frozen policy-v10 source. The latest Round 10 runner recorded ordinary p95 `2.589708 ms`, five-repository surrogate p95 `112.310521 ms`, Codex-all surrogate p95 `49.690010 ms`, public p95/p99 `9.306253/9.847559 ms`, and SQLite c=16 p95 `1.169612 ms`, with zero failures and zero recovered panics. The JSON path is `/tmp/cyber-abuse-guard-round10-performance.json`. No current policy-v12, CPA Host/container, fixed-workload p99 baseline, protected 4,424-request run, exact commit, or independent performance result is inferred. |
| Frozen CPA v7.2.104 / `e7a00b02d7e0e4ca837204cfed476b4f371f599facbf546e342362370111ec14` performance acceptance | **HISTORICAL LOCAL LINUX SOURCE-ONLY PASS.** Isolated `make round6-benchmark` passed under WSL Ubuntu 26.04 / Linux amd64 / Go 1.26.4. Classifier P50/P95/P99 were `328.852/412.093/558.688 us`; candidate-rich/near-budget were `35.943486/16.983200 ms/op`; long META was `113.071336 ms/op`; the 1,024-unique-prohibition boundary was `80.469498 ms/op`. The 1 MiB profiled defensive-quote path measured `198.164561-211.251020 ms/op`, below the external `<250 ms/op` target. No current v7.2.113, CPA Host, exact-commit CI, or independent performance PASS is inferred. |
| Historical `150c25e6...` / `e0cbc975...` engineering and audit result | **ENGINEERING CI PASS / SECURITY AUDIT FAIL BLOCKED.** Exact-HEAD CI run `30353591705` passed, but the Tencent Cloud #2 isolated audit found 287 complete malicious fail-open cases, 36 malicious incomplete 403 cases, and 2 complete benign false positives. No performance acceptance is inferred for either that identity or the current tree. |
| Historical `1a64639c...` / `f9529ada...` classifier gate | **HISTORICAL SOURCE-ONLY PASS.** The isolated classifier gate passed with P95 `1.5067 ms` against `<2 ms`, and the directive-overflow boundary reached at most `153.72 ms` against `<175 ms`. The complete `make round6-benchmark` recipe remained pending; this PASS is bound only to `1a64639c0bac7a157d8201c1593bd68cf6e7fe11` and `f9529ada85dee7e35267c70da54aa74e266e88b4ed2703924f352c2cb0cb4333`. |
| Pre-refresh complete local Linux development recipe (`2c968f70...`) | **HISTORICAL DEVELOPMENT SELF-CHECK PASS.** The complete recipe produced the detailed latency/allocation figures recorded above, including the long-prompt follow-up. It predates the current referent-policy identity and is not current-source, Host, artifact, or release evidence. |
| Previous working-tree complete recipe (`5012c101...`) | **HISTORICAL DEVELOPMENT SELF-CHECK PASS.** The preceding policy snapshot recorded P50/P95/P99 `459.731/563.714/765.255 us`, candidate-rich/near-budget `41.898827/21.298198 ms/op`, long META `152.808023 ms/op`, and a transient 30,674-byte log SHA-256 `a0a2ae3ce885ca4c64bde47578bda0a8ec67534c73849a4ee65c6dcc7329249b`; it is not current-identity evidence |
| Pre-final isolated classifier latency study | **HISTORICAL DEVELOPMENT PASS.** Fourteen predecessor working-tree runs and five clean-HEAD controls passed P95 `<2 ms` / P99 `<5 ms`. Their stable median was P50 `391.237 us`, P95 `468.491 us`, P99 `620.655 us`, and about `28,041 B/classification`; one whole-process WSL noise round reached P99 `4.871859 ms` but still passed. Do not use this predecessor study as a present-policy result. |
| Historical complete local Linux development recipe (pre-current identity) | **HISTORICAL DEVELOPMENT SELF-CHECK PASS.** `GO=/home/yujian/.cache/codex-go/go1.26.4/bin/go make round6-benchmark` with `GOFLAGS=-mod=readonly` exited successfully. Raw log: `dist/round9-worklogs/round6-benchmark-post-perf-20260724.log`, 26441 bytes, SHA-256 `ec603a4b437820f579d69340feba76bd63752ab5a63cf63998b6e87873d6c063` |
| Historical role-aware maximum-parts path (pre-current identity) | **HISTORICAL DEVELOPMENT REGRESSION PASS.** Three `BenchmarkClassifierCandidateRichMaxParts` samples recorded 37.311769-39.621583 ms/op, 6,622,070-6,624,038 B/op, and 700-706 allocs/op. The checked-in hard-bound test remains part of CI, but its timing/allocation result was not rerun for the working-tree identity stated above |
| Pre-fix v9 WSL source self-check (`f37a25dd`) | **HISTORICAL DEVELOPMENT PASS.** Linux amd64 Go 1.26.4 recorded classifier p50/p95/p99 of 454.800 µs / 764.214 µs / 1.007808 ms over 10,000 samples; adversarial candidate-rich and near-budget cases were 42.930 ms/op and 24.744 ms/op. One-iteration streaming samples were 51.037 ms for 270 KiB, 197.453 ms for 1 MiB, 803.990 ms for 4 MiB, and 1.616 s near 8 MiB. These numbers predate the current policy identity and are not CPA Host or release evidence |
| Pre-fix normalized multilingual long-frame signal pass (`f37a25dd`) | **HISTORICAL DEVELOPMENT PASS.** Three isolated Go 1.26.4 `BenchmarkStreamingDefensiveQuotedReviewFrameSignals` runs measured 0.355-0.363 ms/op at 16 KiB (45.15-46.21 MB/s, 810-813 B/op, 2 allocs/op) and 22.230-22.564 ms/op at 1 MiB (46.47-47.17 MB/s, 841-847 B/op, 2 allocs/op) for normalization plus one Aho-Corasick pass. The full profiled path measured 7.873-8.598 ms/op at 16 KiB (543,028-563,462 B/op, 108-110 allocs/op) and 250.230-259.302 ms/op at 1 MiB (16,886,254-17,299,688 B/op, 333-339 allocs/op). These are historical WSL source microbenchmarks, not current-identity or CPA Host evidence |
| Pre-fix directive-clause overflow wall-clock boundary (`f37a25dd`) | **HISTORICAL DEVELOPMENT PASS WITH LIMITED CONCURRENT HEADROOM.** Three isolated Go 1.26.4 runs measured the 1,024-unique-prohibition case at 93.324-97.670 ms/op, and a later exact-commit isolated rerun measured 99.842 ms/op, 449,483 B/op, and 2,103 allocs/op against the `<175 ms/op` gate. The independent audit also observed 184-198 ms/op when unrelated package work ran concurrently. Keep the deterministic wall-clock gate isolated and treat Host concurrency, RSS, P95/P99, and near-8 MiB fields as a separate acceptance lane; no current-policy or CPA Host latency/throughput result is inferred |
| Pre-fix diagnostic retained as history | The earlier working-tree snapshot recorded 14.948-16.418 s/op, approximately 397 MB/op, and about 1.077 million allocs/op. Its CPU profile (`6eb5ec36955f30df460a64111ebbeea5b9b9ed32e5394ee04b78e1b0f1834d69`) and memory profile (`fdc111fca573a32701fdee9abd206c680481f1247998a394578cbdd7fcd17eb6`) remain diagnostic chronology only and are not attributed to the current classifier identity |
| Classifier latency and allocation acceptance on the current source identity | **LOCAL HARD ACCEPTANCE AND BENCHMARK RECIPE PASS; FULL REVALIDATION PENDING.** Linux amd64 Go 1.26.4 passed the Round 5 long-prompt hard gate at 134.498 ms/op, 6,333,833 B/op, and 99 allocs/op after allocation preflight hardening, and the current Round 6 benchmark recipe passed. Final commit/tree, exact candidate artifact, CPA Host, fixed-workload p99 baseline, and independent binding are not provided. |
| Standalone and CPA Host RSS on the exact candidate | `NOT_PROVIDED` |
| CPA Host latency, throughput, concurrency, and first-byte behavior | `NOT_PROVIDED` |
| Repository-local counted-Mock runtime performance | `NOT_PROVIDED` |
| Tencent Cloud #2 isolated counted-Mock runtime performance | `NOT_PROVIDED` |
| Protected external evaluation runtime and resource evidence | `NOT_PROVIDED` |
| Final commit/tree, exact Linux `.so`, exact-main CI, and independent performance audit | `NOT_PROVIDED` |

The performance repair preserves same-group cross-field evidence composition,
deduplicates only byte-identical source fields, constructs one-to-one physical
ownership from the newest field backward, and stops only after a complete safe
assignment. The hard acceptance test now prevents the previous maximum-parts
CPU/allocation explosion from silently returning. The old profiles remain
useful root-cause evidence, but neither the old failure nor the current fix is
final release evidence until the exact candidate is frozen and independently
rerun.

The defensive-quote parity repair runs only when a current profiled scope has
both directive and carrier units. Ordinary short requests avoid reconstruction;
long fields retain a three-bit signal set. A single carrier is no longer
classified twice, and a reconstructed proof is capped at 66,080 bytes. Tight
`MaxChunks` regression remains historical `1a64639c` / `f9529ada...` evidence;
the current-identity complete recipe and isolated short classifier latency gate
also passed in the 2026-07-29 source-only run. The
over-512-byte signal path performs one multi-pattern scan and shares the main
normalized view when no compact carry was injected; the conservative fallback
normalizes independently. Chinese, Japanese, Korean, and mixed-language terms
extend only that precompiled ambiguity matcher; they do not add repeated literal
scans or grant suppression. The 64-unit overflow retains only content-free field
identity and signal state. The 64-scope path performs bounded proof or carrier
classification only when capacity eviction is required, allowing complete safe
scopes to leave the window. No exact CPA Host latency, RSS, or throughput result
is inferred from those source-only checks.

The current remediation includes bounded classifier, streaming proof-budget,
and eligibility-path changes. Historical `1a64639c` / `f9529ada...` has the isolated
classifier evidence recorded above; its complete benchmark recipe remained
pending. The frozen CPA v7.2.104 /
`e7a00b02d7e0e4ca837204cfed476b4f371f599facbf546e342362370111ec14`
identity passed the complete local recipe but still requires separate CPA Host
concurrency/RSS/tail-latency evidence, and its
1 MiB profiled defensive-quote path measured `198.164561-211.251020 ms/op`,
below the external `<250 ms/op` local target, before any broader performance claim.

A CPU profile of the historical `f37a25dd` overflow fixture measured about
130.066 ms/op with profiling overhead. The overlapping cumulative samples put
the clause walker at 48.75%, `analyzeDirectives.func3` at 45.42%, negation proof
at 21.67%, and `semanticDimensionsByMatch` at 5.42%. This supports future
allocation work such as delaying zero-value semantic-owner slices, but does not
prove semantic DP is the largest hotspot. No such production optimization is
included in the current false-positive repair because it would require its own
semantic differential and performance evidence.

Round 8 and earlier numbers below are historical development self-checks only.
They cannot be transferred to Round 9 because candidate eligibility, classifier
selection, audit explanation, and execution paths changed. A valid final rerun
must bind raw output, environment, final commit/tree, classifier/ruleset
identities, exact candidate SHA-256, and the named evidence boundary.

## Historical Round 8 status

**ROUND 8 DEVELOPMENT SOURCE-TREE SNAPSHOT / NOT ROUND 9 OR RELEASE EVIDENCE.**
The historical source target was the Linux amd64 `v0.16-rc.2` prerelease
contract on `feat/round8-balanced-readmission`. The final local Go 1.26.4 Linux development
gate, race run, benchmark acceptance, same-machine baseline comparison, and one
standalone RSS comparison have completed. They remain source-tree self-checks:
the source was not yet tag-, artifact-, or Release-bound when measured.
Exact-main GitHub CI and the CPA v7.2.95 counted-Mock Host lane remain pending, so no
Host latency, throughput, concurrency, or production-performance claim is made.

The sections following this Round 8 block retain still older P1-P2,
classifier, and reliability measurements as regression context. They are not
Round 9 evidence, a formal release benchmark, or a blind quality result.
Methodologically valid evaluation v10 remains the frozen, first-and-only
authoritative `FAIL`. Earlier over-broad read-only searches displayed
evaluation/holdout test or historical-report filenames, historical ruleset
SHA-256 references, caller-path lines, and aggregate summaries. During the
current closure, one additional broad `git grep` unexpectedly emitted several
individual request and label lines from retired holdout fixture files. The
possessive-browser-target false negative had already been identified by
classifier review before that search; none of the emitted lines was used for
performance, classifier, rule, score, or threshold calibration or copied into
source/tests/docs. One separate over-broad classifier command may also have
compiled or run the restricted gate during development, so that result is
excluded. This session cannot claim fixture non-access, blind, independent, or
zero-access evidence; a new untouched holdout under an independent reviewer is
required.

The WSL command `make cpa-router-fixture-blackbox`, the now-removed legacy
target `cpa-v7272-host-blackbox`, and
`scripts/management-proxy-413-test.sh` were mistakenly executed outside the
authorized evidence path. They used loopback/Mock components only and cleanup
left no fixture process. Their results are excluded from this report:

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

## Historical Round 8 performance status

Round 8 changed the classifier, extractor provenance, audit aggregation, raw
capture deduplication, and decision-explanation paths, so still older
measurements were not transferred to that candidate. The results below compare
baseline `d540eaa43497c1ae0b4b84106b2bac9fe1617bb2` with the historical Round 8 source-tree
snapshot on the same WSL Ubuntu-26.04 Linux amd64 host, using Go 1.26.4
(`go version go1.26.4 linux/amd64`). They are **DEVELOPMENT SELF-CHECKS / NOT
RELEASE OR HOST EVIDENCE**. The measurements must be rerun if
performance-sensitive source changes before the release commit.

### Acceptance latency comparison

| Path | Baseline `d540eaa` | Round 8 source-tree snapshot | Change |
|---|---:|---:|---:|
| Short classifier p50 (10,000 samples) | 173.973 us | 105.272 us | -39.5% |
| Short classifier p95 | 282.720 us | 146.139 us | -48.3% |
| Short classifier p99 | 406.484 us | 263.117 us | -35.3% |

All recorded acceptance values remain below their checked-in thresholds. These
percentiles are in-process classifier timings; they do not represent CPA Host or
network tail latency.

### Classifier allocation and adversarial-path acceptance

The final isolated acceptance recheck recorded:

| Acceptance path | Round 8 source-tree observation |
|---|---:|
| Single-clause classifier | 132.119 us/op; 35,667 B/op; 76 allocs/op |
| Candidate-rich maximum-parts classifier | 45.245564 ms/op |
| Near-budget adversarial classifier | 17.877290 ms/op; 323,825 B/op |

The candidate-rich latency remains 65.4% below the 130.700829 ms/op baseline
observation. The complete benchmark gate also passed its checked-in latency,
allocation, and adversarial-boundary ceilings. These isolated values can vary
with host scheduling and are not CPA Host latency.

### Paired long-text acceptance

| Fixture | Baseline `d540eaa` | Round 8 source-tree snapshot | Change |
|---|---:|---:|---:|
| Text 1 MiB | 20.843284 ms | 19.887227 ms | -4.6% |
| Text Near-8 MiB | 159.114903 ms | 163.926518 ms | +3.0% |
| KeyRich 1 MiB | 5.534472 ms | 5.072744 ms | -8.3% |
| KeyRich Near-8 MiB | 47.263144 ms | 38.876913 ms | -17.7% |
| SemanticRich 1 MiB | 4.775169 ms | 4.180488 ms | -12.5% |
| SemanticRich Near-8 MiB | 36.190022 ms | 34.056162 ms | -5.9% |

All six paired cases stayed below the Round 8 `+25%` regression ceiling and the
absolute checked-in latency/allocation/slope limits.

### Standalone RSS observation and complete benchmark gate

Paired standalone Linux test binaries, run with the same scope, recorded a
maximum resident set size of 46,132 KiB for baseline `d540eaa` and 46,616 KiB
for the final Round 8 source-tree snapshot (+1.0%). This is one controlled
process comparison, not a CPA Host, concurrent-load, or production RSS
envelope.

The final acceptance run additionally recorded these bounded paths:

| Acceptance path | Latency | Bytes/op | Allocs/op |
|---|---:|---:|---:|
| Raw Capture prepare | 437,369,818 ns/op | 3,359,605 | 57 |
| Raw Capture composite | 427,176,459 ns/op | 3,369,141 | 87 |
| Raw Capture queue-full fast path | 46 ns/op | 0 | 0 |
| Raw Capture management response | 53,230,244 ns/op | 8,528,651 | 1,327 |
| Wrapper audit fast path | 13,337,858 ns/op | 1,513,024 | 2,846 |

The final local `make round6-benchmark` rerun passed, including classifier,
long-text extraction, Raw Capture, management-response, wrapper/audit, and the
four-repository full-route performance acceptances. The complete `make race`
rerun also passed with no reported data race; the plugin package took 379.920
seconds and the classifier package 69.762 seconds. Exact allocation
assertions remain in the ordinary Linux lane because race instrumentation adds
nondeterministic allocation bookkeeping.

## Historical v0.16-rc.1 P1-P2 performance self-check

Environment and scope:

- Date: 2026-07-21 (Asia/Shanghai); retained as historical evidence.
- Platform: WSL Ubuntu-26.04, Linux amd64.
- Toolchain: Go 1.26.4 with `GOTOOLCHAIN=local`.
- Source: historical P1-P2 development branch based on `7b2422e`; not
  artifact-bound and superseded by Round 8.
- Evidence class: **DEVELOPMENT SELF-CHECK / NOT RELEASE EVIDENCE**.

The acceptance checks below were produced by the complete
`make round6-benchmark` target with the existing Linux toolchain. The same
frozen code also passed `make test`, `make round6-vet`,
`make round6-format-check`, `make round6-module-verify`,
`make round6-script-test`, deterministic 13-target `make fuzz-smoke`, audit and
raw-capture race tests, and the pinned CPA v7.2.95 raw-capture Host source
overlay.

- `go test ./internal/extract -count=1 -v -run='^TestRound6LongTextScaleAcceptance$'`
- `CAG_RAW_CAPTURE_PERFORMANCE_ACCEPTANCE=1 go test ./internal/audit -count=1 -v -run='^TestRawCapturePerformanceAcceptance$'`
- `go test -tags=sqlite_omit_load_extension ./internal/plugin -count=1 -v -run='^TestRawCaptureManagementResponsePerformanceAcceptance$'`

The raw-capture wall-clock acceptance is enabled only by the serialized
`round6-benchmark` recipe. Broad multi-package unit runs skip that timing gate
so shared-runner contention cannot masquerade as a production regression; the
dedicated recipe retains the original latency and allocation limits.

### P2 long-JSON scaling

The Near-8 MiB body size is `8 MiB - 4 KiB`. Every fixture also enforces a
CPU-slope gate: its Near-8 MiB `ns/byte` must be no more than 2.5 times its
1 MiB `ns/byte`.

| Fixture | 1 MiB threshold and observation | Near-8 MiB threshold and observation | Self-check |
|---|---|---|---|
| Text | <= 150 ms, <= 512 KiB/op, <= 64 allocs/op; observed 20.0 ms, 342,036 B/op, 45 allocs/op | <= 1.2 s, <= 512 KiB/op, <= 64 allocs/op; observed 155.7 ms, 341,997 B/op, 45 allocs/op | **PASS**, including slope |
| KeyRich | <= 150 ms, <= 768 KiB/op, <= 25,000 allocs/op; observed 4.89 ms, 372,029 B/op, 17,205 allocs/op | <= 1.2 s, <= 3 MiB/op, <= 160,000 allocs/op; observed 41.8 ms, 2,409,686 B/op, 137,464 allocs/op | **PASS**, including slope |
| SemanticRich | <= 150 ms, <= 512 KiB/op, <= 10,000 allocs/op; observed 4.33 ms, 160,400 B/op, 5,473 allocs/op | <= 1.2 s, <= 1 MiB/op, <= 60,000 allocs/op; observed 32.9 ms, 717,366 B/op, 43,553 allocs/op | **PASS**, including slope |

### P1 raw-capture and management response

| Acceptance case | Frozen threshold | Observed result | Self-check |
|---|---|---|---|
| Near-8 MiB prepare (`8 MiB - 64 KiB` request) | latency <= 1.2 s; <= 4 MiB/op; <= 160 allocs/op | 457,790,105 ns/op; 3,355,125 B/op; 43 allocs/op | **PASS** |
| Near-8 MiB composite event + capture admission | latency <= 1.5 s; <= 5 MiB/op; <= 200 allocs/op | 454,296,686 ns/op; 3,360,418 B/op; 68 allocs/op | **PASS** |
| Queue-full rejection before body preparation | latency <= 50 us; exactly 0 B/op and 0 allocs/op | 46 ns/op; 0 B/op; 0 allocs/op | **PASS** |
| Management response, eight 1 MiB worst-case HTML fixtures, bounded to complete 8 MiB CPA Host body | latency <= 500 ms; <= 16 MiB/op; <= 1,600 allocs/op | 54,596,462 ns/op; 8,529,000 B/op; 1,329 allocs/op | **PASS** |

These `testing.Benchmark` acceptance samples report aggregate `ns/op`,
`B/op`, and `allocs/op`. They do **not** collect or prove p50, p95, p99, peak
RSS, end-to-end CPA Host latency, request throughput, or concurrent-load
behavior; those values are **UNAVAILABLE / NOT MEASURED** and must not be
inferred from these historical `ns/op` values. Separate Round 8 in-process
percentiles and one standalone RSS observation are recorded above, but the CPA
v7.2.95 counted-Mock Host lane, Host tail
latency, throughput, concurrency, and Host RSS remain **NOT RUN / NOT PROVIDED**.

Exact-main GitHub CI run
[`29799561002`](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29799561002)
predates this P1-P2 working tree and failed in both attempts before benchmark
and artifact stages completed. It supplies no current v0.16 performance
evidence or Actions artifact.

The remaining release-level comparisons are **NOT RUN**: ordinary allowed
requests with capture disabled/enabled, final blocked requests through the real
Host, 1 MiB and Host-limit end-to-end routes, `limit=20` versus `limit=100`
management pages, and concurrent load. Sensitive request text must not appear
in benchmark logs or public Actions artifacts.

## Historical classifier before/after reference

Environment:

```text
OS/arch: Windows amd64
CPU: 13th Gen Intel Core i7-13650HX
Go: 1.26.4
Command: go test ./internal/classifier -run '^$' \
  -bench '^BenchmarkClassifier' -benchmem -count=3
Statistic: median of three runs
```

| Benchmark | `a121a44` median | `a1be19f` median | Latency change |
|---|---:|---:|---:|
| `Classifier` | 165,552 ns/op; 24,446 B/op; 43 allocs/op | 103,190 ns/op; 25,487 B/op; 46 allocs/op | -37.7% |
| `LargeBenign` | 18,461,010 ns/op; 301,778 B/op; 9 allocs/op | 17,682,477 ns/op; 300,966 B/op; 9 allocs/op | -4.2% |
| `LargePunctuation` | 17,705,454 ns/op; 301,778 B/op; 9 allocs/op | 16,397,845 ns/op; 299,551 B/op; 9 allocs/op | -7.4% |
| `CandidateRichMaxParts` | 119,484,917 ns/op; 82,548 B/op; 175 allocs/op | 97,126,983 ns/op; 83,588 B/op; 178 allocs/op | -18.7% |
| `RoleAwareConversation` | 383,775 ns/op; 130,412 B/op; 198 allocs/op | 356,226 ns/op; 135,614 B/op; 213 allocs/op | -7.2% |

Interpretation:

- all five measured median latency cases improved on the same machine;
- large benign/punctuation allocations decreased slightly;
- the ordinary, candidate-rich, and role-aware paths allocate more after adding
  the behavior graph and richer evidence ownership;
- the role-aware path increased from 198 to 213 allocations/op, so memory work
  remains open even though latency improved;
- no scan, decode, part, history, carrier, or taxonomy coverage was reduced to
  obtain these measurements.

## Historical implementation-freeze development rerun

The full local WSL/Linux amd64 rerun used review-closure commit `8814dbf` with Go
1.26.4 and classifier-policy SHA-256
`dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2`.
The final implementation freeze `9c8114e` changes only the integration-test
Provider probe lifecycle; its exact-commit GitHub CI benchmark is recorded
separately below. Neither result is Leo or release evidence.

Median of three `-bench=. -benchmem` runs:

| Benchmark | Local `8814dbf` median |
|---|---:|
| `Classifier` | 92,070 ns/op; 25,488 B/op; 46 allocs/op |
| `LargeBenign` | 15,612,625 ns/op; 297,664 B/op; 9 allocs/op |
| `LargePunctuation` | 15,395,706 ns/op; 298,037 B/op; 9 allocs/op |
| `CandidateRichMaxParts` | 88,235,463 ns/op; 83,559 B/op; 178 allocs/op |
| `RoleAwareConversation` | 333,250 ns/op; 135,616 B/op; 213 allocs/op |

The acceptance test recorded p50 80.412 us, p95 123.307 us, p99 215.204 us;
candidate-rich 90.261 ms/op; near-budget 15.731 ms/op and 299,131 B/op. Both
acceptance cases and the full benchmark target passed.

Exact-freeze GitHub CI run `29292693070` also passed benchmark acceptance. Its
three-run medians were:

| Benchmark | CI `9c8114e` median |
|---|---:|
| `Classifier` | 94,050 ns/op; 25,480 B/op; 46 allocs/op |
| `LargeBenign` | 14,301,144 ns/op; 297,742 B/op; 9 allocs/op |
| `LargePunctuation` | 13,073,068 ns/op; 296,386 B/op; 9 allocs/op |
| `CandidateRichMaxParts` | 81,008,678 ns/op; 83,322 B/op; 178 allocs/op |
| `RoleAwareConversation` | 354,428 ns/op; 135,577 B/op; 213 allocs/op |

The CI acceptance sample recorded p50 84.275 us, p95 150.672 us, p99 182.349
us; candidate-rich 81.051285 ms/op; near-budget 14.665888 ms/op and 297,256
B/op.

## Historical subject and pending-cache reference

The shared reliability work replaces linear pending-cache eviction with ordered
O(1) refresh/eviction and makes subject scoring idempotent per domain-separated
request digest.

Windows development ranges on the same i7-13650HX / Go 1.26.4 machine:

| Benchmark | Result |
|---|---:|
| Pending cache parallel hit | 119.6–124.1 ns/op; 0 B/op; 0 allocs/op |
| Pending cache full insert | 266.4–318.5 ns/op; 64 B/op; 2 allocs/op |
| Previous linear full-cache reference | 105.2–112.3 us/op |
| Parallel duplicate subject request | 374.9–405.5 ns/op; 0 B/op; 0 allocs/op |

WSL/ext4 development ranges with Go 1.26.4 independently showed:

| Benchmark | Result |
|---|---:|
| Pending cache full insert | 302.9–409.8 ns/op; 64 B/op; 2 allocs/op |
| Previous linear full-cache reference | 121.6–136.1 us/op |
| Duplicate subject request | 438.4–479.0 ns/op; 0 B/op; 0 allocs/op |

These microbenchmarks isolate data-structure operations. They do not predict
end-to-end CPA throughput or tail latency.

## Historical pre-v0.16 rerun instruction

Leo should rerun on the proposed frozen commit and record raw output, runner
identity, variance, and artifact/commit identity:

```bash
go version
go env GOOS GOARCH CGO_ENABLED GOMAXPROCS GOAMD64
uname -a
lscpu

go test ./internal/classifier -run '^$' \
  -bench '^BenchmarkClassifier' -benchmem -count=5

make benchmark
```

If the final tree changes classifier, extractor, rules, pending-cache, subject,
audit-event, or build dependencies, these development numbers must be treated as
stale and rerun. Do not weaken coverage or resource boundaries to improve them.

## Historical evidence block

```text
starting_baseline: a121a444cb0d82cba4e27754914a1f88258e1d7b
classifier_reference_commit: a1be19f2f5a5317cf979d608f89289ac7cfa2a71
reliability_checkpoint_commit: 573def2649d164161e2dfdfeb3f59b1e1b38ebbc
implementation_freeze_commit: 9c8114e22841f9a19b15b1f4b3c48531aa2453a0
evidence_document_commit: SELF (resolve with git log -1 -- this file)
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
historical_classifier_policy_version: classifier-policy-v2
historical_classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
development_benchmark_result: PASS FOR RECORDED SELF-CHECKS
github_ci_benchmark: PASS — push run 29292693070
leo_independent_benchmark: NOT RUN
formal_performance_gate: BLOCKED
```
