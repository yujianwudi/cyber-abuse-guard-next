# Performance Report — Round 9 status and historical development evidence

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: 5012c1013645e593422c76546d1afaf41b1e4f5184e0400cc58bd04db8f02b03
```

Last updated: 2026-07-27 (Asia/Shanghai)

## Round 9 current status

The final Round 9 classifier/source snapshot has not been frozen. The current
working-tree identity is `classifier-policy-v9` /
`5012c1013645e593422c76546d1afaf41b1e4f5184e0400cc58bd04db8f02b03`
and ruleset `1.0.10` /
`e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0`.
The complete `make round6-benchmark` recipe was rerun for the working-tree
identity stated above under WSL Ubuntu 26.04, Go 1.26.4 linux/amd64, and GNU Make
4.4.1, and exited 0. The hard acceptance lane recorded classifier
P50/P95/P99 `459.731/563.714/765.255 us`, candidate-rich and near-budget
adversarial cases `41.898827/21.298198 ms/op`, the approximately 1 MiB META
wrapper at `152.808023 ms/op`, `6,339,221 B/op`, and 110 allocations, and the
1,024-clause negated-prohibition flood at `34.427263 ms/op`, `4,358,060 B/op`, and 6,003
allocations. At 64 complete call/result pairs, the request-local association
planner measured OpenAI Chat/Responses, Claude, and Gemini at
`1.382390/1.209921/0.922327/1.093778 ms/op`,
`845,978/784,565/568,114/736,338 B/op`, and
`16,981/15,552/14,046/15,005 allocs/op`. Long JSON extraction, raw-capture
admission/management, and four-repository full-route acceptance also passed in
the same recipe. The transient local log was 30,674 bytes with SHA-256
`a0a2ae3ce885ca4c64bde47578bda0a8ec67534c73849a4ee65c6dcc7329249b`;
it is not checked into Git. This is
source-only development evidence for the current policy identity, not a final
commit/tree, CPA Host, reproducible Linux `.so`, release, or independent result.
The isolated classifier latency comparison and predecessor complete benchmark
below remain useful supporting history but are not substituted for the current
recipe.

| Round 9 evidence | Current status |
|---|---|
| Current complete local Linux development recipe | **SOURCE-ONLY DEVELOPMENT PASS.** `make round6-benchmark` exited 0 for `classifier-policy-v9` / `5012c1013645e593422c76546d1afaf41b1e4f5184e0400cc58bd04db8f02b03` under WSL Ubuntu 26.04, Go 1.26.4 linux/amd64, and GNU Make 4.4.1. Classifier P50/P95/P99 were `459.731/563.714/765.255 us`; candidate-rich/near-budget were `41.898827/21.298198 ms/op` with near-budget `308,727 B/op`; the long META wrapper was `152.808023 ms/op`, `6,339,221 B/op`, 110 allocs; the negated-prohibition flood was `34.427263 ms/op`, `4,358,060 B/op`, 6,003 allocs. At 64 complete tool call/result pairs, OpenAI Chat/Responses, Claude, and Gemini association planning measured `1.382390/1.209921/0.922327/1.093778 ms/op`, `845,978/784,565/568,114/736,338 B/op`, and `16,981/15,552/14,046/15,005 allocs/op`. Extract, raw-capture, and plugin-route acceptance lanes passed. The transient 30,674-byte log hashed to `a0a2ae3ce885ca4c64bde47578bda0a8ec67534c73849a4ee65c6dcc7329249b`; no raw log is checked in, and no CPA Host, final artifact, or independent claim is inferred |
| Pre-final isolated classifier latency study | **HISTORICAL DEVELOPMENT PASS.** Fourteen predecessor working-tree runs and five clean-HEAD controls passed P95 `<2 ms` / P99 `<5 ms`. Their stable median was P50 `391.237 us`, P95 `468.491 us`, P99 `620.655 us`, and about `28,041 B/classification`; one whole-process WSL noise round reached P99 `4.871859 ms` but still passed. Use the complete recipe above for the present-policy result; do not relabel this predecessor study |
| Historical complete local Linux development recipe (pre-current identity) | **HISTORICAL DEVELOPMENT SELF-CHECK PASS.** `GO=/home/yujian/.cache/codex-go/go1.26.4/bin/go make round6-benchmark` with `GOFLAGS=-mod=readonly` exited successfully. Raw log: `dist/round9-worklogs/round6-benchmark-post-perf-20260724.log`, 26441 bytes, SHA-256 `ec603a4b437820f579d69340feba76bd63752ab5a63cf63998b6e87873d6c063` |
| Historical role-aware maximum-parts path (pre-current identity) | **HISTORICAL DEVELOPMENT REGRESSION PASS.** Three `BenchmarkClassifierCandidateRichMaxParts` samples recorded 37.311769-39.621583 ms/op, 6,622,070-6,624,038 B/op, and 700-706 allocs/op. The checked-in hard-bound test remains part of CI, but its timing/allocation result was not rerun for the working-tree identity stated above |
| Pre-fix v9 WSL source self-check (`f37a25dd`) | **HISTORICAL DEVELOPMENT PASS.** Linux amd64 Go 1.26.4 recorded classifier p50/p95/p99 of 454.800 µs / 764.214 µs / 1.007808 ms over 10,000 samples; adversarial candidate-rich and near-budget cases were 42.930 ms/op and 24.744 ms/op. One-iteration streaming samples were 51.037 ms for 270 KiB, 197.453 ms for 1 MiB, 803.990 ms for 4 MiB, and 1.616 s near 8 MiB. These numbers predate the current policy identity and are not CPA Host or release evidence |
| Pre-fix normalized multilingual long-frame signal pass (`f37a25dd`) | **HISTORICAL DEVELOPMENT PASS.** Three isolated Go 1.26.4 `BenchmarkStreamingDefensiveQuotedReviewFrameSignals` runs measured 0.355-0.363 ms/op at 16 KiB (45.15-46.21 MB/s, 810-813 B/op, 2 allocs/op) and 22.230-22.564 ms/op at 1 MiB (46.47-47.17 MB/s, 841-847 B/op, 2 allocs/op) for normalization plus one Aho-Corasick pass. The full profiled path measured 7.873-8.598 ms/op at 16 KiB (543,028-563,462 B/op, 108-110 allocs/op) and 250.230-259.302 ms/op at 1 MiB (16,886,254-17,299,688 B/op, 333-339 allocs/op). These are historical WSL source microbenchmarks, not current-identity or CPA Host evidence |
| Pre-fix directive-clause overflow wall-clock boundary (`f37a25dd`) | **HISTORICAL DEVELOPMENT PASS WITH LIMITED CONCURRENT HEADROOM.** Three isolated Go 1.26.4 runs measured the 1,024-unique-prohibition case at 93.324-97.670 ms/op, and a later exact-commit isolated rerun measured 99.842 ms/op, 449,483 B/op, and 2,103 allocs/op against the `<175 ms/op` gate. The independent audit also observed 184-198 ms/op when unrelated package work ran concurrently. Keep the deterministic wall-clock gate isolated and treat Host concurrency, RSS, P95/P99, and near-8 MiB fields as a separate acceptance lane; no current-policy or CPA Host latency/throughput result is inferred |
| Pre-fix diagnostic retained as history | The earlier working-tree snapshot recorded 14.948-16.418 s/op, approximately 397 MB/op, and about 1.077 million allocs/op. Its CPU profile (`6eb5ec36955f30df460a64111ebbeea5b9b9ed32e5394ee04b78e1b0f1834d69`) and memory profile (`fdc111fca573a32701fdee9abd206c680481f1247998a394578cbdd7fcd17eb6`) remain diagnostic chronology only and are not attributed to the current classifier identity |
| Classifier latency and allocation acceptance on the current source identity | **SOURCE-ONLY DEVELOPMENT PASS** through the complete recipe above; final commit/tree and exact candidate artifact binding remain `NOT_PROVIDED` |
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
`MaxChunks` regression passes as a source behavior check; the complete current-
identity performance recipe and the isolated short classifier latency gate both
passed at the source boundary. The
over-512-byte signal path performs one multi-pattern scan and shares the main
normalized view when no compact carry was injected; the conservative fallback
normalizes independently. Chinese, Japanese, Korean, and mixed-language terms
extend only that precompiled ambiguity matcher; they do not add repeated literal
scans or grant suppression. The 64-unit overflow retains only content-free field
identity and signal state. The 64-scope path performs bounded proof or carrier
classification only when capacity eviction is required, allowing complete safe
scopes to leave the window. No exact CPA Host latency, RSS, or throughput result
is inferred from those source-only checks.

The incident-response false-positive repair changes only bounded analytical and
non-execution grammar and does not alter the long-frame matcher or streaming
data structures. The current policy now has both the complete source benchmark
recipe and isolated classifier latency evidence above, but still requires
separate CPA Host concurrency/RSS/tail-latency evidence before any broader
performance claim.

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
