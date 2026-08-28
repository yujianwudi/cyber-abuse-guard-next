# Round 6 development handoff

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: f98ee38cea5b38b60130b98bd3ca6100cb6aeeee223128311235469af40ec9e3
```

> **Frozen historical snapshot.** The classifier identity above is active-tree
> navigation metadata only. The body below preserves the Round 6 /
> v0.15 handoff, including its `classifier-policy-v5` values and any CPA v7.2.95
> wording such as "current release target"; those statements are historical only
> and are not the active repository release identity. The current Round 16
> overlay is CAG source `1.0.0`, planned `v1.0.0-rc.3` on Linux amd64, and
> `v7.2.144@d36b776c790a4d58027fd4fb434800fb5334bceb` (C ABI 1 / RPC schema 4).
> Round 13 v7.2.125/schema 2 evidence retains its historical identity and does
> not transfer a PASS. Every `/v1/realtime*` route currently bypasses CAG
> `RequestInterceptor`, `ModelRouter`, and request lifecycle and is
> **OUT_OF_SCOPE / UNPROTECTED / CAG_NOT_VISIBLE**. Only registered callback
> paths such as chat and Responses are protected; there is no all-traffic
> coverage claim. See [Round 16 status](ROUND16_STATUS.md).

Historical status: **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**

Target project version: exact `0.15`; intended formal tag: exact `v0.15`
(never `v0.15.0`).

This is the retained historical Round 6 source handoff. It is not a deployment approval,
Host validation report, independent audit approval, merge record, or Release
record.

## 1. Executive result

The development worktree contains a streaming long-text inspection design that
removes the Round 5.2 production-path dependency on a raw
body[:max_scan_bytes] prefix. The legacy max_scan_bytes=262144 setting now
selects a bounded classifier window rather than limiting inspection to the
first 256 KiB of the JSON body.

The candidate is still blocked because the final post-migration v0.15 PR head
and PR CI, merge to `main`, exact post-merge `main` Linux amd64 push CI, and a
private clean-candidate artifact do not yet exist; CPA v7.2.95 has not been run
as a real Host with the
official candidate `.so` and Mock upstream, and no independent
source/artifact/Host audit or candidate-bound external evaluation-v11+
`CONSUMED / PASS` attestation has approved it.

The candidate has not been merged to main and no `v0.15` tag or Release has
been created. The final PR head must first pass PR CI, then merge to `main`, and
the exact resulting main commit/tree must pass push CI. Only then may the clean
candidate workflow be dispatched from `refs/heads/main` to produce a private,
untagged, exact-source GitHub Actions artifact. Merge is a candidate-generation
prerequisite, not release approval; clean candidate bytes remain unreleased.

## 2. Scope and evidence rules

This round has one validation platform:

~~~text
Linux amd64
~~~

Windows and macOS builds, tests, race runs, benchmarks, and artifacts are not
required and are not evidence for this round. musl/Alpine remains outside the
documented target. The release build target is Linux amd64 with glibc 2.34 or
newer.

The work was restricted to the repository, exact-source CI, and the future
authorized Linux CPA + Mock-upstream sandbox. It did not authorize:

- local deployment;
- production Host access or production configuration changes;
- reading production requests, audit rows, tokens, API keys, HMAC keys, account
  pools, or user data;
- connecting a real Provider or billing upstream;
- executing the four public adversarial repositories or replaying their raw
  payloads;
- rerunning consumed evaluation or Holdout data.

Only Linux CI and authorized Linux sandbox results may become final execution
evidence. Development-machine diagnostics are not release evidence and no
performance number from them is promoted by this handoff.

## 3. Source and policy identity

| Identity | Value |
|---|---|
| Repository | yujianwudi/cyber-abuse-guard |
| Project version / formal tag | 0.15 / v0.15 (never v0.15.0) |
| Development branch | agent/round6-long-text-streaming |
| Round 5.2 base commit | 7a416df66a79218d73214084d4bf8a733268d894 |
| Round 5.2 base tree | 63db7b7cb14a636f5ba9ff4453be4ebeef170b68 |
| Historical Round 5.2 Linux amd64 SO SHA-256 | e859d4882f14ec180cbbe80a1a497ae3cd79d688668e0974f17f91b750e6d5ec |
| Passed pre-version-migration checkpoint | 21ceb57e6b6030e56d7820c9a67a8eecd068c669 |
| Checkpoint tree | e55437442f30bdb1b6b748b9611c6760172784cd |
| Checkpoint CI | Push 29578024185 PASS; PR 29578025961 PASS; not final v0.15 evidence |
| Final v0.15 candidate commit | **PENDING - exact post-merge `main` commit after final PR CI and merge** |
| Final v0.15 candidate tree | **PENDING - post-merge `main` push CI, build metadata, and candidate manifest must agree** |
| Candidate artifact hashes | **PENDING - private untagged clean-candidate Actions run only** |
| Scanner identity | streaming-scanner-v1 |
| Historical v0.15 classifier policy | classifier-policy-v5 |
| Historical v0.15 classifier policy SHA-256 | 0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b |
| YAML ruleset | 1.0.7 |
| YAML ruleset SHA-256 | 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134 |
| Audit schema | v3 |

The final v0.15 candidate commit and tree are deliberately not guessed here. A
source file cannot reliably self-reference the future merged commit that
contains it. Final handoff must record the final PR head and PR CI, the actual
merge result on `main`, the exact post-merge main push CI, and the identities in
`build-metadata.json` and `candidate-manifest.json`. The candidate commit/tree
is the post-merge `main` identity, and all candidate records must agree with it.
The `21ceb57` checkpoint proves the pre-migration implementation state, not the
later v0.15 candidate identity.

Future Host/audit PASS hashes, merge identity, tag state, and Release state are
external attestation fields and are intentionally not backfilled into this
reusable source document. Stable v0.15 eligibility must be read from the Round 6
and formal attestation assets that bind the final source and candidate bytes.
The neutral source policy is [RELEASE_POLICY.md](RELEASE_POLICY.md); the external
decision assets are `round6-prerelease-attestation.json` and
`formal-release-attestation.json`.

The historical v10 result remains CONSUMED / FAIL. It is not rerun by Round 6,
Round 6 engineering work does not convert it into a release PASS, and it is not
accepted as a formal-build input.

## 4. Root cause and security objective

Round 5.2 overloaded max_scan_bytes as both a raw JSON prefix bound and a
cumulative classifier-text bound. A valid request larger than 256 KiB could be
parsed from only the leading prefix, become incomplete before later
model-visible text reached classification, and then be allowed by balanced
according to the incomplete-mode contract.

The fix separates four concepts:

1. the complete raw envelope visible through the CPA RPC boundary;
2. the retained classifier window;
3. cumulative model-visible text coverage;
4. bounded classification work.

The security objective is complete inspection of supported, valid, CPA-visible
long requests within those explicit bounds without changing the documented
malformed/unknown/incomplete disposition contract.

## 5. Implemented architecture

The production Router now creates a bounded classifier ScanSession and calls
the streaming request entry points. It does not slice the request body by
MaxScanBytes.

~~~text
complete CPA-visible envelope traversal
  -> bounded transactional shadow plan and raw text spans
  -> media / metadata / tool-schema / role decision
  -> incremental JSON-string or multipart UTF-8 replay
  -> bounded classifier windows plus derived overlap/carry
  -> one disposition decision
  -> local self-route block or allow/observe/audit
~~~

Important properties:

- long prompt strings are referenced by bounded raw spans instead of copied
  into the structural plan;
- JSON escapes, surrogate pairs, and UTF-8 boundaries are replayed
  incrementally;
- oversized Base64 candidates are validated and incrementally decoded with
  constant memory for a full-stream printable-text signal, so a binary prefix
  cannot hide a later encoded instruction and a malformed suffix cannot erase
  a previously proven strong printable Base64 prefix;
- one logical field retains only fixed-size classifier signal facts; when
  actionable evidence exists only after two or more windows contribute distinct
  risk ingredients, the result becomes classifier-window incomplete rather
  than being mislabeled complete and clean;
- logical field boundaries remain distinct from internal classifier chunks;
- every actual UTF-8-safe emitted chunk rechecks the classification-chunk hard
  limit, including cases where rune boundaries require more chunks than the
  initial byte estimate;
- media classification is transactional, including marker-last objects;
- metadata and unapproved fields do not become prompt text;
- CPA-transformed OpenAI image multipart JSON has a dedicated top-level
  allowlist planner; approved 270 KiB and 1 MiB prompts use raw spans and
  streaming limits instead of legacy `MaxScanBytes`/multipart part limits;
- transformed unknown fields or non-string prompts abort before replay, while
  transformed file fields remain opaque and fixed incomplete categories are
  preserved for binary controls and oversized encoded derived views;
- tool definitions, tool payloads, and provider-native message shapes remain
  inspectable;
- RoleUnknown keeps unknown schema/role text distinct from proven user text;
- role ambiguity aborts provisional classification and becomes incomplete;
- different roles and unrelated fields are not joined as one prompt;
- assistant/system quoted safety examples remain provisional until a real
  closing delimiter appears; an unclosed field commits its bounded provisional
  result as ordinary content instead of becoming incomplete or silently safe;
- classifier overlap and proof state are bounded and do not retain the complete
  request.

The compact shadow planner now:

- collapses arbitrary long or unique keys to fixed representatives unless their
  closed semantic identity is required;
- maps role, type, MIME, and approved tool-control values to closed
  representatives;
- emits no text span for metadata strings;
- uses short base-36 span markers;
- remains bounded by JSON token, node, depth, and logical-field limits.

This closes the earlier caller-controlled raw-key/value retention concern. A
residual remains: structural indexes, decoder state, maps, and span metadata
still grow with token/node and logical-field counts. That growth is bounded
rather than constant and must be measured on Linux at the largest accepted
envelope.

## 6. Configuration migration

~~~yaml
# Deprecated compatibility alias; now selects the text window.
max_scan_bytes: 262144

# Optional explicit replacement, 16384..1048576.
# max_text_window_bytes: 262144

# Cumulative model-visible decoded text, maximum 8 MiB.
max_total_text_bytes: 8388608

# Optional explicit work bound; otherwise computed with a floor of 2048.
# max_classification_chunks: 2048

# Counts logical fields, not internal streaming chunks.
max_text_parts: 512
~~~

Compatibility rules:

- if max_text_window_bytes is absent, max_scan_bytes is its alias;
- alias values below 16 KiB or above 1 MiB are clamped for the retained window;
- conflicting explicit alias/window values are rejected;
- max_total_text_bytes must be at least the window and no more than 8 MiB;
- an explicit classification-chunk limit must cover the configured text and
  logical-field limits;
- text_bytes_scanned_total is cumulative and may exceed max_scan_bytes.

Management status exposes the effective limits and migration source. Full
details are in [ROUND6_CONFIG_MIGRATION.md](ROUND6_CONFIG_MIGRATION.md).

## 7. Completeness and disposition

Envelope and text coverage are independent. The classifier reports complete,
budget_exhausted, or unavailable with a fixed reason.

If either the envelope or model-visible text coverage is incomplete, the Router
clears partial category, risk score, rule IDs, evidence, behavior graph, and
finding confidence before policy or subject-state evaluation.

| Mode | Incomplete result |
|---|---|
| off | allow |
| observe | allow + observe |
| audit | allow + audit |
| balanced | allow + audit |
| strict | local block + audit |

Incomplete results do not update rolling subject risk.

The optional verified-local-hard-finding exception is not enabled in this
candidate. verified_hard_finding_enabled is false, and
verified_hard_block_under_incomplete is expected to remain zero.

## 8. Long-text and protocol test inventory

The worktree contains an explicit Linux size ladder:

~~~text
64 KiB
255 KiB
256 KiB
256 KiB + 1
270 KiB
512 KiB
1 MiB
4 MiB
near the effective CPA RPC envelope limit
~~~

For each tier, TestRound6LinuxLongTextSizeLadderCompleteCoverage covers benign
text plus malicious synthetic canaries at start, middle, and end and asserts
exact complete coverage. Separate tests cover cross-window proof,
cross-window negation, metadata before/after content, provider profiles, raw
multipart, transformed-multipart JSON, tool surfaces, role separation, and
pre-route local blocking. The transformed-multipart matrix covers benign and
malicious 270 KiB/1 MiB prompts, start/middle/end placement, and metadata before
or after the prompt.

Additional public regressions cover split core/qualifier evidence inside one
logical field, negated and field-isolated controls, a binary Base64 prefix with
a late printable canary, malformed Base64 trailing junk/padding, UTF-8
chunk-count underestimation, unclosed assistant/system safety quotes in the same
or later window, exact/cross-window boundaries, genuine closed quoted refusals,
and malicious suffixes after a close.

The source also contains:

- FuzzRound6JSONStringChunkDecoderMatchesStdlib;
- FuzzRound6StreamingChunkAndRoleBoundaries;
- TestRound6NormalizeBytesMatchesStringNormalization;
- TestRound6NormalizeBytesRejectsInvalidUTF8;
- BenchmarkRound6ScanLongJSON with 64 KiB, 270 KiB, 1 MiB, 4 MiB, and
  near-8-MiB ordinary/key-rich/semantic-rich cases;
- BenchmarkRound6StreamingScale for classifier scaling.

These names prove that test code exists. The `21ceb57` push/PR checkpoint passed
its Linux CI, but it predates the v0.15 version/release-chain migration and is
not the final candidate result. Authoritative final v0.15 unit, race, fuzz,
benchmark, allocation, RSS, and concurrency evidence remains **PENDING LINUX
CI**.

The public CI path must use the Round 6 allowlist and must not replace it with
broad ./... commands because consumed evaluation packages are intentionally
isolated behind the consumed_evaluation build tag.

## 9. CPA compatibility and Host matrix

| Target | Identity | Source/compile result | Real Host result |
|---|---|---|---|
| Current release target | CPA v7.2.95 / f71ec0eb6776854457892452cf28c47f0d658251 | v7.2.95 final PR-head rerun PENDING; historical `21ceb57` passed only an older latest-source lane | **NOT RUN / PENDING** |

Earlier v7.2.85/v7.2.84/v7.2.83/v7.2.82/v7.2.81 source/compile profiles are historical non-gating
engineering evidence. They are not current v0.15 Host or release requirements.

The required Host evidence must use the private untagged clean-candidate Linux
amd64 `.so`, an
isolated CPA Host, a Mock upstream, no real auth pool, and no real Provider.
The v7.2.95 Host evidence record and the independent audit must cite the same
candidate workflow run ID, commit, tree, and SO SHA-256. The candidate manifest
binds those values before any tag exists. If an optional blocked development
prerelease is later needed, its workflow must bind the same successful candidate
run, rebuild byte-identical clean artifacts, and recheck the expected SO hash
before and after transfer. For
every locally blocked request the Host evidence must record before/after zero
deltas for:

1. Auth Selector;
2. Provider execution;
3. usage accounting;
4. Mock-upstream requests.

It must also prove plugin loading, registration, Router ordering, executor
readiness, supported source formats, stream and non-stream routes, audit
privacy, and rollback.

None of that real Host evidence exists yet. Source/compile checks cannot replace
it.

## 10. Resource and performance status

Resource controls include:

- raw visible envelope: 8 MiB;
- text window: 16 KiB to 1 MiB;
- total model-visible text: no more than 8 MiB;
- logical text fields and classification chunks: computed and hard bounded;
- JSON token, node, and depth limits;
- bounded decoding layers, variants, source bytes, and retained decoded bytes;
- no Guard-created temporary prompt file;
- no prompt text in metrics labels, audit rows, or logs.

Dense encoded derived views remain an intentional limitation. The ordinary
model-visible source text is streamed, but a dense encoded value whose derived
inspection requires more than 128 KiB of encoded source, or exceeds the 64 KiB
aggregate retained decoded-text bound, is marked incomplete. It is not reported
as fully covered.

The `21ceb57` CI checkpoint passed before the version migration. Final v0.15
CPU/op, B/op, allocations/op, peak RSS, concurrent throughput, and
reproducibility numbers are **PENDING LINUX CI**. Development-machine
diagnostics are excluded from final evidence.

## 11. Audit, management, and privacy

Audit schema v3 adds decision, coverage, incomplete_reason, and scanner.
A synthetic shape, without request text, is:

~~~json
{
  "action": "audit",
  "mode": "balanced",
  "decision": "allow_due_to_incomplete_inspection",
  "coverage": "incomplete",
  "incomplete_reason": "total_text_limit",
  "scanner": "streaming-scanner-v1",
  "text_bytes_scanned": 8388608
}
~~~

Actual events also use one-way request/model correlation values and fixed
source-format enums. The schema cannot represent a request body, prompt,
header, plaintext credential, or arbitrary metadata.

Management status exposes policy identity, scanner identity, required overlap,
verified_hard_finding_enabled=false, effective limits, migration mode, and
fixed low-cardinality coverage/exhaustion counters.

SQLite migration to schema v3 requires a privacy check and, when configured, a
pre-migration backup. An older binary must not open a v3 database as though it
were v2.

## 12. Known limitations and residual risk

- CPA v7.2.95 real Host behavior is unverified.
- Linux race, fuzz duration, benchmark, allocation, RSS, and reproducibility
  evidence is not yet attached to the final source identity.
- The Linux build script now audits complete `readelf --version-info` tags,
  rejects non-numeric GLIBC ABI tags and numeric versions above 2.34, but the
  authoritative result still belongs to exact-source Linux CI.
- Dense encoded derived views beyond the bounded decoding budget are
  incomplete.
- The legacy ExtractText API still materializes Parts and preserves its old
  part-splitting and compatibility-limit semantics. Production routing uses the
  streaming APIs instead.
- Shadow/index memory is compressed but still scales with bounded structural
  complexity.
- RPC representation overhead means the largest accepted model body can be
  smaller than 8 MiB. Host evidence must record the accepted boundary.
- Opaque media bytes are not inspected.
- Host loading, Router fuse/error behavior, Router priority, duplicate
  libraries, and executor readiness can still create fail-open conditions
  outside plugin-internal status.
- A candidate-bound external `evaluation-v11` or later first-and-only
  `CONSUMED / PASS` attestation is still required for any formal decision.

See [ROUND6_LIMITATIONS.md](ROUND6_LIMITATIONS.md).

## 13. Restricted-data and production disclosure

This round cannot truthfully claim complete zero contact with every restricted
source path:

1. One over-broad source-name search unintentionally printed two lines from
   cmd/holdout-fixtures/main.go and references to evaluation author source. It
   did not open or execute a corpus, private payload, or production data.
2. Eleven evaluation/Holdout gate test files were mechanically given the
   //go:build consumed_evaluation header. For two external-package files, only
   the package declaration was queried. Their bodies and fixtures were not
   printed or executed.

No evaluation-v10 corpus content, retired Holdout payload, private prompt
payload, production request, production audit row, credential, token, HMAC key,
or real account data was read. None of that data was used for tuning,
implementation, test canaries, documentation conclusions, or performance
claims.

Formal source and audit bundles must exclude all evaluation, Holdout, private,
blind, and retired material. Only the low-sensitivity external evaluation ID and
report SHA-256 recorded in `round6-prerelease-attestation.json` may cross the
release boundary. Historical evaluation-v10 is not a bundle input.

The four public adversarial repositories were treated only as untrusted
defensive context. Their original payloads were not executed or replayed.

No production Host was logged into or modified. No production observe
configuration was changed, and no real Provider or account pool was contacted.

Historical disclosure from earlier rounds remains in the historical audit
documents and is not erased by this Round 6 statement.

## 14. Review status

- Development-time manual static inspection is not an independent approval.
- The final PR head must have no unresolved, non-outdated actionable review
  threads before merge.
- Automated review is advisory; no remote or independent approval is claimed.
- A clean automated review is not an independent source/artifact/Host audit.
- Leo or another independent auditor has not reviewed the frozen Round 6
  source, Linux artifact, or Host evidence.
- The final `publish` job references the GitHub Environment
  round6-independent-audit. Repository settings must configure required
  independent reviewers; the YAML reference alone is not independent approval.
- Repository settings must enforce a Round 6 release-tag ruleset that prohibits
  both modification and deletion, with no release participant allowed to bypass
  it. The workflow's peeled-tag recheck does not replace immutable tag policy.

Status therefore remains **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**.

## 15. Rollback plan

No Round 6 deployment has occurred. Before merge, repository rollback means
abandoning the development branch after preserving required audit evidence and
leaving `main` unchanged. After merge, rollback must use a normal reviewed
revert PR against `main`; never rewrite shared history, move a release tag, or
delete evidence needed to explain the reverted candidate.

For the authorized Linux sandbox only:

1. Before loading the candidate, record the CPA identity, existing plugin
   archive/SO hash, configuration hash, plugin mode, and audit directory.
2. Preserve the previous known artifact and configuration outside the candidate
   install path.
3. If schema v3 migration will be exercised, create and verify the configured
   pre-v3 SQLite backup without exposing audit contents.
4. On rollback, stop or reload the isolated Host according to CPA operations,
   restore the previous plugin artifact and configuration, and either restore
   the pre-v3 database backup or use a fresh audit directory.
5. Never let an older binary open the v3 database as v2.
6. Restart only against Mock components, then verify plugin version/hash,
   Router order, mode, health, and zero real-upstream connectivity.
7. Preserve low-sensitivity before/after results and hashes for the independent
   auditor.

These steps were not run against production and are not authorization to do so.
Production mode must not change from observe to balanced without a later
independent PASS and a new explicit user decision.

## 16. Remaining release gates

| Gate | Status |
|---|---|
| Pre-version checkpoint `21ceb57` push/PR CI | **PASS; not final v0.15 evidence** |
| Final PR head commit/tree frozen after version migration | Pending |
| Final PR-head PR CI | Pending |
| Merge final PR to `main` | Pending; candidate-generation prerequisite, not release approval |
| Exact post-merge `main` push CI | Pending; must bind the candidate commit/tree |
| Candidate dispatch from `refs/heads/main` | **NOT RUN / PENDING** |
| Private untagged clean-candidate Actions artifact | **NOT CREATED / PENDING** |
| Candidate manifest and clean SO/Store ZIP hashes | **PENDING** |
| CPA v7.2.95 official SO + Host + Mock matrix | **NOT RUN** |
| Four-layer zero-call proof | **NOT RUN** |
| SQLite v3 migration, privacy canary, quick-check, and rollback | **NOT RUN** |
| Independent source/artifact/Host audit | **NOT RUN** |
| GitHub Environment round6-independent-audit with required independent reviewers | Repository-side configuration required; not evidenced here |
| Round 6 release-tag ruleset prohibits tag modification and deletion | Repository-side configuration required; not evidenced here |
| Candidate-bound external evaluation-v11 or later | **NOT RUN**; must be first-and-only `CONSUMED / PASS`; v10 remains immutable FAIL |
| Optional annotated `v0.15-dev.round6[.N]` draft prerelease | Not created; blocked until Host/audit and candidate-bound evaluation PASS |
| `round6-prerelease-attestation.json` | External asset; not created / pending |
| Annotated formal `v0.15` tag and draft Release | Not created; blocked |
| `formal-release-attestation.json` | External asset; not created / pending |
| Protected promotion of unchanged formal draft | Not run; blocked |
| Production deployment or mode change | Prohibited |

The release chain in [ROUND6_RELEASE_GATE.md](ROUND6_RELEASE_GATE.md) must be
followed in order: final PR head and PR CI, merge to `main`, exact post-merge
main push CI, clean-candidate dispatch from `refs/heads/main`, Host and
independent evidence, candidate-bound external evaluation-v11+ `CONSUMED /
PASS`, optional annotated development prerelease, annotated formal `v0.15`
draft, then protected promotion.

## 17. Handoff summary

~~~text
Status: BLOCKED
Project version: 0.15
Formal tag: v0.15 (never v0.15.0)
Reason: final v0.15 candidate, CPA v7.2.95 Host, independent audit, and candidate-bound evaluation-v11+ PASS are pending
Base commit: 7a416df66a79218d73214084d4bf8a733268d894
Base tree: 63db7b7cb14a636f5ba9ff4453be4ebeef170b68
Pre-version checkpoint: 21ceb57e6b6030e56d7820c9a67a8eecd068c669 / push+PR CI PASS / not final v0.15 evidence
Final PR head and PR CI: PENDING AFTER VERSION MIGRATION
Merged to main: NO / PENDING CANDIDATE-GENERATION PREREQUISITE
Post-merge main push CI: PENDING
Candidate commit: PENDING EXACT POST-MERGE MAIN COMMIT
Candidate tree: PENDING POST-MERGE MAIN CI / BUILD METADATA / CANDIDATE MANIFEST
Candidate artifact: PRIVATE UNTAGGED CLEAN ACTIONS ARTIFACT / NOT CREATED / PENDING
Platform: Linux amd64 only
Streaming scanner identity: streaming-scanner-v1
Historical v0.15 classifier policy: classifier-policy-v5
Historical v0.15 classifier policy SHA-256: 0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b
CPA v7.2.95 Host result: NOT RUN / PENDING
Long-text Linux size ladder result: PENDING FINAL PR / POST-MERGE MAIN LINUX CI
Cross-window result: PENDING FINAL PR / POST-MERGE MAIN LINUX CI
Race/fuzz/benchmark/RSS result: PENDING FINAL PR / POST-MERGE MAIN LINUX CI
Independent review: NOT RUN / PENDING
Candidate-bound evaluation-v11+ result: NOT RUN / PENDING / requires CONSUMED PASS
Round6 prerelease attestation: NOT CREATED / PENDING
Formal release attestation: NOT CREATED / PENDING
CodeRabbit: LOCAL AUTOMATED REVIEW COMPLETED / ADVISORY ONLY / NOT INDEPENDENT APPROVAL
Historical v10: CONSUMED / FAIL / immutable / not a formal input
Formal bundle restricted content: evaluation/holdout/private/blind/retired excluded
Round 6 Release: NOT CREATED
Production touched: NO
Final status: BLOCKED / PENDING HOST AND INDEPENDENT AUDIT
~~~
