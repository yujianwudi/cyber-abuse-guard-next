# Known Limitations — v1.0.0-rc.1 candidate

> [!IMPORTANT]
> The active Round 13 boundary is Linux amd64, source `1.0.0`, planned
> `v1.0.0-rc.1`, and CPA
> `v7.2.125@2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e`. The Round 12 evidence
> table below remains historical and non-transferable; current gate status is
> tracked in [ROUND13_STATUS.md](ROUND13_STATUS.md).

```text
current_classifier_policy_version: classifier-policy-v19
current_classifier_policy_sha256: b9ee45401a50ae5c6fafa80d219e8f47e726bdfe15b5fc7838a96edd095460a1
```

Last updated: 2026-08-11 (Asia/Shanghai)

## Current Round 13 evidence boundary

The active Linux amd64 target is CAG source `1.0.0`, planned prerelease
`v1.0.0-rc.1`, and CPA
`v7.2.125@2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e` with C ABI 1 / RPC schema 2.
The CPA module sum is `h1:jz3yxTI7mp+ej2kI1T4OPs+QhIgP6Mmu5BGvipjQWRg=`, the go.mod sum is
`h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=`, the official archive
SHA-256 is `4e940b7dc5bdf867b5c58ca30f1b368fae6dc2e041e8a351d5c2c07f3f610233`,
and the binary SHA-256 is
`656cde7bfd966dbcaaa9d9260dd1de75716c0b9dead66d91ceb2d8d55f6d623a`.
GitHub's current upstream latest is `v7.2.127`, but Round 13 remains deliberately
frozen to v7.2.125. No later-version compatibility or runtime evidence is
inferred.

The current five-repository source policy SHA-256 is
`516a5aac90676cb079466ed2bb795f2683d88f859d5e11d283d089cb2d17de87`.
It reviews Keysmith at commit
`b2b87df296f96f3d4049cadd82fd61c9a6a34595` / tree
`98cf7431b1d1a3d189930dd9929c12c756f032ea` and Codex-X at commit
`826a142fc040920a5c23c3dafabbfc8d21655478` / tree
`95e2638756c97b844179a905513d41ea2e8aea0e`. Their five selected blobs are
byte-identical to the preceding review. A fresh read-only GitHub acquisition
validated 5 repositories, 11 selected text sources, and 19 semantic cases
without executing third-party code, then removed the ephemeral text.

| Evidence boundary | Current Round 13 status |
|---|---|
| Pinned CPA source/compile contract and audit-harness unit suite | `DIRTY_WORKTREE PASS / 244_OF_244 / NOT_FINAL_CANDIDATE` |
| no-copy, `response.failed`, Codex `Originator`, and Claude replay source/test coverage | `PASS / DIRTY_WORKTREE_NATIVE_HOST_PASS / FINAL_CANDIDATE_PENDING` |
| Dirty-worktree Linux unit, race, full script matrix, and root-isolated CPA Host/Router matrix | `PASS / NO_DATA_RACE / NOT_FINAL_CANDIDATE`; Host functional evidence only, not Host latency/RSS |
| Exact-candidate Linux native Host, required GitHub checks, race, and full matrix | `NOT_RUN / PENDING` |
| Local in-process performance | `CLASSIFIER-POLICY-V18 DIRTY_WORKTREE SOURCE-ONLY PASS / JSON adaeab59...a80d`; ordinary c16 p95 `2.012662 ms`; five-repository surrogate p95 `108.288998 ms`; Codex-all p95 `46.827635 ms`; public p95/p99 `8.728750/9.440184 ms`; SQLite c16 p95 `2.549483 ms`, queue max `30/256`; 2,304 operations with zero failures/panics; CPA Host overhead, RSS, paired throughput, and production SLO remain `NOT_PROVIDED` |
| Local development corpus | malicious recall `154/154`; benign audit hits `3/142`; local-only and not a second-machine false-positive result |
| Local CodeRabbit | final v18 review iterations complete; 2 valid findings fixed; 3 stale findings disproved against current source; 0 open valid findings; pushed-head GitHub CodeRabbit remains pending |
| Pre-merge and post-main second-machine executions | `NOT_RUN` |
| Protected Host and independent attestation | `NOT_PROVIDED` |
| Post-main release admission | `NOT_RUN` |
| Tag and GitHub Release | `NOT_CREATED` |
| Production approval | `NOT_PROVIDED` |

No dirty-worktree source, unit, race, surrogate-performance, or local Host
result closes exact-candidate GitHub/Host, second-machine, independent-audit,
release, or production gates. Current status is maintained in
[ROUND13_STATUS.md](ROUND13_STATUS.md).

## Frozen historical Round 12 evidence boundary

The remainder of this document preserves the Round 12 / CPA v7.2.124
point-in-time limitation record. Its uses of "current", RT12 lane names, and
v0.16 identities are scoped only to that frozen historical section and must not
be used as active Round 13 guidance.

Round 12 starts from exact
`main@21267e742b624b29a75bd3683fd6914f76c764b5`, and now targets CPA v7.2.124 at
`197f520426374e514218ed155933ac546c98d345` with
Go 1.26.4 on Linux amd64, and ends with a gated PR merge rather than a tag or
Release. The following evidence classes are independent and must not be
collapsed into a generic "Host," "second machine," or "counted-Mock" claim.
The table below and [Round 12 status](ROUND12_STATUS.md) define the current
v7.2.124 boundary; v7.2.116 results inside them are historical evidence only.

| Evidence boundary | Current status |
|---|---|
| Historical exact baseline GitHub engineering checks | `PASS / HISTORICAL_V7.2.116_EXACT_MAIN_ONLY`; five required contexts for `main@21267e7`; does not transfer to v7.2.124 |
| Round 12 v7.2.124 working/final candidate GitHub checks | `PENDING_FINAL_CANDIDATE`; historical baseline PASS does not transfer |
| Historical supplied CPA v7.2.116 1,320-transport second-machine report | `HISTORICAL_ONLY / DIAGNOSTIC_ONLY / NOT_FINAL_CANDIDATE / NOT_INDEPENDENT_ATTESTATION` |
| RT12-05/06 exact-v7.2.124 final-candidate second-machine run | `PENDING_FINAL_CANDIDATE_EXECUTION` |
| Multi-Agent v2 `/v1/responses` pre-interceptor tool-definition rewrite | `PENDING_EXACT_V7.2.124_REGRESSION`; historical v7.2.116 CI, second-machine, and five-repository data are non-transferable |
| Protected Host / external evaluation | `NOT_PROVIDED` |
| Independent attestation | `NOT_PROVIDED` |
| Production approval / release readiness | `NOT_PROVIDED`; no tag or Release is authorized |

Historical local Host results used generated Linux amd64 development bytes,
loopback fixtures, and a Mock upstream. They remain non-transferable. The owner-
run input diagnostic also cannot substitute for the pending final-candidate
RT12-05/06 evidence. This repository work did not inspect production. No source,
unit, compatibility, Docker-runner, development-corpus, baseline CI, or input
diagnostic result can close the protected, independent, production, or release
boundaries.

1. **No guarantee against account action.** The plugin reduces the number of
   clearly risky requests that reach upstream. It cannot guarantee that an
   account will never be warned, rate-limited, suspended, or deactivated.

2. **The Round 12 candidate is not final or production-approved.** The current
   source version is `0.16`, but Round 12 does not create an RC, stable tag, or
   GitHub Release. Stable `v0.16` does not exist. Final-candidate exact GitHub
   checks, RT12-05/06 second-machine execution, protected Host evidence, and
   external admission remain required. Independent attestation and production
   approval are not provided by this round. The local `v0.16-rc.1`
   package, Round 8 `v0.16-rc.2` identity, failed Phase 1 `v0.16-rc.3` identity,
   and Round 5/6 v0.15 evidence are immutable historical records and cannot be
   moved, overwritten, or relabeled as current Round 12 output.

3. **Deterministic language rules are imperfect.** Novel phrasing, languages,
   slang, semantic indirection, encrypted content, unknown encodings, and
   sufficiently adversarial obfuscation may evade detection. False positives
   and false negatives remain possible.

4. **Decoding is intentionally bounded.** URL escapes, HTML entities,
   inspectable Base64, textual data URLs, JSON escapes, and nested tool JSON are
   limited to two decode layers, eight variants, 128 KiB source, and 64 KiB
   retained decoded text. The plugin does not decompress, expand archives, or
   parse arbitrary documents. An incomplete recognized text envelope follows
   the fixed incomplete-inspection mode contract. Strings with an unknown
   encoding shape or high entropy are scanned literally when their schema and
   role provenance remain supported, and are not blocked solely because they
   appear encoded. This does not make arbitrarily long `RoleUnknown` fields
   exactly reconstructable across fields; bounded streaming proof loss may
   instead yield `classifier_window_incomplete`. Encrypted or novel encodings
   can therefore still evade semantic detection.

5. **Opaque media is not inspected.** Image/audio/video/document-attachment
   bytes and their meaning are unavailable to the classifier. The plugin never fetches HTTPS media
   URLs. Mode-aware defaults audit opaque media in Observe/Audit/Balanced and
   block it in Strict; operators may explicitly choose `block`, `audit`, or
   `allow`. `allow` is uninspected pass-through, not a safety determination.

6. **Truncated content cannot be fully classified.** Inputs beyond byte, part,
   depth, segment, native RPC, or decode budgets are marked incomplete.
   Balanced allows and audits incomplete inspection; Strict self-routes and
   blocks for the fixed incomplete reason. Neither mode may enforce a partial
   classification or update subject risk from a prefix. A no-copy oversized RPC
   event cannot include a request hash, model, source format, or body-derived
   byte count because the body is not copied into Go.
   Inert quoted-review credit is likewise available only when the single quote,
   unsafe assessment, and final non-execution boundary are all visible in one
   complete classification view. A later bare affirmative referential directive
   is linked only to the newest eligible trusted RoleUser review and reclassifies
   only that quote. Historical assistant/system/tool/unknown reviews, tool
   schemas, and assistant tool-call arguments cannot seed that referent;
   questions, explanations, negation, consequences, and remediation do not
   establish execution intent. An explicit current-user harmful restatement is
   evaluated independently. A current request-local system/developer instruction
   or terminal tool result may still block only its own independently complete
   candidate, without historical referent promotion. Complete long reviews
   retain only a privacy-safe result, never quoted text. Truncation or
   cross-window proof loss receives no quoted-review credit and yields
   `CoverageUnavailable` / `classifier_window_incomplete`; insufficient
   reclassification budget yields `classification_chunk_limit`.
   The accepted lead-ins are exact enumerated English templates, not a general
   natural-language intent model. A multipart request receives the optional
   prior-history proof only for at most 8 prior parts totaling at most 32 KiB;
   larger histories fail closed without running a second large streaming scan.

7. **Role provenance is bounded, not universal.** Standard OpenAI, Anthropic,
   and Gemini envelopes use role-aware segments. Unsupported explicit roles and
   over-capacity histories are conservative in enforcing modes. Vendor-specific
   quotation/provenance extensions and deliberately split non-adjacent evidence
   can remain outside the deterministic follow-up window.

   Round 9 source adds candidate-bound eligibility, occurrence ownership, and
   active-directive boundaries, but this
   is still a deterministic bounded parser rather than unrestricted natural-
   language understanding. An unusual but valid explicit referent may be missed,
   while a sufficiently ambiguous directive may remain audit-only.

   Provider-native tool authority is deliberately narrower than every valid
   Host conversation. In particular, a Responses request containing only
   `previous_response_id` and a function/custom output cannot be elevated: the
   plugin cannot independently verify the Host session, pending call, consumed
   state, or replay status. Gemini ID-free results are elevated only for one
   complete adjacent terminal transaction whose calls and results have equal
   cardinality and match by name+ordinal. These restrictions may leave some
   legitimate continuation outputs audit-only, but prevent request-local
   metadata from forging tool authority.

8. **CPA interceptor failures retain host-level fail-open boundaries.** The
   required Host matrix is CPA v7.2.124 with unchanged C ABI 1 and RPC schema 2.
   CPA skips
   an interceptor that returns an RPC error and fuses an interceptor that
   panics across the Host boundary; it may then continue the remaining chain and
   native execution. The plugin returns successful, mode-aware responses for
   known scan failures, shutdown, malformed envelopes, recovered in-process
   panics, and oversized callbacks. Balanced and Strict terminate on operational
   inspection failures; the oversized content-incomplete exception remains
   Strict-only while Balanced preserves its documented allow+audit policy. It cannot
   alter CPA's policy when the binary is absent, registration fails, the Host
   fuses/skips it, or the native callback fails before a valid response is
   accepted. `enforcement_ready` reports only internal plugin state and does not
   prove Host load, registration, interceptor ordering, fuse state, or callback
   delivery. The compatibility field `router_errors` therefore aggregates
   legacy Router and RPC schema 2 RequestInterceptor protocol-path failures;
   watchdog and counter-delta monitoring remain mandatory. Historical dirty
   Host/Router evidence is development-only; the exact-candidate counted-Mock
   matrix is still required.

9. **RequestInterceptor ordering cannot be enumerated in-process.** CPA invokes
   interceptors by priority descending and then plugin ID ascending. A preceding
   interceptor can terminate the chain before Guard inspection or rewrite the
   request Guard receives; an interceptor that runs later can rewrite a request
   after Guard has inspected that stage. Use priority 300, inspect the complete
   deployment inventory and priorities, disable the old
   `antigravity-coding-filter`, and treat any unreviewed request-rewriting plugin
   as outside the admission boundary. A higher-priority legacy schema-1
   ModelRouter alone no longer bypasses ordinary model requests because the
   schema-2 before-auth interceptor still runs before execution. Alpha Search is
   different: CPA v7.2.124 omits RequestInterceptor there, so deployment must
   also ensure no unreviewed higher-priority ModelRouter handles
   `codex-alpha-search` before CAG.

   CPA v7.2.124 Multi-Agent v2 also rewrites `/v1/responses` tool definitions
   before `RequestInterceptor`. The plugin cannot infer the original client-wire
   tool schema from the post-rewrite envelope. Exact-target tests must cover
   recognized/unknown tool definitions, inert tool schemas, tool-call arguments,
   terminal tool-result provenance, budget behavior, and allow/block parity.
   No v7.2.116 result is admissible for that new ordering boundary.

10. **Duplicate plugin binaries cannot be detected in-process.** ABI v1 does
    not expose the plugin directory. The operator must ensure only one
    `cyber-abuse-guard` `.so` version is installed before restart.

11. **403, SSE, Alpha Search, and Router cost are Host-contract tradeoffs.** `ExecutorResponse` has no status
    field. A blocked stream returns a genuine HTTP 403 before SSE is
    established. ABI v1 cannot return both a 403 and a successful terminal SSE
    frame; successful chunks would force HTTP 200. The policy executor routes
    `execute`, `execute_stream`, and `count_tokens` to the same policy HTTP 403;
    `http_request` returns an unsupported-method RPC error whose `StatusCode()`
    is 405; the official adapter returns `(nil, error)`. CPA v7.2.124's two Alpha
    Search routes do not call RequestInterceptor or request lifecycle. CAG's
    format-gated ModelRouter returns a self-target for malicious search, which
    the Alpha handler rejects as HTTP 503 before Codex credential selection or
    upstream execution. Native policy HTTP 403 is therefore unavailable on
    Alpha Search until CPA exposes local termination there; the Linux Host test
    must prove both aliases with an in-memory OAuth auth and a networkless Codex
    probe rather than claiming the ordinary interceptor response shape.
    `ModelRouter` registration is global in CPA v7.2.124, so ordinary requests
    still pay Host-side body cloning, JSON/Base64 serialization, and one Router
    RPC before CAG returns `Handled:false`; the plugin cannot make that work
    O(1). An oversized callback supplies only the method name, not the source
    format, so keeping large Alpha Search fail-closed can cause an oversized
    ordinary request to be counted once by `model.route` and once by
    `request.intercept_before`. Non-strict oversized after-auth remains a
    side-effect-free pass-through to avoid a third count, but Strict records and
    blocks it so a post-before-auth oversized mutation cannot bypass enforcement.
    A timing-window dedupe would create concurrent-request
    mismatches and is not used. Full removal requires a CPA format-scoped Router
    capability or Alpha Search RequestInterceptor support.

12. **Protocol-specific error shapes differ.** OpenAI-compatible handlers can
    retain a stable marker. Anthropic may normalize plugin errors and drop
    custom code/category fields. CPA's executor adapter controls the final
    protocol envelope.

13. **No `Retry-After` on executor errors.** ABI-v1 RPC errors cannot attach
    arbitrary downstream response headers.

14. **Exact management routes only.** CPA v7.2.124 rejects dynamic `:`/`*`
    plugin routes, so subject unblock uses a fixed path and bounded JSON body.
    CPA host middleware, not the plugin, is the Management Key verification
    authority; ABI v1 does not reveal the configured key to the plugin. Host
    401 behavior must be integration-tested. CPA currently executes
    `io.ReadAll` in `ServeManagementHTTP` before calling the plugin, so the
    plugin's 1 MiB body and 2 MiB RPC-envelope limits are not a host HTTP memory
    ceiling. Deployments need an upstream body limit such as Nginx
    `client_max_body_size 1m`, with a server test proving HTTP 413 occurs before
    CPA receives the request.

15. **No trustworthy remote address in `RequestInterceptRequest`.** CPA exposes
    neither a verified direct peer nor a separate authenticated principal/key
    policy ID. `trusted_proxy.enabled: true` is rejected; forwarded headers are
    not trusted. Subjects are HMACed from the authenticated downstream key or
    use an anonymous bucket.

16. **No external/local model classifier.** The configuration shape is
    reserved, but `classifier.enabled: true` is rejected. The plugin makes no
    classifier network request and does not upload prompts to a third party.

17. **No authenticated management UI.** CPA v7.2.124 resource routes are not a
    safe place for audit/subject data. This version exposes exact authenticated
    management API routes only.

18. **No external rule override.** Rules remain embedded for deterministic,
    auditable builds. Signed external rules, path constraints, atomic rollback,
    and license metadata require a later version. No rule is downloaded at
    runtime.

19. **No challenge workflow.** Strict mode blocks. ABI v1 and this release do
    not define a portable challenge/approval state machine.

20. **HMAC dual-key rotation is not implemented.** Changing the key breaks
    correlation with stored subject IDs. A future active/previous-key design is
    documented, but v0.15 accepts one active key. Preserve the current key for
    normal upgrades or explicitly treat the change as a state reset.

21. **Subject persistence is optional, not universal.** With persistence off
    (the default), restart clears risk, cooldown, and manual blocks. With it on,
    a stable HMAC key, audit DB, and `max_subjects <= 10000` are required. A key
    mismatch blocks persistence writes and reports degradation; the operator
    must deliberately retain, archive, or reset the old snapshot.

22. **Persisted-state completeness is not cryptographically authenticated.**
    The loader rejects malformed types, hashes, rows, versions, and key
    mismatches, but schema v2 has no keyed whole-snapshot MAC. An actor who can
    write the SQLite file can delete otherwise valid subject rows without that
    deletion being distinguishable from a legitimate smaller snapshot. Keep
    the DB below a trusted, non-writable path and treat local DB writers as
    trusted for persistence completeness.

23. **Schema downgrade is not promised.** v0.15 migrates supported legacy event
    databases to schema v3 atomically and can create bounded pre-migration
    backups. Older binaries are not claimed to understand schema v3. A full rollback should restore the
    matching pre-migration database backup. Before publishing a backup or
    migrating, legacy `request_hash`, `subject_hash`, `model`, and
    `source_format` must already satisfy digest/fixed-provider privacy contracts.
    A nonconforming value fails closed: no backup is published, no migration
    occurs, and the original DB is retained for operator repair. The plugin does
    not automatically sanitize a legacy plaintext database.

24. **Audit path ancestors are a trust boundary.** The final data directory
    must not be group/world writable; final DB/WAL/SHM symlinks are rejected.
    The plugin does not provide a fully `openat`-anchored walk of every ancestor,
    so do not place `data_dir` below an attacker-controlled path.

25. **Audit availability is not enforcement availability.** SQLite lock,
    permission, queue, migration, or write failures degrade audit/persistence
    while local classification and blocking continue. This avoids making the
    database an availability dependency, but means events may be dropped. Treat
    any degradation as an operational alarm.

26. **Host logging is trusted to return.** Error callbacks are rate-limited,
    panic-contained, and invoked outside store locks. A host logger that blocks
    forever may leave a background finalizer pending even after bounded plugin
    shutdown returns.

27. **Non-Linux secret-file hardening is weaker and unsupported for release.**
    Linux uses `O_NOFOLLOW` and same-descriptor validation. Other targets use a
    weaker fallback and are not release platforms.

28. **Capacity shrink does not immediately compact Go map buckets.** Hot shrink
    evicts logical entries immediately, but heap buckets may remain until later
    garbage collection. The new logical limit is enforced for every request.

29. **Only one platform and one fixed CPA Host target are in scope.** The
    release platform is Linux amd64 with glibc 2.34+; musl/Alpine is unsupported.
    The root module and both current contract modules pin CPA v7.2.124.
    Source/compile success is not runtime admission. Exact-candidate counted-Mock
    Host evidence is required for this target.
    Earlier v7.2.85/v7.2.84/v7.2.83/v7.2.82/v7.2.81 checks are historical and non-gating.
    Windows/macOS checks and source contracts do
    not establish native compatibility.

30. **Final/exact-candidate Round 9 performance evidence is not provided.** The
    current Linux amd64 working-tree development benchmark is no longer in the
    earlier 15-second regression state: the complete post-fix recipe passed and
    `BenchmarkClassifierCandidateRichMaxParts` measured 37.311769-39.621583
    ms/op, 6,622,070-6,624,038 B/op, and 700-706 allocs/op. The explicit
    profiled maximum-parts acceptance test also enforces <=2 s/op, <=16 MiB/op,
    and <=2048 allocs/op. The raw development log is
    `dist/round9-worklogs/round6-benchmark-post-perf-20260724.log` (26441 bytes,
    SHA-256 `ec603a4b437820f579d69340feba76bd63752ab5a63cf63998b6e87873d6c063`).
    This is still not bound to a final commit/tree or exact Linux `.so`.
    Exact-candidate RSS, CPA Host latency, throughput, concurrency, database
    behavior, and counted-Mock runtime performance remain `NOT_PROVIDED`.

31. **Unknown provider shapes are only generically understood.** Strict blocks
    an unknown non-multipart `SourceFormat` before interpretation.
    Balanced/Audit/Observe use a bounded all-nonmetadata-string fallback and
    expose a counter/Watchdog delta, but a future provider may encode semantics
    under fields the generic walker cannot identify. Unknown multipart never
    guesses text fields: every non-file field is schema-incomplete, Balanced
    allows+audits, and Strict blocks for the fixed reason. Every new
    CPA/provider source label still requires compatibility review and an
    explicit canonical mapping.

32. **Prompt-injection detection remains heuristic.** The post-v10
    `META-OVERRIDE-001` overlay requires combinations of reviewed control-plane
    evidence, but cannot guarantee coverage of every persona, hierarchy
    inversion, language, steganographic form, or future jailbreak technique.

33. **Cross-request continuation remains stateless.** The classifier can use
    adjacent segments and history present in the current request body. It does
    not retain prompt fragments or semantic flags across independent API calls;
    callers that omit relevant history can therefore remove context the plugin
    never received.

34. **Local instruction-file and remote-template integrity are outside the
    plugin boundary.** The Router cannot prove the path, owner, mode, allowlist
    membership, hash/signature, or reload history of a local
    `model_instructions_file`, `AGENTS.md`, remote instruction template, or
    other high-priority client configuration loaded before CPA serializes a
    request. The launcher/deployment environment must enforce a path allowlist,
    non-business-user ownership and write restrictions, SHA-256 or signature
    binding, verification at startup and every reload, fixed configuration
    audit, and human-approved remote templates pinned to a commit/hash.

35. **Control-plane signals have no standalone Cyber Abuse taxonomy.** Wrapper-
    only text is allowed or audited and cannot synthesize `defense_evasion` or
    another Cyber Abuse category. When an independent dangerous behavior is
    present, wrapper evidence retains and amplifies that behavior's taxonomy.
    Operators needing a distinct prompt-injection reporting taxonomy must add a
    separate non-Cyber-Abuse control-plane event model in a future version.

36. **An earlier local Host mis-execution is excluded; the later dirty Host run
    is development-only.** An earlier four-protocol harness, real store install,
    zero Auth Selector/Provider/Usage/Mock Upstream counters, Router fixture, and
    proxy-413 fixture were mistakenly executed in WSL using loopback/Mock
    components and cleaned up without residual fixture processes. Those results
    remain excluded. The separate 2026-07-27 CPA v7.2.102 Host/Router PASS is
    retained only for its generated `0.16-dirty` `.so` and cannot become clean
    exact-candidate or release evidence. Earlier CPA and Round 5/8 records are
    frozen historical evidence only. Repository-local counted-Mock, Tencent
    Cloud #2 isolated counted-Mock, and protected external evaluation/one-shot-
    ledger evidence are separately `NOT_PROVIDED`; none can be inferred from
    source compilation or another boundary's result.

37. **Classifier-policy identity is source- and artifact-bound, but still not
    independent approval.** The active source-line identity is
    `classifier-policy-v12` / SHA-256
`2e9d02371c2ff18d6f5efe7765db45517471603ea9d772c73664bf92c7625a5b`,
    and remains pending until bound to the final commit,
    tree, and candidate bytes.
    Build metadata and artifact verification carry it. The historical
    round5.2 value was `classifier-policy-v2` /
    `e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec`,
    and the historical round5.1 value was `classifier-policy-v2` /
    `c2092d0949fcaa1d0f085dfe31a668d45cc4d14efc10427d0f3ebcf3e821a112`.
    Ruleset `1.0.10` separately identifies YAML assets and
    does **not** include the Go-level `META-OVERRIDE-001` overlay, extractor
    semantics, approved tool-schema mappings, or control-plane telemetry. A
    digest test binds the reviewed source list, and authenticated status exposes
    the policy identity. The full Git commit/tree and candidate workflow run
    remain required for provenance.

38. **Provider safety-control semantics are not enforced.** Recognized
    transport/configuration containers such as `safetySettings`,
    `generationConfig`, and generic `options` are not interpreted as model
    policy. The plugin scans model-visible text and tool data; it does not prove
    that a client or CPA configuration kept every provider-side safety option
    enabled. Enforce those controls with a versioned server-side schema
    allowlist and reject or forcibly overwrite unsafe values before routing;
    verify the effective values independently in the owner-operated sandbox.

39. **Key-only tool controls are schema-specific, not globally scanned.** Text
    values inside established tool payloads are scanned recursively. Only an
    explicitly approved, versioned tool schema may map a boolean/numeric/null
    property to a fixed low-cardinality semantic signal; unknown control keys
    in that known schema become fixed `tool_schema` incomplete inspection,
    following the existing Balanced allow+audit / Strict local-block contract
    without classification.
    The fifth-round mapping is activated only by
    `cag_control_schema=meta_override_control/v1` inside established
    tool/tool-payload provenance; the same marker elsewhere is inert. Ordinary
    business JSON property names never become prompt text. Provider
    configuration keys remain a host schema-policy responsibility rather than
    classifier guesses.

40. **The CPA store ZIP is not the audit bundle.**
    `cyber-abuse-guard_<version>_linux_amd64.zip` must contain exactly one root
    `.so`; CPA's official store installer rejects the former nested
    `plugins/linux/amd64/...` layout. Documentation, SBOM, build metadata,
    reports, and operator scripts belong in the separate
    `cyber-abuse-guard-v<version>-audit-bundle.zip`. Historical round5.1 dirty
    versions of these files exist on a blocked development prerelease, but
    neither is an approved stable release artifact. Round 12 runtime evidence
    must use the exact final-candidate commit/tree/SO and name its Tencent Cloud
    #2 diagnostic or protected-external boundary; it cannot use a historical
    Round 5/6/8/9 or v0.16-rc.1 through v0.16-rc.4 asset.

41. **Visible Round 9 development corpora are not independent evidence.** The
    1,200-case development-benign corpus, paired-malicious v3 corpus, and
    `testdata/round9-public-adversarial-v13` are visible to development and may
    prove only their frozen identity, schema, static contracts, and named
    development regressions. The public v13 manifest is 481448 bytes with
    SHA-256
    `91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6`,
    declares `development_only=true`, `independent_holdout=false`, and records
    `third_party_code_executed=false`; all 199 Release assets are metadata-only
    records, and no binary Release asset was downloaded or opened. No case or derived wording may be
    relabeled as independent holdout. The protected independent evaluation is
    separately `NOT_PROVIDED`. The v12 manifest remains immutable history at
    485221 bytes / `eb72fd7b88c052c6af98c97636c18aba96f499597741bcba262dda59de3c2387`;
    v11/v10/v9 and earlier identities also remain frozen history.

42. **Synthetic Store tests cannot close the artifact lifecycle.** Authorized
    CI must require the real `.so`, Store ZIP, metadata, and checksums; use
    `InstallManifest` for first install and Host load; and run
    `TestPublishedStoreArchive` against the same Dist identity for repeat-skip
    and tamper-repair. Missing artifacts must fail rather than falling back to
    synthetic bytes.

43. **JSON media suppression cannot avoid the decoder's initial string
    allocation.** Deferred media candidates have fixed retained bounds and do
    not classify a prefix. Candidate overflow remains complete only if later
    evidence proves media; a final non-media object becomes
    `deferred_text_candidate_limit`. Go's token decoder can still allocate the
    full encoded string transiently before a later member proves that it is
    media. Raw-body limits remain the outer memory control.

44. **Multipart schemas are intentionally incomplete by default.** Only the
    reviewed `openai-image` profile admits `prompt` and `negative_prompt` (plus
    its two bounded spelling variants) as text. Unknown profiles and unknown
    non-file fields become fixed incomplete inspection; adding a future
    provider or field requires source evidence, tests, and a policy-identity
    refresh.

45. **No-tempfile and no-raw-prompt claims stop at the Guard boundary.** The
    extractor and plugin audit do not create temp files or persist prompt/media
    content. CPA request logging can spool non-multipart bodies and can
    persist raw bodies for HTTP error responses. Deployment must separately
    control CPA commercial mode, log directory, retention, and access.

46. **Parser evidence is not Host evidence.** RPC schema 2 exposes the current
    model payload and headers in `RequestInterceptRequest`, not the raw ingress
    socket, route, trusted direct peer, or every handler transformation that ran
    before the callback. CPA handlers can parse, normalize, translate, or rebuild
    a request before either interceptor stage. Unit tests prove only the payload
    delivered to the Guard; they cannot prove ingress boundary/header order,
    CPA reconstruction, pre-SSE termination, or Auth/Provider/Usage/upstream
    side effects. Those claims require the exact CI artifact in the authorized
    isolated Host matrix.

47. **Unit tests and GitHub CI are not production admission.** Passing source,
    unit, race, vet, fuzz, benchmark, privacy, packaging, or reproducibility
    gates shows only that the named command passed on the named commit and
    environment. It cannot replace artifact inspection, repository-local
    counted-Mock, Tencent Cloud #2 isolated counted-Mock, protected external
    evaluation/one-shot-ledger evidence, or independent review, and it cannot
    reverse the frozen v10 failure.

48. **The Round 6 deployment decision is still blocked.** Historical
    `v0.1.2-dev.round5.1` is a prerelease and is not production admission.
    The current source tree cannot self-record future Host/audit PASS hashes,
    merge identity, tag, or Release state. Stable v0.15 eligibility must be
    determined only from external Round 6/formal attestation assets that bind
    the final source and candidate bytes. Host validation, independent
    source/artifact review, and production observation remain separate gates.
    Even after all source and artifact gates
    pass, the strongest permitted status is
    `READY FOR INDEPENDENT SOURCE/ARTIFACT REVIEW`; it is never
    `PRODUCTION APPROVED`.

49. **Role-aware cross-source composition is intentionally incomplete.** To
    avoid treating a system policy example or assistant refusal as user intent,
    the classifier does not combine base Cyber Abuse taxonomy evidence from a
    system/assistant segment with a later user segment. It may combine bounded
    control-plane/meta-override evidence, but high-priority instruction source,
    owner, mode, hash/signature, and reload integrity remain mandatory host
    gates. A compromised high-priority source can therefore create semantics the
    plugin cannot independently authenticate.

50. **Parts and Segments do not yet share one semantic parse product.** The
    primary token walk creates `Parts`; recognized role envelopes then undergo
    a second bounded JSON parse to create `Segments`, reusing the same bounded
    extraction helpers. Differential, race, fuzz, and fifth-round media tests
    have not reproduced a leak, but two parses retain a parser-drift risk. A
    future refactor should emit both views from one immutable semantic result.

51. **The fifth-round restricted-corpus access claim is not clean.** One
    over-broad read-only `git grep` unexpectedly emitted content from restricted
    `testdata/holdout/malicious-operational.jsonl`. No holdout test ran, no
    output was redirected or copied into implementation artifacts, and it was
    not analyzed or used for tuning or conclusions. Nevertheless, this round
    must not claim zero restricted-corpus access, and the incident independently
    keeps methodological handoff blocked.

52. **The round5.2 evaluation-report exclusion was not case-insensitive.** A
    read-only status search used an exclusion that failed under case variation
    and printed exactly one status line from each of
    `EVALUATION_V5_REPORT.md` through `EVALUATION_V10_REPORT.md`. It did not open
    or print evaluation corpus rows or sample content, run an evaluation test,
    classify or extract the corpus, or influence any source, test,
    documentation, or release decision. This disclosure does not change the
    frozen v10 `CONSUMED / FAIL` result and independently keeps methodology
    handoff blocked.

53. **A broad recursive Go test was started and forcibly terminated.** A
    classifier sub-agent mistakenly launched
    `go test -shuffle=on -count=20 ./...`. The root process interrupted it after
    about 23 seconds and sent `TERM` to PID `265343`. The same command then
    reappeared as PID `266741` with WSL `/init` as its parent, consistent with
    an orphaned CodeRabbit/tool session. The root interrupted the classifier
    agent again, terminated every matching process, and verified that none
    remained. It is unknown whether any consumed evaluation or Holdout test
    selected or read a restricted fixture before termination. The command and
    all partial results are permanently inadmissible and did not inform source,
    tests, documentation, or release decisions. Subsequent validation is
    restricted to the explicit safe allowlist. The project cannot claim no
    restricted access; v10 remains `CONSUMED / FAIL`, and methodology handoff
    remains blocked.

54. **The CPA source/compile contract is evidence only until counted-Mock Host
    validation.** `integration/cpalatestcontract` and
    `integration/pluginstorecontract` both bind CPA v7.2.124. Each module asserts
    the named critical Host tests and executes the complete upstream
    `internal/pluginhost` package, so this source coverage overlaps rather than
    forming two non-duplicative exact-name runs. The wider contract compiles the
    Guard and integration packages and runs Responses, Interactions, fail-open,
    Raw Capture, and Store contracts. It does not start the release CPA binary,
    load the candidate `.so`, or prove request reconstruction, logging,
    Auth/Provider/Usage isolation, and upstream behavior.
    No runtime baseline is admitted until the authorized counted-Mock sandbox
    matrix binds the same candidate SHA-256. Later CPA versions do not
    automatically change these pinned requirements.

55. **The public-reference corpus cannot attribute attack origin.** Its 36
    sanitized cases cover visible mechanism families and abstract source
    contexts, including local instructions, managed `AGENTS`, Skill/MCP,
    aliases, concealment, segmented continuation, and HTML-comment modules.
    `source_context` is test metadata, not a runtime security signal. The Guard
    cannot infer that text came from a particular GitHub repository, inspect
    content available only through a URL, `file_id`, archive, encryption,
    compression, or opaque media, stop a local program from modifying config,
    or correlate fragments omitted across independent requests.

56. **The final diff audit exposed author-source snippets.** One overly broad
    read-only `cmd/**/*.go` search printed evaluation/holdout author-source
    snippets and a few synthetic examples. It did not open restricted
    `testdata`, execute an author/evaluation/holdout tool, or inform source,
    tests, documentation, or release conclusions. The output is permanently
    excluded, but the event must remain disclosed and independently prevents a
    clean restricted-access methodology claim.

57. **Native CPA Interactions remains without exact-artifact Host evidence.**
    The Guard now registers `interactions` directly, retains it in the fixed
    audit enum, and scans its mixed schema conservatively without role trust.
    Source contracts can prove handler/Router field visibility and direct
    executor-format readiness, but they do not load the release `.so`. On CPA
    v7.2.80, an `agent` request that the Guard self-routes is rejected by CPA's
    native-Interactions validator with HTTP 400 before the Guard executor runs;
    a uniform Guard 403 would require an upstream CPA change. The owner-operated
    sandbox must recheck that behavior on v7.2.124 and
    separately verify model/agent, stream/non-stream, exact status
    shapes, first-byte behavior, and zero Auth/Provider/Usage/upstream effects.

58. **Clean candidate bytes are not released bytes.** Commit
    `21ceb57e6b6030e56d7820c9a67a8eecd068c669` passed push and PR CI as a
    pre-version-migration checkpoint, not final v0.15 evidence. The final
    PR head must pass PR CI, merge to `main`, and the exact resulting main
    commit/tree must pass push CI before the private untagged candidate workflow
    is dispatched from `refs/heads/main`. That workflow binds the post-merge
    main commit/tree and hashes in `candidate-manifest.json`. Only after the
    v7.2.95 Host record, independent audit, and candidate-bound external
    evaluation-v11+ `CONSUMED / PASS` report bind that same candidate may an
    optional annotated `v0.15-dev.round6[.N]` draft prerelease be created. The
    annotated formal `v0.15` tag and verified draft remain a later, separate
    gate, followed by protected promotion of that unchanged draft.
    The neutral policy is [RELEASE_POLICY.md](RELEASE_POLICY.md); external
    decisions are `round6-prerelease-attestation.json` and
    `formal-release-attestation.json`.
    Historical v10 is not a formal-build input. Formal source/audit bundles
    exclude evaluation, Holdout, private, blind, and retired material.

59. **Automated review is not independent approval.** The final PR head must
    have no unresolved, non-outdated actionable review threads before merge.
    That does not replace independent source, artifact, and Host review.

60. **The fixed Go 1.26.4 toolchain has two imported-but-not-called standard
    library advisories.** The current `govulncheck` symbol analysis reports zero
    reachable vulnerabilities in project code and zero vulnerable required
    modules, but package analysis reports `GO-2026-5856` in `crypto/tls` and
    `GO-2026-4970` in `os`, both fixed in Go 1.26.5. The task's reviewed Linux
    lane remains pinned to Go 1.26.4, so this residual toolchain risk must be
    disclosed and reassessed before any exact-candidate release; a development
    vulnerability-gate exit code cannot be represented as a clean standard
    library bill of health.

61. **The multilingual defensive-frame repair is source-only until the exact
    main commit is independently rerun.** A prior user-supplied external CPA
    v7.2.95 counted-Mock report for historical commit
    `aea54c8c3b357b085fb8c37d06eb4b501dcd29bb`
    observed 20/20 Chinese, Japanese, Korean, and mixed-language long-frame
    cases complete-allowing an upstream call. The current tree adds bounded
    multilingual ambiguity signals and Linux classifier/plugin regressions, but
    those checks do not prove CPA reconstruction, counters, latency, or
    Balanced/Strict Host behavior. Repository-local and Tencent Cloud #2
    counted-Mock matrices must bind the final commit and plugin bytes before
    Host promotion; green GitHub Actions alone are insufficient.

62. **The incident-response false-positive repair is intentionally finite; its
    local dirty Host coverage still requires exact-candidate review.** The
    user-supplied external
    report `Cyber-Abuse-Guard-Next-f37a25dd独立审计与二号机隔离测试报告-20260726.md`
    for `f37a25dd1ef7f64677282f154372cf2b4cb0ad7b`
    confirmed the multilingual malicious-carrier repair but found that an
    explicit defensive incident-response analysis request was blocked in both
    Balanced and Strict. The current source extends only the exact English
    analytical introduction grammar and preserves quote count, field/scope
    binding, byte/clause budgets, non-execution boundaries, and execution-tail
    reactivation. That external file is not checked into or cryptographically
    bound by this repository. Repository classifier/simulated-route checks and
    the later local CPA v7.2.102 `0.16-dirty` safe-review/direct-candidate Host
    cases are still not clean exact-candidate bytes, protected latency/RSS, or
    independent re-audit evidence.
    Coarse multilingual admission still uses a finite literal matcher whose
    same-field bits may accumulate across distant windows; changing that
    conservative behavior requires a reproducible safe fixture plus fuzz and
    Host evidence because a broad relaxation could restore complete-allow
    bypasses.

63. **The diagnostic CPA runner does not provide same-UID evidence
    attestation.** Linux has no ordinary syscall that atomically creates a
    directory and returns an fd for that newly created inode. The runner rejects
    a non-private evidence parent and keeps every later write on the opened
    directory descriptor, so post-bind path replacement is detected and cannot
    silently redirect those writes. The short create-to-bind interval, direct
    access through `/proc/<pid>/fd`, the verified normal-path handoff required
    because Docker/runc rejects proc-fd bind-mount sources, and process control
    such as `ptrace` remain available to a hostile process sharing the runner
    UID. The runner snapshots and revalidates every real, non-symlink component
    of the normal absolute evidence path; below the evidence root it also
    requires each normal mount-source component to match the descriptor-bound
    directory inode while the private evidence root and parent owner/mode remain
    unchanged. It repeats those checks after start and closes Docker's observed
    five-bind Source/Destination/RW/rprivate set. `HostConfig.Tmpfs` must contain
    only the hardened `/tmp` contract; `.Mounts` may omit it or repeat it once,
    and other volumes or mounts are rejected. This is still not an atomic same-UID
    boundary. Run the harness under a dedicated non-root UID with no untrusted
    peer and trusted ancestors. A stronger claim requires a different-UID
    trusted collector or an fd supplied by a trusted supervisor; RT12-05/06
    remains diagnostic and is not independent attestation.

64. **Unchanged ABI and RPC schema do not prove v7.2.124 request-shape
    compatibility.** CPA v7.2.124 retains C ABI 1 and RPC schema 2, but
    Multi-Agent v2 rewrites `/v1/responses` tool definitions before
    `RequestInterceptor`. CAG therefore sees a Host-mutated representation on
    that path. Until an exact-v7.2.124 candidate regression proves tool-schema
    inertness, tool-call/result provenance, bounded extraction, allow/block
    parity, and zero forbidden side effects, the Responses Multi-Agent path is
    `PENDING / NOT ADMITTED`. Historical v7.2.116 GitHub CI, second-machine,
    and five-repository data remain historical evidence only.
