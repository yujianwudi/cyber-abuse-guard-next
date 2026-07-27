# Threat Model

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: 72976ff80ca9c25478fda5b50f4fd129ffc04e4c5fdcfde478ff06024a6839e1
```

## Protected assets

- upstream OpenAI/Codex and other provider accounts behind CPA;
- downstream API credentials and authenticated identities;
- request privacy, including prompts, uploaded code, cookies, and tokens;
- CPA availability and correct routing/accounting behavior;
- structural integrity and operational availability of audit and subject-control state.

## Trust boundaries

The plugin is trusted in-process native code. Downstream request bodies,
headers, tool arguments, plugin YAML configuration, optional rule data, and
management test input are untrusted. CPA's Plugin Host and authenticated
management middleware are trusted. No upstream or external classifier is
trusted with request text.

The active source version is `0.16`; the Round 9 artifact target is the
non-latest Linux amd64 prerelease `v0.16-rc.4`. Stable `v0.16` does not exist and
production approval has not been granted. The source/compile and future
counted-Mock Host matrix is fixed to CPA v7.2.102
(`8423cce2d1004e80948a9e2c60ee69354c0aabc3`). Later upstream
versions are not followed automatically. The protected Host may expose CPA
only as `127.0.0.1:18394 -> 8317/tcp`; wildcard, random, extra, or multiple CPA
bindings are outside the admitted sandbox.

Source overlays, CI, candidate bytes, local dirty Host runs, protected Host
records, one-shot independent corpora, and independent review are separate
evidence classes. The v0.16-rc.1 package, Round 8 v0.16-rc.2 identity, and failed
Phase 1 v0.16-rc.3 identity are historical evidence only. A 2026-07-27 local
CPA v7.2.102 Host/Router run exercised a generated `0.16-dirty` `.so` with
loopback fixtures and a Mock upstream, but it proves only those dirty development
bytes. Neither source compatibility nor that local run proves that a future
clean exact candidate loaded correctly, blocked before Auth/Provider/Usage, or
preserved benign upstream calls at an admitted release evidence boundary.

Round 9 keeps the runtime evidence boundaries separate and does not infer one
from another:

| Evidence boundary | Current status | What would be required to close it |
|---|---|---|
| Local dirty development Host/Router | `PASS / DEVELOPMENT ONLY` | No release boundary is closed; the result is non-transferable from its generated `0.16-dirty` `.so` |
| Repository-local counted-Mock | `NOT_PROVIDED` | A final-source, exact-candidate Linux run with persisted counters and hashes |
| Tencent Cloud #2 isolated counted-Mock | `NOT_PROVIDED` | An operator-authorized run in the isolated loopback sandbox, with no production, real Provider, real account, or real-user contact |
| Protected external evaluation and one-shot ledger | `NOT_PROVIDED` | Signed external-evaluation, counted-Mock, ledger-event, and ledger-proof assets bound to the same frozen candidate |

The Round 9 task requires production to remain `mode=audit` with subject
control disabled. That is a requested safety constraint, not a live
verification of the current production configuration; this development work
did not inspect or change production.

## Principal threats and controls

| Threat | Control |
|---|---|
| Explicit malicious request reaches an upstream account | ModelRouter runs before provider/auth selection; handled decisions target only the local executor. The exact v0.16-rc.4 candidate must be loaded by CPA v7.2.102, and each eligible malicious local block must prove zero Auth Selector, Provider, Usage, and Mock Upstream deltas. Repository-local counted-Mock, Tencent Cloud #2 isolated counted-Mock, and protected external verification are all `NOT_PROVIDED`. |
| Another router handles the request first | Install at priority 300, verify effective ordering, disable the obsolete identity-rewrite filter, and document that any higher-priority handled Router can bypass this guard. At equal priority CPA orders by plugin ID ascending, so a lexicographically earlier handled Router can also win. |
| Plugin is absent, registration fails, it is fused, or its self executor is unusable | Treat load/registration/fuse state, Router errors or pre-result panics, invalid/empty targets, and executor-not-ready as CPA host fail-open conditions that may continue other Routers or native routing. `enforcement_ready` is internal plugin state only; external load/order/readiness monitoring remains required. |
| Keyword-only false positive blocks legitimate coding or security work | Balanced uses candidate-bound eligibility before score or hard floor. Incomplete, defensive, analytical, quoted, credential-lifecycle, code/log/fixture, cross-scope, or ambiguous evidence is allow+audit unless an independent current malicious clause proves complete actionable harm. |
| Historical assistant/tool/system/unknown text or a tool schema is combined with the current user request | Every occurrence retains role, provenance, current-turn, field, clause/sentence, directive-owner, polarity, and inert state. Assistant, system, tool, and unknown-role history cannot fill a current malicious core or seed a bare referent; only the newest eligible trusted RoleUser review can be reactivated after complete referent proof and a fresh eligibility assessment. Tool schemas and assistant tool-call arguments are never referent payloads. An explicit current-user harmful restatement is evaluated independently. Separately, an active request-local system/developer instruction or terminal tool result may block only its own independently complete malicious candidate; that direct evaluation is not referent promotion. |
| One broad token is counted as action, target, delivery, and evasion | Dimension assignment is occurrence-owned: one occurrence can satisfy at most one scoring dimension, and hard floors require a complete strong core predicate first. |
| Instruction-hierarchy or unrestricted-persona replacement controls the model | Multi-family `META-OVERRIDE-001` remains bounded candidate evidence. Historical, quoted, defensive, or otherwise ineligible wrapper text allows or audits; an active standalone current-user control request may retain the `defense_evasion` / `META-OVERRIDE-001` winner only after the same candidate-level eligibility gate proves it complete and actionable. |
| Refusal/safety-disable inversion is presented as a safety policy | Policy wording that negates refusal, blocking, filtering, guardrails, or safety checks is treated as hostile control rather than benign policy suppression. |
| Fake sandbox, benchmark, placeholder, or authorization scope washes a real target | Prompt-derived CTF/lab/fictional/authorization claims do not reduce the meta-override overlay; explicit negative authorization increases risk. |
| System/developer prompt or hidden-reasoning disclosure is forced through exact-output controls | Protected-disclosure evidence composes with hierarchy/output-control signals and emits only fixed evidence IDs, never the requested secret text. |
| Caller hides intent with casing, spaces, punctuation, zero-width characters, light leetspeak, URL/HTML/Base64/text-data encoding, or nested tool JSON | Bounded Unicode normalization, compact matching, at most two decode layers/eight variants, and explicit byte budgets; no claim of resistance to arbitrary adversarial encoding. |
| Supported `SourceFormat` carries a forged or future schema | Failure to prove a recognized role envelope triggers the bounded untrusted-text walker instead of trusting the source label. |
| Tool output or a double-stringified payload carries an indirect instruction | Tool provenance is inspected separately and valid JSON-looking strings inside established tool payloads recurse under the shared budget. |
| A media marker placed after `source.data` turns opaque bytes into classifier text | Payload-adjacent `data`/`bytes`/`blob`/`binary`/`filename`/`format`/`detail`/`width`/`height`/`duration` values are bounded object-level candidates. A later media marker discards them before Parts, Segments, decoding, or text-budget accounting; a final non-media object commits them as text. Candidate propagation is restricted to media-style ownership, tool boundaries cut inherited media meaning, and opaque kinds have fixed ordering. |
| An attacker labels executable tool data as media to suppress inspection | Provider-native tool/tool-payload boundaries retain text semantics. Tool `data` remains inspectable and cannot make itself opaque merely by adding `type=image` outside a reviewed media container. |
| An unknown multipart field injects text into classification or creates a partial-score block | Multipart text is selected only by a fixed SourceFormat profile. `openai-image` admits prompt/negative-prompt text; unknown non-file fields and text/file type mismatches become fixed incomplete schema without retaining name/value. Balanced allows+audits, Strict blocks for the incomplete reason, and neither uses partial rule IDs, score, or subject state. |
| Parser tests are mistaken for real ingress/Host proof | CPA `ModelRouteRequest` has no general HTTP path and the image handler may rebuild multipart before routing. Parser tests prove only the plugin-input contract; the exact-candidate Host test on the sole pinned CPA v7.2.102 profile must separately prove CPA reconstruction, pre-SSE behavior, and Auth/Provider/Usage/upstream deltas. |
| Base64 or high-risk words are split across provider blocks, ordered tool fields, or isolated characters | Same-message content and ordered tool-payload/output strings are re-decoded after pristine joining, and a tightly bounded isolated-character reconstruction path closes simple fragmentation. |
| Public adversarial material contaminates later evaluation | External repositories are frozen read-only as repo/ref/commit/path/bytes/SHA-256 development corpora, never executed, and never reused as blind/independent Holdout. Default branches, branch heads, and unmerged candidate carriers remain separately labeled. |
| A local instruction file or remote template injects higher-priority policy before CPA sees the request | This is outside the Router boundary. The host must allowlist instruction paths, enforce owner/mode and write restrictions, bind SHA-256/signatures, verify at startup and every reload, audit changes, and pin human-approved remote templates to a commit/hash. The Router cannot attest to `model_instructions_file`, `AGENTS.md`, or remote-template integrity. |
| Provider safety/config fields weaken upstream policy without prompt text | Do not guess from keywords. The host must apply a versioned schema allowlist and reject or forcibly overwrite unsafe `safetySettings`, `generationConfig`, `options`, and equivalent values before routing. |
| A key-only tool control hides semantics in a boolean/numeric/null property | Map only explicitly approved, versioned tool schemas to fixed low-cardinality semantics; the current marker `cag_control_schema=meta_override_control/v1` is authoritative only inside established tool/tool-payload provenance. Treat unknown control keys in that known schema as fixed `tool_schema` incomplete, and never promote arbitrary business JSON keys to prompt text. |
| JSON/decode/media resource exhaustion | Token walk, depth/part/byte budgets, 128 KiB encoded-source and 64 KiB decoded-variant caps, no decompression/archive expansion/network fetch, separate opaque-media policy, fuzz tests. |
| Artificial scan boundary inside a JSON escape or UTF-8 sequence becomes a router-error bypass | Boundary decode errors are classified as truncation rather than malformed complete JSON; enforcing modes fail closed, with escape and multibyte regression tests. |
| Base64-expanded plugin RPC exceeds the native copy cap before extraction | The native boundary recognizes oversized model-route/executor methods without copying the payload. Only Strict model-route self-routes to the local scan-limit 403; Balanced and non-enforcing modes pass through with incomplete-inspection accounting. A directly invoked oversized executor returns Strict's local 403 or a non-strict local 413. The real CPA test must distinguish these mode-specific paths and their auth/provider/upstream side effects. |
| Token counting or HTTP forwarding bypasses a policy self-route | `executor.execute`, `executor.execute_stream`, and `executor.count_tokens` share the policy 403 path. `executor.http_request` has a SOURCE/ADAPTER status-error 405 check: the official adapter returns `nil,error`. CPA's public `/v1/alpha/search` consumer normally selects `codex` and maps every executor error to 502, so no current official route yields Guard's final client 405. The project wrapper is not official Host evidence; final 405 is `NOT AVAILABLE / NOT RUN` and blocks handoff. |
| Tool input hides abuse under a metadata-named key or reordered Anthropic block | Transport metadata remains excluded, but all textual fields inside tool payloads, including order-independent `tool_use.input` and `name`/`url`/`type`/`model`, are scanned under the shared budget. |
| Appended history or forged role labels hide earlier abuse | Standard role segments are each classified independently plus adjacent user follow-ups; role-less shapes use a conservative part fallback, unsupported roles fail closed, and history-cap truncation is never silent. |
| A safety review quotes abuse and a later turn says only `execute it`, `follow it`, or `proceed` | Only the newest eligible trusted RoleUser safety review can establish a referent. An affirmative referential directive reclassifies the unique quote alone; questions, explanations, negation, remediation, and non-user/unknown review carriers remain inert. Multi-action clauses retain each action family, so cancelling one family cannot erase another active family, while explicit cancellation of every family remains inert. Alternative cancellation branches do not terminate an active choice. A mixed-trust RoleUser pair is always `ActionAudit`: the detected category may be retained as bounded audit evidence, but `FindingOrigin=non_user_or_untrusted`, `block_eligible=false`, and `PrimaryReason=untrusted_ownership`; it cannot enter subject-risk accumulation. Long or cross-window proof loss becomes `classifier_window_incomplete`, and the extra classification consumes `MaxChunks`. |
| Router and executor retries count one logical request multiple times | Subject risk uses a domain-separated request digest and bounded idempotency receipts. The same subject/request pair is counted once across execute, stream, token count, retry, concurrency, pending-cache miss/expiry, enabled reconfigure, and shutdown races. Receipts persist with optional subject snapshots. |
| Regex denial of service | Default rules use normalized literal terms; validation rejects unsupported/oversized rule constructs. |
| Prompt or secret leakage through Guard audit | Fixed minimal event schema; SHA-256/HMAC correlation; tests search the DB for canary prompt/key/unknown-field values. This does not cover CPA Host request/error logs. |
| CPA Host logging persists request bodies outside the Guard audit boundary | CPA may temporarily spool non-multipart bodies and persist a raw body in an HTTP error log. Every current Host-matrix sandbox uses a temporary log directory and must review mode, retention, permissions, canary absence/presence, and cleanup before any production observation. |
| Subject hash reversal/correlation or secret-file path swap | HMAC-SHA256 with a production mode-0600 regular-file secret; Linux uses `O_NOFOLLOW` and validates/reads the same descriptor; no plaintext subjects; status exposes no secret. |
| Persisted subject state leaks plaintext or is restored under a different key | Typed HMAC-only schema, bounded atomic snapshots, one-way key ID, explicit key mismatch with writes blocked, expiry/decay/capacity on restore. |
| Forged `X-Forwarded-For` | CPA ABI v1 exposes no trusted peer address to ModelRouter, so the Guard rejects trusted-proxy activation and never accepts the header as identity. |
| High-cardinality subject IDs exhaust memory or displace manual blocks | `max_subjects` defaults to 10,000; least-recent-risk non-manual entries are evicted, manual blocks are protected, and new risky subjects fail closed if no entry is evictable. |
| Audit DB lock/corruption takes CPA down or path swap changes another file | Busy timeout, bounded queue, fail-open audit path, deadline-bounded close, rate-limited diagnostics, exact schema/index/history validation, rejection of writable/final-symlink directories and DB/WAL/SHM symlinks, and visible runtime permission degradation. Enforcement continues while audit/persistence degrades. |
| A local DB writer deletes valid persisted subjects | Filesystem ownership/mode is the trust boundary. Schema v2 detects malformed or inconsistent rows but has no keyed whole-snapshot MAC and does not claim adversarial completeness. |
| v0.1.1 database upgrade is partial, exposes a temporary copy, or destroys the old store | Explicit schema version/history, transactional v1→v2 migration, private mode-0700 staging, mode-0400 sync-before-publish backup, bounded backup count, and failure rollback tests. |
| Invalid hot reload weakens policy or erases enforcement history | Parse/compile/validate full state before atomic swap; last valid state is retained; compatible enabled-to-enabled changes preserve subject risk, cooldown, and manual blocks; unsafe capacity shrink is rejected. |
| Plugin panic crashes CPA or bypasses enforcement | ABI entrypoints recover. A recovered `model.route` panic self-routes in a validated Balanced/Strict runtime and increments counters; other methods preserve a non-zero ABI failure signal. CPA may still fuse a plugin, so monitoring remains required. |
| Router error silently weakens enforcement | Known scan-boundary, recovered panic, and guarded Router failures self-route in enforcing modes. Oversized RPCs are the explicit exception described above: only Strict model-route self-routes, while Balanced passes through with incomplete-inspection accounting. Status exposes readiness/error/panic counters; the watchdog alarms on deltas. CPA still owns host-level fail-open policy that the plugin cannot change; the sole pinned CPA v7.2.102 Host profile must verify it. |
| Management test/unblock exposed to normal API keys | Routes registered exclusively through CPA Management API; no public resource routes. |
| Oversized management HTTP body is fully buffered by CPA before plugin limits run | CPA currently uses `io.ReadAll` in `ServeManagementHTTP`, so plugin 1 MiB body / 2 MiB envelope checks are not a host memory ceiling. The deployment proxy sets `client_max_body_size 1m`; the server sandbox must prove Nginx returns 413 before CPA receives the request. |
| CPA store rejects or misinstalls the release archive | Keep the store ZIP separate from the audit bundle. CI must require real `.so`/ZIP/metadata/checksums, use `InstallManifest` for first install and Host load, then verify same-Dist repeat-skip/tamper-repair with `TestPublishedStoreArchive`. Synthetic fallback is source evidence only. |
| SSRF or prompt/media exfiltration via classifier or URL inspection | The Guard rejects external classifier activation, never fetches media URLs, and performs no outbound classification/telemetry call. |
| Identity spoofing to evade upstream policy | Plugin never changes model, system prompt, client name, headers that claim identity, or upstream safety declarations. |

## Abuse cases intentionally still blocked

An assertion of authorization does not by itself permit deployment-oriented
credential theft, phishing collection, ransomware, or data exfiltration. A
request for static analysis, detection, containment, or remediation can still
be allowed when those defensive signals dominate and no deployment intent is
present.

## Residual risk

Deterministic local rules cannot infer intent perfectly, can be evaded by novel
language or encoding, and can produce false positives/negatives. Decoding is
bounded, images/audio/video are not semantically inspected, and public media
URLs are never fetched. `observe` and `audit` deliberately do not block. CPA or
upstream behavior outside the pinned ABI may change. Native compatibility for
the Round 9 candidate requires an exact CPA v7.2.102 counted-Mock Host record
plus an independent audit. CPA retains the
host-level Router fail-open conditions described above. Holdout/evaluation generations v1-v9 are
retired, consumed, or methodology-invalid history; methodologically valid v10
was consumed and failed. Any future release attempt requires a new
independently authored unseen set for a materially new implementation and must
not reuse v10 or the visible 35-case
`development-adversarial-v11-prep` corpus. Upstream providers independently enforce their own policies.
Therefore the plugin reduces risk but cannot guarantee that an account will
never be warned, suspended, or deactivated.

The classifier remains stateless across separate API calls, cannot attest to
the path, owner, permissions, hash/signature, reload history, or remote origin
of a local instruction file or template before a request reaches CPA, and does
not claim arbitrary-transform or opaque-media semantic coverage. Provider
safety/config semantics remain a host schema-policy responsibility. An earlier
set of local WSL Host/Router/proxy commands was mistakenly executed with
loopback/Mock components and cleaned up without residual processes; those
historical results remain excluded. The later 2026-07-27 `0.16-dirty`
Host/Router run is retained as local development evidence only and does not
close an exact-candidate, protected, or independent boundary. Detailed legacy
results remain in Git history; the
legacy CPA-version-specific handoff files are not part of the active source
tree. Current source and pending-candidate status are recorded in `AUDIT_HANDOFF.md`,
`reports/TEST_REPORT.md`, and
`reports/RELEASE_EVIDENCE.md`. Any missing final-commit Host,
GitHub CI, artifact, or proxy result is **NOT RUN** or **BLOCKED**, never an
inferred PASS. Embedded ruleset `1.0.10` identifies YAML assets only and does
not include the complete Go classifier/extractor policy. Repository-local
counted-Mock, Tencent Cloud #2 isolated counted-Mock, protected external
evaluation/one-shot-ledger evidence, independent source/artifact/Host review,
and candidate-bound external admission all remain `NOT_PROVIDED`. The Round 9
lane targets the non-latest `v0.16-rc.4` identity, but new public Release
creation is `BLOCKED_FAIL_CLOSED` until exact-candidate independent-audit
evidence is provided and the mechanical audit-admission gate is implemented and
passes. Admission rejects every already existing matching Release; the retained
legacy verifier is statically unreachable and documents only a possible future
review contract. The lane must not mutate a Release or create/imply stable
`v0.16`. Any later stable
promotion remains a separate protected operation on the unchanged,
independently admitted draft. Historical v10 remains `CONSUMED / FAIL`, cannot
be rerun, and is not a formal-build input. Formal source/audit bundles exclude
evaluation, Holdout, private, blind, and retired material.

The final PR head must have no unresolved, non-outdated actionable review
threads before merge. Automated review is development feedback only and does
not reduce the independent-review threat boundary.

The neutral source gate is [RELEASE_POLICY.md](RELEASE_POLICY.md). Only external
`round6-prerelease-attestation.json` and `formal-release-attestation.json`
assets can close Host/audit and formal publication boundaries.
