# CPA Cyber Abuse Guard v0.16 Round 9 Design

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: f9529ada85dee7e35267c70da54aa74e266e88b4ed2703924f352c2cb0cb4333
```

## Scope, release state, and invariants

Cyber Abuse Guard is an in-process CPA C-ABI v1 plugin for CLIProxyAPI. The
current source version is `0.16`; the Round 9 development target is the Linux
amd64 prerelease `v0.16-rc.4`. It is not the stable `v0.16` release and is not
production-approved. The earlier `v0.16-rc.1`, Round 8 `v0.16-rc.2`, and failed
Phase 1 `v0.16-rc.3` identities are immutable historical evidence and must not
be overwritten, relabeled, repaired, or republished as current Round 9 output.

The fixed CPA source/compile target is:

- CPA `v7.2.104` at
  `c9417c8ae9b16fabc0386ca35d36f13bf8b1d678`, module sum
  `h1:59vZ1rtgxs6etE0Z3iFsLWgZ/MrcIi4mhXLt0XLSNcY=`, and `go.mod` sum
  `h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=`.

The root module, `integration/cpalatestcontract`, and
`integration/pluginstorecontract` bind this same identity. A later CPA tag is
not followed automatically.
Source/compile contracts are not counted-Mock Host evidence, and neither is a
substitute for independent review of the exact candidate bytes.

Round 9 redesigns the Balanced false-positive boundary around candidate-level
block eligibility. The classifier does not treat a request as a bag of globally
composable keywords or use a request-global safety boolean. Each harmful-core
candidate binds category, clause, ownership scope, referent chain, and evidence
occurrences. Only a candidate whose inspection, current execution act, harmful
core, operational actionability, authorization state, and defensive/quoted
scope all satisfy `CandidateBlockEligibility` may enter scoring or hard-floor
processing. Historical assistant/system/tool/unknown-role content, tool schemas,
assistant tool-call arguments, unrelated JSON fields, code, logs, and distant
long-text windows cannot fill missing dimensions for a current request.

The implementation has seven non-negotiable invariants:

1. A blocked request is terminated by the schema-2 before-auth
   `RequestInterceptor` with a direct HTTP 403 before auth scheduling, provider
   execution, usage accounting, SSE establishment, or upstream work. The legacy
   executor remains a callback-safe, outbound-free defense-in-depth path.
2. Every malicious-text block producer consumes an eligible candidate; score,
   threshold, wrapper amplification, semantic composition, and hard floor cannot
   create eligibility or bypass the common gate.
3. A single keyword, wrapper, role, field name, or historical fragment is never
   sufficient to block. Generic development terms are weak evidence only.
4. Evidence cannot cross message, segment, clause, ownership, role, provenance,
   or referent boundaries unless the same bounded candidate proves the link.
5. Balanced and Strict share malicious-text eligibility. Incomplete inspection
   remains separate: Balanced allows and audits; Strict may block only with
   `block_incomplete_inspection`, without a malicious category, rule, or subject
   accumulation.
6. Defensive, analytical, authorized, quoted, educational, code, log, and test
   fixture evidence is resolved at local clause/scope level; it cannot wash an
   independent malicious clause or be overridden by a cross-scope hard floor.
7. The plugin never rewrites the requested model, client identity, or system
   prompt, never sends request content to an auxiliary classifier, and stores
   no original request text by default.

Current traceability and known gaps are tracked in
[ROUND9_EXECUTION_RECORD.md](reports/ROUND9_EXECUTION_RECORD.md). The Host,
audit-migration, and operator-owned rollback contracts are documented in
[ROUND9_HOST_RUNNER.md](ROUND9_HOST_RUNNER.md),
[ROUND9_AUDIT_SCHEMA_V6.md](ROUND9_AUDIT_SCHEMA_V6.md), and
[ROUND9_OPERATOR_ROLLOUT.md](ROUND9_OPERATOR_ROLLOUT.md). Exact-main CI,
counted-Mock Host validation on the sole pinned CPA v7.2.104 identity, and
independent audit remain mandatory; self-tests do not authorize production
Balanced mode.

## CPA ABI path

The shared object exports `cliproxy_plugin_init` and returns C ABI version 1.
Its JSON RPC registration uses schema version 2 and declares:

- `request_interceptor`: classify before auth and directly terminate a blocked
  request. The bounded lifecycle cache retains only the opaque `RequestID` and
  a per-process, request-ID-bound HMAC-SHA256 fingerprint of canonical
  `SourceFormat`, body, case-normalized header names with exact ordered values,
  and the stream flag. After auth skips duplicate classification and side
  effects only when both the ID and fingerprint match; computing the body
  fingerprint remains O(n). A body, header, format, or stream mutation is
  reclassified and replaces the cached fingerprint. A fail-open operational
  failure is not cached as checked, so after auth can retry. No request text or
  header value is retained in the cache. This still assumes the attested Host
  chain
  has no untrusted mutator that runs after Guard at the final interceptor stage;
- `request_lifecycle_plugin`: remove the bounded, TTL-limited opaque RequestID
  and fingerprint entry for succeeded, failed, rejected, or canceled requests;
- `model_router: true`: only the CPA v7.2.104 `codex-alpha-search` compatibility
  entry is handled because those two HTTP routes do not invoke
  RequestInterceptor. Host-originated Router callbacks for every other format
  return `Handled:false` without classification; ordinary enforcement remains
  on the schema-2 before-auth interceptor;
- `executor`: retain the outbound-free local refusal path as defense in depth;
  HTTP forwarding remains explicitly unsupported;
- `management_api`: expose management-key-protected status, event, stats, test,
  unblock, and delete routes.

The canonical CPA formats `openai`, `openai-response`, `interactions`,
`codex-alpha-search`, `openai-image`, `openai-video`, `claude`, and `gemini` are declared as executor input and output
formats. The real-Host harness retains separate allow/block, stream,
token-count, and native error-shape assertions for the four original entry
protocols; the image/profile and native Interactions matrices are distinct
pending Host gates. Interactions is a known format but intentionally uses the
conservative untrusted-text extractor until a fixed role schema is proven.
Alpha Search uses its dedicated query profile and is never sent to CAG's
executor: a malicious self-route is rejected by CPA's Alpha handler as HTTP 503
before Codex auth or upstream because that handler currently accepts only a
`provider=codex` target.

CPA v7.2.104 exposes `ModelRouter` as a global capability rather than a
source-format-scoped capability. Once CAG registers it for Alpha Search, an
ordinary routed request still incurs CPA's body clone, JSON/Base64
serialization, and Router RPC before CAG can return `Handled:false`; the plugin
fast path cannot remove that Host-side O(n) work. For a native RPC above 8 MiB,
`CallOversized` receives only the method name and cannot distinguish Alpha
Search from an ordinary request. CAG therefore retains security-first
oversized `model.route` handling so a large Alpha Search request cannot bypass
inspection. The consequence is that a large ordinary request can produce one
incomplete disposition at `model.route` and another at
`request.intercept_before`; `request.intercept_after` is an unconditional
pass-through for oversized envelopes, preventing a third disposition. A
time-window suppression heuristic is intentionally rejected because concurrent
requests could be mismatched. Eliminating this cost and duplicate accounting
requires CPA to scope Router capabilities by format or invoke
RequestInterceptor for Alpha Search.

For an unknown non-multipart `SourceFormat`, Strict terminates before
interpretation. Balanced, Audit, and Observe still run a bounded generic
untrusted-text walk so a new label is not a silent bypass; a counter and
watchdog delta make it visible. Unknown multipart is different: every non-file
field becomes schema-incomplete, Balanced allows+audits, and Strict blocks for
the fixed incomplete reason. Neither path guesses future provider semantics;
a new CPA/provider shape requires review and an explicit canonical mapping.

For an allowed request, the interceptor returns an empty modification response.
For a blocked request, it returns `Terminate: true`, status 403, no-store and
nosniff headers, and the stable `cyber_abuse_guard_blocked` JSON body. CPA maps
that termination into the native error shape for each entry protocol. The
counted-Mock Host lane must reverify the exact client shapes against the same
candidate bytes.

`executor.execute`, `executor.execute_stream`, and `executor.count_tokens` use
this same policy-403 path. `executor.http_request` produces an unsupported-method
RPC error whose `StatusCode()` is 405; the official adapter returns `(nil,
error)`. This is a SOURCE/ADAPTER check, not a final client HTTP result. The
audited root CPA contract exposes the provider-specific public consumer
`POST /v1/alpha/search`, but ordinary selection is fixed to `codex` and the
handler maps every `HttpRequest` error to HTTP 502. The project's
`httptest.Server` manually maps the status error and cannot establish official
Host HTTP 405. No current official public route maps Guard's error to final
client 405, so the result is `NOT AVAILABLE / NOT RUN` and remains a handoff
blocker that current CI cannot solve. The real four-protocol HTTP/SSE and zero
Auth/Usage/Provider/Upstream matrix must be executed against the exact
`v0.16-rc.4` candidate in the protected Round 9 counted-Mock lane before it
becomes Host evidence.

CPA ABI v1 `ExecutorResponse` has payload and headers but no HTTP status.
Consequently, ABI v1 cannot simultaneously return an arbitrary plugin-owned
JSON body and a non-200 status from `executor.execute`. The Guard favors the
security property and correct 403 status, using CPA's protocol error wrapper.
The stable marker and coarse category remain in the message; rule IDs and
bypass details do not.

CPA serializes request bodies as Base64 inside `RequestInterceptRequest`, so a raw
request slightly above 6 MiB can exceed the native 8 MiB RPC copy budget.
Returning an interceptor RPC error there would make CPA continue its chain. The
native boundary therefore detects oversized before-auth methods before
`C.GoBytes` and uses a no-copy, mode-aware success response: `strict` terminates
directly with `scan_limit`; `balanced`/`audit`/`observe`/`off` pass through
according to their documented incomplete-inspection behavior. Oversized
after-auth callbacks pass through without counters or audit because before-auth
already owns the logical request disposition. An oversized executor RPC returns
a local 403 policy refusal in Strict and a local 413 size error in Balanced;
neither executor result can fall back to a provider.

## Request extraction

The extractor is format-tolerant and walks JSON tokens with bounded work:

- maximum JSON depth, text parts, and scanned text bytes are configurable;
- common text-bearing fields (`system`, `instructions`, `input`, `content`,
  `text`, and tool `arguments`) are collected across nested arrays/objects;
- role, model, identifiers, URLs, image fields, and known binary fields are not
  treated as prompt text at transport/message level; metadata-named keys such
  as `name`, `url`, `type`, and `model` remain inspectable inside tool payloads;
- recognized image/audio/video/document-attachment payloads are omitted and marked as opaque media,
  independently from incomplete text scanning;
- HTTPS media URLs are metadata and are never fetched;
- unknown fields (including a tool argument named `data`) remain inspectable;
  text decoding recognizes bounded URL escapes, HTML entities, Base64 text,
  textual data URLs, JSON escapes, and nested tool JSON;
- nested JSON inside tool arguments is scanned using the same shared budget;
- Anthropic `tool_use.input` and equivalent nested `input` payloads are scanned
  as tool data regardless of whether the sibling `type` field appears before
  or after `input`;
- standard OpenAI/Anthropic/Gemini histories are also indexed into bounded
  `system`/`user`/`assistant`/`tool` segments. Role-less standard items use a
  conservative legacy-plus-per-part fallback; explicit unsupported roles fail
  closed, and discarding history at the 64-segment cap sets `truncated`;
- adjacent user turns and one explicitly linked bounded three-turn plan can
  compose behavior evidence across an assistant refusal, while non-user safety
  text cannot supply user intent;
- provider-native tool payloads retain tool provenance and are scanned
  independently; placeholders and renamed variables are ordinary text until a
  nearby definition binds them to a dangerous object, asset, or target;
- malformed complete JSON is a parse error, not automatically malicious;
- an artificial scan boundary inside an escape or UTF-8 sequence is treated as
  truncation, not a parse error; `balanced` allows+audits without a prefix
  score, while `strict` blocks for the fixed incomplete reason;
- over-limit input is marked truncated without panicking.

The original request byte slice is used only during the call. It is never
stored in events or risk-control state.

### Order-independent JSON media and schema-bound multipart

JSON object members are unordered. Values under the payload-adjacent keys
`data`, `bytes`, `blob`, `binary`, `filename`, `format`, `detail`, `width`,
`height`, and `duration` are therefore held as bounded object-level candidates
until their media meaning is known. A later media marker discards
the candidates without adding `Parts`, `Segments`, decode variants, or
`TextBytesScanned`; a final non-media object commits them as inspectable text.
Candidate overflow retains and classifies no prefix: a final media object stays
complete/opaque, while a final non-media object gets the fixed
`deferred_text_candidate_limit` reason. Candidate propagation is limited to
media-style ownership such as `source`, and crossing a tool/tool-payload
boundary cuts inherited media meaning. Consequently, tool argument/output
`data` remains inspectable and cannot hide itself merely by adding a sibling
`type=image`. Opaque media kinds are deduplicated in a fixed order so equivalent
member permutations have identical telemetry.

Multipart extraction is selected by a fixed `RequestProfile` derived from the
canonical `SourceFormat`. CPA schema-2 `RequestInterceptRequest` has no general HTTP
path, and the official image handler may parse and rebuild multipart before the
interceptor receives it, so endpoint-path inference is neither available nor valid.
For `openai-image`, inspectable text is limited to `prompt` and
`negative_prompt` (plus `negative-prompt` and `negative prompt`); reviewed
metadata/control fields are discarded, and `image`, `image[]`, `images`,
`images[]`, and `mask` are opaque files. File evidence has precedence. An
allowlisted text field carrying file evidence becomes
`multipart_text_field_type_mismatch`; every unknown non-file field becomes
`multipart_unknown_field`. Neither name nor value is classified or persisted.

Both schema reasons are incomplete inspection. No partial classification or
subject-risk update is used: Balanced allows+audits as `multipart_schema`,
Strict terminates with `cyber_abuse_guard_multipart_schema`, and a complete
malicious prompt still follows ordinary policy. Parser unit tests prove the
payload delivered to the plugin; only exact-candidate counted-Mock Host
execution can prove pre-interceptor reconstruction and Auth/Provider/Usage/upstream
side effects.

The original-body statement above is a Guard boundary, not an end-to-end Host
logging guarantee. CPA request logging may temporarily spool a
non-multipart body and persist a raw body in an HTTP error log. Host validation
must isolate and inspect that log path, commercial-mode behavior, retention,
permissions, and cleanup.

### Bounded decoding and opaque media

Encoded text is inspected without entering unbounded recursive decoding. At
most two decode layers and eight unique variants are retained. Encoded input is
capped at 128 KiB and decoded variants share a 64 KiB retained-byte budget.
Only valid UTF-8, printable textual results are added. An incomplete recognized
text envelope sets the ordinary truncation signal, which enforcing modes treat
conservatively. There is no decompression, archive expansion, document parser,
binary-media decoder, redirect handling, DNS resolution, or network fetch.
Strings with an unknown encoding shape or merely high entropy remain literal
classifier input when their schema and role provenance are otherwise supported;
they do not become an automatic block signal. This is not a promise that an
arbitrarily long `RoleUnknown` field can participate in exact cross-field text
reconstruction: once the bounded summary cannot retain it, the streaming
classifier keeps only fixed risk facts and may report
`classifier_window_incomplete`. The distinction avoids treating arbitrary
tokens, hashes, and compressed-looking identifiers as malicious, while leaving
encrypted and novel encodings as an explicit detection limitation.

Opaque image/audio/video/document attachment is a separate signal controlled by
`opaque_media_policy`. An explicit `block`, `audit`, or `allow` wins. If the
field is omitted, Off allows, Observe/Audit/Balanced audit, and Strict blocks.
Auditing records only a coarse disposition and counters, not media bytes. An
allow decision means “not inspectable by this plugin,” not “known safe.” Pure
text behavior does not depend on this policy.

## Deterministic classifier

Ruleset `1.0.10` is versioned YAML embedded into the shared object. Its current
canonical embedded SHA-256 is
`e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0`. Startup
compiles and validates it once. Rules use literal normalized terms rather than
runtime regular expressions, eliminating catastrophic-backtracking risk.

Text is normalized with Unicode NFKC, lower-casing, removal of zero-width
format characters, whitespace folding, and a conservative adjacent-letter
leet normalization. Matching also uses a punctuation/space-compacted view for
light obfuscation.

Each category uses evidence groups:

- harmful action and dangerous object establish intent;
- operational detail, a real target, credential/data access, evasion, and
  scale/automation add risk;
- defensive analysis, remediation, static analysis, incident response,
  CTF/lab, explicit authorization, and high-level-only context subtract risk;
- an authorization statement alone does not override credential theft,
  phishing deployment, ransomware deployment, or data exfiltration.

Negation and prohibition cues are scoped to nearby evidence in the same clause.
They can preserve a genuine request to avoid or prohibit abuse, but an unrelated
prefix such as "do not add comments" cannot suppress a later implementation
request, and a prior negated policy statement cannot poison a follow-up segment.

High-density directive analysis retains at most 64 exact head clauses and an
exact four-clause suffix, while every later clause still updates bounded
per-rule, per-provider-pair composition, context-conflict, and semantic
summaries. The head and suffix are never joined across omitted clauses. Compact
intent patterns are compiled once, and one reusable clause-position proof is
shared by negation and composition checks, preventing repeated clauses or
unique signal-bearing catalogs from multiplying proof allocations by the rule
count.

For recognized role histories, each retained segment is classified on its own,
so old explicit abuse cannot be hidden by appending benign turns. Adjacent user
turns are additionally classified as a pair to preserve follow-up semantics
across an intervening assistant refusal. Non-user text is never combined with
user evidence. A structurally proven active system/developer instruction or
terminal provider-native tool result may block only its own independently
complete harmful candidate under `request_local_system` or
`request_local_tool`; it is never user-owned and never enters subject state.
Provider-native tool authority is closed over one request-local transaction.
OpenAI Chat, Responses, and Claude require their exact native identifier and
owner shapes. Gemini additionally requires one adjacent call/result message
pair ending at the terminal history item, equal call/result cardinality, and an
entire group that is either explicit-ID matched or wholly ID-free and matched by
name+ordinal. Mixed-ID, partial, duplicate, wrong-owner, malformed, orphaned, or
nonterminal groups are inert. A Responses `previous_response_id` plus an output
alone is also inert because the plugin cannot prove Host session ownership,
pending-call state, prior consumption, or replay protection.
Historical assistant, system, tool, and unknown-role content remains ineligible
as a referent source and may contribute only bounded inspection or audit
evidence. A bare current-user referent can reactivate only the newest eligible
trusted RoleUser review; tool schemas and assistant tool-call arguments are never
historical referent payloads. An explicit current-user harmful restatement is
evaluated on its own. A structurally proven active request-local system/developer
instruction or terminal tool result may still block its own independently
complete candidate as described above; that is direct candidate evaluation, not
historical referent promotion. Ambiguous or role-less envelopes never gain
request authority.

### Defensive quotation and referential reactivation

A safety review may discount exactly one closed quoted Cyber Abuse referent only
when the surrounding user text proves an unsafe assessment and an exact final
non-execution boundary. The quote is classified independently from the wrapper.
The wrapper never lends its context, signals, evidence, or behavior graph to the
referent.

The exact analytical governor may use a bounded `for ... only,` or `for ...
only:` introduction for defensive incident-response training/analysis (with or
without the compound hyphen), after which the existing `analyze`/`explain`/
`review` proof must still establish risk plus detection/remediation purpose.
This is an enumerated grammar extension, not a keyword exemption: a second
quote, an execution tail, missing boundary, excessive frame, or independently
actionable carrier outside the proven structure receives no suppression.

Provider extraction may split that one original string into natural-language
and fenced content-kind units. Streaming reconstruction is therefore allowed
only for consecutive units with the same nonempty `FieldPathHash`, role,
provenance, attribution, conversation, turn, current-turn flag, and `ScopeID`.
Suppression still requires exactly one closed referent plus the complete
governor, assessment, and terminal boundary. A second referent, missing
governor, split malicious carrier, clause overflow, or over-budget frame cannot
reuse the first referent's credit. Long fields retain only three content-free
frame-signal bits; a complete carrier must independently satisfy the malicious
eligibility gate before it is activated, while a benign carrier remains
nonblocking. An incomplete carrier or unprovable classification budget returns
explicit incomplete coverage rather than a complete allow.

Long-frame signals are generated from the same NFKC, lower-case, homoglyph, and
zero-width-normalized rune view as ordinary classification. A precompiled
Aho-Corasick matcher derives the three coarse bits in one linear pass. The
ordinary classification path exposes its normalized rune view to this matcher
when no compact carry was injected; otherwise the scanner keeps the independent
bounded fallback. A window may emit qualifier bits only after the same
reference- or boundary-stem gate used by the predecessor scanner, preventing a
distant qualifier-only window from completing an unrelated partial frame.

When Chinese, Japanese, Korean, or mixed-language reference, analysis/risk, and
non-execution terms satisfy this gate, they establish ambiguity only. They do
not prove the exact bounded safe-review structure and never grant suppression.
The scanner instead classifies each complete carrier in the same logical field
independently; a carrier cannot borrow signals across field, role, provenance,
turn, or scope boundaries. Benign carriers remain nonblocking, while an
incomplete or unclassifiable carrier makes coverage unavailable.

The three coarse ambiguity bits can accumulate only inside one logical field.
They deliberately remain conservative for overlong multilingual material; the
finite literal vocabulary and same-field distance are fuzzing and Host-review
targets, not permission to relax the exact suppression proof.

If the 64-scope or 64-unit profiled budget is reached, only the logical-field
metadata, those three bits, and a content-free lost-carrier flag cross the
rolling boundary. A complete attempted frame is never silently evicted; lost
carrier text makes coverage explicitly incomplete, while a retained carrier is
reclassified so benign code remains available. Scope-cap eviction first proves
a complete bounded inert review or classifies the retained carrier; fully safe
scopes remain evictable instead of exhausting the 64-scope budget.

Only the newest eligible trusted RoleUser safety review can be linked to one
later user follow-up.
An affirmative referential directive such as `execute it`, `proceed`, or
`go ahead`, including bounded polite or conditional forms, reclassifies only the
quoted referent. The final score, category, rule IDs, evidence, context, and
behavior graph are therefore the same as a direct classification of that
referent. Explanations, meaning/risk/consequence questions, negation, and
remediation do not reactivate it. A review carried by assistant, system, tool,
or unknown-role provenance cannot establish a user referent, and an older review
is discarded when a newer eligible trusted RoleUser review is observed. User
attribution is separate: mixed-trust RoleUser pairs retain conservative direct
classification with `FindingOriginNonUserOrUntrusted`, but cannot enter subject
accumulation.

Each bounded clause retains every recognized active or cancelled occurrence.
The parser walks clauses and occurrences from newest to oldest, so a later
non-alternative prohibition cancels only its equivalent action family. It cannot
erase a different active family (`implement and run; do not run` still blocks),
while separately cancelling every requested family remains inert. Alternative
branches such as `A or do not A`/`otherwise` do not become terminating
cancellations. A coordinated prohibition such as `do not A or/nor B` retains
one negation scope across both action families. Once an `or` arm begins, later
`and`-joined occurrences in that same clause retain the arm's alternative
identity and cannot cancel an active occurrence from the first arm.

The speech-act parser has three outcomes: active, proven inert, and
unrecognized. Common directive governors such as `just`, `simply`, `let's`, and
`let us` are active. A complete explanation, meaning/status/consequence
question, safety deliverable, or explicit negation is proven inert. An
unrecognized complete phrase does not receive inert credit: when exact prior
text is already unavailable, the streaming path still evaluates its bounded
implementation signals and degrades coverage if they can complete a block.

Complete long reviews retain only the privacy-safe `Result` and bounded state,
never the quote or prompt text. A long current follow-up likewise retains only a
bounded affirmative-reference fact. If the review or follow-up crosses a
classifier window and exact linkage cannot be proved, the session returns
`CoverageUnavailable` with `classifier_window_incomplete`; it must not produce
`CoverageComplete` plus allow. Direct referent classification is charged through
the same `MaxChunks` accounting as every other role classification, so an
insufficient budget returns `classification_chunk_limit` rather than bypassing
the limit. Bounded adjacent head/tail classification is skipped when either
field has already proved an inert quoted referent, because removing the other
side of that wrapper would not be an exact semantic view.

The result contains only category, score, action, evidence IDs, aggregate
context flags, the ruleset version, the classifier-policy identity, and a privacy-safe
`BehaviorGraph`. It never contains matched prompt fragments.

`quoted_or_inert_suppressed` is intentionally a request-level diagnostic flag,
not a property of the winning occurrence set. It is `true` when any non-empty
quoted, inert, or trusted carrier content in the inspected request was excluded
from active evidence or was capped to audit. A separate active directive may
still win and block in the same request. Operators must use `winning_role`,
`winning_provenance`, `evidence_occurrence_count`, and
`evidence_segment_count` to interpret the winning evidence; the suppression
flag only confirms that unrelated inert material was not allowed to contribute.
Batch and streaming classification expose the same request-level meaning.

### Wrapper/amplifier separation and behavior graph

The development tree adds `META-OVERRIDE-001` after ordinary category
assessment. It compiles bounded bilingual evidence families for hierarchy
replacement, refusal suppression, unrestricted persona, direct completion,
scope laundering, forced output/authorization bypass, protected-prompt
disclosure, and explicit negative authorization. Independent families must
compose; it is not a single-keyword bypass detector.

Wrapper/control evidence is structurally separate from base behavior. If an
ordinary Cyber Abuse candidate exists, the layer may raise its score while
preserving the original taxonomy and records an amplifier relation. Without a
base candidate, wrapper-only text never produces `defense_evasion` or another
Cyber Abuse category: weak combinations allow, while strong combinations are
capped at the configured audit boundary and remain observe/audit even in
classifier Strict mode. Defensive quoted analysis is discounted only with an
affirmative non-execution purpose and no contradictory continuation.

`BehaviorGraph` is the deterministic relation model behind the result. It uses
stable booleans and edges for requester, action, object, target, destination,
technique, delivery/execution, credential/access, persistence, evasion,
exfiltration, impact, scale, authorization/defensive purpose,
wrapper/amplifier, role scope, carrier, composition mode, and reason codes.
No node or edge contains a prompt span. Rule-local candidates, same-category
composition, and bounded semantic windows all emit through this common model.

Role proof failure on a supported provider body causes a bounded conservative
re-extraction. Tool provenance is inspected independently, nested valid JSON
strings recurse only inside an established tool payload, joined content blocks
are decoded again, and isolated single-character fragmentation has a narrow
reconstruction path. Adjacent user turns and an explicitly linked three-turn
plan may compose; placeholder bindings remain local to the supplied request.
These mechanisms remain stateless across independent API calls and do not
attest to local instruction-file integrity.

Ruleset `1.0.10` identifies the embedded YAML assets only. The complete
code-level behavior is separately identified as `classifier-policy-v9`; its
exact SHA-256 is the canonical current identity in this document's prologue and
`internal/classifier/policy_identity.go`.
Its tested source list binds the classifier, matcher, normalizer, role logic,
wrapper assessment, behavior graph, semantic composition, bounded extractor,
rule loader/schema, embedded YAML assets, and module dependency locks. The
identity is returned in classifier results and exposed by authenticated status.

Mode semantics are:

- `off`: skip extraction, classification, audit, and risk accumulation;
- `observe`: classify and update counters only; never block or persist events;
- `audit`: classify and persist minimal events; never block;
- `balanced`: only an eligible malicious-text candidate may be compared with
  `balanced_block`; incomplete or ineligible risk allows and audits;
- `strict`: shares the same malicious-text eligibility gate and may use its own
  configured eligible-candidate threshold; inspection-incomplete requests may
  be blocked only as `block_incomplete_inspection`.

Thresholds, score composition, semantic cores, wrapper/meta control, and hard
floors apply only after candidate eligibility. A standalone active current-user
meta-override candidate may retain the bounded `defense_evasion` /
`META-OVERRIDE-001` winner only when it independently passes that same gate;
historical, quoted, defensive, or otherwise ineligible wrapper text remains
audit-only.

The mode definitions intentionally take precedence over the task book's
non-binding suggested statement that a score of 80 blocks every non-off mode;
otherwise `observe` and `audit` would not mean "never block", and score would
incorrectly create eligibility.

## Subject risk control

Subject selection is ordered:

1. the downstream bearer/API key on the CPA-authenticated request, immediately
   HMACed in memory;
2. an anonymous bucket.

The anonymous identity is never admitted to rolling subject state. Anonymous
requests still receive the same direct classifier/transport disposition, but
cannot allocate a shared bucket or accumulate cross-request risk across users.

CPA schema 2 does not supply a distinct authenticated principal/key-policy ID or
a trustworthy direct-peer address to RequestInterceptor. The Guard therefore rejects
`trusted_proxy.enabled: true`; forwarded headers alone are spoofable and are
never accepted as identity.

Plain API keys and IP addresses are never stored. The HMAC key comes from
`CYBER_ABUSE_GUARD_HMAC_KEY` or an explicitly configured mode-0600 secret file.
If no key is available, process-random key material is used and status reports
that hashes will not be stable across restarts. On Linux, a configured secret
file is opened with `O_NOFOLLOW`; its type, permissions, size, and contents are
validated through that same descriptor to prevent final-component symlink and
path-swap races.

Subject control is disabled by default and request interception does not enter the
identifier/controller path unless `subject_control.enabled: true` is explicit.
The domain-separated request digest is computed lazily only for an eligible
accumulating subject hit, a final block pending key, or a persisted audit event
whose configuration includes `log_request_hash: true`. A read-only subject
lookup never hashes the request body.

Risk entries are in-memory rolling windows with time decay. A hit, request
receipt, and repeat multiplier are added only when every admission condition is
true: the identity is authenticated rather than anonymous; extractor and
classifier coverage are complete; finding confidence is
`FindingCompleteRequest`; the winning finding origin is the closed,
text-free `user_content` value; the behavior graph contains `BaseBehavior`;
the classifier returned an eligible `block_malicious_text` decision; and the
score is at or above the configured `hard_block` threshold. Every system,
assistant, tool, tool-payload, roleless, unknown, mixed-role, or
lower-confidence finding is ineligible for subject accumulation. A structurally
proven active system/developer instruction or terminal tool result may still
produce its request-local malicious-text block, while the other non-user cases
remain inert or auditable. A Strict incomplete/opaque request decision is a
separate disposition and never supplies a malicious winner or subject hit.

User authorship is a separate, zero-value-untrusted transient proof rather than
an inference from `RoleUser`. The extractor marks it trusted only for recognized
model-visible `content` / `parts` / `refusal` below one explicit valid
`role: user`, or for a profile-allowlisted multipart prompt. Unknown top-level
fields, unknown message siblings, roleless/future items, non-user roles, tool
definitions, tool arguments, and tool output remain untrusted. Multi-field or
multi-turn findings receive `user_content` only when every contributing
user-like field carries the trusted proof; unrelated untrusted fields do not
erase a separately winning trusted user finding.

Non-accumulating observations never allocate state or add a hit, receipt, or
multiplier. A non-accumulating risky candidate at or above the audit threshold
may read an already active cooldown/manual-block disposition, while an ordinary
score below the audit threshold remains safe even for a previously cooling or
manually blocked subject. Expired inactive state is pruned during this lookup.
Manual blocks can be cleared through the authenticated management API.

Risk accounting is idempotent per subject and domain-separated request digest.
The same logical request crossing before/after-auth interception and legacy executor methods, retrying, racing
concurrently, missing or expiring from the pending cache, or surviving an
enabled-to-enabled reconfigure contributes at most one risk hit inside the risk
window. Receipt metadata is bounded with the hit window and can be restored
from the optional subject snapshot; older snapshots without receipts remain
readable. If the bounded receipt capacity is exhausted, the controller refuses
to evict a still-live receipt merely to count a retry again.

`subject_control.max_subjects` bounds state cardinality and defaults to 10,000.
The controller keeps non-manual entries in least-recent-risk order and evicts
the oldest when capacity is needed. Manual blocks are never capacity-evicted;
if they consume all capacity, a new risky subject is blocked with
`subject_capacity` rather than admitted without state. Status exposes current
capacity through `subject_control`: `subjects`, `max_subjects`,
`manual_blocked`, `evicted`, and `rejected_capacity`.

### Optional subject persistence

Persistence defaults to disabled. With `subject_control.persistence: false`,
all risk, cooldown, and manual-block state is process-local and intentionally
resets on CPA restart. Enabling persistence requires subject control, audit
storage, a stable HMAC secret, and `max_subjects <= 10000`.

The persistent type can represent only an HMAC subject, score/hit timestamps,
cooldown, and manual state. It cannot represent a plaintext credential. A
bounded snapshot replaces prior subject-state rows atomically. Restoration
validates schema and key fingerprint, rejects duplicate or malformed hashes,
applies expiry and time decay, then enforces the current capacity. Expired and
over-capacity rows are counted in status.

The loader detects schema/type/version errors, malformed or duplicate HMAC
subject IDs, row/payload mismatches, and invalid bounded state. The snapshot is
not protected by a separate keyed whole-snapshot MAC, so it does not prove
completeness or authenticity against an actor who can write the SQLite file.
Such an actor can delete otherwise valid rows. Production filesystem ownership
and mode controls therefore remain part of the persistence trust boundary.

Writes are debounced and periodic, and a bounded shutdown save is attempted.
Database failure degrades persistence while in-memory rule enforcement
continues. A different HMAC key produces an explicit key-mismatch state and
blocks persistence writes, preserving the old snapshot for operator review
instead of silently replacing uncorrelatable identities.

### Dual-key rotation design (not implemented)

The current implementation supports one active HMAC key only. A future safe rotation mechanism must
be an explicit state machine:

1. configure one active key and at most one previous read-only key;
2. expose only domain-separated key fingerprints in authenticated status;
3. accept old persisted subjects only during a finite, operator-configured
   overlap window and keep them in a bounded transition map;
4. compute every new subject ID and persistence write with the active key;
5. never compare plaintext credentials across keys or log either key;
6. finalize rotation explicitly, remove the previous key, and atomically drop
   unmigrated old-key state after an operator-reviewed backup.

Until that mechanism exists, normal upgrades must preserve the current key.
Changing it is a correlation reset, not a transparent rotation.

## Audit store

When enabled, SQLite stores only the minimal event schema. The database uses
WAL, a busy timeout, parameterized SQL, bounded asynchronous writes, retention
cleanup, and a configured maximum size. A database open/write failure degrades
to in-memory counters and rate-limited host-error diagnostics; classification
continues. Shutdown has a five-second runtime budget so a locked SQLite writer
cannot indefinitely stall plugin reconfiguration or shutdown.

A complete non-user/untrusted category-free wrapper-only
`audit_suspicious_text` result with no opaque media is a counter-only
observation by default. It increments the fixed
`audited` and `control_plane_meta_override` counters without deriving request or
subject hashes and without enqueuing a SQLite event. This narrow fast path never
applies to trusted-user wrapper evidence, a Cyber Abuse base behavior, block,
incomplete inspection, or opaque media. `audit.persist_wrapper_only: true`
explicitly restores the legacy
per-request event stream for wrapper-only observations.

New database directories are created with mode 0700, but the plugin never
changes permissions on an existing operator-owned directory. Database, WAL,
and shared-memory files are restricted to mode 0600. Existing directories with
group/world write bits, final database-directory symlinks, and database/WAL/SHM
symlinks are rejected; runtime permission failures make audit status visibly
degraded. Operator-selected ancestor paths remain part of the deployment trust
boundary.

Before any upgrade that crosses into audit schema v6, the plugin creates a
mandatory SQLite online snapshot even when the legacy
`audit.backup_before_migration` switch is false. The database and its JSON
manifest are first built below a same-filesystem mode-0700 staging directory,
verified with `quick_check`, changed to mode 0400, synced, and only then
published through no-overwrite hard links. The manifest binds the backup name,
source and target schema, byte count, SHA-256, quick-check result, and exact
snapshot status. Backup retention removes each old database and its paired
manifest together. A complete rollback copy is therefore not temporarily
exposed with SQLite's default creation mode in a 0755 data directory.

An RPC rejected by the native no-copy size guard has no safely available body,
model, source format, or request hash. When audit is enabled, the plugin records
a minimal `scan_limit` event with `text_bytes_scanned: 0` and does not invent
those unavailable fields.

By default no prompt, message, authorization header, plaintext subject, token,
cookie, OAuth material, user code, or upstream account identity is persisted.
The sole explicit exception is `audit.raw_capture.enabled`: after a final
blocking decision (`block`, including subject cooldown) it may persist a
separately stored, mandatory-redacted preview bounded
by `max_bytes` and `ttl_hours`. Allowed, observed, and audit-only requests never
enter that table. Request correlation uses SHA-256 of the raw body. Subject
correlation uses HMAC-SHA256.
Requested models use a separate `cyber-abuse-guard/audit/model/v1` hash domain
and `sha256-model-v1:` prefix. Source format is restricted to the canonical
`openai`, `openai-response`, `interactions`, `openai-image`, `openai-video`,
`claude`, `gemini`, or `unknown` enum. Legacy
database reads are sanitized before query or CSV output.

The database schema is versioned. `schema_version` records the active schema;
`migration_history` records every applied version. A v0.1.1 event database with
no metadata is recognized as schema v1. The schema-v2 migration adds optional
subject-state tables; schema v3 adds the fixed decision/coverage fields; schema
v4 adds the separate `raw_request_captures` table, its event foreign key with
`ON DELETE CASCADE`, and bounded query indexes; schema v5 adds the closed
Round 8 explanation and raw-capture deduplication metadata; schema v6 splits
the original disposition from the canonical Round 9 `decision_kind`, adds the
explicit explanation schema identity, and carries those identities into Raw
Capture. Migrations run inside one writer transaction. On failure, the old
schema remains intact and the already-published pre-v6 snapshot remains
available for recovery. Backups are capped by
`audit.max_migration_backups`, paired with their manifests, and are never
placed in a release archive.

In the SQLite `audit_events` table, schema v6 stores the canonical decision kind
in the historical `decision` column and the transport/mode disposition in the
new `disposition` column. Public Go/JSON/CSV surfaces keep the operator-facing
names: `decision` is the disposition and `decision_kind` is the canonical kind.
The mapping is deliberate compatibility behavior and is covered by query and
export tests. Historical schema-v5 rows migrate to
`decision_kind=legacy_unspecified`; they are not guessed from score, category,
or disposition text. The four v2 explanation variants are `malicious`,
`incomplete`, `opaque_media`, and `subject_risk`. Non-malicious variants cannot
carry classifier rule IDs, categories, score components, or eligibility state.

Schema v6 cannot be opened by an older SO whose supported schema is v5. An
operator rollback must stop CPA, verify the `.bak.manifest.json`, preserve the
v6 database for incident review, and restore the matching
`.pre-v6-*.bak` database before loading the older SO. The old SO must never be
started against the v6 database or its WAL/SHM sidecars. The complete procedure
and verification commands are in [Round 9 audit schema v6](ROUND9_AUDIT_SCHEMA_V6.md).

Existing schema objects are accepted only after exact column name/order/type/
nullability/primary-key, required CHECK fragment, index column/direction,
singleton version-row, and contiguous migration-history validation. This is a
structural contract, not a keyed proof that no otherwise valid row was deleted.

`audit.log_original_text` remains in the compatibility schema only to reject
unsafe input. A value of `true` prevents activation or reconfiguration. There
is no debug or emergency mode that persists unrestricted raw request text.
The replacement review facility is `audit.raw_capture`: it defaults off,
requires audit storage, requires `only_blocked: true` and
`redact_secrets: true`, redacts before UTF-8-safe truncation, and applies a
separate capture TTL no longer than the ordinary audit retention period. See
[Blocked-request review capture](RAW_CAPTURE.md).

Reconfiguration builds and validates a complete immutable runtime state before
an atomic swap. Invalid configuration leaves the last valid state active. This
requires a CPA-specific behavior: `plugin.reconfigure` still returns the valid
registration envelope after a rejected update, because returning an RPC error
would make CPA omit the plugin from its next active snapshot. Status exposes
the rejected update as `last_config_error` and the plugin logs it through the
host logging callback.

Compatible enabled-to-enabled reconfiguration reuses the subject controller,
preserving rolling risk, cooldowns, and manual blocks. Capacity shrink evicts
only non-manual entries and is rejected atomically if the requested limit is
below the number of protected manual blocks. Disabling subject control clears
its process-local state. `started_at` remains the original process-runtime
timestamp across compatible hot reload, while `configured_at` records the most
recent successful configuration.

## Management routes

Only CPA management routes are registered; no unauthenticated resource page is
exposed.

- `GET /plugins/cyber-abuse-guard/status`
- `GET /plugins/cyber-abuse-guard/events`
- `GET /plugins/cyber-abuse-guard/raw-captures`
- `GET /plugins/cyber-abuse-guard/stats`
- `POST /plugins/cyber-abuse-guard/test`
- `POST /plugins/cyber-abuse-guard/health/probe`
- `POST /plugins/cyber-abuse-guard/subjects/unblock` with
  `{"subject_hash":"..."}`
- `DELETE /plugins/cyber-abuse-guard/events`

CPA mounts these below `/v0/management` and enforces its Management Key before
the plugin handler runs. The test route does not persist its input.

`GET /events` response schema v2 includes `audit_schema_version` and accepts the
fixed `decision_kind` filter. Raw Capture response schema v4 exposes the same
schema identity plus its fixed decision/explanation semantics. Authenticated
management mutation markers use `decision_kind=allow_clean` rather than the
historical `legacy_unspecified` identity; they contain no request text and no
malicious explanation.

The audited CPA ABI management routes are exact matches and reject `:` or `*`, so the
task book's suggested `{hash}` path parameter cannot be registered safely.

CPA's Management Key middleware is the authentication authority. The plugin
adds bounded body/query/method guards but cannot independently compare the
configured Management Key because ABI v1 does not expose it. A normal client
key therefore cannot authorize these routes, and deployment tests must verify
the host's 401 behavior. Ordinary responses never include prompt text or
plaintext subjects. The exact authenticated `/raw-captures` route is the only
exception and returns only enabled, redacted, truncated block-review previews.

The plugin rejects a management body above 1 MiB and a serialized RPC envelope
above 2 MiB. These are plugin-side limits only: CPA currently calls `io.ReadAll`
inside `ServeManagementHTTP` before invoking the plugin. A reverse proxy must
therefore enforce the HTTP request-body ceiling, and the server sandbox must
prove that an oversized request receives 413 before CPA reads it.

## Failure behavior

- invalid initial config: plugin registration fails visibly;
- invalid reconfigure: keep the previous state, expose/log the error, and return
  the current valid registration so CPA keeps the plugin active;
- rule load/validation failure: registration/reconfigure fails;
- malformed request: allow and optionally audit `parse_error` outside `off`;
- RPC beyond the native copy budget: a request-interceptor callback terminates only in
  Strict; Balanced/Off/Observe/Audit pass through after recording the applicable
  incomplete-inspection counters/event. If an executor callback is nevertheless
  invoked directly, Strict returns the local policy 403 and every non-strict
  mode returns a local 413 size error;
- audit failure: continue classifying and blocking;
- panic in request interception: increment counters and, when a validated
  Balanced/Strict runtime is active, return a successful direct termination so
  CPA cannot fall through to auth/provider selection; non-enforcing/no-runtime
  cases deliberately return pass-through;
- panic in another ABI method: recover, return a parseable internal error, and
  retain the non-zero ABI failure signal;
- optional external classifier: interface reserved but not implemented.

CPA owns the host fail-open policy. A plugin that is absent, fails registration,
is fused, or returns an interceptor RPC error can be skipped while later
interceptors and native execution continue. The Guard therefore converts known
panic, shutdown, malformed-envelope, and guarded runtime failures into a valid
mode-aware interceptor response. An earlier interceptor may terminate the chain
before Guard runs or rewrite the representation that Guard inspects; a later
interceptor may rewrite the request after Guard has inspected it. Equal priority
is ordered by plugin ID ascending. Production must allowlist the interceptor
inventory and verify that no untrusted post-Guard mutator is active. No
in-process plugin can prove that every host or ABI failure will be fail-closed.
The authenticated status exposes `loaded`, `enforcement_ready`,
`router_errors` (the compatibility aggregate for Router/interceptor protocol
failures), `panics_recovered`, audit/HMAC/persistence degradation,
reconfigure error, build/ruleset identity, and the classifier-policy
version/hash. The read-only production watchdog checks those fields and runs
built-in local-only probes. The ABI cannot enumerate interceptor ordering or
scan the plugin directory, so earlier interceptor conflicts and duplicate `.so`
versions remain mandatory operator checks.
`enforcement_ready` reflects plugin-internal runtime state only; it does not
prove host load/registration, non-fused state, ordering, or per-request callback
delivery.

## Verification strategy

Unit tests cover extraction limits, scoring, modes, bilingual and obfuscated
inputs, hard-block exceptions, subject decay/cooldown, config rollback, SQLite
privacy, management handlers, and ABI envelopes. Separate corpora contain at
least 100 benign security prompts and 100 clearly malicious operational
prompts. Benchmarks report classifier latency and allocations.

The visible `testdata/development-adversarial-v11-prep` corpus adds 35
development cases: 16 block, 14 allow, 2 audit, and 3 resource-boundary
fixtures. It covers all eight taxonomies, four provider protocols, English,
Chinese, mixed language, role-aware and untrusted extraction, wrapper-only and
wrapper-plus-behavior, multi-turn/refusal continuation, tool payload/output,
bounded encodings, placeholders, and scan/part boundaries. Its validator checks
schema, taxonomy, IDs, duplicates/near-duplicates, balance, coverage,
production extraction, recovered semantics, and action/category. It is marked
development-only and must never be reused as a future Holdout.

The safe broad Go gate uses `scripts/go-safe-development-test.sh` in `test`,
`race`, and `boundary` modes so routine development verification does not open
consumed v4-v9 fixtures. Broad `go test ./...` is not an acceptable substitute.

Both v7.2.104 compatibility contract modules first prove that the named critical
upstream Host tests still exist and then each executes the complete upstream
`internal/pluginhost` package for the current platform. Their CI coverage is
intentionally overlapping; it is neither an exact-name-only run nor a pair of
non-duplicative contracts. The plugin-store module also calls the official
`pluginstore.InstallArchive` for both synthetic bytes and, when supplied, the
real build artifact. These checks cover store naming, root-only library layout,
checksum, installed path/bytes, repeat installation, tamper repair, priority
ordering, and documented Host fallback. They remain source/installer
compatibility evidence. Current admission requires the v7.2.104 counted-Mock
Host run on the same candidate and independent verification.

The integration harness builds the `.so`, builds CPA at the pinned commit,
starts a local mock OpenAI-compatible upstream, and starts CPA with the plugin.
It installs the real store ZIP, loads the installed Guard, and asserts that safe
requests carry a valid CPA credential-selection trace, cross Provider execution
and Mock Upstream, and increment Usage, while blocked requests terminate in the
schema-2 before-auth callback and expose no credential-selection trace, CAG
executor call, Provider call, Usage event, Mock Upstream call, or SSE headers.
The local harness does not claim a counted Auth Selector delta; that remains a
protected exact-candidate counted-Mock requirement. It covers OpenAI Chat, OpenAI
Responses, Anthropic, and Gemini non-streaming/streaming paths, pre-SSE 403,
token-count 403 where exposed, adapter-level nil-response/status-error 405 for `http_request`, safe model/body
and tool preservation, management authentication, reconfiguration, role-aware
follow-ups, encoded tool payloads, a Base64-expanded RPC above 8 MiB, and
disabled-plugin recovery.

The 2026-07-27 working-tree report records a real local CPA v7.2.102 Host and
Router run for a generated Linux amd64 `0.16-dirty` `.so`. That result proves the
development artifact exercised the reported loopback/Mock paths; it is not a
clean exact-main candidate, protected counted-Mock record, independently audited
artifact, release admission, or production approval, and it cannot be carried
forward to different bytes.

A separately compiled schema-1 Router/executor fixture remains an explicit
legacy compatibility lane. It exercises priority, invalid targets, missing or
disabled Guard state, registration failure, route error, and executor
identifier/format/scope readiness, while the schema-2 Guard interceptor still
blocks malicious requests when registered. Host fuse and pre-result panic remain
pinned to official source-overlay tests; the fixture does not use a process
crash as a false substitute for a recoverable plugin panic.

Historically, the Host/Router targets and management-proxy fixture were mistakenly executed
once in WSL outside the authorized evidence path. They used loopback/Mock
components only and cleanup left no fixture process, but the results are
excluded: `LOCAL MIS-EXECUTION RECORDED / EXCLUDED; CI REQUIRED / NOT YET
AUTHORITATIVE`. Separately, an earlier CPA v7.2.72 exact-freeze GitHub CI passed
the historical Host/Router/proxy matrix. Neither result validates the current
Round 9 candidate. The exact-candidate counted-Mock Host matrix and independent
verification remain not run.

The following v0.15 artifact lifecycle is retained as historical Round 6
evidence and does not authorize the Round 9 prerelease:
the final PR head passes PR CI, merges to `main`, and the exact resulting main
commit/tree passes push CI without producing a release; the private untagged
candidate workflow is then dispatched from `refs/heads/main` and produces clean
SO/Store ZIP bytes plus `candidate-manifest.json`; the CPA v7.2.88 Host record
and the independent audit bind that SO SHA-256. Historical attestation schema v2
records the Host identity and evidence hash as `cpa_version`, `cpa_commit`, and
`cpa_host_sha256`; an
annotated development prerelease is optional; the annotated formal `v0.15` tag
and verified draft remain separate; and protected promotion may publish only
that unchanged draft. `InstallManifest` must prove first install and real Host
load, while `TestPublishedStoreArchive` verifies repeat-skip and tamper-repair.
Missing `.so`, Store ZIP, metadata, checksums, or candidate manifest must fail;
synthetic fallback cannot satisfy Host evidence.

Whether the authorized sandbox and independent auditor ran the suite against the
exact candidate is an evidence field, not an architectural property; consult
the Round 9 execution record, the historical Round 8 readiness report, and the
explicitly historical Round 6 handoff.
Release verification inspects the ELF and rejects a binary whose imported glibc
symbol version exceeds `GLIBC_2.34`. The published artifact therefore requires
glibc 2.34 or newer, is compatible with the official Debian Bookworm CPA image,
and does not support musl/Alpine runtimes.

For streaming blocks, the executor returns the 403 error before a stream is
established. CPA closes the request promptly with a protocol-compatible regular
error response. ABI v1 cannot simultaneously send HTTP 403 and establish an
SSE stream with terminal frames; returning successful chunks would force HTTP
200, so the Guard chooses the genuine pre-stream 403.

## Build identity and release reproducibility

Builds link immutable version, full commit SHA, ruleset version/hash,
`classifier-policy-v9` and its exact policy SHA-256, streaming-scanner identity,
and dirty state. Build metadata and the verifier bind
these identities. Candidate mode requires a clean worktree, exact expected
commit/tree, the commit timestamp, an absent stable `v0.16` tag, and forbids
formal operations. The Round 9 RC workflow may create only the non-latest
prerelease `v0.16-rc.4`. `ALLOW_DIRTY_BUILD=1` remains development-only and
cannot produce the Host-test candidate.

`SOURCE_DATE_EPOCH` derives from the commit timestamp; clean candidate and formal
builds reject a different override.
Builds use `-trimpath`, a pinned Go toolchain, deterministic ZIP ordering and
timestamps, strict file allowlists, and a canonical ruleset manifest. The CPA
store ZIP contains exactly one root mode-0755 `.so`; documentation, metadata,
SBOM, and operational material live in a separately named audit bundle.
CycloneDX SBOM and checksums are verified against source and cover both ZIPs.
The candidate reproducibility gate builds in two clean clones and byte-compares
the `.so`, Store ZIP, metadata, ruleset identity, and SBOM without packaging an
audit bundle. The formal gate separately covers the audit bundle and source
archive.

Formal source and audit bundles exclude evaluation, Holdout, private, blind,
and retired material. Only low-sensitivity external evaluation identity/hash and
release-attestation files cross that packaging boundary.

These mechanisms make evidence reproducible; they do not turn a failed safety
gate into a release. v1-v8 are retired or consumed failures, v9 is a consumed
methodology-invalid failure, and methodologically valid v10 is a consumed
formal failure. Historical 0.1.2, v0.15, and Round 8 evidence remains frozen.
Round 9 is blocked from production approval until the exact candidate passes
the required independent audit, the protected CPA counted-Mock Host gate, and
the remaining release admission policy; historical restricted evidence cannot
be rerun, renamed, or supplied as new evidence.
