# Public jailbreak repository review

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: 6cd7296bee90b9352a9cf1745b7760c0ff1b18a265da4af498c5877d4b542f87
```

Last updated: 2026-07-26 (Asia/Shanghai)

## Scope and safety boundary

This review covers public prompt-override projects that can change the
high-authority instructions seen by CPA-routed model requests. Repositories were
inspected as untrusted bytes and metadata only. No repository code, script,
workflow, installer, hook, dependency, application, binary, or embedded
instruction was executed.

The current development corpus is frozen at:

| Property | Frozen value |
|---|---|
| Path | `testdata/round9-public-adversarial-v13/manifest.json` |
| Manifest identity | 481448 bytes; SHA-256 `91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6` |
| Schema / dataset | `round9-public-adversarial-corpus/v13` / `round9-public-adversarial-v13` |
| Payload records | 24 |
| Formal unique payloads | 23 |
| Historical unique payloads | 8 |
| Branch-head payloads | 1 |
| Current prompt-like payloads | 14 |
| Unmerged candidate carriers | 1 |
| Active behind non-default branches | 5 |
| Formal Release assets reviewed | 16 total; 4 with prompt entries |
| Release asset metadata frozen | 199 total; GitHub metadata/digest only; none downloaded or opened during v13 |
| Serialized contexts | 5 per scenario payload, 120 total |
| Methodology flags | `development_only=true`; `independent_holdout=false`; `third_party_code_executed=false` |

The v13 manifest is visible development regression data, not blind, holdout,
independent, production, or attack-origin evidence. Its frozen `queried_at` is
part of the manifest identity. V12 remains byte-for-byte history at 485221 bytes
and SHA-256
`eb72fd7b88c052c6af98c97636c18aba96f499597741bcba262dda59de3c2387`;
v11 and earlier identities also remain immutable history.

The repositories were live rechecked through authenticated, read-only GitHub
metadata at `2026-07-24T23:47:18+08:00`. Since v12, MDX advanced from
`cccbfae8a75c948bde22407dd07de7af88731d9b` to
`61feb6a1940bd1d58163c2550869a0a9aed2ddc1`; the other three repository
snapshots remained unchanged. The refresh therefore received a new v13
identity even though no standalone prompt payload changed or was added:

The MDX delta contains five current changed-or-added Star History data,
maintenance-source, workflow, and test blobs. Two removed source paths are
recorded path-only; no current blob identity is fabricated for them. All 19
previously frozen MDX payload-source paths remain byte-identical.

| Repository | Default HEAD | Branches | Open PRs | Tags | Releases |
|---|---|---:|---:|---:|---:|
| `Jia-Ethan/codex-keysmith` | `700f1be22446af4dc2c362080cbde669e215094d` | 5 | 0 | 2 | 2 |
| `MDX-Tom/gpt-5.6-instruct` | `61feb6a1940bd1d58163c2550869a0a9aed2ddc1` | 1 | 0 | 2 | 2 |
| `yynxxxxx/Codex-X` | `e8b0e5b73c508484cfb636339c82d70360487442` | 2 | 0 | 37 | 36 |
| `yynxxxxx/Codex-5.5-codex-instruct-5.5` | `ed0b6dc37d1994e93788d92f7af63f58bf0b9e2d` | 1 | 1 | 0 | 0 |

### Supplemental NERV evidence

`lingbol088-spec/5.6-JAILBREAK-NERV` is tracked as a fifth, supplemental
development source at commit
`11430ee4771186df401c8eac0b49cfb9f5537185` and tree
`b1ab2db990c7e038de1c34ad17e912a01f8fb173`. It is not inserted into the
immutable v13 corpus and no repository code or payload is copied into the
production ruleset.

The 2026-07-26 isolated report tested the older CAG source baseline
`fdb47a99c3b38336e00ded6de3208c796f19c31f` against CPA
`v7.2.100@27fc3169`. It recorded 78/88 raw texts, 135/160 activated carriers,
294/480 explicit-malicious combinations, and 117/120 tool-carried explicit
malicious combinations reaching counted-Mock. Eighteen blocks were incomplete
`scan_limit` decisions and are not semantic success. This is failure evidence
for that exact older artifact, not proof about the current working tree or CPA
v7.2.102 Host compatibility.

Current source regression uses disarmed, repository-neutral intent classes in
`internal/classifier/nerv_repository_regression_test.go`,
`internal/classifier/nerv_carrier_matrix_regression_test.go`, and
`internal/plugin/nerv_repository_regression_test.go`. It covers credential and
session theft, covert persistence/C2, monitoring evasion, ransomware impact,
phishing deployment, covert keylogging, unauthorized exploitation, and
post-exploitation exfiltration through trusted user, request-local
system/developer, and provider-native terminal tool-result carriers. The
long-field matrix places malicious cores at the front, middle, and back of a
roughly 7 KiB risk-rich but inert catalog and exercises OpenAI Chat, OpenAI
Responses, Claude, and Gemini system and terminal-tool routes. Balanced/Strict
and batch/stream parity are required. Repository names, approved remote-access
documentation, detector/scanner authoring and detector deployment, credential-
exposure alert triage, consented accessibility telemetry, and closed incident-
response review remain non-blocking; an independent instruction to create or
deploy the malicious agent still blocks. Provider-specific adjacent complete
transactions, one-to-one IDs, Responses subtype identity, result-owner roles,
canonical Chat function shape, exact result boundaries, and closed Gemini
matching ID+name or ID-free name+ordinal groups are separately covered by
extraction, classifier, and routed audit regressions. Gemini `result`, `output`,
and other string descendants below the exact `functionResponse.response` object
are eligible only after that transaction proof; siblings outside `response`
remain untrusted. Claude text blocks may retain CPA v7.2.102 `cache_control`
objects, but metadata strings inside that object never gain result authority.
Responses continuation outputs remain non-authoritative
without a same-request call because Host session/pending/replay state cannot be
proven. These are local development assertions only;
five-repository counted-Mock coverage remains pending an exact-main independent
rerun.

The local matrix does not replay the report's 88 frozen raw files, its selected
40-file activation family, or its 20 real approximately-7-KiB chunks. It also
does not reproduce the five-repository counted-Mock runner or bind the external
case/result files to this source tree. Those remain independent Host-evidence
requirements and must not be inferred from synthetic source tests.

The sole open PR remains Codex-5.5 PR #9 with head
`3b64052a7706626b47bd66fde74d43f8b80e020d`; it remains an
`unmerged_candidate_carrier` and is not represented as default-branch output.
Five behind non-default branches are recorded separately and do not create new
formal payload identities. The new Codex-X `v0.3.1` tag is frozen at
`5b6655754d578a4b303bea3df0844d8c932e0f4e`; its five prompt files are
byte-identical to main and `v0.3.0`. All 199 enumerated Release assets retain
only GitHub metadata and server-provided SHA-256 digests in the v13 refresh;
none was downloaded or opened. The 16 earlier bounded asset reviews remain
inherited v10 provenance rather than a new binary inspection. Historical
v1-v12 corpora remain immutable and are not relabeled as v13.

The production rule set does not contain repository names, release names, file
hashes, or complete third-party prompts. Tests use repository-neutral, disarmed
surrogates so a renamed or lightly edited template does not bypass the Guard and
ordinary discussion of these projects is not treated as abuse.

## CPA-visible attack surfaces

The common CPA-visible carriers are:

1. OpenAI Responses root `instructions`;
2. chat `system`, `developer`, `assistant`, or `tool` messages;
3. Chat/Responses function and custom-tool descriptions, including legacy
   `functions[]`;
4. CPA v7.2.102 Codex Desktop
   `input[].type="additional_tools"`, including
   namespace-nested MCP/custom tools;
5. persisted model-instruction or managed `AGENTS.md` content;
6. function/custom call arguments and tool output;
7. user text containing role-tag forgery, adjacent fragments, or encoded wrappers.

The source material also contains candidate-rich 1,397-17,166 decoded-byte
templates. Several templates enumerate many cyber domains in one fixed instruction
block. Classifying
that catalog as the user's current credential, malware, phishing, exploitation, or
evasion intent would block every benign request that carries the template and could
poison subject risk.

## Disposition contract

- A wrapper-only request with a harmless or benign current task is at most an
  audit finding and must remain HTTP 200.
- A proven current user explicitly requesting persistent instruction-file
  override remains a local hard block; non-persistent wrapper-only controls do
  not become cyber-abuse taxonomy by themselves.
- A wrapper plus an independent, complete malicious cyber request from a proven
  current user is blocked locally and may accumulate subject risk.
- Historical assistant output, non-terminal tool output, tool schemas, tool-call
  arguments, and unknown payloads remain inert unless a later trusted current
  user supplies a complete bounded reactivation proof.
- A current request-local system/developer field or provider-native terminal
  tool result may block only when one unique, complete field owns the full
  malicious candidate, proves an explicit uncancelled execution act, retains
  exact request-local scope, and passes the ordinary eligibility gate. It never
  becomes current-user evidence and cannot add user subject risk.
- Quotation, static review, incident analysis, explanation, detection, and explicit
  non-execution requests remain allowed.
- Repository names, a single mode label, or a single security-domain word are never
  sufficient block evidence.

## Repository-neutral coverage

The frozen v13 manifest carries 24 scenario payload records and five serialized
contexts per payload. Its direct-current-user ground truth is split between 12
`block_malicious_text` and 12 `allow_or_audit` cases; repository origin never
creates block eligibility. Static identity validation is development evidence
only, and the final static validator rerun remains `PENDING_LINUX_RERUN`. Final
classifier scenario results remain `PENDING_FINAL_SOURCE_FREEZE` and
`PENDING_LINUX_RERUN`; counted-Mock results for the v13 payloads are `NOT_PROVIDED`.

The regression matrix covers these observed control families without copying a
live prompt:

- instruction-hierarchy replacement and default-constraint override;
- refusal suppression and disabled-filter claims;
- safety-priority inversion and authorization laundering;
- concealment of the active mode or instruction source;
- fixed prefixes, continuation markers, classification-boundary splits, and
  neutral padding;
- maximum-permission personas and unapproved autonomous tool execution;
- persistent instruction-file changes;
- defensive quotation and benign near-neighbors.

Each of the four active control families is routed through 17 exact non-user
carrier shapes: Responses instructions; Chat system/developer/assistant/tool;
Chat assistant tool calls; Chat nested and legacy function descriptions;
Responses function/custom descriptions; CPA `additional_tools` function and
namespace/custom definitions; Responses assistant history; function/custom calls;
and function/custom outputs. Every carrier verifies both wrapper + benign user
allow/audit behavior and wrapper + independent malicious trusted-user blocking.

The supplemental NERV matrix is intentionally separate from those four frozen
control families. It validates selected repository-neutral semantic gaps
reported by the fifth source without replaying its raw corpus, changing v13
identity, or teaching repository names as signatures. Its
tool cases use an OpenAI assistant `tool_calls` item followed by a matching,
terminal `tool_call_id` result rather than an isolated synthetic `role=tool`
message. Additional provider-long cases use each provider's native adjacent,
complete call/result transaction; they do not grant authority to arbitrary
`tool`, `name`, `id`, `call_id`, or unknown sibling fields. Only the exact
provider-native result text path can carry request-local tool authority.

Decoded-text coverage includes 1,397, 1,743, 4,575, 5,137, 7,899, 10,198, 13,641,
16,383, 16,384, 16,385, and 17,166 bytes. Existing Round6 tests separately cover
32 KiB role windows, the 256 KiB compatibility boundary, multi-megabyte fields,
and more than 64 logical role segments.

## Attribution hardening

User-origin subject risk now requires a closed provider-aware proof:

- only a SourceProfile-matched root history container can establish a trusted
  user role;
- OpenAI Responses root scalar `input` is a trusted user carrier;
- exact CPA v7.2.102 Codex Responses Lite `additional_tools` items,
  including the
  official `role: developer` sibling, are system-originated and untrusted, while
  a following exact Responses user message remains trusted;
- type-derived Responses call/output/reasoning/additional-tools items cannot add
  an explicit `role: user`; the conflict makes role attribution incomplete;
- root `instructions`, valid provider system fields, developer messages, tool
  payloads, function responses, unknown content types, cross-provider envelopes,
  and nested histories remain non-user or untrusted;
- a failed role-aware parse clears all tentative user attribution;
- compatibility scanning beyond 64 segments preserves attribution;
- an independent trusted-user hard winner wins an otherwise exact result tie, so
  a preceding non-user catalog cannot suppress subject accountability.

Sanitized repository material frequently appears inside a safety review. That
review can make exactly one closed quote inert only while its unsafe assessment
and final non-execution boundary remain intact. A later affirmative user
follow-up such as `execute it`, `proceed`, or `go ahead` reclassifies the quoted
referent alone and cannot borrow wrapper signals. Explanations, questions,
negation, remediation, and non-user review carriers remain inert. Long-field
state retains no quoted text; unprovable cross-window linkage becomes
`classifier_window_incomplete`, and the additional classification remains bound
by `MaxChunks`. Common governors such as `just`, `simply`, `let's`, and `let us`
remain active. Only positively proven analytical, safety, or negated speech acts
suppress the incomplete-prior fallback; wrapper-stripped adjacent heads/tails
are not reclassified when either field already proved an inert quote.

## Performance work and acceptance

Round 9 performance, RSS, CPA Host latency, and counted-Mock runtime evidence
are `NOT_PROVIDED` because the final classifier/source has not been frozen. The
optimization description below is source design context, not a completed Round
9 performance or runtime claim.

The hot path avoids request hashing when subject accumulation is ineligible,
skips subject HMAC derivation and controller locking for complete clean allows,
avoids per-request Observe-event persistence by default, skips unnecessary
cross-window risk aggregation, bounds short JSON buffers to actual content, and
uses a zero-copy decode path for valid unescaped JSON strings.

Final acceptance is Linux-only:

1. GitHub CI on Ubuntu 24.04, including race, vet, fuzz smoke, corpus, benchmarks,
   CPA v7.2.102 pinned-source checks, and Linux
   amd64 artifact build;
2. exact-head SO verification in an isolated CPA v7.2.102 sandbox;
3. zero benign blocks across the repository-neutral matrix;
4. all independent malicious-user links blocked before Mock upstream;
5. zero subject growth from non-user carriers and a clean same-auth follow-up;
6. repeated off/observe/balanced A/B measurements for throughput, latency, CPU,
   RSS, coverage, and error counters.

Static review and unit fixtures do not by themselves claim real-CPA compatibility
or performance. Those claims require the exact Linux artifact and sandbox evidence.
