# Public jailbreak repository review

```text
current_classifier_policy_version: classifier-policy-v8
current_classifier_policy_sha256: b3f1e751bf648d426023e4207b8b562fe3aac91d48fa74c1462c79e08fa49dde
```

Last updated: 2026-07-24 (Asia/Shanghai)

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
4. CPA v7.2.95 Codex Desktop
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
- A malicious-looking system, developer, assistant, tool, or unknown payload
  remains inspectable and auditable, but it cannot directly produce a
  malicious-text block or subject-risk hit. Only a later current, trusted user
  execution directive with a complete bounded referent proof can reactivate it,
  after which the reactivated candidate must pass the ordinary eligibility gate.
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

Decoded-text coverage includes 1,397, 1,743, 4,575, 5,137, 7,899, 10,198, 13,641,
16,383, 16,384, 16,385, and 17,166 bytes. Existing Round6 tests separately cover
32 KiB role windows, the 256 KiB compatibility boundary, multi-megabyte fields,
and more than 64 logical role segments.

## Attribution hardening

User-origin subject risk now requires a closed provider-aware proof:

- only a SourceProfile-matched root history container can establish a trusted
  user role;
- OpenAI Responses root scalar `input` is a trusted user carrier;
- exact CPA v7.2.95 Codex Responses Lite `additional_tools` items,
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
   CPA v7.2.95 pinned-source checks, and Linux
   amd64 artifact build;
2. exact-head SO verification in an isolated CPA v7.2.95 sandbox;
3. zero benign blocks across the repository-neutral matrix;
4. all independent malicious-user links blocked before Mock upstream;
5. zero subject growth from non-user carriers and a clean same-auth follow-up;
6. repeated off/observe/balanced A/B measurements for throughput, latency, CPU,
   RSS, coverage, and error counters.

Static review and unit fixtures do not by themselves claim real-CPA compatibility
or performance. Those claims require the exact Linux artifact and sandbox evidence.
