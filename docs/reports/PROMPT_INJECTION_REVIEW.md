# Defensive Review: public prompt-injection references and v0.15 Round 6 controls

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: e7a00b02d7e0e4ca837204cfed476b4f371f599facbf546e342362370111ec14
```

> **Frozen historical snapshot.** The Round 6 addendum and the older
> single-repository review below preserve their historical wording and evidence,
> including CPA v7.2.95 as the then-current Round 6 target. Their branch, commit,
> classifier identity, validation, taxonomy, and "current" statements must not
> be inherited as current release or v0.15 PASS evidence.
>
> The current formal CPA identity is:
>
> ```text
> current_formal_cpa: v7.2.104@c9417c8ae9b16fabc0386ca35d36f13bf8b1d678
> current_module_sum: h1:59vZ1rtgxs6etE0Z3iFsLWgZ/MrcIi4mhXLt0XLSNcY=
> current_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
> ```

## Round 6 CPA pinned-compatibility addendum

Exact project version is `0.15`; the only formal tag is `v0.15`, never
`v0.15.0`. The current source/compile and real-Host release target is v7.2.95
only. Its native Host + Mock matrix remains **NOT RUN / PENDING**. Earlier
v7.2.85/v7.2.84/v7.2.83/v7.2.82/v7.2.81 profiles are historical and non-gating. Commit
`21ceb57e6b6030e56d7820c9a67a8eecd068c669` passed push
and PR CI for the then-current v7.2.83 latest-source lane as a
pre-version-migration checkpoint, not final v0.15 evidence. Any
v7.2.80 PASS wording later in this historical report applies
only to its recorded source/compile run and must not be promoted to the current
matrix or Host evidence.

## Round 6 defensive addendum

Round 6 treats the pinned snapshots of `Jia-Ethan/codex-keysmith`,
`MDX-Tom/gpt-5.6-instruct`, `yynxxxxx/Codex-X`, and
`yynxxxxx/Codex-5.5-codex-instruct-5.5` only as
untrusted public adversarial references. No prompt installer, injection script,
configuration mutator, or third-party test runner is installed or executed.
No original jailbreak prompt, live payload, real target, credential, URL/IP,
or model output is copied into rules, tests, audit, counters, or reports.

The 2026-07-22 read-only refresh fixed these default-branch snapshots without
executing third-party code or copying prompt payloads:

| Public reference | Fixed commit | Abstract mechanisms used for defensive review |
|---|---|---|
| `Jia-Ethan/codex-keysmith` | `f699b9bd2cb59eb0d54e69139c68f7808d869b6d` | conditional session routing, placeholder/default branches, hierarchy inversion, refusal suppression, concealed exact-output completion |
| `MDX-Tom/gpt-5.6-instruct` | `18fea37f4f1a263cc0fc31bb0e32e61ace0b1f69` | persistent instruction-file replacement, refusal suppression, unrestricted persona, scope/placeholder laundering, direct completion, benchmark coercion, bilingual compound routing |
| `yynxxxxx/Codex-X` | `7d0e0064d54f860d4bf12b557fd9f8c489043a35` | remote template/cache and Markdown import, append/replace, managed `AGENTS`, Skill/MCP, activation aliases, agentic execution, segmented continuation, concealment |
| `yynxxxxx/Codex-5.5-codex-instruct-5.5` | `ed0b6dc37d1994e93788d92f7af63f58bf0b9e2d` | unrestricted developer mode, filter/refusal suppression, default lab authorization, persistent instruction-file injection |

The corresponding Codex-5.5 example shared by the latter two repositories is
the same Git blob (`b1428e813708188d62fedba02bd49e31397f6296`). This
deduplication fact is source-review metadata only, not classifier evidence.
The MDX-Tom refresh advanced only documentation and GitHub Pages maintenance;
its reviewed instruction/deployment payloads were unchanged from the earlier
`5f469e43...` snapshot, and the current v5 Markdown is Git blob
`4fa25ea7f680ff07808467b0d164764dc0161d39`.

The sanitized mechanism-level additions are combination-based rather than a
jailbreak keyword blocklist:

- `benchmark_coercion`;
- `persistent_instruction_injection`;
- strengthened `scope_laundering`, `refusal_suppression`, and `output_control`;
- `persona_takeover`;
- `agentic_execution_escalation` as a non-standalone amplifier;
- compound-intent routing that preserves a harmful second clause; and
- a stricter defensive quoted-sample boundary whose final effective directive
  must remain inert analysis;
- override-concealment phrases mapped into fixed `output_control` evidence; and
- boundary-split/delayed-continuation phrases that retain evidence through long
  benign padding without introducing prompt text into telemetry.

Wrapper-only harmless text remains allow/audit and cannot synthesize
`defense_evasion` or another Cyber Abuse taxonomy. A complete independent base
behavior remains primary; meta evidence only amplifies it or emits a fixed,
orthogonal `control_plane_event=meta_override` observation. Evidence and
telemetry contain fixed family IDs only—never prompt text, repository names,
dynamic field names, targets, filenames, URLs, or prompt hashes.

The bounded key-only control mapping is enabled only by
`cag_control_schema=meta_override_control/v1` inside established
tool/tool-payload provenance. The marker has no authority in ordinary business
JSON or Provider configuration, arbitrary keys are never promoted to prompt
text, and an unknown control in that known schema becomes fixed `tool_schema`
incomplete without classification.

The visible corpus at
`testdata/development-public-jailbreak-patterns-v1` is required to declare:

```json
{
  "development_only": true,
  "future_holdout_eligible": false,
  "derived_from_public_adversarial_taxonomy": true,
  "contains_live_payloads": false
}
```

It contains 36 harmless cases (18 allow / 18 audit), five protocols, 14
carriers, 19 transforms, and five effective source contexts: ordinary request
bodies plus four abstract instruction-source contexts. Added cases cover
mixed system/developer/tool composition, local model instructions, managed
`AGENTS`, Skill/MCP payloads, semantic aliases, concealment, filter-boundary
splits, and HTML-comment modules. The 8 KiB-class benign-padding behavior is
covered by a generated unit regression rather than copied corpus text. All
cases and derived wording are permanently ineligible for future blind
evaluation. `source_context` is development metadata only: it cannot prove a
runtime request came from one of these repositories, a local file, or a cache.

Two supply-chain/configuration risks remain outside the Router:

1. It cannot attest to the path, owner, mode, hash/signature, reload history,
   or remote origin of `model_instructions_file`, `AGENTS.md`, or another local
   high-priority instruction template loaded before CPA receives a request.
2. It cannot prove safe semantics for Provider controls such as
   `safetySettings`, `generationConfig`, or `options`.

It also cannot inspect an instruction that is present only as a URL, `file_id`,
ZIP/archive member, encrypted/compressed blob, image/audio/video reference, or
other opaque carrier that CPA does not convert to visible supported text. It is
stateless across independent requests and cannot stop a local client from
editing config, `AGENTS`, Skills, MCP registration, or cached templates before
the request reaches CPA.

The host must therefore use instruction-path allowlists, owner/mode and write
restrictions, hash/signature binding at startup and reload, audited changes,
human-approved remote templates pinned to a commit/hash, and a versioned
Provider schema allowlist with rejection or forced-safe-value overrides.

Ruleset `1.0.7` identifies only embedded YAML Cyber Abuse assets. It does not
include the Go-level `META-OVERRIDE-001` overlay, extraction semantics,
tool-schema mappings, or control-plane telemetry. Current v0.15 provenance must
also bind `classifier-policy-v5` /
`0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b`,
the exact Git commit/tree, and the candidate workflow run.

The final reverse audit also closed a large-request extraction gap relevant to
Codex/MCP tool inventories. When a raw request exceeds the 256 KiB semantic
budget, the second role index is intentionally skipped; the primary walker now
recognizes only root container-valued `tools` and `functions` declarations, so
model-visible descriptions remain inspected even beyond that raw offset.
Nested business lookalikes and scalar fields remain inert. Native CPA
`interactions` is now a fixed supported format and uses conservative no-role
inspection; this is source-level compatibility, not native Host evidence.

Ordinary CI does not invoke the consumed evaluation-v10 boundary target or
start CPA. The current v7.2.95 contract is source/compile compatibility evidence
only. The final PR head must first pass PR CI, merge to `main`, and the exact
resulting main commit/tree must pass push CI. The private untagged clean
candidate is then dispatched from `refs/heads/main`; the owner-operated
v7.2.95 Host validation and
independent source/artifact/Host review plus a candidate-bound external
`evaluation-v11` or later first-and-only `CONSUMED / PASS` attestation are
separate and are not production authorization. Until exact evidence is recorded, status is:

```text
BLOCKED / PENDING HOST AND INDEPENDENT AUDIT
```

After the Host/audit and candidate-level evaluation gates, an optional annotated
`v0.15-dev.round6[.N]` draft prerelease remains
`BLOCKED / NOT A FORMAL RELEASE`. The annotated formal `v0.15` tag and verified
draft consume that same attestation; protected promotion may publish only the
unchanged draft. Historical v10 remains immutable `CONSUMED / FAIL`, cannot be
rerun, and is not a formal-build input. Formal source/audit bundles exclude
evaluation, Holdout, private, blind, and retired material.

The final PR head must have no unresolved, non-outdated actionable review
threads before merge. Automated review is not remote or independent approval.

Release admission follows [RELEASE_POLICY.md](../RELEASE_POLICY.md) and external
`round6-prerelease-attestation.json` / `formal-release-attestation.json` assets.

---

## Historical single-repository review

Status: **development input only / not blind evidence / server sandbox validation pending**

Implementation branch: `agent/post-v10-production-hardening`

Starting source commit for this diff:
`68ce0f662cbb034e61e1f3a8b91f50ea20c57637`

Delivery identity: the base commit above is comparison context only. The Git
commit that contains this report and its code diff, together with the YAML
ruleset identity, is the authoritative development-tree identity. This is
still **RELEASE BLOCKED** and is not a release commit/tag identity.

Reviewed source:

- Repository: <https://github.com/MDX-Tom/gpt-5.6-instruct>
- Read-only snapshot: `680c3d3d1c4a27fb7c8f9aae678e89cfa351b4d4`
- Review date: 2026-07-13 (Asia/Shanghai)

No script, deployment helper, instruction file, or prompt-bank runner from the
external repository was executed. The repository was used only to derive a
sanitized defensive taxonomy. Complete jailbreak prompts are not copied into
this project, its tests, or this report.

## Observed attack mechanisms

The relevant mechanisms are compositional rather than keyword-only:

1. configuration-level instruction replacement through a
   `model_instructions_file`-style control;
2. instruction-hierarchy inversion and unrestricted/developer persona claims;
3. evaluation reversal in which refusal or a safe fallback is declared a test
   failure;
4. explicit suppression of refusal, policy framing, risk assessment,
   clarification, and authorization checks;
5. sandbox, benchmark, fictional-target, or local-fixture claims used to wash
   real or unauthorized scope;
6. replacement of concrete targets with placeholders while preserving a full
   operational workflow;
7. bilingual and mixed-language routing across several related sub-intents;
8. forced first lines, exact templates, autonomous slot filling, and immediate
   code/step output;
9. system/developer-prompt or hidden-reasoning disclosure requests; and
10. delivery through system/developer content, tool payloads, nested JSON,
    encoded text, or split content blocks.

## Implemented in development source

The post-v10 development tree adds a deterministic `META-OVERRIDE-001` overlay.
It compiles bilingual signal families into the existing bounded literal matcher
and requires combinations of independent control-plane evidence. It does not
block a lone word such as `jailbreak`, `benchmark`, or `developer`.

The overlay covers:

- hierarchy replacement;
- refusal suppression;
- unrestricted-mode/persona declarations;
- direct-completion demands;
- sandbox and placeholder laundering;
- exact-output and no-clarification controls;
- system/developer-prompt or hidden-reasoning disclosure; and
- explicit negative authorization.

When ordinary cyber-abuse evidence is already present, the overlay raises that
candidate without replacing its original taxonomy. A strong standalone
control-plane attack is reported under `defense_evasion`. Prompt-derived CTF,
lab, fictional-target, and authorization claims do not reduce the overlay.
Explicit defensive analysis, quoted-sample review, detection, and mitigation
can reduce it only when the request also has an affirmative non-execution
purpose.

Quoted-review credit is transactional rather than a reusable signal discount.
Only one closed quoted referent is independently classified. If the newest
eligible RoleUser review is followed by an affirmative referential directive
such as `execute it`, `proceed`, or `go ahead`, the quote alone is reclassified
and produces the same result as direct input. Wrapper signals are not reused.
Questions, explanations, negation, consequences, remediation, and reviews from
assistant/system/tool or unknown provenance remain inert. Mixed-trust RoleUser
pairs remain conservatively classified with `non_user_or_untrusted` origin and
cannot accumulate subject risk. Streaming retains only privacy-safe results and
bounded follow-up facts; lost cross-window proof is
`classifier_window_incomplete`, and the extra referent classification is charged
to `MaxChunks`.

The reviewed grammar treats `just`, `simply`, `let's`, and `let us` as directive
governors. It separately records proven inert explanations/questions/safety
deliverables/negations. A complete but unrecognized phrase cannot suppress the
bounded implementation-signal fallback after prior text has crossed a scanner
window. Likewise, adjacent head/tail classification is skipped if either field
already proved an inert quoted referent.

Additional extraction and scope hardening in the same change:

- a supported provider label whose role schema is ambiguous is re-extracted by
  the router with the conservative untrusted walker;
- JSON-looking strings under any already-established tool-payload field are
  recursively inspected under the existing depth/part/byte budgets;
- content joined from multiple provider blocks and ordered strings from a tool
  payload or function output are decoded again, closing sub-threshold Base64
  splits;
- one-character fragments may be reconstructed across line/content boundaries,
  while ordinary multi-character clauses remain hard-separated;
- unknown semantic siblings are retained in top-level JSON order as untrusted
  user segments, while recognized `metadata`/`options` containers do not erase
  role isolation; hostile linked system/tool control may carry into a user
  continuation regardless of top-level property order;
- linked meta chains retain a bounded cumulative family bitset while only the
  latest eight evidence-bearing text parts are kept for contextual review; a
  non-meta part breaks the chain, preventing quadratic tail construction;
- an inert refusal quotation exits scope on a new `now`/`then` operational
  turn, direct protected-prompt disclosure requests are audited, and defensive
  non-execution text must follow the final quoted meta phrase;
- dotless `ı` and Cyrillic `к` join the narrow high-risk homoglyph map;
- negative-authorization conflict phrases clear prompt-derived lab/authorization
  deductions; and
- a system message that negates refusal, blocking, filtering, guardrails, or
  safety checks is no longer suppressed as a benign safety policy.

Primary implementation and regression files:

- `internal/classifier/meta_override.go`
- `internal/classifier/meta_override_test.go`
- `internal/classifier/classifier.go`
- `internal/classifier/roles.go`
- `internal/classifier/matcher.go`
- `internal/classifier/normalize.go`
- `internal/extract/extract.go`
- `internal/extract/roles.go`
- `internal/extract/roles_test.go`
- `internal/plugin/router.go`
- `internal/plugin/prompt_injection_regression_test.go`

## Source-level validation performed

On 2026-07-13 (Asia/Shanghai), the following current-diff checks exited zero.
The invoked toolchain reported `go version go1.26.4 linux/amd64`:

The historical operator-local executable paths are normalized below as `$GO`
and `$GOFMT`; they identified the reported Go 1.26.4 Linux amd64 toolchain and
are not required to reproduce the commands.

```text
$GO test -tags=sqlite_omit_load_extension \
  ./internal/rules ./internal/extract ./internal/classifier ./internal/plugin \
  -count=1
$GO vet -tags=sqlite_omit_load_extension \
  ./internal/rules ./internal/extract ./internal/classifier ./internal/plugin
$GO test -race -tags=sqlite_omit_load_extension \
  ./internal/extract ./internal/classifier ./internal/plugin \
  -run '^(TestMetaOverride.*|TestNegativeAuthorizationClearsLabLaundering|TestMaliciousSystemPolicyCannotNegateRefusalInsteadOfAbuse|TestSystemClosedQuoteCannotHideNewOperationalSentence|TestAssistant.*|Test.*Permission.*|TestExtractTextRoleAmbiguityReextractsUnknownTopLevelSemantics|TestExtractTextUnknownTopLevelMetadataDoesNotEraseRoleIsolation|TestExtractTextRedecodesEncodedContentSplitAcrossBlocks|TestExtractTextRedecodesEncodedToolFieldsAfterPristineJoin|TestExtractTextRecursesJSONStringUnderArbitraryToolPayloadField|TestPromptInjection.*)$' \
  -count=1
$GOFMT -l internal/classifier/classifier.go \
  internal/classifier/matcher.go internal/classifier/meta_override.go \
  internal/classifier/meta_override_test.go internal/classifier/normalize.go \
  internal/classifier/roles.go internal/extract/extract.go \
  internal/extract/roles.go internal/extract/roles_test.go \
  internal/plugin/router.go internal/plugin/prompt_injection_regression_test.go \
  internal/rules/types.go
$GO mod verify
$GO mod tidy -diff
git diff --check
```

These are developer-visible source checks only. Current-diff real-CPA
integration, native plugin loading, deployment, formal
Holdout, formal packaging, tag, and GitHub Release were not run. **SERVER
SANDBOX VALIDATION: PENDING / NOT RUN.** See `TEST_REPORT.md` and
`RELEASE_EVIDENCE.md` for the evidence boundary.

## Ruleset and policy identity

Ruleset `1.0.7` and its canonical SHA-256 identify the embedded YAML
cyber-abuse assets. They do not include the complete Go-level policy:
`META-OVERRIDE-001`, matcher/normalizer mappings, role handling, and extraction
semantics all affect decisions. The containing Git/build commit plus the YAML
identity are required for this development behavior. A release-eligible
successor must add a separately verified classifier-policy version/hash or
fully bind these semantics to verified build provenance.

## External evidence quality warning

The external repository is useful as an adversarial development source, but its
published performance claims are not independently reproducible from the
reviewed tree:

- README declares SHA-256
  `08a257814f515bbcb842be7ff4932a48ba112a56caef91371369881c256efd0c`;
- the reviewed ZIP hashes to
  `398ebd9e04141cbf0baf598fbbe6db0eb508f7e5f1d49207ca18c1beac37b097`;
- the Markdown extracted from that ZIP hashes to
  `5867af4e6d039fb331e2368ec13499b01c8e93d189e072631f31a226108becf7`;
- README references `tests/` and `reports/`, but neither directory exists in
  the reviewed Git tree; and
- the repository's safety-evaluation note still describes an older prompt
  version.

The archive hashes above were reproduced without executing or writing its
contents to the workspace:

- pinned raw path:
  `https://raw.githubusercontent.com/MDX-Tom/gpt-5.6-instruct/680c3d3d1c4a27fb7c8f9aae678e89cfa351b4d4/gpt-5.6-sol-unrestricted.zip`;
- Git path: `gpt-5.6-sol-unrestricted.zip`, 2,881 bytes;
- in-archive path: `gpt-5.6-sol-unrestricted.md`, 5,137 bytes.

Reproduction used the GitHub Contents API and an in-memory ZIP reader:

```powershell
$ref = '680c3d3d1c4a27fb7c8f9aae678e89cfa351b4d4'
$j = gh api "repos/MDX-Tom/gpt-5.6-instruct/contents/gpt-5.6-sol-unrestricted.zip?ref=$ref" | ConvertFrom-Json
$bytes = [Convert]::FromBase64String(($j.content -replace '\s',''))
$sha = [Security.Cryptography.SHA256]::Create()
([BitConverter]::ToString($sha.ComputeHash($bytes)) -replace '-','').ToLowerInvariant()
Add-Type -AssemblyName System.IO.Compression
$stream = [IO.MemoryStream]::new($bytes, $false)
$zip = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Read, $false)
$entry = $zip.GetEntry('gpt-5.6-sol-unrestricted.md')
([BitConverter]::ToString($sha.ComputeHash($entry.Open())) -replace '-','').ToLowerInvariant()
gh api "repos/MDX-Tom/gpt-5.6-instruct/git/trees/$ref?recursive=1" --jq '.tree[].path'
```

Accordingly, claims such as `120/120` are not treated as verified facts and are
not used as release evidence.

## Validation and release boundary

Only source-level unit checks are authorized for this change. No local CPA
deployment, native plugin loading, real-CPA integration, release packaging,
formal holdout run, tag, or GitHub Release is part of this work. Server-side
sandbox validation remains pending for the project owner.

This public repository and every derived regression case are developer-visible.
They must never be reused, relabelled, or counted as a future independent
holdout. The v0.1.2 release decision remains **FAIL / NOT PRODUCTION-READY**;
the consumed v10 result remains immutable.

## Remaining limits

- The plugin can inspect only the request that reaches its router. It cannot
  attest to the ownership, permissions, or hash of a local Codex instruction
  file before CPA receives the request.
- Provider transport/configuration containers such as `safetySettings`,
  `generationConfig`, and generic `options` are not semantically enforced as
  upstream safety policy; the server must constrain them separately.
- Tool JSON property names with only boolean/numeric/null values are not treated
  as standalone prompt text; schema allowlists must reject unapproved key-only
  controls.
- Classification is stateless across separate API calls unless the caller sends
  the relevant history in the current body. No prompt text is persisted.
- Decoding remains intentionally bounded and does not claim coverage for
  arbitrary encryption, compression, Base32, hex, quoted-printable, or novel
  transforms.
- Opaque documents, images, audio, and video are not converted to text.
