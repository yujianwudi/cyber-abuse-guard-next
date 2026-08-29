# Round 6 known limitations and release blockers

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: 974f05d1109bde75847b0063c3110c81944ddef249d9fdf8c374ddcd8c218683
```

> **Frozen historical snapshot.** Except for the active-tree classifier identity
> above and this notice, the body below preserves the Round 6 / v0.15 release
> posture. References to CPA v7.2.95 as "current" or as the current CI/Host
> target are scoped only to that frozen Round 6 snapshot and are not the active
> repository release identity.
>
> The current Round 17 active-tree overlay is CAG source `1.0.0`, planned
> `v1.0.0-rc.3` on Linux amd64, and:
>
> ```text
> current_formal_cpa: v7.2.145@d9cea8904b14fbbebb77ef26e98ef08f6b48a724
> current_cpa_contract: C_ABI_1 / RPC_SCHEMA_4
> current_module_sum: h1:5AG1q4MhRK+IU5oP5PPvm04AJYvEkj60br85jiBan5o=
> current_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
> ```
>
> Round 13 v7.2.125/schema 2 evidence is historical and transfers no PASS.
> Every `/v1/realtime*` route currently bypasses CAG `RequestInterceptor`,
> `ModelRouter`, and request lifecycle and is **OUT_OF_SCOPE / UNPROTECTED /
> CAG_NOT_VISIBLE**. Only registered callback paths such as chat and Responses
> are protected; there is no all-traffic coverage claim. See
> [Round 17 status](ROUND16_STATUS.md).

Status: **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**; a candidate-bound
`evaluation-v11` or later first-and-only `CONSUMED / PASS` attestation is also
pending.

This document describes exact project version `0.15` and intended formal tag
`v0.15` (never `v0.15.0`) as a Linux amd64-only development candidate, not a
production approval. Windows and macOS validation is outside this round. See
[ROUND6_DEVELOPMENT_HANDOFF.md](ROUND6_DEVELOPMENT_HANDOFF.md) and the neutral
[RELEASE_POLICY.md](RELEASE_POLICY.md). External eligibility is recorded only in
`round6-prerelease-attestation.json` and `formal-release-attestation.json`.

Historical v0.15 classifier identity is `classifier-policy-v5` /
`0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b`.

## Release blockers

- Official CPA v7.2.95 source/compile compatibility is the current CI gate, and
  its real Host + Mock-upstream validation must be performed by the user in the
  authorized server sandbox. Earlier v7.2.85/v7.2.84/v7.2.83/v7.2.82/v7.2.81 checks are historical and
  non-gating.
- No Los Angeles production host may be accessed or modified by this task.
- Candidate bytes may be clean only when produced by the dedicated private,
  untagged GitHub Actions candidate workflow. Clean bytes are still unreleased
  and must not be installed in production.
- A candidate-bound external `evaluation-v11` or later report must be authored
  outside development, consumed once, and declare `CONSUMED / PASS` before an
  optional annotated `v0.15-dev.round6[.N]` development prerelease. That
  prerelease remains draft, prerelease, not latest, and
  `BLOCKED / NOT A FORMAL RELEASE`.
- The annotated formal tag `v0.15` and verified formal draft remain prohibited
  without that external candidate-level attestation. Publishing is a later,
  protected promotion of the unchanged draft. Historical v10 remains immutable
  `CONSUMED / FAIL`, cannot be rerun, and is not a formal-build input.
- Production `observe -> balanced` is outside this task and requires a later explicit approval.
- The ordinary CI and candidate/release boundary is documented in
  [ROUND6_RELEASE_GATE.md](ROUND6_RELEASE_GATE.md). The candidate workflow
  may run only after the final PR head passes PR CI, merges to `main`, and the
  exact resulting main commit/tree passes push CI; it is dispatched from
  `refs/heads/main` and produces only a private untagged Actions artifact. The
  separate development-prerelease workflow
  defaults to blocked and cannot create a draft prerelease without the same
  successful candidate run, an explicit PASS input for the CPA v7.2.95 Host
  record, an independent audit PASS, candidate-bound evaluation-v11+ PASS ID
  and report hash, and a separate authorization boolean.
- Host evidence PASS values and SHA-256 inputs are externally reviewed declarations. The workflow validates their format and candidate binding but does not download the underlying evidence files or recompute those evidence hashes; protected Environment reviewers must independently obtain and verify the files, with self-review disabled.
- The workflow's exact run/environment hashes, clean execution environment,
  canonical checksums, and ZIP-contained identity checks reduce runner and
  transfer ambiguity but do not replace GitHub Environment reviewers,
  immutable release-tag rules, exact-source Linux CI, real CPA Host evidence,
  or independent artifact review.
- Commit `21ceb57e6b6030e56d7820c9a67a8eecd068c669` passed push and PR CI
  before the 0.15 release-chain migration. It is a checkpoint only, not final
  v0.15 artifact or release evidence.
- The final PR head must have no unresolved, non-outdated actionable review
  threads before merge. Automated review is not independent approval.
- Formal source and audit bundles exclude evaluation, Holdout, private, blind,
  and retired data; only low-sensitivity external evaluation identity/hash and
  release attestations may be included.

## Deliberate safety behavior

- The verified-local-hard-block-under-incomplete exception is disabled. Any incomplete request has neutralized classifier findings and follows the mode table.
- Model-visible text above 8 MiB is incomplete: balanced allows with audit; strict blocks.
- Opaque image/audio/video/document content is not decoded or fetched. Only surrounding model-visible text is classified.
- Unknown multipart schema, ambiguous roles, unsupported encodings, and unavailable full RPC bodies are incomplete rather than guessed.
- Ordinary audit and status contain fixed enums, counters, digests, and bounded
  timing only. The later default-off `audit.raw_capture` operator feature is a
  documented exception that stores mandatory-redacted, bounded previews only
  for final blocking decisions (`block`, including subject cooldown); see
  [Blocked-request review capture](RAW_CAPTURE.md).
- Dense encoded derived views beyond 128 KiB of encoded source or the 64 KiB
  aggregate retained decoded-text budget remain incomplete. Long plain text is
  streamed, but oversized derived views are not reported as fully covered.

## Compatibility boundaries

- The CPA ABI limits the complete RPC envelope to 8 MiB. Because a `[]byte` body is represented inside the RPC envelope, the largest model request body visible to a particular Host can be smaller than 8 MiB. Host evidence must report the actual accepted body size.
- Legacy `ExtractText` returns materialized `Parts` for source compatibility
  and preserves its old part-splitting and compatibility-limit semantics.
  Production routing uses the streaming sink and does not materialize the full
  prompt.
- Transformed multipart JSON is schema-bound to the currently proven
  `openai-image` top-level field allowlist. Its approved long prompt fields are
  streamed, but unknown fields or non-string prompt values remain incomplete;
  the scanner does not guess future transformed schemas.
- The streaming classifier preserves bounded cross-role and cross-message proofs. It intentionally does not join arbitrary distant messages or unrelated roles into a hard finding.
- If actionable classifier evidence is distributed across multiple windows of
  one logical field, the scanner conservatively reports classifier-window
  incompleteness rather than reconstructing or retaining the full field.
  Balanced mode therefore allows with audit and strict mode blocks, following
  the existing incomplete-inspection policy.
- A defensive quoted Cyber Abuse review is recognized only when its one closed
  quotation, unsafe assessment, and exact non-execution boundary are contained
  in a complete classifier view. A later affirmative referential directive can
  bind only the newest eligible user review; the quote is reclassified without
  borrowing wrapper context. The scanner retains only a privacy-safe result and
  bounded follow-up facts, never the quote, and does not infer inert or active
  quotation scope across a lost/truncated window boundary. Such proof loss is
  `classifier_window_incomplete`; referent reclassification also consumes the
  ordinary `MaxChunks` budget. The recognized speech-act grammar is bounded;
  only a positively proven analytical, safety, or negated form receives inert
  credit. An unrecognized form retains the conservative signal fallback rather
  than being treated as a complete safe negative.
- The compact shadow/index path no longer copies arbitrary long keys or semantic
  values, but structural metadata and decoder allocations still grow with
  bounded JSON token/node and logical-field counts. Linux allocation and RSS
  evidence is still required at the near-envelope tier.

## Independent validation still required

The external auditor should independently verify:

1. the Linux size ladder at 64 KiB, 255 KiB, 256 KiB, 256 KiB + 1,
   270 KiB, 512 KiB, 1 MiB, 4 MiB, and near the effective RPC limit, including
   benign text and malicious text at start, middle, end, and a window boundary;
2. benign and negated neighbors;
3. system, user, tool, Responses, Claude, Gemini, Interactions, raw multipart,
   and CPA-transformed multipart JSON paths;
4. zero Auth Selector, provider, Mock upstream, and usage deltas for every local block;
5. SQLite `quick_check`, schema migration backup, privacy canaries, race, fuzz, allocation, RSS, and reproducible artifact hashes;
6. rollback to the prior sandbox artifact without touching production request
   or audit data;
7. exact binding between final commit/tree, candidate workflow run,
   `candidate-manifest.json`, clean SO SHA-256, and every Host/audit record.

The CPA v7.2.95 real Host + Mock-upstream result is **NOT RUN / PENDING**.
Source/compile checks cannot substitute for this gate.
Later upstream CPA versions do not automatically change this supported target.
