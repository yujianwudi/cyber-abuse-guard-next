# Round 9 public adversarial corpus v3

This directory freezes inert public prompt bytes for development regression
only. GitHub repository metadata, branches, tags, releases, pull-request
metadata, changed paths, and selected file bytes were read through the GitHub
API at `2026-07-23T10:36:51.0071485+08:00`. No third-party repository code,
installer, dependency, hook, workflow, test, application, or binary was
executed.

Version 3 is a new immutable corpus identity created after another live
upstream drift. The prior identities remain unchanged:

- v1 manifest: 27,297 bytes, SHA-256
  `55c05fa407f05ffe21a87791f3b7a4e7d2e68bc026e0d8ced7654bb13932f386`;
- v2 manifest: 27,194 bytes, SHA-256
  `06625e48f0cd7ae8e43ebfb82da266e9b98061a3411262c305277a6ec2fdfe8e`.

The live refresh found two material metadata changes:

- `Jia-Ethan/codex-keysmith` added open PR #4 at
  `codex/fix-release-draft-upload@f0db3e659805a42d0886460fb66fe7dd8ef13d8e`.
  It changes release workflows, documentation, and tests. Its existing
  `examples/gpt-unrestricted.md` is still exactly 7,038 bytes, SHA-256
  `2c2c9f0e008c492bfc9487170a7a08daedeb8b0625af1f85617ab2d1bd3f35c0`,
  Git blob `dee05f309e305373d7c9ebb478c632a0c4b99c35`. Because the PR adds or
  modifies no prompt payload, it is an `unmerged_candidate_carrier` with
  `payload_status=NOT_PROVIDED`, not an extra route execution.
- `MDX-Tom/gpt-5.6-instruct` PR #15 advanced to
  `af6aada3006d31c6eadd27ead5de11e3c8173fd4` and is no longer a draft. It
  now also adds `.github/workflows/test-codex-instruct.yml`. The v5 prompt and
  v35 ZIP remain byte-identical to default main: 1,397 bytes / SHA-256
  `02c018e5...` and 4,748 bytes / SHA-256 `72ca29f1...` respectively. No new
  or modified prompt payload exists, so this carrier also remains
  `NOT_PROVIDED` and its loader behavior is not inferred.

The four default branch heads, Codex-X/Codex-5.5 payloads, keysmith v0.1.0 and
v0.1.1 identities, MDX v5/v35 payload bytes, Codex-5.5 PR #9 compact payload,
tags, and Releases otherwise remain the same as v2. Every available payload or
unchanged prompt source is bound to repository, ref kind, exact commit, path,
byte length, SHA-256, and Git blob SHA.

The corpus therefore contains:

- 10 payload records;
- 9 unique payload byte identities (the historical eight plus the keysmith
  branch-head identity);
- 3 unmerged candidate carriers;
- 1 candidate-carrier payload execution (Codex-5.5 PR #9 compact);
- 2 explicitly `NOT_PROVIDED` candidate carriers;
- 10 serialized direct-current-user route executions.

Duplicate protocol wrappers, refs, and carriers do not increase the unique
payload denominator. Direct-current-user and quoted/analytical scenarios are
evaluated separately. These public bytes are visible development data and must
never be described as blind, independent, holdout, production approval, or
proof of population recall.
