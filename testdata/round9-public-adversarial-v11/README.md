# Round 9 public adversarial corpus v11

This is the active visible development-only public adversarial corpus. Its
manifest is 476,165 bytes / SHA-256
`297c01072eb8bea3c6102b957c741722e621860c1116b65450b68a8704e75038`
under schema `round9-public-adversarial-corpus/v11`.

V11 preserves v1 through v10 verbatim and records a new authenticated,
read-only GitHub API snapshot at `2026-07-24T16:40:44+08:00`. Since v10:

- `MDX-Tom/gpt-5.6-instruct` advanced from `b32eb0dd...` to
  `334f8cd2...`; its two changed text blobs are the Star History renderer and
  its unit test;
- `yynxxxxx/Codex-X` advanced from `7d0e0064...` to `e8b0e5b7...`; its 59
  changed paths implement and publish a skin center, while the five frozen
  `examples/` prompt blobs remain byte-identical; and
- Codex-X published `v0.3.1` at `5b665575...`. The five tag-carried prompt
  files have the same Git blobs, byte counts, and SHA-256 identities as the
  current default branch and prior `v0.3.0` tag.

No new or changed standalone prompt-like payload was found. The 24 payload
records, 23 formal unique payloads, one unmerged candidate carrier, and 120
serialized context routes therefore remain unchanged. All 24 `.b64` files
were copied byte-for-byte from v10; the refresh did not print payload text.

The manifest freezes the default branch, every enumerated branch, every open
pull request, every tag, every GitHub Release, and metadata for all 199 Release
assets returned by the authenticated API. Each asset record includes its
repository, release/tag and exact tag commit, release/asset ID, name, byte
count, content type, timestamps, state, and GitHub-provided SHA-256 digest.
During the v11 refresh no Release asset was downloaded or opened, and no
third-party code, installer, dependency, hook, workflow, test, application, or
binary was executed.

The manifest keeps provenance tiers closed and separate:

- default-branch and release-tag Git objects remain attached to the unique
  payload they carry;
- previously frozen repository/archive and Release-asset provenance remains
  historical evidence inherited from v10, not a new v11 binary inspection;
- five active non-default branches remain separately classified as behind
  candidates with no distinct prompt bytes; and
- Codex-5.5 PR #9 remains the sole unmerged candidate carrier and is never
  presented as default-branch or released provenance.

These bytes are visible development regressions only. They are not a blind or
independent holdout, production approval, or population-level false-positive
or recall proof.
