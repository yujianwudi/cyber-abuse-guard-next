# Round 9 public adversarial corpus v10

This is the active visible development-only public adversarial corpus. Its
manifest is 183,752 bytes / SHA-256
`bda9f4e70b9e3a050e7e40d025024fa8a9ebb1ffa2fb46f9f7ac47d27691526d`
under schema `round9-public-adversarial-corpus/v10`.

V10 preserves v9 byte-for-byte and records the 2026-07-24 read-only GitHub
refresh. The only default-head movement since v9 was
`MDX-Tom/gpt-5.6-instruct` from `a2476cd2...` to `b32eb0dd...`. The eight
changed or added blobs are Actions deployment source, workflow configuration,
README text, two executable-source archives, and one unit test. Read-only text
and archive-entry inspection found no new standalone prompt payload, so the 24
payload records and 23 formal unique payloads are unchanged.

The manifest now separates provenance tiers explicitly:

- formal default-branch and release-tag Git objects remain attached to the
  unique payload they carry;
- Git repository archive entries use `repository_archive_entry` provenance;
- GitHub Release archive entries use `release_asset_archive_entry` provenance
  with immutable release/asset IDs and asset digests;
- five still-active non-default branches are recorded separately as behind
  candidates with no distinct prompt bytes; and
- Codex-5.5 PR #9 remains the sole unmerged candidate carrier, with its compact
  prompt distinct from the unchanged formal GPT-5.5 payload.

The refresh reviewed 16 current formal Release assets. Four archive assets
carry prompt entries: Keysmith v0.1.1 zip/tar, MDX v35, and MDX v41. Repeated
entry bytes retain all provenance but consume one unique-payload index only.
The Codex-X v0.3.0 portable archive contained no standalone prompt-like entry;
opaque application assets were never opened or executed.

Corpus accounting remains 24 payload records, 23 formal unique payloads, one
unmerged candidate-carrier execution, and 120 serialized context routes. The
12 reviewed defensive or dual-use direct-user texts remain `allow_or_audit`;
the 12 explicitly adversarial direct-user scenarios remain
`block_malicious_text`; every inert carrier context remains `allow_or_audit`.

These bytes are visible development regressions only. They are not a blind or
independent holdout, production approval, or population-level false-positive
or recall proof. No third-party repository code, installer, dependency, hook,
workflow, test, application, or binary was executed.
