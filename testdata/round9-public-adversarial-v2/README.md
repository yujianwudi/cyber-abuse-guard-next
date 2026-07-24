# Round 9 public adversarial corpus v2

This directory freezes inert public prompt bytes for development regression
only. GitHub repository metadata, trees, pull-request metadata, and file bytes
were read through the GitHub API at
`2026-07-23T09:43:30.2222616+08:00`. No third-party repository code,
installer, dependency, hook, desktop application, or binary was executed.

Version 2 is a new corpus identity created after upstream drift. Version 1 is
retained without modification at `../round9-public-adversarial-v1`; its frozen
manifest is 27,297 bytes with SHA-256
`55c05fa407f05ffe21a87791f3b7a4e7d2e68bc026e0d8ced7654bb13932f386`.

The live refresh found these material changes:

- `Jia-Ethan/codex-keysmith` now has
  `main@d8335f99a557403f3ef919c8601502e5a8362414` and tag `v0.1.1` at the
  same commit. PR #3 was merged and closed, so it is no longer represented as
  an `unmerged_candidate_carrier`. The current main payload is the same 7,038
  bytes / SHA-256 `2c2c9f0e...` previously frozen as unique branch-head
  payload 9. The former 7,899-byte main payload remains historical unique
  payload 1 and is also bound to the still-live `v0.1.0` tag.
- The keysmith candidate branch advanced to
  `c54a0d9352da1bd2664340862a67deb33dcb5b82`; its prompt bytes are unchanged
  from unique payload 9.
- `MDX-Tom/gpt-5.6-instruct` now has
  `main@82a3957533435f6e98111174dbfb41de2a2227f5`. The intervening four commits
  changed only `.gitignore`, `README.md`, and `README_EN.md`; the v5 payload,
  v35 ZIP, and decoded v35 payload identities are unchanged.
- `yynxxxxx/Codex-X` and
  `yynxxxxx/Codex-5.5-codex-instruct-5.5` retain their prior default heads.
  MDX draft PR #15 and Codex-5.5 PR #9 remain open.

The corpus retains all eight historical unique payloads and unique payload 9.
The branch-origin label on payload 9 records why that identity entered the
Round 9 denominator; its current provenance additionally binds the promoted
default branch and `v0.1.1` tag. Duplicate protocol wrappers, refs, and
carriers do not increase the unique-payload denominator.

There are now two unmerged candidate carriers:

- Codex-5.5 PR #9 supplies the separately frozen compact payload and is one
  candidate route execution.
- MDX draft PR #15 changes documentation, loader code, and tests but provides
  no added or modified prompt payload blob, so its payload status remains
  `NOT_PROVIDED`. Loader behavior is not inferred and repository code is not
  executed.

Every available source binds repository, ref kind, exact commit, path, byte
length, SHA-256, and Git blob SHA. For the MDX v35 ZIP, the source ZIP identity
is recorded separately from the decoded archive-member payload identity.
Base64 files preserve exact decoded bytes, including missing trailing
newlines.

Direct-current-user and quoted/analytical scenarios are evaluated separately.
These bytes are visible development data and must never be described as blind,
independent, holdout, production approval, or proof of population recall.
