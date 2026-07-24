# Round 9 public adversarial corpus v1

This directory freezes inert public prompt bytes for development regression
only. GitHub repository metadata, trees, and file bytes were read through the
GitHub API; no third-party repository code, installer, dependency, hook,
desktop application, or binary was executed.

The manifest retains eight historical unique default-branch payloads and one
additional codex-keysmith branch-head payload. `unique_payloads_with_branch_head`
therefore remains 9. Protocol wrappers, repeated refs, and PR carriers are
route executions and do not increase that unique-payload denominator.

The 2026-07-23 live refresh records three open-PR carriers separately:

- keysmith PR #3 at `9acd55168898e1fe6f6cfe5c99f50d8a84e89a41`
  reuses the exact 7038-byte unique payload 9; it is tested as an unmerged
  carrier without being counted as another unique payload;
- Codex-5.5 PR #9 at `3b64052a7706626b47bd66fde74d43f8b80e020d`
  supplies the separately frozen compact payload;
- MDX draft PR #15 at `72156f5a7c06c32e350838df36aca82828052c34`
  changes documentation, loader code, and tests but no prompt payload blob, so
  its payload status is explicitly `NOT_PROVIDED`; loader behavior is not
  inferred and repository code is not executed.

Every available source binds repository, ref kind, exact commit, path, byte
length, SHA-256, and Git blob SHA. For the MDX v35 ZIP, the source ZIP identity
is recorded separately from the decoded archive-member payload identity.
Base64 files preserve exact decoded bytes, including missing trailing newlines.

The initial live manifest identity is retained in `refresh_history` before the
new keysmith branch and PR are added:

```text
queried_at: 2026-07-23T06:38:46.9201771+08:00
bytes: 21656
sha256: 5141ff51ca4d8128f62698b554ee569ee9e47732433c6b765e4092707f64d153
```

Direct-current-user and quoted/analytical scenarios are evaluated separately.
These bytes are visible development data and must never be described as blind,
independent, holdout, production approval, or proof of population recall.
