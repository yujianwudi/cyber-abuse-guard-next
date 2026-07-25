# Security Policy

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: fbdba9387158dfb1a5c0e6f175a5d56ae95a526c75b19644f72b74fb1675d227
```

## Supported versions

| Version | Status | Security support |
|---|---|---|
| `v0.15` | Current latest stable, manually published on 2026-07-20 UTC | Supported for confirmed security defects |
| Source `0.16` / `v0.16-rc.4` target | Round 9 Linux amd64 prerelease development target only; exact-main CI, counted-Mock Host evidence, and independent audit are `NOT_PROVIDED`, production approval is `NOT_GRANTED`, and stable `v0.16` is not released | Reports are accepted, but the target is not production-supported |
| `v0.16-rc.1` / `v0.16-rc.2` / failed `v0.16-rc.3` identities | Immutable historical candidate and incident evidence; they are not current Round 9 output and must not be overwritten or republished | Historical only; not production-supported |
| Earlier versions | Historical or development evidence | Unsupported |

The project uses exact two-part stable versions. `v0.15.0` is not an alias for
`v0.15`, and the intended future formal tag is `v0.16`, not `v0.16.0`.
Development snapshots, local RC packages, CI artifacts, and prereleases do not
become supported stable releases merely because they can be built or loaded.

## Reporting a vulnerability

Use GitHub's **Security > Report a vulnerability** flow for this repository;
Private Vulnerability Reporting is enabled and is the primary channel. Do not
put vulnerability details in a public issue. If the private form is temporarily
unavailable, a public issue may only ask the maintainer to establish a private
channel and must contain no technical details, reproducer, credentials, prompts,
capture values, account identifiers, or other sensitive material.

Include the affected version, CPA version, operating environment, reproduction
steps, expected impact, and whether the issue can expose prompts, credentials,
audit records, or upstream accounts. Please avoid including live credentials or
unredacted production prompts.

For issues involving `audit.raw_capture`, do not attach the audit SQLite file,
WAL/SHM files, an unredacted `raw_preview`, a `raw_preview_b64` value, or its
decoded content. Prefer the capture `event_id`, a request hash when enabled,
the blocking decision, the non-secret configuration, and the smallest synthetic
reproduction. Treat a potentially exposed CPA Management Key, HMAC key, request
credential, or captured secret as compromised and rotate it through the
operator's normal incident process.

The legacy `raw_preview` response field remains available for compatibility
but is deprecated. `raw_preview_b64` is the canonical byte-stable transport
field for the single pinned CPA v7.2.95 lane. Base64 is not encryption, access
control, or additional
redaction; its decoded UTF-8 text remains sensitive request content. Review
clients must insert decoded content into a plain-text node (for example,
`textContent`) and must never pass it to `innerHTML`, an HTML template, a
Markdown renderer with embedded HTML, a shell, or a code interpreter. Protect
management responses and any decoded files with the same controls as the audit
database.

The maintainer will acknowledge a complete report, assess severity and scope,
and coordinate a fix and disclosure timeline when the report is confirmed.
