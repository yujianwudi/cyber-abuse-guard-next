# Security Policy

The actively reviewed candidate is source `1.0.0`, planned tag
`v1.0.0-rc.3`, against CLIProxyAPI
`v7.2.144@d36b776c790a4d58027fd4fb434800fb5334bceb` on Linux amd64, C ABI 1 /
RPC schema 4. It remains a prerelease until the Round 14 exact-candidate gates
pass; Round 13 v7.2.125/schema 2 and older results are historical only and no
old PASS transfers. See [Round 14 status](docs/ROUND14_STATUS.md).

Every `/v1/realtime*` route currently bypasses CAG `RequestInterceptor`,
`ModelRouter`, and request lifecycle and is **OUT_OF_SCOPE / UNPROTECTED**.
Only registered callback paths such as chat and Responses are protected; this
is not an all-traffic security control.

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: f98ee38cea5b38b60130b98bd3ca6100cb6aeeee223128311235469af40ec9e3
```

## Supported versions

| Version | Status | Security support |
|---|---|---|
| Planned `v1.0.0-rc.3` | Active Linux amd64 candidate pinned to CPA `v7.2.144@d36b776c790a4d58027fd4fb434800fb5334bceb`, C ABI 1 / RPC schema 4; RC1 and RC2 are immutable historical admission records | Prerelease reports accepted; not stable production support |
| `v0.15` | **UNAVAILABLE**. The previously documented repository and Release returned GitHub API `404` on 2026-08-04; original bytes and digests are not currently reachable from the documented URLs | **SUPPORT SUSPENDED** until a verifiable read-only repository or signed immutable archive is restored |
| Source `0.16` / Round 12 working tree | Linux amd64 development source pinned to Go 1.26.4 and CPA v7.2.124 at `197f520426374e514218ed155933ac546c98d345`. C ABI 1 / RPC schema 2 are unchanged. Exact baseline `main@21267e742b624b29a75bd3683fd6914f76c764b5` CI, the supplied second-machine diagnostic, and five-repository data are historical v7.2.116 evidence only; exact v7.2.124 final-candidate CI, Multi-Agent v2 Responses-tool regression, and second-machine run remain pending, while protected Host, independent attestation, production approval, and release readiness are `NOT_PROVIDED` | Reports are accepted, but source development is not a supported release or production authorization |
| `v0.16-rc.1` / `v0.16-rc.2` / failed `v0.16-rc.3` / uncreated `v0.16-rc.4` identities | Immutable historical candidate and incident evidence; they are not current Round 12 output and must not be overwritten or republished | Historical only; not production-supported |
| Earlier versions | Historical or development evidence | Unsupported |

There is currently no downloadable release with active security support. The
project historically used exact two-part stable versions: `v0.15.0` is not an
alias for `v0.15`. Round 14 is a compatibility/admission round and does not
authorize a release. [Round 14 status](docs/ROUND14_STATUS.md) and the root
README status block define the active v7.2.144 identity while retaining all
older results as history only.
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
field for the single pinned CPA v7.2.144 lane. Its Host-visible encoding still
requires the exact-target regression; historical v7.2.124 and earlier results do not
transfer. Base64 is not encryption, access
control, or additional
redaction; its decoded UTF-8 text remains sensitive request content. Review
clients must insert decoded content into a plain-text node (for example,
`textContent`) and must never pass it to `innerHTML`, an HTML template, a
Markdown renderer with embedded HTML, a shell, or a code interpreter. Protect
management responses and any decoded files with the same controls as the audit
database.

The maintainer will acknowledge a complete report, assess severity and scope,
and coordinate a fix and disclosure timeline when the report is confirmed.
