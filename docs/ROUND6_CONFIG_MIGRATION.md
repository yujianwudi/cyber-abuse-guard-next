# Round 6 configuration migration

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: 1580f71d77cbb4bf58d3a734ae3a3994dfe2472478ed5f2dc1f18c86fa004b2d
```

Status: **BLOCKED / PENDING HOST AND INDEPENDENT AUDIT**. Configuration
migration is not deployment authorization. The only validation target in this
round is Linux amd64; see
[ROUND6_DEVELOPMENT_HANDOFF.md](ROUND6_DEVELOPMENT_HANDOFF.md).

Round 6 keeps old configurations bootable while removing the raw-prefix meaning of `max_scan_bytes`.

## Effective fields

```yaml
# Deprecated compatibility alias. It now selects the bounded text window.
max_scan_bytes: 262144

# Optional explicit replacement for max_scan_bytes.
# Range: 16384..1048576
# max_text_window_bytes: 262144

# Cumulative model-visible decoded text inspected per request.
# Default and hard maximum: 8388608
max_total_text_bytes: 8388608

# Optional classifier work bound. The default is computed from the window,
# total-text limit, and logical-field limit, with a floor of 2048.
# max_classification_chunks: 2048

# Logical text fields, not internal chunks.
max_text_parts: 512
```

## Compatibility rules

1. If `max_text_window_bytes` is omitted, `max_scan_bytes` is its compatibility alias.
2. Legacy values below 16 KiB are clamped to 16 KiB. They no longer truncate raw JSON.
3. Legacy values above 1 MiB are clamped to 1 MiB for retained-window memory.
4. If both keys are explicitly set, they must match; conflicting configuration is rejected.
5. `max_total_text_bytes` must be at least the effective window and cannot exceed 8 MiB.
6. An explicit `max_classification_chunks` must satisfy the computed minimum for the configured total text and logical-field limits.
7. Internal chunks do not consume `max_text_parts`; that field counts logical model-visible units.

## Operational behavior

A request is not incomplete merely because its raw JSON or decoded text exceeds 262144 bytes. It becomes incomplete only when a true bound or trust condition is reached, for example malformed JSON, unknown multipart schema, ambiguous role attribution, total text above the configured hard limit, classification-work exhaustion, unsupported content encoding, or an RPC body the plugin cannot see completely.

This also applies when CPA has converted an OpenAI image multipart form into a
JSON execution object while retaining the multipart Content-Type. Approved long
`prompt` strings use the streaming total-text/work limits; they are not cut by
the legacy multipart text-part or `max_scan_bytes` limits. Unknown fields and
non-string prompt values remain schema-incomplete.

Management status exposes the effective values and one fixed migration mode:

- `legacy_max_scan_bytes_alias`;
- `legacy_max_scan_bytes_clamped`;
- `explicit_max_text_window_bytes`.

## Rollback

Round 6 audit databases migrate to schema v3 after a privacy check and optional no-overwrite backup. Rolling back the plugin binary requires restoring the pre-v3 SQLite backup or using a fresh audit directory; an older binary must not open a v3 database as if it were v2.

Do not change a production `observe` deployment to `balanced` as part of configuration migration. Enforcement mode changes require separate approval after independent source, artifact, and Host validation.
