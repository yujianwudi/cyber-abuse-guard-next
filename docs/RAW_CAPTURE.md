# Blocked-request review capture

> [!IMPORTANT]
> The active Round 14 Host identity is CPA
> `v7.2.144@d36b776c790a4d58027fd4fb434800fb5334bceb`, C ABI 1 / RPC schema 4.
> Round 13 v7.2.125/schema 2 and older capture observations retain their exact
> historical identities and transfer no PASS. Every `/v1/realtime*` route
> bypasses CAG `RequestInterceptor`, `ModelRouter`, and request lifecycle, so it
> is **OUT_OF_SCOPE / UNPROTECTED / CAG_NOT_VISIBLE** and cannot produce a CAG
> blocked-request capture. Capture applies only to protected registered callback
> paths such as chat and Responses; it is not evidence of all-traffic coverage.
> The exact v7.2.144 / CAG `1.0.0` lane must revalidate it before any current
> transport or capture claim is admitted.

The raw-capture facility exists only for operator review of false-positive
blocks. It is not general request logging and it does not preserve an exact,
unbounded copy of every prompt.

> [!WARNING]
> Captures contain user-supplied request content. Secret redaction is
> best-effort and cannot recognize every custom, encoded, or fragmented secret.
> Restrict the audit data directory to the CPA service account, protect the CPA
> Management Key, keep the management listener private, and use transport
> encryption whenever the query crosses a host boundary.

## Safety contract

- Default: disabled. If a prior audit database or WAL/SHM artifact exists,
  startup publishes a disabled-capture runtime only after that storage opens
  and the retained previews are purged. A purge/open failure rejects the new
  runtime instead of hiding old review text. A hot reconfiguration to disabled
  is accepted only after the old audit queue is drained, every preview is
  deleted, and the WAL truncation succeeds; otherwise the previous runtime
  remains active and the reconfiguration is reported as failed.
  The purge preflights WAL progress and file permissions, then keeps a bounded
  in-memory snapshot of already-redacted rows until the post-delete gates pass
  (at most 256 MiB and 100,000 rows; larger snapshots fail before deletion).
  A recoverable post-commit failure restores the exact visible row set before
  rejection. An unrecoverable storage/I/O failure can also defeat compensation;
  that condition latches audit readiness unhealthy and blocks further raw
  writes, and is not claimed as byte-level rollback of failed media.
- `audit.data_dir` is immutable across an enabled-to-enabled hot
  reconfiguration. A path change is rejected before the candidate directory or
  SQLite database is opened; move the audit store only through a controlled
  restart and the operator backup/rollback procedure.
- Migration backups are a separate rollback boundary. A current schema-v7
  `<audit-db>.pre-v7-*.bak` is an exact snapshot and can retain sensitive
  request previews that existed before migration. Disabling Raw Capture purges
  only the active database and never silently deletes those backups. The
  authenticated status response discloses their count, oldest creation time,
  total bytes, and a sensitive-data warning.
- Scope: only requests whose final Guard disposition prevents upstream routing
  (`block`, including subject `cooldown`).
  `only_blocked: false` is rejected.
- Redaction: mandatory. `redact_secrets: false` is rejected.
- Processing: queue capacity is reserved before request-derived capture work.
  SHA-256 still covers the complete original request, while secret redaction is
  bounded to `max_bytes + 64 KiB` of prefix/overlap; the resulting preview is
  then truncated on a valid UTF-8 boundary.
- Per-record bound: `max_bytes`, default 8192, allowed range 1..1048576.
- Database bound: `audit.max_db_mb` is a live-page runtime hard cap, not only a
  periodic retention target. After each bounded writer batch, the Store removes
  oldest previews before ordinary events. If it cannot recover below the cap,
  later audit/capture writes are rejected and status becomes degraded; the
  request classification/disposition is not changed by that storage failure.
  Subject-state replacement uses a transactional live-page preflight and rolls
  back on overflow rather than allowing subject data to trigger evidence
  eviction; deleting subject state remeasures the gate immediately.
- Lifetime: `ttl_hours`, default 72 and allowed range 1..87600. When capture is
  enabled it may not exceed `audit.retention_days * 24`.
- Storage: the ordinary block event and optional preview enter the shared queue
  as one composite work item and are written in one SQLite transaction. If the
  preview insert fails, the metadata-only audit event remains the durable
  priority and dedicated capture-failure counters expose the missing preview.
- Retry deduplication: every blocking decision remains an ordinary audit event,
  but at most one preview of the same complete request is retained in one
  `ttl_hours` window. Deduplication reuses the already-persisted `raw_sha256`
  integrity value, so it still works when `log_request_hash: false` without
  manufacturing or exposing a `request_hash`. A request arriving exactly at
  the TTL boundary may create a fresh preview.
- Output: preview text must not be printed to service logs or included in CI or
  release artifacts. It is available only through the authenticated management
  query described below.
- Legacy switch: `audit.log_original_text: true` remains invalid. There is no
  unrestricted full-request logging mode.

The preview is intended to answer "why was this request blocked?" while
placing a hard bound on retained content. It may be truncated and may contain
replacement markers, so it is not a byte-exact legal or billing record.

## Migration-backup inventory and explicit cleanup

Authenticated `GET /v0/management/plugins/cyber-abuse-guard/status` includes a
path-free `migration_backups` object. It reports `inventory_available`,
`count`, `manifest_count`, `orphan_manifest_count`, `total_bytes`,
`oldest_created_at`, `potential_raw_capture_backup_count`, and
`may_contain_sensitive_request_data`. No backup filename, filesystem path,
digest, or preview is returned.

Deleting these files removes the exact database required for an older-SO
rollback, so cleanup is deliberately separate from Raw Capture disable and
requires both authenticated confirmations:

```bash
curl -fsS -X POST \
  -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  -H "Content-Type: application/json" \
  --data '{
    "delete_confirmation":"DELETE_ALL_MIGRATION_BACKUPS",
    "rollback_loss_confirmation":"ACKNOWLEDGE_OLD_SO_ROLLBACK_REQUIRES_EXTERNAL_BACKUP"
  }' \
  "http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/migration-backups/purge"
```

The body is a closed JSON contract: missing, wrong, trailing, or unknown fields
are rejected. Before cleanup, preserve and independently verify an external
rollback copy if an older SO may be needed. The response reports only deleted
counts, freed bytes, and the remaining path-free inventory.

## Configuration

```yaml
audit:
  enabled: true
  data_dir: /plugin-data/cyber-abuse-guard
  require_persistent_storage: true
  retention_days: 30
  max_db_mb: 256
  log_request_hash: true
  log_subject_hash: true
  log_original_text: false
  raw_capture:
    enabled: true
    only_blocked: true
    redact_secrets: true
    max_bytes: 8192
    ttl_hours: 72
```

Raw capture requires `audit.enabled: true`, an explicit absolute `audit.data_dir`,
and an explicit `audit.require_persistent_storage: true`. A configuration outside
the safety contract is rejected rather than silently weakened.

## Authenticated query

CPA's management middleware verifies the configured Management Key before the
plugin handler runs. The plugin additionally rejects a callback with no
management credential header.

```bash
curl -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  "http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/raw-captures?limit=20"
```

Supported query parameters are:

| Parameter | Meaning |
|---|---|
| `event_id` | Exact audit event UUID |
| `request_hash` | Exact `sha256:` request-correlation value from `/events`; unavailable when request-hash logging is disabled |
| `limit` | 1..100; defaults to 20 |

Parameters may be combined. Unknown, duplicate, malformed, or oversized
parameters return HTTP 400. A request body is not accepted.

Example correlation flow:

```bash
curl -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  "http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/events?action=block&decision_kind=block_malicious_text&limit=20"

curl -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  "http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/raw-captures?event_id=01234567-89ab-4def-8123-456789abcdef"
```

The response is JSON and is always sent with `Cache-Control: no-store`.
The payload below is illustrative: IDs, hashes, preview text, and every displayed
byte-count value are examples rather than an exact encoding of the placeholder
strings. In each live response, `cpa_host_response_bytes` is the exact predicted
size of that complete CPA Host-visible body:

```json
{
  "enabled": true,
  "audit_schema_version": 7,
  "decision_kind_semantics": "canonical-mutually-exclusive-v1",
  "explanation_schema_semantics": "decision-explanation-v2",
  "requested_limit": 20,
  "returned_count": 1,
  "response_truncated": false,
  "preview_bytes": 55,
  "encoded_preview_bytes": 63,
  "cpa_host_encoded_preview_bytes": 151,
  "response_preview_budget_bytes": 8388608,
  "cpa_host_response_budget_bytes": 8388608,
  "cpa_host_response_bytes": 1189,
  "raw_preview_transport": "cpa-json-html-escaped-utf8",
  "raw_preview_b64_encoding": "base64-standard-utf8",
  "raw_preview_rendering": "text-only-never-html",
  "raw_preview_deprecated": true,
  "encoded_preview_bytes_deprecated": true,
  "preferred_preview_field": "raw_preview_b64",
  "raw_capture_response_schema_version": 4,
  "captures": [
    {
      "id": "capture-id",
      "event_id": "01234567-89ab-4def-8123-456789abcdef",
      "timestamp": "2026-07-21T00:00:00Z",
      "request_hash": "sha256:...",
      "subject_hash": "hmac-sha256:...",
      "action": "block",
      "decision": "block_malicious_text",
      "decision_kind": "block_malicious_text",
      "explanation_schema": "decision-explanation-v2",
      "truncated": false,
      "preview_truncated": false,
      "redacted": true,
      "redaction_applied": true,
      "redaction_pattern_hits": 2,
      "redaction_version": "raw-redactor-v2",
      "raw_preview": "{\"messages\":[{\"content\":\"...\"}]}",
      "raw_preview_b64": "eyJtZXNzYWdlcyI6W3siY29udGVudCI6Ii4uLiJ9XX0=",
      "raw_sha256": "sha256:..."
    }
  ]
}
```

Historical CPA v7.2.116 Host evidence HTML-escaped every JSON string after the
plugin returned. That observation is not relabelled as v7.2.125 evidence; the
exact v7.2.125 / CAG `1.0.0` lane must revalidate it. The legacy `raw_preview` field is retained
for existing clients but is explicitly
deprecated by `raw_preview_deprecated: true`; it may not be byte-identical to
the stored redacted preview. `raw_preview_b64` is the canonical
transport-stable field identified by `preferred_preview_field`. It contains the
standard-Base64 encoding of the UTF-8 preview text. Base64 is not encryption,
access control, or additional redaction: after decoding it remains sensitive
user content.

Decode only into a mode-0600 file or a UI text node such as `textContent`.
Render it as plain text only. Never pass decoded bytes to `innerHTML`, an HTML
template, Markdown-with-HTML renderer, shell, or code interpreter. For a CLI
review:

```bash
umask 077
curl -fsS -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  "http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/raw-captures?event_id=01234567-89ab-4def-8123-456789abcdef" \
  | jq -r '.captures[0].raw_preview_b64' \
  | base64 --decode > reviewed-request.txt
```

The audit scanner enforces a fixed cumulative 8 MiB raw-preview budget and
scans at most one additional sentinel row, independent of both the accepted
query limit and the current `max_bytes` setting. This remains safe after a
configuration downgrade when the database still contains older 1 MiB rows: a
`limit=100` query cannot first materialize roughly 100 MiB of previews. The
management encoder separately enforces an 8 MiB budget over the complete
predicted Host-visible JSON body, including both preview fields and response
metadata. Its historical v7.2.116 Host-body result remains non-transferable;
the exact v7.2.125 / CAG `1.0.0` regression must confirm the prediction. The maximum single
1 MiB preview fits this budget for the reviewed worst-case HTML-escaping fixture.

`returned_count` is the number of records in `captures`.
`response_truncated: true` means the requested result may contain more records
than were returned under the response budget or bounded fetch. `preview_bytes`
counts the returned UTF-8 preview bytes. `encoded_preview_bytes` is the legacy
plugin-JSON size for `raw_preview` only and is deprecated.
`cpa_host_encoded_preview_bytes` counts the Host-encoded string content for
both `raw_preview` and `raw_preview_b64`; it is not the complete response size.
`cpa_host_response_bytes` is the exact predicted complete Host body and is the
value constrained by `cpa_host_response_budget_bytes`. Callers must not assume
that `returned_count == requested_limit`.

`subject_hash` can be empty when subject correlation is unavailable or
disabled. `request_hash` is likewise omitted when `log_request_hash: false`;
Raw Capture TTL deduplication still operates in that mode and does not expose a
replacement correlation hash.

Raw Capture response schema v4 adds `audit_schema_version`, fixed decision-kind
and explanation-schema semantics, and per-capture `decision_kind` plus
`explanation_schema`. `decision` remains the original transport/mode
disposition, while `decision_kind` is the canonical mutually exclusive reason.
For example, a Strict unknown-format refusal uses
`decision=block_unknown_source_format` with
`decision_kind=block_incomplete_inspection` and an incomplete v2 explanation.
Consumers must not infer a malicious classifier winner from `action=block` or
from the disposition string alone.

`preview_truncated` and `redaction_applied` are the canonical schema-v4 field
names. `truncated` and `redacted` are compatibility aliases for existing
clients; each alias always has the same value as its canonical field.
`preview_truncated` reports whether content exceeded `max_bytes` after
redaction or the bounded redaction window. `redaction_applied` reports only
that at least one supported redaction pattern made a replacement. A value of
`false` is **not** proof that the request contains no secret; custom, encoded,
fragmented, or otherwise unsupported secrets may remain.

`redaction_pattern_hits` is the number of supported-pattern matches replaced
while preparing the preview. `redaction_version` identifies how that metadata
was produced:

- `raw-redactor-v2`: current bounded redactor; it redacts complete unquoted
  semicolon-delimited cookie values and reports the hit count.
- `raw-redactor-v1`: prior bounded redactor retained for read compatibility;
  the hit count is available, but operators should treat its unquoted
  semicolon-delimited cookie handling as incomplete.
- `legacy-boolean-v0`: a row migrated from the earlier boolean-only schema;
  `redaction_pattern_hits` is `0` because the historical count is unknown, not
  because migration proved that no match existed.

`raw_sha256` is the direct SHA-256 of the complete original request bytes before
redaction and truncation. It supports integrity checks and the internal
unique-request TTL deduplication, but it is not a substitute for the
domain-separated `request_hash` audit correlation value. Repeated requests keep
all audit events and enforcement/accounting boundaries; only duplicate preview
storage is suppressed. A v4-to-v5 migration retains the newest preview for each
nonempty `raw_sha256` and labels migrated redaction metadata
`legacy-boolean-v0`. A v5-to-v6 migration adds the decision metadata columns;
historical captures are intentionally labeled
`decision_kind=legacy_unspecified` and `explanation_schema=none` rather than
being reclassified from legacy disposition text.

Expired captures are removed when the audit database opens and by the existing
periodic cleanup path (normally hourly). Deleting an ordinary audit event also
deletes its associated capture through the database relationship. TTL is a
retention ceiling evaluated by cleanup, not a promise that a row disappears at
the exact expiry nanosecond. SQLite `secure_delete` is enabled for every schema
v4 audit connection, including when capture is currently disabled. Disabling
capture deletes all preview rows and requests a truncating WAL checkpoint, but
these controls are not a forensic guarantee against storage-controller caches,
filesystem snapshots, external backups, or other copies.

If the entire `audit` subsystem is disabled before process startup, the plugin
does not open or mutate the configured audit database. Operators switching from
a prior capture-enabled deployment directly to `audit.enabled: false` across a
restart must securely remove or separately purge the old database and its
WAL/SHM files. A live reconfiguration from audit enabled to audit disabled does
perform the purge gate before the new runtime is published.

When capture is disabled and either audit is intentionally disabled or its
enabled store completed the startup/transition purge gate, the response has the
following shape. As above, the displayed `cpa_host_response_bytes` value is
illustrative; the live field is exact for the live body:

```json
{
  "enabled": false,
  "audit_schema_version": 7,
  "decision_kind_semantics": "canonical-mutually-exclusive-v1",
  "explanation_schema_semantics": "decision-explanation-v2",
  "requested_limit": 20,
  "returned_count": 0,
  "response_truncated": false,
  "preview_bytes": 0,
  "encoded_preview_bytes": 0,
  "cpa_host_encoded_preview_bytes": 0,
  "response_preview_budget_bytes": 8388608,
  "cpa_host_response_budget_bytes": 8388608,
  "cpa_host_response_bytes": 636,
  "raw_preview_transport": "cpa-json-html-escaped-utf8",
  "raw_preview_b64_encoding": "base64-standard-utf8",
  "raw_preview_rendering": "text-only-never-html",
  "raw_preview_deprecated": true,
  "encoded_preview_bytes_deprecated": true,
  "preferred_preview_field": "raw_preview_b64",
  "raw_capture_response_schema_version": 4,
  "captures": []
}
```

If `audit.enabled: true` but the audit database never opened and no prior audit
artifact was present to trigger a hard startup rejection, this endpoint returns
HTTP 503 with `audit_unavailable`; it does not present an authoritative empty
capture list. This preserves enforcement availability without concealing an
unknown storage state.

No fallback reads a CPA request log, ordinary audit event, or in-memory request
body. Consequently, enabling this setting cannot recover requests that were
blocked before it was enabled.

## Operational review

For each reviewed block, compare the required `event_id` with `/events`. When
`audit.log_request_hash: true`, also compare `request_hash`; when it is false,
the hash is intentionally omitted and must not be treated as missing evidence.
Record the disposition outside the capture database using an access-controlled
review system. Do not paste captured content into public issues, GitHub Actions
logs, chat rooms, or classifier test fixtures. If a capture reveals a false
positive, reduce it with a synthetic, repository-neutral regression rather than
copying customer text into the source tree.

`/status` and `/stats` expose dedicated
`raw_capture_enqueued/written/dropped/failed/rejected/deduplicated` counters,
the shared queue high-water observed by capture attempts, and preparation
count/total/last/max latency in microseconds. Queue-full attempts do not
increment the preparation count because they are rejected before request-body
capture work begins. Any queue admission loss immediately degrades audit
readiness. Recovery requires a successful post-loss durable event plus an
explicit Flush that covers the same loss generation; merely draining older work
cannot make readiness green.

CSAM privacy taint is request-wide and irreversible. A CSAM candidate, positive,
coverage loss, or private-budget exhaustion prevents Raw Capture for the final
block even if a legacy cyber-abuse or incomplete-inspection decision wins. The
ordinary low-cardinality audit event remains available for review without
persisting request text.
