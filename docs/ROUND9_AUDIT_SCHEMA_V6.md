# Round 9 audit schema v6

```text
current_classifier_policy_version: classifier-policy-v18
current_classifier_policy_sha256: 9f9541fe30a3b95aeb89fba0dc400fc8cdf89c4ad94880bc61bd4b1895036eaa
```

This document defines the durable audit contract introduced for Round 9. It is
an implementation and rollback reference, not production-deployment approval.
Production Balanced admission still requires the independent audit and
operator authorization described by the Round 9 task book.

## Identities and field mapping

Audit schema v6 separates the transport/mode disposition from the canonical,
mutually exclusive reason for the outcome.

| Public Go/JSON/CSV field | SQLite `audit_events` column | Meaning |
|---|---|---|
| `decision` | `disposition` | Original route disposition such as `block_unknown_source_format` or `audit_ineligible_risk` |
| `decision_kind` | `decision` | Canonical reason from the fixed enum below |
| `explanation_schema` | `explanation_schema` | `none`, `decision-explanation-v1`, or `decision-explanation-v2` |

The SQLite column reuse is intentional migration compatibility. Consumers must
use the public field names and must not infer a malicious winner from
`action=block`, `risk_score`, category, or the disposition string.

The eligibility explanation follows this closed chain:

| Stage | Source symbol | Representation |
|---|---|---|
| Candidate eligibility | `internal/classifier/eligibility.go` → `CandidateBlockEligibility` | Candidate-bound typed booleans, authorization state, primary gate, and reason bitset; no request text |
| Classifier explanation | `internal/classifier` → `DecisionExplanation` and `applyEligibilityToExplanation` | Adds referent-use, hard-floor, provenance, score, and bounded evidence-count fields to the eligibility scalars |
| Plugin conversion | `internal/plugin/decision_explanation.go` → `auditDecisionExplanation` | Explicit field-by-field copy into the audit package; occurrence offsets and request text are discarded |
| Public audit JSON | `internal/audit/event.go` → `Event.DecisionExplanation` | Closed `decision-explanation-v2` union branch validated against `decision_kind` and `explanation_schema` |
| SQLite | `audit_events.decision_explanation` | One bounded closed JSON value (`TEXT`, maximum 32768 bytes); the eligibility members are not independent free-text columns |
| Query/export | `internal/audit/query.go` | SQLite JSON is decoded and revalidated for `/events` and JSON export; CSV emits the same closed object in the `decision_explanation` cell |

The complete Round 9 malicious-eligibility mapping is below. "Same JSON
member" means the audit package retains the listed name inside the closed
`decision_explanation` object and persists that object in the single SQLite
column described above.

| Public/audit field | Classifier source | Audit JSON / SQLite / export mapping |
|---|---|---|
| `decision_kind` | Plugin disposition, not `CandidateBlockEligibility` | `Event.DecisionKind` → SQLite `decision` → JSON/CSV `decision_kind` |
| `winning_rule_id` | Classifier `DecisionExplanation.WinningRuleID` | Same JSON member; stored in `decision_explanation`; returned in JSON and the CSV JSON cell |
| `category` / `winning_category` | Result category and classifier `WinningCategory` | Top-level `category` plus bounded `winning_category` in `decision_explanation` |
| `block_eligible` | `CandidateBlockEligibility.Eligible` | `DecisionExplanation.BlockEligible`; same JSON member |
| `primary_eligibility_reason` | `CandidateBlockEligibility.PrimaryReason` | Same JSON member; closed `DispositionGate` value |
| `eligibility_reason_flags` | `CandidateBlockEligibility.ReasonFlags` | Same JSON member; unknown bits and evidence contradictions are rejected |
| `inspection_complete` | `CandidateBlockEligibility.InspectionComplete` | Same JSON member |
| `evidence_owned_by_current_user` | `CandidateBlockEligibility.EvidenceOwnedByCurrentUser` | Same JSON member; proves text provenance only, not real-world target ownership |
| `enforcement_scope` | `CandidateBlockEligibility.EnforcementScope` | Same JSON member; closed values are `current_user`, `request_local_system`, and `request_local_tool` |
| `current_execution_act_proven` | `CandidateBlockEligibility.CurrentExecutionActProven` | Same JSON member |
| `harmful_core_complete` | `CandidateBlockEligibility.HarmfulCoreComplete` | Same JSON member |
| `operationally_actionable` | `CandidateBlockEligibility.OperationallyActionable` | Same JSON member |
| `authorization_claim_state` | `CandidateBlockEligibility.AuthorizationClaim` | Same JSON member; `absent`, `consistent`, `conflicting`, or `unverifiable` |
| `explicit_victim_or_nonconsent` | `CandidateBlockEligibility.ExplicitVictimOrNonConsent` | Same JSON member; audit Go field is `ExplicitVictimOrNonconsent` but the JSON spelling is unchanged |
| `covert_acquisition` | `CandidateBlockEligibility.CovertAcquisition` | Same JSON member |
| `exfiltration_or_takeover` | `CandidateBlockEligibility.ExfiltrationOrTakeover` | Same JSON member |
| `malicious_persistence` | `CandidateBlockEligibility.MaliciousPersistence` | Same JSON member |
| `destructive_outcome` | `CandidateBlockEligibility.DestructiveOutcome` | Same JSON member |
| `security_control_evasion` | `CandidateBlockEligibility.SecurityControlEvasion` | Same JSON member |
| `defensive_scope_conflict` | `CandidateBlockEligibility.DefensiveScopeConflict` | Same JSON member |
| `quoted_or_analytical_scope` | `CandidateBlockEligibility.QuotedOrAnalyticalScope` | Same JSON member |
| `cross_scope_composition` | `CandidateBlockEligibility.CrossScopeComposition` | Same JSON member |
| `referent_link_used` | Classifier `DecisionExplanation.ReferentLinkUsed` | Same JSON member; it is true only for the bounded referent link actually used |
| `referent_proof_complete` | `CandidateBlockEligibility.ReferentProofComplete` | Same JSON member |
| `evidence_ambiguous` | `CandidateBlockEligibility.EvidenceAmbiguous` | Same JSON member |
| `hard_floor_applied` | Classifier `DecisionExplanation.HardFloorApplied` | Same JSON member; forbidden for ineligible explanations |
| `hard_floor_reason` | Classifier `DecisionExplanation.HardFloorReason` | Same JSON member; closed applied-reason identity or omitted |
| `evidence_segment_count` | Classifier `DecisionExplanation.EvidenceSegmentCount` | Same JSON member; bounded count only |
| `evidence_occurrence_count` | Classifier `DecisionExplanation.EvidenceOccurrenceCount` | Same JSON member; bounded count only |

Additional bounded scope/provenance members include `winning_role`,
`winning_provenance`, `current_turn_evidence`,
`cross_segment_composition`, and `quoted_or_inert_suppressed`. Candidate clause,
scope, referent-chain, field, and occurrence identities are used internally to
prevent cross-candidate evidence borrowing; raw text, spans, offsets, field
paths, arbitrary maps, and the internal identity coordinates are deliberately
not persisted.

Every newly written eligible malicious explanation has a nonempty
`enforcement_scope`. `current_user` requires the exact owned user-content,
current-turn provenance tuple. `request_local_system` and `request_local_tool`
require non-user content provenance and never prove subject ownership; the tool
scope is limited to a structurally terminal tool result. For read compatibility,
an older eligible v2 row may omit the field only when
`evidence_owned_by_current_user=true`, `winning_role=user`,
`winning_provenance=content`, and `current_turn_evidence=true`. Empty-scope
system/tool rows and every contradictory tuple are rejected. Ineligible v2
history may retain an empty scope because it asserts no blocking authority.

There are no independent SQLite columns for the eligibility booleans, malicious
predicates, hard-floor fields, or evidence counts. Consequently the supported
query filter is the canonical top-level `decision_kind`; consumers needing the
nested explanation must decode the closed JSON returned by `/events`, JSON
export, or the CSV `decision_explanation` field rather than treating arbitrary
SQLite JSON paths as a public API.

Canonical decision kinds are:

- `legacy_unspecified`
- `allow_clean`
- `audit_ineligible_risk`
- `audit_eligible_malicious_text`
- `block_malicious_text`
- `block_incomplete_inspection`
- `block_opaque_media`
- `block_subject_risk`

`legacy_unspecified` is read compatibility for historical rows, not a valid
identity for new router or management-mutation decisions.

## Explanation schemas

`decision-explanation-v1` is the read-only Round 8 flat explanation. New
canonical Round 9 decisions use `decision-explanation-v2`, a closed
discriminated union with exactly four variants:

| `kind` | Used for | Branch-only data |
|---|---|---|
| `malicious` | eligible malicious blocks, non-blocking eligible malicious findings, and audited ineligible classifier findings | bounded rule/category, score components, provenance and eligibility scalars |
| `incomplete` | incomplete-inspection blocks | one fixed `incomplete_inspection_reason` |
| `opaque_media` | opaque-media blocks | fixed `opaque_media_reason=opaque_media_present` |
| `subject_risk` | subject block or cooldown | `subject_risk_action=block` or `cooldown` |

`decision_kind=block_malicious_text` and
`decision_kind=audit_eligible_malicious_text` both require an eligible
malicious explanation with a logged winning category and winning rule. The
former requires a real block disposition; the latter is reserved for Observe,
Audit, or below-threshold non-blocking handling of the same eligible candidate.
Eligibility must prove complete inspection, one closed request authority scope,
a current execution act, a complete and actionable harmful core, resolved
scope/referent state, and no defensive, quoted, cross-scope, or ambiguous
conflict. `current_user` is ownership-bound; request-local system/tool authority
is non-user and cannot enter rolling subject state.
`audit_ineligible_risk` may carry an ineligible classifier explanation but must
never carry `block_eligible=true`. An ineligible explanation cannot apply a
hard floor.

The other three blocking kinds require their own independent v2 branch and
forbid malicious category/rule, score, hard-floor, or eligibility payload. A
Strict unknown CPA source format is represented as:

```text
decision=block_unknown_source_format
decision_kind=block_incomplete_inspection
coverage=incomplete
incomplete_reason=unknown_source_format
explanation_schema=decision-explanation-v2
decision_explanation.kind=incomplete
```

JSON decoding rejects unknown fields, unknown variants, trailing values, and
fields from another union branch. SQLite reads repeat schema and cross-field
validation so a malformed persisted row is not silently exported.

## v5 to v6 migration

Crossing into v6 performs these changes in one SQLite writer transaction:

1. add `audit_events.disposition`;
2. copy the historical `decision` value into `disposition`;
3. set the canonical `decision` column to `legacy_unspecified` for every
   historical row;
4. add `explanation_schema`, labeling empty historical explanations `none` and
   nonempty explanations `decision-explanation-v1`;
5. add the canonical decision/timestamp index;
6. add `decision_kind` and `explanation_schema` to Raw Capture, with historical
   values `legacy_unspecified` and `none`.

Raw Capture remains block-only. A non-blocking
`audit_eligible_malicious_text` event is queryable through the normal audit
event API but is never admitted to `raw_request_captures`.

Historical rows are deliberately not reclassified from score, category, rule,
or disposition text. If any migration statement, migration-history write, or
post-migration schema-contract check fails, the active database remains v5.
The pre-v6 recovery artifacts remain available.

## Mandatory pre-v6 backup

A migration into v6 always creates a backup even when
`audit.backup_before_migration` is false:

```text
<audit-db>.pre-v6-<UTC timestamp>.bak
<audit-db>.pre-v6-<UTC timestamp>.bak.manifest.json
```

The database is a SQLite online snapshot taken while the migration writer lock
is held. It includes all committed schema and rows, including retained Raw
Capture previews. Both artifacts are published mode `0400` from a private
same-filesystem staging directory and are synced before migration continues.
Treat them as sensitive audit data.

The manifest binds:

- manifest schema identity;
- backup filename;
- source and target schema versions;
- creation time;
- byte count and `sha256:` digest;
- `PRAGMA quick_check=ok`;
- `exact_snapshot=true`;
- the old-SO rollback instruction.

`audit.max_migration_backups` retention deletes an expired backup and its paired
manifest together. The manifest is not a signature or MAC: an actor able to
rewrite both files remains inside the filesystem trust boundary.

### Visibility and explicit cleanup

The authenticated management status exposes a path-free
`migration_backups` inventory with the backup/manifest counts, total bytes,
oldest creation time, potential Raw Capture backup count, and an explicit
sensitive-data warning. Inventory failures are reported as unavailable rather
than as a trustworthy zero.

Raw Capture disable and `PurgeRawCaptures` intentionally do not delete
migration backups. They are required for the old-SO rollback below and may
also retain request-preview material. Deletion is available only through the
separate authenticated `POST /migration-backups/purge` operation with both
exact confirmation values:

```json
{
  "delete_confirmation": "DELETE_ALL_MIGRATION_BACKUPS",
  "rollback_loss_confirmation": "ACKNOWLEDGE_OLD_SO_ROLLBACK_REQUIRES_EXTERNAL_BACKUP"
}
```

The operation rejects unknown JSON fields and non-regular/symlink artifacts,
does not expose filenames or paths, and records a bounded management mutation
when the active audit store is available. Operators must preserve another
verified rollback copy before confirming deletion if an older SO may be used.

## Old-SO rollback

An SO whose supported audit schema is v5 must reject a v6 database. Never load
an older SO against the v6 database or its WAL/SHM sidecars. The following is an
operator-only template; substitute the real service name, paths, owner, and
group.

1. Stop CPA and prove no process has the database open.
2. Select the manifest whose source is v5 and target is v6.
3. Verify the backup filename, bytes, SHA-256, schema version, and
   `quick_check` before copying it.
4. Preserve the current v6 database and sidecars for incident review.
5. Restore the verified pre-v6 backup on the same filesystem, set the CPA
   service ownership and mode `0600`, verify the restored hash, and only then
   load the old SO.

Example verification while CPA is stopped:

```bash
set -eu
db=/var/lib/cliproxyapi/cyber-abuse-guard/audit.db
backup="$db.pre-v6-YYYYMMDDTHHMMSS.NNNNNNNNNZ.bak"
manifest="$backup.manifest.json"

test "$(jq -r '.schema' "$manifest")" = "cyber-abuse-guard-audit-backup-v1"
test "$(jq -r '.database_file' "$manifest")" = "$(basename "$backup")"
test "$(jq -r '.source_schema_version' "$manifest")" = "5"
test "$(jq -r '.target_schema_version' "$manifest")" = "6"
test "$(jq -r '.exact_snapshot' "$manifest")" = "true"

expected_sha=$(jq -r '.sha256' "$manifest")
actual_sha="sha256:$(sha256sum "$backup" | awk '{print $1}')"
test "$actual_sha" = "$expected_sha"
test "$(stat -c '%s' "$backup")" = "$(jq -r '.bytes' "$manifest")"
test "$(sqlite3 -readonly "$backup" 'PRAGMA quick_check;')" = "ok"
test "$(sqlite3 -readonly "$backup" \
  'SELECT version FROM schema_version WHERE singleton=1;')" = "5"
```

Example same-filesystem restoration after the service has been stopped and the
verification above has passed:

```bash
set -eu
stamp=$(date -u +%Y%m%dT%H%M%SZ)
tmp="$db.restore-$stamp.tmp"

install -m 0600 "$backup" "$tmp"
test "sha256:$(sha256sum "$tmp" | awk '{print $1}')" = "$expected_sha"
sync -f "$tmp"

test ! -e "$db" || mv -- "$db" "$db.v6-before-rollback-$stamp"
test ! -e "$db-wal" || mv -- "$db-wal" "$db-wal.v6-before-rollback-$stamp"
test ! -e "$db-shm" || mv -- "$db-shm" "$db-shm.v6-before-rollback-$stamp"
mv -- "$tmp" "$db"
chmod 0600 "$db"
# chown <cpa-user>:<cpa-group> "$db"
sync -f "$(dirname "$db")"
```

Do not delete the preserved v6 artifacts until the rollback has been reviewed.
After CPA starts with the old SO, verify plugin load, audit health, database
schema v5, and one synthetic management query before restoring traffic.

## Query, export, management, and Raw Capture

- Audit-disabled and audit-unavailable are intentionally different management
  states. When `audit.enabled=false`, authenticated `/events` and `/stats`
  return their bounded schema-correct empty results and `DELETE /events`
  returns the disabled/no-op result. When `audit.enabled=true` but the runtime
  audit store is `nil` or otherwise unavailable, all three routes fail closed
  with HTTP `503` and the fixed `audit_unavailable` error; they must not
  fabricate a successful empty audit history or successful deletion.
- `audit.Query.DecisionKind` and the authenticated `/events?decision_kind=...`
  route filter the canonical SQLite decision column with a parameterized query.
- `Stats.ByDecisionKind` aggregates the same canonical identity.
- JSON events expose both `decision` and `decision_kind`.
- CSV exports include `decision`, `decision_kind`, `explanation_schema`, and the
  bounded structured explanation.
- `/events` response schema v2 includes `audit_schema_version`.
- Raw Capture response schema v4 includes `audit_schema_version`, fixed
  decision/explanation semantics, and per-capture `decision_kind` plus
  `explanation_schema`.
- Authenticated delete/unblock mutation markers are new canonical
  `allow_clean` events with no explanation; they do not use
  `legacy_unspecified`.

Raw Capture remains disabled by default, mandatory-redacted, bounded,
block-only, TTL-limited, and protected by CPA management authentication. Schema
metadata does not weaken those privacy controls. See [Raw Capture](RAW_CAPTURE.md).

## Linux verification coverage

Round 9 tests cover:

- the four v2 variants through validation, SQLite, JSON, CSV, and restart;
- unknown and cross-branch JSON field rejection;
- forced backup and manifest bytes, SHA-256, modes, schema, quick-check, and
  retained Raw Capture snapshot;
- injected v6 migration failure, v5 atomic preservation, and backup recovery;
- the supported-v5 old-SO schema gate rejecting v6;
- WAL, repeated reopen, and `PRAGMA quick_check`;
- decision-kind query/statistics/export;
- Raw Capture metadata and Strict unknown-source incomplete decisions;
- management events schema v2, Raw Capture schema v4, filter validation, and
  non-legacy management mutation markers;
- paired backup/manifest retention.
- path-free migration-backup status, Raw Capture-disable separation,
  dual-confirmation cleanup, literal database-name isolation, and symlink
  rejection.

The intermediate Linux audit-package run is recorded at
`dist/round9-worklogs/audit-schema-v6.log` (44528 bytes; SHA-256
`2fa6ebaf6baad0de384a20bc063cb9e7fb4f0734f8660596df89fcf17d593805`).
It passed for that uncommitted source snapshot, but the final repository source
has not been frozen and the final cross-package rerun is `PENDING_RERUN`. The
intermediate result does not execute an archived historical SO binary,
cryptographically authenticate the SQLite database, authorize production
deployment, or replace independent review of the exact release candidate.
