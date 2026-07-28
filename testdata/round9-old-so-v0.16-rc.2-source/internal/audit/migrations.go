package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

const currentSchemaVersion = 5

const migrationMetadataSchema = `
CREATE TABLE IF NOT EXISTS schema_version (
    singleton     INTEGER PRIMARY KEY CHECK (singleton = 1),
    version       INTEGER NOT NULL CHECK (version >= 0),
    updated_at_ns INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS migration_history (
    version       INTEGER PRIMARY KEY,
    applied_at_ns INTEGER NOT NULL,
    description   TEXT NOT NULL
);`

const subjectStateSchema = `
CREATE TABLE IF NOT EXISTS subject_state_meta (
    singleton           INTEGER PRIMARY KEY CHECK (singleton = 1),
    persistence_version INTEGER NOT NULL,
    hmac_key_id          TEXT NOT NULL,
    saved_at_ns          INTEGER NOT NULL,
    updated_at_ns        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS subject_state (
    subject_hash  TEXT PRIMARY KEY,
    state_json    TEXT NOT NULL CHECK (length(state_json) <= 1048576),
    updated_at_ns INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subject_state_updated_at
    ON subject_state(updated_at_ns DESC);`

const round6AuditEventColumns = `
ALTER TABLE audit_events ADD COLUMN decision TEXT NOT NULL DEFAULT 'legacy_unspecified';
ALTER TABLE audit_events ADD COLUMN coverage TEXT NOT NULL DEFAULT 'legacy_unknown';
ALTER TABLE audit_events ADD COLUMN incomplete_reason TEXT NOT NULL DEFAULT '';
ALTER TABLE audit_events ADD COLUMN scanner TEXT NOT NULL DEFAULT 'legacy';`

const rawRequestCaptureSchema = `
CREATE TABLE IF NOT EXISTS raw_request_captures (
    id             TEXT PRIMARY KEY,
    event_id       TEXT NOT NULL,
    timestamp_ns   INTEGER NOT NULL,
    request_hash   TEXT NOT NULL,
    subject_hash   TEXT NOT NULL,
    action         TEXT NOT NULL CHECK (action IN ('block', 'cooldown')),
    decision       TEXT NOT NULL,
    truncated      INTEGER NOT NULL CHECK (truncated IN (0, 1)),
    redacted       INTEGER NOT NULL CHECK (redacted IN (0, 1)),
    raw_preview    TEXT NOT NULL CHECK (length(CAST(raw_preview AS BLOB)) <= 1048576),
    raw_sha256     TEXT NOT NULL,
    FOREIGN KEY (event_id) REFERENCES audit_events(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_raw_request_captures_event
    ON raw_request_captures(event_id);
CREATE INDEX IF NOT EXISTS idx_raw_request_captures_timestamp
    ON raw_request_captures(timestamp_ns DESC);
CREATE INDEX IF NOT EXISTS idx_raw_request_captures_request_timestamp
    ON raw_request_captures(request_hash, timestamp_ns DESC);`

const round8AuditSchema = `
ALTER TABLE audit_events
    ADD COLUMN decision_explanation TEXT NOT NULL DEFAULT '{}'
    CHECK (length(CAST(decision_explanation AS BLOB)) <= 32768);
ALTER TABLE raw_request_captures
    ADD COLUMN redaction_pattern_hits INTEGER NOT NULL DEFAULT 0
    CHECK (redaction_pattern_hits >= 0 AND redaction_pattern_hits <= 1000000);
ALTER TABLE raw_request_captures
    ADD COLUMN redaction_version TEXT NOT NULL DEFAULT 'legacy-boolean-v0'
    CHECK (length(redaction_version) BETWEEN 1 AND 64);`

const round8RawCaptureDedupIndex = `CREATE UNIQUE INDEX IF NOT EXISTS idx_raw_request_captures_raw_sha256_unique
    ON raw_request_captures(raw_sha256)
    WHERE raw_sha256 <> '';`

const round8RawCaptureReplayIndex = `CREATE INDEX idx_raw_request_captures_replay_v5
    ON raw_request_captures(raw_sha256, timestamp_ns, id)
    WHERE raw_sha256 <> '';`

// Keep migration replay below SQLite's conservative variable limit while
// bounding both Go heap growth and the number of rows touched by one DELETE.
const rawCaptureReplayBatchSize = 256

type rowQueryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

type sqliteQueryer interface {
	rowQueryer
	Query(query string, args ...any) (*sql.Rows, error)
}

type sqliteQueryExecer interface {
	sqliteQueryer
	Exec(query string, args ...any) (sql.Result, error)
}

type migrationConnection struct {
	ctx  context.Context
	conn *sql.Conn
}

func (c migrationConnection) QueryRow(query string, args ...any) *sql.Row {
	return c.conn.QueryRowContext(c.ctx, query, args...)
}

func (c migrationConnection) Query(query string, args ...any) (*sql.Rows, error) {
	return c.conn.QueryContext(c.ctx, query, args...)
}

func (c migrationConnection) Exec(query string, args ...any) (sql.Result, error) {
	return c.conn.ExecContext(c.ctx, query, args...)
}

type sqliteColumnContract struct {
	name       string
	typeName   string
	notNull    bool
	primaryKey int
}

type sqliteIndexContract struct {
	name    string
	columns []string
	desc    []bool
}

var auditEventColumnContract = []sqliteColumnContract{
	{name: "id", typeName: "TEXT", primaryKey: 1},
	{name: "timestamp_ns", typeName: "INTEGER", notNull: true},
	{name: "action", typeName: "TEXT", notNull: true},
	{name: "mode", typeName: "TEXT", notNull: true},
	{name: "category", typeName: "TEXT", notNull: true},
	{name: "risk_score", typeName: "INTEGER", notNull: true},
	{name: "rule_ids", typeName: "TEXT", notNull: true},
	{name: "request_hash", typeName: "TEXT", notNull: true},
	{name: "subject_hash", typeName: "TEXT", notNull: true},
	{name: "model", typeName: "TEXT", notNull: true},
	{name: "source_format", typeName: "TEXT", notNull: true},
	{name: "stream", typeName: "INTEGER", notNull: true},
	{name: "text_bytes_scanned", typeName: "INTEGER", notNull: true},
	{name: "classifier", typeName: "TEXT", notNull: true},
	{name: "latency_us", typeName: "INTEGER", notNull: true},
	{name: "decision", typeName: "TEXT", notNull: true},
	{name: "coverage", typeName: "TEXT", notNull: true},
	{name: "incomplete_reason", typeName: "TEXT", notNull: true},
	{name: "scanner", typeName: "TEXT", notNull: true},
	{name: "decision_explanation", typeName: "TEXT", notNull: true},
}

var auditEventIndexContract = []sqliteIndexContract{
	{name: "idx_audit_events_timestamp", columns: []string{"timestamp_ns"}, desc: []bool{true}},
	{name: "idx_audit_events_action_timestamp", columns: []string{"action", "timestamp_ns"}, desc: []bool{false, true}},
	{name: "idx_audit_events_category_timestamp", columns: []string{"category", "timestamp_ns"}, desc: []bool{false, true}},
	{name: "idx_audit_events_subject_timestamp", columns: []string{"subject_hash", "timestamp_ns"}, desc: []bool{false, true}},
}

var rawRequestCaptureColumnContract = []sqliteColumnContract{
	{name: "id", typeName: "TEXT", primaryKey: 1},
	{name: "event_id", typeName: "TEXT", notNull: true},
	{name: "timestamp_ns", typeName: "INTEGER", notNull: true},
	{name: "request_hash", typeName: "TEXT", notNull: true},
	{name: "subject_hash", typeName: "TEXT", notNull: true},
	{name: "action", typeName: "TEXT", notNull: true},
	{name: "decision", typeName: "TEXT", notNull: true},
	{name: "truncated", typeName: "INTEGER", notNull: true},
	{name: "redacted", typeName: "INTEGER", notNull: true},
	{name: "raw_preview", typeName: "TEXT", notNull: true},
	{name: "raw_sha256", typeName: "TEXT", notNull: true},
	{name: "redaction_pattern_hits", typeName: "INTEGER", notNull: true},
	{name: "redaction_version", typeName: "TEXT", notNull: true},
}

var rawRequestCaptureIndexContract = []sqliteIndexContract{
	{name: "idx_raw_request_captures_event", columns: []string{"event_id"}, desc: []bool{false}},
	{name: "idx_raw_request_captures_timestamp", columns: []string{"timestamp_ns"}, desc: []bool{true}},
	{name: "idx_raw_request_captures_request_timestamp", columns: []string{"request_hash", "timestamp_ns"}, desc: []bool{false, true}},
	{name: "idx_raw_request_captures_raw_sha256_unique", columns: []string{"raw_sha256"}, desc: []bool{false}},
}

func migrateDatabase(db *sql.DB, cfg Config, databasePath string) error {
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("audit: reserve migration connection: %w", err)
	}
	defer conn.Close()

	locked := migrationConnection{ctx: ctx, conn: conn}
	if _, err := locked.Exec("BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("audit: acquire migration writer lock: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = locked.Exec("ROLLBACK")
		}
	}()

	version, err := detectSchemaVersion(locked)
	if err != nil {
		return fmt.Errorf("audit: detect schema version: %w", err)
	}
	if version > currentSchemaVersion {
		return fmt.Errorf("audit: database schema version %d is newer than supported version %d", version, currentSchemaVersion)
	}
	if err := validateSchemaContract(locked, version); err != nil {
		return fmt.Errorf("audit: schema version %d contract is invalid: %w", version, err)
	}
	if version > 0 && version < currentSchemaVersion {
		// A pre-migration backup is an additional persistent copy. Refuse to
		// create it (or advance the schema) when legacy correlation columns do
		// not already satisfy the privacy-minimal digest/canonical contracts.
		// The original database remains untouched for operator-directed repair.
		if err := validateLegacyAuditPrivacy(locked, version); err != nil {
			return fmt.Errorf("audit: legacy privacy contract is invalid: %w", err)
		}
	}
	if cfg.BackupBeforeMigration && version > 0 && version < currentSchemaVersion {
		if err := createMigrationBackup(db, cfg, databasePath); err != nil {
			return fmt.Errorf("audit: create pre-migration backup: %w", err)
		}
	}

	if _, err := locked.Exec(migrationMetadataSchema); err != nil {
		return fmt.Errorf("audit: create migration metadata: %w", err)
	}
	nowNS := cfg.Now().UTC().UnixNano()
	if version > 0 {
		if _, err := locked.Exec(`INSERT OR IGNORE INTO migration_history(version, applied_at_ns, description) VALUES(1, ?, ?)`, nowNS, "v0.1.1 audit_events baseline"); err != nil {
			return fmt.Errorf("audit: record baseline migration: %w", err)
		}
		if _, err := locked.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, ?, ?)
ON CONFLICT(singleton) DO UPDATE SET version=excluded.version, updated_at_ns=excluded.updated_at_ns`, version, nowNS); err != nil {
			return fmt.Errorf("audit: initialize schema version: %w", err)
		}
	}

	for next := version + 1; next <= currentSchemaVersion; next++ {
		description := ""
		switch next {
		case 1:
			description = "create audit event schema"
			if _, err := locked.Exec(schema); err != nil {
				return fmt.Errorf("audit: apply schema migration 1: %w", err)
			}
		case 2:
			description = "add version metadata and optional subject state storage"
			if _, err := locked.Exec(subjectStateSchema); err != nil {
				return fmt.Errorf("audit: apply schema migration 2: %w", err)
			}
		case 3:
			description = "add Round6 decision, coverage, incomplete reason, and scanner identity"
			if _, err := locked.Exec(round6AuditEventColumns); err != nil {
				return fmt.Errorf("audit: apply schema migration 3: %w", err)
			}
		case 4:
			description = "add bounded redacted block-only raw request captures"
			if _, err := locked.Exec(rawRequestCaptureSchema); err != nil {
				return fmt.Errorf("audit: apply schema migration 4: %w", err)
			}
		case 5:
			description = "add privacy-safe decision explanations and request-deduplicated raw captures"
			if _, err := locked.Exec(round8AuditSchema); err != nil {
				return fmt.Errorf("audit: apply schema migration 5: %w", err)
			}
			// The replay index keeps keyset pages bounded while avoiding a full
			// table sort for every page. It is dropped before commit because the
			// final partial unique index serves the runtime contract.
			if _, err := locked.Exec(round8RawCaptureReplayIndex); err != nil {
				return fmt.Errorf("audit: apply schema migration 5 replay index: %w", err)
			}
			if err := replayRawCaptureTTLWindows(locked, cfg.RawCapture.TTL); err != nil {
				return fmt.Errorf("audit: apply schema migration 5 raw capture deduplication: %w", err)
			}
			if _, err := locked.Exec(`DROP INDEX idx_raw_request_captures_replay_v5`); err != nil {
				return fmt.Errorf("audit: remove schema migration 5 replay index: %w", err)
			}
			if _, err := locked.Exec(round8RawCaptureDedupIndex); err != nil {
				return fmt.Errorf("audit: apply schema migration 5 raw capture index: %w", err)
			}
		default:
			return fmt.Errorf("audit: missing schema migration %d", next)
		}
		if _, err := locked.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(?, ?, ?)`, next, nowNS, description); err != nil {
			return fmt.Errorf("audit: record schema migration %d: %w", next, err)
		}
		if _, err := locked.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, ?, ?)
ON CONFLICT(singleton) DO UPDATE SET version=excluded.version, updated_at_ns=excluded.updated_at_ns`, next, nowNS); err != nil {
			return fmt.Errorf("audit: advance schema version to %d: %w", next, err)
		}
	}
	if err := validateSchemaContract(locked, currentSchemaVersion); err != nil {
		return fmt.Errorf("audit: migrated schema contract is invalid before commit: %w", err)
	}

	if _, err := locked.Exec("COMMIT"); err != nil {
		return fmt.Errorf("audit: commit schema migration: %w", err)
	}
	committed = true
	if err := validateSchemaContract(db, currentSchemaVersion); err != nil {
		return fmt.Errorf("audit: migrated schema contract is invalid: %w", err)
	}
	return nil
}

// replayRawCaptureTTLWindows deterministically replays the v5 admission rule
// over v4 rows. The first capture in a TTL window is retained; later captures
// with the same digest are duplicates until the retained capture reaches the
// exact TTL boundary. Ordering by ID makes equal-timestamp legacy rows stable.
func replayRawCaptureTTLWindows(db sqliteQueryExecer, ttl time.Duration) error {
	if ttl <= 0 {
		return errors.New("raw capture TTL must be positive")
	}
	var (
		currentRawSHA     string
		retainedID        string
		retainedTimestamp int64
		haveRetained      bool
		cursorRawSHA      string
		cursorID          string
		cursorTimestamp   int64
		haveCursor        bool
	)
	for {
		var (
			rows *sql.Rows
			err  error
		)
		if !haveCursor {
			rows, err = db.Query(`SELECT id, raw_sha256, timestamp_ns
FROM raw_request_captures
WHERE raw_sha256 <> ''
ORDER BY raw_sha256 ASC, timestamp_ns ASC, id ASC
LIMIT ?`, rawCaptureReplayBatchSize)
		} else {
			rows, err = db.Query(`SELECT id, raw_sha256, timestamp_ns
FROM raw_request_captures
WHERE raw_sha256 <> '' AND (
    raw_sha256 > ? OR
    (raw_sha256 = ? AND (
        timestamp_ns > ? OR
        (timestamp_ns = ? AND id > ?)
    ))
)
ORDER BY raw_sha256 ASC, timestamp_ns ASC, id ASC
LIMIT ?`, cursorRawSHA, cursorRawSHA, cursorTimestamp, cursorTimestamp, cursorID, rawCaptureReplayBatchSize)
		}
		if err != nil {
			return fmt.Errorf("read legacy raw captures for TTL replay: %w", err)
		}

		pageRows := 0
		duplicateIDs := make([]string, 0, rawCaptureReplayBatchSize)
		for rows.Next() {
			var id, rawSHA string
			var timestampNS int64
			if err := rows.Scan(&id, &rawSHA, &timestampNS); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan legacy raw capture for TTL replay: %w", err)
			}
			pageRows++
			cursorRawSHA = rawSHA
			cursorTimestamp = timestampNS
			cursorID = id
			haveCursor = true

			if !haveRetained || rawSHA != currentRawSHA {
				currentRawSHA = rawSHA
				retainedID = id
				retainedTimestamp = timestampNS
				haveRetained = true
				continue
			}
			if timestampNS < retainedTimestamp {
				_ = rows.Close()
				return errors.New("legacy raw capture TTL replay order is invalid")
			}

			// Unsigned subtraction preserves the full non-negative int64 timestamp
			// distance without overflow. Equality opens a new window, matching the
			// runtime DELETE ... timestamp_ns <= incoming-TTL boundary.
			elapsed := uint64(timestampNS) - uint64(retainedTimestamp)
			if elapsed < uint64(ttl) {
				duplicateIDs = append(duplicateIDs, id)
				continue
			}
			// The incoming capture starts a new live window. Runtime admission
			// deletes the expired retained row before inserting this capture.
			duplicateIDs = append(duplicateIDs, retainedID)
			retainedID = id
			retainedTimestamp = timestampNS
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("iterate legacy raw captures for TTL replay: %w", err)
		}
		if err := rows.Close(); err != nil {
			return fmt.Errorf("close legacy raw capture TTL replay rows: %w", err)
		}
		if err := deleteRawCaptureReplayBatch(db, duplicateIDs); err != nil {
			return err
		}
		if pageRows < rawCaptureReplayBatchSize {
			break
		}
	}
	return nil
}

func deleteRawCaptureReplayBatch(db sqliteQueryExecer, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	if len(ids) > rawCaptureReplayBatchSize {
		return errors.New("legacy raw capture replay delete batch exceeds budget")
	}
	placeholders := strings.Repeat("?,", len(ids))
	placeholders = strings.TrimSuffix(placeholders, ",")
	args := make([]any, len(ids))
	for index, id := range ids {
		args[index] = id
	}
	result, err := db.Exec(`DELETE FROM raw_request_captures WHERE id IN (`+placeholders+`)`, args...)
	if err != nil {
		return fmt.Errorf("delete legacy raw capture duplicate batch: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("count deleted legacy raw capture duplicate batch: %w", err)
	}
	if deleted != int64(len(ids)) {
		return errors.New("legacy raw capture duplicate batch changed during TTL replay")
	}
	return nil
}

func validateLegacyAuditPrivacy(db sqliteQueryer, version int) error {
	rows, err := db.Query(`SELECT request_hash, subject_hash, model, source_format FROM audit_events`)
	if err != nil {
		return fmt.Errorf("inspect legacy audit privacy fields: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var requestHash, subjectHash, model, sourceFormat string
		if err := rows.Scan(&requestHash, &subjectHash, &model, &sourceFormat); err != nil {
			return fmt.Errorf("scan legacy audit privacy fields: %w", err)
		}
		if requestHash != "" && !validDigest(requestHash, "sha256:") {
			return errors.New("request_hash is not a SHA-256 correlation value")
		}
		if subjectHash != "" && !validDigest(subjectHash, "hmac-sha256:") {
			return errors.New("subject_hash is not an HMAC-SHA256 correlation value")
		}
		if model != "" && !validDigest(model, modelHashPrefix) {
			return errors.New("model is not a domain-separated SHA-256 correlation value")
		}
		if sourceFormat != "" && !oneOf(sourceFormat, "openai", "openai-response", "interactions", SourceFormatCodexAlphaSearch, "openai-image", "openai-video", "claude", "anthropic", "gemini", SourceFormatUnknown) {
			return errors.New("source_format is not a fixed provider value")
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy audit privacy fields: %w", err)
	}
	if version >= 4 {
		if err := validateLegacyRawCapturePrivacy(db); err != nil {
			return err
		}
	}
	return nil
}

func validateLegacyRawCapturePrivacy(db sqliteQueryer) error {
	rows, err := db.Query(`SELECT id, event_id, timestamp_ns, request_hash, subject_hash,
action, decision, truncated, redacted, raw_preview, raw_sha256
FROM raw_request_captures`)
	if err != nil {
		return fmt.Errorf("inspect legacy raw capture privacy fields: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var capture RawRequestCapture
		var timestampNS int64
		var truncated, redacted int
		if err := rows.Scan(
			&capture.ID, &capture.EventID, &timestampNS, &capture.RequestHash,
			&capture.SubjectHash, &capture.Action, &capture.Decision, &truncated,
			&redacted, &capture.RawPreview, &capture.RawSHA256,
		); err != nil {
			return fmt.Errorf("scan legacy raw capture privacy fields: %w", err)
		}
		capture.Timestamp = time.Unix(0, timestampNS).UTC()
		capture.Truncated = truncated != 0
		capture.Redacted = redacted != 0
		capture.PreviewTruncated = capture.Truncated
		capture.RedactionApplied = capture.Redacted
		capture.RedactionVersion = legacyRawCaptureRedactionVersion
		if err := validateRawRequestCapture(capture); err != nil {
			return fmt.Errorf("legacy raw capture privacy contract is invalid: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate legacy raw capture privacy fields: %w", err)
	}
	return nil
}

func validateSchemaContract(db sqliteQueryer, version int) error {
	if version >= 1 {
		columns := auditEventColumnContract
		if version < 3 {
			// Versions 1 and 2 predate the four fixed Round6 metadata columns.
			columns = auditEventColumnContract[:15]
		} else if version < 5 {
			// Versions 3 and 4 predate the Round8 decision explanation.
			columns = auditEventColumnContract[:19]
		}
		if err := requireSQLiteTable(db, "audit_events", columns); err != nil {
			return err
		}
		if version >= 5 {
			if err := requireSQLiteDDLFragments(db, "audit_events",
				"check(length(cast(decision_explanationasblob))<=32768)"); err != nil {
				return err
			}
		}
		for _, index := range auditEventIndexContract {
			if err := requireSQLiteIndex(db, index); err != nil {
				return err
			}
		}
	}
	hasMetadata, err := sqliteTableExists(db, "schema_version")
	if err != nil {
		return fmt.Errorf("inspect schema metadata presence: %w", err)
	}
	if version >= 2 && !hasMetadata {
		return errors.New("schema version 2 is missing schema_version metadata")
	}
	if hasMetadata {
		if err := requireSQLiteTable(db, "schema_version", []sqliteColumnContract{
			{name: "singleton", typeName: "INTEGER", primaryKey: 1},
			{name: "version", typeName: "INTEGER", notNull: true},
			{name: "updated_at_ns", typeName: "INTEGER", notNull: true},
		}); err != nil {
			return err
		}
		if err := requireSQLiteTable(db, "migration_history", []sqliteColumnContract{
			{name: "version", typeName: "INTEGER", primaryKey: 1},
			{name: "applied_at_ns", typeName: "INTEGER", notNull: true},
			{name: "description", typeName: "TEXT", notNull: true},
		}); err != nil {
			return err
		}
		if err := requireSQLiteDDLFragments(db, "schema_version", "check(singleton=1)", "check(version>=0)"); err != nil {
			return err
		}
		if err := validateMigrationMetadata(db, version); err != nil {
			return err
		}
	}
	if version >= 2 {
		if err := requireSQLiteTable(db, "subject_state_meta", []sqliteColumnContract{
			{name: "singleton", typeName: "INTEGER", primaryKey: 1},
			{name: "persistence_version", typeName: "INTEGER", notNull: true},
			{name: "hmac_key_id", typeName: "TEXT", notNull: true},
			{name: "saved_at_ns", typeName: "INTEGER", notNull: true},
			{name: "updated_at_ns", typeName: "INTEGER", notNull: true},
		}); err != nil {
			return err
		}
		if err := requireSQLiteTable(db, "subject_state", []sqliteColumnContract{
			{name: "subject_hash", typeName: "TEXT", primaryKey: 1},
			{name: "state_json", typeName: "TEXT", notNull: true},
			{name: "updated_at_ns", typeName: "INTEGER", notNull: true},
		}); err != nil {
			return err
		}
		if err := requireSQLiteDDLFragments(db, "subject_state_meta", "check(singleton=1)"); err != nil {
			return err
		}
		if err := requireSQLiteDDLFragments(db, "subject_state", "check(length(state_json)<=1048576)"); err != nil {
			return err
		}
		if err := requireSQLiteIndex(db, sqliteIndexContract{
			name: "idx_subject_state_updated_at", columns: []string{"updated_at_ns"}, desc: []bool{true},
		}); err != nil {
			return err
		}
	}
	if version >= 4 {
		columns := rawRequestCaptureColumnContract
		indexes := rawRequestCaptureIndexContract
		if version < 5 {
			columns = rawRequestCaptureColumnContract[:11]
			indexes = rawRequestCaptureIndexContract[:3]
		}
		if err := requireSQLiteTable(db, "raw_request_captures", columns); err != nil {
			return err
		}
		if err := requireSQLiteDDLFragments(db, "raw_request_captures",
			"check(actionin('block','cooldown'))",
			"check(truncatedin(0,1))",
			"check(redactedin(0,1))",
			"check(length(cast(raw_previewasblob))<=1048576)",
			"foreignkey(event_id)referencesaudit_events(id)ondeletecascade",
		); err != nil {
			return err
		}
		if version >= 5 {
			if err := requireSQLiteDDLFragments(db, "raw_request_captures",
				"check(redaction_pattern_hits>=0andredaction_pattern_hits<=1000000)",
				"check(length(redaction_version)between1and64)"); err != nil {
				return err
			}
		}
		for _, index := range indexes {
			if err := requireSQLiteIndex(db, index); err != nil {
				return err
			}
		}
		if version >= 5 {
			if err := requireSQLiteIndexDDLFragments(db, "idx_raw_request_captures_raw_sha256_unique",
				"create unique index", "where raw_sha256 <> ''"); err != nil {
				return err
			}
		}
	}
	return nil
}

func requireSQLiteIndexDDLFragments(db rowQueryer, index string, fragments ...string) error {
	var statement string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'index' AND name = ?`, index).Scan(&statement); err != nil {
		return fmt.Errorf("inspect index %s definition: %w", index, err)
	}
	normalized := strings.Join(strings.Fields(strings.ToLower(statement)), " ")
	for _, fragment := range fragments {
		if !strings.Contains(normalized, strings.Join(strings.Fields(strings.ToLower(fragment)), " ")) {
			return fmt.Errorf("index %s is missing required definition %s", index, fragment)
		}
	}
	return nil
}

func requireSQLiteTable(db sqliteQueryer, table string, required []sqliteColumnContract) error {
	rows, err := db.Query(`SELECT name, type, "notnull", pk FROM pragma_table_info(?) ORDER BY cid`, table)
	if err != nil {
		return fmt.Errorf("inspect table %s: %w", table, err)
	}
	defer rows.Close()
	found := make([]sqliteColumnContract, 0, len(required))
	for rows.Next() {
		var column sqliteColumnContract
		var notNull int
		if err := rows.Scan(&column.name, &column.typeName, &notNull, &column.primaryKey); err != nil {
			return fmt.Errorf("scan table %s contract: %w", table, err)
		}
		column.typeName = strings.ToUpper(strings.TrimSpace(column.typeName))
		column.notNull = notNull == 1
		found = append(found, column)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate table %s contract: %w", table, err)
	}
	if len(found) != len(required) {
		return fmt.Errorf("table %s has %d columns, want exactly %d", table, len(found), len(required))
	}
	for index, want := range required {
		got := found[index]
		if got.name != want.name || got.typeName != want.typeName || got.notNull != want.notNull || got.primaryKey != want.primaryKey {
			return fmt.Errorf("table %s column %d contract mismatch: got name=%s type=%s notnull=%t pk=%d, want name=%s type=%s notnull=%t pk=%d",
				table, index, got.name, got.typeName, got.notNull, got.primaryKey,
				want.name, want.typeName, want.notNull, want.primaryKey)
		}
	}
	return nil
}

func requireSQLiteIndex(db sqliteQueryer, required sqliteIndexContract) error {
	rows, err := db.Query(`SELECT name, "desc" FROM pragma_index_xinfo(?) WHERE key = 1 ORDER BY seqno`, required.name)
	if err != nil {
		return fmt.Errorf("inspect index %s: %w", required.name, err)
	}
	defer rows.Close()
	columns := make([]string, 0, len(required.columns))
	descending := make([]bool, 0, len(required.desc))
	for rows.Next() {
		var name string
		var desc int
		if err := rows.Scan(&name, &desc); err != nil {
			return fmt.Errorf("scan index %s contract: %w", required.name, err)
		}
		columns = append(columns, name)
		descending = append(descending, desc == 1)
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("iterate index %s contract: %w", required.name, err)
	}
	if len(columns) != len(required.columns) || len(descending) != len(required.desc) {
		return fmt.Errorf("index %s has %d key columns, want %d", required.name, len(columns), len(required.columns))
	}
	for index := range required.columns {
		if columns[index] != required.columns[index] || descending[index] != required.desc[index] {
			return fmt.Errorf("index %s key %d mismatch: got column=%s desc=%t, want column=%s desc=%t",
				required.name, index, columns[index], descending[index], required.columns[index], required.desc[index])
		}
	}
	return nil
}

func requireSQLiteDDLFragments(db sqliteQueryer, table string, fragments ...string) error {
	var statement string
	if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&statement); err != nil {
		return fmt.Errorf("inspect table %s definition: %w", table, err)
	}
	normalized := strings.Join(strings.Fields(strings.ToLower(statement)), "")
	for _, fragment := range fragments {
		if !strings.Contains(normalized, strings.ToLower(fragment)) {
			return fmt.Errorf("table %s is missing required constraint %s", table, fragment)
		}
	}
	return nil
}

func validateMigrationMetadata(db sqliteQueryer, version int) error {
	rows, err := db.Query(`SELECT singleton, version FROM schema_version ORDER BY singleton`)
	if err != nil {
		return fmt.Errorf("inspect schema_version rows: %w", err)
	}
	var metadataRows int
	for rows.Next() {
		var singleton, recorded int
		if err := rows.Scan(&singleton, &recorded); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan schema_version row: %w", err)
		}
		metadataRows++
		if singleton != 1 || recorded != version {
			_ = rows.Close()
			return fmt.Errorf("schema_version row is singleton=%d version=%d, want singleton=1 version=%d", singleton, recorded, version)
		}
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close schema_version rows: %w", err)
	}
	if metadataRows != 1 {
		return fmt.Errorf("schema_version contains %d rows, want exactly 1", metadataRows)
	}

	history, err := db.Query(`SELECT version FROM migration_history ORDER BY version`)
	if err != nil {
		return fmt.Errorf("inspect migration history: %w", err)
	}
	defer history.Close()
	next := 1
	for history.Next() {
		var recorded int
		if err := history.Scan(&recorded); err != nil {
			return fmt.Errorf("scan migration history: %w", err)
		}
		if recorded != next {
			return fmt.Errorf("migration history version %d is out of sequence; want %d", recorded, next)
		}
		next++
	}
	if err := history.Err(); err != nil {
		return fmt.Errorf("iterate migration history: %w", err)
	}
	if next != version+1 {
		return fmt.Errorf("migration history covers %d versions, want %d", next-1, version)
	}
	return nil
}

func detectSchemaVersion(db rowQueryer) (int, error) {
	hasMetadata, err := sqliteTableExists(db, "schema_version")
	if err != nil {
		return 0, err
	}
	if hasMetadata {
		var version int
		if err := db.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return 0, errors.New("schema_version table has no singleton row")
			}
			return 0, err
		}
		if version < 0 {
			return 0, errors.New("schema version must not be negative")
		}
		return version, nil
	}
	hasEvents, err := sqliteTableExists(db, "audit_events")
	if err != nil {
		return 0, err
	}
	if hasEvents {
		return 1, nil
	}
	return 0, nil
}

func sqliteTableExists(db rowQueryer, name string) (bool, error) {
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?`, name).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func createMigrationBackup(db *sql.DB, cfg Config, databasePath string) error {
	if cfg.MaxMigrationBackups < 1 || cfg.MaxMigrationBackups > 32 {
		return fmt.Errorf("maximum migration backups must be between 1 and 32, got %d", cfg.MaxMigrationBackups)
	}
	stamp := cfg.Now().UTC().Format("20060102T150405.000000000Z")
	backupPath := fmt.Sprintf("%s.pre-v%d-%s.bak", databasePath, currentSchemaVersion, stamp)
	if strings.ContainsAny(backupPath, "\x00\r\n") {
		return errors.New("generated backup path contains control characters")
	}
	if _, err := os.Lstat(backupPath); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("generated backup path already exists")
		}
		return err
	}
	// Build the online-backup destination in a same-filesystem 0700 staging
	// directory, secure and sync it, then publish with a no-overwrite hard link.
	// migrateDatabase holds BEGIN IMMEDIATE across this call, so the snapshot and
	// the preceding privacy validation observe the same writer-exclusive state.
	stagingDirectory, err := os.MkdirTemp(filepath.Dir(databasePath), ".cyber-abuse-guard-migration-*")
	if err != nil {
		return fmt.Errorf("create private migration-backup staging directory: %w", err)
	}
	defer os.RemoveAll(stagingDirectory)
	if err := os.Chmod(stagingDirectory, 0o700); err != nil {
		return fmt.Errorf("secure migration-backup staging directory: %w", err)
	}
	stagedPath := filepath.Join(stagingDirectory, "audit-backup.db")
	if err := copySQLiteDatabase(db, stagedPath, cfg.BusyTimeout); err != nil {
		return fmt.Errorf("copy migration backup: %w", err)
	}
	if err := sanitizeMigrationBackup(stagedPath); err != nil {
		return fmt.Errorf("sanitize migration backup: %w", err)
	}
	info, err := os.Lstat(stagedPath)
	if err != nil {
		return fmt.Errorf("inspect staged migration backup: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("staged migration backup must be a regular non-symlink file")
	}
	if err := os.Chmod(stagedPath, 0o400); err != nil {
		return err
	}
	staged, err := os.Open(stagedPath)
	if err != nil {
		return fmt.Errorf("open staged migration backup for sync: %w", err)
	}
	if err := staged.Sync(); err != nil {
		_ = staged.Close()
		return fmt.Errorf("sync staged migration backup: %w", err)
	}
	if err := staged.Close(); err != nil {
		return fmt.Errorf("close staged migration backup: %w", err)
	}
	if err := os.Link(stagedPath, backupPath); err != nil {
		return fmt.Errorf("publish migration backup without overwrite: %w", err)
	}
	published, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("open published migration backup for sync: %w", err)
	}
	if err := published.Sync(); err != nil {
		_ = published.Close()
		return fmt.Errorf("sync published migration backup: %w", err)
	}
	if err := published.Close(); err != nil {
		return fmt.Errorf("close published migration backup: %w", err)
	}
	parent, err := os.Open(filepath.Dir(databasePath))
	if err != nil {
		return fmt.Errorf("open migration-backup parent for sync: %w", err)
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		return fmt.Errorf("sync migration-backup parent: %w", err)
	}
	if err := parent.Close(); err != nil {
		return fmt.Errorf("close migration-backup parent: %w", err)
	}
	return pruneMigrationBackups(databasePath, cfg.MaxMigrationBackups)
}

// sanitizeMigrationBackup keeps rollback schema-compatible while preventing
// every Raw Capture preview from escaping the active database's TTL and purge
// lifecycle through an automatic pre-migration copy. A preview that is fresh
// when the backup is created would otherwise outlive its TTL permanently.
// Removing child preview rows does not affect audit events or schema version,
// so an older binary can still restore and open the backup.
func sanitizeMigrationBackup(path string) error {
	parameters := url.Values{}
	parameters.Set("_foreign_keys", "on")
	parameters.Set("_journal_mode", "DELETE")
	parameters.Set("_secure_delete", "true")
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: parameters.Encode()}).String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return fmt.Errorf("open staged migration backup: %w", err)
	}
	db.SetMaxOpenConns(1)
	closed := false
	defer func() {
		if !closed {
			_ = db.Close()
		}
	}()
	if err := db.Ping(); err != nil {
		return fmt.Errorf("connect staged migration backup: %w", err)
	}
	hasCaptures, err := sqliteTableExists(db, "raw_request_captures")
	if err != nil {
		return fmt.Errorf("inspect staged raw capture table: %w", err)
	}
	if hasCaptures {
		if _, err := db.Exec("DELETE FROM raw_request_captures"); err != nil {
			return fmt.Errorf("purge staged raw captures: %w", err)
		}
		// VACUUM rewrites the staged file after secure_delete so removed previews
		// do not remain in freelist pages in the published rollback copy.
		if _, err := db.Exec("VACUUM"); err != nil {
			return fmt.Errorf("compact staged migration backup: %w", err)
		}
	}
	var integrity string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&integrity); err != nil {
		return fmt.Errorf("check staged migration backup: %w", err)
	}
	if integrity != "ok" {
		return errors.New("staged migration backup failed SQLite quick_check")
	}
	if err := db.Close(); err != nil {
		return fmt.Errorf("close staged migration backup: %w", err)
	}
	closed = true
	return nil
}

func copySQLiteDatabase(source *sql.DB, destinationPath string, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 2500 * time.Millisecond
	}
	ctx := context.Background()

	destinationDSN := (&url.URL{Scheme: "file", Path: filepath.ToSlash(destinationPath)}).String()
	destination, err := sql.Open("sqlite3", destinationDSN)
	if err != nil {
		return fmt.Errorf("open backup destination: %w", err)
	}
	destination.SetMaxOpenConns(1)
	defer destination.Close()
	if err := destination.PingContext(ctx); err != nil {
		return fmt.Errorf("connect backup destination: %w", err)
	}

	sourceConn, err := source.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve backup source connection: %w", err)
	}
	defer sourceConn.Close()
	destinationConn, err := destination.Conn(ctx)
	if err != nil {
		return fmt.Errorf("reserve backup destination connection: %w", err)
	}
	defer destinationConn.Close()

	return sourceConn.Raw(func(sourceDriver any) error {
		sourceSQLite, ok := sourceDriver.(*sqlite3.SQLiteConn)
		if !ok {
			return fmt.Errorf("unexpected backup source driver %T", sourceDriver)
		}
		return destinationConn.Raw(func(destinationDriver any) error {
			destinationSQLite, ok := destinationDriver.(*sqlite3.SQLiteConn)
			if !ok {
				return fmt.Errorf("unexpected backup destination driver %T", destinationDriver)
			}
			backup, err := destinationSQLite.Backup("main", sourceSQLite, "main")
			if err != nil {
				return fmt.Errorf("initialize SQLite online backup: %w", err)
			}
			closed := false
			busyDeadline := time.Now().Add(timeout)
			defer func() {
				if !closed {
					_ = backup.Close()
				}
			}()
			for {
				done, err := backup.Step(-1)
				if err != nil {
					return fmt.Errorf("copy SQLite backup pages: %w", err)
				}
				if done {
					closed = true
					if err := backup.Close(); err != nil {
						return fmt.Errorf("finish SQLite online backup: %w", err)
					}
					return nil
				}
				if time.Now().After(busyDeadline) {
					return errors.New("SQLite online backup remained busy past the configured timeout")
				}
				time.Sleep(5 * time.Millisecond)
			}
		})
	})
}

func pruneMigrationBackups(databasePath string, keep int) error {
	directory := filepath.Dir(databasePath)
	databaseName := filepath.Base(databasePath)
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	type candidate struct {
		path    string
		modTime time.Time
	}
	backups := make([]candidate, 0, len(entries))
	for _, entry := range entries {
		if !isMigrationBackupName(databaseName, entry.Name()) {
			continue
		}
		match := filepath.Join(directory, entry.Name())
		info, err := os.Lstat(match)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("migration backup must be a regular non-symlink file: %s", match)
		}
		backups = append(backups, candidate{path: match, modTime: info.ModTime()})
	}
	sort.Slice(backups, func(i, j int) bool {
		if backups[i].modTime.Equal(backups[j].modTime) {
			return backups[i].path > backups[j].path
		}
		return backups[i].modTime.After(backups[j].modTime)
	})
	if len(backups) <= keep {
		return nil
	}
	for _, backup := range backups[keep:] {
		if err := os.Remove(backup.path); err != nil {
			return err
		}
	}
	return nil
}

func isMigrationBackupName(databaseName, candidate string) bool {
	prefix := databaseName + ".pre-v"
	if !strings.HasPrefix(candidate, prefix) || !strings.HasSuffix(candidate, ".bak") {
		return false
	}
	remainder := strings.TrimSuffix(strings.TrimPrefix(candidate, prefix), ".bak")
	separator := strings.IndexByte(remainder, '-')
	if separator < 1 || separator == len(remainder)-1 {
		return false
	}
	for index := 0; index < separator; index++ {
		if remainder[index] < '0' || remainder[index] > '9' {
			return false
		}
	}
	return true
}
