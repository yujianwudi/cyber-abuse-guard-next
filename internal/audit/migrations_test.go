package audit

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMigrationRejectsPrivacyUnsafeLegacyRowsBeforePublishingBackup(t *testing.T) {
	t.Parallel()
	testCases := []struct {
		name   string
		canary string
		field  string
	}{
		{name: "request hash", canary: "MIGRATION_PROMPT_CANARY_9e788c12", field: "request_hash"},
		{name: "subject hash", canary: "MIGRATION_CREDENTIAL_CANARY_a6f3c102", field: "subject_hash"},
		{name: "model", canary: "MIGRATION_MODEL_CANARY_2d509c87", field: "model"},
		{name: "source format", canary: "MIGRATION_SOURCE_CANARY_80742b91", field: "source_format"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			directory := t.TempDir()
			path := filepath.Join(directory, "audit.db")
			legacy, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := legacy.Exec(schema); err != nil {
				t.Fatal(err)
			}
			requestHash := "sha256:" + strings.Repeat("a", 64)
			subjectHash := "hmac-sha256:" + strings.Repeat("b", 64)
			model := HashModel("legacy-safe-model")
			sourceFormat := "openai"
			switch testCase.field {
			case "request_hash":
				requestHash = testCase.canary
			case "subject_hash":
				subjectHash = testCase.canary
			case "model":
				model = testCase.canary
			case "source_format":
				sourceFormat = testCase.canary
			}
			if _, err := legacy.Exec(`INSERT INTO audit_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				"privacy-migration-event", fixedMigrationTime().UnixNano(), "block", "balanced", "credential_theft", 90, "[]",
				requestHash, subjectHash, model, sourceFormat, 0, 32, "privacy-rules", 5); err != nil {
				t.Fatal(err)
			}
			before := captureV1DatabaseSnapshot(t, legacy)
			if err := legacy.Close(); err != nil {
				t.Fatal(err)
			}

			store, openErr := Open(Config{
				Path:                  path,
				Now:                   fixedMigrationTime,
				BackupBeforeMigration: true,
				MaxMigrationBackups:   1,
			})
			if openErr == nil {
				_ = store.Close()
				t.Fatal("migration accepted a privacy-unsafe legacy correlation field")
			}
			if store == nil || !store.Status().Degraded {
				t.Fatal("privacy-contract failure did not return a degraded audit store")
			}
			_ = store.Close()
			if strings.Contains(openErr.Error(), testCase.canary) {
				t.Fatal("migration error reflected a legacy privacy canary")
			}
			backups, err := filepath.Glob(path + ".pre-v*.bak")
			if err != nil || len(backups) != 0 {
				t.Fatalf("migration backup count = %d", len(backups))
			}
			check, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			if exists, err := sqliteTableExists(check, "subject_state"); err != nil || exists {
				_ = check.Close()
				t.Fatalf("rejected migration changed the v1 schema: exists=%t", exists)
			}
			after := captureV1DatabaseSnapshot(t, check)
			if !reflect.DeepEqual(after, before) {
				_ = check.Close()
				t.Fatalf("rejected migration changed the v1 database:\nbefore=%#v\nafter=%#v", before, after)
			}
			if err := check.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestV5MigrationRejectsDecisionExplanationPrivacyBypassBeforeBackup(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(schema + subjectStateSchema + round6AuditEventColumns + rawRequestCaptureSchema + round8AuditSchema + round8RawCaptureDedupIndex + migrationMetadataSchema); err != nil {
		t.Fatal(err)
	}
	nowNS := fixedMigrationTime().UnixNano()
	if _, err := legacy.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 5, ?)`, nowNS); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 5; version++ {
		if _, err := legacy.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(?, ?, 'fixture')`, version, nowNS); err != nil {
			t.Fatal(err)
		}
	}
	const privacyCanary = "ROUND9_DECISION_EXPLANATION_PROMPT_CANARY"
	if _, err := legacy.Exec(`INSERT INTO audit_events (
id, timestamp_ns, action, mode, category, risk_score, rule_ids,
request_hash, subject_hash, model, source_format, stream, text_bytes_scanned,
classifier, latency_us, decision, coverage, incomplete_reason, scanner, decision_explanation
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"v5-privacy-bypass", nowNS, "audit", "balanced", "", 0, "[]",
		HashRequest([]byte("v5-privacy-bypass")), testSubjectHash("v5-privacy-bypass"), HashModel("safe-model"),
		"openai", 0, 0, "classifier-policy-v7", 1, "allow_clean", "complete", "", "streaming-scanner-v1",
		`{"request_text":"`+privacyCanary+`"}`,
	); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	store, openErr := Open(Config{
		Path: path, Now: fixedMigrationTime,
		BackupBeforeMigration: true, MaxMigrationBackups: 1,
	})
	if openErr == nil {
		_ = store.Close()
		t.Fatal("migration accepted a request-text field in the closed v5 decision explanation")
	}
	if store == nil || !store.Status().Degraded {
		t.Fatal("decision-explanation privacy rejection did not return a degraded store")
	}
	_ = store.Close()
	if strings.Contains(openErr.Error(), privacyCanary) {
		t.Fatal("migration error reflected the decision-explanation privacy canary")
	}
	for _, pattern := range []string{
		path + ".pre-v*.bak",
		path + ".pre-v*.bak.manifest.json",
	} {
		artifacts, err := filepath.Glob(pattern)
		if err != nil || len(artifacts) != 0 {
			t.Fatalf("migration artifacts for %q = %v, err=%v", pattern, artifacts, err)
		}
	}
	check, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var version int
	if err := check.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 5 {
		t.Fatalf("schema version after rejected privacy migration = %d, want 5", version)
	}
	var dispositionColumns int
	if err := check.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('audit_events') WHERE name = 'disposition'`).Scan(&dispositionColumns); err != nil {
		t.Fatal(err)
	}
	if dispositionColumns != 0 {
		t.Fatal("rejected privacy migration left a partial schema-v6 disposition column")
	}
}

func TestMigrationBackupPublishCollisionBlocksMigrationWithoutChangingSchema(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(schema); err != nil {
		t.Fatal(err)
	}
	insertSafeLegacyAuditRow(t, legacy, "backup-collision-event")
	before := captureV1DatabaseSnapshot(t, legacy)
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	stamp := fixedMigrationTime().UTC().Format("20060102T150405.000000000Z")
	backupPath := fmt.Sprintf("%s.pre-v%d-%s.bak", path, currentSchemaVersion, stamp)
	const sentinel = "operator-owned collision sentinel"
	if err := os.WriteFile(backupPath, []byte(sentinel), 0o400); err != nil {
		t.Fatal(err)
	}

	store, openErr := Open(Config{
		Path:                  path,
		Now:                   fixedMigrationTime,
		BackupBeforeMigration: true,
		MaxMigrationBackups:   1,
	})
	if openErr == nil {
		_ = store.Close()
		t.Fatal("migration succeeded despite a backup publish collision")
	}
	if store == nil || !store.Status().Degraded {
		t.Fatal("backup publication failure did not return a degraded audit store")
	}
	_ = store.Close()
	data, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != sentinel {
		t.Fatal("backup collision overwrote the existing operator file")
	}

	check, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	if exists, err := sqliteTableExists(check, "subject_state"); err != nil || exists {
		t.Fatalf("failed migration changed the v1 schema: exists=%t", exists)
	}
	after := captureV1DatabaseSnapshot(t, check)
	if !reflect.DeepEqual(after, before) {
		t.Fatalf("backup publication failure changed the v1 database:\nbefore=%#v\nafter=%#v", before, after)
	}
}

func TestMigrationWriterLockCoversValidationBackupAndSchemaChange(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(schema); err != nil {
		t.Fatal(err)
	}
	insertSafeLegacyAuditRow(t, legacy, "writer-lock-safe-event")
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	lockHeld := make(chan struct{})
	releaseMigration := make(chan struct{})
	var signalOnce sync.Once
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseMigration) }) }
	defer release()
	type openResult struct {
		store *Store
		err   error
	}
	result := make(chan openResult, 1)
	go func() {
		store, err := Open(Config{
			Path:                  path,
			BusyTimeout:           500 * time.Millisecond,
			BackupBeforeMigration: true,
			MaxMigrationBackups:   1,
			Now: func() time.Time {
				signalOnce.Do(func() {
					close(lockHeld)
					<-releaseMigration
				})
				return fixedMigrationTime()
			},
		})
		result <- openResult{store: store, err: err}
	}()

	select {
	case <-lockHeld:
	case <-time.After(5 * time.Second):
		t.Fatal("migration did not reach the writer-locked backup phase")
	}
	writer, err := sql.Open("sqlite3", path+"?_busy_timeout=50")
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := writer.Exec(`INSERT INTO audit_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"writer-race-event", fixedMigrationTime().UnixNano(), "block", "balanced", "credential_theft", 90, "[]",
		"MIGRATION_RACE_PROMPT_CANARY", "hmac-sha256:"+strings.Repeat("b", 64), HashModel("safe-model"), "openai", 0, 32, "privacy-rules", 5)
	_ = writer.Close()
	if writeErr == nil {
		t.Fatal("concurrent writer bypassed the migration writer lock")
	}
	release()

	var opened openResult
	select {
	case opened = <-result:
	case <-time.After(10 * time.Second):
		t.Fatal("migration did not finish after releasing the test barrier")
	}
	if opened.err != nil {
		if opened.store != nil {
			_ = opened.store.Close()
		}
		t.Fatalf("writer-locked migration failed: %v", opened.err)
	}
	t.Cleanup(func() { _ = opened.store.Close() })
	var racedRows int
	if err := opened.store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = 'writer-race-event'`).Scan(&racedRows); err != nil {
		t.Fatal(err)
	}
	if racedRows != 0 {
		t.Fatalf("concurrent writer row count = %d, want 0", racedRows)
	}
	backups, err := filepath.Glob(path + ".pre-v*.bak")
	if err != nil || len(backups) != 1 {
		t.Fatalf("migration backups = %v, err=%v", backups, err)
	}
	backup, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(backups[0])+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer backup.Close()
	var safeRows int
	if err := backup.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = 'writer-lock-safe-event'`).Scan(&safeRows); err != nil {
		t.Fatal(err)
	}
	if safeRows != 1 {
		t.Fatalf("safe backup row count = %d, want 1", safeRows)
	}
}

func TestFreshDatabaseAppliesAllMigrations(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(Config{Path: path, Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if got := store.Status().SchemaVersion; got != currentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", got, currentSchemaVersion)
	}

	db := store.db
	var version int
	if err := db.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != currentSchemaVersion {
		t.Fatalf("persisted schema version = %d", version)
	}
	var migrations int
	if err := db.QueryRow(`SELECT COUNT(*) FROM migration_history`).Scan(&migrations); err != nil {
		t.Fatal(err)
	}
	if migrations != currentSchemaVersion {
		t.Fatalf("migration history rows = %d", migrations)
	}
	if exists, err := sqliteTableExists(db, "subject_state"); err != nil || !exists {
		t.Fatalf("subject_state exists = %v, err = %v", exists, err)
	}
	if exists, err := sqliteTableExists(db, "raw_request_captures"); err != nil || !exists {
		t.Fatalf("raw_request_captures exists = %v, err = %v", exists, err)
	}
}

func TestCurrentSchemaReopenPreservesVersionMetadata(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	firstTime := time.Unix(1_700_000_000, 123).UTC()
	store, err := Open(Config{Path: path, Now: func() time.Time { return firstTime }})
	if err != nil {
		t.Fatal(err)
	}
	var firstVersion int
	var firstUpdatedAt int64
	if err := store.db.QueryRow(`SELECT version, updated_at_ns FROM schema_version WHERE singleton = 1`).Scan(&firstVersion, &firstUpdatedAt); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	secondTime := firstTime.Add(24 * time.Hour)
	reopened, err := Open(Config{Path: path, Now: func() time.Time { return secondTime }})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	var secondVersion int
	var secondUpdatedAt int64
	if err := reopened.db.QueryRow(`SELECT version, updated_at_ns FROM schema_version WHERE singleton = 1`).Scan(&secondVersion, &secondUpdatedAt); err != nil {
		t.Fatal(err)
	}
	if secondVersion != firstVersion || secondUpdatedAt != firstUpdatedAt {
		t.Fatalf(
			"schema metadata changed on reopen: before=(%d,%d) after=(%d,%d)",
			firstVersion, firstUpdatedAt, secondVersion, secondUpdatedAt,
		)
	}
}

func TestV3DatabaseMigratesThroughRawCaptureSchemaV5(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema + subjectStateSchema + round6AuditEventColumns + migrationMetadataSchema); err != nil {
		t.Fatal(err)
	}
	now := fixedMigrationTime().UnixNano()
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 3, ?)`, now); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 3; version++ {
		if _, err := db.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(?, ?, 'fixture')`, version, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(Config{Path: path, Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if got := store.Status().SchemaVersion; got != currentSchemaVersion {
		t.Fatalf("schema version = %d, want %d", got, currentSchemaVersion)
	}
	if err := validateSchemaContract(store.db, currentSchemaVersion); err != nil {
		t.Fatalf("current schema contract = %v", err)
	}
	var migrationRows int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM migration_history WHERE version IN (4, 5)`).Scan(&migrationRows); err != nil {
		t.Fatal(err)
	}
	if migrationRows != 2 {
		t.Fatalf("migration v4-v5 rows = %d", migrationRows)
	}
}

func TestV4RawCaptureMigrationKeepsFirstLiveCaptureAndCreatesPartialUniqueRawSHAIndex(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema + subjectStateSchema + round6AuditEventColumns + rawRequestCaptureSchema + migrationMetadataSchema); err != nil {
		t.Fatal(err)
	}
	now := fixedMigrationTime()
	nowNS := now.UnixNano()
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 4, ?)`, nowNS); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 4; version++ {
		if _, err := db.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(?, ?, 'fixture')`, version, nowNS); err != nil {
			t.Fatal(err)
		}
	}

	insertV4Event := func(id string, timestamp time.Time, requestHash string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO audit_events (
id, timestamp_ns, action, mode, category, risk_score, rule_ids,
request_hash, subject_hash, model, source_format, stream, text_bytes_scanned,
classifier, latency_us, decision, coverage, incomplete_reason, scanner
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, timestamp.UnixNano(), "block", "balanced", "defense_evasion", 90, `["EVADE-002"]`,
			requestHash, testSubjectHash("subject-"+id), HashModel("migration-model"), "openai", 0, 128,
			"classifier-policy-v6", 25, "block_malicious_text", "complete", "", "streaming-scanner-v1"); err != nil {
			t.Fatal(err)
		}
	}
	insertV4Capture := func(id, eventID string, timestamp time.Time, requestHash, rawSHA256 string, redacted bool) {
		t.Helper()
		redactedInt := 0
		if redacted {
			redactedInt = 1
		}
		if _, err := db.Exec(`INSERT INTO raw_request_captures (
id, event_id, timestamp_ns, request_hash, subject_hash, action, decision,
truncated, redacted, raw_preview, raw_sha256
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, eventID, timestamp.UnixNano(), requestHash, testSubjectHash("subject-"+eventID),
			"block", "block_malicious_text", 0, redactedInt, "legacy preview", rawSHA256); err != nil {
			t.Fatal(err)
		}
	}

	duplicateHash := HashRequest([]byte("migration-duplicate-request"))
	duplicateRawSHA := "sha256:" + strings.Repeat("c", 64)
	fixtures := []struct {
		eventID, captureID, requestHash, rawSHA256 string
		timestamp                                  time.Time
		redacted                                   bool
	}{
		{eventID: "migration-old", captureID: "capture-old", requestHash: duplicateHash, rawSHA256: duplicateRawSHA, timestamp: now.Add(-2 * time.Hour), redacted: true},
		{eventID: "migration-new", captureID: "capture-new", requestHash: duplicateHash, rawSHA256: duplicateRawSHA, timestamp: now.Add(-time.Hour), redacted: false},
		{eventID: "migration-empty-a", captureID: "capture-empty-a", requestHash: "", rawSHA256: "sha256:" + strings.Repeat("e", 64), timestamp: now.Add(-45 * time.Minute)},
		{eventID: "migration-empty-b", captureID: "capture-empty-b", requestHash: "", rawSHA256: "sha256:" + strings.Repeat("f", 64), timestamp: now.Add(-30 * time.Minute)},
	}
	for _, fixture := range fixtures {
		insertV4Event(fixture.eventID, fixture.timestamp, fixture.requestHash)
		insertV4Capture(fixture.captureID, fixture.eventID, fixture.timestamp, fixture.requestHash, fixture.rawSHA256, fixture.redacted)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(Config{
		Path:      path,
		Retention: 30 * 24 * time.Hour,
		MaxBytes:  8 << 20,
		Now:       func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	var retainedID, retainedEventID, redactionVersion string
	var patternHits int
	if err := store.db.QueryRow(`SELECT id, event_id, redaction_pattern_hits, redaction_version
FROM raw_request_captures WHERE raw_sha256 = ?`, duplicateRawSHA).
		Scan(&retainedID, &retainedEventID, &patternHits, &redactionVersion); err != nil {
		t.Fatal(err)
	}
	if retainedID != "capture-old" || retainedEventID != "migration-old" || patternHits != 0 || redactionVersion != legacyRawCaptureRedactionVersion {
		t.Fatalf("retained migrated capture id=%q event=%q hits=%d version=%q",
			retainedID, retainedEventID, patternHits, redactionVersion)
	}
	var emptyCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM raw_request_captures WHERE request_hash = ''`).Scan(&emptyCount); err != nil {
		t.Fatal(err)
	}
	if emptyCount != 2 {
		t.Fatalf("migrated empty-hash captures = %d, want 2", emptyCount)
	}

	rows, err := store.db.Query(`PRAGMA index_list('raw_request_captures')`)
	if err != nil {
		t.Fatal(err)
	}
	foundUniquePartial := false
	for rows.Next() {
		var sequence, unique, partial int
		var name, origin string
		if err := rows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if name == "idx_raw_request_captures_raw_sha256_unique" {
			foundUniquePartial = unique == 1 && partial == 1
		}
	}
	if err := rows.Close(); err != nil {
		t.Fatal(err)
	}
	if !foundUniquePartial {
		t.Fatal("raw_sha256 deduplication index is not both unique and partial")
	}

	for _, id := range []string{"migration-post-a", "migration-post-b"} {
		event := testEvent(id, now.Add(time.Minute))
		event.Action = "block"
		event.Decision = "block_malicious_text"
		event.Coverage = "complete"
		event.Scanner = "streaming-scanner-v1"
		if !store.Record(event) {
			t.Fatalf("Record(%s) failed", id)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	insertV5Capture := func(id, eventID, requestHash, rawSHA256 string) error {
		_, err := store.db.Exec(`INSERT INTO raw_request_captures (
id, event_id, timestamp_ns, request_hash, subject_hash, action, decision,
truncated, redacted, raw_preview, raw_sha256, redaction_pattern_hits, redaction_version
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			id, eventID, now.Add(time.Minute).UnixNano(), requestHash, testSubjectHash("subject-"+eventID),
			"block", "block_malicious_text", 0, 0, "post-migration preview", rawSHA256,
			0, rawCaptureRedactionVersion)
		return err
	}
	if err := insertV5Capture("capture-post-duplicate", "migration-post-a", "", duplicateRawSHA); err == nil {
		t.Fatal("partial unique index accepted a duplicate nonempty raw_sha256")
	}
	if err := insertV5Capture("capture-post-empty-a", "migration-post-a", "", "sha256:"+strings.Repeat("1", 64)); err != nil {
		t.Fatalf("partial unique index rejected first empty request_hash: %v", err)
	}
	if err := insertV5Capture("capture-post-empty-b", "migration-post-b", "", "sha256:"+strings.Repeat("2", 64)); err != nil {
		t.Fatalf("partial unique index rejected second empty request_hash: %v", err)
	}
}

func TestV4RawCaptureMigrationReplaysV5TTLWindowsAndPreservesEventAssociation(t *testing.T) {
	t.Parallel()
	const epsilon = time.Nanosecond
	ttl := 72 * time.Hour
	t0 := fixedMigrationTime().Add(-14 * 24 * time.Hour)
	batchBoundaryOffsets := make([]time.Duration, 0, rawCaptureReplayBatchSize+2)
	for index := 0; index < rawCaptureReplayBatchSize; index++ {
		batchBoundaryOffsets = append(batchBoundaryOffsets, time.Duration(index)*time.Nanosecond)
	}
	batchBoundaryOffsets = append(batchBoundaryOffsets, ttl, ttl+epsilon)
	type replayGroup struct {
		name        string
		offsets     []time.Duration
		wantCapture int
	}
	groups := []replayGroup{
		{name: "inside", offsets: []time.Duration{0, ttl - epsilon}, wantCapture: 0},
		{name: "exact", offsets: []time.Duration{0, ttl}, wantCapture: 1},
		{name: "beyond", offsets: []time.Duration{0, ttl + epsilon}, wantCapture: 1},
		{name: "chronological", offsets: []time.Duration{0, ttl - epsilon, ttl + epsilon}, wantCapture: 2},
		{name: "batch-boundary", offsets: batchBoundaryOffsets, wantCapture: rawCaptureReplayBatchSize},
	}

	path := filepath.Join(t.TempDir(), "audit.db")
	fixtures := make([]v4RawCaptureFixture, 0, 9)
	rawSHAs := make(map[string]string, len(groups))
	for groupIndex, group := range groups {
		rawSHA := fmt.Sprintf("sha256:%064x", groupIndex+1)
		rawSHAs[group.name] = rawSHA
		for captureIndex, offset := range group.offsets {
			name := fmt.Sprintf("ttl-%s-%d", group.name, captureIndex)
			fixtures = append(fixtures, v4RawCaptureFixture{
				EventID:     "event-" + name,
				CaptureID:   "capture-" + name,
				Timestamp:   t0.Add(offset),
				RequestHash: HashRequest([]byte("request-" + name)),
				SubjectHash: testSubjectHash("subject-" + name),
				RawPreview:  "legacy preview " + name,
				RawSHA256:   rawSHA,
			})
		}
	}
	createV4RawCaptureDatabase(t, path, fixedMigrationTime(), fixtures)

	store, err := Open(Config{
		Path:                    path,
		Now:                     fixedMigrationTime,
		SkipDisabledPurgeOnOpen: true,
		RawCapture:              RawCaptureConfig{TTL: ttl},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	for _, group := range groups {
		wantIndex := group.wantCapture
		wantTimestamp := t0.Add(group.offsets[wantIndex]).UnixNano()
		wantCaptureID := fmt.Sprintf("capture-ttl-%s-%d", group.name, wantIndex)
		wantEventID := fmt.Sprintf("event-ttl-%s-%d", group.name, wantIndex)
		var captureID, captureEventID, joinedEventID string
		var captureTimestamp, eventTimestamp int64
		if err := store.db.QueryRow(`SELECT capture.id, capture.event_id, capture.timestamp_ns,
event.id, event.timestamp_ns
FROM raw_request_captures AS capture
JOIN audit_events AS event ON event.id = capture.event_id
WHERE capture.raw_sha256 = ?`, rawSHAs[group.name]).Scan(
			&captureID, &captureEventID, &captureTimestamp, &joinedEventID, &eventTimestamp,
		); err != nil {
			t.Fatalf("query %s replay result: %v", group.name, err)
		}
		if captureID != wantCaptureID || captureEventID != wantEventID || joinedEventID != wantEventID ||
			captureTimestamp != wantTimestamp || eventTimestamp != wantTimestamp {
			t.Fatalf("%s replay retained capture=%q capture_event=%q capture_timestamp=%d joined_event=%q event_timestamp=%d; want capture=%q event=%q timestamp=%d",
				group.name, captureID, captureEventID, captureTimestamp, joinedEventID, eventTimestamp,
				wantCaptureID, wantEventID, wantTimestamp)
		}
	}

	var eventCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != len(fixtures) {
		t.Fatalf("audit event count after raw capture replay = %d, want %d", eventCount, len(fixtures))
	}
	var replayIndexes int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master
WHERE type = 'index' AND name = 'idx_raw_request_captures_replay_v5'`).Scan(&replayIndexes); err != nil {
		t.Fatal(err)
	}
	if replayIndexes != 0 {
		t.Fatalf("temporary raw capture replay indexes after migration=%d, want 0", replayIndexes)
	}
}

func TestV4MigrationBackupIsExactBeforeV6RawCaptureCleanup(t *testing.T) {
	t.Parallel()
	now := fixedMigrationTime()
	fixtures := []v4RawCaptureFixture{
		{
			EventID:     "backup-expired-event",
			CaptureID:   "backup-expired-capture",
			Timestamp:   now.Add(-73 * time.Hour),
			RequestHash: HashRequest([]byte("backup-expired-request")),
			SubjectHash: testSubjectHash("backup-expired-subject"),
			RawPreview:  "expired sensitive preview",
			RawSHA256:   "sha256:" + strings.Repeat("a", 64),
		},
		{
			EventID:     "backup-fresh-event",
			CaptureID:   "backup-fresh-capture",
			Timestamp:   now.Add(-time.Hour),
			RequestHash: HashRequest([]byte("backup-fresh-request")),
			SubjectHash: testSubjectHash("backup-fresh-subject"),
			RawPreview:  "fresh sensitive preview",
			RawSHA256:   "sha256:" + strings.Repeat("b", 64),
		},
	}

	t.Run("disabled purges every preview", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.db")
		createV4RawCaptureDatabase(t, path, now, fixtures)
		store, err := Open(Config{
			Path:                  path,
			Now:                   func() time.Time { return now },
			BackupBeforeMigration: true,
			MaxMigrationBackups:   1,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })

		var currentCaptures, currentEvents int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM raw_request_captures`).Scan(&currentCaptures); err != nil {
			t.Fatal(err)
		}
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&currentEvents); err != nil {
			t.Fatal(err)
		}
		if currentCaptures != 0 || currentEvents != len(fixtures) {
			t.Fatalf("current database captures=%d events=%d", currentCaptures, currentEvents)
		}

		backup := onlyMigrationBackup(t, path)
		backupDB, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(backup)+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		defer backupDB.Close()
		var version, backupCaptures, backupEvents int
		if err := backupDB.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		if err := backupDB.QueryRow(`SELECT COUNT(*) FROM raw_request_captures`).Scan(&backupCaptures); err != nil {
			t.Fatal(err)
		}
		if err := backupDB.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&backupEvents); err != nil {
			t.Fatal(err)
		}
		if version != 4 || backupCaptures != len(fixtures) || backupEvents != len(fixtures) {
			t.Fatalf("disabled backup version=%d captures=%d events=%d", version, backupCaptures, backupEvents)
		}
	})

	t.Run("enabled cleans active TTL state after preserving exact rollback copy", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "audit.db")
		createV4RawCaptureDatabase(t, path, now, fixtures)
		store, err := Open(Config{
			Path:                  path,
			Now:                   func() time.Time { return now },
			BackupBeforeMigration: true,
			MaxMigrationBackups:   1,
			RawCapture: RawCaptureConfig{
				Enabled: true, MaxBytes: 8192, TTL: 72 * time.Hour,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })

		var currentCaptures int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM raw_request_captures`).Scan(&currentCaptures); err != nil {
			t.Fatal(err)
		}
		if currentCaptures != 1 {
			t.Fatalf("current database captures=%d, want 1", currentCaptures)
		}

		backup := onlyMigrationBackup(t, path)
		backupDB, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(backup)+"?mode=ro")
		if err != nil {
			t.Fatal(err)
		}
		defer backupDB.Close()
		var version, backupCaptures int
		if err := backupDB.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
			t.Fatal(err)
		}
		if err := backupDB.QueryRow(`SELECT COUNT(*) FROM raw_request_captures`).Scan(&backupCaptures); err != nil {
			t.Fatal(err)
		}
		var backupEvents int
		if err := backupDB.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&backupEvents); err != nil {
			t.Fatal(err)
		}
		if version != 4 || backupCaptures != len(fixtures) || backupEvents != len(fixtures) {
			t.Fatalf("enabled backup version=%d captures=%d events=%d", version, backupCaptures, backupEvents)
		}
		backupBytes, err := os.ReadFile(backup)
		if err != nil {
			t.Fatal(err)
		}
		for _, preview := range []string{"expired sensitive preview", "fresh sensitive preview"} {
			if !bytes.Contains(backupBytes, []byte(preview)) {
				t.Fatalf("exact migration backup did not retain raw preview bytes %q", preview)
			}
		}
	})
}

func TestV4MigrationRejectsMalformedRawCaptureBeforePublishingBackup(t *testing.T) {
	t.Parallel()
	now := fixedMigrationTime()
	tests := []struct {
		name      string
		canary    string
		malformed func(*v4RawCaptureFixture)
	}{
		{
			name:   "request hash",
			canary: "ROUND8_RAW_REQUEST_HASH_CANARY",
			malformed: func(fixture *v4RawCaptureFixture) {
				fixture.RequestHash = "ROUND8_RAW_REQUEST_HASH_CANARY"
			},
		},
		{
			name:   "subject hash",
			canary: "ROUND8_RAW_SUBJECT_HASH_CANARY",
			malformed: func(fixture *v4RawCaptureFixture) {
				fixture.SubjectHash = "ROUND8_RAW_SUBJECT_HASH_CANARY"
			},
		},
		{
			name:   "raw sha256",
			canary: "ROUND8_RAW_SHA_CANARY",
			malformed: func(fixture *v4RawCaptureFixture) {
				fixture.RawSHA256 = "ROUND8_RAW_SHA_CANARY"
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.db")
			fixture := v4RawCaptureFixture{
				EventID:     "malformed-capture-event",
				CaptureID:   "malformed-capture",
				Timestamp:   now,
				RequestHash: HashRequest([]byte("malformed-capture-request")),
				SubjectHash: testSubjectHash("malformed-capture-subject"),
				RawPreview:  "preview must remain only in the rejected source database",
				RawSHA256:   "sha256:" + strings.Repeat("c", 64),
			}
			test.malformed(&fixture)
			createV4RawCaptureDatabase(t, path, now, []v4RawCaptureFixture{fixture})

			store, openErr := Open(Config{
				Path:                  path,
				Now:                   func() time.Time { return now },
				BackupBeforeMigration: true,
				MaxMigrationBackups:   1,
				RawCapture: RawCaptureConfig{
					Enabled: true, MaxBytes: 8192, TTL: 72 * time.Hour,
				},
			})
			if openErr == nil {
				_ = store.Close()
				t.Fatal("migration accepted a malformed v4 raw capture")
			}
			if store == nil || !store.Status().Degraded {
				t.Fatalf("malformed raw capture did not produce a degraded store: store=%#v err=%v", store, openErr)
			}
			_ = store.Close()
			if strings.Contains(openErr.Error(), test.canary) {
				t.Fatal("migration error reflected malformed raw-capture content")
			}
			backups, err := filepath.Glob(path + ".pre-v*.bak")
			if err != nil || len(backups) != 0 {
				t.Fatalf("migration backups=%v err=%v, want none", backups, err)
			}

			check, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			defer check.Close()
			var version, captures, v5Columns int
			if err := check.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
				t.Fatal(err)
			}
			if err := check.QueryRow(`SELECT COUNT(*) FROM raw_request_captures`).Scan(&captures); err != nil {
				t.Fatal(err)
			}
			if err := check.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('audit_events') WHERE name = 'decision_explanation'`).Scan(&v5Columns); err != nil {
				t.Fatal(err)
			}
			if version != 4 || captures != 1 || v5Columns != 0 {
				t.Fatalf("rejected source version=%d captures=%d v5_columns=%d", version, captures, v5Columns)
			}
		})
	}
}

func TestV5ContractFailureRollsBackSchemaVersionAndCaptureDeduplication(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema + subjectStateSchema + round6AuditEventColumns + rawRequestCaptureSchema + migrationMetadataSchema); err != nil {
		t.Fatal(err)
	}
	now := fixedMigrationTime()
	nowNS := now.UnixNano()
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 4, ?)`, nowNS); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 4; version++ {
		if _, err := db.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(?, ?, 'fixture')`, version, nowNS); err != nil {
			t.Fatal(err)
		}
	}

	rawSHA256 := "sha256:" + strings.Repeat("9", 64)
	for index, suffix := range []string{"old", "new"} {
		eventID := "rollback-event-" + suffix
		captureID := "rollback-capture-" + suffix
		timestamp := now.Add(time.Duration(index) * time.Minute)
		if _, err := db.Exec(`INSERT INTO audit_events (
id, timestamp_ns, action, mode, category, risk_score, rule_ids,
request_hash, subject_hash, model, source_format, stream, text_bytes_scanned,
classifier, latency_us, decision, coverage, incomplete_reason, scanner
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			eventID, timestamp.UnixNano(), "block", "balanced", "defense_evasion", 90, `["EVADE-002"]`,
			HashRequest([]byte(eventID)), testSubjectHash("subject-"+eventID), HashModel("rollback-model"), "openai", 0, 128,
			"classifier-policy-v6", 25, "block_malicious_text", "complete", "", "streaming-scanner-v1"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO raw_request_captures (
id, event_id, timestamp_ns, request_hash, subject_hash, action, decision,
truncated, redacted, raw_preview, raw_sha256
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			captureID, eventID, timestamp.UnixNano(), "", testSubjectHash("subject-"+eventID),
			"block", "block_malicious_text", 0, 0, "legacy preview", rawSHA256); err != nil {
			t.Fatal(err)
		}
	}
	// A v4 database may contain a future-named index because the v4 contract
	// deliberately knows only its first three indexes. Migration 5 must not
	// commit data deletion or version metadata when IF NOT EXISTS encounters a
	// wrong definition under the future name.
	if _, err := db.Exec(`CREATE INDEX idx_raw_request_captures_raw_sha256_unique ON raw_request_captures(request_hash)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	if store, err := Open(Config{Path: path, Now: fixedMigrationTime}); err == nil {
		_ = store.Close()
		t.Fatal("Open() accepted a v5 contract with a wrong preexisting future index")
	}

	inspected, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = inspected.Close() })
	var version int
	if err := inspected.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 4 {
		t.Fatalf("schema version after failed migration = %d, want 4", version)
	}
	var captures int
	if err := inspected.QueryRow(`SELECT COUNT(*) FROM raw_request_captures WHERE raw_sha256 = ?`, rawSHA256).Scan(&captures); err != nil {
		t.Fatal(err)
	}
	if captures != 2 {
		t.Fatalf("duplicate captures after failed migration = %d, want 2", captures)
	}
	var migrationV5Rows int
	if err := inspected.QueryRow(`SELECT COUNT(*) FROM migration_history WHERE version = 5`).Scan(&migrationV5Rows); err != nil {
		t.Fatal(err)
	}
	if migrationV5Rows != 0 {
		t.Fatalf("migration history v5 rows after rollback = %d, want 0", migrationV5Rows)
	}
	var decisionExplanationColumns int
	if err := inspected.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('audit_events') WHERE name = 'decision_explanation'`).Scan(&decisionExplanationColumns); err != nil {
		t.Fatal(err)
	}
	if decisionExplanationColumns != 0 {
		t.Fatal("failed migration retained the v5 decision_explanation column")
	}
}

func TestMigrationAcceptsCanonicalMediaSourceFormats(t *testing.T) {
	t.Parallel()
	for _, sourceFormat := range []string{"openai-image", "openai-video"} {
		t.Run(sourceFormat, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.db")
			legacy, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := legacy.Exec(schema); err != nil {
				t.Fatal(err)
			}
			if _, err := legacy.Exec(`INSERT INTO audit_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				"media-source-event", fixedMigrationTime().UnixNano(), "audit", "balanced", "opaque_media", 0, "[]",
				"sha256:"+strings.Repeat("a", 64), "hmac-sha256:"+strings.Repeat("b", 64), HashModel("safe-model"),
				sourceFormat, 0, 0, "rules", 5); err != nil {
				t.Fatal(err)
			}
			if err := legacy.Close(); err != nil {
				t.Fatal(err)
			}

			store, err := Open(Config{Path: path, Now: fixedMigrationTime})
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestV011DatabaseMigrationPreservesEventsAndCreatesReadonlyBackup(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.db")
	legacy, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(schema); err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`INSERT INTO audit_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"legacy-event", int64(1), "block", "balanced", "credential_theft", 90, "[]",
		"sha256:"+strings.Repeat("a", 64), "hmac-sha256:"+strings.Repeat("b", 64), HashModel("legacy-model"), "openai", 0, 10, "rules", 5); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}

	store, err := Open(Config{
		Path:                  path,
		Now:                   fixedMigrationTime,
		BackupBeforeMigration: true,
		MaxMigrationBackups:   2,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var events int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = 'legacy-event'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("legacy event count = %d", events)
	}

	backups, err := filepath.Glob(path + ".pre-v*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("backup files = %v", backups)
	}
	info, err := os.Stat(backups[0])
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o400 {
		t.Fatalf("backup permissions = %#o", got)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".cyber-abuse-guard-migration-") {
			t.Fatalf("private migration staging directory was not removed: %s", entry.Name())
		}
	}
	backupDB, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(backups[0])+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer backupDB.Close()
	if err := backupDB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = 'legacy-event'`).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if events != 1 {
		t.Fatalf("backup legacy event count = %d", events)
	}
}

func TestFailedMigrationRollsBackVersionMetadata(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema + migrationMetadataSchema); err != nil {
		t.Fatal(err)
	}
	now := fixedMigrationTime().UnixNano()
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 1, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(1, ?, 'legacy')`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE subject_state(subject_hash TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, openErr := Open(Config{Path: path, Now: fixedMigrationTime})
	if openErr == nil {
		_ = store.Close()
		t.Fatal("migration unexpectedly succeeded")
	}
	if store == nil || !store.Status().Degraded {
		t.Fatalf("degraded store = %#v, error = %v", store, openErr)
	}
	_ = store.Close()

	check, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var version int
	if err := check.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != 1 {
		t.Fatalf("schema version after failed migration = %d", version)
	}
	var migrationTwo int
	if err := check.QueryRow(`SELECT COUNT(*) FROM migration_history WHERE version = 2`).Scan(&migrationTwo); err != nil {
		t.Fatal(err)
	}
	if migrationTwo != 0 {
		t.Fatalf("failed migration history rows = %d", migrationTwo)
	}
}

func TestDeclaredSchemaVersionRequiresItsTableContract(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(migrationMetadataSchema); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 1, ?)`, fixedMigrationTime().UnixNano()); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, openErr := Open(Config{Path: path, Now: fixedMigrationTime})
	if openErr == nil {
		_ = store.Close()
		t.Fatal("declared v1 schema without audit_events unexpectedly opened")
	}
	if store == nil || !store.Status().Degraded {
		t.Fatalf("invalid schema did not produce a degraded store: store=%#v err=%v", store, openErr)
	}
	_ = store.Close()
}

func TestSchemaContractRejectsColumnTypeDrift(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	corrupt := strings.Replace(schema, "id                 TEXT PRIMARY KEY", "id                 INTEGER PRIMARY KEY", 1)
	if _, err := db.Exec(corrupt); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	requireDegradedOpenFailure(t, path)
}

func TestSchemaContractRejectsWrongIndexDefinition(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(schema + `
DROP INDEX idx_audit_events_timestamp;
CREATE INDEX idx_audit_events_timestamp ON audit_events(category ASC);`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	requireDegradedOpenFailure(t, path)
}

func TestSchemaContractRejectsMissingConstraint(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	metadataWithoutVersionCheck := strings.Replace(migrationMetadataSchema, " CHECK (version >= 0)", "", 1)
	if _, err := db.Exec(schema + metadataWithoutVersionCheck + subjectStateSchema); err != nil {
		t.Fatal(err)
	}
	now := fixedMigrationTime().UnixNano()
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 2, ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(1, ?, 'baseline'), (2, ?, 'subject state')`, now, now); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	requireDegradedOpenFailure(t, path)
}

func TestSchemaContractRejectsIncompleteMigrationHistory(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := Open(Config{Path: path, Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DELETE FROM migration_history WHERE version = 2`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	requireDegradedOpenFailure(t, path)
}

func requireDegradedOpenFailure(t testing.TB, path string) {
	t.Helper()
	store, err := Open(Config{Path: path, Now: fixedMigrationTime})
	if err == nil {
		_ = store.Close()
		t.Fatal("invalid schema unexpectedly opened")
	}
	if store == nil || !store.Status().Degraded {
		t.Fatalf("invalid schema did not produce a degraded store: store=%#v err=%v", store, err)
	}
	_ = store.Close()
}

func TestMigrationBackupRetentionIsBounded(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema); err != nil {
		t.Fatal(err)
	}
	now := fixedMigrationTime()
	for i := 0; i < 4; i++ {
		current := now.Add(time.Duration(i) * time.Second)
		if err := createMigrationBackup(db, Config{Now: func() time.Time { return current }, MaxMigrationBackups: 2}, path); err != nil {
			t.Fatal(err)
		}
	}
	backups, err := filepath.Glob(path + ".pre-v*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 2 {
		t.Fatalf("retained backups = %v", backups)
	}
	manifests, err := filepath.Glob(path + ".pre-v*.bak.manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) != len(backups) {
		t.Fatalf("retained manifests = %v, backups = %v", manifests, backups)
	}
	for _, backup := range backups {
		if _, err := os.Stat(backup + ".manifest.json"); err != nil {
			t.Fatalf("retained backup %q has no paired manifest: %v", backup, err)
		}
	}
}

func TestMigrationBackupRetentionTreatsDatabaseNameLiterally(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "audit[prod]?*.db")
	oldBackup := path + ".pre-v2-20260712T000000.000000000Z.bak"
	newBackup := path + ".pre-v2-20260712T000001.000000000Z.bak"
	unrelated := filepath.Join(directory, "auditXprodY.db.pre-v2-20260712T000002.000000000Z.bak")
	oldManifest := oldBackup + ".manifest.json"
	newManifest := newBackup + ".manifest.json"
	for _, candidate := range []string{oldBackup, newBackup, unrelated, oldManifest, newManifest} {
		if err := os.WriteFile(candidate, []byte("backup"), 0o400); err != nil {
			t.Fatal(err)
		}
	}
	oldTime := fixedMigrationTime()
	if err := os.Chtimes(oldBackup, oldTime, oldTime); err != nil {
		t.Fatal(err)
	}
	newTime := oldTime.Add(time.Second)
	if err := os.Chtimes(newBackup, newTime, newTime); err != nil {
		t.Fatal(err)
	}
	if err := pruneMigrationBackups(path, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldBackup); !os.IsNotExist(err) {
		t.Fatalf("old literal backup still exists or stat failed: %v", err)
	}
	if _, err := os.Stat(oldManifest); !os.IsNotExist(err) {
		t.Fatalf("old literal backup manifest still exists or stat failed: %v", err)
	}
	for _, candidate := range []string{newBackup, newManifest, unrelated} {
		if _, err := os.Stat(candidate); err != nil {
			t.Fatalf("expected file %q to remain: %v", candidate, err)
		}
	}
}

type v1DatabaseSnapshot struct {
	Schema []v1SchemaObject
	Events []v1AuditRow
}

type v1SchemaObject struct {
	Type  string
	Name  string
	Table string
	SQL   string
}

type v1AuditRow struct {
	ID               string
	TimestampNS      int64
	Action           string
	Mode             string
	Category         string
	RiskScore        int
	RuleIDs          string
	RequestHash      string
	SubjectHash      string
	Model            string
	SourceFormat     string
	Stream           int
	TextBytesScanned int
	Classifier       string
	LatencyUS        int
}

func captureV1DatabaseSnapshot(t testing.TB, db *sql.DB) v1DatabaseSnapshot {
	t.Helper()
	var snapshot v1DatabaseSnapshot
	schemaRows, err := db.Query(`SELECT type, name, tbl_name, COALESCE(sql, '')
FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)
	if err != nil {
		t.Fatal(err)
	}
	for schemaRows.Next() {
		var object v1SchemaObject
		if err := schemaRows.Scan(&object.Type, &object.Name, &object.Table, &object.SQL); err != nil {
			_ = schemaRows.Close()
			t.Fatal(err)
		}
		snapshot.Schema = append(snapshot.Schema, object)
	}
	if err := schemaRows.Err(); err != nil {
		_ = schemaRows.Close()
		t.Fatal(err)
	}
	if err := schemaRows.Close(); err != nil {
		t.Fatal(err)
	}

	eventRows, err := db.Query(`SELECT id, timestamp_ns, action, mode, category, risk_score, rule_ids,
request_hash, subject_hash, model, source_format, stream, text_bytes_scanned, classifier, latency_us
FROM audit_events ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for eventRows.Next() {
		var row v1AuditRow
		if err := eventRows.Scan(&row.ID, &row.TimestampNS, &row.Action, &row.Mode, &row.Category,
			&row.RiskScore, &row.RuleIDs, &row.RequestHash, &row.SubjectHash, &row.Model,
			&row.SourceFormat, &row.Stream, &row.TextBytesScanned, &row.Classifier, &row.LatencyUS); err != nil {
			_ = eventRows.Close()
			t.Fatal(err)
		}
		snapshot.Events = append(snapshot.Events, row)
	}
	if err := eventRows.Err(); err != nil {
		_ = eventRows.Close()
		t.Fatal(err)
	}
	if err := eventRows.Close(); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func insertSafeLegacyAuditRow(t testing.TB, db *sql.DB, id string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO audit_events VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		id, fixedMigrationTime().UnixNano(), "allow", "balanced", "", 0, "[]",
		"sha256:"+strings.Repeat("a", 64), "hmac-sha256:"+strings.Repeat("b", 64), HashModel("safe-model"),
		"openai", 0, 32, "privacy-rules", 5); err != nil {
		t.Fatal(err)
	}
}

type v4RawCaptureFixture struct {
	EventID     string
	CaptureID   string
	Timestamp   time.Time
	RequestHash string
	SubjectHash string
	RawPreview  string
	RawSHA256   string
	Redacted    bool
}

func createV4RawCaptureDatabase(t testing.TB, path string, now time.Time, fixtures []v4RawCaptureFixture) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema + subjectStateSchema + round6AuditEventColumns + rawRequestCaptureSchema + migrationMetadataSchema); err != nil {
		t.Fatal(err)
	}
	nowNS := now.UnixNano()
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 4, ?)`, nowNS); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 4; version++ {
		if _, err := db.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(?, ?, 'fixture')`, version, nowNS); err != nil {
			t.Fatal(err)
		}
	}
	for _, fixture := range fixtures {
		if _, err := db.Exec(`INSERT INTO audit_events (
id, timestamp_ns, action, mode, category, risk_score, rule_ids,
request_hash, subject_hash, model, source_format, stream, text_bytes_scanned,
classifier, latency_us, decision, coverage, incomplete_reason, scanner
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fixture.EventID, fixture.Timestamp.UnixNano(), "block", "balanced", "defense_evasion", 90, `["EVADE-002"]`,
			HashRequest([]byte("event-"+fixture.EventID)), testSubjectHash("event-subject-"+fixture.EventID),
			HashModel("v4-raw-capture-fixture"), "openai", 0, 128, "classifier-policy-v6", 25,
			"block_malicious_text", "complete", "", "streaming-scanner-v1"); err != nil {
			t.Fatal(err)
		}
		redacted := 0
		if fixture.Redacted {
			redacted = 1
		}
		if _, err := db.Exec(`INSERT INTO raw_request_captures (
id, event_id, timestamp_ns, request_hash, subject_hash, action, decision,
truncated, redacted, raw_preview, raw_sha256
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			fixture.CaptureID, fixture.EventID, fixture.Timestamp.UnixNano(), fixture.RequestHash,
			fixture.SubjectHash, "block", "block_malicious_text", 0, redacted,
			fixture.RawPreview, fixture.RawSHA256); err != nil {
			t.Fatal(err)
		}
	}
}

func onlyMigrationBackup(t testing.TB, path string) string {
	t.Helper()
	backups, err := filepath.Glob(path + ".pre-v*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 1 {
		t.Fatalf("migration backups=%v, want exactly one", backups)
	}
	return backups[0]
}

func fixedMigrationTime() time.Time {
	return time.Date(2026, 7, 12, 0, 0, 0, 123456789, time.UTC)
}
