package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRound10V6ToV7MigrationPreservesEventsAndCaptures exercises the new
// taxonomy boundary with capture retention enabled. The backup is inspected as
// an independent, immutable v6 snapshot rather than inferred from the active
// post-migration database.
func TestRound10V6ToV7MigrationPreservesEventsAndCaptures(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "round10-v6-to-v7.db")
	createRound10V6Database(t, path)

	store, err := Open(Config{
		Path: path, Now: fixedMigrationTime,
		RawCapture:          RawCaptureConfig{Enabled: true, MaxBytes: 8192, TTL: 72 * time.Hour},
		MaxMigrationBackups: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	assertSchemaVersion(t, store.db, 7)
	var eventCount, captureCount int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = 'round9-v5-event'`).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM raw_request_captures WHERE id = 'round9-v5-capture'`).Scan(&captureCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 1 || captureCount != 1 {
		t.Fatalf("v7 active rows event=%d capture=%d; want one of each", eventCount, captureCount)
	}
	captures, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{EventID: "round9-v5-event"})
	if err != nil {
		t.Fatal(err)
	}
	if len(captures) != 1 || captures[0].EventID != "round9-v5-event" || captures[0].DecisionKind != decisionKindLegacyUnspecified {
		t.Fatalf("migrated capture = %#v", captures)
	}

	backup := onlyMigrationBackup(t, path)
	if !strings.Contains(filepath.Base(backup), ".pre-v7-") {
		t.Fatalf("v6->v7 backup path = %q, want pre-v7 identity", backup)
	}
	manifest := readRound10Manifest(t, backup)
	digest, err := hashMigrationArtifact(backup)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SourceSchemaVersion != 6 || manifest.TargetSchemaVersion != 7 ||
		manifest.SQLiteQuickCheck != "ok" || !manifest.ExactSnapshot ||
		manifest.SHA256 != digest || manifest.Bytes != info.Size() {
		t.Fatalf("v6->v7 manifest = %#v", manifest)
	}
	backupDB := openRound10ReadOnly(t, backup)
	defer backupDB.Close()
	assertSchemaVersion(t, backupDB, 6)
	var backupEvents, backupCaptures int
	if err := backupDB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = 'round9-v5-event'`).Scan(&backupEvents); err != nil {
		t.Fatal(err)
	}
	if err := backupDB.QueryRow(`SELECT COUNT(*) FROM raw_request_captures WHERE id = 'round9-v5-capture'`).Scan(&backupCaptures); err != nil {
		t.Fatal(err)
	}
	if backupEvents != 1 || backupCaptures != 1 {
		t.Fatalf("pre-v7 backup rows event=%d capture=%d", backupEvents, backupCaptures)
	}
}

// TestRound10V6ToV7MigrationFailureRollsBackExactly verifies that a failure
// after the v7 table rebuild has begun leaves the primary file at byte-level
// logical v6 identity (including the injected failure trigger) and that the
// online-backup artifact can restore that same state.
func TestRound10V6ToV7MigrationFailureRollsBackExactly(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "round10-v6-failure.db")
	createRound10V6Database(t, path)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_round10_history
BEFORE INSERT ON migration_history
WHEN NEW.version = 7
BEGIN
    SELECT RAISE(ABORT, 'round10 migration rejection');
END;`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	before := round10V6Snapshot(t, db)
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, openErr := Open(Config{
		Path: path, Now: fixedMigrationTime,
		RawCapture:          RawCaptureConfig{Enabled: true, MaxBytes: 8192, TTL: 72 * time.Hour},
		MaxMigrationBackups: 1,
	})
	if store != nil {
		t.Cleanup(func() { _ = store.Close() })
	}
	if openErr == nil {
		t.Fatal("v6->v7 migration unexpectedly succeeded with injected failure")
	}
	if store == nil || !store.Status().Degraded {
		t.Fatalf("failed v7 migration did not return degraded store: store=%#v err=%v", store, openErr)
	}

	check := openRound10ReadOnly(t, path)
	defer check.Close()
	after := round10V6Snapshot(t, check)
	if after != before {
		t.Fatalf("failed v6->v7 migration changed the v6 database:\nbefore=%#v\nafter=%#v", before, after)
	}
	if after.Version != 6 || after.EventRows != before.EventRows || after.CaptureRows != before.CaptureRows {
		t.Fatalf("rolled-back v6 identity = %#v", after)
	}

	backup := onlyMigrationBackup(t, path)
	manifest := readRound10Manifest(t, backup)
	if manifest.SourceSchemaVersion != 6 || manifest.TargetSchemaVersion != 7 || manifest.SQLiteQuickCheck != "ok" || !manifest.ExactSnapshot {
		t.Fatalf("failed migration manifest = %#v", manifest)
	}
	restoredPath := filepath.Join(t.TempDir(), "round10-restored-v6.db")
	backupBytes, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restoredPath, backupBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	restored := openRound10ReadOnly(t, restoredPath)
	defer restored.Close()
	restoredSnapshot := round10V6Snapshot(t, restored)
	if restoredSnapshot != before {
		t.Fatalf("restored pre-v7 backup differs from exact v6 state:\nwant=%#v\ngot=%#v", before, restoredSnapshot)
	}
	var quickCheck string
	if err := restored.QueryRow(`PRAGMA quick_check`).Scan(&quickCheck); err != nil {
		t.Fatal(err)
	}
	if quickCheck != "ok" {
		t.Fatalf("restored v6 quick_check=%q", quickCheck)
	}
}

func TestRound10V6ToV7MigrationRejectsNonContractRawCaptureSchemaObjects(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		statement string
		object    string
	}{
		{
			name:      "index",
			statement: `CREATE INDEX operator_raw_capture_subject ON raw_request_captures(subject_hash)`,
			object:    "operator_raw_capture_subject",
		},
		{
			name: "trigger",
			statement: `CREATE TRIGGER operator_raw_capture_insert
AFTER INSERT ON raw_request_captures
BEGIN
    SELECT NEW.id;
END`,
			object: "operator_raw_capture_insert",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "round10-v6-extra-"+test.name+".db")
			createRound10V6Database(t, path)
			db, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(test.statement); err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			before := round10V6Snapshot(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			store, openErr := Open(Config{
				Path: path, Now: fixedMigrationTime,
				RawCapture:          RawCaptureConfig{Enabled: true, MaxBytes: 8192, TTL: 72 * time.Hour},
				MaxMigrationBackups: 1,
			})
			if store != nil {
				t.Cleanup(func() { _ = store.Close() })
			}
			if openErr == nil || !strings.Contains(openErr.Error(), "non-contract raw_request_captures") || !strings.Contains(openErr.Error(), test.object) {
				t.Fatalf("Open error=%v, want fail-closed rejection for %s", openErr, test.object)
			}
			if store == nil || !store.Status().Degraded {
				t.Fatalf("rejected migration store=%#v error=%v", store, openErr)
			}

			check := openRound10ReadOnly(t, path)
			defer check.Close()
			after := round10V6Snapshot(t, check)
			if after != before || after.Version != 6 {
				t.Fatalf("rejected v6->v7 migration changed the source database:\nbefore=%#v\nafter=%#v", before, after)
			}
			backups, err := filepath.Glob(path + ".pre-v7-*.bak")
			if err != nil {
				t.Fatal(err)
			}
			if len(backups) != 0 {
				t.Fatalf("schema preflight created backups before rejection: %v", backups)
			}
			manifests, err := filepath.Glob(path + ".pre-v7-*.bak.manifest.json")
			if err != nil {
				t.Fatal(err)
			}
			if len(manifests) != 0 {
				t.Fatalf("schema preflight created manifests before rejection: %v", manifests)
			}
		})
	}
}

func TestRound10V6ToV7MigrationRejectsRawCaptureViewsAndForeignKeys(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		statement string
		object    string
		check     func(t *testing.T, db *sql.DB)
	}{
		{
			name: "view",
			statement: `CREATE VIEW operator_raw_capture_view AS
SELECT id, event_id, raw_sha256 FROM raw_request_captures`,
			object: "operator_raw_capture_view",
			check: func(t *testing.T, db *sql.DB) {
				var count int
				if err := db.QueryRow(`SELECT COUNT(*) FROM operator_raw_capture_view`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Fatalf("raw-capture view rows=%d, want 1", count)
				}
			},
		},
		{
			name: "foreign-key",
			statement: `PRAGMA foreign_keys = ON;
CREATE TABLE operator_raw_capture_refs (
    capture_id TEXT NOT NULL,
    note TEXT NOT NULL,
    FOREIGN KEY (capture_id) REFERENCES raw_request_captures(id) ON DELETE CASCADE
);
INSERT INTO operator_raw_capture_refs(capture_id, note)
VALUES ('round9-v5-capture', 'must survive rejected migration');`,
			object: "operator_raw_capture_refs",
			check: func(t *testing.T, db *sql.DB) {
				var count int
				if err := db.QueryRow(`SELECT COUNT(*) FROM operator_raw_capture_refs WHERE capture_id = 'round9-v5-capture'`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Fatalf("external foreign-key rows=%d, want 1", count)
				}
				var parent string
				if err := db.QueryRow(`SELECT "table" FROM pragma_foreign_key_list('operator_raw_capture_refs')`).Scan(&parent); err != nil {
					t.Fatal(err)
				}
				if !strings.EqualFold(parent, "raw_request_captures") {
					t.Fatalf("external foreign-key parent=%q, want raw_request_captures", parent)
				}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "round10-v6-dependency-"+test.name+".db")
			createRound10V6Database(t, path)
			db, err := sql.Open("sqlite3", path)
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			if _, err := db.Exec(test.statement); err != nil {
				_ = db.Close()
				t.Fatal(err)
			}
			before := round10V6Snapshot(t, db)
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}

			store, openErr := Open(Config{
				Path: path, Now: fixedMigrationTime,
				RawCapture:          RawCaptureConfig{Enabled: true, MaxBytes: 8192, TTL: 72 * time.Hour},
				MaxMigrationBackups: 1,
			})
			if store != nil {
				t.Cleanup(func() { _ = store.Close() })
			}
			if openErr == nil || !strings.Contains(openErr.Error(), "non-contract raw_request_captures") || !strings.Contains(openErr.Error(), test.object) {
				t.Fatalf("Open error=%v, want fail-closed rejection for %s", openErr, test.object)
			}
			if store == nil || !store.Status().Degraded {
				t.Fatalf("rejected migration store=%#v error=%v", store, openErr)
			}

			check := openRound10ReadOnly(t, path)
			defer check.Close()
			after := round10V6Snapshot(t, check)
			if after != before || after.Version != 6 {
				t.Fatalf("rejected v6->v7 migration changed the source database:\nbefore=%#v\nafter=%#v", before, after)
			}
			test.check(t, check)
			for _, pattern := range []string{path + ".pre-v7-*.bak", path + ".pre-v7-*.bak.manifest.json"} {
				artifacts, err := filepath.Glob(pattern)
				if err != nil {
					t.Fatal(err)
				}
				if len(artifacts) != 0 {
					t.Fatalf("schema preflight published artifacts before rejection: %v", artifacts)
				}
			}
		})
	}
}

func TestRound10CSAMTextEventsQueryStatsAndExports(t *testing.T) {
	t.Parallel()
	now := fixedMigrationTime()
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "round10-csam-events.db"), Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	auditEvent := round10CSAMTextEvent("round10-csam-audit", now, false)
	blockEvent := round10CSAMTextEvent("round10-csam-block", now.Add(time.Nanosecond), true)
	for _, event := range []Event{auditEvent, blockEvent} {
		if err := store.Enqueue(event); err != nil {
			t.Fatalf("enqueue %s: %v", event.ID, err)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	queried, err := store.Query(context.Background(), Query{DecisionKind: decisionKindAuditCSAMText, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(queried) != 1 || queried[0].ID != auditEvent.ID || queried[0].Decision != "audit_csam_text" ||
		queried[0].DecisionKind != decisionKindAuditCSAMText || queried[0].Category != "csam_malicious" ||
		queried[0].DecisionExplanation == nil || queried[0].DecisionExplanation.Kind != decisionExplanationKindCSAMText {
		t.Fatalf("CSAM query result = %#v", queried)
	}

	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.ByDecisionKind[decisionKindAuditCSAMText] != 1 || stats.ByDecisionKind[decisionKindBlockCSAMText] != 1 ||
		stats.ByCategory["csam_malicious"] != 2 || stats.ByAction["audit"] != 1 || stats.ByAction["block"] != 1 {
		t.Fatalf("CSAM stats = %#v", stats)
	}

	var jsonExport bytes.Buffer
	if err := store.ExportJSON(context.Background(), &jsonExport, Query{Category: "csam_malicious", Limit: 10}); err != nil {
		t.Fatal(err)
	}
	var exported []Event
	if err := json.Unmarshal(jsonExport.Bytes(), &exported); err != nil {
		t.Fatal(err)
	}
	if len(exported) != 2 {
		t.Fatalf("CSAM JSON rows=%d, want 2", len(exported))
	}
	for _, event := range exported {
		if event.DecisionExplanation == nil || event.DecisionExplanation.Kind != decisionExplanationKindCSAMText ||
			event.ExplanationSchema != DecisionExplanationSchemaV2 {
			t.Fatalf("CSAM JSON event=%#v", event)
		}
	}

	var csvExport bytes.Buffer
	if err := store.ExportCSV(context.Background(), &csvExport, Query{Category: "csam_malicious", Limit: 10}); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(csvExport.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 3 {
		t.Fatalf("CSAM CSV rows=%d, want header plus 2", len(records))
	}
	columns := make(map[string]int, len(records[0]))
	for i, name := range records[0] {
		columns[name] = i
	}
	for _, required := range []string{"decision", "decision_kind", "category", "explanation_schema", "decision_explanation"} {
		if _, ok := columns[required]; !ok {
			t.Fatalf("CSAM CSV header missing %q: %v", required, records[0])
		}
	}
	for _, row := range records[1:] {
		if row[columns["category"]] != "csam_malicious" ||
			(row[columns["decision_kind"]] != decisionKindAuditCSAMText && row[columns["decision_kind"]] != decisionKindBlockCSAMText) ||
			row[columns["explanation_schema"]] != DecisionExplanationSchemaV2 ||
			!strings.Contains(row[columns["decision_explanation"]], `"kind":"csam_text"`) {
			t.Fatalf("CSAM CSV row=%v", row)
		}
	}
}

func TestRound10RawCaptureDDLRejectsCSAMAndForgedKinds(t *testing.T) {
	t.Parallel()
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "round10-csam-ddl.db"), Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	event := round10CSAMTextEvent("round10-csam-ddl-event", fixedMigrationTime(), true)
	if err := store.Enqueue(event); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	args := []any{
		"round10-csam-ddl-capture", event.ID, event.Timestamp.UnixNano(), event.RequestHash,
		event.SubjectHash, "block", "block_csam_text", 0, 0, "synthetic preview",
		"sha256:" + strings.Repeat("c", 64), 0, rawCaptureRedactionVersion,
		decisionKindBlockCSAMText, DecisionExplanationSchemaV2,
	}
	insertCapture := `INSERT INTO raw_request_captures (
id, event_id, timestamp_ns, request_hash, subject_hash, action, decision,
truncated, redacted, raw_preview, raw_sha256, redaction_pattern_hits,
redaction_version, decision_kind, explanation_schema
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	for index, forbiddenKind := range []string{
		decisionKindAuditEligibleMaliciousText,
		decisionKindAuditCSAMText,
		decisionKindBlockCSAMText,
	} {
		args[0] = fmt.Sprintf("round10-csam-ddl-capture-%d", index)
		args[10] = fmt.Sprintf("sha256:%064x", index+1)
		args[13] = forbiddenKind
		if _, err := store.db.Exec(insertCapture, args...); err == nil {
			t.Fatalf("v7 DDL accepted a %s raw capture", forbiddenKind)
		}
	}

	for index, forgedKind := range []string{"csam_text", "block_csam_text_v99", "future_decision_kind"} {
		forgedEvent := round10CSAMTextEvent(
			fmt.Sprintf("round10-forged-event-%d", index),
			event.Timestamp.Add(time.Duration(index+1)*time.Nanosecond), true,
		)
		if err := store.Enqueue(forgedEvent); err != nil {
			t.Fatalf("enqueue forged-kind fixture event %q: %v", forgedKind, err)
		}
		if err := store.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		args[0] = "round10-forged-" + strings.ReplaceAll(forgedKind, "_", "-")
		args[1] = forgedEvent.ID
		args[2] = forgedEvent.Timestamp.UnixNano()
		args[3] = forgedEvent.RequestHash
		args[4] = forgedEvent.SubjectHash
		args[10] = fmt.Sprintf("sha256:%064x", index+10)
		args[13] = forgedKind
		if _, err := store.db.Exec(insertCapture, args...); err == nil {
			t.Fatalf("forged raw capture decision_kind %q was accepted", forgedKind)
		}
	}
}

func TestRound10CSAMTextEventRejectsUnregisteredRuleID(t *testing.T) {
	t.Parallel()
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "round10-csam-rule.db"), Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	event := round10CSAMTextEvent("round10-csam-unregistered-rule", fixedMigrationTime(), true)
	event.RuleIDs = []string{"CSAM-TXT-UNREGISTERED-999"}
	if err := store.Enqueue(event); err == nil {
		t.Fatal("audit store accepted an unregistered CSAM-text rule ID")
	}
}

func TestRound10RawCaptureAPIsRejectCSAMDecisionKinds(t *testing.T) {
	t.Parallel()
	now := fixedMigrationTime()
	store, err := Open(Config{
		Path: filepath.Join(t.TempDir(), "round10-csam-api.db"), Now: fixedMigrationTime,
		RawCapture: RawCaptureConfig{Enabled: true, MaxBytes: 8192, TTL: 72 * time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	for index, blocking := range []bool{false, true} {
		event := round10CSAMTextEvent(fmt.Sprintf("round10-csam-api-%d", index), now.Add(time.Duration(index)*time.Nanosecond), blocking)
		input := RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
			DecisionKind: event.DecisionKind, ExplanationSchema: event.ExplanationSchema,
			RawRequest: []byte("synthetic preview"),
		}
		if err := store.RecordRawCapture(input); !errors.Is(err, ErrInvalidRawCapture) {
			t.Fatalf("RecordRawCapture(%s) error=%v, want ErrInvalidRawCapture", event.DecisionKind, err)
		}
		accepted, err := store.EnqueueEventWithRawCapture(event, input)
		if !accepted || !errors.Is(err, ErrInvalidRawCapture) {
			t.Fatalf("EnqueueEventWithRawCapture(%s) accepted=%t error=%v", event.DecisionKind, accepted, err)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var captures int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM raw_request_captures`).Scan(&captures); err != nil {
		t.Fatal(err)
	}
	if captures != 0 {
		t.Fatalf("CSAM API rejection persisted %d raw captures", captures)
	}
}

func TestRound10SchemaContractRejectsNonUniqueEventCaptureIndex(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "round10-index-drift.db")
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
	if _, err := db.Exec(`DROP INDEX idx_raw_request_captures_event;
CREATE INDEX idx_raw_request_captures_event ON raw_request_captures(event_id);`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	requireDegradedOpenFailure(t, path)
}

func TestRound10CurrentV7ReopenKeepsRowsAndDoesNotCreateMigrationBackup(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "round10-reopen-v7.db")
	first, err := Open(Config{Path: path, Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	event := round10CSAMTextEvent("round10-reopen-event", fixedMigrationTime(), false)
	if err := first.Enqueue(event); err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	if err := first.Flush(context.Background()); err != nil {
		_ = first.Close()
		t.Fatal(err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	backupsBefore, err := filepath.Glob(path + ".pre-v*.bak")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Open(Config{Path: path, Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = second.Close() })
	assertSchemaVersion(t, second.db, currentSchemaVersion)
	if events, err := second.Query(context.Background(), Query{DecisionKind: decisionKindAuditCSAMText, Limit: 10}); err != nil {
		t.Fatal(err)
	} else if len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("v7 reopen events=%#v", events)
	}
	backupsAfter, err := filepath.Glob(path + ".pre-v*.bak")
	if err != nil {
		t.Fatal(err)
	}
	if len(backupsAfter) != len(backupsBefore) {
		t.Fatalf("current-v7 reopen changed migration backup count before=%v after=%v", backupsBefore, backupsAfter)
	}
}

func round10CSAMTextEvent(id string, timestamp time.Time, blocking bool) Event {
	event := testEvent(id, timestamp)
	event.Category = "csam_malicious"
	event.RiskScore = 0
	event.RuleIDs = []string{"CSAM-TXT-PRODUCTION-001"}
	event.Classifier = "csam-text-v1"
	event.Coverage = "complete"
	event.IncompleteReason = ""
	event.Scanner = "streaming-scanner-v1"
	event.DecisionExplanation = &DecisionExplanation{Kind: decisionExplanationKindCSAMText}
	if blocking {
		event.Action = "block"
		event.Decision = "block_csam_text"
		event.DecisionKind = decisionKindBlockCSAMText
	} else {
		event.Action = "audit"
		event.Decision = "audit_csam_text"
		event.DecisionKind = decisionKindAuditCSAMText
	}
	return event
}

// createRound10V6Database starts with the checked-in v5 fixture, applies the
// v6 schema in one explicit step, and records complete v6 metadata/history.
func createRound10V6Database(t testing.TB, path string) {
	t.Helper()
	createRound9V5Database(t, path, true)
	insertRound9V5RawCapture(t, path)
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(round9AuditSchema); err != nil {
		t.Fatal(err)
	}
	nowNS := fixedMigrationTime().UnixNano()
	if _, err := db.Exec(`UPDATE schema_version SET version = 6, updated_at_ns = ? WHERE singleton = 1`, nowNS); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(6, ?, 'round10-v6-fixture')`, nowNS); err != nil {
		t.Fatal(err)
	}
	if err := validateSchemaContract(db, 6); err != nil {
		t.Fatalf("constructed v6 fixture violates v6 contract: %v", err)
	}
}

type round10V6DatabaseSnapshot struct {
	Version           int
	SchemaDDL         string
	SchemaVersionRows string
	HistoryRows       string
	EventRows         string
	CaptureRows       string
	SubjectMetaRows   string
	SubjectStateRows  string
}

func round10V6Snapshot(t testing.TB, db *sql.DB) round10V6DatabaseSnapshot {
	t.Helper()
	var version int
	if err := db.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	return round10V6DatabaseSnapshot{
		Version:           version,
		SchemaDDL:         round10SnapshotRows(t, db, `SELECT type, name, COALESCE(sql, '') FROM sqlite_master WHERE type IN ('table','index','trigger','view') ORDER BY type, name`),
		SchemaVersionRows: round10SnapshotRows(t, db, `SELECT singleton, version, updated_at_ns FROM schema_version ORDER BY singleton`),
		HistoryRows:       round10SnapshotRows(t, db, `SELECT version, applied_at_ns, description FROM migration_history ORDER BY version`),
		EventRows:         round10SnapshotRows(t, db, `SELECT id, timestamp_ns, action, mode, category, risk_score, rule_ids, request_hash, subject_hash, model, source_format, stream, text_bytes_scanned, classifier, decision, coverage, incomplete_reason, scanner, latency_us, decision_explanation, disposition, explanation_schema FROM audit_events ORDER BY id`),
		CaptureRows:       round10SnapshotRows(t, db, `SELECT id, event_id, timestamp_ns, request_hash, subject_hash, action, decision, truncated, redacted, raw_preview, raw_sha256, redaction_pattern_hits, redaction_version, decision_kind, explanation_schema FROM raw_request_captures ORDER BY id`),
		SubjectMetaRows:   round10SnapshotRows(t, db, `SELECT singleton, persistence_version, hmac_key_id, saved_at_ns, updated_at_ns FROM subject_state_meta ORDER BY singleton`),
		SubjectStateRows:  round10SnapshotRows(t, db, `SELECT subject_hash, state_json, updated_at_ns FROM subject_state ORDER BY subject_hash`),
	}
}

func round10SnapshotRows(t testing.TB, db *sql.DB, query string, args ...any) string {
	t.Helper()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var result []string
	for rows.Next() {
		values := make([]sql.RawBytes, len(columns))
		destinations := make([]any, len(values))
		for i := range values {
			destinations[i] = &values[i]
		}
		if err := rows.Scan(destinations...); err != nil {
			t.Fatal(err)
		}
		fields := make([]string, len(values))
		for i := range values {
			fields[i] = fmt.Sprintf("%s=%s", columns[i], string(values[i]))
		}
		result = append(result, strings.Join(fields, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(result, "\n")
}

func readRound10Manifest(t testing.TB, backup string) migrationBackupManifest {
	t.Helper()
	data, err := os.ReadFile(backup + ".manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest migrationBackupManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	return manifest
}

func openRound10ReadOnly(t testing.TB, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	return db
}

func assertSchemaVersion(t testing.TB, db *sql.DB, want int) {
	t.Helper()
	var got int
	if err := db.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("schema version=%d, want %d", got, want)
	}
}
