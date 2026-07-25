package audit

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRound9V5ToV6MigrationIsAtomic(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "round9-atomic-v5.db")
	createRound9V5Database(t, path, false)

	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER reject_round9_history
BEFORE INSERT ON migration_history
WHEN NEW.version = 6
BEGIN
    SELECT RAISE(ABORT, 'round9 migration rejection');
END;`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	store, openErr := Open(Config{Path: path, Now: fixedMigrationTime})
	if store != nil {
		t.Cleanup(func() { _ = store.Close() })
	}
	if openErr == nil {
		t.Fatal("Open() succeeded despite an injected v6 migration failure")
	}
	backup := onlyMigrationBackup(t, path)
	if _, err := os.Stat(backup + ".manifest.json"); err != nil {
		t.Fatalf("failed migration did not retain its recovery manifest: %v", err)
	}

	check, err := sql.Open("sqlite3", path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var version, dispositionColumns, explanationSchemaColumns, v6History int
	if err := check.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if err := check.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('audit_events') WHERE name = 'disposition'`).Scan(&dispositionColumns); err != nil {
		t.Fatal(err)
	}
	if err := check.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('audit_events') WHERE name = 'explanation_schema'`).Scan(&explanationSchemaColumns); err != nil {
		t.Fatal(err)
	}
	if err := check.QueryRow(`SELECT COUNT(*) FROM migration_history WHERE version = 6`).Scan(&v6History); err != nil {
		t.Fatal(err)
	}
	if version != 5 || dispositionColumns != 0 || explanationSchemaColumns != 0 || v6History != 0 {
		t.Fatalf("failed v6 migration left version=%d disposition_columns=%d explanation_schema_columns=%d history_v6=%d", version, dispositionColumns, explanationSchemaColumns, v6History)
	}
	var integrity string
	if err := check.QueryRow("PRAGMA quick_check").Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if integrity != "ok" {
		t.Fatalf("quick_check after rolled-back v6 migration = %q", integrity)
	}

	backupBytes, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	restoredPath := filepath.Join(t.TempDir(), "restored-round9-v5.db")
	if err := os.WriteFile(restoredPath, backupBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err := sql.Open("sqlite3", restoredPath+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	var restoredVersion, restoredTrigger int
	if err := restored.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&restoredVersion); err != nil {
		t.Fatal(err)
	}
	if err := restored.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'trigger' AND name = 'reject_round9_history'`).Scan(&restoredTrigger); err != nil {
		t.Fatal(err)
	}
	if err := restored.QueryRow("PRAGMA quick_check").Scan(&integrity); err != nil {
		t.Fatal(err)
	}
	if restoredVersion != 5 || restoredTrigger != 1 || integrity != "ok" {
		t.Fatalf("restored pre-v6 backup version=%d trigger=%d quick_check=%q", restoredVersion, restoredTrigger, integrity)
	}
}

func TestRound9V5ToV6MigrationCreatesPreMigrationBackup(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "round9-backup-v5.db")
	createRound9V5Database(t, path, true)
	insertRound9V5RawCapture(t, path)

	store, err := Open(Config{
		Path:                  path,
		Now:                   fixedMigrationTime,
		BackupBeforeMigration: false,
		MaxMigrationBackups:   1,
		RawCapture: RawCaptureConfig{
			Enabled:  true,
			MaxBytes: 8192,
			TTL:      72 * time.Hour,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	backup := onlyMigrationBackup(t, path)
	if !strings.Contains(filepath.Base(backup), ".pre-v6-") {
		t.Fatalf("migration backup name = %q, want pre-v6 identity", backup)
	}
	manifestPath := backup + ".manifest.json"
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest migrationBackupManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatal(err)
	}
	digest, err := hashMigrationArtifact(backup)
	if err != nil {
		t.Fatal(err)
	}
	backupInfo, err := os.Stat(backup)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != migrationBackupManifestSchema || manifest.DatabaseFile != filepath.Base(backup) ||
		manifest.SourceSchemaVersion != 5 || manifest.TargetSchemaVersion != 6 ||
		manifest.SHA256 != digest || manifest.Bytes != backupInfo.Size() ||
		manifest.SQLiteQuickCheck != "ok" || !manifest.ExactSnapshot ||
		!strings.Contains(manifest.RollbackInstruction, "stop CPA") ||
		!strings.Contains(manifest.RollbackInstruction, "older SO") {
		t.Fatalf("migration backup manifest = %#v", manifest)
	}
	if backupInfo.Mode().Perm() != 0o400 {
		t.Fatalf("migration backup mode = %o, want 400", backupInfo.Mode().Perm())
	}
	if info, err := os.Stat(manifestPath); err != nil || info.Mode().Perm() != 0o400 {
		t.Fatalf("migration manifest mode info=%v err=%v", info, err)
	}
	backupDB, err := sql.Open("sqlite3", backup+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer backupDB.Close()
	var backupVersion, backupDispositionColumns, backupEvents, backupCaptures int
	if err := backupDB.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&backupVersion); err != nil {
		t.Fatal(err)
	}
	if err := backupDB.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('audit_events') WHERE name = 'disposition'`).Scan(&backupDispositionColumns); err != nil {
		t.Fatal(err)
	}
	if err := backupDB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = 'round9-v5-event'`).Scan(&backupEvents); err != nil {
		t.Fatal(err)
	}
	if err := backupDB.QueryRow(`SELECT COUNT(*) FROM raw_request_captures WHERE id = 'round9-v5-capture'`).Scan(&backupCaptures); err != nil {
		t.Fatal(err)
	}
	if backupVersion != 5 || backupDispositionColumns != 0 || backupEvents != 1 || backupCaptures != 1 {
		t.Fatalf("pre-migration backup version=%d disposition_columns=%d events=%d captures=%d", backupVersion, backupDispositionColumns, backupEvents, backupCaptures)
	}

	var activeVersion, activeDispositionColumns, activeExplanationSchemaColumns int
	if err := store.db.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&activeVersion); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('audit_events') WHERE name = 'disposition'`).Scan(&activeDispositionColumns); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('audit_events') WHERE name = 'explanation_schema'`).Scan(&activeExplanationSchemaColumns); err != nil {
		t.Fatal(err)
	}
	if activeVersion != 6 || activeDispositionColumns != 1 || activeExplanationSchemaColumns != 1 {
		t.Fatalf("active database version=%d disposition_columns=%d explanation_schema_columns=%d", activeVersion, activeDispositionColumns, activeExplanationSchemaColumns)
	}
	captures, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{EventID: "round9-v5-event"})
	if err != nil {
		t.Fatal(err)
	}
	if len(captures) != 1 || captures[0].DecisionKind != decisionKindLegacyUnspecified ||
		captures[0].ExplanationSchema != DecisionExplanationSchemaNone {
		t.Fatalf("migrated raw capture metadata = %#v", captures)
	}
}

func TestRound9V6ReadsV5RowsAsLegacyUnspecified(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "round9-read-v5.db")
	createRound9V5Database(t, path, true)

	store, err := Open(Config{Path: path, Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	events, err := store.Query(context.Background(), Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("migrated events = %d, want 1", len(events))
	}
	if events[0].DecisionKind != decisionKindLegacyUnspecified {
		t.Fatalf("migrated decision_kind = %q, want %q", events[0].DecisionKind, decisionKindLegacyUnspecified)
	}
	if !reflect.DeepEqual(events[0].DecisionExplanation, round8DecisionExplanationFixture()) {
		t.Fatalf("legacy decision explanation changed during v6 migration: %#v", events[0].DecisionExplanation)
	}
}

func TestRound9DecisionExplanationRejectsUnknownAndContradictoryEligibility(t *testing.T) {
	t.Parallel()
	valid := round9EligibleDecisionExplanationFixture()
	if err := validateDecisionExplanation(valid); err != nil {
		t.Fatalf("valid Round9 explanation rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*DecisionExplanation)
	}{
		{name: "unknown primary reason", mutate: func(value *DecisionExplanation) {
			value.PrimaryEligibilityReason = "future_reason"
		}},
		{name: "unknown authorization state", mutate: func(value *DecisionExplanation) {
			value.AuthorizationClaimState = "caller_asserted"
		}},
		{name: "unknown reason flag", mutate: func(value *DecisionExplanation) {
			value.EligibilityReasonFlags |= 1 << 63
		}},
		{name: "eligible primary mismatch", mutate: func(value *DecisionExplanation) {
			value.PrimaryEligibilityReason = eligibilityReasonAmbiguousCore
			value.EligibilityReasonFlags = eligibilityFlagAmbiguousCore
		}},
		{name: "eligible defensive conflict", mutate: func(value *DecisionExplanation) {
			value.DefensiveScopeConflict = true
		}},
		{name: "eligible ambiguous evidence", mutate: func(value *DecisionExplanation) {
			value.EvidenceAmbiguous = true
		}},
		{name: "ineligible hard floor", mutate: func(value *DecisionExplanation) {
			value.BlockEligible = false
			value.PrimaryEligibilityReason = eligibilityReasonNoCurrentDirective
			value.EligibilityReasonFlags = eligibilityFlagNoCurrentDirective
			value.CurrentExecutionActProven = false
		}},
		{name: "ineligible explicit-malice flag", mutate: func(value *DecisionExplanation) {
			value.BlockEligible = false
			value.PrimaryEligibilityReason = eligibilityReasonAmbiguousCore
			value.EligibilityReasonFlags = eligibilityFlagAmbiguousCore | eligibilityFlagExplicitMalice
			value.HardFloorApplied = false
			value.HardFloorReason = ""
			value.HarmfulCoreComplete = false
		}},
		{name: "primary reason contradicts evidence", mutate: func(value *DecisionExplanation) {
			value.BlockEligible = false
			value.PrimaryEligibilityReason = eligibilityReasonNoCurrentDirective
			value.EligibilityReasonFlags = eligibilityFlagNoCurrentDirective
			value.HardFloorApplied = false
			value.HardFloorReason = ""
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := cloneDecisionExplanation(valid)
			test.mutate(value)
			if err := validateDecisionExplanation(value); err == nil {
				t.Fatalf("validateDecisionExplanation accepted contradictory eligibility: %#v", value)
			}
		})
	}

	encoded, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.TrimSuffix(string(encoded), "}") + `,"eligibility_debug_text":"forbidden"}`
	if _, err := decodeDecisionExplanation(unknown); err == nil {
		t.Fatal("decodeDecisionExplanation accepted an unknown Round9 field")
	}
}

func TestRound9DecisionKindRejectsMasqueradingBlockExplanations(t *testing.T) {
	t.Parallel()
	valid := round9MaliciousBlockEventFixture()
	if err := validateEvent(valid); err != nil {
		t.Fatalf("valid Round9 malicious block rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "unknown kind", mutate: func(event *Event) {
			event.DecisionKind = "future_block_kind"
		}},
		{name: "malicious block missing explanation", mutate: func(event *Event) {
			event.DecisionExplanation = nil
		}},
		{name: "malicious block ineligible", mutate: func(event *Event) {
			event.DecisionExplanation.BlockEligible = false
			event.DecisionExplanation.PrimaryEligibilityReason = eligibilityReasonNoCurrentDirective
			event.DecisionExplanation.EligibilityReasonFlags = eligibilityFlagNoCurrentDirective
			event.DecisionExplanation.CurrentExecutionActProven = false
			event.DecisionExplanation.HardFloorApplied = false
			event.DecisionExplanation.HardFloorReason = ""
		}},
		{name: "incomplete block carries malicious winner", mutate: func(event *Event) {
			event.DecisionKind = decisionKindBlockIncomplete
			event.Decision = "block_due_to_incomplete_inspection"
			event.Coverage = "incomplete"
			event.IncompleteReason = "scan_limit"
			event.Category = "scan_limit"
		}},
		{name: "opaque block carries malicious winner", mutate: func(event *Event) {
			event.DecisionKind = decisionKindBlockOpaqueMedia
			event.Decision = "block_opaque_media"
			event.Category = "opaque_media"
		}},
		{name: "subject block carries malicious winner", mutate: func(event *Event) {
			event.DecisionKind = decisionKindBlockSubjectRisk
			event.Decision = "block_subject_risk"
			event.Category = "subject_risk"
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			event := valid
			event.RuleIDs = append([]string(nil), valid.RuleIDs...)
			event.DecisionExplanation = cloneDecisionExplanation(valid.DecisionExplanation)
			test.mutate(&event)
			if err := validateEvent(event); err == nil {
				t.Fatalf("validateEvent accepted a contradictory Round9 decision: %#v", event)
			}
		})
	}
}

func TestRound9EligibleMaliciousAuditHasDistinctDecisionKind(t *testing.T) {
	t.Parallel()
	event := round9MaliciousBlockEventFixture()
	event.ID = "round9-malicious-audit"
	event.Action = "audit"
	event.Decision = "audit_malicious_text"
	event.DecisionKind = decisionKindAuditEligibleMaliciousText
	if err := validateEvent(event); err != nil {
		t.Fatalf("valid eligible malicious audit rejected: %v", err)
	}

	ineligibleKind := event
	ineligibleKind.DecisionExplanation = cloneDecisionExplanation(event.DecisionExplanation)
	ineligibleKind.DecisionKind = decisionKindAuditIneligibleRisk
	if err := validateEvent(ineligibleKind); err == nil {
		t.Fatal("audit_ineligible_risk accepted an eligible malicious explanation")
	}

	ineligibleExplanation := event
	ineligibleExplanation.DecisionExplanation = cloneDecisionExplanation(event.DecisionExplanation)
	ineligibleExplanation.DecisionExplanation.BlockEligible = false
	ineligibleExplanation.DecisionExplanation.PrimaryEligibilityReason = eligibilityReasonNoCurrentDirective
	ineligibleExplanation.DecisionExplanation.EligibilityReasonFlags = eligibilityFlagNoCurrentDirective
	ineligibleExplanation.DecisionExplanation.CurrentExecutionActProven = false
	if err := validateEvent(ineligibleExplanation); err == nil {
		t.Fatal("audit_eligible_malicious_text accepted an ineligible explanation")
	}
}

func TestRound9DecisionExplanationV2UnionRoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 23, 8, 0, 0, 0, time.UTC)
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "round9-union.db"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	malicious := round9MaliciousBlockEventFixture()
	malicious.ID = "round9-union-malicious"
	malicious.Timestamp = now
	incomplete := round9IndependentBlockEventFixture(
		"round9-union-incomplete", now.Add(time.Nanosecond),
		decisionKindBlockIncomplete, "block_due_to_incomplete_inspection", "scan_limit",
		&DecisionExplanation{Kind: decisionExplanationKindIncomplete, IncompleteInspectionReason: "scan_limit"},
	)
	opaque := round9IndependentBlockEventFixture(
		"round9-union-opaque", now.Add(2*time.Nanosecond),
		decisionKindBlockOpaqueMedia, "block_opaque_media", "opaque_media",
		&DecisionExplanation{Kind: decisionExplanationKindOpaque, OpaqueMediaReason: opaqueMediaExplanationReason},
	)
	subject := round9IndependentBlockEventFixture(
		"round9-union-subject", now.Add(3*time.Nanosecond),
		decisionKindBlockSubjectRisk, "block_subject_risk", "subject_risk",
		&DecisionExplanation{Kind: decisionExplanationKindSubject, SubjectRiskAction: "block"},
	)

	wants := []Event{malicious, incomplete, opaque, subject}
	for _, event := range wants {
		if !store.Record(event) {
			t.Fatalf("Record(%s) rejected a valid v2 union branch", event.ID)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, err := store.Query(context.Background(), Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != len(wants) {
		t.Fatalf("persisted union branches = %d, want %d", len(events), len(wants))
	}
	byID := make(map[string]Event, len(events))
	for _, event := range events {
		byID[event.ID] = event
	}
	for _, want := range wants {
		got, ok := byID[want.ID]
		if !ok {
			t.Fatalf("missing persisted union branch %s", want.ID)
		}
		if got.ExplanationSchema != DecisionExplanationSchemaV2 {
			t.Fatalf("%s explanation_schema=%q", want.ID, got.ExplanationSchema)
		}
		if !reflect.DeepEqual(got.DecisionExplanation, want.DecisionExplanation) {
			t.Fatalf("%s explanation=%#v, want %#v", want.ID, got.DecisionExplanation, want.DecisionExplanation)
		}
		encoded, err := marshalDecisionExplanationForSchema(got.DecisionExplanation, got.ExplanationSchema)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := decodeDecisionExplanationForSchema(encoded, got.ExplanationSchema)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded, want.DecisionExplanation) {
			t.Fatalf("%s JSON round trip=%#v, want %#v", want.ID, decoded, want.DecisionExplanation)
		}
	}
}

func TestRound9DecisionExplanationV2RejectsUnknownAndCrossBranchFields(t *testing.T) {
	t.Parallel()
	validMalicious, err := json.Marshal(round9EligibleDecisionExplanationFixture())
	if err != nil {
		t.Fatal(err)
	}
	maliciousCrossBranch := strings.TrimSuffix(string(validMalicious), "}") + `,"opaque_media_reason":"opaque_media_present"}`
	tests := []struct {
		name string
		json string
	}{
		{name: "unknown field", json: `{"kind":"incomplete","incomplete_inspection_reason":"scan_limit","future_metadata":"forbidden"}`},
		{name: "unknown kind", json: `{"kind":"future_decision","opaque_media_reason":"opaque_media_present"}`},
		{name: "incomplete carries malicious winner", json: `{"kind":"incomplete","incomplete_inspection_reason":"scan_limit","winning_rule_id":"EVADE-002"}`},
		{name: "opaque carries incomplete reason", json: `{"kind":"opaque_media","opaque_media_reason":"opaque_media_present","incomplete_inspection_reason":"scan_limit"}`},
		{name: "subject carries eligibility", json: `{"kind":"subject_risk","subject_risk_action":"block","block_eligible":true}`},
		{name: "malicious carries opaque reason", json: maliciousCrossBranch},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if _, err := decodeDecisionExplanationForSchema(test.json, DecisionExplanationSchemaV2); err == nil {
				t.Fatalf("v2 decoder accepted %s: %s", test.name, test.json)
			}
		})
	}
}

func TestRound9DecisionKindQueryStatsAndExports(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 23, 8, 30, 0, 0, time.UTC)
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "round9-query-export.db"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	incomplete := round9IndependentBlockEventFixture(
		"round9-query-incomplete", now, decisionKindBlockIncomplete,
		"block_unknown_source_format", "unknown_source_format",
		&DecisionExplanation{Kind: decisionExplanationKindIncomplete, IncompleteInspectionReason: "unknown_source_format"},
	)
	malicious := round9MaliciousBlockEventFixture()
	malicious.ID = "round9-query-malicious"
	malicious.Timestamp = now.Add(time.Nanosecond)
	for _, event := range []Event{incomplete, malicious} {
		if !store.Record(event) {
			t.Fatalf("Record(%s) failed", event.ID)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	query := Query{DecisionKind: decisionKindBlockIncomplete, Limit: 10}
	events, err := store.Query(context.Background(), query)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID != incomplete.ID ||
		events[0].Decision != "block_unknown_source_format" ||
		events[0].DecisionKind != decisionKindBlockIncomplete {
		t.Fatalf("decision_kind query = %#v", events)
	}
	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.ByDecisionKind[decisionKindBlockIncomplete] != 1 ||
		stats.ByDecisionKind[decisionKindBlockMaliciousText] != 1 {
		t.Fatalf("decision_kind stats = %#v", stats.ByDecisionKind)
	}

	var jsonExport bytes.Buffer
	if err := store.ExportJSON(context.Background(), &jsonExport, query); err != nil {
		t.Fatal(err)
	}
	var exportedEvents []Event
	if err := json.Unmarshal(jsonExport.Bytes(), &exportedEvents); err != nil {
		t.Fatal(err)
	}
	if len(exportedEvents) != 1 || exportedEvents[0].Decision != "block_unknown_source_format" ||
		exportedEvents[0].DecisionKind != decisionKindBlockIncomplete ||
		exportedEvents[0].ExplanationSchema != DecisionExplanationSchemaV2 {
		t.Fatalf("JSON export = %#v", exportedEvents)
	}

	var csvExport bytes.Buffer
	if err := store.ExportCSV(context.Background(), &csvExport, query); err != nil {
		t.Fatal(err)
	}
	records, err := csv.NewReader(bytes.NewReader(csvExport.Bytes())).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("CSV rows = %d, want header plus one event", len(records))
	}
	columns := make(map[string]int, len(records[0]))
	for index, name := range records[0] {
		columns[name] = index
	}
	for _, required := range []string{"decision", "decision_kind", "explanation_schema", "decision_explanation"} {
		if _, ok := columns[required]; !ok {
			t.Fatalf("CSV header missing %q: %v", required, records[0])
		}
	}
	row := records[1]
	if row[columns["decision"]] != "block_unknown_source_format" ||
		row[columns["decision_kind"]] != decisionKindBlockIncomplete ||
		row[columns["explanation_schema"]] != DecisionExplanationSchemaV2 ||
		!strings.Contains(row[columns["decision_explanation"]], `"kind":"incomplete"`) {
		t.Fatalf("CSV Round9 row = %v", row)
	}
}

func TestRound9StatsRejectsUnknownPersistedDecisionKind(t *testing.T) {
	t.Parallel()
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "round9-tampered-stats.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	event := round9MaliciousBlockEventFixture()
	event.ID = "round9-tampered-stats"
	if !store.Record(event) {
		t.Fatal("Record() failed")
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(
		context.Background(),
		"UPDATE audit_events SET decision = ? WHERE id = ?",
		"future_decision_kind_with_request_fragment",
		event.ID,
	); err != nil {
		t.Fatal(err)
	}

	stats, err := store.Stats(context.Background())
	if err == nil || !strings.Contains(err.Error(), "invalid persisted decision_kind") {
		t.Fatalf("Stats() error = %v, stats = %#v", err, stats)
	}
	if len(stats.ByDecisionKind) != 0 {
		t.Fatalf("Stats() exposed a tampered decision_kind: %#v", stats.ByDecisionKind)
	}
}

func TestRound9AuditRejectsRequestLikeTopLevelRuleID(t *testing.T) {
	t.Parallel()
	event := round9MaliciousBlockEventFixture()
	event.RuleIDs = append(event.RuleIDs, "Bearer token=synthetic-secret")
	if _, err := prepareEvent(event, time.Now().UTC()); err == nil || !strings.Contains(err.Error(), "invalid stable rule_id") {
		t.Fatalf("prepareEvent() error = %v", err)
	}
}

func TestRound9RawCaptureMetadataAndUnknownSourceBlockSurviveRestart(t *testing.T) {
	now := time.Date(2026, 7, 23, 9, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "round9-raw-capture.db")
	open := func() *Store {
		store, err := Open(Config{
			Path: path,
			Now:  func() time.Time { return now },
			RawCapture: RawCaptureConfig{
				Enabled:  true,
				MaxBytes: 8192,
				TTL:      72 * time.Hour,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return store
	}

	raw := []byte(`{"messages":[{"role":"user","content":"synthetic password is round9-secret"}]}`)
	event := round9IndependentBlockEventFixture(
		"round9-unknown-source", now, decisionKindBlockIncomplete,
		"block_unknown_source_format", "unknown_source_format", nil,
	)
	event.RequestHash = HashRequest(raw)
	store := open()
	accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
		RawRequest: raw,
	})
	if !accepted || err != nil {
		t.Fatalf("unknown-source event/capture accepted=%t err=%v", accepted, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store = open()
	defer store.Close()
	events, err := store.Query(context.Background(), Query{DecisionKind: decisionKindBlockIncomplete, Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Decision != "block_unknown_source_format" ||
		events[0].IncompleteReason != "unknown_source_format" ||
		events[0].ExplanationSchema != DecisionExplanationSchemaV2 ||
		events[0].DecisionExplanation == nil ||
		events[0].DecisionExplanation.Kind != decisionExplanationKindIncomplete ||
		events[0].DecisionExplanation.IncompleteInspectionReason != "unknown_source_format" {
		t.Fatalf("unknown-source event after restart = %#v", events)
	}
	captures, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{EventID: event.ID})
	if err != nil {
		t.Fatal(err)
	}
	if len(captures) != 1 || captures[0].Decision != "block_unknown_source_format" ||
		captures[0].DecisionKind != decisionKindBlockIncomplete ||
		captures[0].ExplanationSchema != DecisionExplanationSchemaV2 {
		t.Fatalf("unknown-source capture after restart = %#v", captures)
	}
	if strings.Contains(captures[0].RawPreview, "round9-secret") ||
		!strings.Contains(captures[0].RawPreview, "[REDACTED]") {
		t.Fatalf("raw capture redaction after restart = %q", captures[0].RawPreview)
	}
}

func TestRound9WALRestartQuickCheckAndOldSOSchemaGate(t *testing.T) {
	now := time.Date(2026, 7, 23, 9, 30, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "round9-wal-restart.db")
	store, err := Open(Config{Path: path, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	var journalMode string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("journal_mode=%q, want WAL", journalMode)
	}
	event := round9MaliciousBlockEventFixture()
	event.ID = "round9-wal-event"
	event.Timestamp = now
	if !store.Record(event) {
		t.Fatal("Record() failed")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	for restart := 0; restart < 2; restart++ {
		store, err = Open(Config{Path: path, Now: func() time.Time { return now.Add(time.Duration(restart+1) * time.Minute) }})
		if err != nil {
			t.Fatal(err)
		}
		var version int
		if err := store.db.QueryRow(`SELECT version FROM schema_version WHERE singleton = 1`).Scan(&version); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		var integrity string
		if err := store.db.QueryRow("PRAGMA quick_check").Scan(&integrity); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		events, err := store.Query(context.Background(), Query{DecisionKind: decisionKindBlockMaliciousText, Limit: 10})
		if err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
		if version != currentSchemaVersion || integrity != "ok" || len(events) != 1 || events[0].ID != event.ID {
			_ = store.Close()
			t.Fatalf("restart=%d version=%d quick_check=%q events=%#v", restart, version, integrity, events)
		}
		if err := rejectUnsupportedSchemaVersion(version, 5); err == nil ||
			!strings.Contains(err.Error(), "newer than supported version 5") {
			_ = store.Close()
			t.Fatalf("old SO schema gate error = %v", err)
		}
		if err := store.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func round9EligibleDecisionExplanationFixture() *DecisionExplanation {
	explanation := round8DecisionExplanationFixture()
	explanation.Kind = decisionExplanationKindMalicious
	explanation.BlockEligible = true
	explanation.PrimaryEligibilityReason = eligibilityReasonExplicitMalice
	explanation.EligibilityReasonFlags = eligibilityFlagExplicitMalice
	explanation.InspectionComplete = true
	explanation.EvidenceOwnedByCurrentUser = true
	explanation.EnforcementScope = EnforcementScopeCurrentUser
	explanation.CurrentExecutionActProven = true
	explanation.HarmfulCoreComplete = true
	explanation.OperationallyActionable = true
	explanation.AuthorizationClaimState = "absent"
	explanation.ReferentProofComplete = true
	return explanation
}

func round9IndependentBlockEventFixture(
	id string,
	timestamp time.Time,
	decisionKind string,
	disposition string,
	category string,
	explanation *DecisionExplanation,
) Event {
	event := testEvent(id, timestamp)
	event.Action = "block"
	event.Category = category
	event.RiskScore = 0
	event.RuleIDs = nil
	event.Decision = disposition
	event.DecisionKind = decisionKind
	event.Coverage = "complete"
	event.Scanner = "streaming-scanner-v1"
	event.ExplanationSchema = DecisionExplanationSchemaV2
	event.DecisionExplanation = explanation
	if decisionKind == decisionKindBlockIncomplete {
		event.Coverage = "incomplete"
		event.IncompleteReason = category
	}
	return event
}

func round9MaliciousBlockEventFixture() Event {
	event := testEvent("round9-malicious-block", fixedMigrationTime())
	event.Action = "block"
	event.Category = "defense_evasion"
	event.RiskScore = 90
	event.RuleIDs = []string{"EVADE-002"}
	event.Model = HashModel(event.Model)
	event.Decision = "block_malicious_text"
	event.DecisionKind = decisionKindBlockMaliciousText
	event.Coverage = "complete"
	event.Scanner = "streaming-scanner-v1"
	event.DecisionExplanation = round9EligibleDecisionExplanationFixture()
	return event
}

func createRound9V5Database(t testing.TB, path string, includeEvent bool) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(schema + subjectStateSchema + round6AuditEventColumns + rawRequestCaptureSchema + migrationMetadataSchema + round8AuditSchema + round8RawCaptureDedupIndex); err != nil {
		t.Fatal(err)
	}
	nowNS := fixedMigrationTime().UnixNano()
	if _, err := db.Exec(`INSERT INTO schema_version(singleton, version, updated_at_ns) VALUES(1, 5, ?)`, nowNS); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 5; version++ {
		if _, err := db.Exec(`INSERT INTO migration_history(version, applied_at_ns, description) VALUES(?, ?, 'round9-v5-fixture')`, version, nowNS); err != nil {
			t.Fatal(err)
		}
	}
	if !includeEvent {
		return
	}
	explanation, err := json.Marshal(legacyDecisionExplanationFromCurrent(round8DecisionExplanationFixture()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO audit_events (
id, timestamp_ns, action, mode, category, risk_score, rule_ids,
request_hash, subject_hash, model, source_format, stream, text_bytes_scanned,
classifier, latency_us, decision, coverage, incomplete_reason, scanner,
decision_explanation
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"round9-v5-event", fixedMigrationTime().UnixNano(), "block", "balanced",
		"defense_evasion", 90, `["EVADE-002"]`, HashRequest([]byte("round9-v5-request")),
		testSubjectHash("round9-v5-subject"), HashModel("round9-v5-model"), "openai", 0,
		128, "round8-v5-rules", 25, "block_malicious_text", "complete", "",
		"streaming-scanner-v1", string(explanation),
	); err != nil {
		t.Fatal(err)
	}
}

func insertRound9V5RawCapture(t testing.TB, path string) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO raw_request_captures (
id, event_id, timestamp_ns, request_hash, subject_hash, action, decision,
truncated, redacted, raw_preview, raw_sha256, redaction_pattern_hits, redaction_version
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		"round9-v5-capture", "round9-v5-event", fixedMigrationTime().UnixNano(),
		HashRequest([]byte("round9-v5-request")), testSubjectHash("round9-v5-subject"),
		"block", "block_malicious_text", 0, 0, "round9-v5-synthetic-preview",
		"sha256:"+strings.Repeat("a", 64), 0, rawCaptureRedactionVersion,
	); err != nil {
		t.Fatal(err)
	}
}

// Keep the compiler honest if the fixed migration clock changes type or is
// moved while this compatibility fixture remains in the audit package.
var _ func() time.Time = fixedMigrationTime
