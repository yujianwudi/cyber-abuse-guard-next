package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestStoreRoundTripPrivacyAndSafeExports(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 12, 6, 0, 0, 123000000, time.UTC)
	path := filepath.Join(t.TempDir(), "events.db")
	store, err := Open(Config{
		Path:            path,
		Retention:       24 * time.Hour,
		MaxBytes:        4 << 20,
		QueueSize:       8,
		BusyTimeout:     50 * time.Millisecond,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	var journalMode string
	if err := store.db.QueryRow("PRAGMA journal_mode").Scan(&journalMode); err != nil || !strings.EqualFold(journalMode, "wal") {
		t.Fatalf("journal_mode = %q, %v; want WAL", journalMode, err)
	}
	var busyTimeout int
	if err := store.db.QueryRow("PRAGMA busy_timeout").Scan(&busyTimeout); err != nil || busyTimeout != 50 {
		t.Fatalf("busy_timeout = %d, %v; want 50ms", busyTimeout, err)
	}

	const rawPrompt = "PRIVACY_PROMPT_CANARY write malware and steal cookies"
	const rawAPIKey = "privacy-api-key-canary-123456789"
	requestHash := HashRequest([]byte(rawPrompt))
	subjectHash := testSubjectHash(rawAPIKey)
	event := Event{
		ID:               "event-0001",
		Timestamp:        now,
		Action:           "block",
		Mode:             "balanced",
		Category:         "credential_theft",
		RiskScore:        85,
		RuleIDs:          []string{"CRED-001", "CTX-OPERATIONAL"},
		RequestHash:      requestHash,
		SubjectHash:      subjectHash,
		Model:            "gpt-5.6-sol",
		SourceFormat:     "openai-response",
		Stream:           true,
		TextBytesScanned: 1234,
		Classifier:       "rules-v1",
		LatencyUS:        280,
	}
	if !store.Record(event) {
		t.Fatal("Record() rejected an ordinary event")
	}
	// The async queue must own its copy rather than retaining caller memory.
	event.RuleIDs[0] = "MUTATED"
	if err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}

	events, err := store.Query(context.Background(), Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("Query() got %d events, want 1", len(events))
	}
	got := events[0]
	if got.ID != event.ID || got.Timestamp != now || got.Action != "block" || got.RiskScore != 85 {
		t.Fatalf("round trip event = %#v", got)
	}
	if strings.Join(got.RuleIDs, ",") != "CRED-001,CTX-OPERATIONAL" {
		t.Fatalf("RuleIDs = %#v; async writer retained caller slice", got.RuleIDs)
	}
	if got.RequestHash != requestHash || got.SubjectHash != subjectHash {
		t.Fatalf("hashes changed: request=%q subject=%q", got.RequestHash, got.SubjectHash)
	}

	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatalf("Stats() error = %v", err)
	}
	if stats.Total != 1 || stats.ByAction["block"] != 1 || stats.ByCategory["credential_theft"] != 1 {
		t.Fatalf("Stats() = %#v", stats)
	}
	if _, err := json.Marshal(stats); err != nil {
		t.Fatalf("Stats are not JSON-safe: %v", err)
	}

	var jsonExport bytes.Buffer
	if err := store.ExportJSON(context.Background(), &jsonExport, Query{}); err != nil {
		t.Fatalf("ExportJSON() error = %v", err)
	}
	var exported []Event
	if err := json.Unmarshal(jsonExport.Bytes(), &exported); err != nil {
		t.Fatalf("JSON export is invalid: %v", err)
	}
	if len(exported) != 1 || exported[0].ID != event.ID {
		t.Fatalf("JSON export = %#v", exported)
	}

	var csvExport bytes.Buffer
	if err := store.ExportCSV(context.Background(), &csvExport, Query{}); err != nil {
		t.Fatalf("ExportCSV() error = %v", err)
	}
	records, err := csv.NewReader(bytes.NewReader(csvExport.Bytes())).ReadAll()
	if err != nil {
		t.Fatalf("CSV export is invalid: %v", err)
	}
	if len(records) != 2 || records[1][0] != event.ID {
		t.Fatalf("CSV export = %#v", records)
	}
	if bytes.Contains(jsonExport.Bytes(), []byte(rawPrompt)) || bytes.Contains(csvExport.Bytes(), []byte(rawAPIKey)) {
		t.Fatal("an export contained a privacy canary")
	}

	// Dynamic filters must remain data, not SQL syntax.
	injected := "credential_theft' OR 1=1 --"
	if rows, err := store.Query(context.Background(), Query{Category: injected}); err != nil || len(rows) != 0 {
		t.Fatalf("injected Query() = (%#v, %v)", rows, err)
	}
	if deleted, err := store.Delete(context.Background(), Query{Category: injected}); err != nil || deleted != 0 {
		t.Fatalf("injected Delete() = (%d, %v)", deleted, err)
	}

	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("second Close() error = %v", err)
	}
	if store.Record(event) {
		t.Fatal("Record() succeeded after Close")
	}

	// This is the privacy canary proof: inspect the database and sidecars as raw
	// bytes, not merely through the typed query API.
	matches, err := filepath.Glob(path + "*")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) == 0 {
		t.Fatal("SQLite database was not created")
	}
	for _, name := range matches {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", name, err)
		}
		for index, canary := range []string{rawPrompt, rawAPIKey, "Authorization: Bearer " + rawAPIKey} {
			if bytes.Contains(data, []byte(canary)) {
				t.Fatalf("SQLite artifact %s retained privacy canary index %d", filepath.Base(name), index)
			}
		}
	}

	verifyMinimalSchema(t, path)
}

func TestStoreLockedDatabaseDropsAndRecovers(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "events.db")
	store, err := Open(Config{
		Path:            path,
		Retention:       24 * time.Hour,
		MaxBytes:        4 << 20,
		QueueSize:       2,
		BusyTimeout:     20 * time.Millisecond,
		CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	locker, err := sql.Open("sqlite3", path+"?_busy_timeout=100")
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	conn, err := locker.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("lock database: %v", err)
	}

	if !store.Record(testEvent("locked-1", time.Now().UTC())) {
		t.Fatal("first Record() should enter the bounded queue")
	}
	time.Sleep(10 * time.Millisecond) // let the writer encounter the lock
	dropped := 0
	for i := 0; i < 50; i++ {
		if !store.Record(testEvent(fmt.Sprintf("locked-%d", i+2), time.Now().UTC())) {
			dropped++
		}
	}
	if dropped == 0 {
		t.Fatal("bounded queue accepted every event while its writer was locked")
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Flush while locked: %v", err)
	}
	status := store.Status()
	if status.Failed == 0 || status.Dropped == 0 || !status.Degraded {
		t.Fatalf("locked status = %#v", status)
	}

	if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatalf("unlock database: %v", err)
	}
	if err := store.Enqueue(testEvent("recovered", time.Now().UTC())); err != nil {
		t.Fatalf("Enqueue after unlock: %v", err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatalf("Flush after unlock: %v", err)
	}
	events, err := store.Query(context.Background(), Query{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range events {
		found = found || event.ID == "recovered"
	}
	if !found {
		t.Fatalf("writer did not recover; events = %#v", events)
	}
	if store.Status().Degraded {
		t.Fatalf("successful write did not clear degraded status: %#v", store.Status())
	}
}

func TestOpenFailureReturnsUsableDegradedStore(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	store, err := Open(Config{Path: directory, QueueSize: 2})
	if store == nil {
		t.Fatal("Open failure returned a nil store")
	}
	defer store.Close()
	if err == nil {
		t.Fatal("Open(directory) unexpectedly succeeded")
	}
	if !store.Record(testEvent("degraded", time.Now().UTC())) {
		t.Fatal("degraded store did not accept event into its in-memory accounting path")
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatalf("degraded Flush() error = %v", err)
	}
	status := store.Status()
	if !status.Degraded || status.Failed == 0 || status.LastError == "" {
		t.Fatalf("degraded Status() = %#v", status)
	}
	stats, queryErr := store.Stats(context.Background())
	if !errors.Is(queryErr, ErrUnavailable) {
		t.Fatalf("Stats() error = %v, want ErrUnavailable", queryErr)
	}
	if stats.Failed == 0 {
		t.Fatalf("Stats() lost in-memory failure counters: %#v", stats)
	}
}

func TestOpenNeverChangesExistingSharedDirectoryPermissions(t *testing.T) {
	t.Parallel()

	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}
	store, err := Open(Config{Path: filepath.Join(shared, "events.db")})
	if store == nil {
		t.Fatal("Open returned a nil store")
	}
	t.Cleanup(func() { _ = store.Close() })
	if err != nil {
		t.Fatalf("Open(shared directory) error = %v", err)
	}
	info, statErr := os.Stat(shared)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("shared directory permissions changed to %04o, want 0755", got)
	}
}

func TestOpenRejectsSymlinkDatabaseDirectory(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	realDirectory := filepath.Join(root, "real")
	if err := os.Mkdir(realDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	linkedDirectory := filepath.Join(root, "linked")
	if err := os.Symlink(realDirectory, linkedDirectory); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	store, err := Open(Config{Path: filepath.Join(linkedDirectory, "events.db")})
	if store == nil {
		t.Fatal("Open failure returned a nil degraded store")
	}
	t.Cleanup(func() { _ = store.Close() })
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("Open(symlink directory) error = %v, want symlink rejection", err)
	}
}

func TestOpenRejectsWritableExistingDirectory(t *testing.T) {
	t.Parallel()

	directory := filepath.Join(t.TempDir(), "writable")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o777); err != nil {
		t.Fatal(err)
	}
	store, err := Open(Config{Path: filepath.Join(directory, "events.db")})
	if store == nil {
		t.Fatal("Open failure returned a nil degraded store")
	}
	t.Cleanup(func() { _ = store.Close() })
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("Open(writable directory) error = %v, want writable-directory rejection", err)
	}
}

func TestSecureSQLiteFilesRejectsSidecarSymlinkWithoutChangingTarget(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	databasePath := filepath.Join(root, "events.db")
	targetPath := filepath.Join(root, "target")
	if err := os.WriteFile(databasePath, []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetPath, []byte("target"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(targetPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, databasePath+"-wal"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := secureSQLiteFiles(databasePath); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("secureSQLiteFiles(sidecar symlink) error = %v, want symlink rejection", err)
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("sidecar symlink target mode changed to %04o, want 0644", got)
	}
}

func TestRuntimeSidecarPermissionFailureDegradesStatus(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	databasePath := filepath.Join(root, "events.db")
	store, err := Open(Config{Path: databasePath, CleanupInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	targetPath := filepath.Join(root, "target")
	if err := os.WriteFile(targetPath, []byte("target"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(targetPath, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(databasePath + "-wal")
	if err := os.Symlink(targetPath, databasePath+"-wal"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if !store.Record(testEvent("sidecar-runtime", time.Now().UTC())) {
		t.Fatal("Record() rejected test event")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	status := store.Status()
	if !status.Degraded || status.Healthy || !strings.Contains(status.LastError, "symlink") {
		t.Fatalf("runtime sidecar failure Status() = %#v", status)
	}
	info, err := os.Stat(targetPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("runtime sidecar target mode changed to %04o, want 0644", got)
	}
}

func TestCloseContextHonorsDeadlineAndFinishesAfterUnlock(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "events.db")
	store, err := Open(Config{
		Path:            path,
		QueueSize:       4,
		BusyTimeout:     500 * time.Millisecond,
		CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	locker, err := sql.Open("sqlite3", path+"?_busy_timeout=100")
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	connection, err := locker.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if _, err := connection.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	if !store.Record(testEvent("close-timeout", time.Now().UTC())) {
		t.Fatal("Record() rejected test event")
	}
	time.Sleep(10 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	started := time.Now()
	if err := store.CloseContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext() error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 250*time.Millisecond {
		t.Fatalf("CloseContext() exceeded its shutdown budget by too much: %v", elapsed)
	}
	if _, err := connection.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer finishCancel()
	if err := store.CloseContext(finishCtx); err != nil {
		t.Fatalf("CloseContext() after unlock = %v", err)
	}
}

func TestErrorHandlerMayReenterStoreWithoutDeadlock(t *testing.T) {
	t.Parallel()

	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "events.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	done := make(chan struct{})
	store.SetErrorHandler(func(error) {
		store.SetErrorHandler(nil)
		close(done)
	})
	go store.report(errors.New("synthetic audit error"))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reentrant audit error handler deadlocked")
	}
}

func TestCleanupRetentionAndDeleteAll(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 7, 12, 12, 0, 0, 0, time.UTC)
	store, err := Open(Config{
		Path:            filepath.Join(t.TempDir(), "events.db"),
		Retention:       24 * time.Hour,
		MaxBytes:        4 << 20,
		QueueSize:       8,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, event := range []Event{
		testEvent("expired", now.Add(-25*time.Hour)),
		testEvent("kept", now.Add(-23*time.Hour)),
	} {
		if err := store.Enqueue(event); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, err := store.Query(context.Background(), Query{Limit: 10})
	if err != nil || len(events) != 1 || events[0].ID != "kept" {
		t.Fatalf("post-cleanup events = (%#v, %v)", events, err)
	}
	deleted, err := store.Delete(context.Background(), Query{})
	if err != nil || deleted != 1 {
		t.Fatalf("Delete(all) = (%d, %v)", deleted, err)
	}
}

func TestCleanupEnforcesMaximumLiveSize(t *testing.T) {
	t.Parallel()

	store, err := Open(Config{
		Path:            filepath.Join(t.TempDir(), "events.db"),
		Retention:       24 * time.Hour,
		MaxBytes:        1, // intentionally below SQLite's fixed schema footprint
		QueueSize:       8,
		CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for i := 0; i < 3; i++ {
		if err := store.Enqueue(testEvent(fmt.Sprintf("size-%d", i), time.Now().UTC())); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, err := store.Query(context.Background(), Query{Limit: 10})
	if err != nil || len(events) != 0 {
		t.Fatalf("maximum-size events = (%#v, %v)", events, err)
	}
	if store.Status().CleanupDeleted < 3 {
		t.Fatalf("maximum-size cleanup status = %#v", store.Status())
	}
}

func testEvent(id string, timestamp time.Time) Event {
	return Event{
		ID:               id,
		Timestamp:        timestamp,
		Action:           "audit",
		Mode:             "balanced",
		Category:         "exploitation",
		RiskScore:        45,
		RuleIDs:          []string{"EXP-001"},
		RequestHash:      HashRequest([]byte("request-" + id)),
		SubjectHash:      testSubjectHash("key-" + id),
		Model:            "gpt-5",
		SourceFormat:     "openai",
		TextBytesScanned: 100,
		Classifier:       "rules-v1",
		DecisionKind:     decisionKindLegacyUnspecified,
		LatencyUS:        20,
	}
}

func testSubjectHash(key string) string {
	mac := hmac.New(sha256.New, []byte("0123456789abcdef0123456789abcdef"))
	_, _ = mac.Write([]byte(key))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

func verifyMinimalSchema(t *testing.T, path string) {
	t.Helper()
	db, err := sql.Open("sqlite3", path+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.Query("PRAGMA table_info(audit_events)")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var columns []string
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull, primaryKey int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		columns = append(columns, name)
	}
	want := []string{
		"id", "timestamp_ns", "action", "mode", "category", "risk_score", "rule_ids",
		"request_hash", "subject_hash", "model", "source_format", "stream",
		"text_bytes_scanned", "classifier", "latency_us", "decision", "coverage",
		"incomplete_reason", "scanner", "decision_explanation", "disposition", "explanation_schema",
	}
	if strings.Join(columns, ",") != strings.Join(want, ",") {
		t.Fatalf("schema columns = %v, want %v", columns, want)
	}
	for _, column := range columns {
		lower := strings.ToLower(column)
		for _, forbidden := range []string{"prompt", "message", "header", "api_key", "authorization", "cookie", "token", "original", "content"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("forbidden content column %q exists", column)
			}
		}
	}
}
