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
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
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

func TestQueuedEventRechecksStorageGateBeforeSQLiteWrite(t *testing.T) {
	workerEntered := make(chan struct{})
	releaseWorker := make(chan struct{})
	var calls atomic.Uint64
	var blocked atomic.Bool
	store, err := Open(Config{
		Path:      filepath.Join(t.TempDir(), "queued-gate.db"),
		QueueSize: 4,
		StorageAccessGate: func() error {
			if calls.Add(1) == 2 {
				close(workerEntered)
				<-releaseWorker
			}
			if blocked.Load() {
				return errors.New("test storage replacement")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Discard() })
	if err := store.Enqueue(testEvent("queued-before-storage-failure", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	select {
	case <-workerEntered:
	case <-time.After(5 * time.Second):
		close(releaseWorker)
		t.Fatal("writer did not reach its second storage-gate check")
	}
	blocked.Store(true)
	close(releaseWorker)
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, err := store.Query(context.Background(), Query{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 0 || store.Status().Failed == 0 {
		t.Fatalf("queued write crossed latched gate: events=%#v status=%#v", events, store.Status())
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

func TestRequiredPersistentOpenDoesNotCreateMissingOperatorDirectory(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "operator-volume", "audit")
	store, err := Open(Config{
		Path:                     filepath.Join(directory, "events.db"),
		RequirePersistentStorage: true,
	})
	if store == nil {
		t.Fatal("required Open failure returned a nil degraded store")
	}
	t.Cleanup(func() { _ = store.Close() })
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("required missing-directory Open error=%v", err)
	}
	if _, statErr := os.Lstat(directory); !os.IsNotExist(statErr) {
		t.Fatalf("required Open created operator directory: %v", statErr)
	}
}

func TestRequiredPersistentOpenRejectsUnsafeDatabaseModeWithoutChmod(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix mode contract is Linux-only")
	}
	directory := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "events.db")
	if err := os.WriteFile(databasePath, []byte("operator-owned"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(databasePath, 0o644); err != nil {
		t.Fatal(err)
	}
	store, err := Open(Config{Path: databasePath, RequirePersistentStorage: true})
	if store == nil {
		t.Fatal("unsafe-mode Open returned a nil degraded store")
	}
	t.Cleanup(func() { _ = store.Close() })
	if err == nil || !strings.Contains(err.Error(), "unsafe permissions") {
		t.Fatalf("unsafe existing database mode error=%v", err)
	}
	info, statErr := os.Stat(databasePath)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("required Open chmod-repaired operator database to %04o", got)
	}
}

func TestMutationFreeCandidateRejectsUnsafeModeAndMissingDirectoryBeforeSQLiteOpen(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix mode contract is Linux-only")
	}
	t.Run("unsafe existing mode", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "events.db")
		seed, err := Open(Config{Path: path, CleanupInterval: time.Hour})
		if err != nil {
			t.Fatalf("seed database: %v", err)
		}
		if err := seed.Close(); err != nil {
			t.Fatalf("close seed database: %v", err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		postOpenCalls := 0
		candidate, openErr := Open(Config{
			Path:                   path,
			SkipAllStartupMutation: true,
			StoragePostOpenBind: func() error {
				postOpenCalls++
				return nil
			},
		})
		if candidate == nil {
			t.Fatal("unsafe mutation-free candidate returned a nil degraded Store")
		}
		t.Cleanup(func() { _ = candidate.Discard() })
		if openErr == nil || !strings.Contains(openErr.Error(), "unsafe permissions") {
			t.Fatalf("mutation-free unsafe-mode error=%v", openErr)
		}
		if postOpenCalls != 0 || candidate.DatabaseAvailable() {
			t.Fatalf(
				"unsafe candidate reached SQLite open: postOpenCalls=%d databaseAvailable=%t",
				postOpenCalls,
				candidate.DatabaseAvailable(),
			)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o644 {
			t.Fatalf("mutation-free candidate changed database mode to %04o", got)
		}
	})

	t.Run("missing directory", func(t *testing.T) {
		directory := filepath.Join(t.TempDir(), "missing", "audit")
		candidate, openErr := Open(Config{
			Path:                   filepath.Join(directory, "events.db"),
			SkipAllStartupMutation: true,
		})
		if candidate == nil {
			t.Fatal("missing-directory candidate returned a nil degraded Store")
		}
		t.Cleanup(func() { _ = candidate.Discard() })
		if openErr == nil || !strings.Contains(openErr.Error(), "does not exist") {
			t.Fatalf("mutation-free missing-directory error=%v", openErr)
		}
		if _, err := os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("mutation-free candidate created a directory: %v", err)
		}
	})
}

func TestRequiredPersistentOpenCreatesPrivateSQLiteArtifacts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Unix mode contract is Linux-only")
	}
	directory := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "events.db")
	store, err := Open(Config{Path: databasePath, RequirePersistentStorage: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if !store.Record(testEvent("secure-artifacts", time.Now().UTC())) {
		t.Fatal("Record was rejected")
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{databasePath, databasePath + "-wal", databasePath + "-shm"} {
		info, statErr := os.Stat(path)
		if os.IsNotExist(statErr) {
			continue
		}
		if statErr != nil {
			t.Fatal(statErr)
		}
		if got := info.Mode().Perm(); got&0o077 != 0 {
			t.Fatalf("new SQLite artifact %s mode=%04o, want private", filepath.Base(path), got)
		}
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
	if err := secureSQLiteFiles(databasePath, true); err == nil || !strings.Contains(err.Error(), "symlink") {
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

func TestOpenRejectsSidecarSymlinkBeforeSQLiteConnect(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	databasePath := filepath.Join(root, "events.db")
	targetPath := filepath.Join(root, "target")
	original := []byte("must-survive")
	if err := os.WriteFile(targetPath, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetPath, databasePath+"-wal"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	store, err := Open(Config{Path: databasePath})
	if store == nil {
		t.Fatal("Open failure returned a nil degraded store")
	}
	t.Cleanup(func() { _ = store.Close() })
	if err == nil || !strings.Contains(err.Error(), "WAL") {
		t.Fatalf("Open(sidecar symlink) error=%v", err)
	}
	got, readErr := os.ReadFile(targetPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(got, original) {
		t.Fatalf("sidecar target changed before rejection: %q", got)
	}
}

func TestOpenRejectsDatabaseWhenQuickCheckIsNotExactlyOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quick-check-corrupt.db")
	store, err := Open(Config{Path: path})
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
	if _, err := db.Exec(`CREATE TABLE quick_check_canary (value BLOB NOT NULL)`); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	for range 64 {
		if _, err := db.Exec(`INSERT INTO quick_check_canary(value) VALUES(zeroblob(2048))`); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	var rootPage, pageSize int64
	if err := db.QueryRow(`SELECT rootpage FROM sqlite_master WHERE name = 'quick_check_canary'`).Scan(&rootPage); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if rootPage <= 1 || pageSize <= 0 {
		t.Fatalf("unexpected canary root page/page size: %d/%d", rootPage, pageSize)
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0xff}, (rootPage-1)*pageSize); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}

	degraded, openErr := Open(Config{Path: path})
	if degraded == nil {
		t.Fatal("corrupt Open returned a nil degraded store")
	}
	t.Cleanup(func() { _ = degraded.Close() })
	if openErr == nil || !strings.Contains(openErr.Error(), "quick_check") {
		t.Fatalf("corrupt Open error=%v, want quick_check rejection", openErr)
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

func TestQuiesceDrainsAcceptedWorkAndLeavesDatabaseOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quiesce-clean.db")
	store, err := Open(Config{
		Path:            path,
		QueueSize:       4,
		CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Discard() })
	for _, id := range []string{"quiesce-one", "quiesce-two"} {
		if err := store.Enqueue(testEvent(id, time.Now().UTC())); err != nil {
			t.Fatalf("enqueue %s: %v", id, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := store.QuiesceContext(ctx); err != nil {
		t.Fatalf("QuiesceContext: %v", err)
	}
	status := store.Status()
	if !status.Closed || status.QueueDepth != 0 || status.Enqueued != 2 || status.Written != 2 ||
		status.Dropped != 0 || !store.DatabaseAvailable() {
		t.Fatalf("quiesced Store status=%#v databaseAvailable=%t", status, store.DatabaseAvailable())
	}
	select {
	case <-store.workerCtx.Done():
	default:
		t.Fatal("quiesce returned before the worker and maintenance ticker stopped")
	}
	if err := store.Enqueue(testEvent("after-quiesce", time.Now().UTC())); !errors.Is(err, ErrClosed) {
		t.Fatalf("post-quiesce admission error=%v, want ErrClosed", err)
	}
	var persisted int
	if err := store.db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM audit_events WHERE id IN (?, ?)`, "quiesce-one", "quiesce-two").Scan(&persisted); err != nil {
		t.Fatalf("query quiesced open database: %v", err)
	}
	if persisted != 2 {
		t.Fatalf("quiesced persisted events=%d, want 2", persisted)
	}
	if err := store.CloseContext(ctx); err != nil {
		t.Fatalf("close quiesced Store: %v", err)
	}
	if store.DatabaseAvailable() {
		t.Fatal("CloseContext left quiesced database open")
	}
}

func TestQuiesceContextDeadlineContinuesDrainWithoutDroppingAcceptedWork(t *testing.T) {
	path := filepath.Join(t.TempDir(), "quiesce-timeout.db")
	workerAtGate := make(chan struct{})
	releaseWorker := make(chan struct{})
	var releaseOnce sync.Once
	var intercept atomic.Bool
	var accessCalls atomic.Int32
	storageGate := func() error {
		if !intercept.Load() {
			return nil
		}
		switch accessCalls.Add(1) {
		case 1:
			return nil
		case 2:
			close(workerAtGate)
			<-releaseWorker
			return nil
		default:
			return nil
		}
	}
	store, err := Open(Config{
		Path:              path,
		QueueSize:         4,
		CleanupInterval:   time.Hour,
		StorageAccessGate: storageGate,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseWorker) })
		_ = store.Discard()
	})
	intercept.Store(true)
	if err := store.Enqueue(testEvent("quiesce-timeout", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	select {
	case <-workerAtGate:
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not reach the quiesce timeout gate")
	}

	timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer timeoutCancel()
	if err := store.QuiesceContext(timeoutCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("QuiesceContext error=%v, want deadline exceeded", err)
	}
	status := store.Status()
	if !status.Closed || status.Enqueued != 1 || status.Written != 0 || status.Dropped != 0 ||
		!store.DatabaseAvailable() {
		t.Fatalf("timed-out quiesce status=%#v databaseAvailable=%t", status, store.DatabaseAvailable())
	}

	const waiters = 4
	waiterResults := make(chan error, waiters)
	for range waiters {
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			waiterResults <- store.QuiesceContext(ctx)
		}()
	}
	select {
	case err := <-waiterResults:
		t.Fatalf("concurrent QuiesceContext returned before drain release: %v", err)
	default:
	}
	discardCtx, discardCancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	if err := store.DiscardContext(discardCtx); !errors.Is(err, context.DeadlineExceeded) {
		discardCancel()
		t.Fatalf("DiscardContext during timed-out quiesce error=%v, want deadline exceeded", err)
	}
	discardCancel()
	releaseOnce.Do(func() { close(releaseWorker) })
	for range waiters {
		if err := <-waiterResults; err != nil {
			t.Fatalf("concurrent QuiesceContext after release: %v", err)
		}
	}
	finishCtx, finishCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer finishCancel()
	if err := store.DiscardContext(finishCtx); err != nil {
		t.Fatalf("finish DiscardContext after quiesce timeout: %v", err)
	}
	status = store.Status()
	if status.Written != 1 || status.Dropped != 0 || status.QueueDepth != 0 || store.DatabaseAvailable() {
		t.Fatalf("completed background quiesce status=%#v databaseAvailable=%t", status, store.DatabaseAvailable())
	}
}

func TestQuiesceWaitsForInFlightMaintenanceBeforeReturning(t *testing.T) {
	maintenanceAtGate := make(chan struct{})
	releaseMaintenance := make(chan struct{})
	var releaseOnce sync.Once
	var intercept atomic.Bool
	var maintenanceCalls atomic.Int32
	storageFailure := errors.New("synthetic maintenance storage latch")
	storageGate := func() error {
		if !intercept.Load() {
			return nil
		}
		if maintenanceCalls.Add(1) == 1 {
			close(maintenanceAtGate)
			<-releaseMaintenance
			return storageFailure
		}
		return storageFailure
	}
	store, err := Open(Config{
		Path:              filepath.Join(t.TempDir(), "quiesce-maintenance.db"),
		QueueSize:         4,
		CleanupInterval:   time.Millisecond,
		StorageAccessGate: storageGate,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseMaintenance) })
		_ = store.Discard()
	})
	intercept.Store(true)
	select {
	case <-maintenanceAtGate:
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance ticker did not reach its storage gate")
	}

	quiesceDone := make(chan error, 1)
	go func() { quiesceDone <- store.QuiesceContext(context.Background()) }()
	deadline := time.Now().Add(5 * time.Second)
	for !store.closedState.Load() && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if !store.closedState.Load() {
		t.Fatal("quiesce did not publish the terminal admission state")
	}
	select {
	case err := <-quiesceDone:
		t.Fatalf("quiesce returned before in-flight maintenance finished: %v", err)
	default:
	}
	releaseOnce.Do(func() { close(releaseMaintenance) })
	select {
	case err := <-quiesceDone:
		if err != nil {
			t.Fatalf("quiesce after maintenance release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("quiesce did not finish after maintenance release")
	}
	select {
	case <-store.workerCtx.Done():
	default:
		t.Fatal("quiesce returned while maintenance worker remained live")
	}
	if maintenanceCalls.Load() < 1 {
		t.Fatalf("maintenance gate calls=%d, want at least the in-flight tick", maintenanceCalls.Load())
	}
	if err := store.Discard(); err != nil {
		t.Fatalf("discard quiesced maintenance failure: %v", err)
	}
}

func TestQuiesceWaitsForConcurrentActivateBeforeReturning(t *testing.T) {
	store, err := Open(Config{
		Path:                        filepath.Join(t.TempDir(), "quiesce-activate.db"),
		SkipAllStartupMutation:      true,
		AllowDeferredDatabaseCreate: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	activationPublished := make(chan struct{})
	releaseActivation := make(chan struct{})
	var releaseOnce sync.Once
	store.activationBeforeWorkerStartHook = func() {
		close(activationPublished)
		<-releaseActivation
	}
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseActivation) })
		_ = store.Discard()
	})

	activationDone := make(chan error, 1)
	go func() { activationDone <- store.Activate(context.Background()) }()
	select {
	case <-activationPublished:
	case <-time.After(5 * time.Second):
		t.Fatal("Activate did not reach the worker publication boundary")
	}
	quiesceDone := make(chan error, 1)
	go func() { quiesceDone <- store.QuiesceContext(context.Background()) }()
	deadline := time.Now().Add(5 * time.Second)
	for !store.closedState.Load() && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if !store.closedState.Load() {
		t.Fatal("Quiesce did not publish closed admission during Activate")
	}
	select {
	case err := <-quiesceDone:
		t.Fatalf("Quiesce returned before Activate released activateMu: %v", err)
	default:
	}
	releaseOnce.Do(func() { close(releaseActivation) })
	select {
	case err := <-activationDone:
		if !errors.Is(err, ErrClosed) {
			t.Fatalf("Activate error=%v, want ErrClosed", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Activate did not finish after release")
	}
	select {
	case err := <-quiesceDone:
		if err != nil {
			t.Fatalf("Quiesce after Activate release: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Quiesce did not finish after Activate release")
	}
	if !store.DatabaseAvailable() || store.IsActive() {
		t.Fatalf("quiesced activation databaseAvailable=%t active=%t",
			store.DatabaseAvailable(), store.IsActive())
	}
}

func TestDiscardAfterQuiesceKeepsNoCheckpointModeStable(t *testing.T) {
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "quiesce-discard-mode.db")})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Quiesce(); err != nil {
		t.Fatalf("Quiesce: %v", err)
	}
	// A normal Close would report a checkpoint query failure on this closed
	// pool. Discard must linearize no-checkpoint mode, and later Close callers
	// must observe that same terminal result rather than changing modes.
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.Discard(); err != nil {
		t.Fatalf("Discard after Quiesce attempted checkpoint: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close changed the first terminal no-checkpoint mode: %v", err)
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

func TestCloseIgnoresBusyWALCheckpointHeldByReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checkpoint-reader.db")
	store, err := Open(Config{
		Path:        path,
		BusyTimeout: 25 * time.Millisecond,
		QueueSize:   4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !store.Record(testEvent("checkpoint-before-reader", time.Now().UTC())) {
		t.Fatal("first Record was rejected")
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	reader, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?_busy_timeout=25")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&count); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if !store.Record(testEvent("checkpoint-after-reader", time.Now().UTC().Add(time.Second))) {
		_ = tx.Rollback()
		t.Fatal("second Record was rejected")
	}
	if err := store.Flush(context.Background()); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}

	if closeErr := store.Close(); closeErr != nil {
		_ = tx.Rollback()
		t.Fatalf("Close treated a reader-pinned durable WAL as fatal: %v", closeErr)
	}
	if status := store.Status(); status.Degraded || status.LastError != "" {
		_ = tx.Rollback()
		t.Fatalf("busy close latched a false storage failure: status=%#v", status)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	reopened, err := Open(Config{Path: path, BusyTimeout: 25 * time.Millisecond})
	if err != nil {
		t.Fatalf("reopen after releasing reader: %v", err)
	}
	events, err := reopened.Query(context.Background(), Query{Limit: 10})
	if err != nil || len(events) != 2 {
		_ = reopened.Close()
		t.Fatalf("recovered WAL events=%d err=%v, want both durable events", len(events), err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatalf("clean close after releasing reader: %v", err)
	}
}

func TestCloseReportsNonBusyWALCheckpointError(t *testing.T) {
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "checkpoint-error.db")})
	if err != nil {
		t.Fatal(err)
	}
	// Closing the underlying pool makes the close-time checkpoint query fail
	// with a non-SQLite-busy error while leaving Store.Close to run its normal
	// finalizer and error-latching path.
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	closeErr := store.Close()
	if closeErr == nil || !strings.Contains(closeErr.Error(), "WAL checkpoint query failed") {
		t.Fatalf("Close error=%v, want genuine checkpoint failure", closeErr)
	}
	status := store.Status()
	if !status.Degraded || !strings.Contains(status.LastError, "WAL checkpoint query failed") {
		t.Fatalf("genuine checkpoint failure was not latched: status=%#v", status)
	}
}

func TestSQLiteBusyRecognitionIsNarrow(t *testing.T) {
	if !isSQLiteBusy(fmt.Errorf("wrapped checkpoint: %w", sqlite3.Error{Code: sqlite3.ErrBusy})) {
		t.Fatal("wrapped SQLITE_BUSY was not recognized")
	}
	if isSQLiteBusy(fmt.Errorf("wrapped checkpoint: %w", sqlite3.Error{Code: sqlite3.ErrLocked})) {
		t.Fatal("SQLITE_LOCKED was incorrectly treated as reader checkpoint contention")
	}
	if isSQLiteBusy(errors.New("database is locked")) {
		t.Fatal("error text without the SQLite driver code was treated as SQLITE_BUSY")
	}
}

func TestDiscardSkipsBusyWALCheckpointHeldByReader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "discard-checkpoint-reader.db")
	store, err := Open(Config{
		Path:        path,
		BusyTimeout: 25 * time.Millisecond,
		QueueSize:   4,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !store.Record(testEvent("discard-before-reader", time.Now().UTC())) {
		t.Fatal("first Record was rejected")
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	reader, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?_busy_timeout=25")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	tx, err := reader.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&count); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if !store.Record(testEvent("discard-after-reader", time.Now().UTC().Add(time.Second))) {
		_ = tx.Rollback()
		t.Fatal("second Record was rejected")
	}
	if err := store.Flush(context.Background()); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}

	if err := store.Discard(); err != nil {
		_ = tx.Rollback()
		t.Fatalf("Discard attempted a busy WAL checkpoint: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
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
	status := store.Status()
	if !status.CapacityMeasurementAvailable || !status.OverLimit || !status.Degraded ||
		status.CurrentLiveBytes <= status.ConfiguredMaxBytes || status.ConfiguredMaxBytes != 1 ||
		status.LastError != ErrCapacityExceeded.Error() {
		t.Fatalf("startup capacity status = %#v", status)
	}
	if err := store.Enqueue(testEvent("size-rejected", time.Now().UTC())); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("Enqueue() error = %v, want capacity exceeded", err)
	}
	status = store.Status()
	if status.Enqueued != 0 || status.Rejected != 1 || status.CapacityRejected != 1 {
		t.Fatalf("capacity rejection counters = %#v", status)
	}
	events, err := store.Query(context.Background(), Query{Limit: 10})
	if err != nil || len(events) != 0 {
		t.Fatalf("capacity-rejected events = (%#v, %v)", events, err)
	}
}

func TestDeferredStoreCreatesNoDatabaseArtifactsOrSchemaBeforeActivate(t *testing.T) {
	for name, path := range map[string]string{
		"empty":      "",
		"whitespace": " \t\n ",
	} {
		t.Run(name+" path fails closed", func(t *testing.T) {
			store, err := Open(Config{
				Path:                        path,
				MaxBytes:                    8 << 20,
				QueueSize:                   4,
				SkipAllStartupMutation:      true,
				AllowDeferredDatabaseCreate: true,
			})
			if store == nil {
				t.Fatal("deferred-path rejection must retain a degraded Store")
			}
			t.Cleanup(func() { _ = store.Discard() })
			if err == nil || !strings.Contains(err.Error(), "deferred database path is empty") {
				t.Fatalf("Open() error=%v, want deferred empty-path rejection", err)
			}
			if store.DatabaseAvailable() || store.IsActive() {
				t.Fatalf(
					"rejected deferred Store databaseAvailable=%t active=%t",
					store.DatabaseAvailable(),
					store.IsActive(),
				)
			}
		})
	}

	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "events.db")
	store, err := Open(Config{
		Path:                        path,
		MaxBytes:                    8 << 20,
		QueueSize:                   4,
		SkipAllStartupMutation:      true,
		AllowDeferredDatabaseCreate: true,
	})
	if err != nil {
		t.Fatalf("prepare deferred Store: %v", err)
	}
	t.Cleanup(func() { _ = store.Discard() })
	if store.DatabaseAvailable() {
		t.Fatal("candidate opened a database before Activate")
	}
	for _, artifact := range []string{path, path + "-wal", path + "-shm"} {
		if _, err := os.Lstat(artifact); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("candidate created database artifact %q before Activate: %v", artifact, err)
		}
	}
	if err := store.Enqueue(testEvent("before-activate", time.Now().UTC())); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("candidate admission error=%v, want ErrUnavailable", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := store.Activate(ctx); err != nil {
		t.Fatalf("Activate deferred Store: %v", err)
	}
	if !store.DatabaseAvailable() {
		t.Fatal("Activate did not open the deferred database")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("Activate did not create the deferred database: %v", err)
	}
	status := store.Status()
	if !status.Healthy || status.Degraded || !status.CapacityMeasurementAvailable || status.OverLimit || status.SchemaVersion != currentSchemaVersion {
		t.Fatalf("activated deferred Store status=%#v", status)
	}
	if err := store.Enqueue(testEvent("after-activate", time.Now().UTC())); err != nil {
		t.Fatalf("activated Store rejected bounded audit event: %v", err)
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatalf("activated Store worker did not drain: %v", err)
	}
}

func TestDeferredRawCaptureActivationPreservesFreshAndExpiresOldCapture(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "deferred-raw-capture.db")
	base := Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20, QueueSize: 8,
		CleanupInterval: time.Hour, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192,
			TTL: 2 * time.Hour, RedactSecrets: true,
		},
	}
	seed, err := Open(base)
	if err != nil {
		t.Fatalf("open seed Store: %v", err)
	}
	for _, fixture := range []struct {
		id        string
		timestamp time.Time
	}{
		{id: "expired-before-deferred-activate", timestamp: now.Add(-3 * time.Hour)},
		{id: "fresh-before-deferred-activate", timestamp: now.Add(-time.Hour)},
	} {
		raw := []byte("password is " + fixture.id)
		event := rawCaptureEvent(fixture.id, fixture.timestamp, "block", "block_malicious_text", raw)
		accepted, enqueueErr := seed.EnqueueEventWithRawCapture(event, RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
			RawRequest: raw,
		})
		if enqueueErr != nil || !accepted {
			_ = seed.Close()
			t.Fatalf("seed capture %q accepted=%t error=%v", fixture.id, accepted, enqueueErr)
		}
	}
	if err := seed.Flush(context.Background()); err != nil {
		_ = seed.Close()
		t.Fatalf("flush seed Store: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed Store: %v", err)
	}

	deferredCfg := base
	deferredCfg.SkipAllStartupMutation = true
	deferredCfg.AllowDeferredDatabaseCreate = true
	// Keep SkipDisabledPurgeOnOpen at its production default false. Enabled raw
	// capture must select the TTL policy, never the disabled-capture purge.
	deferred, err := Open(deferredCfg)
	if err != nil {
		t.Fatalf("prepare deferred Store: %v", err)
	}
	t.Cleanup(func() { _ = deferred.Discard() })
	if deferred.DatabaseAvailable() {
		t.Fatal("deferred Store opened the database before Activate")
	}
	if err := deferred.Activate(context.Background()); err != nil {
		t.Fatalf("Activate deferred Store: %v", err)
	}
	captures, err := deferred.QueryRawCaptures(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil {
		t.Fatalf("query activated raw captures: %v", err)
	}
	if len(captures) != 1 || captures[0].EventID != "fresh-before-deferred-activate" {
		t.Fatalf("activated raw captures=%#v, want only the fresh capture", captures)
	}
}

func TestPreparedStoreRejectsLegacySchemaWithoutMigrating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-candidate.db")
	seed, err := Open(Config{Path: path, MaxBytes: 8 << 20})
	if err != nil {
		t.Fatalf("seed current database: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seeded database: %v", err)
	}

	legacyVersion := currentSchemaVersion - 1
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("UPDATE schema_version SET version = ? WHERE singleton = 1", legacyVersion); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	candidate, openErr := Open(Config{
		Path:                   path,
		MaxBytes:               8 << 20,
		SkipAllStartupMutation: true,
	})
	if candidate != nil {
		t.Cleanup(func() { _ = candidate.Discard() })
	}
	if openErr == nil || !strings.Contains(openErr.Error(), "prepared candidate schema version") {
		t.Fatalf("prepared legacy candidate error=%v", openErr)
	}

	check, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var version int
	if err := check.QueryRow("SELECT version FROM schema_version WHERE singleton = 1").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != legacyVersion {
		t.Fatalf("prepared candidate migrated schema version=%d, want unchanged %d", version, legacyVersion)
	}
	if _, err := check.Exec("CREATE TABLE read_only_probe (id INTEGER)"); err == nil {
		t.Fatal("mode=ro verification connection accepted a schema write")
	}
}

func TestActivateFailureKeepsStoreUnactivatedAndBlocksAdmission(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activation-failure.db")
	seed, err := Open(Config{Path: path, MaxBytes: 8 << 20})
	if err != nil {
		t.Fatalf("seed current-schema database: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed database: %v", err)
	}

	storageFailure := errors.New("synthetic activation storage failure")
	store, err := Open(Config{
		Path:                   path,
		MaxBytes:               8 << 20,
		QueueSize:              4,
		SkipAllStartupMutation: true,
		StorageAccessGate: func() error {
			return storageFailure
		},
	})
	if err != nil {
		t.Fatalf("prepare current-schema Store: %v", err)
	}
	t.Cleanup(func() { _ = store.Discard() })
	if err := store.Enqueue(testEvent("before-failed-activate", time.Now().UTC())); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("prepared Store admission error=%v, want ErrUnavailable", err)
	}

	activationErr := store.Activate(context.Background())
	if !errors.Is(activationErr, ErrStorageBlocked) || !strings.Contains(activationErr.Error(), storageFailure.Error()) {
		t.Fatalf("Activate error=%v, want storage failure", activationErr)
	}
	if store.workerStarted || store.activated.Load() {
		t.Fatalf("failed Activate left workerStarted=%t activated=%t", store.workerStarted, store.activated.Load())
	}
	status := store.Status()
	if status.Healthy || !status.Degraded || status.CapacityMeasurementAvailable || !status.OverLimit || !strings.Contains(status.LastError, storageFailure.Error()) {
		t.Fatalf("failed Activate status=%#v", status)
	}
	if err := store.Enqueue(testEvent("after-failed-activate", time.Now().UTC())); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed Activate admission error=%v, want unactivated Store rejection", err)
	}
	flushCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := store.Flush(flushCtx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed Activate Flush error=%v, want ErrUnavailable", err)
	}
	if status := store.Status(); status.QueueDepth != 0 || status.Enqueued != 0 || status.CapacityRejected != 0 {
		t.Fatalf("failed Activate counters=%#v", status)
	}
}

func TestPostMaintenanceBindFailurePreventsActivationAndWorkerStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "final-activation-bind-failure.db")
	finalBindFailure := errors.New("synthetic final activation bind failure")
	var store *Store
	var bindCalls atomic.Uint32
	var observedActive atomic.Bool
	var observedWorker atomic.Bool
	store, err := Open(Config{
		Path:                        path,
		MaxBytes:                    8 << 20,
		QueueSize:                   4,
		SkipAllStartupMutation:      true,
		AllowDeferredDatabaseCreate: true,
		StoragePostMaintenanceBind: func() error {
			bindCalls.Add(1)
			observedActive.Store(store.activated.Load() || store.IsActive())
			observedWorker.Store(store.workerStarted)
			return finalBindFailure
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Discard() })

	activationErr := store.Activate(context.Background())
	if !errors.Is(activationErr, ErrStorageBlocked) || !strings.Contains(activationErr.Error(), finalBindFailure.Error()) {
		t.Fatalf("final-bind Activate error=%v, want ErrStorageBlocked with cause", activationErr)
	}
	if bindCalls.Load() != 1 || observedActive.Load() || observedWorker.Load() {
		t.Fatalf("final bind calls=%d observedActive=%t observedWorker=%t", bindCalls.Load(), observedActive.Load(), observedWorker.Load())
	}
	if store.activated.Load() || store.workerStarted || store.IsActive() {
		t.Fatalf("failed final bind activated=%t workerStarted=%t active=%t", store.activated.Load(), store.workerStarted, store.IsActive())
	}
	if !store.DatabaseAvailable() {
		t.Fatal("final bind did not run after deferred database open and maintenance")
	}
	if err := store.Enqueue(testEvent("after-final-bind-failure", time.Now().UTC())); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("final-bind failure admission error=%v, want ErrUnavailable", err)
	}
	status := store.Status()
	if status.Enqueued != 0 || status.Written != 0 || status.QueueDepth != 0 {
		t.Fatalf("final-bind failure leaked queue work: %#v", status)
	}
}

func TestActivateDoesNotStartWorkerAfterCloseWaitWinsPublicationBoundary(t *testing.T) {
	reported := make(chan error, 1)
	store, err := Open(Config{
		Path:                        filepath.Join(t.TempDir(), "activation-close-boundary.db"),
		MaxBytes:                    8 << 20,
		QueueSize:                   4,
		SkipAllStartupMutation:      true,
		AllowDeferredDatabaseCreate: true,
		OnError: func(err error) {
			reported <- err
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Discard() })

	activationPublished := make(chan struct{})
	releaseWorkerStart := make(chan struct{})
	var releaseOnce sync.Once
	release := func() {
		releaseOnce.Do(func() { close(releaseWorkerStart) })
	}
	t.Cleanup(release)
	store.activationBeforeWorkerStartHook = func() {
		close(activationPublished)
		<-releaseWorkerStart
	}

	activationDone := make(chan error, 1)
	go func() { activationDone <- store.Activate(context.Background()) }()
	select {
	case <-activationPublished:
	case <-time.After(5 * time.Second):
		t.Fatal("Activate did not publish admission before the worker-start barrier")
	}
	if !store.activated.Load() || store.workerStarted {
		t.Fatalf("activation boundary activated=%t workerStarted=%t", store.activated.Load(), store.workerStarted)
	}

	closeDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		closeDone <- store.CloseContext(ctx)
	}()
	select {
	case <-store.workerCtx.Done():
		// CloseContext cancels workerCtx only after its worker wait has returned.
	case <-time.After(5 * time.Second):
		t.Fatal("CloseContext did not complete its worker wait at the activation barrier")
	}
	if !store.closedState.Load() || store.workerStarted {
		t.Fatalf("close boundary closed=%t workerStarted=%t", store.closedState.Load(), store.workerStarted)
	}
	select {
	case closeErr := <-closeDone:
		t.Fatalf("CloseContext returned before Activate released activateMu: %v", closeErr)
	default:
	}

	release()
	select {
	case activationErr := <-activationDone:
		if !errors.Is(activationErr, ErrClosed) {
			t.Fatalf("Activate error=%v, want ErrClosed after terminal close won", activationErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Activate did not finish after releasing the worker-start barrier")
	}
	select {
	case closeErr := <-closeDone:
		if closeErr != nil {
			t.Fatalf("CloseContext error=%v", closeErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("CloseContext did not finish after terminal activation failure")
	}

	if store.workerStarted || store.activated.Load() || store.IsActive() || store.DatabaseAvailable() {
		t.Fatalf("terminal Store workerStarted=%t activated=%t active=%t databaseAvailable=%t",
			store.workerStarted, store.activated.Load(), store.IsActive(), store.DatabaseAvailable())
	}
	select {
	case reportedErr := <-reported:
		if !errors.Is(reportedErr, ErrClosed) {
			t.Fatalf("activation report=%v, want ErrClosed", reportedErr)
		}
	default:
		t.Fatal("terminal activation failure was not reported")
	}
	status := store.Status()
	if !status.Closed || !status.Degraded || !strings.Contains(status.LastError, ErrClosed.Error()) || status.QueueDepth != 0 {
		t.Fatalf("terminal activation status=%#v", status)
	}
}

func TestStoreIsActiveRequiresDatabaseSuccessfulActivationAndOpenLifecycle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "active-lifecycle.db")
	var store *Store
	var bindCalls atomic.Uint32
	var observedActive atomic.Bool
	var observedWorker atomic.Bool
	store, err := Open(Config{
		Path:                        path,
		SkipAllStartupMutation:      true,
		AllowDeferredDatabaseCreate: true,
		StoragePostMaintenanceBind: func() error {
			bindCalls.Add(1)
			observedActive.Store(store.activated.Load() || store.IsActive())
			observedWorker.Store(store.workerStarted)
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if store.IsActive() || store.DatabaseAvailable() {
		t.Fatalf("deferred Store active=%t databaseAvailable=%t before Activate", store.IsActive(), store.DatabaseAvailable())
	}
	if err := store.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !store.IsActive() || !store.DatabaseAvailable() {
		t.Fatalf("activated Store active=%t databaseAvailable=%t", store.IsActive(), store.DatabaseAvailable())
	}
	if bindCalls.Load() != 1 || observedActive.Load() || observedWorker.Load() || !store.workerStarted {
		t.Fatalf("successful bind calls=%d observedActive=%t observedWorker=%t workerStarted=%t", bindCalls.Load(), observedActive.Load(), observedWorker.Load(), store.workerStarted)
	}
	if err := store.Activate(context.Background()); err != nil {
		t.Fatalf("idempotent Activate: %v", err)
	}
	if bindCalls.Load() != 1 || !store.workerStarted {
		t.Fatalf("idempotent Activate repeated bind/worker publication: calls=%d workerStarted=%t", bindCalls.Load(), store.workerStarted)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if store.IsActive() {
		t.Fatal("closed Store remained active")
	}

	postOpenFailure := errors.New("synthetic post-open lifecycle failure")
	failed, err := Open(Config{
		Path:                        filepath.Join(t.TempDir(), "failed-active-lifecycle.db"),
		SkipAllStartupMutation:      true,
		AllowDeferredDatabaseCreate: true,
		StorageActivationGate:       func() error { return nil },
		StorageAccessGate:           func() error { return postOpenFailure },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = failed.Discard() })
	activationErr := failed.Activate(context.Background())
	if !errors.Is(activationErr, ErrStorageBlocked) || !strings.Contains(activationErr.Error(), postOpenFailure.Error()) {
		t.Fatalf("post-open activation error=%v", activationErr)
	}
	if !failed.DatabaseAvailable() || failed.IsActive() {
		t.Fatalf("failed Store databaseAvailable=%t active=%t, want open but inactive", failed.DatabaseAvailable(), failed.IsActive())
	}
}

func TestStoreLifecyclePredicateHasNoActivateCloseFlushDiscardLockInversion(t *testing.T) {
	for _, discard := range []bool{false, true} {
		name := "close"
		if discard {
			name = "discard"
		}
		t.Run(name, func(t *testing.T) {
			postOpen := make(chan struct{})
			releaseOpen := make(chan struct{})
			var releaseOpenOnce sync.Once
			releaseOpenBarrier := func() {
				releaseOpenOnce.Do(func() { close(releaseOpen) })
			}
			defer releaseOpenBarrier()
			store, err := Open(Config{
				Path:                        filepath.Join(t.TempDir(), name+"-lifecycle-race.db"),
				SkipAllStartupMutation:      true,
				AllowDeferredDatabaseCreate: true,
				StoragePostOpenBind: func() error {
					close(postOpen)
					<-releaseOpen
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}

			stopReaders := make(chan struct{})
			var readers sync.WaitGroup
			for range 8 {
				readers.Add(1)
				go func() {
					defer readers.Done()
					for {
						select {
						case <-stopReaders:
							return
						default:
							_ = store.IsActive()
							_ = store.DatabaseAvailable()
							_ = store.Status()
						}
					}
				}()
			}

			activationDone := make(chan error, 1)
			go func() { activationDone <- store.Activate(context.Background()) }()
			select {
			case <-postOpen:
			case <-time.After(5 * time.Second):
				releaseOpenBarrier()
				close(stopReaders)
				readers.Wait()
				t.Fatal("Activate did not reach post-open lifecycle barrier")
			}

			closeDone := make(chan error, 1)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if discard {
					closeDone <- store.DiscardContext(ctx)
					return
				}
				closeDone <- store.CloseContext(ctx)
			}()
			deadline := time.Now().Add(5 * time.Second)
			for !store.closedState.Load() && time.Now().Before(deadline) {
				runtime.Gosched()
			}
			if !store.closedState.Load() {
				releaseOpenBarrier()
				close(stopReaders)
				readers.Wait()
				t.Fatal("Close/Discard did not publish closed lifecycle state")
			}
			flushCtx, cancelFlush := context.WithTimeout(context.Background(), time.Second)
			flushErr := store.Flush(flushCtx)
			cancelFlush()
			if !errors.Is(flushErr, ErrClosed) {
				releaseOpenBarrier()
				close(stopReaders)
				readers.Wait()
				t.Fatalf("Flush during close error=%v, want ErrClosed", flushErr)
			}
			releaseOpenBarrier()
			select {
			case <-activationDone:
			case <-time.After(5 * time.Second):
				t.Fatal("Activate deadlocked with Close/Discard")
			}
			select {
			case err := <-closeDone:
				if err != nil {
					t.Fatalf("Close/Discard error=%v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close/Discard deadlocked with Activate")
			}
			close(stopReaders)
			readers.Wait()
			if store.IsActive() || store.DatabaseAvailable() {
				t.Fatalf("terminal Store active=%t databaseAvailable=%t", store.IsActive(), store.DatabaseAvailable())
			}
		})
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
