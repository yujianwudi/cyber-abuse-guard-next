//go:build linux

package audit

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPurgeRawCapturesRestoresExactRowsWhenPostDeletePermissionCheckFails(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 30, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "permission-rollback.db")
	store, err := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		QueueSize: 16, RequirePersistentStorage: true, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	raw := []byte(`{"messages":[{"role":"user","content":"permission rollback review text"}]}`)
	event := rawCaptureEvent("permission-rollback-event", now, "block", "block_malicious_text", raw)
	if accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
	}); err != nil || !accepted {
		t.Fatalf("EnqueueEventWithRawCapture() accepted=%t error=%v", accepted, err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(before.Captures) != 1 {
		t.Fatalf("pre-purge captures=%#v error=%v", before, err)
	}

	// Open created and validated private production files. Widen the main file
	// only after preflight so the post-delete secureSQLiteFiles gate exercises
	// compensation instead of the fail-before-mutation path.
	var permissionHookErr error
	store.rawCapturePurgeHook = func(stage rawCapturePurgeStage) error {
		if stage == rawCapturePurgeAfterPreflight {
			permissionHookErr = os.Chmod(path, 0o644)
		}
		return permissionHookErr
	}
	defer func() { _ = os.Chmod(path, 0o600) }()

	deleted, purgeErr := store.PurgeRawCaptures(context.Background())
	if permissionHookErr != nil {
		t.Fatal(permissionHookErr)
	}
	if purgeErr == nil || deleted != 0 {
		t.Fatalf("permission-gate purge deleted=%d error=%v, want restored failure", deleted, purgeErr)
	}
	if message := purgeErr.Error(); !strings.Contains(message, "rolled back after deleting 1 rows") ||
		!strings.Contains(message, "unsafe permissions") {
		t.Fatalf("permission-gate purge error=%q", message)
	}
	after, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(after.Captures) != 1 || after.Captures[0] != before.Captures[0] {
		t.Fatalf("compensated captures=%#v error=%v, want exact %#v", after, err, before)
	}
	if status := store.Status(); status.CleanupDeleted != 0 || status.QueueDepth != 0 {
		t.Fatalf("compensated permission failure status=%#v", status)
	}
	if status := store.Status(); status.Healthy || !status.Degraded {
		t.Fatalf("post-delete file-security failure did not latch readiness: %#v", status)
	}
	if err := store.RecordRawCapture(RawCaptureInput{EventID: "blocked-after-file-failure", Action: "block", Decision: "block_malicious_text", RawRequest: raw}); !errors.Is(err, ErrRawCapturePurgeUnrecovered) {
		t.Fatalf("post-delete file-security raw write error=%v", err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	store.rawCapturePurgeHook = nil
	deleted, err = store.PurgeRawCaptures(context.Background())
	if err != nil || deleted != 1 {
		t.Fatalf("repaired purge deleted=%d error=%v", deleted, err)
	}
}

func TestPurgeRawCapturesPermissionPreflightFailsBeforeDelete(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 45, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "permission-preflight.db")
	store, err := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		QueueSize: 16, RequirePersistentStorage: true, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.db.SetMaxOpenConns(1)
	store.db.SetMaxIdleConns(1)
	if _, err := store.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("PRAGMA wal_autocheckpoint=0"); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"messages":[{"role":"user","content":"permission preflight review text"}]}`)
	const canary = "permission preflight review text"
	event := rawCaptureEvent("permission-preflight-event", now, "block", "block_malicious_text", raw)
	if accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
	}); err != nil || !accepted {
		t.Fatalf("EnqueueEventWithRawCapture() accepted=%t error=%v", accepted, err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	beforeImmutable, err := immutableRawCaptureCanaryCount(path, canary)
	if err != nil || beforeImmutable != 0 {
		t.Fatalf("immutable main-file canary count before unsafe preflight=%d error=%v", beforeImmutable, err)
	}
	walBytes, err := os.ReadFile(path + "-wal")
	if err != nil || !strings.Contains(string(walBytes), canary) {
		t.Fatalf("private WAL did not contain the test canary: bytes=%d error=%v", len(walBytes), err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(path, 0o600) }()

	deleted, purgeErr := store.PurgeRawCaptures(context.Background())
	if deleted != 0 || purgeErr == nil || !strings.Contains(purgeErr.Error(), "preflight file security") ||
		strings.Contains(purgeErr.Error(), "rolled back after deleting") {
		t.Fatalf("permission preflight deleted=%d error=%v", deleted, purgeErr)
	}
	page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("permission preflight changed captures=%#v error=%v", page, err)
	}
	afterImmutable, err := immutableRawCaptureCanaryCount(path, canary)
	if err != nil || afterImmutable != 0 {
		t.Fatalf("unsafe main file received WAL canary before rejection: count=%d error=%v", afterImmutable, err)
	}
	if status := store.Status(); status.Healthy || !status.Degraded {
		t.Fatalf("unsafe preflight did not latch readiness: %#v", status)
	}
	if err := store.RecordRawCapture(RawCaptureInput{EventID: "blocked-after-unsafe-preflight", Action: "block", Decision: "block_malicious_text", RawRequest: raw}); !errors.Is(err, ErrRawCapturePurgeUnrecovered) {
		t.Fatalf("unsafe preflight raw write error=%v", err)
	}
}

func TestPurgeRawCapturesIncompleteCheckpointStillRunsSecondSecurityCheck(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "incomplete-checkpoint-security.db")
	store, err := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		QueueSize: 16, RequirePersistentStorage: true, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.db.SetMaxOpenConns(1)
	store.db.SetMaxIdleConns(1)
	if _, err := store.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("PRAGMA wal_autocheckpoint=0"); err != nil {
		t.Fatal(err)
	}

	write := func(id string, timestamp time.Time) {
		raw := []byte(`{"messages":[{"role":"user","content":"` + id + ` review text"}]}`)
		event := rawCaptureEvent(id, timestamp, "block", "block_malicious_text", raw)
		if accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
		}); err != nil || !accepted {
			t.Fatalf("enqueue %s accepted=%t error=%v", id, accepted, err)
		}
		if err := store.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	write("incomplete-security-a", now)
	readTx := holdRawCapturePurgeReader(t, path, 1)
	readOpen := true
	defer func() {
		if readOpen {
			_ = readTx.Rollback()
		}
	}()
	write("incomplete-security-b", now.Add(time.Second))

	var chmodErr error
	store.rawCapturePurgeHook = func(stage rawCapturePurgeStage) error {
		if stage == rawCapturePurgeAfterPreflightCheckpoint {
			chmodErr = os.Chmod(path, 0o644)
		}
		return chmodErr
	}
	defer func() { _ = os.Chmod(path, 0o600) }()
	deleted, purgeErr := store.PurgeRawCaptures(context.Background())
	if chmodErr != nil {
		t.Fatal(chmodErr)
	}
	if deleted != 0 || purgeErr == nil || !strings.Contains(purgeErr.Error(), "checkpoint incomplete") ||
		!strings.Contains(purgeErr.Error(), "unsafe permissions") {
		t.Fatalf("incomplete checkpoint security deleted=%d error=%v", deleted, purgeErr)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	readOpen = false
	page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 2 {
		t.Fatalf("incomplete checkpoint security page=%#v error=%v", page, err)
	}
	if status := store.Status(); status.Healthy || !status.Degraded {
		t.Fatalf("second security failure did not latch readiness: %#v", status)
	}
}

func immutableRawCaptureCanaryCount(path, canary string) (int, error) {
	parameters := url.Values{}
	parameters.Set("mode", "ro")
	parameters.Set("immutable", "1")
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(path), RawQuery: parameters.Encode()}).String()
	db, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM raw_request_captures WHERE instr(raw_preview, ?) > 0`, canary).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}
