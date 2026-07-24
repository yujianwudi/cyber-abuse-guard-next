package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestPrepareRawCaptureRedactsSecretsBeforeUTF8Truncation(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	raw := []byte(`{"password":"hunter2-canary","api_key":"sk-1234567890abcdef","auth":"auth-json-canary","session_token":"session-token-canary","authorization":"Bearer bearer-token-canary","cookie":"session=cookie-canary","note":"keep this"}
auth=auth-form-canary&note=keep-form-context
cookie=session=primary-cookie-canary; csrf=secondary-cookie-canary&note=keep-cookie-context
my password is prose-password-canary
auth is prose-auth-canary
session token is prose-session-token-canary
the api key is prose-api-key-canary
eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.signaturecanary`)
	capture, err := prepareRawCapture(RawCaptureInput{
		EventID:     "redaction-event",
		Timestamp:   now,
		RequestHash: HashRequest(raw),
		SubjectHash: testSubjectHash("redaction-subject"),
		Action:      "block",
		Decision:    "block_malicious_text",
		RawRequest:  raw,
	}, RawCaptureConfig{
		Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
	}, now)
	if err != nil {
		t.Fatalf("prepareRawCapture() error = %v", err)
	}
	for _, secret := range []string{
		"hunter2-canary", "sk-1234567890abcdef", "auth-json-canary", "auth-form-canary", "session-token-canary",
		"bearer-token-canary", "cookie-canary", "prose-password-canary", "prose-auth-canary",
		"primary-cookie-canary", "secondary-cookie-canary",
		"prose-session-token-canary", "prose-api-key-canary", "eyJhbGciOiJIUzI1NiJ9",
	} {
		if strings.Contains(capture.RawPreview, secret) {
			t.Fatalf("raw preview retained secret %q: %q", secret, capture.RawPreview)
		}
	}
	if !capture.Redacted || capture.Truncated {
		t.Fatalf("redacted/truncated = %t/%t", capture.Redacted, capture.Truncated)
	}
	if !strings.Contains(capture.RawPreview, "keep this") {
		t.Fatalf("non-secret review context was lost: %q", capture.RawPreview)
	}
	if !strings.Contains(capture.RawPreview, "keep-cookie-context") {
		t.Fatalf("cookie redaction consumed unrelated form context: %q", capture.RawPreview)
	}
	sum := sha256.Sum256(raw)
	if want := "sha256:" + hex.EncodeToString(sum[:]); capture.RawSHA256 != want {
		t.Fatalf("raw_sha256 = %q, want %q", capture.RawSHA256, want)
	}

	truncated, err := prepareRawCapture(RawCaptureInput{
		EventID: "utf8-event", Action: "block", Decision: "block_malicious_text",
		RawRequest: []byte("password is secret-before-boundary 你好世界"),
	}, RawCaptureConfig{
		Enabled: true, OnlyBlocked: true, MaxBytes: 20, RedactSecrets: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !truncated.Truncated || !truncated.Redacted || len(truncated.RawPreview) > 20 || !utf8.ValidString(truncated.RawPreview) {
		t.Fatalf("unsafe UTF-8 truncation result = %#v", truncated)
	}
	if strings.Contains(truncated.RawPreview, "secret-before-boundary") {
		t.Fatalf("capture truncated before redaction: %q", truncated.RawPreview)
	}
}

func TestRawCaptureRejectsDecisionKindExplanationSchemaMismatch(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 24, 8, 0, 0, 0, time.UTC)
	raw := []byte(`{"prompt":"synthetic blocked request"}`)
	cfg := RawCaptureConfig{
		Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
	}
	_, err := prepareRawCapture(RawCaptureInput{
		EventID:           "schema-mismatch-prepare",
		Timestamp:         now,
		Action:            "block",
		Decision:          "block_malicious_text",
		DecisionKind:      decisionKindBlockMaliciousText,
		ExplanationSchema: DecisionExplanationSchemaNone,
		RawRequest:        raw,
	}, cfg, now)
	if err == nil || !strings.Contains(err.Error(), DecisionExplanationSchemaV2) {
		t.Fatalf("prepareRawCapture() error = %v", err)
	}

	store, err := Open(Config{
		Path:       filepath.Join(t.TempDir(), "raw-capture-schema-mismatch.db"),
		Retention:  24 * time.Hour,
		MaxBytes:   8 << 20,
		QueueSize:  16,
		RawCapture: cfg,
		Now:        func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	event := round9MaliciousBlockEventFixture()
	event.ID = "schema-mismatch-persisted"
	event.Timestamp = now
	event.RequestHash = HashRequest(raw)
	event.SubjectHash = testSubjectHash("schema-mismatch-persisted")
	if !store.Record(event) {
		t.Fatal("Record() rejected valid Round 9 block event")
	}
	if err := store.RecordRawCapture(RawCaptureInput{
		EventID:           event.ID,
		Timestamp:         event.Timestamp,
		RequestHash:       event.RequestHash,
		SubjectHash:       event.SubjectHash,
		Action:            event.Action,
		Decision:          event.Decision,
		DecisionKind:      event.DecisionKind,
		ExplanationSchema: DecisionExplanationSchemaV2,
		RawRequest:        raw,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE raw_request_captures SET explanation_schema = ? WHERE event_id = ?`,
		DecisionExplanationSchemaNone, event.ID); err != nil {
		t.Fatal(err)
	}
	if captures, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{EventID: event.ID}); err == nil || !strings.Contains(err.Error(), DecisionExplanationSchemaV2) || len(captures) != 0 {
		t.Fatalf("QueryRawCaptures() captures=%#v error=%v", captures, err)
	}
}

func TestStoreRecordsOnlyBlockingRawCapturesAndCapsQuery(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 13, 0, 0, 0, time.UTC)
	store, err := Open(Config{
		Path:            filepath.Join(t.TempDir(), "raw-capture.db"),
		Retention:       24 * time.Hour,
		MaxBytes:        8 << 20,
		QueueSize:       512,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	var secureDelete int
	if err := store.db.QueryRow("PRAGMA secure_delete").Scan(&secureDelete); err != nil || secureDelete != 1 {
		t.Fatalf("secure_delete = %d, err=%v", secureDelete, err)
	}

	for index := 0; index < 105; index++ {
		id := fmt.Sprintf("blocked-%03d", index)
		raw := []byte(fmt.Sprintf(`{"message":"review-%03d","password":"secret-%03d"}`, index, index))
		event := rawCaptureEvent(id, now.Add(time.Duration(index)*time.Nanosecond), "block", "block_malicious_text", raw)
		if !store.Record(event) {
			t.Fatalf("Record(%s) failed", id)
		}
		if err := store.RecordRawCapture(RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
		}); err != nil {
			t.Fatalf("RecordRawCapture(%s) error = %v", id, err)
		}
		raw[0] = 'X'
	}
	if err := store.RecordRawCapture(RawCaptureInput{
		EventID: "not-blocked", Action: "audit", Decision: "audit_malicious_text", RawRequest: []byte("must not persist"),
	}); !errors.Is(err, ErrInvalidRawCapture) {
		t.Fatalf("non-blocking capture error = %v", err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	captures, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	if len(captures) != maxRawCaptureLimit {
		t.Fatalf("capped query returned %d captures, want %d", len(captures), maxRawCaptureLimit)
	}
	latest := captures[0]
	if latest.EventID != "blocked-104" || !latest.Redacted || strings.Contains(latest.RawPreview, "secret-104") {
		t.Fatalf("latest capture = %#v", latest)
	}
	byEvent, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{EventID: latest.EventID})
	if err != nil || len(byEvent) != 1 || byEvent[0].ID != latest.ID {
		t.Fatalf("event filter = %#v, err=%v", byEvent, err)
	}
	byHash, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{RequestHash: latest.RequestHash})
	if err != nil || len(byHash) != 1 || byHash[0].EventID != latest.EventID {
		t.Fatalf("request hash filter = %#v, err=%v", byHash, err)
	}
	defaults, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{})
	if err != nil || len(defaults) != defaultRawCaptureLimit {
		t.Fatalf("default query count = %d, err=%v", len(defaults), err)
	}
}

func TestQueryRawCapturesPageStopsAfterOneBudgetSentinel(t *testing.T) {
	now := time.Date(2026, 7, 21, 13, 30, 0, 0, time.UTC)
	store, err := Open(Config{
		Path:      filepath.Join(t.TempDir(), "raw-capture-page-budget.db"),
		Retention: 24 * time.Hour,
		MaxBytes:  256 << 20,
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: maxRawCaptureBytes, TTL: 72 * time.Hour, RedactSecrets: true,
		},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Model a database populated under the historical 1 MiB per-record setting.
	// The current management configuration may later be reduced to only a few
	// bytes, but the audit scan must still stop after 8 MiB plus one sentinel
	// even though limit=100 requests every available historical row.
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	const insertLargeCapture = `INSERT INTO raw_request_captures (
    id, event_id, timestamp_ns, request_hash, subject_hash, action, decision,
    truncated, redacted, raw_preview, raw_sha256
) VALUES (?, ?, ?, '', '', 'block', 'block_malicious_text', 0, 0, CAST(zeroblob(?) AS TEXT), ?)`
	const historicalRows = 12
	for index := 0; index < historicalRows; index++ {
		eventID := fmt.Sprintf("historical-large-%03d", index)
		timestamp := now.Add(time.Duration(index) * time.Nanosecond)
		if _, err := tx.Exec(insertEventSQL,
			eventID, timestamp.UnixNano(), "block", "balanced", "exploitation", 100, "[]",
			"", "", "", "openai", 0, 0, "raw-capture-budget-test",
			decisionKindLegacyUnspecified, "complete", "", "streaming-scanner-v1", 0, "{}",
			"block_malicious_text", DecisionExplanationSchemaNone,
		); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(insertLargeCapture,
			"capture-"+eventID, eventID, timestamp.UnixNano(), maxRawCaptureBytes,
			fmt.Sprintf("sha256:%064x", index+1),
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	committed = true

	page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: maxRawCaptureLimit})
	if err != nil {
		t.Fatal(err)
	}
	wantRows := RawCaptureQueryPreviewBudgetBytes / maxRawCaptureBytes
	if len(page.Captures) != wantRows || page.PreviewBytes != RawCaptureQueryPreviewBudgetBytes || !page.HasMore {
		t.Fatalf("bounded page rows=%d bytes=%d has_more=%t, want rows=%d bytes=%d has_more=true",
			len(page.Captures), page.PreviewBytes, page.HasMore, wantRows, RawCaptureQueryPreviewBudgetBytes)
	}
	for _, capture := range page.Captures {
		if len(capture.RawPreview) != maxRawCaptureBytes {
			t.Fatalf("returned historical preview bytes=%d, want %d", len(capture.RawPreview), maxRawCaptureBytes)
		}
	}
}

func TestRawCaptureTTLStartupCleanupAndEventDeleteCascade(t *testing.T) {
	t.Parallel()
	clock := time.Date(2026, 7, 21, 14, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "raw-capture-retention.db")
	open := func() *Store {
		store, err := Open(Config{
			Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20, QueueSize: 32,
			CleanupInterval: time.Hour, Now: func() time.Time { return clock },
			RawCapture: RawCaptureConfig{
				Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 2 * time.Hour, RedactSecrets: true,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		return store
	}
	store := open()
	for _, fixture := range []struct {
		id        string
		timestamp time.Time
	}{
		{id: "ttl-expired", timestamp: clock.Add(-3 * time.Hour)},
		{id: "ttl-kept", timestamp: clock.Add(-time.Hour)},
	} {
		raw := []byte("password is " + fixture.id)
		event := rawCaptureEvent(fixture.id, fixture.timestamp, "block", "block_malicious_text", raw)
		if !store.Record(event) {
			t.Fatal("event enqueue failed")
		}
		if err := store.RecordRawCapture(RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := store.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	captures, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{})
	if err != nil || len(captures) != 1 || captures[0].EventID != "ttl-kept" {
		t.Fatalf("post-TTL captures = %#v, err=%v", captures, err)
	}
	if events, err := store.Query(context.Background(), Query{Limit: 10}); err != nil || len(events) != 2 {
		t.Fatalf("event retention unexpectedly followed shorter raw TTL: count=%d err=%v", len(events), err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	clock = clock.Add(3 * time.Hour)
	store = open()
	captures, err = store.QueryRawCaptures(context.Background(), RawCaptureQuery{})
	if err != nil || len(captures) != 0 {
		t.Fatalf("startup TTL cleanup captures = %#v, err=%v", captures, err)
	}

	raw := []byte("password is cascade-secret")
	event := rawCaptureEvent("cascade-event", clock, "cooldown", "cooldown_subject_risk", raw)
	if !store.Record(event) {
		t.Fatal("cascade event enqueue failed")
	}
	if err := store.RecordRawCapture(RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if deleted, err := store.Delete(context.Background(), Query{Action: "cooldown"}); err != nil || deleted != 1 {
		t.Fatalf("Delete(cooldown) = %d, err=%v", deleted, err)
	}
	if captures, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{EventID: event.ID}); err != nil || len(captures) != 0 {
		t.Fatalf("cascade captures = %#v, err=%v", captures, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRawCaptureDisabledAndOrphanProtection(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 15, 0, 0, 0, time.UTC)
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "disabled.db"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RecordRawCapture(RawCaptureInput{
		EventID: "disabled-event", Action: "block", Decision: "block_malicious_text", RawRequest: []byte("secret"),
	}); !errors.Is(err, ErrRawCaptureDisabled) {
		t.Fatalf("disabled capture error = %v", err)
	}
	var secureDelete int
	if err := store.db.QueryRow("PRAGMA secure_delete").Scan(&secureDelete); err != nil || secureDelete != 1 {
		t.Fatalf("disabled raw capture secure_delete = %d, err=%v", secureDelete, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(Config{
		Path: filepath.Join(t.TempDir(), "orphan.db"), QueueSize: 8, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{Enabled: true, MaxBytes: 8192, TTL: 72 * time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.RecordRawCapture(RawCaptureInput{
		EventID: "missing-event", Action: "block", Decision: "block_malicious_text", RawRequest: []byte("password is orphan"),
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := store.db.QueryRow("SELECT COUNT(*) FROM raw_request_captures").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 || store.Status().Failed == 0 {
		t.Fatalf("orphan count=%d status=%#v", count, store.Status())
	}
}

func TestDisabledReopenPurgesCapturesWithSecureDelete(t *testing.T) {
	now := time.Date(2026, 7, 21, 16, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "disabled-reopen-purge.db")
	const canary = "RAW-CAPTURE-DISABLE-PURGE-CANARY-7f3a2b19"

	enabled, err := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"messages":[{"role":"user","content":"` + canary + `"}]}`)
	event := rawCaptureEvent("disabled-reopen-event", now, "block", "block_malicious_text", raw)
	if !enabled.Record(event) {
		t.Fatal("audit event enqueue failed")
	}
	if err := enabled.RecordRawCapture(RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
	}); err != nil {
		t.Fatal(err)
	}
	if err := enabled.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(before, []byte(canary)) {
		t.Fatal("fixture canary was not persisted before the disabled reopen")
	}

	disabled, err := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{Enabled: false, MaxBytes: 8192, TTL: 72 * time.Hour},
	})
	if err != nil {
		t.Fatal(err)
	}
	var secureDelete int
	if err := disabled.db.QueryRow("PRAGMA secure_delete").Scan(&secureDelete); err != nil || secureDelete != 1 {
		t.Fatalf("secure_delete after disabled reopen = %d, err=%v", secureDelete, err)
	}
	var captureCount, eventCount int
	if err := disabled.db.QueryRow("SELECT COUNT(*) FROM raw_request_captures").Scan(&captureCount); err != nil {
		t.Fatal(err)
	}
	if err := disabled.db.QueryRow("SELECT COUNT(*) FROM audit_events WHERE id = ?", event.ID).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if captureCount != 0 || eventCount != 1 {
		t.Fatalf("disabled reopen retained captures=%d events=%d, want captures=0 events=1", captureCount, eventCount)
	}
	if err := disabled.Close(); err != nil {
		t.Fatal(err)
	}
	for _, candidate := range []string{path, path + "-wal", path + "-shm"} {
		data, err := os.ReadFile(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(canary)) {
			t.Fatalf("disabled purge left the request canary in %s", filepath.Base(candidate))
		}
	}
}

func TestDisabledReopenFailsWhileExistingStoreIsLocked(t *testing.T) {
	now := time.Date(2026, 7, 21, 16, 30, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "disabled-reopen-locked.db")
	raw := []byte(`{"messages":[{"role":"user","content":"retained review canary"}]}`)
	event := rawCaptureEvent("disabled-reopen-locked-event", now, "block", "block_malicious_text", raw)

	enabled, err := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !enabled.Record(event) {
		t.Fatal("audit event enqueue failed")
	}
	if err := enabled.RecordRawCapture(RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
	}); err != nil {
		t.Fatal(err)
	}
	if err := enabled.Close(); err != nil {
		t.Fatal(err)
	}

	locker, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?_busy_timeout=25")
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	locker.SetMaxOpenConns(1)
	if _, err := locker.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_, _ = locker.Exec("ROLLBACK")
		}
	}()

	disabled, openErr := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20, BusyTimeout: 25 * time.Millisecond,
		Now:        func() time.Time { return now },
		RawCapture: RawCaptureConfig{Enabled: false, MaxBytes: 8192, TTL: 72 * time.Hour},
	})
	if openErr == nil {
		t.Fatal("disabled reopen unexpectedly succeeded while the existing store was locked")
	}
	if disabled == nil || !disabled.Status().Degraded {
		t.Fatalf("disabled reopen store=%#v error=%v, want degraded store", disabled, openErr)
	}
	if err := disabled.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := locker.Exec("ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	locked = false

	reopened, err := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	page, err := reopened.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("retained capture page=%#v error=%v, want one row after rejected purge", page, err)
	}
}

func rawCaptureEvent(id string, timestamp time.Time, action, decision string, raw []byte) Event {
	return Event{
		ID: id, Timestamp: timestamp, Action: action, Mode: "balanced",
		Category: "exploitation", RiskScore: 80, RequestHash: HashRequest(raw),
		SubjectHash: testSubjectHash("subject-" + id), Classifier: "raw-capture-test",
		Decision: decision, Coverage: "complete", Scanner: "streaming-scanner-v1",
	}
}
