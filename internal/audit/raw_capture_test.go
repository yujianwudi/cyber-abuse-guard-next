package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

type rawCaptureRollbackFailureDriver struct {
	closed           atomic.Bool
	rollbackAttempts atomic.Int32
	queryErr         error
	commitErr        error
	rollbackErr      error
}

func (d *rawCaptureRollbackFailureDriver) Open(string) (driver.Conn, error) {
	return &rawCaptureRollbackFailureConn{owner: d}, nil
}

type rawCaptureRollbackFailureConn struct {
	owner *rawCaptureRollbackFailureDriver
}

func (c *rawCaptureRollbackFailureConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("unexpected Prepare in raw capture rollback failure test")
}

func (c *rawCaptureRollbackFailureConn) Close() error {
	c.owner.closed.Store(true)
	return nil
}

func (*rawCaptureRollbackFailureConn) Begin() (driver.Tx, error) {
	return nil, errors.New("unexpected driver transaction in raw capture rollback failure test")
}

func (c *rawCaptureRollbackFailureConn) ExecContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Result, error) {
	switch strings.ToUpper(strings.TrimSpace(query)) {
	case "BEGIN", "BEGIN IMMEDIATE":
		return driver.RowsAffected(0), nil
	case "DELETE FROM RAW_REQUEST_CAPTURES":
		return driver.RowsAffected(0), nil
	case "COMMIT":
		return nil, c.owner.commitErr
	case "ROLLBACK":
		c.owner.rollbackAttempts.Add(1)
		return nil, c.owner.rollbackErr
	default:
		return nil, fmt.Errorf("unexpected ExecContext query %q", query)
	}
}

func (c *rawCaptureRollbackFailureConn) QueryContext(_ context.Context, query string, _ []driver.NamedValue) (driver.Rows, error) {
	normalized := strings.ToUpper(strings.Join(strings.Fields(query), " "))
	switch {
	case normalized == "SELECT COUNT(*) FROM SQLITE_SCHEMA":
		return &rawCaptureRollbackFailureRows{columns: []string{"schema_objects"}, values: [][]driver.Value{{int64(1)}}}, nil
	case strings.HasPrefix(normalized, "SELECT COUNT(*) FROM RAW_REQUEST_CAPTURES WHERE"):
		return &rawCaptureRollbackFailureRows{columns: []string{"non_canonical_rows"}, values: [][]driver.Value{{int64(0)}}}, nil
	case strings.HasPrefix(normalized, "SELECT NAME FROM SQLITE_MASTER"):
		return &rawCaptureRollbackFailureRows{columns: []string{"name"}}, nil
	case strings.HasPrefix(normalized, "SELECT COUNT(*), COALESCE(SUM("):
		return &rawCaptureRollbackFailureRows{columns: []string{"row_count", "snapshot_bytes"}, values: [][]driver.Value{{int64(0), int64(0)}}}, nil
	case strings.HasPrefix(normalized, "SELECT ID, EVENT_ID, TIMESTAMP_NS"):
		if c.owner.queryErr != nil {
			return nil, c.owner.queryErr
		}
		return &rawCaptureRollbackFailureRows{columns: make([]string, 15)}, nil
	default:
		return nil, fmt.Errorf("unexpected QueryContext query %q", query)
	}
}

type rawCaptureRollbackFailureRows struct {
	columns []string
	values  [][]driver.Value
}

func (r *rawCaptureRollbackFailureRows) Columns() []string { return r.columns }
func (*rawCaptureRollbackFailureRows) Close() error        { return nil }

func (r *rawCaptureRollbackFailureRows) Next(dest []driver.Value) error {
	if len(r.values) == 0 {
		return io.EOF
	}
	copy(dest, r.values[0])
	r.values = r.values[1:]
	return nil
}

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

func TestPrepareRawCaptureRedactsGenericCredentialKeys(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	raw := []byte(`{"token":"generic-token-canary","id_token":"id-token-canary","oauth_token":"oauth-token-canary","credential":"credential-canary","private_key":"private-key-canary","note":"retain-review-context"}`)
	capture, err := prepareRawCapture(RawCaptureInput{
		EventID: "generic-redaction", Action: "block", Decision: "block_malicious_text", RawRequest: raw,
	}, RawCaptureConfig{Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: time.Hour, RedactSecrets: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"generic-token-canary", "id-token-canary", "oauth-token-canary", "credential-canary", "private-key-canary"} {
		if strings.Contains(capture.RawPreview, secret) {
			t.Fatalf("generic sensitive key %q was retained: %q", secret, capture.RawPreview)
		}
	}
	if !capture.Redacted || !strings.Contains(capture.RawPreview, "retain-review-context") {
		t.Fatalf("generic redaction result=%#v", capture)
	}
}

func TestPrepareRawCaptureRedactsUnicodeEscapedCredentialKeys(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 30, 0, 0, time.UTC)
	raw := []byte(`{"p\u0061ssword":"escaped-password-canary","o\u0061uth_token":"escaped-oauth-canary","note":"escaped-key-review-context"}`)
	capture, err := prepareRawCapture(RawCaptureInput{
		EventID: "unicode-key-redaction", Action: "block", Decision: "block_malicious_text", RawRequest: raw,
	}, RawCaptureConfig{Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: time.Hour, RedactSecrets: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"escaped-password-canary", "escaped-oauth-canary"} {
		if strings.Contains(capture.RawPreview, secret) {
			t.Fatalf("unicode-escaped sensitive key %q was retained: %q", secret, capture.RawPreview)
		}
	}
	if !capture.Redacted || !strings.Contains(capture.RawPreview, "escaped-key-review-context") {
		t.Fatalf("unicode-key redaction result=%#v", capture)
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

func TestQueryRawCapturesPageDiscardsConnectionWhenDeferredRollbackFails(t *testing.T) {
	queryErr := errors.New("injected raw capture query failure")
	rollbackErr := errors.New("injected raw capture rollback failure")
	failingDriver := &rawCaptureRollbackFailureDriver{
		queryErr:    queryErr,
		rollbackErr: rollbackErr,
	}
	driverName := fmt.Sprintf("raw-capture-rollback-failure-%p", failingDriver)
	sql.Register(driverName, failingDriver)
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	store := &Store{db: db}
	store.activated.Store(true)
	_, err = store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 1})
	if !errors.Is(err, queryErr) {
		t.Fatalf("QueryRawCapturesPage error=%v, want injected query failure", err)
	}
	if !failingDriver.closed.Load() {
		t.Fatal("failed deferred ROLLBACK returned an indeterminate connection to the pool")
	}
}

func TestQueryRawCapturesPagePinsSnapshotBeforeSensitiveReadGate(t *testing.T) {
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "sensitive-read-snapshot.db")
	baseConfig := Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		QueueSize: 16, BusyTimeout: time.Second, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	}
	writer, err := Open(baseConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })

	enqueueCapture := func(id, marker string, timestamp time.Time) error {
		raw := []byte(`{"messages":[{"role":"user","content":"` + marker + `"}]}`)
		event := rawCaptureEvent(id, timestamp, "block", "block_malicious_text", raw)
		accepted, err := writer.EnqueueEventWithRawCapture(event, RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
		})
		if err != nil {
			return err
		}
		if !accepted {
			return errors.New("raw capture snapshot fixture was not accepted")
		}
		return writer.Flush(context.Background())
	}
	if err := enqueueCapture("snapshot-before-gate-a", "snapshot A", now); err != nil {
		t.Fatal(err)
	}

	var insertedDuringGate atomic.Bool
	readerConfig := baseConfig
	readerConfig.StorageReadAccessGate = func() error {
		if insertedDuringGate.CompareAndSwap(false, true) {
			return enqueueCapture("snapshot-during-gate-b", "snapshot B", now.Add(time.Second))
		}
		return nil
	}
	reader, err := Open(readerConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	first, err := reader.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if !insertedDuringGate.Load() {
		t.Fatal("sensitive read gate did not execute the concurrent writer fixture")
	}
	if len(first.Captures) != 1 || first.Captures[0].EventID != "snapshot-before-gate-a" {
		t.Fatalf("first pinned snapshot captures=%#v, want only the pre-gate row", first.Captures)
	}

	second, err := reader.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Captures) != 2 ||
		second.Captures[0].EventID != "snapshot-during-gate-b" ||
		second.Captures[1].EventID != "snapshot-before-gate-a" {
		t.Fatalf("second snapshot captures=%#v, want the concurrent and original rows", second.Captures)
	}
}

func TestDeleteRawCapturesWithSnapshotDiscardsConnectionWhenCommitAndRollbackFail(t *testing.T) {
	commitErr := errors.New("injected raw capture purge commit failure")
	rollbackErr := errors.New("injected raw capture purge rollback failure")
	failingDriver := &rawCaptureRollbackFailureDriver{
		commitErr:   commitErr,
		rollbackErr: rollbackErr,
	}
	driverName := fmt.Sprintf("raw-capture-purge-commit-rollback-failure-%p", failingDriver)
	sql.Register(driverName, failingDriver)
	db, err := sql.Open(driverName, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	snapshot, deleted, purgeErr := deleteRawCapturesWithSnapshot(context.Background(), conn, maxRawCapturePurgeSnapshotBytes)
	wipeRawCapturePurgeRows(snapshot)
	if deleted != 0 || !errors.Is(purgeErr, commitErr) {
		t.Fatalf("deleteRawCapturesWithSnapshot deleted=%d error=%v, want commit failure", deleted, purgeErr)
	}
	if attempts := failingDriver.rollbackAttempts.Load(); attempts != 1 {
		t.Fatalf("ROLLBACK attempts=%d, want 1 after COMMIT failure", attempts)
	}
	if !failingDriver.closed.Load() {
		t.Fatal("failed COMMIT followed by failed ROLLBACK returned an indeterminate connection to the pool")
	}
}

func TestRawCaptureSensitiveQueryReturnsStorageBlockedForInactiveClosedAndUntrustedStore(t *testing.T) {
	deferred, err := Open(Config{
		Path:                        filepath.Join(t.TempDir(), "deferred-read.db"),
		SkipAllStartupMutation:      true,
		AllowDeferredDatabaseCreate: true,
		RawCapture:                  RawCaptureConfig{Enabled: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := deferred.QueryRawCapturesPage(context.Background(), RawCaptureQuery{}); !errors.Is(err, ErrStorageBlocked) {
		t.Fatalf("inactive sensitive query error=%v, want ErrStorageBlocked", err)
	}
	if err := deferred.Activate(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := deferred.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := deferred.QueryRawCapturesPage(context.Background(), RawCaptureQuery{}); !errors.Is(err, ErrStorageBlocked) {
		t.Fatalf("closed sensitive query error=%v, want ErrStorageBlocked", err)
	}

	readFailure := errors.New("synthetic realtime read identity failure")
	untrusted, err := Open(Config{
		Path:                  filepath.Join(t.TempDir(), "untrusted-read.db"),
		RawCapture:            RawCaptureConfig{Enabled: true},
		StorageReadAccessGate: func() error { return readFailure },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = untrusted.Close() })
	if _, err := untrusted.QueryRawCapturesPage(context.Background(), RawCaptureQuery{}); !errors.Is(err, ErrStorageBlocked) || !strings.Contains(err.Error(), readFailure.Error()) {
		t.Fatalf("untrusted sensitive query error=%v, want wrapped ErrStorageBlocked", err)
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

func TestPurgeRawCapturesRestoresExactRowsWhenTruncatingCheckpointIsBusy(t *testing.T) {
	now := time.Date(2026, 8, 9, 9, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "checkpoint-rollback.db")
	store, err := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		QueueSize: 16, BusyTimeout: 25 * time.Millisecond, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	raw := []byte(`{"messages":[{"role":"user","content":"checkpoint rollback review text"}]}`)
	event := rawCaptureEvent("checkpoint-rollback-event", now, "block", "block_malicious_text", raw)
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

	reader, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?_busy_timeout=25")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	reader.SetMaxOpenConns(1)
	readTx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	readOpen := true
	defer func() {
		if readOpen {
			_ = readTx.Rollback()
		}
	}()
	var readerCount int
	if err := readTx.QueryRow("SELECT COUNT(*) FROM raw_request_captures").Scan(&readerCount); err != nil {
		t.Fatal(err)
	}
	if readerCount != 1 {
		t.Fatalf("reader snapshot count=%d, want 1", readerCount)
	}

	deleted, purgeErr := store.PurgeRawCaptures(context.Background())
	if purgeErr == nil || deleted != 0 {
		t.Fatalf("busy-checkpoint purge deleted=%d error=%v, want restored failure", deleted, purgeErr)
	}
	if message := purgeErr.Error(); !strings.Contains(message, "rolled back after deleting 1 rows") ||
		!strings.Contains(message, "checkpoint remained busy") {
		t.Fatalf("busy-checkpoint purge error=%q", message)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	readOpen = false

	after, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(after.Captures) != 1 || after.Captures[0] != before.Captures[0] {
		t.Fatalf("compensated captures=%#v error=%v, want exact %#v", after, err, before)
	}
	if status := store.Status(); status.CleanupDeleted != 0 || status.QueueDepth != 0 {
		t.Fatalf("compensated purge status=%#v, want no net deletion and drained queue", status)
	}

	deleted, err = store.PurgeRawCaptures(context.Background())
	if err != nil || deleted != 1 {
		t.Fatalf("unblocked purge deleted=%d error=%v", deleted, err)
	}
	page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 0 {
		t.Fatalf("successful purge captures=%#v error=%v", page, err)
	}
	var busy, logFrames, checkpointedFrames int
	if err := store.db.QueryRow("PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointedFrames); err != nil {
		t.Fatal(err)
	}
	if busy != 0 || logFrames != 0 || checkpointedFrames != 0 {
		t.Fatalf("post-success WAL state busy=%d log=%d checkpointed=%d", busy, logFrames, checkpointedFrames)
	}
}

func TestPurgeRawCapturesLatchesOperationalFaultWhenCompensationFails(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "compensation-fault.db")
	store, err := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		QueueSize: 16, BusyTimeout: 25 * time.Millisecond, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	raw := []byte(`{"messages":[{"role":"user","content":"compensation fault review text"}]}`)
	event := rawCaptureEvent("compensation-fault-event", now, "block", "block_malicious_text", raw)
	if accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
	}); err != nil || !accepted {
		t.Fatalf("EnqueueEventWithRawCapture() accepted=%t error=%v", accepted, err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	reader, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?_busy_timeout=25")
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	reader.SetMaxOpenConns(1)
	readTx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	readOpen := true
	defer func() {
		if readOpen {
			_ = readTx.Rollback()
		}
	}()
	var readerCount int
	if err := readTx.QueryRow("SELECT COUNT(*) FROM raw_request_captures").Scan(&readerCount); err != nil {
		t.Fatal(err)
	}
	if readerCount != 1 {
		t.Fatalf("reader snapshot count=%d, want 1", readerCount)
	}
	store.rawCapturePurgeHook = func(stage rawCapturePurgeStage) error {
		if stage == rawCapturePurgeBeforeCompensation {
			return errors.New("injected compensation I/O failure")
		}
		return nil
	}

	deleted, purgeErr := store.PurgeRawCaptures(context.Background())
	if deleted != 1 || !errors.Is(purgeErr, ErrRawCapturePurgeUnrecovered) {
		t.Fatalf("unrecovered purge deleted=%d error=%v", deleted, purgeErr)
	}
	status := store.Status()
	if status.Healthy || !status.Degraded || !strings.Contains(status.LastError, ErrRawCapturePurgeUnrecovered.Error()) {
		t.Fatalf("unrecovered purge status=%#v", status)
	}
	if err := store.RecordRawCapture(RawCaptureInput{
		EventID: "blocked-after-compensation-fault", Action: "block", Decision: "block_malicious_text",
		RawRequest: []byte("must not enter the raw capture queue"),
	}); !errors.Is(err, ErrRawCapturePurgeUnrecovered) {
		t.Fatalf("raw write after unrecovered purge error=%v", err)
	}
	if accepted, err := store.EnqueueEventWithRawCapture(
		rawCaptureEvent("pair-after-compensation-fault", now, "block", "block_malicious_text", raw),
		RawCaptureInput{EventID: "pair-after-compensation-fault", Action: "block", Decision: "block_malicious_text", RawRequest: raw},
	); accepted || !errors.Is(err, ErrRawCapturePurgeUnrecovered) {
		t.Fatalf("paired raw write after unrecovered purge accepted=%t error=%v", accepted, err)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	readOpen = false
}

func TestRawCapturePurgeSnapshotBoundFailsBeforeDelete(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 15, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "snapshot-bound.db")
	store, err := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		QueueSize: 16, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	raw := []byte(`{"messages":[{"role":"user","content":"snapshot bound review text"}]}`)
	event := rawCaptureEvent("snapshot-bound-event", now, "block", "block_malicious_text", raw)
	if accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
	}); err != nil || !accepted {
		t.Fatalf("EnqueueEventWithRawCapture() accepted=%t error=%v", accepted, err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	conn, err := store.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	snapshot, deleted, purgeErr := deleteRawCapturesWithSnapshot(context.Background(), conn, 1)
	wipeRawCapturePurgeRows(snapshot)
	if purgeErr == nil || deleted != 0 || snapshot != nil || !strings.Contains(purgeErr.Error(), "safety bound") {
		t.Fatalf("bounded snapshot=%#v deleted=%d error=%v", snapshot, deleted, purgeErr)
	}
	page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("snapshot bound changed captures=%#v error=%v", page, err)
	}
}

func TestRawCapturePurgeSnapshotVisibleRejectsUnexpectedRows(t *testing.T) {
	now := time.Date(2026, 8, 29, 13, 0, 0, 0, time.UTC)
	store, _, _ := openRawCapturePurgeFixture(t, "unexpected-row", now)
	t.Cleanup(func() { _ = store.Close() })
	conn, err := store.db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	visible, err := rawCapturePurgeSnapshotVisible(context.Background(), conn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if visible {
		t.Fatal("fresh purge verification accepted an unexpected row for an empty snapshot")
	}
}

func TestPurgeRawCapturesFreezesConcurrentRawAdmissionThroughCompensation(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 30, 0, 0, time.UTC)
	store, path, before := openRawCapturePurgeFixture(t, "concurrent-admission", now)
	readTx := holdRawCapturePurgeReader(t, path, 1)
	readOpen := true
	defer func() {
		if readOpen {
			_ = readTx.Rollback()
		}
	}()

	compensationReached := make(chan struct{})
	continueCompensation := make(chan struct{})
	store.rawCapturePurgeHook = func(stage rawCapturePurgeStage) error {
		if stage == rawCapturePurgeBeforeCompensation {
			close(compensationReached)
			<-continueCompensation
		}
		return nil
	}
	type purgeResult struct {
		deleted int64
		err     error
	}
	purgeDone := make(chan purgeResult, 1)
	go func() {
		deleted, err := store.PurgeRawCaptures(context.Background())
		purgeDone <- purgeResult{deleted: deleted, err: err}
	}()
	<-compensationReached

	rawB := []byte(`{"messages":[{"role":"user","content":"concurrent B review text"}]}`)
	eventB := rawCaptureEvent("concurrent-admission-b", now.Add(time.Second), "block", "block_malicious_text", rawB)
	type admissionResult struct {
		accepted bool
		err      error
	}
	admissionDone := make(chan admissionResult, 1)
	go func() {
		accepted, err := store.EnqueueEventWithRawCapture(eventB, RawCaptureInput{
			EventID: eventB.ID, Timestamp: eventB.Timestamp, RequestHash: eventB.RequestHash,
			SubjectHash: eventB.SubjectHash, Action: eventB.Action, Decision: eventB.Decision, RawRequest: rawB,
		})
		admissionDone <- admissionResult{accepted: accepted, err: err}
	}()
	select {
	case result := <-admissionDone:
		t.Fatalf("raw producer completed before compensation: %+v", result)
	case <-time.After(50 * time.Millisecond):
	}
	close(continueCompensation)
	result := <-purgeDone
	if result.deleted != 0 || result.err == nil || !strings.Contains(result.err.Error(), "rolled back after deleting 1 rows") {
		t.Fatalf("compensated purge=%+v", result)
	}
	admission := <-admissionDone
	if !admission.accepted || admission.err != nil {
		t.Fatalf("post-compensation admission=%+v", admission)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	readOpen = false

	page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 2 {
		t.Fatalf("post-compensation A/B page=%#v error=%v", page, err)
	}
	seen := map[string]bool{}
	for _, capture := range page.Captures {
		seen[capture.EventID] = true
	}
	if !seen[before.Captures[0].EventID] || !seen[eventB.ID] {
		t.Fatalf("post-compensation rows=%#v, want A and B", seen)
	}
}

func TestRawCaptureCompensationCommitErrorAndRollbackErrorRequiresFreshVisibility(t *testing.T) {
	now := time.Date(2026, 8, 9, 10, 45, 0, 0, time.UTC)
	store, path, _ := openRawCapturePurgeFixture(t, "uncertain-compensation", now)
	readTx := holdRawCapturePurgeReader(t, path, 1)
	defer func() { _ = readTx.Rollback() }()
	var freshChecks int
	store.rawCapturePurgeHook = func(stage rawCapturePurgeStage) error {
		switch stage {
		case rawCapturePurgeBeforeCompensationCommit:
			return errors.New("injected commit transport error before COMMIT")
		case rawCapturePurgeBeforeCompensationRollback:
			return errors.New("injected rollback transport error")
		case rawCapturePurgeFreshVerification:
			freshChecks++
		}
		return nil
	}

	deleted, purgeErr := store.PurgeRawCaptures(context.Background())
	if deleted != 1 || !errors.Is(purgeErr, ErrRawCapturePurgeUnrecovered) {
		t.Fatalf("uncertain compensation deleted=%d error=%v", deleted, purgeErr)
	}
	if freshChecks < 2 {
		t.Fatalf("fresh verification count=%d, want pre-commit and post-error checks", freshChecks)
	}
	if status := store.Status(); status.Healthy || !status.Degraded {
		t.Fatalf("uncertain compensation status=%#v", status)
	}
}

func TestRawCaptureCompensationReportedCommitErrorAcceptsOnlyFreshCommittedRows(t *testing.T) {
	now := time.Date(2026, 8, 9, 11, 0, 0, 0, time.UTC)
	store, path, before := openRawCapturePurgeFixture(t, "committed-compensation", now)
	readTx := holdRawCapturePurgeReader(t, path, 1)
	readOpen := true
	defer func() {
		if readOpen {
			_ = readTx.Rollback()
		}
	}()
	var freshChecks int
	store.rawCapturePurgeHook = func(stage rawCapturePurgeStage) error {
		switch stage {
		case rawCapturePurgeAfterCompensationCommit:
			return errors.New("injected error reported after durable COMMIT")
		case rawCapturePurgeFreshVerification:
			freshChecks++
		}
		return nil
	}

	deleted, purgeErr := store.PurgeRawCaptures(context.Background())
	if deleted != 0 || purgeErr == nil || errors.Is(purgeErr, ErrRawCapturePurgeUnrecovered) {
		t.Fatalf("durably committed compensation deleted=%d error=%v", deleted, purgeErr)
	}
	if freshChecks < 2 {
		t.Fatalf("fresh verification count=%d, want durable visibility proof", freshChecks)
	}
	if err := readTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	readOpen = false
	after, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(after.Captures) != 1 || after.Captures[0] != before.Captures[0] {
		t.Fatalf("durably committed compensation page=%#v error=%v", after, err)
	}
}

func TestRawCapturePurgeRejectsNonCanonicalRowsAndTriggersBeforeDelete(t *testing.T) {
	t.Run("storage-class", func(t *testing.T) {
		now := time.Date(2026, 8, 9, 11, 15, 0, 0, time.UTC)
		store, _, _ := openRawCapturePurgeFixture(t, "noncanonical-storage", now)
		if _, err := store.db.Exec(`UPDATE raw_request_captures SET id = CAST(id AS BLOB)`); err != nil {
			t.Fatal(err)
		}
		deleted, purgeErr := store.PurgeRawCaptures(context.Background())
		if deleted != 0 || purgeErr == nil || !strings.Contains(purgeErr.Error(), "non-canonical SQLite storage classes") {
			t.Fatalf("noncanonical purge deleted=%d error=%v", deleted, purgeErr)
		}
		var count int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM raw_request_captures").Scan(&count); err != nil || count != 1 {
			t.Fatalf("noncanonical rows count=%d error=%v", count, err)
		}
	})

	t.Run("trigger", func(t *testing.T) {
		now := time.Date(2026, 8, 9, 11, 30, 0, 0, time.UTC)
		store, _, _ := openRawCapturePurgeFixture(t, "noncanonical-trigger", now)
		if _, err := store.db.Exec(`CREATE TRIGGER purge_side_effect AFTER DELETE ON raw_request_captures
BEGIN
    DELETE FROM audit_events WHERE id = OLD.event_id;
END`); err != nil {
			t.Fatal(err)
		}
		deleted, purgeErr := store.PurgeRawCaptures(context.Background())
		if deleted != 0 || purgeErr == nil || !strings.Contains(purgeErr.Error(), "non-project SQLite trigger") {
			t.Fatalf("trigger purge deleted=%d error=%v", deleted, purgeErr)
		}
		var captures, events int
		if err := store.db.QueryRow("SELECT COUNT(*) FROM raw_request_captures").Scan(&captures); err != nil {
			t.Fatal(err)
		}
		if err := store.db.QueryRow("SELECT COUNT(*) FROM audit_events").Scan(&events); err != nil {
			t.Fatal(err)
		}
		if captures != 1 || events != 1 {
			t.Fatalf("trigger preflight changed captures=%d events=%d", captures, events)
		}
	})
}

func TestRawCaptureCompensationRevalidatesTriggerContractBeforeInsertAndPreservesConcurrentB(t *testing.T) {
	now := time.Date(2026, 8, 9, 11, 45, 0, 0, time.UTC)
	store, path, before := openRawCapturePurgeFixture(t, "compensation-trigger-drift", now)
	if _, err := store.db.Exec(`CREATE TABLE raw_capture_compensation_copies (id TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	reader := holdRawCapturePurgeReader(t, path, 1)
	readerOpen := true
	t.Cleanup(func() {
		if readerOpen {
			_ = reader.Rollback()
		}
	})

	original := before.Captures[0]
	concurrentRaw := []byte(`{"messages":[{"role":"user","content":"concurrent B must survive compensation drift"}]}`)
	concurrentSHA := sha256.Sum256(concurrentRaw)
	var injected bool
	store.rawCapturePurgeHook = func(stage rawCapturePurgeStage) error {
		if stage != rawCapturePurgeBeforeCompensation || injected {
			return nil
		}
		injected = true
		if err := reader.Rollback(); err != nil {
			return fmt.Errorf("release checkpoint reader: %w", err)
		}
		readerOpen = false
		if _, err := store.db.Exec(`INSERT INTO audit_events (
    id, timestamp_ns, action, mode, category, risk_score, rule_ids,
    request_hash, subject_hash, model, source_format, stream,
    text_bytes_scanned, classifier, decision, coverage, incomplete_reason,
    scanner, latency_us, decision_explanation, disposition, explanation_schema
) SELECT ?, timestamp_ns, action, mode, category, risk_score, rule_ids,
    request_hash, subject_hash, model, source_format, stream,
    text_bytes_scanned, classifier, decision, coverage, incomplete_reason,
    scanner, latency_us, decision_explanation, disposition, explanation_schema
FROM audit_events WHERE id = ?`, "concurrent-event-b", original.EventID); err != nil {
			return fmt.Errorf("insert concurrent event B: %w", err)
		}
		if _, err := store.db.Exec(restoreRawCaptureSQL,
			"concurrent-capture-b", "concurrent-event-b", now.Add(time.Second).UnixNano(),
			HashRequest(concurrentRaw), original.SubjectHash, original.Action, original.Decision,
			0, 1, concurrentRaw, "sha256:"+hex.EncodeToString(concurrentSHA[:]), 0,
			rawCaptureRedactionVersion, original.DecisionKind, original.ExplanationSchema,
		); err != nil {
			return fmt.Errorf("insert concurrent capture B: %w", err)
		}
		if _, err := store.db.Exec(`CREATE TRIGGER compensation_copy_attack
AFTER INSERT ON raw_request_captures
BEGIN
    INSERT INTO raw_capture_compensation_copies(id) VALUES (NEW.id);
END`); err != nil {
			return fmt.Errorf("install concurrent compensation trigger: %w", err)
		}
		return nil
	}

	deleted, purgeErr := store.PurgeRawCaptures(context.Background())
	if deleted != 1 || !errors.Is(purgeErr, ErrRawCapturePurgeUnrecovered) ||
		!strings.Contains(purgeErr.Error(), errRawCaptureCompensationContractDrift.Error()) {
		t.Fatalf("compensation drift purge deleted=%d error=%v", deleted, purgeErr)
	}
	var captureID, preview string
	if err := store.db.QueryRow(`SELECT id, raw_preview FROM raw_request_captures`).Scan(&captureID, &preview); err != nil {
		t.Fatal(err)
	}
	if captureID != "concurrent-capture-b" || preview != string(concurrentRaw) {
		t.Fatalf("concurrent B changed: id=%q preview=%q", captureID, preview)
	}
	var copies int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM raw_capture_compensation_copies`).Scan(&copies); err != nil {
		t.Fatal(err)
	}
	if copies != 0 {
		t.Fatalf("compensation executed attacker trigger copies=%d, want 0", copies)
	}
	if err := store.RecordRawCapture(RawCaptureInput{}); !errors.Is(err, ErrRawCapturePurgeUnrecovered) {
		t.Fatalf("contract drift did not latch raw writes: %v", err)
	}
}

func openRawCapturePurgeFixture(t testing.TB, name string, now time.Time) (*Store, string, RawCapturePage) {
	t.Helper()
	path := filepath.Join(t.TempDir(), name+".db")
	store, err := Open(Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		QueueSize: 16, BusyTimeout: 25 * time.Millisecond, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	raw := []byte(`{"messages":[{"role":"user","content":"` + name + ` A review text"}]}`)
	event := rawCaptureEvent(name+"-a", now, "block", "block_malicious_text", raw)
	if accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision, RawRequest: raw,
	}); err != nil || !accepted {
		t.Fatalf("EnqueueEventWithRawCapture() accepted=%t error=%v", accepted, err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("fixture captures=%#v error=%v", page, err)
	}
	return store, path, page
}

func holdRawCapturePurgeReader(t testing.TB, path string, want int) *sql.Tx {
	t.Helper()
	reader, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?_busy_timeout=25")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reader.Close() })
	reader.SetMaxOpenConns(1)
	tx, err := reader.Begin()
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRow("SELECT COUNT(*) FROM raw_request_captures").Scan(&count); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if count != want {
		_ = tx.Rollback()
		t.Fatalf("reader snapshot count=%d, want %d", count, want)
	}
	return tx
}

func rawCaptureEvent(id string, timestamp time.Time, action, decision string, raw []byte) Event {
	return Event{
		ID: id, Timestamp: timestamp, Action: action, Mode: "balanced",
		Category: "exploitation", RiskScore: 80, RequestHash: HashRequest(raw),
		SubjectHash: testSubjectHash("subject-" + id), Classifier: "raw-capture-test",
		Decision: decision, Coverage: "complete", Scanner: "streaming-scanner-v1",
	}
}
