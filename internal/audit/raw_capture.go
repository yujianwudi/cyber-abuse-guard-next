package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	defaultRawCaptureBytes = 8192
	maxRawCaptureBytes     = 1 << 20
	defaultRawCaptureLimit = 20
	maxRawCaptureLimit     = 100
	// Redaction inspects a bounded tail beyond the stored preview so labels,
	// delimiters, and secret values split at max_bytes are still visible to the
	// best-effort rules without running every regexp over a near-8 MiB request.
	rawCaptureRedactionOverlapBytes = 64 << 10

	// RawCaptureQueryPreviewBudgetBytes is a hard scan-time bound shared by the
	// audit store and management API. It is intentionally independent from the
	// current per-record capture setting because a database may contain larger
	// previews written before a configuration downgrade.
	RawCaptureQueryPreviewBudgetBytes = 8 << 20
	rawCaptureRedactionVersion        = "raw-redactor-v2"
	priorRawCaptureRedactionVersion   = "raw-redactor-v1"
	legacyRawCaptureRedactionVersion  = "legacy-boolean-v0"
	rawCapturePurgeRecoveryTimeout    = 30 * time.Second
	// Snapshotting is deliberately fail-closed before DELETE. The configured
	// live-database cap may be as high as 10 GiB, which is not a safe transient
	// heap allocation for a hot reconfiguration.
	maxRawCapturePurgeSnapshotBytes int64 = 256 << 20
	rawCapturePurgeRowOverheadBytes int64 = 256
	maxRawCapturePurgeSnapshotRows  int64 = 100000
)

const rawCapturePurgeSelect = `SELECT
    id, event_id, timestamp_ns, request_hash, subject_hash, action, decision,
    truncated, redacted, raw_preview, raw_sha256, redaction_pattern_hits,
    redaction_version, decision_kind, explanation_schema
FROM raw_request_captures
ORDER BY id`

const restoreRawCaptureSQL = `INSERT OR IGNORE INTO raw_request_captures (
    id, event_id, timestamp_ns, request_hash, subject_hash, action, decision,
    truncated, redacted, raw_preview, raw_sha256, redaction_pattern_hits,
    redaction_version, decision_kind, explanation_schema
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CAST(? AS TEXT), ?, ?, ?, ?, ?)`

const rawCapturePurgeSnapshotSizeSQL = `SELECT COUNT(*), COALESCE(SUM(
    256 +
    length(CAST(id AS BLOB)) + length(CAST(event_id AS BLOB)) +
    length(CAST(request_hash AS BLOB)) + length(CAST(subject_hash AS BLOB)) +
    length(CAST(action AS BLOB)) + length(CAST(decision AS BLOB)) +
    length(CAST(raw_preview AS BLOB)) + length(CAST(raw_sha256 AS BLOB)) +
    length(CAST(redaction_version AS BLOB)) + length(CAST(decision_kind AS BLOB)) +
    length(CAST(explanation_schema AS BLOB))
), 0) FROM raw_request_captures`

const rawCapturePurgeNonCanonicalRowsSQL = `SELECT COUNT(*)
FROM raw_request_captures
WHERE id IS NULL OR typeof(id) <> 'text'
   OR event_id IS NULL OR typeof(event_id) <> 'text'
   OR typeof(timestamp_ns) <> 'integer'
   OR typeof(request_hash) <> 'text'
   OR typeof(subject_hash) <> 'text'
   OR typeof(action) <> 'text'
   OR typeof(decision) <> 'text'
   OR typeof(truncated) <> 'integer'
   OR typeof(redacted) <> 'integer'
   OR typeof(raw_preview) <> 'text'
   OR typeof(raw_sha256) <> 'text'
   OR typeof(redaction_pattern_hits) <> 'integer'
   OR typeof(redaction_version) <> 'text'
   OR typeof(decision_kind) <> 'text'
   OR typeof(explanation_schema) <> 'text'`

type rawCapturePurgeStage uint8

const (
	rawCapturePurgeAfterPreflight rawCapturePurgeStage = iota + 1
	rawCapturePurgeBeforePreflightCheckpoint
	rawCapturePurgeAfterPreflightCheckpoint
	rawCapturePurgeBeforeCompensation
	rawCapturePurgeBeforeCompensationCommit
	rawCapturePurgeAfterCompensationCommit
	rawCapturePurgeBeforeCompensationRollback
	rawCapturePurgeFreshVerification
)

var (
	ErrRawCaptureDisabled = errors.New("audit: raw request capture is disabled")
	ErrInvalidRawCapture  = errors.New("audit: invalid raw request capture")
)

var errRawCaptureCompensationContractDrift = errors.New("audit: raw capture compensation storage contract drifted")

// RawCaptureConfig bounds the explicit operator-only review capture. OnlyBlocked
// and RedactSecrets are invariant safety switches: withDefaults forces both on
// even for direct package callers that bypass the validated YAML configuration.
type RawCaptureConfig struct {
	Enabled       bool
	OnlyBlocked   bool
	MaxBytes      int
	TTL           time.Duration
	RedactSecrets bool
}

// RawCaptureInput is the transient input accepted after a final block decision.
// RawRequest is converted immediately into a redacted, bounded preview before
// it can enter the asynchronous queue.
type RawCaptureInput struct {
	EventID           string
	Timestamp         time.Time
	RequestHash       string
	SubjectHash       string
	Action            string
	Decision          string
	DecisionKind      string
	ExplanationSchema string
	RawRequest        []byte
}

// RawRequestCapture is the only sensitive request-text model exposed to the
// management layer. RawPreview is always produced with secret redaction enabled
// and is bounded by RawCaptureConfig.MaxBytes.
type RawRequestCapture struct {
	ID                string    `json:"id"`
	EventID           string    `json:"event_id"`
	Timestamp         time.Time `json:"timestamp"`
	RequestHash       string    `json:"request_hash,omitempty"`
	SubjectHash       string    `json:"subject_hash,omitempty"`
	Action            string    `json:"action"`
	Decision          string    `json:"decision"`
	DecisionKind      string    `json:"decision_kind"`
	ExplanationSchema string    `json:"explanation_schema"`
	Truncated         bool      `json:"truncated"`
	Redacted          bool      `json:"redacted"`
	// PreviewTruncated and RedactionApplied are the canonical names. Truncated
	// and Redacted remain compatibility aliases for existing management clients.
	PreviewTruncated     bool   `json:"preview_truncated"`
	RedactionApplied     bool   `json:"redaction_applied"`
	RedactionPatternHits int    `json:"redaction_pattern_hits"`
	RedactionVersion     string `json:"redaction_version"`
	RawPreview           string `json:"raw_preview"`
	RawSHA256            string `json:"raw_sha256"`
	deduplicated         bool
}

// RawCaptureQuery is deliberately narrow. Sensitive captures may be correlated
// by their event or request digest only; broad listing is capped at 100 rows.
type RawCaptureQuery struct {
	EventID     string `json:"event_id,omitempty"`
	RequestHash string `json:"request_hash,omitempty"`
	Limit       int    `json:"limit,omitempty"`
}

// RawCapturePage is a scan-bounded page of sensitive previews. HasMore is set
// after scanning at most one non-returned sentinel row, either because the row
// limit or the cumulative raw-preview byte budget was reached.
type RawCapturePage struct {
	Captures     []RawRequestCapture
	PreviewBytes int
	HasMore      bool
}

type rawCaptureRedactor struct {
	expression  *regexp.Regexp
	replacement string
}

var rawCaptureRedactors = []rawCaptureRedactor{
	{
		expression:  regexp.MustCompile(`(?im)^([\t ]*(?:auth|authorization|proxy-authorization|cookie|set-cookie)[\t ]*:[\t ]*)[^\r\n]*`),
		replacement: `${1}[REDACTED]`,
	},
	{
		expression:  regexp.MustCompile(`(?i)(["']?(?:cookie|set[-_]?cookie)["']?[\t ]*[:=][\t ]*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n&}\]]+)`),
		replacement: `${1}"[REDACTED]"`,
	},
	{
		expression:  regexp.MustCompile(`(?i)(["']?(?:auth|authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|api[-_]?key|apikey|access[-_]?token|refresh[-_]?token|session[-_]?token|password|passwd|secret|client[-_]?secret)["']?[\t ]*[:=][\t ]*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n,;&}\]]+)`),
		replacement: `${1}"[REDACTED]"`,
	},
	{
		expression:  regexp.MustCompile(`(?i)(\bbearer[\t ]+)[A-Za-z0-9._~+/=-]{8,}`),
		replacement: `${1}[REDACTED]`,
	},
	{
		expression:  regexp.MustCompile(`(?i)(\b(?:auth|password|passwd|api[ _-]?key|access[ _-]?token|refresh[ _-]?token|session[ _-]?token|client[ _-]?secret|secret|cookie)\b[\t ]+(?:is|was)[\t ]+)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;&}\]]+)`),
		replacement: `${1}[REDACTED]`,
	},
	{
		expression:  regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{8,}\b`),
		replacement: `[REDACTED-API-KEY]`,
	},
	{
		expression:  regexp.MustCompile(`(?i)\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{8,}\b`),
		replacement: `[REDACTED-API-KEY]`,
	},
	{
		expression:  regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		replacement: `[REDACTED-ACCESS-KEY]`,
	},
	{
		expression:  regexp.MustCompile(`(?i)\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b`),
		replacement: `[REDACTED-ACCESS-TOKEN]`,
	},
	{
		expression:  regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b`),
		replacement: `[REDACTED-JWT]`,
	},
	{
		expression:  regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|$)`), // repo-secret-scan: allow redaction-pattern
		replacement: `-----BEGIN PRIVATE KEY-----[REDACTED]-----END PRIVATE KEY-----`,                                                        // repo-secret-scan: allow redaction-pattern
	},
}

const insertRawCaptureSQL = `INSERT INTO raw_request_captures (
    id, event_id, timestamp_ns, request_hash, subject_hash, action, decision,
    truncated, redacted, raw_preview, raw_sha256, redaction_pattern_hits,
    redaction_version, decision_kind, explanation_schema
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(raw_sha256) WHERE raw_sha256 <> '' DO NOTHING`

// RecordRawCapture performs a bounded, nonblocking enqueue. The associated
// audit Event must be enqueued first with the same EventID; the shared queue
// then preserves write order and the schema foreign key prevents orphan text.
func (s *Store) RecordRawCapture(input RawCaptureInput) error {
	if s == nil || !s.activated.Load() {
		return ErrUnavailable
	}
	s.rawAdmissionMu.RLock()
	defer s.rawAdmissionMu.RUnlock()
	if !s.cfg.RawCapture.Enabled {
		return ErrRawCaptureDisabled
	}
	if s.rawCaptureWriteBlocked.Load() {
		s.rejected.Add(1)
		s.rawRejected.Add(1)
		return ErrRawCapturePurgeUnrecovered
	}
	if err := s.rejectCapacityAdmission(1, 1); err != nil {
		return err
	}
	if err := s.checkStorageAccess(); err != nil {
		s.rejected.Add(1)
		s.rawRejected.Add(1)
		return err
	}
	// Reserve bounded capacity before converting, redacting, hashing, or
	// truncating the request body. A saturated writer therefore rejects a large
	// blocked request in constant time instead of repeating full-body work that
	// cannot be persisted.
	if err := s.reserveAdmission(); err != nil {
		s.observeRawCaptureAdmission(err)
		if errors.Is(err, ErrQueueFull) {
			s.dropped.Add(1)
			s.rawDropped.Add(1)
		}
		return err
	}
	admissionOwned := true
	defer func() {
		if admissionOwned {
			s.cancelAdmission()
		}
	}()
	s.observeRawCaptureAdmission(nil)
	prepared, err := s.prepareRawCaptureObserved(input)
	if err != nil {
		s.rejected.Add(1)
		s.rawRejected.Add(1)
		return fmt.Errorf("%w: %v", ErrInvalidRawCapture, err)
	}
	s.enqueued.Add(1)
	s.rawEnqueued.Add(1)
	admissionOwned = false
	s.publishAdmission(workItem{rawCapture: &prepared})
	return nil
}

// EnqueueEventWithRawCapture atomically admits one ordinary blocking event and
// its optional review preview as a single queue work item. The event and capture
// cannot be interleaved by another producer and the worker writes them in one
// SQLite transaction. The bool reports whether the ordinary event was accepted;
// on capture validation failure the event is still queued by itself.
func (s *Store) EnqueueEventWithRawCapture(event Event, input RawCaptureInput) (bool, error) {
	if s == nil || !s.activated.Load() {
		return false, ErrUnavailable
	}
	s.rawAdmissionMu.RLock()
	defer s.rawAdmissionMu.RUnlock()
	if !s.cfg.RawCapture.Enabled {
		return false, ErrRawCaptureDisabled
	}
	if s.rawCaptureWriteBlocked.Load() {
		s.rejected.Add(2)
		s.rawRejected.Add(1)
		return false, ErrRawCapturePurgeUnrecovered
	}
	if err := s.rejectCapacityAdmission(2, 1); err != nil {
		return false, err
	}
	if err := s.checkStorageAccess(); err != nil {
		s.rejected.Add(2)
		s.rawRejected.Add(1)
		return false, err
	}
	preparedEvent, err := prepareEvent(event, s.cfg.Now())
	if err != nil {
		s.rejected.Add(1)
		return false, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	if input.DecisionKind == "" {
		input.DecisionKind = preparedEvent.DecisionKind
	}
	if input.ExplanationSchema == "" {
		input.ExplanationSchema = preparedEvent.ExplanationSchema
	}
	if err := s.reserveAdmission(); err != nil {
		s.observeRawCaptureAdmission(err)
		if errors.Is(err, ErrQueueFull) {
			// Two logical records were rejected by one composite admission.
			s.dropped.Add(2)
			s.rawDropped.Add(1)
		}
		return false, err
	}
	admissionOwned := true
	defer func() {
		if admissionOwned {
			s.cancelAdmission()
		}
	}()
	s.observeRawCaptureAdmission(nil)
	if err := validateRawCapturePair(preparedEvent, input); err != nil {
		s.rejected.Add(1)
		s.rawRejected.Add(1)
		s.enqueued.Add(1)
		admissionOwned = false
		s.publishAdmission(workItem{event: &preparedEvent})
		return true, fmt.Errorf("%w: %v", ErrInvalidRawCapture, err)
	}
	preparedCapture, err := s.prepareRawCaptureObserved(input)
	if err != nil {
		s.rejected.Add(1)
		s.rawRejected.Add(1)
		s.enqueued.Add(1)
		admissionOwned = false
		s.publishAdmission(workItem{event: &preparedEvent})
		return true, fmt.Errorf("%w: %v", ErrInvalidRawCapture, err)
	}
	s.enqueued.Add(2)
	s.rawEnqueued.Add(1)
	admissionOwned = false
	s.publishAdmission(workItem{event: &preparedEvent, rawCapture: &preparedCapture})
	return true, nil
}

func validateRawCapturePair(event Event, input RawCaptureInput) error {
	if rawCaptureDecisionKindForbidden(input.DecisionKind) || rawCaptureDecisionKindForbidden(event.DecisionKind) {
		return errors.New("raw capture is forbidden for CSAM-text decisions")
	}
	if event.ID != input.EventID {
		return errors.New("raw capture event_id does not match its audit event")
	}
	if event.Action != input.Action {
		return errors.New("raw capture action does not match its audit event")
	}
	if event.Decision != input.Decision {
		return errors.New("raw capture decision does not match its audit event")
	}
	if event.DecisionKind != input.DecisionKind {
		return errors.New("raw capture decision_kind does not match its audit event")
	}
	if event.ExplanationSchema != input.ExplanationSchema {
		return errors.New("raw capture explanation_schema does not match its audit event")
	}
	if input.Timestamp.IsZero() || !event.Timestamp.Equal(input.Timestamp) {
		return errors.New("raw capture timestamp does not match its audit event")
	}
	if event.RequestHash != input.RequestHash {
		return errors.New("raw capture request_hash does not match its audit event")
	}
	if event.SubjectHash != input.SubjectHash {
		return errors.New("raw capture subject_hash does not match its audit event")
	}
	return nil
}

func (s *Store) prepareRawCaptureObserved(input RawCaptureInput) (RawRequestCapture, error) {
	started := time.Now()
	prepared, err := prepareRawCapture(input, s.cfg.RawCapture, s.cfg.Now())
	elapsedUS := uint64(time.Since(started).Microseconds())
	if elapsedUS == 0 {
		elapsedUS = 1
	}
	s.rawPrepareCount.Add(1)
	s.rawPrepareTotalUS.Add(elapsedUS)
	s.rawPrepareLastUS.Store(elapsedUS)
	for {
		current := s.rawPrepareMaxUS.Load()
		if elapsedUS <= current || s.rawPrepareMaxUS.CompareAndSwap(current, elapsedUS) {
			break
		}
	}
	return prepared, err
}

func (s *Store) observeRawCaptureAdmission(admissionErr error) {
	depth := len(s.queueSlots)
	if errors.Is(admissionErr, ErrQueueFull) {
		// A full-channel select is the authoritative saturation observation. The
		// writer may release a token before this goroutine samples len(), so using
		// the capacity here preserves the promised saturated-attempt high-water.
		depth = cap(s.queueSlots)
	}
	s.observeRawCaptureQueueDepth(uint64(depth))
}

func (s *Store) observeRawCaptureQueueDepth(depth uint64) {
	for {
		current := s.rawQueueHighWater.Load()
		if depth <= current || s.rawQueueHighWater.CompareAndSwap(current, depth) {
			return
		}
	}
}

// QueryRawCaptures returns the captures from a bounded page. Callers that need
// to distinguish a complete page from a byte/row-budget truncation should use
// QueryRawCapturesPage.
func (s *Store) QueryRawCaptures(ctx context.Context, query RawCaptureQuery) ([]RawRequestCapture, error) {
	page, err := s.QueryRawCapturesPage(ctx, query)
	if err != nil {
		return nil, err
	}
	return page.Captures, nil
}

func rollbackRawCaptureTransactionOrDiscard(conn *sql.Conn) {
	if conn == nil {
		return
	}
	if _, err := conn.ExecContext(context.Background(), "ROLLBACK"); err != nil {
		// These transactions begin through raw SQL, so database/sql cannot know
		// that a failed rollback left the driver connection in an indeterminate
		// state. Mark it bad before Conn.Close can return it to the pool.
		discardSQLiteConnection(conn)
	}
}

// QueryRawCapturesPage returns recent sensitive previews while enforcing both
// the 100-row API cap and a fixed 8 MiB cumulative raw-preview scan budget. SQL
// is limited to one extra row so HasMore never requires materializing the rest
// of a large result set.
func (s *Store) QueryRawCapturesPage(ctx context.Context, query RawCaptureQuery) (RawCapturePage, error) {
	if s == nil {
		return RawCapturePage{}, fmt.Errorf("%w: raw capture Store is unavailable", ErrStorageBlocked)
	}
	s.sendMu.RLock()
	closed := s.closed
	s.sendMu.RUnlock()
	if closed || !s.activated.Load() || s.db == nil {
		return RawCapturePage{}, fmt.Errorf("%w: raw capture Store is not active", ErrStorageBlocked)
	}
	where, args, err := rawCaptureWhere(query)
	if err != nil {
		return RawCapturePage{}, err
	}
	limit := query.Limit
	if limit <= 0 {
		limit = defaultRawCaptureLimit
	}
	if limit > maxRawCaptureLimit {
		limit = maxRawCaptureLimit
	}
	args = append(args, limit+1)
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return RawCapturePage{}, fmt.Errorf("%w: acquire raw capture read connection: %v", ErrStorageBlocked, err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, "BEGIN"); err != nil {
		discardSQLiteConnection(conn)
		return RawCapturePage{}, fmt.Errorf("%w: begin raw capture read transaction: %v", ErrStorageBlocked, err)
	}
	transactionOpen := true
	defer func() {
		if transactionOpen {
			rollbackRawCaptureTransactionOrDiscard(conn)
		}
	}()
	// SQLite BEGIN is deferred and does not establish a read snapshot by itself.
	// Touch sqlite_schema on this same connection before the independent storage
	// gate so a concurrent WAL writer cannot change the rows visible between the
	// gate and the sensitive preview SELECT. This remains a read-only transaction;
	// BEGIN IMMEDIATE would reserve the writer and can block the audit worker.
	var schemaObjects int64
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM sqlite_schema").Scan(&schemaObjects); err != nil {
		return RawCapturePage{}, fmt.Errorf("%w: pin raw capture read snapshot: %v", ErrStorageBlocked, err)
	}
	// Runtime implementations must force a fresh pathname/mount/object probe
	// here; a cached write verdict is not authority to release sensitive previews.
	if err := s.checkSensitiveReadStorageAccess(); err != nil {
		_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
		transactionOpen = false
		discardSQLiteConnection(conn)
		return RawCapturePage{}, err
	}
	rows, err := conn.QueryContext(ctx, `SELECT id, event_id, timestamp_ns, request_hash,
subject_hash, action, decision, truncated, redacted, raw_preview, raw_sha256,
redaction_pattern_hits, redaction_version, decision_kind, explanation_schema
FROM raw_request_captures`+where+` ORDER BY timestamp_ns DESC, id DESC LIMIT ?`, args...)
	if err != nil {
		return RawCapturePage{}, fmt.Errorf("audit: query raw request captures: %w", err)
	}
	defer rows.Close()
	page := RawCapturePage{Captures: make([]RawRequestCapture, 0, limit)}
	for rows.Next() {
		var capture RawRequestCapture
		var timestampNS int64
		var truncated, redacted int
		if err := rows.Scan(
			&capture.ID, &capture.EventID, &timestampNS, &capture.RequestHash,
			&capture.SubjectHash, &capture.Action, &capture.Decision, &truncated,
			&redacted, &capture.RawPreview, &capture.RawSHA256,
			&capture.RedactionPatternHits, &capture.RedactionVersion,
			&capture.DecisionKind, &capture.ExplanationSchema,
		); err != nil {
			return RawCapturePage{}, fmt.Errorf("audit: scan raw request capture: %w", err)
		}
		capture.Timestamp = time.Unix(0, timestampNS).UTC()
		capture.Truncated = truncated != 0
		capture.Redacted = redacted != 0
		capture.PreviewTruncated = capture.Truncated
		capture.RedactionApplied = capture.Redacted
		if err := validateRawRequestCapture(capture); err != nil {
			return RawCapturePage{}, fmt.Errorf("audit: invalid persisted raw request capture: %w", err)
		}
		if len(page.Captures) >= limit || len(capture.RawPreview) > RawCaptureQueryPreviewBudgetBytes-page.PreviewBytes {
			page.HasMore = true
			break
		}
		page.Captures = append(page.Captures, capture)
		page.PreviewBytes += len(capture.RawPreview)
	}
	if err := rows.Err(); err != nil {
		return RawCapturePage{}, fmt.Errorf("audit: iterate raw request captures: %w", err)
	}
	if err := rows.Close(); err != nil {
		return RawCapturePage{}, fmt.Errorf("audit: close raw request capture rows: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		discardSQLiteConnection(conn)
		return RawCapturePage{}, fmt.Errorf("%w: commit raw capture read transaction: %v", ErrStorageBlocked, err)
	}
	transactionOpen = false
	return page, nil
}

// PurgeRawCaptures drains work already accepted by this Store, removes every
// retained request preview, and truncates the WAL. It is used when capture is
// disabled so sensitive rows do not become hidden-but-retained data. A purge
// failure degrades audit readiness but never changes classification policy.
func (s *Store) PurgeRawCaptures(ctx context.Context) (int64, error) {
	if s == nil || s.db == nil {
		return 0, ErrUnavailable
	}
	// Lock order is raw admission -> queue drain -> maintenance. Producers that
	// include a raw preview cannot publish behind the drain barrier and cannot
	// complete until purge/checkpoint/compensation has reached a final state.
	s.rawAdmissionMu.Lock()
	defer s.rawAdmissionMu.Unlock()
	if err := s.checkStorageAccess(); err != nil {
		return 0, err
	}
	if err := s.Flush(ctx); err != nil {
		return 0, s.rawCaptureMaintenanceFailure(fmt.Errorf("audit: flush before raw capture purge: %w", err))
	}
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	deleted, err := s.purgeRawCapturesLocked(ctx)
	if err != nil {
		return deleted, err
	}
	// The purge is already committed. A residual capacity condition remains
	// visible through Status without turning successful sensitive-data removal
	// into a misleading operation failure.
	_ = s.remeasureCapacityMaintenanceLocked(ctx)
	return deleted, nil
}

// purgeRawCaptures is the startup form used before the writer goroutine starts.
// Callers that may have queued work must use PurgeRawCaptures instead.
func (s *Store) purgeRawCaptures(ctx context.Context) (int64, error) {
	s.maintenanceMu.Lock()
	defer s.maintenanceMu.Unlock()
	return s.purgeRawCapturesLocked(ctx)
}

func (s *Store) purgeRawCapturesLocked(ctx context.Context) (int64, error) {
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return 0, s.rawCaptureMaintenanceFailure(fmt.Errorf("audit: acquire raw capture purge connection: %w", err))
	}
	defer conn.Close()
	if err := s.preflightRawCapturePurge(ctx, conn); err != nil {
		return 0, s.rawCaptureMaintenanceFailure(err)
	}
	if err := s.runRawCapturePurgeHook(rawCapturePurgeAfterPreflight); err != nil {
		return 0, s.rawCaptureMaintenanceFailure(fmt.Errorf("audit: raw capture purge pre-delete hook: %w", err))
	}

	// A truncating WAL checkpoint cannot participate in the transaction that
	// deletes the rows. Keep an exact, process-memory-only copy of the already
	// redacted and bounded previews until every post-commit privacy gate passes.
	// If a later gate fails, a compensating transaction restores the visible
	// table before the caller is told that the purge failed.
	snapshot, deleted, err := deleteRawCapturesWithSnapshot(ctx, conn, maxRawCapturePurgeSnapshotBytes)
	defer wipeRawCapturePurgeRows(snapshot)
	if err != nil {
		if snapshot == nil {
			return 0, s.rawCaptureMaintenanceFailure(err)
		}
		return s.rollbackRawCapturePurge(conn, snapshot, deleted, err)
	}
	var busy, logFrames, checkpointedFrames int
	if err := conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointedFrames); err != nil {
		return s.rollbackRawCapturePurge(conn, snapshot, deleted,
			fmt.Errorf("audit: checkpoint purged raw request captures: %w", err))
	}
	if busy != 0 {
		return s.rollbackRawCapturePurge(conn, snapshot, deleted,
			fmt.Errorf("audit: raw request capture purge WAL checkpoint remained busy (busy=%d log=%d checkpointed=%d)",
				busy, logFrames, checkpointedFrames))
	}
	if logFrames != checkpointedFrames {
		return s.rollbackRawCapturePurge(conn, snapshot, deleted,
			fmt.Errorf("audit: raw request capture purge WAL checkpoint was incomplete (log=%d checkpointed=%d)",
				logFrames, checkpointedFrames))
	}
	if err := secureSQLiteFiles(s.cfg.Path, !s.cfg.RequirePersistentStorage); err != nil {
		// The logical rows can be restored, but a post-commit file-security
		// failure means SQLite may already have copied sensitive pages into an
		// unsafe artifact. Keep readiness failed and reject every later raw write.
		s.rawCaptureWriteBlocked.Store(true)
		return s.rollbackRawCapturePurge(conn, snapshot, deleted, err)
	}
	if deleted > 0 {
		s.cleaned.Add(uint64(deleted))
	}
	if !s.overLimit.Load() && !s.rawCaptureWriteBlocked.Load() {
		s.degraded.Store(false)
		s.lastErr.Store("")
	}
	return deleted, nil
}

func (s *Store) preflightRawCapturePurge(ctx context.Context, conn *sql.Conn) error {
	if err := secureSQLiteFiles(s.cfg.Path, !s.cfg.RequirePersistentStorage); err != nil {
		s.rawCaptureWriteBlocked.Store(true)
		return fmt.Errorf("audit: purge raw request captures first preflight file security: %w", err)
	}
	if err := s.runRawCapturePurgeHook(rawCapturePurgeBeforePreflightCheckpoint); err != nil {
		return fmt.Errorf("audit: raw capture purge before preflight checkpoint: %w", err)
	}
	var busy, logFrames, checkpointedFrames int
	checkpointErr := conn.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &logFrames, &checkpointedFrames)
	hookErr := s.runRawCapturePurgeHook(rawCapturePurgeAfterPreflightCheckpoint)
	securityErr := secureSQLiteFiles(s.cfg.Path, !s.cfg.RequirePersistentStorage)
	if securityErr != nil {
		s.rawCaptureWriteBlocked.Store(true)
	}
	var checkpointStateErr error
	if checkpointErr == nil && (busy != 0 || logFrames != checkpointedFrames) {
		checkpointStateErr = fmt.Errorf(
			"audit: purge raw request captures preflight WAL checkpoint incomplete (busy=%d log=%d checkpointed=%d)",
			busy, logFrames, checkpointedFrames,
		)
	}
	if checkpointErr != nil {
		return errors.Join(
			fmt.Errorf("audit: purge raw request captures preflight WAL checkpoint: %w", checkpointErr),
			wrapRawCapturePurgeHookError("after preflight checkpoint", hookErr),
			wrapRawCapturePurgeSecurityError("second preflight file security", securityErr),
		)
	}
	if err := errors.Join(
		wrapRawCapturePurgeHookError("after preflight checkpoint", hookErr),
		wrapRawCapturePurgeSecurityError("second preflight file security", securityErr),
		checkpointStateErr,
	); err != nil {
		return err
	}
	return nil
}

func wrapRawCapturePurgeHookError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("audit: raw capture purge %s: %w", stage, err)
}

func wrapRawCapturePurgeSecurityError(stage string, err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("audit: purge raw request captures %s: %w", stage, err)
}

func (s *Store) runRawCapturePurgeHook(stage rawCapturePurgeStage) error {
	if s.rawCapturePurgeHook == nil {
		return nil
	}
	return s.rawCapturePurgeHook(stage)
}

type rawCapturePurgeRow struct {
	id                   string
	eventID              string
	timestampNS          int64
	requestHash          string
	subjectHash          string
	action               string
	decision             string
	truncated            int64
	redacted             int64
	rawPreview           []byte
	rawSHA256            string
	redactionPatternHits int64
	redactionVersion     string
	decisionKind         string
	explanationSchema    string
}

func deleteRawCapturesWithSnapshot(
	ctx context.Context,
	conn *sql.Conn,
	snapshotLimit int64,
) ([]rawCapturePurgeRow, int64, error) {
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return nil, 0, fmt.Errorf("audit: begin purge raw request captures transaction: %w", err)
	}
	transactionOpen := true
	defer func() {
		if transactionOpen {
			rollbackRawCaptureTransactionOrDiscard(conn)
		}
	}()

	if err := validateRawCapturePurgeDataContract(ctx, conn); err != nil {
		return nil, 0, err
	}
	var rowCount, snapshotBytes int64
	if err := conn.QueryRowContext(ctx, rawCapturePurgeSnapshotSizeSQL).Scan(&rowCount, &snapshotBytes); err != nil {
		return nil, 0, fmt.Errorf("audit: size raw capture purge snapshot: %w", err)
	}
	if rowCount < 0 || rowCount > maxRawCapturePurgeSnapshotRows ||
		snapshotBytes < 0 || snapshotBytes > snapshotLimit {
		return nil, 0, fmt.Errorf(
			"audit: raw capture purge snapshot exceeds in-memory safety bound (rows=%d bytes=%d limit=%d)",
			rowCount, snapshotBytes, snapshotLimit,
		)
	}
	snapshot, err := readRawCapturePurgeRows(ctx, conn, int(rowCount), snapshotLimit)
	if err != nil {
		return nil, 0, err
	}
	result, err := conn.ExecContext(ctx, "DELETE FROM raw_request_captures")
	if err != nil {
		wipeRawCapturePurgeRows(snapshot)
		return nil, 0, fmt.Errorf("audit: purge raw request captures: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		wipeRawCapturePurgeRows(snapshot)
		return nil, 0, fmt.Errorf("audit: count purged raw request captures: %w", err)
	}
	if _, err := conn.ExecContext(ctx, "COMMIT"); err != nil {
		transactionOpen = false
		rollbackRawCaptureTransactionOrDiscard(conn)
		return snapshot, deleted, fmt.Errorf("audit: commit purged raw request captures: %w", err)
	}
	transactionOpen = false
	return snapshot, deleted, nil
}

func validateRawCapturePurgeDataContract(ctx context.Context, conn *sql.Conn) error {
	var nonCanonicalRows int64
	if err := conn.QueryRowContext(ctx, rawCapturePurgeNonCanonicalRowsSQL).Scan(&nonCanonicalRows); err != nil {
		return fmt.Errorf("audit: inspect raw capture purge storage classes: %w", err)
	}
	if nonCanonicalRows != 0 {
		return fmt.Errorf("audit: raw capture purge rejected %d rows with non-canonical SQLite storage classes", nonCanonicalRows)
	}
	// The project schema deliberately owns no SQLite triggers. A trigger can run
	// unreviewed side effects during either the DELETE or compensating INSERT, so
	// every trigger is non-project state and invalidates this fail-closed
	// contract. Do not add an allowlist unless a migration introduces and schema
	// validation closes over an actual reviewed project trigger.
	var triggerName string
	err := conn.QueryRowContext(ctx, `SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name LIMIT 1`).Scan(&triggerName)
	if err == nil {
		return fmt.Errorf("audit: raw capture purge rejected non-project SQLite trigger %q", triggerName)
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("audit: inspect raw capture purge triggers: %w", err)
	}
	return nil
}

func readRawCapturePurgeRows(
	ctx context.Context,
	conn *sql.Conn,
	rowCount int,
	snapshotLimit int64,
) ([]rawCapturePurgeRow, error) {
	rows, err := conn.QueryContext(ctx, rawCapturePurgeSelect)
	if err != nil {
		return nil, fmt.Errorf("audit: snapshot raw request captures before purge: %w", err)
	}
	defer rows.Close()

	snapshot := make([]rawCapturePurgeRow, 0, rowCount)
	var snapshotBytes int64
	for rows.Next() {
		var row rawCapturePurgeRow
		if err := rows.Scan(
			&row.id, &row.eventID, &row.timestampNS, &row.requestHash, &row.subjectHash,
			&row.action, &row.decision, &row.truncated, &row.redacted, &row.rawPreview,
			&row.rawSHA256, &row.redactionPatternHits, &row.redactionVersion,
			&row.decisionKind, &row.explanationSchema,
		); err != nil {
			wipeBytes(row.rawPreview)
			wipeRawCapturePurgeRows(snapshot)
			return nil, fmt.Errorf("audit: scan raw request capture purge snapshot: %w", err)
		}
		if len(row.rawPreview) > maxRawCaptureBytes {
			wipeBytes(row.rawPreview)
			wipeRawCapturePurgeRows(snapshot)
			return nil, fmt.Errorf("audit: raw capture purge snapshot row exceeds %d bytes", maxRawCaptureBytes)
		}
		rowBytes := row.memoryBytes()
		if rowBytes < 0 || snapshotBytes > snapshotLimit-rowBytes {
			wipeBytes(row.rawPreview)
			wipeRawCapturePurgeRows(snapshot)
			return nil, fmt.Errorf("audit: raw capture purge snapshot exceeds %d in-memory bytes", snapshotLimit)
		}
		snapshotBytes += rowBytes
		snapshot = append(snapshot, row)
	}
	if err := rows.Err(); err != nil {
		wipeRawCapturePurgeRows(snapshot)
		return nil, fmt.Errorf("audit: iterate raw request capture purge snapshot: %w", err)
	}
	return snapshot, nil
}

func (s *Store) rollbackRawCapturePurge(
	conn *sql.Conn,
	snapshot []rawCapturePurgeRow,
	deleted int64,
	cause error,
) (int64, error) {
	recoveryCtx, cancel := context.WithTimeout(context.Background(), rawCapturePurgeRecoveryTimeout)
	defer cancel()
	recoveryErr := s.runRawCapturePurgeHook(rawCapturePurgeBeforeCompensation)
	if recoveryErr == nil {
		recoveryErr = s.restoreRawCapturePurgeRows(recoveryCtx, conn, snapshot)
	}
	if recoveryErr != nil {
		s.rawCaptureWriteBlocked.Store(true)
		return deleted, s.rawCaptureMaintenanceFailure(errors.Join(
			fmt.Errorf("%w after deleting %d rows", ErrRawCapturePurgeUnrecovered, deleted),
			cause,
			fmt.Errorf("audit: raw capture purge compensation: %w", recoveryErr),
		))
	}
	return 0, s.rawCaptureMaintenanceFailure(fmt.Errorf(
		"audit: raw request capture purge rolled back after deleting %d rows: %w", deleted, cause,
	))
}

func (s *Store) restoreRawCapturePurgeRows(ctx context.Context, conn *sql.Conn, snapshot []rawCapturePurgeRow) error {
	autoCommit, stateErr := sqliteConnectionAutoCommit(conn)
	if stateErr != nil {
		discardSQLiteConnection(conn)
		return fmt.Errorf("audit: inspect purge connection before compensation: %w", stateErr)
	}
	if !autoCommit {
		rollbackErr := s.rollbackRawCaptureCompensation(ctx, conn)
		autoCommit, stateErr = sqliteConnectionAutoCommit(conn)
		if stateErr != nil || !autoCommit {
			discardSQLiteConnection(conn)
			return errors.Join(
				errors.New("audit: purge connection could not recover autocommit before compensation"),
				rollbackErr,
				stateErr,
			)
		}
	}
	matches, err := s.freshRawCapturePurgeSnapshotVisible(ctx, snapshot)
	if err != nil {
		return fmt.Errorf("audit: verify persisted rows before purge compensation: %w", err)
	}
	if matches {
		return nil
	}
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return fmt.Errorf("audit: begin raw capture purge compensation: %w", err)
	}
	autoCommit, stateErr = sqliteConnectionAutoCommit(conn)
	if stateErr != nil || autoCommit {
		return s.abortRawCaptureCompensation(ctx, conn, errors.Join(
			errors.New("audit: raw capture purge compensation did not enter a transaction"),
			stateErr,
		))
	}
	// BEGIN IMMEDIATE excludes every concurrent schema/trigger writer for the
	// remainder of compensation. Revalidate the complete current schema and the
	// row/trigger contract on this exact connection and transaction before the
	// first INSERT. The pre-delete validation is intentionally not reused: a
	// different process can commit a trigger or schema change after DELETE.
	if err := validateRawCaptureCompensationContract(ctx, conn); err != nil {
		abortErr := s.abortRawCaptureCompensation(ctx, conn, fmt.Errorf("%w: %v", errRawCaptureCompensationContractDrift, err))
		// A connection that observed compensation-boundary drift is never returned
		// to the pool, even when ROLLBACK itself succeeded.
		discardSQLiteConnection(conn)
		return abortErr
	}
	statement, err := conn.PrepareContext(ctx, restoreRawCaptureSQL)
	if err != nil {
		return s.abortRawCaptureCompensation(ctx, conn,
			fmt.Errorf("audit: prepare raw capture purge compensation: %w", err))
	}
	for index := range snapshot {
		row := &snapshot[index]
		if _, err := statement.ExecContext(ctx,
			row.id, row.eventID, row.timestampNS, row.requestHash, row.subjectHash,
			row.action, row.decision, row.truncated, row.redacted, row.rawPreview,
			row.rawSHA256, row.redactionPatternHits, row.redactionVersion,
			row.decisionKind, row.explanationSchema,
		); err != nil {
			_ = statement.Close()
			return s.abortRawCaptureCompensation(ctx, conn,
				fmt.Errorf("audit: restore raw capture purge snapshot row %d: %w", index, err))
		}
	}
	if err := statement.Close(); err != nil {
		return s.abortRawCaptureCompensation(ctx, conn,
			fmt.Errorf("audit: close raw capture purge compensation statement: %w", err))
	}
	commitErr := s.commitRawCaptureCompensation(ctx, conn)
	autoCommit, stateErr = sqliteConnectionAutoCommit(conn)
	var rollbackErr error
	if stateErr == nil && !autoCommit {
		rollbackErr = s.rollbackRawCaptureCompensation(ctx, conn)
		autoCommit, stateErr = sqliteConnectionAutoCommit(conn)
	}
	// Keep conn checked out while a different pooled connection verifies what
	// is durably visible. The transaction connection must never validate its own
	// uncommitted writes after an ambiguous COMMIT.
	matches, verifyErr := s.freshRawCapturePurgeSnapshotVisible(ctx, snapshot)
	if stateErr == nil && autoCommit && verifyErr == nil && matches {
		return nil
	}
	if stateErr != nil || !autoCommit {
		discardSQLiteConnection(conn)
	}
	return errors.Join(
		errors.New("audit: raw capture purge compensation was not durably visible from a fresh connection"),
		commitErr,
		rollbackErr,
		stateErr,
		verifyErr,
	)
}

func validateRawCaptureCompensationContract(ctx context.Context, conn *sql.Conn) error {
	version, err := detectSchemaVersion(migrationConnection{ctx: ctx, conn: conn})
	if err != nil {
		return fmt.Errorf("detect compensation schema version: %w", err)
	}
	if version != currentSchemaVersion {
		return fmt.Errorf("compensation schema version is %d, want %d", version, currentSchemaVersion)
	}
	locked := migrationConnection{ctx: ctx, conn: conn}
	if err := validateSchemaContract(locked, currentSchemaVersion); err != nil {
		return fmt.Errorf("validate compensation schema contract: %w", err)
	}
	if err := validateRawCapturePurgeDataContract(ctx, conn); err != nil {
		return fmt.Errorf("validate compensation row and trigger contract: %w", err)
	}
	return nil
}

func (s *Store) commitRawCaptureCompensation(ctx context.Context, conn *sql.Conn) error {
	if err := s.runRawCapturePurgeHook(rawCapturePurgeBeforeCompensationCommit); err != nil {
		return fmt.Errorf("audit: injected pre-commit compensation failure: %w", err)
	}
	_, commitErr := conn.ExecContext(ctx, "COMMIT")
	hookErr := s.runRawCapturePurgeHook(rawCapturePurgeAfterCompensationCommit)
	return errors.Join(commitErr, hookErr)
}

func (s *Store) rollbackRawCaptureCompensation(ctx context.Context, conn *sql.Conn) error {
	if err := s.runRawCapturePurgeHook(rawCapturePurgeBeforeCompensationRollback); err != nil {
		return fmt.Errorf("audit: injected compensation rollback failure: %w", err)
	}
	_, err := conn.ExecContext(ctx, "ROLLBACK")
	return err
}

func (s *Store) abortRawCaptureCompensation(ctx context.Context, conn *sql.Conn, cause error) error {
	rollbackErr := s.rollbackRawCaptureCompensation(ctx, conn)
	autoCommit, stateErr := sqliteConnectionAutoCommit(conn)
	if stateErr != nil || !autoCommit {
		discardSQLiteConnection(conn)
	}
	return errors.Join(cause, rollbackErr, stateErr)
}

func (s *Store) freshRawCapturePurgeSnapshotVisible(ctx context.Context, snapshot []rawCapturePurgeRow) (bool, error) {
	if err := s.runRawCapturePurgeHook(rawCapturePurgeFreshVerification); err != nil {
		return false, err
	}
	fresh, err := s.db.Conn(ctx)
	if err != nil {
		return false, fmt.Errorf("audit: acquire fresh purge verification connection: %w", err)
	}
	defer fresh.Close()
	return rawCapturePurgeSnapshotVisible(ctx, fresh, snapshot)
}

func rawCapturePurgeSnapshotVisible(ctx context.Context, conn *sql.Conn, snapshot []rawCapturePurgeRow) (bool, error) {
	rows, err := conn.QueryContext(ctx, rawCapturePurgeSelect)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	snapshotIndex := 0
	for rows.Next() {
		var current rawCapturePurgeRow
		if err := rows.Scan(
			&current.id, &current.eventID, &current.timestampNS, &current.requestHash,
			&current.subjectHash, &current.action, &current.decision, &current.truncated,
			&current.redacted, &current.rawPreview, &current.rawSHA256,
			&current.redactionPatternHits, &current.redactionVersion,
			&current.decisionKind, &current.explanationSchema,
		); err != nil {
			wipeBytes(current.rawPreview)
			return false, err
		}
		if snapshotIndex >= len(snapshot) {
			wipeBytes(current.rawPreview)
			continue
		}
		wanted := snapshot[snapshotIndex]
		if current.id < wanted.id {
			wipeBytes(current.rawPreview)
			continue
		}
		if current.id > wanted.id {
			wipeBytes(current.rawPreview)
			return false, nil
		}
		matches := current.equal(wanted)
		wipeBytes(current.rawPreview)
		if !matches {
			return false, nil
		}
		snapshotIndex++
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return snapshotIndex == len(snapshot), nil
}

func (row rawCapturePurgeRow) equal(other rawCapturePurgeRow) bool {
	return row.id == other.id &&
		row.eventID == other.eventID &&
		row.timestampNS == other.timestampNS &&
		row.requestHash == other.requestHash &&
		row.subjectHash == other.subjectHash &&
		row.action == other.action &&
		row.decision == other.decision &&
		row.truncated == other.truncated &&
		row.redacted == other.redacted &&
		bytes.Equal(row.rawPreview, other.rawPreview) &&
		row.rawSHA256 == other.rawSHA256 &&
		row.redactionPatternHits == other.redactionPatternHits &&
		row.redactionVersion == other.redactionVersion &&
		row.decisionKind == other.decisionKind &&
		row.explanationSchema == other.explanationSchema
}

func (row rawCapturePurgeRow) memoryBytes() int64 {
	return rawCapturePurgeRowOverheadBytes + int64(
		len(row.id)+len(row.eventID)+len(row.requestHash)+len(row.subjectHash)+
			len(row.action)+len(row.decision)+len(row.rawPreview)+len(row.rawSHA256)+
			len(row.redactionVersion)+len(row.decisionKind)+len(row.explanationSchema),
	)
}

func wipeRawCapturePurgeRows(rows []rawCapturePurgeRow) {
	for index := range rows {
		wipeBytes(rows[index].rawPreview)
		rows[index].rawPreview = nil
	}
}

func wipeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func (s *Store) rawCaptureMaintenanceFailure(err error) error {
	if err == nil {
		return nil
	}
	s.failed.Add(1)
	s.degraded.Store(true)
	s.lastErr.Store(err.Error())
	s.report(err)
	return err
}

func rawCaptureWhere(query RawCaptureQuery) (string, []any, error) {
	clauses := make([]string, 0, 2)
	args := make([]any, 0, 2)
	if query.EventID != "" {
		if err := validateField("event_id", query.EventID, 128, false); err != nil {
			return "", nil, fmt.Errorf("audit: invalid raw capture query: %w", err)
		}
		clauses = append(clauses, "event_id = ?")
		args = append(args, query.EventID)
	}
	if query.RequestHash != "" {
		if !validDigest(query.RequestHash, "sha256:") {
			return "", nil, errors.New("audit: invalid raw capture query request_hash")
		}
		clauses = append(clauses, "request_hash = ?")
		args = append(args, query.RequestHash)
	}
	if len(clauses) == 0 {
		return "", args, nil
	}
	return " WHERE " + strings.Join(clauses, " AND "), args, nil
}

// validateRawRequestCapture is the single privacy and integrity contract for a
// prepared, migrated, or read-back preview row. Legacy schema-v4 rows may have
// an empty raw_sha256, so callers that create new rows separately require that
// field after this shared validation succeeds.
func validateRawRequestCapture(capture RawRequestCapture) error {
	if err := validateField("raw capture id", capture.ID, 128, false); err != nil {
		return err
	}
	if err := validateField("raw capture event_id", capture.EventID, 128, false); err != nil {
		return err
	}
	if capture.Timestamp.Year() < 1970 || capture.Timestamp.Year() > 9999 {
		return errors.New("audit: invalid raw capture timestamp")
	}
	if capture.RequestHash != "" && !validDigest(capture.RequestHash, "sha256:") {
		return errors.New("audit: raw capture request_hash is not a SHA-256 correlation value")
	}
	if capture.SubjectHash != "" && !validDigest(capture.SubjectHash, "hmac-sha256:") {
		return errors.New("audit: raw capture subject_hash is not an HMAC-SHA256 correlation value")
	}
	if rawCaptureDecisionKindForbidden(capture.DecisionKind) {
		return errors.New("audit: raw capture is forbidden for CSAM-text decisions")
	}
	if !oneOf(capture.Action, "block", "cooldown") {
		return errors.New("audit: raw capture action is not a blocking action")
	}
	if err := validateField("raw capture decision", capture.Decision, 96, false); err != nil {
		return err
	}
	if !validDecision(capture.Decision) {
		return errors.New("audit: raw capture decision is unsupported")
	}
	if !validDecisionKind(capture.DecisionKind) {
		return errors.New("audit: raw capture decision_kind is unsupported")
	}
	if !validDecisionExplanationSchema(capture.ExplanationSchema) {
		return errors.New("audit: raw capture explanation_schema is unsupported")
	}
	if err := validateDecisionKindExplanationSchema(capture.DecisionKind, capture.Decision, capture.ExplanationSchema); err != nil {
		return fmt.Errorf("audit: raw capture decision metadata is inconsistent: %w", err)
	}
	if capture.DecisionKind != decisionKindLegacyUnspecified &&
		capture.DecisionKind != decisionKindForDisposition(capture.Decision) {
		return errors.New("audit: raw capture decision_kind contradicts decision")
	}
	switch capture.Action {
	case "block":
		if !strings.HasPrefix(capture.Decision, "block_") {
			return errors.New("audit: raw capture block action requires a block decision")
		}
	case "cooldown":
		if capture.Decision != "cooldown_subject_risk" {
			return errors.New("audit: raw capture cooldown action requires cooldown_subject_risk")
		}
	}
	if capture.PreviewTruncated != capture.Truncated {
		return errors.New("audit: raw capture preview_truncated alias is inconsistent")
	}
	if capture.RedactionApplied != capture.Redacted {
		return errors.New("audit: raw capture redaction_applied alias is inconsistent")
	}
	if !utf8.ValidString(capture.RawPreview) {
		return errors.New("audit: raw capture preview is not valid UTF-8")
	}
	if len(capture.RawPreview) > maxRawCaptureBytes {
		return fmt.Errorf("audit: raw capture preview exceeds %d bytes", maxRawCaptureBytes)
	}
	if capture.RawSHA256 != "" && !validDigest(capture.RawSHA256, "sha256:") {
		return errors.New("audit: raw capture raw_sha256 is not a SHA-256 integrity value")
	}
	if capture.RedactionPatternHits < 0 || capture.RedactionPatternHits > 1_000_000 {
		return errors.New("audit: raw capture redaction_pattern_hits is outside the supported range")
	}
	switch capture.RedactionVersion {
	case rawCaptureRedactionVersion, priorRawCaptureRedactionVersion:
		if capture.Redacted != (capture.RedactionPatternHits > 0) {
			return errors.New("audit: raw capture current redaction metadata is inconsistent")
		}
	case legacyRawCaptureRedactionVersion:
		if capture.RedactionPatternHits != 0 {
			return errors.New("audit: raw capture legacy redaction metadata must not claim a hit count")
		}
	default:
		return errors.New("audit: raw capture redaction_version is unsupported")
	}
	return nil
}

func prepareRawCapture(input RawCaptureInput, cfg RawCaptureConfig, now time.Time) (RawRequestCapture, error) {
	if !cfg.Enabled {
		return RawRequestCapture{}, ErrRawCaptureDisabled
	}
	if !cfg.OnlyBlocked {
		return RawRequestCapture{}, errors.New("raw capture must remain block-only")
	}
	if !cfg.RedactSecrets {
		return RawRequestCapture{}, errors.New("raw capture secret redaction must remain enabled")
	}
	if cfg.MaxBytes < 1 || cfg.MaxBytes > maxRawCaptureBytes {
		return RawRequestCapture{}, fmt.Errorf("raw capture max bytes must be between 1 and %d", maxRawCaptureBytes)
	}
	if err := validateField("event_id", input.EventID, 128, false); err != nil {
		return RawRequestCapture{}, err
	}
	if rawCaptureDecisionKindForbidden(input.DecisionKind) {
		return RawRequestCapture{}, errors.New("raw capture is forbidden for CSAM-text decisions")
	}
	if !oneOf(input.Action, "block", "cooldown") {
		return RawRequestCapture{}, fmt.Errorf("raw capture action %q is not a blocking action", input.Action)
	}
	if err := validateField("decision", input.Decision, 96, false); err != nil {
		return RawRequestCapture{}, err
	}
	if !validDecision(input.Decision) {
		return RawRequestCapture{}, fmt.Errorf("invalid raw capture decision %q", input.Decision)
	}
	if input.DecisionKind == "" {
		input.DecisionKind = decisionKindForDisposition(input.Decision)
	}
	if !validDecisionKind(input.DecisionKind) {
		return RawRequestCapture{}, fmt.Errorf("invalid raw capture decision_kind %q", input.DecisionKind)
	}
	if rawCaptureDecisionKindForbidden(input.DecisionKind) {
		return RawRequestCapture{}, errors.New("raw capture is forbidden for CSAM-text decisions")
	}
	if input.ExplanationSchema == "" {
		if input.DecisionKind == decisionKindLegacyUnspecified {
			input.ExplanationSchema = DecisionExplanationSchemaNone
		} else {
			input.ExplanationSchema = DecisionExplanationSchemaV2
		}
	}
	if !validDecisionExplanationSchema(input.ExplanationSchema) {
		return RawRequestCapture{}, fmt.Errorf("invalid raw capture explanation_schema %q", input.ExplanationSchema)
	}
	if input.RequestHash != "" && !validDigest(input.RequestHash, "sha256:") {
		return RawRequestCapture{}, errors.New("raw capture request_hash is not a SHA-256 correlation value")
	}
	if input.SubjectHash != "" && !validDigest(input.SubjectHash, "hmac-sha256:") {
		return RawRequestCapture{}, errors.New("raw capture subject_hash is not an HMAC-SHA256 correlation value")
	}

	id, err := randomID()
	if err != nil {
		return RawRequestCapture{}, err
	}
	timestamp := input.Timestamp
	if timestamp.IsZero() {
		timestamp = now
	}
	timestamp = timestamp.UTC()
	if timestamp.Year() < 1970 || timestamp.Year() > 9999 {
		return RawRequestCapture{}, errors.New("invalid raw capture timestamp")
	}

	previewInput, beyondRedactionWindow := rawCaptureRedactionWindow(input.RawRequest, cfg.MaxBytes)
	preview := strings.ToValidUTF8(string(previewInput), "\uFFFD")
	preview, redactionPatternHits := redactRawCapture(preview)
	preview, truncated := truncateUTF8(preview, cfg.MaxBytes)
	truncated = truncated || beyondRedactionWindow
	sum := sha256.Sum256(input.RawRequest)
	capture := RawRequestCapture{
		ID:                   id,
		EventID:              input.EventID,
		Timestamp:            timestamp,
		RequestHash:          input.RequestHash,
		SubjectHash:          input.SubjectHash,
		Action:               input.Action,
		Decision:             input.Decision,
		DecisionKind:         input.DecisionKind,
		ExplanationSchema:    input.ExplanationSchema,
		Truncated:            truncated,
		Redacted:             redactionPatternHits > 0,
		PreviewTruncated:     truncated,
		RedactionApplied:     redactionPatternHits > 0,
		RedactionPatternHits: redactionPatternHits,
		RedactionVersion:     rawCaptureRedactionVersion,
		RawPreview:           preview,
		RawSHA256:            "sha256:" + hex.EncodeToString(sum[:]),
	}
	if err := validateRawRequestCapture(capture); err != nil {
		return RawRequestCapture{}, err
	}
	return capture, nil
}

func rawCaptureDecisionKindForbidden(decisionKind string) bool {
	return decisionKind == decisionKindAuditCSAMText || decisionKind == decisionKindBlockCSAMText
}

func rawCaptureRedactionWindow(raw []byte, maxBytes int) ([]byte, bool) {
	windowBytes := maxBytes + rawCaptureRedactionOverlapBytes
	if len(raw) <= windowBytes {
		return raw, false
	}
	return raw[:windowBytes], true
}

func redactRawCapture(value string) (string, int) {
	hits := 0
	for _, rule := range rawCaptureRedactors {
		matches := rule.expression.FindAllStringSubmatchIndex(value, -1)
		if len(matches) == 0 {
			continue
		}
		replaced := make([]byte, 0, len(value))
		last := 0
		for _, match := range matches {
			start, end := match[0], match[1]
			replaced = append(replaced, value[last:start]...)
			replaced = rule.expression.ExpandString(replaced, rule.replacement, value, match)
			last = end
		}
		replaced = append(replaced, value[last:]...)
		value = string(replaced)
		hits += len(matches)
	}
	return value, hits
}

func truncateUTF8(value string, maxBytes int) (string, bool) {
	if len(value) <= maxBytes {
		return value, false
	}
	end := maxBytes
	for end > 0 && !utf8.ValidString(value[:end]) {
		end--
	}
	return value[:end], true
}
