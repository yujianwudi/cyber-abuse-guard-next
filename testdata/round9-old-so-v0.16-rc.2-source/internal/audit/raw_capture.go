package audit

import (
	"context"
	"crypto/sha256"
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
	rawCaptureRedactionVersion        = "raw-redactor-v1"
	legacyRawCaptureRedactionVersion  = "legacy-boolean-v0"
)

var (
	ErrRawCaptureDisabled = errors.New("audit: raw request capture is disabled")
	ErrInvalidRawCapture  = errors.New("audit: invalid raw request capture")
)

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
	EventID     string
	Timestamp   time.Time
	RequestHash string
	SubjectHash string
	Action      string
	Decision    string
	RawRequest  []byte
}

// RawRequestCapture is the only sensitive request-text model exposed to the
// management layer. RawPreview is always produced with secret redaction enabled
// and is bounded by RawCaptureConfig.MaxBytes.
type RawRequestCapture struct {
	ID          string    `json:"id"`
	EventID     string    `json:"event_id"`
	Timestamp   time.Time `json:"timestamp"`
	RequestHash string    `json:"request_hash,omitempty"`
	SubjectHash string    `json:"subject_hash,omitempty"`
	Action      string    `json:"action"`
	Decision    string    `json:"decision"`
	Truncated   bool      `json:"truncated"`
	Redacted    bool      `json:"redacted"`
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
		expression:  regexp.MustCompile(`(?im)^([\t ]*(?:authorization|proxy-authorization|cookie|set-cookie)[\t ]*:[\t ]*)[^\r\n]*`),
		replacement: `${1}[REDACTED]`,
	},
	{
		expression:  regexp.MustCompile(`(?i)(["']?(?:authorization|proxy[-_]?authorization|cookie|set[-_]?cookie|api[-_]?key|apikey|access[-_]?token|refresh[-_]?token|password|passwd|secret|client[-_]?secret)["']?[\t ]*[:=][\t ]*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\r\n,;&}\]]+)`),
		replacement: `${1}"[REDACTED]"`,
	},
	{
		expression:  regexp.MustCompile(`(?i)(\bbearer[\t ]+)[A-Za-z0-9._~+/=-]{8,}`),
		replacement: `${1}[REDACTED]`,
	},
	{
		expression:  regexp.MustCompile(`(?i)(\b(?:password|passwd|api[ _-]?key|access[ _-]?token|refresh[ _-]?token|client[ _-]?secret|secret|cookie)\b[\t ]+(?:is|was)[\t ]+)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,;&}\]]+)`),
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
		expression:  regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----|$)`),
		replacement: `-----BEGIN PRIVATE KEY-----[REDACTED]-----END PRIVATE KEY-----`,
	},
}

const insertRawCaptureSQL = `INSERT INTO raw_request_captures (
    id, event_id, timestamp_ns, request_hash, subject_hash, action, decision,
    truncated, redacted, raw_preview, raw_sha256, redaction_pattern_hits,
    redaction_version
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(raw_sha256) WHERE raw_sha256 <> '' DO NOTHING`

// RecordRawCapture performs a bounded, nonblocking enqueue. The associated
// audit Event must be enqueued first with the same EventID; the shared queue
// then preserves write order and the schema foreign key prevents orphan text.
func (s *Store) RecordRawCapture(input RawCaptureInput) error {
	if s == nil {
		return ErrUnavailable
	}
	if !s.cfg.RawCapture.Enabled {
		return ErrRawCaptureDisabled
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
	if s == nil {
		return false, ErrUnavailable
	}
	if !s.cfg.RawCapture.Enabled {
		return false, ErrRawCaptureDisabled
	}
	preparedEvent, err := prepareEvent(event, s.cfg.Now())
	if err != nil {
		s.rejected.Add(1)
		return false, fmt.Errorf("%w: %v", ErrInvalidEvent, err)
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
	if event.ID != input.EventID {
		return errors.New("raw capture event_id does not match its audit event")
	}
	if event.Action != input.Action {
		return errors.New("raw capture action does not match its audit event")
	}
	if event.Decision != input.Decision {
		return errors.New("raw capture decision does not match its audit event")
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

// QueryRawCapturesPage returns recent sensitive previews while enforcing both
// the 100-row API cap and a fixed 8 MiB cumulative raw-preview scan budget. SQL
// is limited to one extra row so HasMore never requires materializing the rest
// of a large result set.
func (s *Store) QueryRawCapturesPage(ctx context.Context, query RawCaptureQuery) (RawCapturePage, error) {
	if s == nil || s.db == nil {
		return RawCapturePage{}, ErrUnavailable
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
	rows, err := s.db.QueryContext(ctx, `SELECT id, event_id, timestamp_ns, request_hash,
subject_hash, action, decision, truncated, redacted, raw_preview, raw_sha256,
redaction_pattern_hits, redaction_version
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
	if err := s.Flush(ctx); err != nil {
		return 0, s.rawCaptureMaintenanceFailure(fmt.Errorf("audit: flush before raw capture purge: %w", err))
	}
	return s.purgeRawCaptures(ctx)
}

// purgeRawCaptures is the startup form used before the writer goroutine starts.
// Callers that may have queued work must use PurgeRawCaptures instead.
func (s *Store) purgeRawCaptures(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM raw_request_captures")
	if err != nil {
		return 0, s.rawCaptureMaintenanceFailure(fmt.Errorf("audit: purge raw request captures: %w", err))
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, s.rawCaptureMaintenanceFailure(fmt.Errorf("audit: count purged raw request captures: %w", err))
	}
	var busy, logFrames, checkpointedFrames int
	if err := s.db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &logFrames, &checkpointedFrames); err != nil {
		return deleted, s.rawCaptureMaintenanceFailure(fmt.Errorf("audit: checkpoint purged raw request captures: %w", err))
	}
	if busy != 0 {
		return deleted, s.rawCaptureMaintenanceFailure(errors.New("audit: raw request capture purge WAL checkpoint remained busy"))
	}
	if err := secureSQLiteFiles(s.cfg.Path); err != nil {
		return deleted, s.rawCaptureMaintenanceFailure(err)
	}
	if deleted > 0 {
		s.cleaned.Add(uint64(deleted))
	}
	s.degraded.Store(false)
	s.lastErr.Store("")
	return deleted, nil
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
	if !oneOf(capture.Action, "block", "cooldown") {
		return errors.New("audit: raw capture action is not a blocking action")
	}
	if err := validateField("raw capture decision", capture.Decision, 96, false); err != nil {
		return err
	}
	if !validDecision(capture.Decision) {
		return errors.New("audit: raw capture decision is unsupported")
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
	case rawCaptureRedactionVersion:
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
	if !oneOf(input.Action, "block", "cooldown") {
		return RawRequestCapture{}, fmt.Errorf("raw capture action %q is not a blocking action", input.Action)
	}
	if err := validateField("decision", input.Decision, 96, false); err != nil {
		return RawRequestCapture{}, err
	}
	if !validDecision(input.Decision) {
		return RawRequestCapture{}, fmt.Errorf("invalid raw capture decision %q", input.Decision)
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
