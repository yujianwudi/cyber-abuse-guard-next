package audit

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const selectColumns = `id, timestamp_ns, action, mode, category, risk_score, rule_ids,
	request_hash, subject_hash, model, source_format, stream, text_bytes_scanned,
	classifier, decision, coverage, incomplete_reason, scanner, latency_us,
	decision_explanation`

const (
	retryWindowSeconds     int64 = 5 * 60
	retryWindowNanoseconds int64 = retryWindowSeconds * int64(time.Second)
	// One statistics snapshot may hold one of SQLite's four pooled
	// connections. Additional management requests wait without reserving a
	// connection, leaving capacity for the audit writer and cleanup work.
	statsConcurrentLimit = 1
)

const retryWindowAggregateSQL = `WITH canonical_events AS (
	SELECT
		request_hash,
		decision,
		CAST(timestamp_ns / ? AS INTEGER) AS window_id,
		COALESCE((
			SELECT group_concat(length(rule_id) || ':' || rule_id, '|')
			FROM (
				SELECT DISTINCT CAST(value AS TEXT) AS rule_id
				FROM json_each(events.rule_ids)
				WHERE type = 'text'
				ORDER BY rule_id
			)
		), '') AS canonical_rule_ids
	FROM audit_events AS events
	WHERE request_hash <> ''
), decision_rule_windows AS (
	SELECT request_hash, decision, canonical_rule_ids, window_id, COUNT(*) AS event_count
	FROM canonical_events
	GROUP BY request_hash, decision, canonical_rule_ids, window_id
)
SELECT COUNT(*), COALESCE(SUM(event_count - 1), 0)
FROM decision_rule_windows`

// Query returns only the fixed Event schema. All caller-controlled filters are
// SQL parameters; limit and offset are validated integers.
func (s *Store) Query(ctx context.Context, query Query) ([]Event, error) {
	if s == nil || s.db == nil {
		return nil, ErrUnavailable
	}
	where, args := queryWhere(query)
	limit := query.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := query.Offset
	if offset < 0 {
		offset = 0
	}
	args = append(args, limit, offset)
	statement := "SELECT " + selectColumns + " FROM audit_events" + where + " ORDER BY timestamp_ns DESC, id DESC LIMIT ? OFFSET ?"
	rows, err := s.db.QueryContext(ctx, statement, args...)
	if err != nil {
		return nil, fmt.Errorf("audit: query events: %w", err)
	}
	defer rows.Close()
	events := make([]Event, 0)
	for rows.Next() {
		event, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("audit: iterate events: %w", err)
	}
	return events, nil
}

// Stats aggregates persisted events without exposing arbitrary values beyond
// the same coarse action/category fields already present in Event.
func (s *Store) Stats(ctx context.Context) (Stats, error) {
	status := s.Status()
	stats := Stats{
		ByAction:                 make(map[string]int64),
		ByCategory:               make(map[string]int64),
		RetryWindowSeconds:       retryWindowSeconds,
		Enqueued:                 status.Enqueued,
		Written:                  status.Written,
		Dropped:                  status.Dropped,
		Failed:                   status.Failed,
		Rejected:                 status.Rejected,
		RawCaptureEnqueued:       status.RawCaptureEnqueued,
		RawCaptureWritten:        status.RawCaptureWritten,
		RawCaptureDropped:        status.RawCaptureDropped,
		RawCaptureFailed:         status.RawCaptureFailed,
		RawCaptureRejected:       status.RawCaptureRejected,
		RawCaptureDeduplicated:   status.RawCaptureDeduplicated,
		RawCaptureQueueHighWater: status.RawCaptureQueueHighWater,
		RawCapturePrepareCount:   status.RawCapturePrepareCount,
		RawCapturePrepareTotalUS: status.RawCapturePrepareTotalUS,
		RawCapturePrepareLastUS:  status.RawCapturePrepareLastUS,
		RawCapturePrepareMaxUS:   status.RawCapturePrepareMaxUS,
		CleanupDeleted:           status.CleanupDeleted,
	}
	if s == nil || s.db == nil {
		return stats, ErrUnavailable
	}
	if err := s.acquireStatsSlot(ctx); err != nil {
		return stats, err
	}
	defer s.releaseStatsSlot()
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return stats, fmt.Errorf("audit: begin statistics snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := tx.QueryRowContext(ctx, `SELECT
COUNT(*),
COUNT(DISTINCT NULLIF(request_hash, '')),
COALESCE(SUM(CASE WHEN request_hash = '' THEN 1 ELSE 0 END), 0)
FROM audit_events`).Scan(&stats.Events, &stats.UniqueRequests, &stats.UnhashedEvents); err != nil {
		return stats, fmt.Errorf("audit: count events: %w", err)
	}
	stats.Total = stats.Events
	hashedEvents := stats.Events - stats.UnhashedEvents
	if hashedEvents > stats.UniqueRequests {
		stats.RepeatEvents = hashedEvents - stats.UniqueRequests
	}
	// This query returns two scalars regardless of event count. Rule IDs are
	// treated as a sorted distinct set for the retry key; neither rule IDs nor
	// request hashes are returned by Stats. The window size is a package constant
	// supplied as an SQL parameter rather than interpolated SQL.
	if err := tx.QueryRowContext(
		ctx,
		retryWindowAggregateSQL,
		retryWindowNanoseconds,
	).Scan(&stats.UniqueDecisionRuleWindows, &stats.WindowRepeatEvents); err != nil {
		return stats, fmt.Errorf("audit: aggregate decision/rule retry windows: %w", err)
	}
	if err := aggregate(ctx, tx, "action", stats.ByAction); err != nil {
		return stats, err
	}
	if err := aggregate(ctx, tx, "category", stats.ByCategory); err != nil {
		return stats, err
	}
	if err := tx.Commit(); err != nil {
		return stats, fmt.Errorf("audit: commit statistics snapshot: %w", err)
	}
	return stats, nil
}

func (s *Store) acquireStatsSlot(ctx context.Context) error {
	// Store values created through Open always have the gate. Keep nil tolerant
	// for zero-value/internal test stores so this helper cannot deadlock them.
	if s.statsSlots == nil {
		return nil
	}
	select {
	case s.statsSlots <- struct{}{}:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("audit: wait for statistics capacity: %w", ctx.Err())
	}
}

func (s *Store) releaseStatsSlot() {
	if s.statsSlots != nil {
		<-s.statsSlots
	}
}

type contextQueryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

func aggregate(ctx context.Context, db contextQueryer, column string, destination map[string]int64) error {
	// column is selected exclusively by package code, never caller input.
	rows, err := db.QueryContext(ctx, "SELECT "+column+", COUNT(*) FROM audit_events GROUP BY "+column)
	if err != nil {
		return fmt.Errorf("audit: aggregate %s: %w", column, err)
	}
	defer rows.Close()
	for rows.Next() {
		var key string
		var count int64
		if err := rows.Scan(&key, &count); err != nil {
			return fmt.Errorf("audit: scan %s aggregate: %w", column, err)
		}
		destination[key] = count
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("audit: iterate %s aggregate: %w", column, err)
	}
	return nil
}

// Delete removes matching persisted events. An empty Query intentionally
// removes every event. It first flushes already-enqueued work so a clear-all
// management action does not immediately repopulate from an older queue item.
func (s *Store) Delete(ctx context.Context, query Query) (int64, error) {
	if s == nil || s.db == nil {
		return 0, ErrUnavailable
	}
	if err := s.Flush(ctx); err != nil {
		return 0, err
	}
	where, args := queryWhere(query)
	result, err := s.db.ExecContext(ctx, "DELETE FROM audit_events"+where, args...)
	if err != nil {
		return 0, fmt.Errorf("audit: delete events: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("audit: count deleted events: %w", err)
	}
	return deleted, nil
}

// ExportJSON writes a JSON array composed solely of Event values.
func (s *Store) ExportJSON(ctx context.Context, writer io.Writer, query Query) error {
	events, err := s.Query(ctx, query)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(events); err != nil {
		return fmt.Errorf("audit: encode JSON export: %w", err)
	}
	return nil
}

// ExportCSV writes a spreadsheet-safe CSV. Formula-significant leading bytes
// are prefixed with an apostrophe even though the csv.Writer also quotes fields.
func (s *Store) ExportCSV(ctx context.Context, writer io.Writer, query Query) error {
	events, err := s.Query(ctx, query)
	if err != nil {
		return err
	}
	csvWriter := csv.NewWriter(writer)
	header := []string{
		"id", "timestamp", "action", "mode", "category", "risk_score", "rule_ids",
		"request_hash", "subject_hash", "model", "source_format", "stream",
		"text_bytes_scanned", "classifier", "decision", "coverage", "incomplete_reason", "scanner", "latency_us",
		"decision_explanation",
	}
	if err := csvWriter.Write(header); err != nil {
		return fmt.Errorf("audit: write CSV header: %w", err)
	}
	for _, event := range events {
		explanation, err := marshalDecisionExplanation(event.DecisionExplanation)
		if err != nil {
			return fmt.Errorf("audit: encode decision explanation for CSV: %w", err)
		}
		record := []string{
			safeCSV(event.ID),
			event.Timestamp.UTC().Format(time.RFC3339Nano),
			safeCSV(event.Action),
			safeCSV(event.Mode),
			safeCSV(event.Category),
			strconv.Itoa(event.RiskScore),
			safeCSV(strings.Join(event.RuleIDs, ";")),
			safeCSV(event.RequestHash),
			safeCSV(event.SubjectHash),
			safeCSV(event.Model),
			safeCSV(event.SourceFormat),
			strconv.FormatBool(event.Stream),
			strconv.Itoa(event.TextBytesScanned),
			safeCSV(event.Classifier),
			safeCSV(event.Decision),
			safeCSV(event.Coverage),
			safeCSV(event.IncompleteReason),
			safeCSV(event.Scanner),
			strconv.FormatInt(event.LatencyUS, 10),
			safeCSV(explanation),
		}
		if err := csvWriter.Write(record); err != nil {
			return fmt.Errorf("audit: write CSV event: %w", err)
		}
	}
	csvWriter.Flush()
	if err := csvWriter.Error(); err != nil {
		return fmt.Errorf("audit: flush CSV export: %w", err)
	}
	return nil
}

func queryWhere(query Query) (string, []any) {
	clauses := make([]string, 0, 5)
	args := make([]any, 0, 5)
	if query.Action != "" {
		clauses = append(clauses, "action = ?")
		args = append(args, query.Action)
	}
	if query.Category != "" {
		clauses = append(clauses, "category = ?")
		args = append(args, query.Category)
	}
	if query.SubjectHash != "" {
		clauses = append(clauses, "subject_hash = ?")
		args = append(args, query.SubjectHash)
	}
	if !query.Since.IsZero() {
		clauses = append(clauses, "timestamp_ns >= ?")
		args = append(args, query.Since.UTC().UnixNano())
	}
	if !query.Until.IsZero() {
		clauses = append(clauses, "timestamp_ns <= ?")
		args = append(args, query.Until.UTC().UnixNano())
	}
	if len(clauses) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(clauses, " AND "), args
}

type rowScanner interface {
	Scan(...any) error
}

func scanEvent(row rowScanner) (Event, error) {
	var event Event
	var timestampNS int64
	var ruleJSON string
	var explanationJSON string
	var stream int
	if err := row.Scan(
		&event.ID, &timestampNS, &event.Action, &event.Mode, &event.Category,
		&event.RiskScore, &ruleJSON, &event.RequestHash, &event.SubjectHash,
		&event.Model, &event.SourceFormat, &stream, &event.TextBytesScanned,
		&event.Classifier, &event.Decision, &event.Coverage, &event.IncompleteReason,
		&event.Scanner, &event.LatencyUS, &explanationJSON,
	); err != nil {
		return Event{}, fmt.Errorf("audit: scan event: %w", err)
	}
	if err := json.Unmarshal([]byte(ruleJSON), &event.RuleIDs); err != nil {
		return Event{}, fmt.Errorf("audit: decode rule IDs: %w", err)
	}
	if event.RuleIDs == nil {
		event.RuleIDs = []string{}
	}
	event.Timestamp = time.Unix(0, timestampNS).UTC()
	event.Stream = stream != 0
	event.Model = privacySafeModel(event.Model)
	event.SourceFormat = privacySafeSourceFormat(event.SourceFormat)
	explanation, err := decodeDecisionExplanation(explanationJSON)
	if err != nil {
		return Event{}, fmt.Errorf("audit: decode decision explanation: %w", err)
	}
	event.DecisionExplanation = explanation
	// This is schema and cross-field consistency validation only. It detects
	// corrupt or internally contradictory rows, but it does not cryptographically
	// authenticate SQLite contents or protect against a database writer that
	// coherently rewrites all related fields.
	if err := validateEvent(event); err != nil {
		return Event{}, fmt.Errorf("audit: invalid persisted event: %w", err)
	}
	return event, nil
}

func marshalDecisionExplanation(explanation *DecisionExplanation) (string, error) {
	if explanation == nil {
		return "{}", nil
	}
	if err := validateDecisionExplanation(explanation); err != nil {
		return "", err
	}
	encoded, err := json.Marshal(explanation)
	if err != nil {
		return "", err
	}
	if len(encoded) > 32768 {
		return "", fmt.Errorf("decision explanation exceeds 32768 bytes")
	}
	return string(encoded), nil
}

func decodeDecisionExplanation(encoded string) (*DecisionExplanation, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" || encoded == "{}" || encoded == "null" {
		return nil, nil
	}
	if len(encoded) > 32768 {
		return nil, fmt.Errorf("decision explanation exceeds 32768 bytes")
	}
	decoder := json.NewDecoder(strings.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var explanation DecisionExplanation
	if err := decoder.Decode(&explanation); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, fmt.Errorf("decision explanation must contain exactly one JSON value")
	}
	if err := validateDecisionExplanation(&explanation); err != nil {
		return nil, err
	}
	return &explanation, nil
}

func safeCSV(value string) string {
	if value == "" {
		return value
	}
	switch value[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + value
	default:
		return value
	}
}
