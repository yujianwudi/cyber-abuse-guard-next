package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRound8DecisionExplanationValidationCloneAndRoundTrip(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	store, err := Open(Config{
		Path: filepath.Join(t.TempDir(), "decision-explanation.db"),
		Now:  func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	want := round8DecisionExplanationFixture()
	event := testEvent("round8-decision-explanation", now)
	event.Action = "block"
	event.Category = "defense_evasion"
	event.RiskScore = 90
	event.RuleIDs = []string{"EVADE-002"}
	event.Decision = "block_malicious_text"
	event.Coverage = "complete"
	event.Scanner = "streaming-scanner-v1"
	event.DecisionExplanation = cloneDecisionExplanation(want)
	if !store.Record(event) {
		t.Fatal("Record() rejected a valid decision explanation")
	}

	// Record/Enqueue must own a deep copy. Mutating the caller's nested slices
	// after admission must not change the queued or persisted explanation.
	event.DecisionExplanation.WinningRuleID = "MUTATED"
	event.DecisionExplanation.ScoreBreakdown[0].EvidenceIDs[0] = "MUTATED:intent"
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	events, err := store.Query(context.Background(), Query{Limit: 10})
	if err != nil || len(events) != 1 {
		t.Fatalf("Query() events=%d err=%v", len(events), err)
	}
	if !reflect.DeepEqual(events[0].DecisionExplanation, want) {
		t.Fatalf("decision explanation round trip = %#v, want %#v", events[0].DecisionExplanation, want)
	}

	var csv bytes.Buffer
	if err := store.ExportCSV(context.Background(), &csv, Query{Limit: 10}); err != nil {
		t.Fatal(err)
	}
	encodedCSV := csv.String()
	if !strings.Contains(encodedCSV, "decision_explanation") ||
		!strings.Contains(encodedCSV, "EVADE-002:intent:explicit_bypass") ||
		strings.Contains(encodedCSV, "MUTATED") {
		t.Fatalf("CSV decision explanation contract mismatch: %s", encodedCSV)
	}

	if _, err := decodeDecisionExplanation(`{"winning_rule_id":"EVADE-002","unknown":"forbidden"}`); err == nil {
		t.Fatal("decodeDecisionExplanation accepted an unknown field")
	}
	if _, err := decodeDecisionExplanation(`{"winning_rule_id":"EVADE-002"} {}`); err == nil {
		t.Fatal("decodeDecisionExplanation accepted trailing JSON")
	}
}

func TestRound8DecisionExplanationRejectsCrossFieldContradictions(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 12, 30, 0, 0, time.UTC)
	base := testEvent("round8-cross-field", now)
	base.Action = "block"
	base.Category = "defense_evasion"
	base.RiskScore = 90
	base.RuleIDs = []string{"EVADE-002"}
	base.Decision = "block_malicious_text"
	base.Coverage = "complete"
	base.Scanner = "streaming-scanner-v1"
	base.Model = HashModel(base.Model)
	base.DecisionExplanation = round8DecisionExplanationFixture()
	if err := validateEvent(base); err != nil {
		t.Fatalf("valid cross-field fixture rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*Event)
	}{
		{name: "final score", mutate: func(event *Event) {
			event.DecisionExplanation.ScoreBreakdown[len(event.DecisionExplanation.ScoreBreakdown)-1].Points++
		}},
		{name: "missing final score", mutate: func(event *Event) {
			event.DecisionExplanation.ScoreBreakdown = event.DecisionExplanation.ScoreBreakdown[:len(event.DecisionExplanation.ScoreBreakdown)-1]
		}},
		{name: "context adjustment", mutate: func(event *Event) {
			event.DecisionExplanation.ContextAdjustment--
		}},
		{name: "category", mutate: func(event *Event) {
			event.DecisionExplanation.WinningCategory = "credential_theft"
		}},
		{name: "missing winning category", mutate: func(event *Event) {
			event.DecisionExplanation.WinningCategory = ""
		}},
		{name: "category logging bypass", mutate: func(event *Event) {
			event.Category = ""
		}},
		{name: "rule", mutate: func(event *Event) {
			event.DecisionExplanation.WinningRuleID = "CRED-001"
		}},
		{name: "missing winning rule", mutate: func(event *Event) {
			event.DecisionExplanation.WinningRuleID = ""
		}},
		{name: "rule logging bypass", mutate: func(event *Event) {
			event.RuleIDs = nil
		}},
		{name: "duplicate winning rule", mutate: func(event *Event) {
			event.RuleIDs = append(event.RuleIDs, event.DecisionExplanation.WinningRuleID)
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			event := base
			event.RuleIDs = append([]string(nil), base.RuleIDs...)
			event.DecisionExplanation = cloneDecisionExplanation(base.DecisionExplanation)
			test.mutate(&event)
			if err := validateEvent(event); err == nil {
				t.Fatalf("validateEvent accepted contradictory explanation: %#v", event.DecisionExplanation)
			}
		})
	}
}

func TestRound8DecisionExplanationReadRejectsCrossFieldInconsistentSQLiteRow(t *testing.T) {
	tests := []struct {
		name      string
		wantError string
		rewrite   func(testing.TB, *Store, string)
	}{
		{
			name:      "category",
			wantError: "winning_category does not match category",
			rewrite: func(t testing.TB, store *Store, eventID string) {
				t.Helper()
				if _, err := store.db.Exec(`UPDATE audit_events SET category = ? WHERE id = ?`, "credential_theft", eventID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:      "rule IDs",
			wantError: "winning_rule_id must occur exactly once in rule_ids",
			rewrite: func(t testing.TB, store *Store, eventID string) {
				t.Helper()
				if _, err := store.db.Exec(`UPDATE audit_events SET rule_ids = ? WHERE id = ?`, `["CRED-001"]`, eventID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:      "risk score",
			wantError: "final_score does not match risk_score",
			rewrite: func(t testing.TB, store *Store, eventID string) {
				t.Helper()
				if _, err := store.db.Exec(`UPDATE audit_events SET risk_score = ? WHERE id = ?`, 89, eventID); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name:      "context adjustment",
			wantError: "context_adjustment is inconsistent",
			rewrite: func(t testing.TB, store *Store, eventID string) {
				t.Helper()
				contradictory := round8DecisionExplanationFixture()
				contradictory.ContextAdjustment++
				encoded, err := json.Marshal(contradictory)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := store.db.Exec(`UPDATE audit_events SET decision_explanation = ? WHERE id = ?`, string(encoded), eventID); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			now := time.Date(2026, 7, 21, 12, 45, 0, 0, time.UTC)
			store, err := Open(Config{
				Path: filepath.Join(t.TempDir(), "tampered-decision-explanation.db"),
				Now:  func() time.Time { return now },
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })

			eventID := "round8-tampered-decision-explanation"
			event := testEvent(eventID, now)
			event.Action = "block"
			event.Category = "defense_evasion"
			event.RiskScore = 90
			event.RuleIDs = []string{"EVADE-002"}
			event.Decision = "block_malicious_text"
			event.Coverage = "complete"
			event.Scanner = "streaming-scanner-v1"
			event.DecisionExplanation = round8DecisionExplanationFixture()
			if !store.Record(event) {
				t.Fatal("Record() rejected valid tamper-test fixture")
			}
			if err := store.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			if events, err := store.Query(context.Background(), Query{Limit: 1}); err != nil || len(events) != 1 {
				t.Fatalf("valid pre-tamper query events=%d err=%v", len(events), err)
			}

			test.rewrite(t, store, eventID)
			if events, err := store.Query(context.Background(), Query{Limit: 1}); err == nil {
				t.Fatalf("Query() returned %d events after a cross-field-inconsistent SQLite rewrite; want error", len(events))
			} else if !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("Query() error = %v, want substring %q", err, test.wantError)
			}
		})
	}
}

func TestRound8DecisionExplanationReadAcceptsInternallyConsistentSQLiteRewrite(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 12, 50, 0, 0, time.UTC)
	store, err := Open(Config{
		Path: filepath.Join(t.TempDir(), "consistent-decision-explanation-rewrite.db"),
		Now:  func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	eventID := "round8-consistent-decision-explanation-rewrite"
	event := testEvent(eventID, now)
	event.Action = "block"
	event.Category = "defense_evasion"
	event.RiskScore = 90
	event.RuleIDs = []string{"EVADE-002"}
	event.Decision = "block_malicious_text"
	event.Coverage = "complete"
	event.Scanner = "streaming-scanner-v1"
	event.DecisionExplanation = round8DecisionExplanationFixture()
	if !store.Record(event) {
		t.Fatal("Record() rejected valid consistency fixture")
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A writer with direct database access can coherently rewrite both sides of
	// the relationship. Read validation deliberately proves only schema and
	// cross-field consistency; it is not a cryptographic integrity guarantee.
	rewritten := round8DecisionExplanationFixture()
	rewritten.WinningCategory = "credential_theft"
	encoded, err := json.Marshal(rewritten)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(
		`UPDATE audit_events SET category = ?, decision_explanation = ? WHERE id = ?`,
		"credential_theft", string(encoded), eventID,
	); err != nil {
		t.Fatal(err)
	}
	events, err := store.Query(context.Background(), Query{Limit: 1})
	if err != nil || len(events) != 1 {
		t.Fatalf("Query() events=%d err=%v", len(events), err)
	}
	if events[0].Category != "credential_theft" ||
		events[0].DecisionExplanation == nil ||
		events[0].DecisionExplanation.WinningCategory != "credential_theft" {
		t.Fatalf("coherent SQLite rewrite was not returned consistently: %#v", events[0])
	}
}

func TestRound8AuditReadRejectsInvalidPersistedEvent(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 12, 55, 0, 0, time.UTC)
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "invalid-persisted-event.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	eventID := "round8-invalid-persisted-event"
	if !store.Record(testEvent(eventID, now)) {
		t.Fatal("Record() rejected valid persisted-event fixture")
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE audit_events SET action = ? WHERE id = ?`, "invalid", eventID); err != nil {
		t.Fatal(err)
	}
	if events, err := store.Query(context.Background(), Query{Limit: 1}); err == nil {
		t.Fatalf("Query() returned %d events with an invalid persisted action; want error", len(events))
	} else if !strings.Contains(err.Error(), `invalid action "invalid"`) {
		t.Fatalf("Query() error = %v, want invalid-action validation", err)
	}
}

func TestRound8DecisionExplanationRejectsUnsafeOrUnboundedMetadata(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*DecisionExplanation)
	}{
		{name: "request-text-shaped rule", mutate: func(value *DecisionExplanation) { value.WinningRuleID = "EVADE-002 raw text" }},
		{name: "unsupported role", mutate: func(value *DecisionExplanation) { value.WinningRole = "developer" }},
		{name: "unsupported provenance", mutate: func(value *DecisionExplanation) { value.WinningProvenance = "raw_prompt" }},
		{name: "unsupported composition", mutate: func(value *DecisionExplanation) { value.CrossSegmentComposition = "arbitrary" }},
		{name: "unsupported score dimension", mutate: func(value *DecisionExplanation) { value.ScoreBreakdown[0].Dimension = "raw_text" }},
		{name: "duplicate dimension", mutate: func(value *DecisionExplanation) {
			value.ScoreBreakdown[1].Dimension = value.ScoreBreakdown[0].Dimension
		}},
		{name: "duplicate evidence", mutate: func(value *DecisionExplanation) {
			value.ScoreBreakdown[0].EvidenceIDs = []string{"EVADE-002:intent:explicit_bypass", "EVADE-002:intent:explicit_bypass"}
		}},
		{name: "evidence assigned to multiple dimensions", mutate: func(value *DecisionExplanation) {
			value.ScoreBreakdown[1].EvidenceIDs = append(
				value.ScoreBreakdown[1].EvidenceIDs,
				value.ScoreBreakdown[0].EvidenceIDs[0],
			)
		}},
		{name: "hard floor without reason", mutate: func(value *DecisionExplanation) { value.HardFloorReason = "" }},
		{name: "unknown hard floor reason", mutate: func(value *DecisionExplanation) { value.HardFloorReason = "caller_supplied_reason" }},
		{name: "reason without hard floor", mutate: func(value *DecisionExplanation) { value.HardFloorApplied = false }},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := round8DecisionExplanationFixture()
			test.mutate(value)
			if err := validateDecisionExplanation(value); err == nil {
				t.Fatalf("validateDecisionExplanation accepted %#v", value)
			}
		})
	}

	oversized := round8DecisionExplanationFixture()
	oversized.ScoreBreakdown = nil
	for index, dimension := range []string{
		"core_predicate_score", "qualifier_score", "scope_coherence_score", "ownership_score",
		"active_directive_score", "context_adjustment", "contradiction_adjustment", "final_score",
	} {
		component := ScoreComponent{Dimension: dimension, Points: index}
		for evidence := 0; evidence < 128; evidence++ {
			component.EvidenceIDs = append(component.EvidenceIDs,
				fmt.Sprintf("EVADE-002:%02d:%03d:%s", index, evidence, strings.Repeat("a", 72)))
		}
		oversized.ScoreBreakdown = append(oversized.ScoreBreakdown, component)
	}
	if err := validateDecisionExplanation(oversized); err == nil || !strings.Contains(err.Error(), "32768") {
		t.Fatalf("oversized decision explanation error = %v", err)
	}
}

func TestRound8DecisionExplanationRejectsUnknownHardFloorReasonAfterJSONDecode(t *testing.T) {
	t.Parallel()
	encoded := []byte(`{"hard_floor_applied":true,"hard_floor_reason":"future_unregistered_reason"}`)
	var value DecisionExplanation
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if err := validateDecisionExplanation(&value); err == nil {
		t.Fatalf("validateDecisionExplanation accepted decoded unknown hard-floor reason: %#v", value)
	} else if !strings.Contains(err.Error(), "hard floor reason is unsupported") {
		t.Fatalf("validateDecisionExplanation error = %v, want unsupported hard-floor reason", err)
	}
}

func TestRound8StatsSeparateEventsUniqueRepeatsAndUnhashed(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 13, 0, 0, 0, time.UTC)
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "stats.db"), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	hashA := HashRequest([]byte("request-a"))
	hashB := HashRequest([]byte("request-b"))
	for index, requestHash := range []string{hashA, hashA, hashB, "", ""} {
		event := testEvent(fmt.Sprintf("round8-stats-%d", index), now.Add(time.Duration(index)*time.Nanosecond))
		event.RequestHash = requestHash
		if !store.Record(event) {
			t.Fatalf("Record(%d) failed", index)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Total != 5 || stats.Events != 5 || stats.UniqueRequests != 2 ||
		stats.RepeatEvents != 1 || stats.UnhashedEvents != 2 {
		t.Fatalf("round8 stats = %#v", stats)
	}
}

func TestRound8StatsRetryWindowSemantics(t *testing.T) {
	t.Parallel()
	windowStart := time.Date(2026, 7, 21, 13, 5, 0, 0, time.UTC)
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "retry-window-stats.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	requestHash := HashRequest([]byte("same-retried-request"))
	fixtures := []struct {
		id          string
		timestamp   time.Time
		requestHash string
		decision    string
		ruleIDs     []string
	}{
		{id: "same-key-first", timestamp: windowStart.Add(time.Second), requestHash: requestHash, decision: "allow_clean", ruleIDs: []string{"RULE-B", "RULE-A"}},
		{id: "same-key-retry-reordered", timestamp: windowStart.Add(2 * time.Second), requestHash: requestHash, decision: "allow_clean", ruleIDs: []string{"RULE-A", "RULE-B"}},
		{id: "next-window", timestamp: windowStart.Add(5 * time.Minute), requestHash: requestHash, decision: "allow_clean", ruleIDs: []string{"RULE-A", "RULE-B"}},
		{id: "different-decision", timestamp: windowStart.Add(3 * time.Second), requestHash: requestHash, decision: "audit_suspicious_text", ruleIDs: []string{"RULE-A", "RULE-B"}},
		{id: "different-rule-set", timestamp: windowStart.Add(4 * time.Second), requestHash: requestHash, decision: "allow_clean", ruleIDs: []string{"RULE-A", "RULE-C"}},
		{id: "unhashed-excluded", timestamp: windowStart.Add(5 * time.Second), requestHash: "", decision: "allow_clean", ruleIDs: []string{"RULE-A", "RULE-B"}},
	}
	for _, fixture := range fixtures {
		event := testEvent("round8-retry-window-"+fixture.id, fixture.timestamp)
		event.RequestHash = fixture.requestHash
		event.Decision = fixture.decision
		event.RuleIDs = append([]string(nil), fixture.ruleIDs...)
		if !store.Record(event) {
			t.Fatalf("Record(%s) failed", fixture.id)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 6 || stats.UniqueRequests != 1 || stats.RepeatEvents != 4 || stats.UnhashedEvents != 1 {
		t.Fatalf("legacy retry stats = %#v", stats)
	}
	if stats.RetryWindowSeconds != 300 || stats.UniqueDecisionRuleWindows != 4 || stats.WindowRepeatEvents != 1 {
		t.Fatalf("windowed retry stats = %#v", stats)
	}
}

func TestRound8StatsUsesSingleSnapshotDuringConcurrentWrites(t *testing.T) {
	now := time.Date(2026, 7, 21, 13, 30, 0, 0, time.UTC)
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "stats-snapshot.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	makeEvent := func(prefix string, index int) (Event, error) {
		event := testEvent(fmt.Sprintf("%s-%05d", prefix, index), now.Add(time.Duration(index)*time.Nanosecond))
		if index%2 == 0 {
			event.Action = "audit"
			event.Category = "exploitation"
		} else {
			event.Action = "block"
			event.Category = "defense_evasion"
			event.RiskScore = 90
		}
		return prepareEvent(event, now)
	}

	const seedEvents = 1000
	seedTx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < seedEvents; index++ {
		event, err := makeEvent("snapshot-seed", index)
		if err != nil {
			_ = seedTx.Rollback()
			t.Fatal(err)
		}
		if err := store.writeWork(seedTx, workItem{event: &event}); err != nil {
			_ = seedTx.Rollback()
			t.Fatal(err)
		}
	}
	if err := seedTx.Commit(); err != nil {
		t.Fatal(err)
	}

	const concurrentEvents = 750
	writerStarted := make(chan error, 1)
	writerDone := make(chan error, 1)
	go func() {
		for index := 0; index < concurrentEvents; index++ {
			event, err := makeEvent("snapshot-concurrent", seedEvents+index)
			if err != nil {
				if index == 0 {
					writerStarted <- err
				}
				writerDone <- err
				return
			}
			if err := store.writeWork(store.db, workItem{event: &event}); err != nil {
				if index == 0 {
					writerStarted <- err
				}
				writerDone <- err
				return
			}
			if index == 0 {
				writerStarted <- nil
			}
		}
		writerDone <- nil
	}()
	select {
	case writerErr := <-writerStarted:
		if writerErr != nil {
			t.Fatal(writerErr)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent statistics writer did not start")
	}

	for attempt := 0; attempt < 20; attempt++ {
		stats, err := store.Stats(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		var actionEvents, categoryEvents int64
		for _, count := range stats.ByAction {
			actionEvents += count
		}
		for _, count := range stats.ByCategory {
			categoryEvents += count
		}
		if stats.Total != stats.Events || actionEvents != stats.Events || categoryEvents != stats.Events {
			t.Fatalf("mixed statistics snapshot on attempt %d: stats=%#v action_sum=%d category_sum=%d",
				attempt, stats, actionEvents, categoryEvents)
		}
		if stats.UniqueRequests+stats.RepeatEvents+stats.UnhashedEvents != stats.Events {
			t.Fatalf("inconsistent request aggregates on attempt %d: stats=%#v", attempt, stats)
		}
	}
	if err := <-writerDone; err != nil {
		t.Fatal(err)
	}
	finalStats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if finalStats.Events != seedEvents+concurrentEvents {
		t.Fatalf("final events=%d, want %d", finalStats.Events, seedEvents+concurrentEvents)
	}
}

func TestRound8RawCaptureDeduplicatesWithinTTLAndRenewsAtBoundary(t *testing.T) {
	t.Parallel()
	base := time.Date(2026, 7, 21, 14, 0, 0, 0, time.UTC)
	clock := base
	const ttl = 2 * time.Hour
	store, err := Open(Config{
		Path:            filepath.Join(t.TempDir(), "raw-dedup.db"),
		Retention:       24 * time.Hour,
		QueueSize:       32,
		CleanupInterval: time.Hour,
		Now:             func() time.Time { return clock },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: ttl, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	raw := []byte(`{"message":"same request","api_key":"sk-round8-dedup-secret"}`)
	record := func(id string, timestamp time.Time) {
		t.Helper()
		clock = timestamp
		event := rawCaptureEvent(id, timestamp, "block", "block_malicious_text", raw)
		accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
			RawRequest: raw,
		})
		if err != nil || !accepted {
			t.Fatalf("EnqueueEventWithRawCapture(%s) accepted=%t err=%v", id, accepted, err)
		}
	}

	record("dedup-1", base)
	record("dedup-2", base.Add(time.Minute))
	record("dedup-3", base.Add(2*time.Minute))
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 1 || page.Captures[0].EventID != "dedup-1" {
		t.Fatalf("deduplicated captures=%#v err=%v", page.Captures, err)
	}
	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 3 || stats.UniqueRequests != 1 || stats.RepeatEvents != 2 ||
		stats.RawCaptureWritten != 1 || stats.RawCaptureDeduplicated != 2 {
		t.Fatalf("deduplicated stats=%#v", stats)
	}

	// The first preview expires exactly at TTL. Equality must permit a fresh
	// preview instead of extending the old row for another retry window.
	record("dedup-at-ttl", base.Add(ttl))
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, err = store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 1 || page.Captures[0].EventID != "dedup-at-ttl" {
		t.Fatalf("TTL-renewed captures=%#v err=%v", page.Captures, err)
	}
	stats, err = store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 4 || stats.UniqueRequests != 1 || stats.RepeatEvents != 3 ||
		stats.RawCaptureWritten != 2 || stats.RawCaptureDeduplicated != 2 {
		t.Fatalf("TTL-renewed stats=%#v", stats)
	}
}

func TestRound8RawCaptureDeduplicatesWithoutPersistingRequestHash(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 14, 30, 0, 0, time.UTC)
	store, err := Open(Config{
		Path:      filepath.Join(t.TempDir(), "raw-private-dedup.db"),
		Retention: 24 * time.Hour,
		Now:       func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 2 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	raw := []byte(`{"messages":[{"role":"user","content":"same blocked request"}]}`)
	for index := 0; index < 2; index++ {
		timestamp := now.Add(time.Duration(index) * time.Minute)
		event := rawCaptureEvent(fmt.Sprintf("private-dedup-%d", index), timestamp, "block", "block_malicious_text", raw)
		event.RequestHash = ""
		accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: "",
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
			RawRequest: raw,
		})
		if err != nil || !accepted {
			t.Fatalf("EnqueueEventWithRawCapture(%d) accepted=%t err=%v", index, accepted, err)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("private dedup captures=%#v err=%v", page.Captures, err)
	}
	if page.Captures[0].RequestHash != "" {
		t.Fatalf("private dedup persisted request_hash=%q", page.Captures[0].RequestHash)
	}
	if page.Captures[0].RawSHA256 == "" {
		t.Fatal("private dedup capture has no internal raw_sha256 key")
	}
	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.Events != 2 || stats.UniqueRequests != 0 || stats.RepeatEvents != 0 ||
		stats.UnhashedEvents != 2 || stats.RawCaptureWritten != 1 || stats.RawCaptureDeduplicated != 1 {
		t.Fatalf("private dedup stats=%#v", stats)
	}
}

func TestRound8RawCaptureCanonicalAliasesHashAndRedactionMetadata(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 7, 21, 15, 0, 0, 0, time.UTC)
	raw := []byte(`{"api_key":"sk-1234567890abcdef","note":"review"}`)
	capture, err := prepareRawCapture(RawCaptureInput{
		EventID: "round8-canonical", Action: "block", Decision: "block_malicious_text", RawRequest: raw,
	}, RawCaptureConfig{
		Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if capture.RequestHash != "" || capture.RawSHA256 == "" || capture.RedactionVersion != rawCaptureRedactionVersion ||
		capture.RedactionPatternHits <= 0 || !capture.RedactionApplied || !capture.Redacted ||
		capture.PreviewTruncated != capture.Truncated {
		t.Fatalf("canonical raw capture metadata=%#v", capture)
	}
	if strings.Contains(capture.RawPreview, "sk-1234567890abcdef") {
		t.Fatalf("canonical raw capture retained secret: %q", capture.RawPreview)
	}

	clean, err := prepareRawCapture(RawCaptureInput{
		EventID: "round8-clean", Action: "block", Decision: "block_malicious_text", RawRequest: []byte("ordinary review text"),
	}, RawCaptureConfig{
		Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if clean.RedactionApplied || clean.Redacted || clean.RedactionPatternHits != 0 ||
		clean.RedactionVersion != rawCaptureRedactionVersion {
		t.Fatalf("clean raw capture metadata=%#v", clean)
	}

	store, err := Open(Config{
		Path:      filepath.Join(t.TempDir(), "canonical-aliases.db"),
		Retention: 24 * time.Hour,
		Now:       func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 24, TTL: 12 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	event := rawCaptureEvent("round8-query-aliases", now, "block", "block_malicious_text", raw)
	accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
		RawRequest: raw,
	})
	if err != nil || !accepted {
		t.Fatalf("EnqueueEventWithRawCapture() accepted=%t err=%v", accepted, err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{EventID: event.ID, Limit: 1})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("QueryRawCapturesPage() captures=%d err=%v", len(page.Captures), err)
	}
	queried := page.Captures[0]
	if queried.PreviewTruncated != queried.Truncated || queried.RedactionApplied != queried.Redacted {
		t.Fatalf("queried canonical aliases disagree: %#v", queried)
	}
	if !queried.PreviewTruncated || !queried.RedactionApplied || queried.RedactionPatternHits <= 0 ||
		queried.RedactionVersion != rawCaptureRedactionVersion {
		t.Fatalf("queried canonical metadata=%#v", queried)
	}
}

func TestRound8RawCaptureReadRejectsMalformedPersistedRows(t *testing.T) {
	tests := []struct {
		name      string
		statement string
		args      []any
		wantError string
	}{
		{
			name:      "request hash",
			statement: `UPDATE raw_request_captures SET request_hash = ? WHERE event_id = ?`,
			args:      []any{"ROUND8_READ_REQUEST_HASH_CANARY"},
			wantError: "request_hash is not a SHA-256 correlation value",
		},
		{
			name:      "subject hash",
			statement: `UPDATE raw_request_captures SET subject_hash = ? WHERE event_id = ?`,
			args:      []any{"ROUND8_READ_SUBJECT_HASH_CANARY"},
			wantError: "subject_hash is not an HMAC-SHA256 correlation value",
		},
		{
			name:      "raw sha256",
			statement: `UPDATE raw_request_captures SET raw_sha256 = ? WHERE event_id = ?`,
			args:      []any{"ROUND8_READ_RAW_SHA_CANARY"},
			wantError: "raw_sha256 is not a SHA-256 integrity value",
		},
		{
			name:      "redaction metadata",
			statement: `UPDATE raw_request_captures SET redaction_pattern_hits = 1 WHERE event_id = ?`,
			wantError: "current redaction metadata is inconsistent",
		},
		{
			name:      "block action with non-block decision",
			statement: `UPDATE raw_request_captures SET decision = 'audit_suspicious_text' WHERE event_id = ?`,
			wantError: "block action requires a block decision",
		},
		{
			name:      "cooldown action with block decision",
			statement: `UPDATE raw_request_captures SET action = 'cooldown' WHERE event_id = ?`,
			wantError: "cooldown action requires cooldown_subject_risk",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			now := time.Date(2026, 7, 21, 15, 30, 0, 0, time.UTC)
			store, err := Open(Config{
				Path: filepath.Join(t.TempDir(), "raw-read-validation.db"),
				Now:  func() time.Time { return now },
				RawCapture: RawCaptureConfig{
					Enabled: true, MaxBytes: 8192, TTL: 72 * time.Hour,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = store.Close() })

			raw := []byte(`{"messages":[{"role":"user","content":"ordinary blocked request"}]}`)
			event := rawCaptureEvent("round8-read-validation", now, "block", "block_malicious_text", raw)
			accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
				EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
				SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
				RawRequest: raw,
			})
			if err != nil || !accepted {
				t.Fatalf("EnqueueEventWithRawCapture() accepted=%t err=%v", accepted, err)
			}
			if err := store.Flush(context.Background()); err != nil {
				t.Fatal(err)
			}
			if page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 1}); err != nil || len(page.Captures) != 1 {
				t.Fatalf("valid pre-tamper captures=%d err=%v", len(page.Captures), err)
			}

			args := append(append([]any(nil), test.args...), "round8-read-validation")
			if _, err := store.db.Exec(test.statement, args...); err != nil {
				t.Fatal(err)
			}
			page, err := store.QueryRawCapturesPage(context.Background(), RawCaptureQuery{Limit: 1})
			if err == nil {
				t.Fatalf("QueryRawCapturesPage() returned %d malformed rows; want error", len(page.Captures))
			}
			if !strings.Contains(err.Error(), test.wantError) {
				t.Fatalf("QueryRawCapturesPage() error=%v, want substring %q", err, test.wantError)
			}
			if strings.Contains(err.Error(), "CANARY") {
				t.Fatal("read validation error reflected malformed persisted content")
			}
		})
	}
}

func TestRound8RawCaptureWriteValidationKeepsPriorityEvent(t *testing.T) {
	now := time.Date(2026, 7, 21, 16, 0, 0, 0, time.UTC)
	store, err := Open(Config{
		Path: filepath.Join(t.TempDir(), "raw-write-validation.db"),
		Now:  func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, MaxBytes: 8192, TTL: 72 * time.Hour,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	preparePair := func(id string) (Event, RawRequestCapture) {
		t.Helper()
		raw := []byte(`{"messages":[{"role":"user","content":"blocked request for write validation"}]}`)
		event, err := prepareEvent(rawCaptureEvent(id, now, "block", "block_malicious_text", raw), now)
		if err != nil {
			t.Fatal(err)
		}
		capture, err := prepareRawCapture(RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
			RawRequest: raw,
		}, store.cfg.RawCapture, now)
		if err != nil {
			t.Fatal(err)
		}
		capture.RawSHA256 = "ROUND8_WRITE_RAW_SHA_CANARY"
		return event, capture
	}

	_, standaloneCapture := preparePair("round8-invalid-standalone-capture")
	if err := store.writeWork(store.db, workItem{rawCapture: &standaloneCapture}); err == nil {
		t.Fatal("writeWork() accepted a malformed raw capture")
	} else if strings.Contains(err.Error(), "CANARY") {
		t.Fatal("write validation error reflected malformed raw-capture content")
	}
	var captures int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM raw_request_captures`).Scan(&captures); err != nil {
		t.Fatal(err)
	}
	if captures != 0 {
		t.Fatalf("standalone malformed raw capture rows=%d, want 0", captures)
	}

	priorityEvent, compositeCapture := preparePair("round8-priority-event")
	store.handleBatch([]workItem{{event: &priorityEvent, rawCapture: &compositeCapture}})
	var events int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE id = ?`, priorityEvent.ID).Scan(&events); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM raw_request_captures WHERE event_id = ?`, priorityEvent.ID).Scan(&captures); err != nil {
		t.Fatal(err)
	}
	status := store.Status()
	if events != 1 || captures != 0 || status.Written != 1 || status.RawCaptureWritten != 0 || status.RawCaptureFailed != 1 {
		t.Fatalf("priority event contract events=%d captures=%d status=%#v", events, captures, status)
	}
}

func round8DecisionExplanationFixture() *DecisionExplanation {
	return &DecisionExplanation{
		WinningRuleID:           "EVADE-002",
		WinningCategory:         "defense_evasion",
		CorePredicateComplete:   true,
		EvidenceDimensionMask:   0b1111,
		EvidenceOccurrenceCount: 4,
		EvidenceSegmentCount:    1,
		WinningRole:             "user",
		WinningProvenance:       "content",
		CurrentTurnEvidence:     true,
		CrossSegmentComposition: "none",
		QuotedOrInertSuppressed: true,
		ContextAdjustment:       -5,
		HardFloorApplied:        true,
		HardFloorReason:         "complete_core_owned_active_scope_with_two_strong_qualifiers",
		ScoreBreakdown: []ScoreComponent{
			{Dimension: "core_predicate_score", Points: 60, EvidenceIDs: []string{"EVADE-002:intent:explicit_bypass", "EVADE-002:object:malicious_payload"}},
			{Dimension: "qualifier_score", Points: 35, EvidenceIDs: []string{"EVADE-002:control:edr", "EVADE-002:outcome:undetected"}},
			{Dimension: "context_adjustment", Points: -5},
			{Dimension: "final_score", Points: 90},
		},
	}
}
