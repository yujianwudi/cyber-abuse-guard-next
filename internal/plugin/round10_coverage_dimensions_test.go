package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

func TestRound10CoverageDimensionsAccountBoundedSinkChunks(t *testing.T) {
	t.Parallel()

	var observation coverageDimensionObservation
	for index, text := range []string{"aa", "bbb", "cccc"} {
		observation.add(extract.SegmentChunk{
			Role:        extract.RoleUser,
			ContentKind: extract.ContentKindNaturalLanguageDirective,
			FieldID:     1,
			Start:       index == 0,
			End:         index == 2,
			Text:        []byte(text),
		})
	}

	// Two content-kind pieces remain one original logical part while retaining
	// separate classifier chunk kinds.
	for ordinal, kind := range []extract.ContentKind{
		extract.ContentKindNaturalLanguageDirective,
		extract.ContentKindCodeBlock,
	} {
		observation.add(extract.SegmentChunk{
			Role:        extract.RoleSystem,
			ContentKind: kind,
			FieldID:     coverageContentPieceFieldIDFlag | uint64(7)<<coverageContentPieceOrdinalBits | uint64(ordinal+1),
			Start:       true,
			End:         true,
			Text:        []byte("piece"),
		})
	}

	derivedTool := []byte("decoded tool result")
	observation.add(extract.SegmentChunk{
		Role:        extract.RoleTool,
		ContentKind: extract.ContentKindToolResult,
		FieldID:     coverageDerivedFieldIDFlag | uint64(9)<<coverageDerivedFieldOrdinalBits | 1,
		Start:       true,
		End:         true,
		Text:        derivedTool,
	})

	var counters coverageDimensionCounters
	counters.add(&observation, coverageDispositionSemanticWinner)
	snapshot := counters.snapshot()

	if got := snapshot["coverage_logical_parts_user"]; got != 1 {
		t.Fatalf("user logical parts=%d, want 1", got)
	}
	if got := snapshot["coverage_logical_parts_system"]; got != 1 {
		t.Fatalf("system logical parts=%d, want one parent across content-kind pieces", got)
	}
	if got := snapshot["coverage_logical_parts_tool"]; got != 0 {
		t.Fatalf("derived tool view changed original logical parts: %d", got)
	}
	if got := snapshot["coverage_logical_bytes_user"]; got != uint64(len("aa")+len("bbb")+len("cccc")) {
		t.Fatalf("user logical bytes=%d", got)
	}
	if got := snapshot["coverage_derived_carrier_bytes"]; got != uint64(len(derivedTool)) {
		t.Fatalf("derived carrier bytes=%d, want %d", got, len(derivedTool))
	}
	if got := snapshot["coverage_tool_carrier_bytes"]; got != uint64(len(derivedTool)) {
		t.Fatalf("tool carrier bytes=%d, want %d", got, len(derivedTool))
	}
	for position, want := range map[string]uint64{"front": 1, "middle": 1, "back": 1} {
		key := "coverage_classification_chunks_user_natural_language_directive_" + position
		if got := snapshot[key]; got != want {
			t.Fatalf("%s=%d, want %d", key, got, want)
		}
	}
	if got := snapshot["coverage_classification_chunks_system_natural_language_directive_front"]; got != 1 {
		t.Fatalf("system directive front chunks=%d, want 1", got)
	}
	if got := snapshot["coverage_classification_chunks_system_code_block_front"]; got != 1 {
		t.Fatalf("system code front chunks=%d, want 1", got)
	}
	if got := snapshot["coverage_classification_chunks_tool_tool_result_front"]; got != 1 {
		t.Fatalf("derived tool-result front chunks=%d, want 1", got)
	}
	if got := snapshot["coverage_disposition_semantic_winner"]; got != 1 {
		t.Fatalf("semantic winner disposition=%d, want 1", got)
	}
}

func TestRound10CoverageLogicalFieldIDNamespaceInvariant(t *testing.T) {
	t.Parallel()

	const (
		parent                  = uint64(extract.HardMaxTextParts)
		contentPieceHighParent  = uint64(1<<14) + 1
		allNamespaceFlags       = coverageDerivedFieldIDFlag | coverageContentPieceFieldIDFlag
		maxDerivedOrdinal       = uint64(1<<coverageDerivedFieldOrdinalBits) - 2
		maxContentPieceOrdinal  = uint64(1<<coverageContentPieceOrdinalBits) - 2
		actualMaxDerivedOrdinal = uint64(7) // extract.maxDecodedVariants is fixed at 8.
		actualMaxContentOrdinal = uint64(extract.HardMaxClassificationChunks - 1)
	)

	tests := []struct {
		name      string
		fieldID   uint64
		wantID    uint64
		derived   bool
		wantFlags uint64
	}{
		{name: "ordinary", fieldID: parent, wantID: parent},
		{
			name:      "derived first ordinal",
			fieldID:   coverageDerivedFieldIDFlag | parent<<coverageDerivedFieldOrdinalBits | 1,
			wantID:    parent,
			derived:   true,
			wantFlags: coverageDerivedFieldIDFlag,
		},
		{
			name:      "derived actual maximum ordinal",
			fieldID:   coverageDerivedFieldIDFlag | parent<<coverageDerivedFieldOrdinalBits | actualMaxDerivedOrdinal + 1,
			wantID:    parent,
			derived:   true,
			wantFlags: coverageDerivedFieldIDFlag,
		},
		{
			name:      "derived adjacent to encoding maximum ordinal",
			fieldID:   coverageDerivedFieldIDFlag | parent<<coverageDerivedFieldOrdinalBits | maxDerivedOrdinal,
			wantID:    parent,
			derived:   true,
			wantFlags: coverageDerivedFieldIDFlag,
		},
		{
			name:      "derived encoding maximum ordinal",
			fieldID:   coverageDerivedFieldIDFlag | parent<<coverageDerivedFieldOrdinalBits | maxDerivedOrdinal + 1,
			wantID:    parent,
			derived:   true,
			wantFlags: coverageDerivedFieldIDFlag,
		},
		{
			name:      "content piece first ordinal",
			fieldID:   coverageContentPieceFieldIDFlag | parent<<coverageContentPieceOrdinalBits | 1,
			wantID:    parent,
			wantFlags: coverageContentPieceFieldIDFlag,
		},
		{
			name:      "content piece actual maximum ordinal",
			fieldID:   coverageContentPieceFieldIDFlag | parent<<coverageContentPieceOrdinalBits | actualMaxContentOrdinal + 1,
			wantID:    parent,
			wantFlags: coverageContentPieceFieldIDFlag,
		},
		{
			name:      "content piece adjacent to encoding maximum ordinal",
			fieldID:   coverageContentPieceFieldIDFlag | parent<<coverageContentPieceOrdinalBits | maxContentPieceOrdinal,
			wantID:    parent,
			wantFlags: coverageContentPieceFieldIDFlag,
		},
		{
			name:      "content piece encoding maximum ordinal",
			fieldID:   coverageContentPieceFieldIDFlag | parent<<coverageContentPieceOrdinalBits | maxContentPieceOrdinal + 1,
			wantID:    parent,
			wantFlags: coverageContentPieceFieldIDFlag,
		},
		{
			name:      "content piece parent bit fourteen is payload",
			fieldID:   coverageContentPieceFieldIDFlag | contentPieceHighParent<<coverageContentPieceOrdinalBits | 1,
			wantID:    contentPieceHighParent,
			wantFlags: allNamespaceFlags,
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := testCase.fieldID & allNamespaceFlags; got != testCase.wantFlags {
				t.Fatalf("namespace flags=%#x, want %#x", got, testCase.wantFlags)
			}
			gotID, gotDerived := coverageLogicalFieldID(testCase.fieldID)
			if gotID != testCase.wantID || gotDerived != testCase.derived {
				t.Fatalf("coverageLogicalFieldID(%#x)=(%d,%v), want (%d,%v)",
					testCase.fieldID, gotID, gotDerived, testCase.wantID, testCase.derived)
			}
		})
	}

	if contentPieceHighParent > uint64(extract.HardMaxJSONNodes+extract.HardMaxTextParts) {
		t.Fatalf("high-parent regression fixture=%d exceeds extractor parent bound", contentPieceHighParent)
	}
}

func TestRound10CoverageLogicalPartsDoNotSplitAcrossContentPieceOrdinals(t *testing.T) {
	t.Parallel()

	const (
		parent                 = uint64(1<<14) + 17
		maxContentPieceOrdinal = uint64(1<<coverageContentPieceOrdinalBits) - 2
		maxDerivedOrdinal      = uint64(1<<coverageDerivedFieldOrdinalBits) - 2
	)
	var observation coverageDimensionObservation
	for _, ordinal := range []uint64{0, 1, maxContentPieceOrdinal - 1, maxContentPieceOrdinal} {
		observation.add(extract.SegmentChunk{
			Role:        extract.RoleUser,
			ContentKind: extract.ContentKindNaturalLanguageDirective,
			FieldID:     coverageContentPieceFieldIDFlag | parent<<coverageContentPieceOrdinalBits | ordinal + 1,
			Start:       true,
			End:         true,
			Text:        []byte("x"),
		})
	}
	for _, ordinal := range []uint64{0, 1, maxDerivedOrdinal - 1, maxDerivedOrdinal} {
		observation.add(extract.SegmentChunk{
			Role:        extract.RoleUser,
			ContentKind: extract.ContentKindNaturalLanguageDirective,
			FieldID:     coverageDerivedFieldIDFlag | parent<<coverageDerivedFieldOrdinalBits | ordinal + 1,
			Start:       true,
			End:         true,
			Text:        []byte("x"),
		})
	}

	if got := observation.logicalParts[coverageRoleUser]; got != 1 {
		t.Fatalf("logical parts=%d, want one parent across adjacent and maximum namespace ordinals", got)
	}
	if got := observation.derivedCarrierBytes; got != 4 {
		t.Fatalf("derived carrier bytes=%d, want 4", got)
	}
}

func TestRound10CoveragePositionDoesNotInventBackForUnterminatedField(t *testing.T) {
	t.Parallel()
	var observation coverageDimensionObservation
	for index := range 3 {
		observation.add(extract.SegmentChunk{
			Role:        extract.RoleUser,
			ContentKind: extract.ContentKindNaturalLanguageDirective,
			FieldID:     1,
			Start:       index == 0,
			End:         false,
			Text:        []byte("x"),
		})
	}
	var counters coverageDimensionCounters
	counters.add(&observation, coverageDispositionIncomplete)
	snapshot := counters.snapshot()
	if got := snapshot["coverage_classification_chunks_user_natural_language_directive_front"]; got != 1 {
		t.Fatalf("front chunks=%d, want 1", got)
	}
	if got := snapshot["coverage_classification_chunks_user_natural_language_directive_middle"]; got != 2 {
		t.Fatalf("middle chunks=%d, want 2", got)
	}
	if got := snapshot["coverage_classification_chunks_user_natural_language_directive_back"]; got != 0 {
		t.Fatalf("unterminated field charged back chunks=%d", got)
	}
}

func TestRound10CoverageDimensionKeysAreFixedAndRequestIndependent(t *testing.T) {
	t.Parallel()

	baseline := (&coverageDimensionCounters{}).snapshot()
	wantKeys := round10ExpectedCoverageDimensionKeys()
	if len(baseline) != len(wantKeys) {
		t.Fatalf("fixed coverage key count=%d, want %d", len(baseline), len(wantKeys))
	}
	if len(baseline) > 256 {
		t.Fatalf("zero-valued coverage status surface=%d keys, want <= 256", len(baseline))
	}
	for key := range wantKeys {
		if _, ok := baseline[key]; !ok {
			t.Fatalf("fixed coverage key %q missing", key)
		}
	}

	const canary = "CALLER_repo-tool-id-request-hash-user-42"
	var observation coverageDimensionObservation
	observation.add(extract.SegmentChunk{
		Role:          extract.Role("caller-role-" + canary),
		ContentKind:   extract.ContentKind(255),
		FieldPathHash: "caller-field-" + canary,
		ScopeID:       0xffffffffffffffff,
		FieldID:       41,
		Start:         true,
		End:           true,
		Text:          []byte("request-text-" + canary),
	})
	var counters coverageDimensionCounters
	counters.add(&observation, coverageDispositionCompleteNoWinner)
	after := counters.snapshot()
	if !reflect.DeepEqual(round10CoverageDimensionKeySet(after), wantKeys) {
		t.Fatal("request-derived input changed the fixed coverage metric key set")
	}
	for key := range after {
		if strings.Contains(key, canary) || strings.Contains(key, "caller-role") || strings.Contains(key, "caller-field") {
			t.Fatalf("request-derived metric key escaped: %q", key)
		}
		if strings.HasPrefix(key, "coverage_failure_") {
			t.Fatalf("complete request emitted a zero-valued failure dimension: %q", key)
		}
	}
	if after["coverage_logical_parts_unknown"] != 1 ||
		after["coverage_classification_chunks_unknown_unknown_front"] != 1 ||
		after["coverage_disposition_complete_no_winner"] != 1 {
		t.Fatalf("unknown fixed buckets were not charged: %v", after)
	}
}

func TestRound10CoverageObservationStorageIsFixedAndBounded(t *testing.T) {
	t.Parallel()
	typeOf := reflect.TypeOf(coverageDimensionObservation{})
	if size := typeOf.Size(); size > 2<<10 {
		t.Fatalf("per-request coverage observation size=%d, want <= 2048 bytes", size)
	}
	for index := range typeOf.NumField() {
		field := typeOf.Field(index)
		switch field.Type.Kind() {
		case reflect.Array, reflect.Bool, reflect.Uint8, reflect.Uint64:
			// Fixed arrays and scalar state are the complete allowed storage set.
		default:
			t.Fatalf("per-request coverage field %s has unbounded kind %s", field.Name, field.Type.Kind())
		}
	}
}

func TestRound10ProductionRouteCoverageDimensionsReconcileCompleteAndIncomplete(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, strings.Join([]string{
		"mode: balanced",
		"max_scan_bytes: 16384",
		"max_text_window_bytes: 16384",
		"max_total_text_bytes: 65536",
		"audit:",
		"  enabled: false",
		"subject_control:",
		"  enabled: false",
		"",
	}, "\n"))

	safeBody := []byte(`{"messages":[{"role":"system","content":"Keep answers concise."},{"role":"user","content":"Summarize these release notes."},{"role":"assistant","content":"The release is stable."}]}`)
	round6CallRoute(t, p, "openai", safeBody, "application/json", false)
	round6CallRoute(t, p, "openai", []byte(maliciousRequest), "application/json", true)

	derivedBody, err := json.Marshal(map[string]string{"input": "ROUND10%20DERIVED%20VIEW%20CANARY"})
	if err != nil {
		t.Fatal(err)
	}
	round6CallRoute(t, p, "openai-response", derivedBody, "application/json", false)

	toolBody := []byte(`{"messages":[{"role":"user","content":"Run the health check."},{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"health","arguments":"{\"target\":\"service\"}"}}]},{"role":"tool","tool_call_id":"call_1","content":"service healthy"},{"role":"user","content":"Thanks."}]}`)
	round6CallRoute(t, p, "openai", toolBody, "application/json", true)

	longCompleteBody, err := json.Marshal(map[string]any{"messages": []map[string]string{{
		"role": "user", "content": strings.Repeat("ordinary documentation filler ", 1900),
	}}})
	if err != nil {
		t.Fatal(err)
	}
	round6CallRoute(t, p, "openai", longCompleteBody, "application/json", false)

	incompleteBody, err := json.Marshal(map[string]any{"messages": []map[string]string{
		{"role": "system", "content": "bounded prefix"},
		{"role": "user", "content": strings.Repeat("ordinary overflow filler ", 3000)},
	}})
	if err != nil {
		t.Fatal(err)
	}
	round6CallRoute(t, p, "openai", incompleteBody, "application/json", true)

	snapshot := p.counters.snapshot()
	const requests = uint64(6)
	if snapshot["streaming_scan_requests"] != requests {
		t.Fatalf("streaming requests=%d, want %d", snapshot["streaming_scan_requests"], requests)
	}
	dispositions := snapshot["coverage_disposition_semantic_winner"] +
		snapshot["coverage_disposition_complete_no_winner"] +
		snapshot["coverage_disposition_incomplete"]
	if dispositions != requests {
		t.Fatalf("coverage dispositions=%d, want %d; snapshot=%v", dispositions, requests, snapshot)
	}
	if snapshot["coverage_disposition_semantic_winner"] != 1 ||
		snapshot["coverage_disposition_complete_no_winner"] != 4 ||
		snapshot["coverage_disposition_incomplete"] != 1 {
		t.Fatalf("semantic/complete/incomplete dispositions=%d/%d/%d, want 1/4/1",
			snapshot["coverage_disposition_semantic_winner"],
			snapshot["coverage_disposition_complete_no_winner"],
			snapshot["coverage_disposition_incomplete"])
	}

	var roleBytes uint64
	for _, role := range []string{"system", "user", "assistant", "tool", "unknown"} {
		roleBytes += snapshot["coverage_logical_bytes_"+role]
	}
	if roleBytes != snapshot["text_bytes_scanned_total"] {
		t.Fatalf("role bytes=%d do not reconcile to streamed text bytes=%d", roleBytes, snapshot["text_bytes_scanned_total"])
	}

	var chunks uint64
	for key, value := range snapshot {
		if strings.HasPrefix(key, "coverage_classification_chunks_") {
			chunks += value
		}
	}
	if chunks != snapshot["classification_chunks_total"] {
		t.Fatalf("dimension chunks=%d do not reconcile to extractor chunks=%d", chunks, snapshot["classification_chunks_total"])
	}
	if snapshot["coverage_classification_chunks_user_natural_language_directive_front"] == 0 ||
		snapshot["coverage_classification_chunks_user_natural_language_directive_middle"] == 0 ||
		snapshot["coverage_classification_chunks_user_natural_language_directive_back"] == 0 {
		t.Fatalf("front/middle/back user dimensions were not all observed")
	}
	if snapshot["coverage_derived_carrier_bytes"] == 0 || snapshot["coverage_tool_carrier_bytes"] == 0 {
		t.Fatalf("derived/tool carrier dimensions=%d/%d, want both non-zero",
			snapshot["coverage_derived_carrier_bytes"], snapshot["coverage_tool_carrier_bytes"])
	}
	for _, role := range []string{"system", "user", "assistant", "tool"} {
		if snapshot["coverage_logical_parts_"+role] == 0 {
			t.Fatalf("production sink did not observe logical parts for role %s", role)
		}
	}
}

func TestRound10IncompleteDispositionDoesNotMutateSemanticWinner(t *testing.T) {
	t.Parallel()
	winner := classifier.Result{
		FindingConfidence: classifier.FindingCompleteRequest,
		Coverage:          classifier.Coverage{State: classifier.CoverageComplete},
		DecisionExplanation: &classifier.DecisionExplanation{
			WinningRuleID:   "SEMANTIC-malware_deployment",
			WinningCategory: "malware",
		},
	}
	want := *winner.DecisionExplanation
	if got := streamingCoverageDisposition(
		extract.Result{TextCoverage: extract.TextCoverageExhausted},
		winner,
		[]extract.IncompleteReason{extract.IncompleteTotalTextLimit},
	); got != coverageDispositionIncomplete {
		t.Fatalf("incomplete winner disposition=%d, want incomplete", got)
	}
	if !reflect.DeepEqual(*winner.DecisionExplanation, want) {
		t.Fatalf("coverage accounting mutated semantic winner: got=%+v want=%+v", *winner.DecisionExplanation, want)
	}
	if got := streamingCoverageDisposition(
		extract.Result{TextCoverage: extract.TextCoverageComplete}, winner, nil,
	); got != coverageDispositionSemanticWinner {
		t.Fatalf("complete winner disposition=%d, want semantic winner", got)
	}
}

func TestRound10CoverageDimensionCountersAreConcurrentAndRaceSafe(t *testing.T) {
	t.Parallel()
	const (
		workers = 12
		adds    = 100
	)
	var counters coverageDimensionCounters
	start := make(chan struct{})
	stopSnapshots := make(chan struct{})
	var reader sync.WaitGroup
	var writers sync.WaitGroup

	reader.Add(1)
	go func() {
		defer reader.Done()
		<-start
		for {
			select {
			case <-stopSnapshots:
				return
			default:
				_ = counters.snapshot()
			}
		}
	}()
	for range workers {
		writers.Add(1)
		go func() {
			defer writers.Done()
			<-start
			for range adds {
				var observation coverageDimensionObservation
				for index := range 3 {
					observation.add(extract.SegmentChunk{
						Role:        extract.RoleUser,
						ContentKind: extract.ContentKindNaturalLanguageDirective,
						FieldID:     1,
						Start:       index == 0,
						End:         index == 2,
						Text:        []byte("x"),
					})
				}
				counters.add(&observation, coverageDispositionCompleteNoWinner)
			}
		}()
	}
	close(start)
	want := uint64(workers * adds)
	writers.Wait()
	close(stopSnapshots)
	reader.Wait()

	snapshot := counters.snapshot()
	if snapshot["coverage_disposition_complete_no_winner"] != want ||
		snapshot["coverage_logical_parts_user"] != want ||
		snapshot["coverage_logical_bytes_user"] != want*3 {
		t.Fatalf("concurrent totals did not reconcile: dispositions=%d parts=%d bytes=%d want=%d/%d/%d",
			snapshot["coverage_disposition_complete_no_winner"],
			snapshot["coverage_logical_parts_user"],
			snapshot["coverage_logical_bytes_user"],
			want, want, want*3)
	}
	for _, position := range []string{"front", "middle", "back"} {
		key := "coverage_classification_chunks_user_natural_language_directive_" + position
		if snapshot[key] != want {
			t.Fatalf("%s=%d, want %d", key, snapshot[key], want)
		}
	}
}

func TestRound10CoverageSnapshotsStayRequestConsistentDuringConcurrentCommits(t *testing.T) {
	t.Parallel()
	const (
		workers = 8
		adds    = 250
	)
	p := &Plugin{}
	start := make(chan struct{})
	stop := make(chan struct{})
	failures := make(chan error, 1)
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		<-start
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := round10CoverageSnapshotInvariant(p.counters.snapshot()); err != nil {
				select {
				case failures <- err:
				default:
				}
				return
			}
		}
	}()

	var writers sync.WaitGroup
	writers.Add(workers)
	for range workers {
		go func() {
			defer writers.Done()
			<-start
			for range adds {
				var observation coverageDimensionObservation
				for index := range 3 {
					observation.add(extract.SegmentChunk{
						Role:        extract.RoleUser,
						ContentKind: extract.ContentKindNaturalLanguageDirective,
						FieldID:     1,
						Start:       index == 0,
						End:         index == 2,
						Text:        []byte("x"),
					})
				}
				p.recordStreamingCoverage(
					extract.Result{TextCoverage: extract.TextCoverageComplete, TextBytesScanned: 3, ClassificationChunks: 3},
					classifier.Result{Coverage: classifier.Coverage{State: classifier.CoverageComplete}},
					nil,
					0,
					16<<10,
					&observation,
					coverageDispositionCompleteNoWinner,
				)
			}
		}()
	}
	close(start)
	writers.Wait()
	close(stop)
	readers.Wait()
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}
	if err := round10CoverageSnapshotInvariant(p.counters.snapshot()); err != nil {
		t.Fatal(err)
	}
}

func TestRound10SinkAndTimeoutFailuresEnterUnifiedCoverageDenominator(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		name   string
		err    error
		reason string
	}{
		{name: "timeout", err: context.DeadlineExceeded, reason: "coverage_reason_timeout"},
		{name: "sink", err: errors.New("injected sink failure"), reason: "coverage_reason_extractor_sink"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			p := &Plugin{}
			var observation coverageDimensionObservation
			for index := range 2 {
				observation.add(extract.SegmentChunk{
					Role:        extract.RoleUser,
					ContentKind: extract.ContentKindNaturalLanguageDirective,
					FieldID:     1,
					Start:       index == 0,
					End:         false,
					Text:        []byte("x"),
				})
			}
			p.recordStreamingFailure(extract.Result{}, &observation, testCase.err, 16<<10)
			snapshot := p.counters.snapshot()
			if err := round10CoverageSnapshotInvariant(snapshot); err != nil {
				t.Fatal(err)
			}
			if snapshot["streaming_scan_requests"] != 1 || snapshot["coverage_incomplete"] != 1 ||
				snapshot["coverage_disposition_incomplete"] != 1 || snapshot[testCase.reason] != 1 {
				t.Fatalf("failure coverage counters did not reconcile: %v", snapshot)
			}
			if snapshot["coverage_classification_chunks_user_natural_language_directive_back"] != 0 {
				t.Fatal("failed unterminated field was charged as back coverage")
			}
		})
	}
}

func round10CoverageSnapshotInvariant(snapshot map[string]uint64) error {
	requests := snapshot["streaming_scan_requests"]
	dispositions := snapshot["coverage_disposition_semantic_winner"] +
		snapshot["coverage_disposition_complete_no_winner"] +
		snapshot["coverage_disposition_incomplete"]
	if requests != dispositions {
		return fmt.Errorf("streaming requests=%d dispositions=%d", requests, dispositions)
	}
	if requests != snapshot["coverage_complete"]+snapshot["coverage_incomplete"] {
		return fmt.Errorf("streaming requests=%d complete/incomplete=%d/%d", requests, snapshot["coverage_complete"], snapshot["coverage_incomplete"])
	}
	var finalDispositions uint64
	for disposition := finalRouteDisposition(1); disposition < finalRouteDispositionCount; disposition++ {
		finalDispositions += snapshot[finalRouteDispositionMetricNames[disposition]]
	}
	if requests != finalDispositions {
		return fmt.Errorf("streaming requests=%d final dispositions=%d", requests, finalDispositions)
	}
	var roleBytes, chunks uint64
	for key, value := range snapshot {
		if strings.HasPrefix(key, "coverage_logical_bytes_") {
			roleBytes += value
		}
		if strings.HasPrefix(key, "coverage_classification_chunks_") {
			chunks += value
		}
	}
	if roleBytes != snapshot["text_bytes_scanned_total"] {
		return fmt.Errorf("role bytes=%d text bytes=%d", roleBytes, snapshot["text_bytes_scanned_total"])
	}
	if chunks != snapshot["classification_chunks_total"] {
		return fmt.Errorf("dimension chunks=%d classification chunks=%d", chunks, snapshot["classification_chunks_total"])
	}
	for reason := coverageIncompleteReason(1); reason < coverageIncompleteReasonCount; reason++ {
		var attributed uint64
		for role := coverageRole(0); role < coverageRoleCount; role++ {
			for kind := coverageContentKind(0); kind < coverageContentKindCount; kind++ {
				for position := coverageFailurePosition(0); position < coverageFailurePositionCount; position++ {
					attributed += snapshot[coverageFailureMetricNames[reason][role][kind][position]]
				}
			}
		}
		if attributed != snapshot[coverageIncompleteMetricNames[reason]] {
			return fmt.Errorf("reason %s total=%d attributed=%d", coverageIncompleteReasonNames[reason], snapshot[coverageIncompleteMetricNames[reason]], attributed)
		}
	}
	return nil
}

func round10ExpectedCoverageDimensionKeys() map[string]struct{} {
	keys := make(map[string]struct{})
	roles := []string{"system", "user", "assistant", "tool", "unknown"}
	kinds := []string{
		"unknown", "natural_language_directive", "quoted_text", "code_block", "log_output",
		"tool_schema", "tool_call_arguments", "tool_result", "configuration", "documentation", "security_analysis",
	}
	positions := []string{"front", "middle", "back"}
	for _, role := range roles {
		keys["coverage_logical_parts_"+role] = struct{}{}
		keys["coverage_logical_bytes_"+role] = struct{}{}
		for _, kind := range kinds {
			for _, position := range positions {
				keys["coverage_classification_chunks_"+role+"_"+kind+"_"+position] = struct{}{}
			}
		}
	}
	for _, key := range []string{
		"coverage_derived_carrier_bytes",
		"coverage_tool_carrier_bytes",
		"coverage_disposition_semantic_winner",
		"coverage_disposition_complete_no_winner",
		"coverage_disposition_incomplete",
		"final_disposition_semantic_block",
		"final_disposition_complete_nonsemantic_block",
		"final_disposition_complete_allow",
		"final_disposition_incomplete_fail_closed",
		"final_disposition_incomplete_allow",
		"final_disposition_unclassified",
	} {
		keys[key] = struct{}{}
	}
	return keys
}

func round10CoverageDimensionKeySet(snapshot map[string]uint64) map[string]struct{} {
	keys := make(map[string]struct{}, len(snapshot))
	for key := range snapshot {
		keys[key] = struct{}{}
	}
	return keys
}
