package plugin

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

func TestRound10ClassifierCoverageReasonsUseOneExactBucket(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		coverage classifier.Coverage
		want     coverageIncompleteReason
	}{
		{
			name: "classification chunk limit",
			coverage: classifier.Coverage{
				State: classifier.CoverageBudgetExhausted, Reason: classifier.CoverageReasonClassificationLimit,
			},
			want: coverageIncompleteClassificationChunkLimit,
		},
		{
			name: "classifier proof budget",
			coverage: classifier.Coverage{
				State: classifier.CoverageUnavailable, Reason: classifier.CoverageReasonClassifierProofBudget,
			},
			want: coverageIncompleteClassifierProofBudget,
		},
		{
			name: "classifier window",
			coverage: classifier.Coverage{
				State: classifier.CoverageUnavailable, Reason: classifier.CoverageReasonClassifierWindow,
			},
			want: coverageIncompleteClassifierWindow,
		},
		{
			name: "total text limit",
			coverage: classifier.Coverage{
				State: classifier.CoverageBudgetExhausted, Reason: classifier.CoverageReasonTotalTextLimit,
			},
			want: coverageIncompleteTotalTextLimit,
		},
		{
			name: "invalid UTF-8",
			coverage: classifier.Coverage{
				State: classifier.CoverageUnavailable, Reason: classifier.CoverageReasonInvalidUTF8,
			},
			want: coverageIncompleteInvalidUTF8,
		},
		{
			name: "normalization carry",
			coverage: classifier.Coverage{
				State: classifier.CoverageUnavailable, Reason: classifier.CoverageReasonNormalizationCarry,
			},
			want: coverageIncompleteNormalizationCarry,
		},
		{
			name: "aborted",
			coverage: classifier.Coverage{
				State: classifier.CoverageUnavailable, Reason: classifier.CoverageReasonAborted,
			},
			want: coverageIncompleteClassifierAborted,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var counters coverageIncompleteCounters
			var reasons coverageIncompleteReasonSet
			reasons.add(classifierCoverageIncompleteReason(testCase.coverage))
			counters.add(reasons)
			assertRound10OneCoverageReason(t, counters.snapshot(), testCase.want)
		})
	}
}

func TestRound10ExtractorCoverageReasonsUseBoundedStageBuckets(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		reasons []extract.IncompleteReason
		want    coverageIncompleteReason
	}{
		{
			name: "classification chunk limit",
			reasons: []extract.IncompleteReason{
				extract.IncompleteClassificationChunkLimit,
			},
			want: coverageIncompleteClassificationChunkLimit,
		},
		{
			name: "classifier proof budget",
			reasons: []extract.IncompleteReason{
				extract.IncompleteClassifierProofBudget,
			},
			want: coverageIncompleteClassifierProofBudget,
		},
		{
			name: "text part byte limit",
			reasons: []extract.IncompleteReason{
				extract.IncompleteTextPartByteLimit,
			},
			want: coverageIncompleteTextPartLimit,
		},
		{
			name: "total text limit",
			reasons: []extract.IncompleteReason{
				extract.IncompleteTotalTextLimit,
			},
			want: coverageIncompleteTotalTextLimit,
		},
		{
			name: "raw scan limit",
			reasons: []extract.IncompleteReason{
				extract.IncompleteRawBodyLimit,
			},
			want: coverageIncompleteRawScanLimit,
		},
		{
			name: "JSON depth",
			reasons: []extract.IncompleteReason{
				extract.IncompleteJSONDepthLimit,
			},
			want: coverageIncompleteJSONDepth,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var counters coverageIncompleteCounters
			counters.add(extractorCoverageIncompleteReasons(testCase.reasons))
			assertRound10OneCoverageReason(t, counters.snapshot(), testCase.want)
		})
	}
}

func TestRound10OperationalCoverageReasonsSeparateTimeoutFromExtractorSink(t *testing.T) {
	t.Parallel()
	if got := extractorErrorCoverageIncompleteReason(nil); got != coverageIncompleteNone {
		t.Fatalf("nil extractor error reason = %d, want none", got)
	}
	for _, testCase := range []struct {
		name string
		err  error
		want coverageIncompleteReason
	}{
		{name: "timeout", err: context.DeadlineExceeded, want: coverageIncompleteTimeout},
		{name: "timeout through legacy sink wrapper", err: errors.New("extract: chunk sink: context deadline exceeded"), want: coverageIncompleteTimeout},
		{name: "extractor sink", err: errors.New("bounded sink failure"), want: coverageIncompleteExtractorSink},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			var counters coverageIncompleteCounters
			var reasons coverageIncompleteReasonSet
			reasons.add(extractorErrorCoverageIncompleteReason(testCase.err))
			counters.add(reasons)
			assertRound10OneCoverageReason(t, counters.snapshot(), testCase.want)
		})
	}
}

func TestRound10ByteAccountingMismatchHasDedicatedReason(t *testing.T) {
	t.Parallel()
	extracted := extract.Result{TextBytesScanned: 17}
	result := classifier.Result{Coverage: classifier.Coverage{State: classifier.CoverageComplete, Bytes: 16}}
	if got := byteAccountingCoverageIncompleteReason(extracted, result); got != coverageIncompleteByteAccountingMismatch {
		t.Fatalf("byte accounting reason = %d, want %d", got, coverageIncompleteByteAccountingMismatch)
	}
	result.Coverage.Bytes = 17
	if got := byteAccountingCoverageIncompleteReason(extracted, result); got != coverageIncompleteNone {
		t.Fatalf("reconciled byte accounting reason = %d, want none", got)
	}
}

func TestRound10CompatibilityTotalsDoNotCollapseCoverageReasons(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name               string
		extracted          extract.Result
		coverage           classifier.Coverage
		compatibility      []extract.IncompleteReason
		reason             coverageIncompleteReason
		wantMaxWindows     uint64
		wantTotalTextLimit uint64
	}{
		{
			name: "classifier chunk budget",
			coverage: classifier.Coverage{
				State: classifier.CoverageBudgetExhausted, Reason: classifier.CoverageReasonClassificationLimit,
			},
			compatibility:  []extract.IncompleteReason{extract.IncompleteClassificationChunkLimit},
			reason:         coverageIncompleteClassificationChunkLimit,
			wantMaxWindows: 1,
		},
		{
			name: "extractor chunk budget",
			extracted: extract.Result{
				IncompleteReasons: []extract.IncompleteReason{extract.IncompleteClassificationChunkLimit},
			},
			coverage: classifier.Coverage{
				State: classifier.CoverageUnavailable, Reason: classifier.CoverageReasonAborted,
			},
			compatibility:  []extract.IncompleteReason{extract.IncompleteClassificationChunkLimit},
			reason:         coverageIncompleteClassificationChunkLimit,
			wantMaxWindows: 1,
		},
		{
			name: "classifier proof budget",
			coverage: classifier.Coverage{
				State: classifier.CoverageUnavailable, Reason: classifier.CoverageReasonClassifierProofBudget,
			},
			compatibility: []extract.IncompleteReason{extract.IncompleteClassifierProofBudget},
			reason:        coverageIncompleteClassifierProofBudget,
		},
		{
			name: "classifier window legacy disposition",
			coverage: classifier.Coverage{
				State: classifier.CoverageUnavailable, Reason: classifier.CoverageReasonClassifierWindow,
			},
			compatibility: []extract.IncompleteReason{extract.IncompleteClassificationChunkLimit},
			reason:        coverageIncompleteClassifierWindow,
		},
		{
			name: "total text budget",
			coverage: classifier.Coverage{
				State: classifier.CoverageBudgetExhausted, Reason: classifier.CoverageReasonTotalTextLimit,
			},
			compatibility:      []extract.IncompleteReason{extract.IncompleteTotalTextLimit},
			reason:             coverageIncompleteTotalTextLimit,
			wantTotalTextLimit: 1,
		},
		{
			name:          "raw scan limit",
			extracted:     extract.Result{IncompleteReasons: []extract.IncompleteReason{extract.IncompleteRawBodyLimit}},
			coverage:      classifier.Coverage{State: classifier.CoverageUnavailable, Reason: classifier.CoverageReasonAborted},
			compatibility: []extract.IncompleteReason{extract.IncompleteRawBodyLimit},
			reason:        coverageIncompleteRawScanLimit,
		},
		{
			name:          "JSON depth",
			extracted:     extract.Result{IncompleteReasons: []extract.IncompleteReason{extract.IncompleteJSONDepthLimit}},
			coverage:      classifier.Coverage{State: classifier.CoverageUnavailable, Reason: classifier.CoverageReasonAborted},
			compatibility: []extract.IncompleteReason{extract.IncompleteJSONDepthLimit},
			reason:        coverageIncompleteJSONDepth,
		},
		{
			name: "invalid UTF-8",
			coverage: classifier.Coverage{
				State: classifier.CoverageUnavailable, Reason: classifier.CoverageReasonInvalidUTF8,
			},
			compatibility: []extract.IncompleteReason{extract.IncompleteParseError},
			reason:        coverageIncompleteInvalidUTF8,
		},
		{
			name:          "byte accounting mismatch",
			coverage:      classifier.Coverage{State: classifier.CoverageComplete},
			compatibility: []extract.IncompleteReason{extract.IncompleteClassificationChunkLimit},
			reason:        coverageIncompleteByteAccountingMismatch,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			p := &Plugin{}
			var reasons coverageIncompleteReasonSet
			reasons.add(testCase.reason)
			p.recordStreamingCoverage(
				testCase.extracted,
				classifier.Result{Coverage: testCase.coverage},
				testCase.compatibility,
				reasons,
				16<<10,
				&coverageDimensionObservation{},
				coverageDispositionIncomplete,
			)

			legacy := p.counters.snapshot()
			if legacy["coverage_incomplete"] != 1 || legacy["coverage_complete"] != 0 {
				t.Fatalf("legacy coverage totals = %v, want one incomplete request", legacy)
			}
			if got := legacy["max_windows_exhausted"]; got != testCase.wantMaxWindows {
				t.Fatalf("max_windows_exhausted = %d, want %d; counters=%v", got, testCase.wantMaxWindows, legacy)
			}
			if got := legacy["total_text_limit_exhausted"]; got != testCase.wantTotalTextLimit {
				t.Fatalf("total_text_limit_exhausted = %d, want %d; counters=%v", got, testCase.wantTotalTextLimit, legacy)
			}
			assertRound10OneCoverageReason(t, legacy, testCase.reason)
		})
	}
}

func TestRound10CompleteCoverageDoesNotIncrementReasonCounters(t *testing.T) {
	t.Parallel()
	p := &Plugin{}
	p.recordStreamingCoverage(
		extract.Result{TextCoverage: extract.TextCoverageComplete},
		classifier.Result{Coverage: classifier.Coverage{State: classifier.CoverageComplete}},
		nil,
		0,
		16<<10,
		&coverageDimensionObservation{},
		coverageDispositionCompleteNoWinner,
	)

	legacy := p.counters.snapshot()
	if legacy["coverage_complete"] != 1 || legacy["coverage_incomplete"] != 0 || legacy["max_windows_exhausted"] != 0 {
		t.Fatalf("complete request changed legacy incomplete counters: %v", legacy)
	}
	for key, value := range p.counters.coverageIncompleteSnapshot() {
		if value != 0 {
			t.Fatalf("complete request incremented %s=%d", key, value)
		}
	}
}

func TestRound10CoverageReasonCountersAreConcurrentAndFixed(t *testing.T) {
	t.Parallel()
	const (
		workers = 16
		adds    = 500
	)
	var counters coverageIncompleteCounters
	var reasons coverageIncompleteReasonSet
	reasons.add(coverageIncompleteClassificationChunkLimit)
	reasons.add(coverageIncompleteRawScanLimit)

	var wait sync.WaitGroup
	wait.Add(workers)
	for range workers {
		go func() {
			defer wait.Done()
			for range adds {
				counters.add(reasons)
			}
		}()
	}
	wait.Wait()

	snapshot := counters.snapshot()
	if len(snapshot) != int(coverageIncompleteReasonCount-1) {
		t.Fatalf("fixed counter count = %d, want %d: %v", len(snapshot), coverageIncompleteReasonCount-1, snapshot)
	}
	want := uint64(workers * adds)
	for reason := coverageIncompleteReason(1); reason < coverageIncompleteReasonCount; reason++ {
		key := coverageIncompleteMetricNames[reason]
		value := snapshot[key]
		if reasons.contains(reason) {
			if value != want {
				t.Fatalf("%s = %d, want %d", key, value, want)
			}
		} else if value != 0 {
			t.Fatalf("unselected reason %s = %d, want 0", key, value)
		}
	}
}

func assertRound10OneCoverageReason(t testing.TB, snapshot map[string]uint64, want coverageIncompleteReason) {
	t.Helper()
	for reason := coverageIncompleteReason(1); reason < coverageIncompleteReasonCount; reason++ {
		key := coverageIncompleteMetricNames[reason]
		wantValue := uint64(0)
		if reason == want {
			wantValue = 1
		}
		if got := snapshot[key]; got != wantValue {
			t.Fatalf("%s = %d, want %d; all counters=%v", key, got, wantValue, snapshot)
		}
	}
}
