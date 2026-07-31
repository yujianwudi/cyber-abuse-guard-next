package plugin

import (
	"sync"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

func TestRound10StrictUnknownSourceUsesAtomicCoverageCommit(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: strict\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	route := round6CallRoute(
		t,
		p,
		"future-provider-v10",
		[]byte(`{"messages":[{"role":"user","content":"ordinary text"}]}`),
		"application/json",
		false,
	)
	if !route.Handled || route.Reason != "cyber_abuse_guard_unknown_source_format" {
		t.Fatalf("strict unknown-source route=%+v, want local incomplete block", route)
	}

	snapshot := p.counters.snapshot()
	assertRound10UnscannedFailure(
		t,
		snapshot,
		coverageIncompleteUnknownSourceFormat,
		finalRouteDispositionIncompleteFailClosed,
	)
}

func TestRound10OversizedRPCUsesAtomicCoverageCommit(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: strict\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	raw, code := p.callOversizedModelRoute()
	if code != 0 {
		t.Fatalf("oversized model.route code=%d envelope=%s", code, raw)
	}
	var route pluginapi.ModelRouteResponse
	decodeOKResult(t, raw, &route)
	if !route.Handled {
		t.Fatalf("strict oversized route=%+v, want local incomplete block", route)
	}

	snapshot := p.counters.snapshot()
	assertRound10UnscannedFailure(
		t,
		snapshot,
		coverageIncompleteRPCBodyLimit,
		finalRouteDispositionIncompleteFailClosed,
	)
}

func TestRound10CoverageFailuresAreCrossDimensionAttributable(t *testing.T) {
	p := &Plugin{}

	var chunkObservation coverageDimensionObservation
	for index := range 2 {
		chunkObservation.add(extract.SegmentChunk{
			Role:        extract.RoleUser,
			ContentKind: extract.ContentKindCodeBlock,
			FieldID:     1,
			Start:       index == 0,
			Text:        []byte("x"),
		})
	}
	var chunkReasons coverageIncompleteReasonSet
	chunkReasons.add(coverageIncompleteClassificationChunkLimit)
	p.recordStreamingCoverage(
		extract.Result{
			TextCoverage:         extract.TextCoverageExhausted,
			TextBytesScanned:     2,
			ClassificationChunks: 2,
			IncompleteReasons:    []extract.IncompleteReason{extract.IncompleteClassificationChunkLimit},
		},
		classifier.Result{Coverage: classifier.Coverage{
			State:  classifier.CoverageBudgetExhausted,
			Reason: classifier.CoverageReasonClassificationLimit,
		}},
		[]extract.IncompleteReason{extract.IncompleteClassificationChunkLimit},
		chunkReasons,
		16<<10,
		&chunkObservation,
		coverageDispositionIncomplete,
	)

	var scanObservation coverageDimensionObservation
	for index := range 3 {
		scanObservation.add(extract.SegmentChunk{
			Role:        extract.RoleTool,
			ContentKind: extract.ContentKindToolResult,
			FieldID:     2,
			Start:       index == 0,
			End:         index == 2,
			Text:        []byte("y"),
		})
	}
	var scanReasons coverageIncompleteReasonSet
	scanReasons.add(coverageIncompleteRawScanLimit)
	p.recordStreamingCoverage(
		extract.Result{
			TextCoverage:         extract.TextCoverageExhausted,
			TextBytesScanned:     3,
			ClassificationChunks: 3,
			IncompleteReasons:    []extract.IncompleteReason{extract.IncompleteRawBodyLimit},
		},
		classifier.Result{Coverage: classifier.Coverage{State: classifier.CoverageUnavailable}},
		[]extract.IncompleteReason{extract.IncompleteRawBodyLimit},
		scanReasons,
		16<<10,
		&scanObservation,
		coverageDispositionIncomplete,
	)

	snapshot := p.counters.snapshot()
	if got := snapshot["coverage_failure_classification_chunk_limit_user_code_block_middle"]; got != 1 {
		t.Fatalf("chunk failure user/code/middle=%d, want 1", got)
	}
	if got := snapshot["coverage_failure_raw_scan_limit_tool_tool_result_back"]; got != 1 {
		t.Fatalf("scan failure tool/result/back=%d, want 1", got)
	}
	if got := snapshot["coverage_failure_classification_chunk_limit_tool_tool_result_back"]; got != 0 {
		t.Fatalf("chunk failure leaked into scan dimensions: %d", got)
	}
	if err := round10CoverageSnapshotInvariant(snapshot); err != nil {
		t.Fatal(err)
	}
}

func TestRound10EarlyFailureSnapshotsStayStableAndConcurrent(t *testing.T) {
	t.Parallel()
	const (
		workers = 4
		adds    = 40
	)
	p := &Plugin{}
	start := make(chan struct{})
	stop := make(chan struct{})
	failures := make(chan error, 1)

	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
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
	for worker := range workers {
		go func(worker int) {
			defer writers.Done()
			<-start
			for index := range adds {
				if (worker+index)%2 == 0 {
					p.recordUnscannedCoverageFailure(
						coverageIncompleteUnknownSourceFormat,
						nil,
						finalRouteDispositionIncompleteFailClosed,
					)
				} else {
					p.recordUnscannedCoverageFailure(
						coverageIncompleteRPCBodyLimit,
						[]extract.IncompleteReason{extract.IncompleteRPCBodyLimit},
						finalRouteDispositionIncompleteAllow,
					)
				}
			}
		}(worker)
	}
	close(start)
	writers.Wait()
	close(stop)
	reader.Wait()
	select {
	case err := <-failures:
		t.Fatal(err)
	default:
	}

	snapshot := p.counters.snapshot()
	if err := round10CoverageSnapshotInvariant(snapshot); err != nil {
		t.Fatal(err)
	}
	want := uint64(workers * adds)
	if snapshot["streaming_scan_requests"] != want || snapshot["coverage_disposition_incomplete"] != want {
		t.Fatalf("concurrent early failures requests/dispositions=%d/%d, want %d",
			snapshot["streaming_scan_requests"], snapshot["coverage_disposition_incomplete"], want)
	}
	if got, wantEach := snapshot["final_disposition_incomplete_fail_closed"], want/2; got != wantEach {
		t.Fatalf("concurrent early failures fail-closed=%d, want %d", got, wantEach)
	}
	if got, wantEach := snapshot["final_disposition_incomplete_allow"], want/2; got != wantEach {
		t.Fatalf("concurrent early failures allow=%d, want %d", got, wantEach)
	}
	if got := snapshot["final_disposition_unclassified"]; got != 0 {
		t.Fatalf("decided concurrent early failures counted unclassified=%d, want 0", got)
	}
}

func assertRound10UnscannedFailure(
	t testing.TB,
	snapshot map[string]uint64,
	reason coverageIncompleteReason,
	finalDisposition finalRouteDisposition,
) {
	t.Helper()
	if err := round10CoverageSnapshotInvariant(snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot["streaming_scan_requests"] != 1 ||
		snapshot["coverage_complete"] != 0 ||
		snapshot["coverage_incomplete"] != 1 ||
		snapshot["coverage_disposition_incomplete"] != 1 ||
		snapshot[coverageIncompleteMetricNames[reason]] != 1 {
		t.Fatalf("unscanned failure did not enter unified coverage commit: %v", snapshot)
	}
	for disposition := finalRouteDisposition(1); disposition < finalRouteDispositionCount; disposition++ {
		want := uint64(0)
		if disposition == finalDisposition {
			want = 1
		}
		if got := snapshot[finalRouteDispositionMetricNames[disposition]]; got != want {
			t.Fatalf("%s=%d, want %d", finalRouteDispositionMetricNames[disposition], got, want)
		}
	}
	wantKey := coverageFailureMetricNames[reason][coverageRoleUnknown][coverageContentUnknown][coverageFailurePositionUnknown]
	if snapshot[wantKey] != 1 {
		t.Fatalf("unscanned failure attribution %s=%d, want 1", wantKey, snapshot[wantKey])
	}
}
