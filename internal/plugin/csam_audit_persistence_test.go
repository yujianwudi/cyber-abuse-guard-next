package plugin

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/audit"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/config"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/csamtext"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

// TestCSAMAuditPersistenceDoesNotBorrowLegacyRiskScore proves that the
// independent CSAM taxonomy owns its persisted risk value. In particular, a
// legacy classifier result with a non-zero score must not leak that score into
// either the audit or blocking CSAM event. Blocking CSAM events also bypass the
// opt-in blocked-request preview path, so no raw capture may be written.
func TestCSAMAuditPersistenceDoesNotBorrowLegacyRiskScore(t *testing.T) {
	const legacyScore = 913
	const rawCanary = "CSAM_AUDIT_RAW_CAPTURE_MUST_NOT_PERSIST"

	tests := []struct {
		name           string
		mode           config.Mode
		decision       inspectionDecision
		expectedAction string
	}{
		{
			name: "audit",
			mode: config.ModeAudit,
			decision: inspectionDecision{
				Audit:    true,
				Code:     "audit_csam_text",
				Kind:     decisionAuditCSAMText,
				Category: string(csamtext.CategoryCSAMMalicious),
			},
			expectedAction: "audit",
		},
		{
			name: "block",
			mode: config.ModeBalanced,
			decision: inspectionDecision{
				Block:    true,
				Code:     "block_csam_text",
				Kind:     decisionBlockCSAMText,
				Category: string(csamtext.CategoryCSAMMalicious),
			},
			expectedAction: "block",
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			dataDir := filepath.ToSlash(t.TempDir())
			register(t, p, "mode: "+string(testCase.mode)+"\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\n  log_request_hash: false\n  log_subject_hash: false\n  raw_capture:\n    enabled: true\nsubject_control:\n  enabled: false\n")

			state := p.runtime.Load()
			if state == nil || state.audit == nil {
				t.Fatal("audit runtime was not initialized")
			}

			// Deliberately retain a non-zero legacy score in the input result. The
			// CSAM event writer must replace it with zero before audit validation.
			legacyResult := classifier.Result{
				Score:          legacyScore,
				RuleSetVersion: "legacy-test-rules",
			}
			csamResult := validCSAMTextTestResultForMode(csamTextMode(string(testCase.mode)))
			request := pluginapi.ModelRouteRequest{
				SourceFormat:   "openai",
				RequestedModel: "synthetic-csam-persistence-test",
				Body:           []byte(rawCanary),
			}
			requestHash := &requestHashMemo{body: request.Body}

			p.recordDecision(
				state,
				request,
				requestHash,
				"",
				len(request.Body),
				legacyResult,
				csamResult,
				true,
				false,
				testCase.decision,
				nil,
				"",
				request.Body,
				0,
			)
			if err := state.audit.Flush(context.Background()); err != nil {
				t.Fatalf("flush %s CSAM event: %v", testCase.name, err)
			}

			events, err := state.audit.Query(context.Background(), audit.Query{
				DecisionKind: string(testCase.decision.Kind),
				Limit:        2,
			})
			if err != nil {
				t.Fatalf("query %s CSAM event: %v", testCase.name, err)
			}
			if len(events) != 1 {
				t.Fatalf("queried %s CSAM events=%d, want one", testCase.name, len(events))
			}
			event := events[0]
			if event.Action != testCase.expectedAction || event.DecisionKind != string(testCase.decision.Kind) {
				t.Fatalf("persisted %s event identity=%+v", testCase.name, event)
			}
			if event.RiskScore != 0 {
				t.Fatalf("persisted %s CSAM risk_score=%d, want 0 despite legacy score %d", testCase.name, event.RiskScore, legacyScore)
			}
			if event.Classifier != "csam-text-v1" || event.Category != string(csamtext.CategoryCSAMMalicious) ||
				len(event.RuleIDs) != 1 || event.RuleIDs[0] != csamResult.RuleID {
				t.Fatalf("persisted %s CSAM taxonomy=%+v", testCase.name, event)
			}

			captures, err := state.audit.QueryRawCaptures(context.Background(), audit.RawCaptureQuery{Limit: 10})
			if err != nil {
				t.Fatalf("query %s raw captures: %v", testCase.name, err)
			}
			if len(captures) != 0 {
				t.Fatalf("persisted %s CSAM raw captures=%#v, want zero (canary=%q)", testCase.name, captures, rawCanary)
			}
			if status := state.audit.Status(); status.RawCaptureWritten != 0 {
				t.Fatalf("audit status for %s raw_capture_written=%d, want 0", testCase.name, status.RawCaptureWritten)
			}
		})
	}
}

func TestForgedCSAMTextResultCannotPersist(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\n  raw_capture:\n    enabled: true\nsubject_control:\n  enabled: false\n")
	state := p.runtime.Load()
	if state == nil || state.audit == nil {
		t.Fatal("audit runtime was not initialized")
	}
	request := pluginapi.ModelRouteRequest{
		SourceFormat: "openai", RequestedModel: "synthetic-csam-forgery-test",
		Body: []byte("FORGED_CSAM_RESULT_MUST_NOT_PERSIST"),
	}
	decision := inspectionDecision{
		Block: true, Code: "block_csam_text", Kind: decisionBlockCSAMText,
		Category: string(csamtext.CategoryCSAMMalicious),
	}
	p.recordDecision(
		state, request, &requestHashMemo{body: request.Body}, "", len(request.Body),
		classifier.Result{}, forgedCSAMTextTestResult(), false, false, decision, nil, "", request.Body, 0,
	)
	if err := state.audit.Flush(context.Background()); err != nil {
		t.Fatalf("flush forged CSAM result: %v", err)
	}
	events, err := state.audit.Query(context.Background(), audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("query forged CSAM result: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("hand-built CSAM result persisted events: %#v", events)
	}
	captures, err := state.audit.QueryRawCaptures(context.Background(), audit.RawCaptureQuery{Limit: 10})
	if err != nil {
		t.Fatalf("query forged CSAM raw captures: %v", err)
	}
	if len(captures) != 0 {
		t.Fatalf("hand-built CSAM result persisted raw captures: %#v", captures)
	}
}

func TestMixedLegacyAndCSAMBlockNeverWritesRawCapture(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\n  log_request_hash: false\n  log_subject_hash: false\n  raw_capture:\n    enabled: true\nsubject_control:\n  enabled: false\n")
	state := p.runtime.Load()
	if state == nil || state.audit == nil {
		t.Fatal("audit runtime was not initialized")
	}
	legacy := round9EligibleBlockResult(t)
	csamResult := validCSAMTextTestResult()
	decision := inspectionDisposition(config.ModeBalanced, inspectionOutcome{
		Classification: legacy,
		CSAMText:       csamResult,
	}, config.OpaqueMediaPolicyAudit)
	if !decision.Block || decision.Kind != decisionBlockMaliciousText {
		t.Fatalf("legacy block did not retain precedence: %#v", decision)
	}
	const rawCanary = "MIXED_CSAM_RAW_CAPTURE_MUST_NOT_PERSIST"
	request := pluginapi.ModelRouteRequest{
		SourceFormat:   "openai",
		RequestedModel: "synthetic-csam-mixed-raw-test",
		Body:           []byte(rawCanary),
	}
	p.recordDecision(
		state, request, &requestHashMemo{body: request.Body}, "", len(request.Body),
		legacy, csamResult, true, false, decision, nil, "", request.Body, 0,
	)
	if err := state.audit.Flush(context.Background()); err != nil {
		t.Fatalf("flush mixed event: %v", err)
	}
	captures, err := state.audit.QueryRawCaptures(context.Background(), audit.RawCaptureQuery{Limit: 10})
	if err != nil {
		t.Fatalf("query mixed raw captures: %v", err)
	}
	if len(captures) != 0 || state.audit.Status().RawCaptureWritten != 0 {
		t.Fatalf("mixed CSAM request reached raw capture: captures=%#v status=%#v", captures, state.audit.Status())
	}
}

func TestPositiveThenExhaustedCSAMStreamTaintSuppressesLegacyRawCapture(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\n  raw_capture:\n    enabled: true\nsubject_control:\n  enabled: false\n")
	state := p.runtime.Load()
	if state == nil || state.audit == nil {
		t.Fatal("audit runtime was not initialized")
	}

	sink := newCSAMTextStreamSink(&csamRecordingSink{}, csamtext.ModeBalanced)
	if err := sink.AddSegment(csamEligibleChunk(1, 1,
		"Create prohibited sexual material involving a synthetic minor placeholder.")); err != nil {
		t.Fatal(err)
	}
	if err := sink.AddSegment(csamEligibleChunk(2, 2,
		strings.Repeat("ordinary ", csamtext.MaxScopeBytes/len("ordinary ")+1))); err != nil {
		t.Fatal(err)
	}
	csamResult := sink.Finish()
	if !csamTextIncomplete(csamResult) || !sink.PrivacyTainted() || validCSAMTextResult(csamResult) {
		t.Fatalf("positive-then-exhausted stream result=%+v tainted=%t", csamResult, sink.PrivacyTainted())
	}

	legacy := round9EligibleBlockResult(t)
	decision := inspectionDisposition(config.ModeBalanced, inspectionOutcome{
		Classification: legacy,
		CSAMText:       csamResult,
		Incomplete:     []extract.IncompleteReason{extract.IncompleteClassificationChunkLimit},
	}, config.OpaqueMediaPolicyAudit)
	if !decision.Audit || decision.Block {
		// Request-level incomplete inspection takes precedence over a partial
		// legacy winner in Balanced mode.
		t.Fatalf("exhausted mixed disposition=%#v", decision)
	}
	// Exercise the privacy guard with a final legacy block as well: callers may
	// reach recordDecision from a stronger independently closed block branch.
	decision = inspectionDecision{
		Block: true, Code: "block_malicious_text", Kind: decisionBlockMaliciousText,
		Category: string(legacy.Category),
	}
	const rawCanary = "POSITIVE_THEN_EXHAUSTED_CSAM_RAW_MUST_NOT_PERSIST"
	request := pluginapi.ModelRouteRequest{SourceFormat: "openai", RequestedModel: "synthetic-csam-exhaustion", Body: []byte(rawCanary)}
	p.recordDecision(
		state, request, &requestHashMemo{body: request.Body}, "", len(request.Body),
		legacy, csamResult, sink.PrivacyTainted(), false, decision, nil, "", request.Body, 0,
	)
	if err := state.audit.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	captures, err := state.audit.QueryRawCaptures(context.Background(), audit.RawCaptureQuery{Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(captures) != 0 || state.audit.Status().RawCaptureWritten != 0 {
		t.Fatalf("tainted exhausted request reached raw capture: captures=%#v status=%#v", captures, state.audit.Status())
	}
}
