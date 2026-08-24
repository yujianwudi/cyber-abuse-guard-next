package audit

import (
	"strings"
	"testing"
	"time"
)

func TestValidateEventCoverageMetadataConsistency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		coverage    string
		reason      string
		wantErrPart string
	}{
		{name: "complete", coverage: "complete"},
		{name: "complete-with-reason", coverage: "complete", reason: "parse_error", wantErrPart: "complete coverage"},
		{name: "incomplete", coverage: "incomplete", reason: "parse_error", wantErrPart: "allow_clean decision_kind requires complete inspection"},
		{name: "incomplete-without-reason", coverage: "incomplete", wantErrPart: "requires incomplete_reason"},
		{name: "legacy-unknown", coverage: "legacy_unknown", wantErrPart: "allow_clean decision_kind requires complete inspection"},
		{name: "legacy-unknown-with-valid-reason", coverage: "legacy_unknown", reason: "parse_error", wantErrPart: "allow_clean decision_kind requires complete inspection"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			event := Event{
				ID:               "coverage-contract",
				Timestamp:        time.Unix(1, 0).UTC(),
				Action:           "allow",
				Mode:             "observe",
				Decision:         "allow_clean",
				DecisionKind:     decisionKindAllowClean,
				Coverage:         test.coverage,
				IncompleteReason: test.reason,
				Scanner:          "streaming-scanner-v1",
			}
			err := validateEvent(event)
			if test.wantErrPart == "" {
				if err != nil {
					t.Fatalf("validateEvent() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErrPart) {
				t.Fatalf("validateEvent() error = %v, want substring %q", err, test.wantErrPart)
			}
		})
	}
}

func TestClassifierProofBudgetIncompleteReasonIsValid(t *testing.T) {
	if !validIncompleteReason("classifier_proof_budget") {
		t.Fatal("classifier proof-budget incomplete reason was rejected")
	}
}

func TestRemovedVerifiedHardPolicyIncompleteDispositionIsRejected(t *testing.T) {
	t.Parallel()

	const removed = "block_verified_hard_policy_under_incomplete_inspection"
	if validDecision(removed) {
		t.Fatalf("removed disposition %q remains in the active audit decision set", removed)
	}
	if got := decisionKindForDisposition(removed); got != decisionKindLegacyUnspecified {
		t.Fatalf("removed disposition kind = %q, want %q", got, decisionKindLegacyUnspecified)
	}
}
