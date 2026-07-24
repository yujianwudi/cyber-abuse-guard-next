package classifier

import (
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

// assertRound9IneligibleNonBlock keeps legacy regression scenarios useful
// without reviving the Round 8 assumption that score or a hard floor alone
// creates Balanced blocking eligibility. A scenario may still produce a
// high-score audit finding; it must not block unless the candidate-bound
// eligibility proof is complete.
func assertRound9IneligibleNonBlock(t testing.TB, result Result, allowedReasons ...DispositionGate) {
	t.Helper()
	if result.Action == ActionBlock {
		t.Fatalf("result=%+v, want Round 9 ineligible allow/audit", result)
	}
	if result.BlockEligibility == nil {
		if result.Score == 0 && len(result.RuleIDs) == 0 && result.Category == "" {
			return
		}
		t.Fatalf("result=%+v, want candidate-bound eligibility for retained finding", result)
	}
	if result.BlockEligibility.Eligible {
		t.Fatalf("eligibility=%+v, want ineligible candidate", result.BlockEligibility)
	}
	if len(allowedReasons) != 0 {
		matched := false
		for _, reason := range allowedReasons {
			if result.BlockEligibility.PrimaryReason == reason {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("eligibility reason=%q, want one of %v; result=%+v", result.BlockEligibility.PrimaryReason, allowedReasons, result)
		}
	}
	if result.DecisionExplanation != nil &&
		(result.DecisionExplanation.BlockEligible || result.DecisionExplanation.HardFloorApplied ||
			result.DecisionExplanation.HardFloorReason != hardFloorReasonNone) {
		t.Fatalf("ineligible finding retained blocking explanation: %+v", result.DecisionExplanation)
	}
}

func assertRound9EligibleBlock(t testing.TB, result Result, category rules.Category, ruleID string) {
	t.Helper()
	if result.Action != ActionBlock || result.Category != category ||
		!resultHasEligibleMaliciousWinner(result, DefaultThresholds()) {
		t.Fatalf("result=%+v, want eligible %s block", result, category)
	}
	if ruleID != "" && !resultContainsRuleID(result, ruleID) {
		t.Fatalf("result=%+v, want winning rule family %s", result, ruleID)
	}
}
