package classifier

import (
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

func TestEligibleMaliciousWinnerRequiresContainedRuleAndEligibilityParity(t *testing.T) {
	eligibility := CandidateBlockEligibility{
		InspectionComplete:         true,
		EvidenceOwnedByCurrentUser: true,
		CurrentExecutionActProven:  true,
		HarmfulCoreComplete:        true,
		OperationallyActionable:    true,
		AuthorizationClaim:         AuthorizationConflicting,
		ExplicitVictimOrNonConsent: true,
		ReferentProofComplete:      true,
		Eligible:                   true,
		PrimaryReason:              GateEligibleExplicitMalice,
	}
	explanation := &DecisionExplanation{
		WinningRuleID:   "CRED-002",
		WinningCategory: string(rules.CategoryCredentialTheft),
	}
	applyEligibilityToExplanation(explanation, eligibility)
	result := Result{
		Score:               DefaultThresholds().BalancedBlock,
		Category:            rules.CategoryCredentialTheft,
		RuleIDs:             []string{"CRED-002"},
		BlockEligibility:    &eligibility,
		DecisionExplanation: explanation,
	}
	if !resultHasEligibleMaliciousWinner(result, DefaultThresholds()) {
		t.Fatalf("valid winner rejected: %+v", result)
	}

	missingWinner := result
	missingWinner.RuleIDs = []string{"CRED-001"}
	if resultHasEligibleMaliciousWinner(missingWinner, DefaultThresholds()) {
		t.Fatal("winner absent from RuleIDs was accepted")
	}

	contradictory := result
	contradictoryExplanation := *result.DecisionExplanation
	contradictoryExplanation.OperationallyActionable = false
	contradictory.DecisionExplanation = &contradictoryExplanation
	if resultHasEligibleMaliciousWinner(contradictory, DefaultThresholds()) {
		t.Fatal("eligibility explanation contradiction was accepted")
	}

	axisFree := result
	axisFreeEligibility := *result.BlockEligibility
	axisFreeEligibility.ExplicitVictimOrNonConsent = false
	axisFreeEligibility.CovertAcquisition = false
	axisFreeEligibility.ExfiltrationOrTakeover = false
	axisFreeEligibility.MaliciousPersistence = false
	axisFreeEligibility.DestructiveOutcome = false
	axisFreeEligibility.SecurityControlEvasion = false
	axisFreeEligibility = finalizeCandidateBlockEligibility(axisFreeEligibility)
	axisFree.BlockEligibility = &axisFreeEligibility
	axisFreeExplanation := *result.DecisionExplanation
	applyEligibilityToExplanation(&axisFreeExplanation, axisFreeEligibility)
	axisFree.DecisionExplanation = &axisFreeExplanation
	if axisFreeEligibility.Eligible || axisFreeEligibility.HarmfulCoreComplete ||
		resultHasEligibleMaliciousWinner(axisFree, DefaultThresholds()) {
		t.Fatalf("axis-free candidate retained malicious winner eligibility: %+v", axisFree)
	}
}
