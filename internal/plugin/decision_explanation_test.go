package plugin

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

func TestAuditDecisionExplanationIsBoundedAndTextFree(t *testing.T) {
	const forbiddenPrompt = "private prompt text must never be persisted"
	result := classifier.Result{
		EvidenceOccurrences: []classifier.EvidenceOccurrence{
			{EvidenceID: "EVADE-002:intent:explicit-bypass", RuleID: "EVADE-002", Dimension: "intent", Start: 1, End: len(forbiddenPrompt)},
			{EvidenceID: "EVADE-002:intent:avoid-detection", RuleID: "EVADE-002", Dimension: "intent", Start: 2, End: 8},
			{EvidenceID: "EVADE-002:object:malicious-payload", RuleID: "EVADE-002", Dimension: "object", Start: 3, End: 9},
			{EvidenceID: "EVADE-002:target:edr", RuleID: "EVADE-002", Dimension: "target", Start: 10, End: 17},
		},
		DecisionExplanation: &classifier.DecisionExplanation{
			WinningRuleID:           "EVADE-002",
			WinningCategory:         "defense_evasion",
			CorePredicateComplete:   true,
			EvidenceDimensionMask:   0b1011,
			EvidenceOccurrenceCount: 4,
			EvidenceSegmentCount:    1,
			WinningRole:             extract.RoleUser,
			WinningProvenance:       extract.ProvenanceContent,
			CurrentTurnEvidence:     true,
			QuotedOrInertSuppressed: true,
			HardFloorApplied:        true,
			HardFloorReason:         "complete_core_owned_active_scope_with_two_strong_qualifiers",
			ScoreBreakdown: classifier.ScoreBreakdown{
				CorePredicateScore:   60,
				QualifierScore:       20,
				ScopeCoherenceScore:  5,
				OwnershipScore:       5,
				ActiveDirectiveScore: 5,
				FinalScore:           95,
			},
		},
	}

	explanation := auditDecisionExplanation(result)
	if explanation == nil {
		t.Fatal("audit decision explanation is nil")
	}
	if explanation.WinningRuleID != "EVADE-002" || explanation.WinningRole != "user" ||
		explanation.WinningProvenance != "content" || !explanation.HardFloorApplied ||
		!explanation.QuotedOrInertSuppressed {
		t.Fatalf("unexpected audit decision explanation: %+v", explanation)
	}
	encoded, err := json.Marshal(explanation)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), forbiddenPrompt) || strings.Contains(string(encoded), `"start"`) ||
		strings.Contains(string(encoded), `"end"`) {
		t.Fatalf("audit explanation leaked request text or offsets: %s", encoded)
	}
	if !strings.Contains(string(encoded), "EVADE-002:intent") ||
		!strings.Contains(string(encoded), "core_predicate_score") {
		t.Fatalf("audit explanation omitted stable evidence or score breakdown: %s", encoded)
	}
	if !strings.Contains(string(encoded), "EVADE-002:intent:explicit-bypass") ||
		!strings.Contains(string(encoded), "EVADE-002:intent:avoid-detection") {
		t.Fatalf("audit explanation collapsed distinct same-dimension occurrences: %s", encoded)
	}
	for _, component := range explanation.ScoreBreakdown {
		switch component.Dimension {
		case "scope_coherence_score", "ownership_score", "active_directive_score":
			if len(component.EvidenceIDs) != 0 {
				t.Fatalf("zero-point gate component claimed occurrence evidence: %+v", component)
			}
		}
	}
}

func TestAuditDecisionExplanationHonorsIdentifierLoggingPolicy(t *testing.T) {
	result := classifier.Result{
		EvidenceOccurrences: []classifier.EvidenceOccurrence{
			{RuleID: "CRED-001", Dimension: "intent"},
			{RuleID: "CRED-001", Dimension: "object"},
		},
		DecisionExplanation: &classifier.DecisionExplanation{
			WinningRuleID:         "CRED-001",
			WinningCategory:       "credential_theft",
			CorePredicateComplete: true,
			ScoreBreakdown: classifier.ScoreBreakdown{
				CorePredicateScore: 60,
				FinalScore:         60,
			},
		},
	}

	t.Run("both identifiers disabled", func(t *testing.T) {
		explanation := applyAuditDecisionExplanationLoggingPolicy(
			auditDecisionExplanation(result), false, false,
		)
		if explanation == nil {
			t.Fatal("audit decision explanation is nil")
		}
		if explanation.WinningCategory != "" || explanation.WinningRuleID != "" {
			t.Fatalf("disabled identifiers leaked through explanation: %+v", explanation)
		}
		for _, component := range explanation.ScoreBreakdown {
			if len(component.EvidenceIDs) != 0 {
				t.Fatalf("disabled rule IDs leaked evidence identifiers: %+v", component)
			}
		}
		if !explanation.CorePredicateComplete || explanation.ScoreBreakdown[len(explanation.ScoreBreakdown)-1].Points != 60 {
			t.Fatalf("privacy filtering removed identifier-free diagnostics: %+v", explanation)
		}
	})

	t.Run("category only", func(t *testing.T) {
		explanation := applyAuditDecisionExplanationLoggingPolicy(
			auditDecisionExplanation(result), true, false,
		)
		if explanation.WinningCategory != "credential_theft" || explanation.WinningRuleID != "" {
			t.Fatalf("category-only policy mismatch: %+v", explanation)
		}
		for _, component := range explanation.ScoreBreakdown {
			if len(component.EvidenceIDs) != 0 {
				t.Fatalf("category-only policy leaked evidence identifiers: %+v", component)
			}
		}
	})

	t.Run("rule only", func(t *testing.T) {
		explanation := applyAuditDecisionExplanationLoggingPolicy(
			auditDecisionExplanation(result), false, true,
		)
		if explanation.WinningCategory != "" || explanation.WinningRuleID != "CRED-001" {
			t.Fatalf("rule-only policy mismatch: %+v", explanation)
		}
		encoded, err := json.Marshal(explanation)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(encoded), "CRED-001:intent") {
			t.Fatalf("enabled rule IDs lost stable evidence identifiers: %s", encoded)
		}
	})
}
