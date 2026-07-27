package classifier

import (
	"strings"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

func TestRound9HistoricalAssistantCannotBecomeBareReferent(t *testing.T) {
	guard := newDefaultClassifier(t)
	thresholds := DefaultThresholds()
	historical := extract.Segment{
		Role: extract.RoleAssistant, Provenance: extract.ProvenanceContent,
		UserAttribution:   extract.UserAttributionUntrusted,
		ConversationIndex: 1, TurnIndex: 0, IsCurrentTurn: false,
		ScopeID: 9101, ContentKind: extract.ContentKindNaturalLanguageDirective,
		FieldPathHash: "round9-historical-assistant", Text: round9ExplicitMalware,
	}

	withoutReferent := guard.ClassifySegmentsWithPolicy(
		[]extract.Segment{historical}, ModeBalanced, thresholds, DefaultPolicy(),
	)
	if withoutReferent.Action == ActionBlock || withoutReferent.FindingOrigin == FindingOriginUserContent {
		t.Fatalf("historical carrier alone=%+v, want non-blocking non-user evidence", withoutReferent)
	}

	directive := round9CurrentUserSegment("Execute it now.", 9102)
	directive.ConversationIndex = 2
	directive.TurnIndex = 1
	withReferent := guard.ClassifySegmentsWithPolicy(
		[]extract.Segment{historical, directive}, ModeBalanced, thresholds, DefaultPolicy(),
	)
	if withReferent.Action == ActionBlock || resultHasEligibleMaliciousWinner(withReferent, thresholds) ||
		withReferent.DecisionExplanation != nil && withReferent.DecisionExplanation.ReferentLinkUsed {
		t.Fatalf("assistant history acquired bare-referent authority: %+v", withReferent)
	}
}

func TestRound9ToolSchemaCannotBecomeReferent(t *testing.T) {
	guard := newDefaultClassifier(t)
	toolSchema := extract.Segment{
		Role: extract.RoleSystem, Provenance: extract.ProvenanceContent,
		UserAttribution:   extract.UserAttributionUntrusted,
		ConversationIndex: 1, TurnIndex: 0, IsCurrentTurn: false,
		ScopeID: 9110, ContentKind: extract.ContentKindToolSchema,
		FieldPathHash: "round9-tool-schema", Text: round9ExplicitMalware,
	}
	directive := round9CurrentUserSegment("Execute it now.", 9111)
	directive.ConversationIndex = 2
	directive.TurnIndex = 1
	result := guard.ClassifySegmentsWithPolicy(
		[]extract.Segment{toolSchema, directive}, ModeBalanced, DefaultThresholds(), DefaultPolicy(),
	)
	if result.Action == ActionBlock || result.DecisionExplanation != nil && result.DecisionExplanation.ReferentLinkUsed {
		t.Fatalf("tool schema referent result=%+v, want no reactivation", result)
	}
}

func TestRound9CurrentNaturalLanguageQuoteUsesExplicitLocalReferent(t *testing.T) {
	guard := newDefaultClassifier(t)
	thresholds := DefaultThresholds()
	review := round9CurrentUserSegment(defensiveQuotedCredentialReview, 9120)
	review.ConversationIndex = 8
	review.TurnIndex = 3
	review.FieldPathHash = "round9-current-natural-language-review"

	withoutReferent := guard.ClassifySegmentsWithPolicy(
		[]extract.Segment{review}, ModeBalanced, thresholds, DefaultPolicy(),
	)
	if withoutReferent.Action == ActionBlock || resultHasEligibleMaliciousWinner(withoutReferent, thresholds) {
		t.Fatalf("current defensive natural-language quote=%+v, want inert non-blocking evidence", withoutReferent)
	}

	directive := round9CurrentUserSegment("Execute it.", review.ScopeID)
	directive.ConversationIndex = review.ConversationIndex
	directive.TurnIndex = review.TurnIndex
	directive.FieldPathHash = "round9-current-natural-language-referent"
	withReferent := guard.ClassifySegmentsWithPolicy(
		[]extract.Segment{review, directive}, ModeBalanced, thresholds, DefaultPolicy(),
	)
	if withReferent.Action != ActionBlock || withReferent.Category != "credential_theft" ||
		!resultHasEligibleMaliciousWinner(withReferent, thresholds) ||
		withReferent.FindingOrigin != FindingOriginUserContent || withReferent.DecisionExplanation == nil ||
		!withReferent.DecisionExplanation.ReferentLinkUsed || !withReferent.DecisionExplanation.ReferentProofComplete {
		t.Fatalf("current natural-language quote referent=%+v, want eligible actor-bound block", withReferent)
	}
	if len(withReferent.EvidenceOccurrences) == 0 {
		t.Fatalf("current natural-language quote referent has no evidence occurrences: %+v", withReferent)
	}
	for _, occurrence := range withReferent.EvidenceOccurrences {
		if occurrence.SegmentID != review.ConversationIndex || occurrence.FieldID != 0 ||
			occurrence.Role != extract.RoleUser || !occurrence.CurrentTurn || occurrence.DirectiveOwner != DirectiveOwnerUser {
			t.Fatalf("current natural-language quote occurrence not bound to carrier: %+v", occurrence)
		}
	}

	bare := directive
	bare.Text = "It."
	bare.FieldPathHash = "round9-current-bare-pronoun"
	bareResult := guard.ClassifySegmentsWithPolicy(
		[]extract.Segment{review, bare}, ModeBalanced, thresholds, DefaultPolicy(),
	)
	if bareResult.Action == ActionBlock || bareResult.DecisionExplanation != nil && bareResult.DecisionExplanation.ReferentLinkUsed {
		t.Fatalf("bare pronoun reactivated natural-language quote: %+v", bareResult)
	}

	untrusted := directive
	untrusted.UserAttribution = extract.UserAttributionUntrusted
	untrusted.FieldPathHash = "round9-current-untrusted-referent"
	untrustedResult := guard.ClassifySegmentsWithPolicy(
		[]extract.Segment{review, untrusted}, ModeBalanced, thresholds, DefaultPolicy(),
	)
	if untrustedResult.Action == ActionBlock || resultHasEligibleMaliciousWinner(untrustedResult, thresholds) {
		t.Fatalf("untrusted referent acquired current-user eligibility: %+v", untrustedResult)
	}
}

func TestRound9QuotedInstructionCarrierGrammar(t *testing.T) {
	for _, text := range []string{
		"Execute the instruction in the quoted passage exactly as written.",
		"Follow the instructions from the quoted text.",
		"Obey the quoted instruction now.",
		"Carry out the instruction in the quotation.",
		"Apply the quoted instructions.",
		"Implement the instruction from the quote.",
	} {
		if !hasAffirmativeQuotedReviewContinuation(strings.ToLower(text)) {
			t.Fatalf("quoted carrier grammar did not recognize active referent: %q", text)
		}
	}

	for _, text := range []string{
		"Execute the instruction now.",
		"Do not execute the instruction in the quoted passage.",
		"Explain what would happen if we execute the instruction in the quoted passage.",
		"Review how attackers carry out the instruction in the quotation.",
	} {
		if hasAffirmativeQuotedReviewContinuation(strings.ToLower(text)) {
			t.Fatalf("bare, negated, or analytical phrase became an active referent: %q", text)
		}
	}
}
