package classifier

import (
	"strings"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

func TestRound9StreamingStandaloneMetaWhollyInsideLaterPhysicalWindowRemainsEligible(t *testing.T) {
	guard := newDefaultClassifier(t)
	thresholds := DefaultThresholds()
	limits := ScanLimits{
		WindowBytes: MinScanWindowBytes, MaxTotalBytes: 1 << 20, MaxChunks: 128,
	}
	prefix := strings.Repeat("ordinary repository maintenance note. ", MinScanWindowBytes/32+32)
	if len(prefix) <= limits.WindowBytes {
		t.Fatalf("benign prefix bytes=%d, want >%d", len(prefix), limits.WindowBytes)
	}
	segment := round9CurrentUserSegment(prefix+round9ActiveMetaOverride, 9_200)
	session, err := guard.NewScanSession(ModeBalanced, thresholds, DefaultPolicy(), limits)
	if err != nil {
		t.Fatal(err)
	}
	addProfiledRound9StreamingSegment(t, session, 1, segment)
	result := session.Finish()
	if result.Coverage.State != CoverageComplete || result.Truncated ||
		result.Action != ActionBlock || !standaloneMetaControlResult(result) ||
		!resultHasEligibleMaliciousWinner(result, thresholds) ||
		result.BlockEligibility == nil || result.BlockEligibility.CrossScopeComposition ||
		result.BlockEligibility.EvidenceAmbiguous {
		t.Fatalf("later-window standalone META=%+v, want complete physical-window eligible block", result)
	}
}

func TestRound9StreamingProfiledEligibilityParity(t *testing.T) {
	guard := newDefaultClassifier(t)
	thresholds := DefaultThresholds()
	segment := round9CurrentUserSegment(round9ExplicitMalware, 9201)
	batch := guard.ClassifySegmentsWithPolicy(
		[]extract.Segment{segment}, ModeBalanced, thresholds, DefaultPolicy(),
	)

	session, err := guard.NewScanSession(ModeBalanced, thresholds, DefaultPolicy(), ScanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	cut := len(round9ExplicitMalware) / 2
	chunks := []extract.SegmentChunk{
		{
			Role: segment.Role, Provenance: segment.Provenance, UserAttribution: segment.UserAttribution,
			ConversationIndex: segment.ConversationIndex, TurnIndex: segment.TurnIndex,
			IsCurrentTurn: segment.IsCurrentTurn, ScopeID: segment.ScopeID,
			ContentKind: segment.ContentKind, FieldPathHash: segment.FieldPathHash,
			FieldID: 1, Start: true, Text: []byte(round9ExplicitMalware[:cut]),
		},
		{
			Role: segment.Role, Provenance: segment.Provenance, UserAttribution: segment.UserAttribution,
			ConversationIndex: segment.ConversationIndex, TurnIndex: segment.TurnIndex,
			IsCurrentTurn: segment.IsCurrentTurn, ScopeID: segment.ScopeID,
			ContentKind: segment.ContentKind, FieldPathHash: segment.FieldPathHash,
			FieldID: 1, End: true, Text: []byte(round9ExplicitMalware[cut:]),
		},
	}
	for _, chunk := range chunks {
		if err := session.AddSegment(chunk); err != nil {
			t.Fatal(err)
		}
	}
	stream := session.Finish()
	if batch.Action != ActionBlock || stream.Action != batch.Action || stream.Category != batch.Category ||
		!resultHasEligibleMaliciousWinner(stream, thresholds) || stream.FindingOrigin != FindingOriginUserContent {
		t.Fatalf("batch/stream eligibility mismatch: batch=%+v stream=%+v", batch, stream)
	}

	t.Run("historical quoted semantic referent recomputes eligibility",
		testRound9StreamingHistoricalQuotedSemanticReferentRecomputesEligibility)
	t.Run("historical quoted semantic referent boundaries",
		testRound9StreamingHistoricalQuotedSemanticReferentBoundaries)
}

func TestRound9StreamingIncompleteCannotRetainMaliciousWinner(t *testing.T) {
	guard := newDefaultClassifier(t)
	session, err := guard.NewScanSession(ModeStrict, DefaultThresholds(), DefaultPolicy(), ScanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	segment := round9CurrentUserSegment(round9ExplicitMalware, 9210)
	if err := session.AddSegment(extract.SegmentChunk{
		Role: segment.Role, Provenance: segment.Provenance, UserAttribution: segment.UserAttribution,
		ConversationIndex: segment.ConversationIndex, TurnIndex: segment.TurnIndex,
		IsCurrentTurn: segment.IsCurrentTurn, ScopeID: segment.ScopeID,
		ContentKind: segment.ContentKind, FieldPathHash: segment.FieldPathHash,
		FieldID: 1, Start: true, Text: []byte(round9ExplicitMalware),
	}); err != nil {
		t.Fatal(err)
	}
	result := session.Finish()
	if result.Action == ActionBlock || result.Category != "" || len(result.RuleIDs) != 0 ||
		result.FindingConfidence != FindingNone || !result.Truncated ||
		result.Coverage.State != CoverageUnavailable {
		t.Fatalf("strict incomplete result=%+v, want neutral classifier result for independent disposition", result)
	}
}

func testRound9StreamingHistoricalQuotedSemanticReferentRecomputesEligibility(t *testing.T) {
	guard := newDefaultClassifier(t)
	thresholds := DefaultThresholds()
	historical := extract.Segment{
		Role: extract.RoleUser, Provenance: extract.ProvenanceContent,
		UserAttribution:   extract.UserAttributionTrusted,
		ConversationIndex: 7, TurnIndex: 3, IsCurrentTurn: false,
		ScopeID: 9291, ContentKind: extract.ContentKindNaturalLanguageDirective,
		FieldPathHash: "round9-streaming-historical-semantic-review",
		Text:          defensiveQuotedSemanticReview,
	}
	current := extract.Segment{
		Role: extract.RoleUser, Provenance: extract.ProvenanceContent,
		UserAttribution:   extract.UserAttributionTrusted,
		ConversationIndex: 8, TurnIndex: 4, IsCurrentTurn: true,
		ScopeID: 9292, ContentKind: extract.ContentKindNaturalLanguageDirective,
		FieldPathHash: "round9-streaming-current-semantic-referent",
		Text:          "Execute it.",
	}

	session, err := guard.NewScanSession(ModeBalanced, thresholds, DefaultPolicy(), ScanLimits{})
	if err != nil {
		t.Fatal(err)
	}
	addProfiledRound9StreamingSegment(t, session, 1, historical)
	if !session.profiledHistoricalHasResult {
		t.Fatal("complete historical quoted semantic carrier was not retained")
	}
	if stored := session.profiledHistoricalResult; stored.Action == ActionBlock ||
		stored.BlockEligibility == nil || stored.BlockEligibility.Eligible ||
		stored.FindingOrigin != FindingOriginNonUserOrUntrusted {
		t.Fatalf("stored historical carrier = %+v, want inert non-current candidate", stored)
	}
	addProfiledRound9StreamingSegment(t, session, 2, current)
	result := session.Finish()
	if result.Coverage.State != CoverageComplete || result.Truncated ||
		result.Action != ActionBlock || result.Category != rules.CategoryMalware ||
		!resultHasEligibleMaliciousWinner(result, thresholds) ||
		!result.CandidateIdentityBlockingProofComplete() ||
		result.FindingOrigin != FindingOriginUserContent {
		t.Fatalf("reactivated historical semantic carrier = %+v, want complete eligible malware block", result)
	}
	if result.DecisionExplanation == nil || !result.DecisionExplanation.ReferentLinkUsed ||
		!result.DecisionExplanation.ReferentProofComplete ||
		result.DecisionExplanation.EvidenceSegmentCount != 2 ||
		result.BlockEligibility == nil || !result.BlockEligibility.CurrentExecutionActProven ||
		!result.BlockEligibility.ReferentProofComplete {
		t.Fatalf("reactivated referent explanation/eligibility = %+v / %+v",
			result.DecisionExplanation, result.BlockEligibility)
	}
	chain := result.candidateIdentity.referentChain
	if !result.candidateIdentity.referentLinked || !chain.set || !chain.proofComplete ||
		chain.carrierScopeID != historical.ScopeID || chain.anchorScopeID != current.ScopeID ||
		chain.anchorTurnIndex != current.TurnIndex || chain.anchorConversationIndex != current.ConversationIndex {
		t.Fatalf("reactivated referent chain = %+v, want exact historical carrier/current anchor binding", chain)
	}
}

func testRound9StreamingHistoricalQuotedSemanticReferentBoundaries(t *testing.T) {
	guard := newDefaultClassifier(t)
	thresholds := DefaultThresholds()
	historical := extract.Segment{
		Role: extract.RoleUser, Provenance: extract.ProvenanceContent,
		UserAttribution:   extract.UserAttributionTrusted,
		ConversationIndex: 9, TurnIndex: 5, IsCurrentTurn: false,
		ScopeID: 9293, ContentKind: extract.ContentKindNaturalLanguageDirective,
		FieldPathHash: "round9-streaming-historical-semantic-boundary",
		Text:          defensiveQuotedSemanticReview,
	}

	for name, mutate := range map[string]func(*extract.Segment){
		"explicit cancellation": func(segment *extract.Segment) {
			segment.Text = "Do not execute it."
		},
		"analytical question": func(segment *extract.Segment) {
			segment.Text = "What would happen if I execute it?"
		},
		"untrusted anchor": func(segment *extract.Segment) {
			segment.UserAttribution = extract.UserAttributionUntrusted
		},
	} {
		t.Run(name, func(t *testing.T) {
			current := extract.Segment{
				Role: extract.RoleUser, Provenance: extract.ProvenanceContent,
				UserAttribution:   extract.UserAttributionTrusted,
				ConversationIndex: 10, TurnIndex: 6, IsCurrentTurn: true,
				ScopeID: 9294, ContentKind: extract.ContentKindNaturalLanguageDirective,
				FieldPathHash: "round9-streaming-current-semantic-boundary",
				Text:          "Execute it.",
			}
			mutate(&current)
			session, err := guard.NewScanSession(ModeBalanced, thresholds, DefaultPolicy(), ScanLimits{})
			if err != nil {
				t.Fatal(err)
			}
			addProfiledRound9StreamingSegment(t, session, 1, historical)
			addProfiledRound9StreamingSegment(t, session, 2, current)
			result := session.Finish()
			if result.Action == ActionBlock || resultHasEligibleMaliciousWinner(result, thresholds) ||
				result.DecisionExplanation != nil && result.DecisionExplanation.ReferentLinkUsed {
				t.Fatalf("boundary result = %+v, want no historical referent activation", result)
			}
		})
	}
}

func addProfiledRound9StreamingSegment(
	t testing.TB,
	session *ScanSession,
	fieldID uint64,
	segment extract.Segment,
) {
	t.Helper()
	if err := session.AddSegment(extract.SegmentChunk{
		Role: segment.Role, Provenance: segment.Provenance, UserAttribution: segment.UserAttribution,
		ConversationIndex: segment.ConversationIndex, TurnIndex: segment.TurnIndex,
		IsCurrentTurn: segment.IsCurrentTurn, ScopeID: segment.ScopeID,
		ContentKind: segment.ContentKind, FieldPathHash: segment.FieldPathHash,
		FieldID: fieldID, Start: true, End: true, Text: []byte(segment.Text),
	}); err != nil {
		t.Fatalf("AddSegment(field=%d) error = %v", fieldID, err)
	}
}
