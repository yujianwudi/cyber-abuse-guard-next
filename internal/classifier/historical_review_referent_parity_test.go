package classifier

import (
	"fmt"
	"strings"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

func TestHistoricalUserSafetyReviewReferentBatchStreamingParity(t *testing.T) {
	guard := newDefaultClassifier(t)
	for _, mode := range []Mode{ModeBalanced, ModeStrict} {
		mode := mode
		for _, testCase := range []struct {
			name             string
			history          []extract.Segment
			interstitial     *extract.Segment
			chunkFirstReview bool
			wantEvidence     int
		}{
			{
				name:             "single field split across chunks",
				history:          []extract.Segment{historicalReviewSegment(defensiveQuotedCredentialReview, 71_001, "single")},
				chunkFirstReview: true,
				wantEvidence:     2,
			},
			{
				name: "long single field privacy safe proof",
				history: []extract.Segment{historicalReviewSegment(
					quotedSafetyReviewForReferent(
						defensiveQuotedCredentialReferent+strings.Repeat(" ordinary documentation filler", 32),
					),
					71_006,
					"long-single",
				)},
				chunkFirstReview: true,
				wantEvidence:     2,
			},
			{
				name:         "assistant acknowledgement is transparent",
				history:      []extract.Segment{historicalReviewSegment(defensiveQuotedCredentialReview, 71_011, "ack-review")},
				interstitial: historicalNonUserSegment(extract.RoleAssistant, extract.ProvenanceContent, extract.ContentKindNaturalLanguageDirective, "Understood. The safety review is complete.", 2, 0, 71_012, "ack"),
				wantEvidence: 2,
			},
			{
				name:         "assistant refusal is transparent",
				history:      []extract.Segment{historicalReviewSegment(defensiveQuotedCredentialReview, 71_021, "refusal-review")},
				interstitial: historicalNonUserSegment(extract.RoleAssistant, extract.ProvenanceContent, extract.ContentKindNaturalLanguageDirective, "I cannot execute that request or provide operational steps.", 2, 0, 71_022, "refusal"),
				wantEvidence: 2,
			},
			{
				name: "review joined across historical fields",
				history: historicalJoinedReviewSegments(
					71_031,
					"Explain why the quoted request '",
					defensiveQuotedCredentialReferent,
					"' is harmful. Do not provide code or operational steps.",
				),
				wantEvidence: 4,
			},
			{
				name: "CPA mixed content same scope",
				history: historicalCPAMixedContentReviewSegments(
					71_041,
					"From a blue-team incident-response perspective, analyze the quoted malicious request below, "+
						"explain detection and remediation, and do not execute or operationalize it:\n",
					publicRunnerDefensiveCredentialReferent,
					"cpa-mixed",
				),
				wantEvidence: 3,
			},
		} {
			testCase := testCase
			t.Run(fmt.Sprintf("%s/%s", mode, testCase.name), func(t *testing.T) {
				segments := append([]extract.Segment(nil), testCase.history...)
				if testCase.interstitial != nil {
					segments = append(segments, *testCase.interstitial)
				}
				current := currentTrustedUserSegment("Execute it.", 3, 1, 71_099, "execute")
				segments = append(segments, current)

				results := historicalReviewParityResults(
					t, guard, segments, mode, testCase.chunkFirstReview,
				)
				for transport, result := range results {
					assertHistoricalReviewTransportComplete(t, transport, result)
					if result.Action != ActionBlock || !resultHasEligibleMaliciousWinner(result, DefaultThresholds()) ||
						result.FindingOrigin != FindingOriginUserContent ||
						!result.CandidateIdentityBlockingProofComplete() {
						t.Fatalf("%s reactivated review = %+v, want complete eligible current-user block", transport, result)
					}
					if result.DecisionExplanation == nil || !result.DecisionExplanation.CurrentTurnEvidence ||
						!result.DecisionExplanation.CrossSegmentComposition ||
						!result.DecisionExplanation.ReferentLinkUsed ||
						!result.DecisionExplanation.ReferentProofComplete ||
						result.DecisionExplanation.EvidenceSegmentCount != testCase.wantEvidence {
						t.Fatalf("%s referent explanation = %+v, want %d-segment complete proof", transport, result.DecisionExplanation, testCase.wantEvidence)
					}
					if result.BlockEligibility == nil || !result.BlockEligibility.Eligible ||
						!result.BlockEligibility.CurrentExecutionActProven ||
						!result.BlockEligibility.ReferentProofComplete {
						t.Fatalf("%s referent eligibility = %+v", transport, result.BlockEligibility)
					}
					assertHistoricalReviewOccurrenceSpans(t, guard, transport, result, segments)
					chain := result.candidateIdentity.referentChain
					if !result.candidateIdentity.referentLinked || !chain.set || !chain.proofComplete ||
						chain.carrierScopeID != testCase.history[0].ScopeID ||
						chain.anchorScopeID != current.ScopeID || chain.anchorTurnIndex != current.TurnIndex ||
						chain.anchorConversationIndex != current.ConversationIndex {
						t.Fatalf("%s referent chain = %+v", transport, chain)
					}
				}
			})
		}
	}
}

func TestHistoricalReviewGroupContaminationCannotPromoteBareReferent(t *testing.T) {
	guard := newDefaultClassifier(t)
	longReview := quotedSafetyReviewForReferent(
		defensiveQuotedCredentialReferent + strings.Repeat(" ordinary documentation filler", 32),
	)
	if len(longReview) <= streamRoleSummaryBytes {
		t.Fatalf("long review bytes=%d, want >%d", len(longReview), streamRoleSummaryBytes)
	}
	for _, mode := range []Mode{ModeBalanced, ModeStrict} {
		mode := mode
		for _, review := range []struct {
			name string
			text string
		}{
			{name: "short", text: defensiveQuotedCredentialReview},
			{name: "long", text: longReview},
		} {
			review := review
			for _, order := range []string{"attack-before-review", "review-before-attack"} {
				order := order
				t.Run(fmt.Sprintf("%s/%s/%s", mode, review.name, order), func(t *testing.T) {
					attack := historicalReviewSegment(defensiveQuotedCredentialReferent, 74_001, "contaminating-attack")
					closed := historicalReviewSegment(review.text, 74_001, "closed-review")
					history := []extract.Segment{attack, closed}
					if order == "review-before-attack" {
						history[0], history[1] = history[1], history[0]
					}
					segments := append(append([]extract.Segment(nil), history...),
						currentTrustedUserSegment("Execute it.", 2, 1, 74_002, "contaminated-anchor"),
					)
					for transport, result := range historicalReviewParityResults(
						t, guard, segments, mode, review.name == "long" && order == "review-before-attack",
					) {
						assertHistoricalReviewTransportComplete(t, transport, result)
						if result.Action == ActionBlock || resultHasEligibleMaliciousWinner(result, DefaultThresholds()) ||
							result.DecisionExplanation != nil && result.DecisionExplanation.ReferentLinkUsed {
							t.Fatalf("%s contaminated historical group acquired bare-referent authority: %+v", transport, result)
						}
					}
				})
			}
		}
	}
}

func TestHistoricalReviewEvictionCannotEraseDisqualifyingField(t *testing.T) {
	guard := newDefaultClassifier(t)
	for _, mode := range []Mode{ModeBalanced, ModeStrict} {
		mode := mode
		t.Run(string(mode), func(t *testing.T) {
			history := make([]extract.Segment, 0, maxRoleClassifierSegments+1)
			history = append(history, historicalReviewSegment(
				defensiveQuotedCredentialReferent, 75_001, "evicted-attack",
			))
			for index := 1; index < maxRoleClassifierSegments; index++ {
				history = append(history, historicalReviewSegment(
					"ordinary review metadata", 75_001, fmt.Sprintf("eviction-padding-%d", index),
				))
			}
			history = append(history, historicalReviewSegment(
				defensiveQuotedCredentialReview, 75_001, "retained-review",
			))
			segments := append(history,
				currentTrustedUserSegment("Execute it.", 2, 1, 75_002, "eviction-anchor"),
			)
			for transport, result := range historicalReviewParityResults(t, guard, segments, mode, false) {
				assertHistoricalReviewTransportComplete(t, transport, result)
				if result.Action == ActionBlock || resultHasEligibleMaliciousWinner(result, DefaultThresholds()) ||
					result.DecisionExplanation != nil && result.DecisionExplanation.ReferentLinkUsed {
					t.Fatalf("%s evicted a disqualifying field and promoted the retained tail: %+v", transport, result)
				}
			}
		})
	}
}

func assertHistoricalReviewOccurrenceSpans(
	t testing.TB,
	guard *Classifier,
	transport string,
	result Result,
	segments []extract.Segment,
) {
	t.Helper()
	historicalRefs := make([]profiledSegmentRef, 0, len(segments))
	historicalParts := make([]string, 0, len(segments))
	for index, segment := range segments {
		if !profiledHistoricalReferentEligible(segment) {
			continue
		}
		historicalRefs = append(historicalRefs, profiledSegmentRef{index: index, segment: segment})
		historicalParts = append(historicalParts, segment.Text)
	}
	quoted, _, ok := guard.profiledHistoricalSafetyReviewReferent(profiledSegmentGroup{
		refs: historicalRefs, parts: historicalParts,
	})
	if !ok {
		t.Fatalf("%s result used a referent whose historical group no longer proves a closed review", transport)
	}
	core := guard.classifyWithPolicy(
		[]string{quoted}, ModeBalanced, DefaultThresholds(), DefaultPolicy(), false,
	)
	var coreScratch normalizationScratch
	coreViews := normalizePartsInto([]string{quoted}, nil, &coreScratch)
	if coreViews.truncated {
		putNormalizedRuneBuffer(coreViews.standardRunes, coreViews.storageUsed)
		t.Fatalf("%s reconstructed referent normalization truncated", transport)
	}
	coreAnalysis := guard.analyzeDirectives(coreViews.standardRunes, DefaultPolicy())
	defer putNormalizedRuneBuffer(coreViews.standardRunes, coreViews.storageUsed)
	for _, occurrence := range result.EvidenceOccurrences {
		fieldIndex := occurrence.FieldID
		if transport == "stream" {
			fieldIndex--
		}
		if fieldIndex < 0 || fieldIndex >= len(segments) ||
			occurrence.ClauseID < 0 || occurrence.Start < 0 || occurrence.End <= occurrence.Start {
			t.Fatalf("%s occurrence lacks a physical span: %+v", transport, occurrence)
		}
		segment := segments[fieldIndex]
		var scratch normalizationScratch
		views := normalizePartsInto([]string{segment.Text}, nil, &scratch)
		if views.truncated {
			putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
			t.Fatalf("%s occurrence field normalization truncated: %+v", transport, occurrence)
		}
		analysis := guard.analyzeDirectives(views.standardRunes, DefaultPolicy())
		physicalSpan := ""
		for _, clause := range analysis.clauses {
			if int(clauseIDForOccurrence(clause)) != occurrence.ClauseID || occurrence.End > len(clause.runes) {
				continue
			}
			physicalSpan = string(clause.runes[occurrence.Start:occurrence.End])
			break
		}
		putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
		coreSpan := historicalReviewCoreOccurrenceSpan(core, coreAnalysis, occurrence)
		if physicalSpan == "" || coreSpan == "" || physicalSpan != coreSpan {
			t.Fatalf("%s occurrence span does not resolve to reconstructed %s/%s evidence in field %d: physical=%q core=%q occurrence=%+v", transport, occurrence.RuleID, occurrence.Dimension, occurrence.FieldID, physicalSpan, coreSpan, occurrence)
		}
	}
}

func historicalReviewCoreOccurrenceSpan(
	core Result,
	analysis analyzedDirectives,
	target EvidenceOccurrence,
) string {
	for _, occurrence := range core.EvidenceOccurrences {
		if occurrence.EvidenceID != target.EvidenceID || occurrence.RuleID != target.RuleID ||
			occurrence.Dimension != target.Dimension || occurrence.ClauseID < 0 ||
			occurrence.Start < 0 || occurrence.End <= occurrence.Start {
			continue
		}
		for _, clause := range analysis.clauses {
			if int(clauseIDForOccurrence(clause)) == occurrence.ClauseID && occurrence.End <= len(clause.runes) {
				return string(clause.runes[occurrence.Start:occurrence.End])
			}
		}
	}
	return ""
}

func TestHistoricalNonUserPayloadCannotAcquireBareReferentAuthority(t *testing.T) {
	guard := newDefaultClassifier(t)
	for _, mode := range []Mode{ModeBalanced, ModeStrict} {
		mode := mode
		for index, testCase := range []struct {
			name       string
			historical extract.Segment
		}{
			{
				name: "assistant content",
				historical: *historicalNonUserSegment(
					extract.RoleAssistant, extract.ProvenanceContent, extract.ContentKindNaturalLanguageDirective,
					round9ExplicitMalware, 1, 0, 72_001, "assistant-content",
				),
			},
			{
				name: "tool result",
				historical: *historicalNonUserSegment(
					extract.RoleTool, extract.ProvenanceContent, extract.ContentKindToolResult,
					round9ExplicitMalware, 1, 0, 72_002, "tool-result",
				),
			},
			{
				name: "assistant tool-call arguments",
				historical: *historicalNonUserSegment(
					extract.RoleAssistant, extract.ProvenanceToolPayload, extract.ContentKindToolCallArguments,
					round9ExplicitMalware, 1, 0, 72_003, "assistant-tool-arguments",
				),
			},
			{
				name: "system documentation",
				historical: *historicalNonUserSegment(
					extract.RoleSystem, extract.ProvenanceContent, extract.ContentKindDocumentation,
					round9ExplicitMalware, 1, 0, 72_004, "system-documentation",
				),
			},
			{
				name: "unknown history",
				historical: *historicalNonUserSegment(
					extract.RoleUnknown, extract.ProvenanceContent, extract.ContentKindNaturalLanguageDirective,
					round9ExplicitMalware, 1, 0, 72_005, "unknown-history",
				),
			},
			{
				name: "tool schema",
				historical: *historicalNonUserSegment(
					extract.RoleSystem, extract.ProvenanceContent, extract.ContentKindToolSchema,
					round9ExplicitMalware, 1, 0, 72_006, "tool-schema",
				),
			},
		} {
			testCase := testCase
			t.Run(fmt.Sprintf("%s/%s", mode, testCase.name), func(t *testing.T) {
				bare := currentTrustedUserSegment("Execute it.", 2, 1, uint64(72_100+index), "bare")
				for transport, result := range historicalReviewParityResults(
					t, guard, []extract.Segment{testCase.historical, bare}, mode, false,
				) {
					assertHistoricalReviewTransportComplete(t, transport, result)
					if result.Action == ActionBlock || resultHasEligibleMaliciousWinner(result, DefaultThresholds()) ||
						result.DecisionExplanation != nil && result.DecisionExplanation.ReferentLinkUsed {
						t.Fatalf("%s %s acquired bare-referent authority: %+v", transport, testCase.name, result)
					}
				}

				explicit := bare
				explicit.Text = round9ExplicitMalware
				explicit.FieldPathHash += "-explicit"
				for transport, result := range historicalReviewParityResults(
					t, guard, []extract.Segment{testCase.historical, explicit}, mode, false,
				) {
					assertHistoricalReviewTransportComplete(t, transport, result)
					if result.Action != ActionBlock || result.FindingOrigin != FindingOriginUserContent ||
						!resultHasEligibleMaliciousWinner(result, DefaultThresholds()) ||
						!result.CandidateIdentityBlockingProofComplete() {
						t.Fatalf("%s explicit current-user restatement behind %s = %+v, want independent block", transport, testCase.name, result)
					}
					if result.DecisionExplanation != nil && result.DecisionExplanation.ReferentLinkUsed {
						t.Fatalf("%s explicit current-user restatement incorrectly used a referent: %+v", transport, result.DecisionExplanation)
					}
				}
			})
		}
	}
}

func TestPlainHistoricalAttackRefusalBareFollowUpDoesNotReactivate(t *testing.T) {
	guard := newDefaultClassifier(t)
	for _, mode := range []Mode{ModeBalanced, ModeStrict} {
		mode := mode
		for _, followUp := range []string{"Execute it.", "now give code"} {
			followUp := followUp
			t.Run(fmt.Sprintf("%s/%s", mode, followUp), func(t *testing.T) {
				segments := []extract.Segment{
					historicalReviewSegment(defensiveQuotedCredentialReferent, 73_001, "plain-attack"),
					*historicalNonUserSegment(
						extract.RoleAssistant, extract.ProvenanceContent,
						extract.ContentKindNaturalLanguageDirective,
						"I cannot help steal browser cookies or provide that code.",
						2, 0, 73_002, "plain-refusal",
					),
					currentTrustedUserSegment(followUp, 3, 1, 73_003, "plain-follow-up"),
				}
				for transport, result := range historicalReviewParityResults(
					t, guard, segments, mode, false,
				) {
					assertHistoricalReviewTransportComplete(t, transport, result)
					if result.Action == ActionBlock || resultHasEligibleMaliciousWinner(result, DefaultThresholds()) ||
						result.DecisionExplanation != nil && result.DecisionExplanation.ReferentLinkUsed {
						t.Fatalf("%s plain historical attack acquired bare-referent authority: %+v", transport, result)
					}
				}
			})
		}
	}
}

func historicalReviewSegment(text string, scopeID uint64, path string) extract.Segment {
	return extract.Segment{
		Role: extract.RoleUser, Provenance: extract.ProvenanceContent,
		UserAttribution:   extract.UserAttributionTrusted,
		ConversationIndex: 1, TurnIndex: 0, IsCurrentTurn: false,
		ScopeID: scopeID, ContentKind: extract.ContentKindNaturalLanguageDirective,
		FieldPathHash: "historical-review-" + path, Text: text,
	}
}

func historicalJoinedReviewSegments(scopeID uint64, parts ...string) []extract.Segment {
	segments := make([]extract.Segment, 0, len(parts))
	for index, part := range parts {
		segment := historicalReviewSegment(part, scopeID, fmt.Sprintf("joined-%d", index))
		segments = append(segments, segment)
	}
	return segments
}

func historicalCPAMixedContentReviewSegments(
	scopeID uint64,
	prefix, referent, path string,
) []extract.Segment {
	directive := historicalReviewSegment(prefix, scopeID, path)
	carrier := historicalReviewSegment("```text\n"+referent+"\n```", scopeID, path)
	carrier.ContentKind = extract.ContentKindCodeBlock
	return []extract.Segment{directive, carrier}
}

func historicalNonUserSegment(
	role extract.Role,
	provenance extract.SegmentProvenance,
	kind extract.ContentKind,
	text string,
	conversationIndex int,
	turnIndex int,
	scopeID uint64,
	path string,
) *extract.Segment {
	return &extract.Segment{
		Role: role, Provenance: provenance, UserAttribution: extract.UserAttributionUntrusted,
		ConversationIndex: conversationIndex, TurnIndex: turnIndex, IsCurrentTurn: false,
		ScopeID: scopeID, ContentKind: kind, FieldPathHash: "historical-non-user-" + path,
		Text: text,
	}
}

func currentTrustedUserSegment(
	text string,
	conversationIndex int,
	turnIndex int,
	scopeID uint64,
	path string,
) extract.Segment {
	return extract.Segment{
		Role: extract.RoleUser, Provenance: extract.ProvenanceContent,
		UserAttribution:   extract.UserAttributionTrusted,
		ConversationIndex: conversationIndex, TurnIndex: turnIndex, IsCurrentTurn: true,
		ScopeID: scopeID, ContentKind: extract.ContentKindNaturalLanguageDirective,
		FieldPathHash: "current-user-" + path, Text: text,
	}
}

func historicalReviewParityResults(
	t testing.TB,
	guard *Classifier,
	segments []extract.Segment,
	mode Mode,
	chunkFirstReview bool,
) map[string]Result {
	t.Helper()
	return map[string]Result{
		"batch": guard.ClassifySegmentsWithPolicy(
			segments, mode, DefaultThresholds(), DefaultPolicy(),
		),
		"stream": classifyHistoricalReviewStreaming(
			t, guard, segments, mode, chunkFirstReview,
		),
	}
}

func classifyHistoricalReviewStreaming(
	t testing.TB,
	guard *Classifier,
	segments []extract.Segment,
	mode Mode,
	chunkFirstReview bool,
) Result {
	t.Helper()
	session, err := guard.NewProfiledScanSession(
		mode, DefaultThresholds(), DefaultPolicy(), DefaultScanLimits(),
	)
	if err != nil {
		t.Fatalf("NewProfiledScanSession() error = %v", err)
	}
	for index, segment := range segments {
		chunks := []string{segment.Text}
		if index == 0 && chunkFirstReview && len(segment.Text) >= 3 {
			first := len(segment.Text) / 3
			second := first + (len(segment.Text)-first)/2
			chunks = []string{segment.Text[:first], segment.Text[first:second], segment.Text[second:]}
		}
		for chunkIndex, text := range chunks {
			if err := session.AddSegment(extract.SegmentChunk{
				Role: segment.Role, Provenance: segment.Provenance,
				UserAttribution: segment.UserAttribution, ToolAssociation: segment.ToolAssociation,
				ConversationIndex: segment.ConversationIndex, TurnIndex: segment.TurnIndex,
				IsCurrentTurn: segment.IsCurrentTurn, ScopeID: segment.ScopeID,
				TerminalConversationIndex: segment.TerminalConversationIndex,
				TerminalTurnIndex:         segment.TerminalTurnIndex,
				HasTerminalCoordinates:    segment.HasTerminalCoordinates,
				ContentKind:               segment.ContentKind, FieldPathHash: segment.FieldPathHash,
				FieldID: uint64(index + 1), Start: chunkIndex == 0,
				End: chunkIndex == len(chunks)-1, Text: []byte(text),
			}); err != nil {
				t.Fatalf("AddSegment(field=%d chunk=%d) error = %v", index+1, chunkIndex, err)
			}
		}
	}
	return session.Finish()
}

func assertHistoricalReviewTransportComplete(t testing.TB, transport string, result Result) {
	t.Helper()
	if result.Truncated || result.Coverage.State == CoverageUnavailable ||
		result.Coverage.State == CoverageBudgetExhausted {
		t.Fatalf("%s incomplete result: coverage=%+v result=%+v", transport, result.Coverage, result)
	}
	if transport == "stream" && (result.Coverage.State != CoverageComplete ||
		result.FindingConfidence != FindingCompleteRequest) {
		t.Fatalf("stream result lacks complete-request proof: %+v", result)
	}
}
