package classifier

import (
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

func TestRound10DirectCompactionNonCurrentProviderUnitIsBarrier(t *testing.T) {
	t.Parallel()
	guard := newDefaultClassifier(t)
	base := round10DirectCloneRun(
		round10DirectProtocolSegments(
			t, extract.SourceProfileOpenAI, round10PublicCompactPayload(t),
		),
		75_001,
		"non-current-barrier",
		false,
	)
	barrier := base[0]
	barrier.IsCurrentTurn = false
	barrier.Text = "Historical provider context that must terminate physical locality."
	segments := []extract.Segment{base[0], barrier, base[1]}

	results := round10DirectClassificationResults(t, guard, segments, ModeBalanced)
	round10AssertDirectResultParity(t, results)
	for transport, result := range results {
		if !resultIsNeutralClassifierIncomplete(result) ||
			result.Coverage.Reason != CoverageReasonClassifierWindow {
			t.Fatalf("%s crossed a non-current provider barrier: %+v", transport, result)
		}
	}
}

func TestRound10DirectCompactionCarrierBeforeApplicationIsIncomplete(t *testing.T) {
	t.Parallel()
	guard := newDefaultClassifier(t)
	base := round10DirectCloneRun(
		round10DirectProtocolSegments(
			t, extract.SourceProfileOpenAI, round10PublicCompactPayload(t),
		),
		75_010,
		"carrier-before-application",
		false,
	)
	if len(base[1].Text) <= streamRoleSummaryBytes {
		t.Fatalf("fixture carrier bytes=%d, want more than %d", len(base[1].Text), streamRoleSummaryBytes)
	}
	segments := []extract.Segment{base[1], base[0]}

	results := round10DirectClassificationResults(t, guard, segments, ModeBalanced)
	round10AssertDirectResultParity(t, results)
	for transport, result := range results {
		if !resultIsNeutralClassifierIncomplete(result) ||
			result.Coverage.Reason != CoverageReasonClassifierWindow {
			t.Fatalf("%s accepted carrier-before-application ordering: %+v", transport, result)
		}
	}
}

func TestRound10DirectCompactionRejectsMixedRuleInertCarriers(t *testing.T) {
	t.Parallel()
	guard := newDefaultClassifier(t)
	base := round10DirectCloneRun(
		round10DirectProtocolSegments(
			t, extract.SourceProfileOpenAI, round10PublicCompactPayload(t),
		),
		75_020,
		"mixed-rule-inert-carrier",
		false,
	)
	for _, kind := range []extract.ContentKind{
		extract.ContentKindQuotedText,
		extract.ContentKindSecurityAnalysis,
	} {
		kind := kind
		t.Run(string(kind), func(t *testing.T) {
			t.Parallel()
			application := base[0]
			carrier := base[1]
			carrier.ContentKind = kind
			carrier.Text = round9ExplicitMalware
			segments := []extract.Segment{application, carrier}

			group := profiledSegmentGroup{
				refs: []profiledSegmentRef{
					{index: 0, segment: application},
					{index: 1, segment: carrier},
				},
				parts:           []string{application.Text, carrier.Text},
				activeDirective: true,
			}
			candidate := guard.classifyProfiledGroupWithPolicy(
				group, ModeBalanced, DefaultThresholds(), DefaultPolicy(),
			)
			if standaloneMetaControlResult(candidate) ||
				!resultHasEligibleBlockingCandidate(candidate, DefaultThresholds()) {
				t.Fatalf("fixture did not produce an eligible mixed-rule candidate: %+v", candidate)
			}

			results := round10DirectClassificationResults(t, guard, segments, ModeBalanced)
			round10AssertDirectResultParity(t, results)
			for transport, result := range results {
				if round10CoverageState(result) != CoverageComplete || result.Truncated ||
					result.Action == ActionBlock ||
					result.BlockEligibility != nil && result.BlockEligibility.Eligible {
					t.Fatalf("%s admitted mixed-rule inert carrier: %+v", transport, result)
				}
			}
		})
	}
}
