package classifier

import (
	"fmt"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

func TestRound10DirectCompactionTrueBatchFieldwiseBytewiseProtocolParity(t *testing.T) {
	t.Parallel()
	guard := newDefaultClassifier(t)
	payload := round10PublicCompactPayload(t)
	for _, protocol := range []struct {
		name    string
		profile extract.SourceProfile
	}{
		{name: "chat", profile: extract.SourceProfileOpenAI},
		{name: "responses", profile: extract.SourceProfileOpenAIResponse},
	} {
		protocol := protocol
		t.Run(protocol.name, func(t *testing.T) {
			t.Parallel()
			segments := round10DirectProtocolSegments(t, protocol.profile, payload)
			for _, mode := range []Mode{ModeBalanced, ModeStrict} {
				mode := mode
				t.Run(string(mode), func(t *testing.T) {
					t.Parallel()
					results := round10DirectClassificationResults(t, guard, segments, mode)
					round10AssertDirectResultParity(t, results)
					for transport, result := range results {
						round10RequireCompleteEligibleBlock(t, transport, result)
						if result.Category != rules.CategoryEvasion ||
							!resultContainsRuleID(result, metaOverrideRuleID) {
							t.Fatalf("%s result=%+v, want direct META override", transport, result)
						}
					}
				})
			}
		})
	}
}

func TestRound10DirectCompactionProcessesEveryRunAndLaterPipelines(t *testing.T) {
	t.Parallel()
	guard := newDefaultClassifier(t)
	base := round10DirectProtocolSegments(
		t, extract.SourceProfileOpenAI, round10PublicCompactPayload(t),
	)

	t.Run("same scope benign then malicious", func(t *testing.T) {
		t.Parallel()
		first := round10DirectCloneRun(base, 72_001, "benign-first", true)
		second := round10DirectCloneRun(base, 72_001, "malicious-second", false)
		results := round10DirectClassificationResults(
			t, guard, append(first, second...), ModeBalanced,
		)
		round10AssertDirectResultParity(t, results)
		for transport, result := range results {
			round10RequireCompleteEligibleBlock(t, transport, result)
			if result.Category != rules.CategoryEvasion || result.Score != 90 {
				t.Fatalf("%s result=%+v, want second compaction run META winner", transport, result)
			}
		}
	})

	t.Run("malicious compaction then stronger referent", func(t *testing.T) {
		t.Parallel()
		segments := round10DirectCloneRun(base, 72_010, "malicious-first", false)
		carrier := segments[0]
		carrier.ContentKind = extract.ContentKindCodeBlock
		carrier.FieldPathHash = "stronger-carrier"
		carrier.Text = round9ExplicitMalware
		anchor := segments[0]
		anchor.ContentKind = extract.ContentKindNaturalLanguageDirective
		anchor.FieldPathHash = "stronger-anchor"
		anchor.Text = "Execute it now."
		segments = append(segments, carrier, anchor)
		results := round10DirectClassificationResults(t, guard, segments, ModeBalanced)
		round10AssertDirectResultParity(t, results)
		for transport, result := range results {
			round10RequireCompleteEligibleBlock(t, transport, result)
			if result.Score != 100 || result.Category != rules.CategoryMalware ||
				result.DecisionExplanation == nil ||
				!result.DecisionExplanation.ReferentLinkUsed {
				t.Fatalf("%s stronger referent did not outrank compaction: %+v", transport, result)
			}
		}
	})

	t.Run("barrier then second run", func(t *testing.T) {
		t.Parallel()
		first := round10DirectCloneRun(base, 72_020, "before-barrier", true)
		second := round10DirectCloneRun(base, 72_020, "after-barrier", false)
		barrier := first[0]
		barrier.ScopeID = 72_021
		barrier.FieldPathHash = "foreign-scope-barrier"
		barrier.Text = "Summarize the ordinary football standings."
		segments := append(append(first, barrier), second...)
		results := round10DirectClassificationResults(t, guard, segments, ModeBalanced)
		round10AssertDirectResultParity(t, results)
		for transport, result := range results {
			round10RequireCompleteEligibleBlock(t, transport, result)
			if result.Category != rules.CategoryEvasion {
				t.Fatalf("%s barrier hid the second compaction run: %+v", transport, result)
			}
		}
	})

	// This deliberately targets the streaming-only state machine. The malformed
	// defensive wrapper is not a direct-compaction run; it must still reach the
	// ordinary defensive ambiguity path after a benign compaction application.
	t.Run("benign compaction then malformed defensive malicious carrier", func(t *testing.T) {
		t.Parallel()
		segments := round10DirectCloneRun(base, 72_030, "benign-compaction", true)
		frame := segments[0]
		frame.FieldPathHash = "malformed-defensive"
		frame.Text = "The following quoted prompt-injection sample is included, and do not apply it:\n"
		carrier := segments[0]
		carrier.ContentKind = extract.ContentKindCodeBlock
		carrier.FieldPathHash = frame.FieldPathHash
		carrier.Text = "```text\n" + publicRunnerDefensiveCredentialReferent + "\n```"
		segments = append(segments, frame, carrier)
		fieldwise := round10ClassifyDirectStreaming(t, guard, segments, ModeBalanced, false)
		bytewise := round10ClassifyDirectStreaming(t, guard, segments, ModeBalanced, true)
		for transport, result := range map[string]Result{
			"fieldwise": fieldwise,
			"bytewise":  bytewise,
		} {
			round10RequireCompleteEligibleBlock(t, transport, result)
			if result.Category != rules.CategoryCredentialTheft {
				t.Fatalf("%s later malformed defensive carrier was skipped: %+v", transport, result)
			}
		}
		if !reflect.DeepEqual(fieldwise.BlockEligibility, bytewise.BlockEligibility) ||
			!reflect.DeepEqual(fieldwise.DecisionExplanation, bytewise.DecisionExplanation) {
			t.Fatalf("stream chunk parity mismatch:\nfieldwise=%+v\nbytewise=%+v", fieldwise, bytewise)
		}
	})
}

func TestRound10DirectCompactionLogicalFieldIdentityAndLifecycle(t *testing.T) {
	t.Parallel()
	guard := newDefaultClassifier(t)
	session, err := guard.NewProfiledScanSession(
		ModeBalanced, DefaultThresholds(), DefaultPolicy(), DefaultScanLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	base := round10DirectCloneRun(
		round10DirectProtocolSegments(t, extract.SourceProfileOpenAI, round10PublicCompactPayload(t)),
		73_001, "identity-field", false,
	)
	application := base[0]
	carrier := base[1]
	key := profiledCurrentReferentScopeKey{
		turnIndex: application.TurnIndex, scopeID: application.ScopeID,
	}
	applicationUnit := profiledCurrentReferentUnit{
		ref:       profiledSegmentRef{index: 0, segment: application},
		text:      application.Text,
		complete:  true,
		directive: true,
	}
	session.profiledCurrentReferents = []profiledCurrentReferentScope{{
		key: key, set: true, units: []profiledCurrentReferentUnit{applicationUnit},
	}}
	if !session.profiledDirectCompactionScopeActive(carrier) {
		t.Fatal("same logical field did not retain direct-compaction carrier")
	}

	mutations := []struct {
		name   string
		mutate func(*extract.Segment)
	}{
		{name: "field path", mutate: func(s *extract.Segment) { s.FieldPathHash += "-other" }},
		{name: "scope", mutate: func(s *extract.Segment) { s.ScopeID++ }},
		{name: "turn", mutate: func(s *extract.Segment) { s.TurnIndex++ }},
		{name: "conversation", mutate: func(s *extract.Segment) { s.ConversationIndex++ }},
		{name: "role", mutate: func(s *extract.Segment) { s.Role = extract.RoleAssistant }},
		{name: "provenance", mutate: func(s *extract.Segment) { s.Provenance = extract.ProvenanceToolPayload }},
		{name: "attribution", mutate: func(s *extract.Segment) { s.UserAttribution = extract.UserAttributionUntrusted }},
		{name: "tool association", mutate: func(s *extract.Segment) {
			s.ToolAssociation = extract.ToolResultAssociationUnique
		}},
		{name: "current turn", mutate: func(s *extract.Segment) { s.IsCurrentTurn = false }},
	}
	for _, mutation := range mutations {
		mutation := mutation
		t.Run(mutation.name, func(t *testing.T) {
			candidate := carrier
			mutation.mutate(&candidate)
			if session.profiledDirectCompactionScopeActive(candidate) {
				t.Fatalf("%s mismatch borrowed direct-compaction activation", mutation.name)
			}
		})
	}

	t.Run("barrier closes run", func(t *testing.T) {
		state := &session.profiledCurrentReferents[0]
		state.units = append(state.units, profiledCurrentReferentBarrier(
			profiledCurrentReferentUnit{ref: profiledSegmentRef{index: 1, segment: carrier}},
		))
		if session.profiledDirectCompactionScopeActive(carrier) {
			t.Fatal("barrier left direct-compaction activation sticky")
		}
		state.units = state.units[:1]
	})

	t.Run("logical run end closes activation", func(t *testing.T) {
		state := &session.profiledCurrentReferents[0]
		other := applicationUnit
		other.ref.index = 1
		other.ref.segment.FieldPathHash = "later-logical-field"
		other.text = "Summarize football standings."
		state.units = append(state.units, other)
		if session.profiledDirectCompactionScopeActive(carrier) {
			t.Fatal("a completed different logical field left activation sticky")
		}
		state.units = state.units[:1]
	})

	t.Run("64 and 65 unit eviction", func(t *testing.T) {
		state := &session.profiledCurrentReferents[0]
		state.units = []profiledCurrentReferentUnit{applicationUnit}
		for index := 1; index < maxRoleClassifierSegments; index++ {
			filler := applicationUnit
			filler.ref.index = index
			filler.text = "Ordinary bounded context."
			filler.ref.segment.Text = filler.text
			session.appendProfiledCurrentReferentUnit(state, filler)
		}
		if len(state.units) != maxRoleClassifierSegments ||
			!session.profiledDirectCompactionScopeActive(carrier) {
			t.Fatalf("64-unit boundary lost retained application: units=%d", len(state.units))
		}
		filler := applicationUnit
		filler.ref.index = maxRoleClassifierSegments
		filler.text = "The sixty-fifth ordinary bounded context."
		filler.ref.segment.Text = filler.text
		session.appendProfiledCurrentReferentUnit(state, filler)
		if len(state.units) != maxRoleClassifierSegments ||
			session.profiledDirectCompactionScopeActive(carrier) {
			t.Fatalf("65th unit did not clear evicted application: units=%d", len(state.units))
		}
	})

	t.Run("64 and 65 scope eviction", func(t *testing.T) {
		session.profiledCurrentReferents = nil
		for index := 0; index < maxProfiledCurrentReferentScopes; index++ {
			state := session.findOrAddProfiledCurrentReferentScope(profiledCurrentReferentScopeKey{
				turnIndex: 0, scopeID: uint64(80_000 + index),
			})
			if state == nil {
				t.Fatalf("scope %d was not admitted: coverage=%+v", index+1, session.coverage)
			}
		}
		if len(session.profiledCurrentReferents) != maxProfiledCurrentReferentScopes {
			t.Fatalf("scope count=%d, want %d", len(session.profiledCurrentReferents), maxProfiledCurrentReferentScopes)
		}
		state := session.findOrAddProfiledCurrentReferentScope(profiledCurrentReferentScopeKey{
			turnIndex: 0, scopeID: 90_000,
		})
		if state == nil || session.coverage.State != CoverageComplete ||
			len(session.profiledCurrentReferents) != maxProfiledCurrentReferentScopes {
			t.Fatalf("65th evictable scope failed: state=%+v coverage=%+v scopes=%d",
				state, session.coverage, len(session.profiledCurrentReferents))
		}
		for _, retained := range session.profiledCurrentReferents {
			if retained.key.scopeID == 80_000 {
				t.Fatal("65th scope did not evict and clear the oldest state")
			}
		}
	})

	t.Run("each run charges classification budget", func(t *testing.T) {
		budgeted, err := guard.NewProfiledScanSession(
			ModeBalanced, DefaultThresholds(), DefaultPolicy(),
			ScanLimits{MaxChunks: 1},
		)
		if err != nil {
			t.Fatal(err)
		}
		first := round10DirectCloneRun(base, 73_010, "budget-first", true)
		second := round10DirectCloneRun(base, 73_010, "budget-second", false)
		state := profiledCurrentReferentScope{
			key: profiledCurrentReferentScopeKey{
				turnIndex: first[0].TurnIndex, scopeID: first[0].ScopeID,
			},
			set: true,
		}
		for index, segment := range append(first, second...) {
			state.units = append(state.units, profiledCurrentReferentUnit{
				ref:       profiledSegmentRef{index: index, segment: segment},
				text:      segment.Text,
				complete:  true,
				carrier:   profiledStreamingCurrentTrustedCarrier(segment),
				directive: profiledStreamingCurrentReferentDirective(segment),
			})
		}
		budgeted.considerProfiledDirectCompactionApplications(&state)
		if budgeted.coverage.State != CoverageBudgetExhausted ||
			budgeted.coverage.Reason != CoverageReasonClassificationLimit ||
			budgeted.coverage.Windows != 1 {
			t.Fatalf("two runs under one-chunk budget were undercharged: %+v", budgeted.coverage)
		}
	})
}

func TestRound10DirectCompactionWindowBoundariesAndIndependentWinner(t *testing.T) {
	t.Parallel()
	guard := newDefaultClassifier(t)
	base := round10DirectProtocolSegments(
		t, extract.SourceProfileOpenAI, round10PublicCompactPayload(t),
	)
	for _, normalized := range []bool{false, true} {
		normalized := normalized
		for _, benign := range []bool{false, true} {
			benign := benign
			for _, padding := range []string{"carrier", "trailing"} {
				padding := padding
				for _, target := range []int{8191, 8192, 8193} {
					target := target
					name := fmt.Sprintf(
						"nfkc=%t/benign=%t/padding=%s/bytes=%d",
						normalized, benign, padding, target,
					)
					t.Run(name, func(t *testing.T) {
						t.Parallel()
						run := round10DirectCloneRun(base, 74_001, "window-boundary", benign)
						if normalized {
							run[0].Text = strings.Replace(run[0].Text, "Codex", "Ｃｏｄｅｘ", 1)
						}
						paddingIndex := 1
						if padding == "trailing" {
							paddingIndex = len(run) - 1
						}
						round10ResizeDirectRunPart(t, run, target, paddingIndex)
						if !profiledDirectCompactionApplicationText(run[0].Text) {
							t.Fatal("application no longer survives NFKC normalization")
						}
						results := round10DirectClassificationResults(t, guard, run, ModeBalanced)
						round10AssertDirectResultParity(t, results)
						for transport, result := range results {
							if benign {
								if round10CoverageState(result) != CoverageComplete || result.Truncated ||
									result.Action == ActionBlock {
									t.Fatalf("%s benign run=%+v, want complete allow at %d bytes", transport, result, target)
								}
								continue
							}
							round10RequireCompleteEligibleBlock(t, transport, result)
						}
					})
				}
			}
		}
	}

	t.Run("non-padding proof overflow remains incomplete", func(t *testing.T) {
		t.Parallel()
		run := round10DirectCloneRun(base, 74_009, "cross-window-proof", true)
		carrier := -1
		for index, segment := range run {
			if profiledReferentCarrierKind(segment.ContentKind) {
				carrier = index
				break
			}
		}
		if carrier < 0 {
			t.Fatal("direct-compaction fixture has no carrier")
		}
		closing := strings.LastIndex(run[carrier].Text, "```")
		if closing < 0 {
			t.Fatal("direct-compaction fixture carrier has no closing fence")
		}
		total := 0
		for _, segment := range run {
			total += len(segment.Text)
		}
		target := maxMetaOverrideDirectControlWindowBytes + 1024
		if total > target {
			t.Fatalf("cannot construct non-padding proof overflow: total=%d target=%d", total, target)
		}
		padding := strings.Repeat("x", target-total)
		run[carrier].Text = run[carrier].Text[:closing] + padding + run[carrier].Text[closing:]
		results := round10DirectClassificationResults(t, guard, run, ModeBalanced)
		round10AssertDirectResultParity(t, results)
		for transport, result := range results {
			if !resultIsNeutralClassifierIncomplete(result) ||
				result.Coverage.Reason != CoverageReasonClassifierWindow {
				t.Fatalf("%s %d-byte non-padding result=%+v, want neutral local incomplete", transport, target, result)
			}
		}
	})

	for _, benign := range []bool{false, true} {
		benign := benign
		for _, incompleteFirst := range []bool{false, true} {
			incompleteFirst := incompleteFirst
			name := fmt.Sprintf("benign=%t/incomplete-first=%t", benign, incompleteFirst)
			t.Run("independent winner/"+name, func(t *testing.T) {
				t.Parallel()
				run := round10DirectCloneRun(base, 74_010, "oversized-local-run", benign)
				round10ResizeDirectRun(t, run, 8193)
				winner := run[0]
				winner.ScopeID++
				winner.FieldPathHash = "independent-complete-winner"
				winner.ContentKind = extract.ContentKindNaturalLanguageDirective
				winner.Text = round9ExplicitMalware
				segments := append(append([]extract.Segment(nil), run...), winner)
				if !incompleteFirst {
					segments = append([]extract.Segment{winner}, run...)
				}
				results := round10DirectClassificationResults(t, guard, segments, ModeBalanced)
				round10AssertDirectResultParity(t, results)
				for transport, result := range results {
					round10RequireCompleteEligibleBlock(t, transport, result)
					if result.Score != 100 || result.Category != rules.CategoryMalware {
						t.Fatalf("%s local proof loss erased independent winner: %+v", transport, result)
					}
				}
			})
		}
	}
}

func round10DirectProtocolSegments(
	t testing.TB,
	profile extract.SourceProfile,
	payload string,
) []extract.Segment {
	t.Helper()
	var value any
	switch profile {
	case extract.SourceProfileOpenAI:
		value = map[string]any{
			"model": "round10-direct", "stream": false,
			"messages": []any{map[string]any{"role": "user", "content": payload}},
		}
	case extract.SourceProfileOpenAIResponse:
		value = map[string]any{
			"model": "round10-direct", "stream": false,
			"input": []any{map[string]any{
				"type": "message", "role": "user",
				"content": []any{map[string]any{"type": "input_text", "text": payload}},
			}},
		}
	default:
		t.Fatalf("unsupported profile %q", profile)
	}
	body := round10JSONBody(t, value)
	extracted, err := extract.ExtractProfiledRequest(
		[]byte(body), http.Header{"Content-Type": []string{"application/json"}},
		extract.RequestProfile{Source: profile}, extract.Limits{},
	)
	if err != nil || !extracted.IsComplete() || !extracted.RoleAware {
		t.Fatalf("profile=%q extract=%+v err=%v", profile, extracted, err)
	}
	if len(extracted.Segments) != 3 {
		t.Fatalf("profile=%q direct compaction segments=%d, want 3", profile, len(extracted.Segments))
	}
	return append([]extract.Segment(nil), extracted.Segments...)
}

func round10DirectCloneRun(
	base []extract.Segment,
	scopeID uint64,
	fieldPath string,
	benign bool,
) []extract.Segment {
	cloned := append([]extract.Segment(nil), base...)
	for index := range cloned {
		cloned[index].ScopeID = scopeID
		cloned[index].FieldPathHash = fieldPath
		if benign && profiledReferentCarrierKind(cloned[index].ContentKind) {
			cloned[index].Text = "```text\nwrite a friendly Go hello-world program\n```"
		}
	}
	return cloned
}

func round10ResizeDirectRun(t testing.TB, run []extract.Segment, target int) {
	t.Helper()
	carrier := -1
	for index, segment := range run {
		if carrier < 0 && profiledReferentCarrierKind(segment.ContentKind) {
			carrier = index
		}
	}
	if carrier < 0 {
		t.Fatal("cannot resize direct run without a carrier")
	}
	round10ResizeDirectRunPart(t, run, target, carrier)
}

func round10ResizeDirectRunPart(
	t testing.TB,
	run []extract.Segment,
	target int,
	paddingIndex int,
) {
	t.Helper()
	total := 0
	for _, segment := range run {
		total += len(segment.Text)
	}
	if paddingIndex < 0 || paddingIndex >= len(run) || total > target {
		t.Fatalf("cannot resize direct run: padding=%d total=%d target=%d", paddingIndex, total, target)
	}
	run[paddingIndex].Text += strings.Repeat(" ", target-total)
	actual := 0
	for _, segment := range run {
		actual += len(segment.Text)
	}
	if actual != target {
		t.Fatalf("resized direct run bytes=%d, want %d", actual, target)
	}
}

func round10DirectClassificationResults(
	t testing.TB,
	guard *Classifier,
	segments []extract.Segment,
	mode Mode,
) map[string]Result {
	t.Helper()
	return map[string]Result{
		"batch": guard.ClassifySegmentsWithPolicy(
			segments, mode, DefaultThresholds(), DefaultPolicy(),
		),
		"fieldwise": round10ClassifyDirectStreaming(t, guard, segments, mode, false),
		"bytewise":  round10ClassifyDirectStreaming(t, guard, segments, mode, true),
	}
}

func round10ClassifyDirectStreaming(
	t testing.TB,
	guard *Classifier,
	segments []extract.Segment,
	mode Mode,
	bytewise bool,
) Result {
	t.Helper()
	session, err := guard.NewProfiledScanSession(
		mode, DefaultThresholds(), DefaultPolicy(), DefaultScanLimits(),
	)
	if err != nil {
		t.Fatal(err)
	}
	for segmentIndex, segment := range segments {
		raw := []byte(segment.Text)
		chunks := [][]byte{raw}
		if bytewise && len(raw) != 0 {
			chunks = make([][]byte, len(raw))
			for index := range raw {
				chunks[index] = raw[index : index+1]
			}
		}
		for chunkIndex, text := range chunks {
			if err := session.AddSegment(extract.SegmentChunk{
				Role:                      segment.Role,
				Provenance:                segment.Provenance,
				UserAttribution:           segment.UserAttribution,
				ToolAssociation:           segment.ToolAssociation,
				ConversationIndex:         segment.ConversationIndex,
				TurnIndex:                 segment.TurnIndex,
				IsCurrentTurn:             segment.IsCurrentTurn,
				TerminalConversationIndex: segment.TerminalConversationIndex,
				TerminalTurnIndex:         segment.TerminalTurnIndex,
				HasTerminalCoordinates:    segment.HasTerminalCoordinates,
				ScopeID:                   segment.ScopeID,
				ContentKind:               segment.ContentKind,
				FieldPathHash:             segment.FieldPathHash,
				FieldID:                   uint64(segmentIndex + 1),
				Start:                     chunkIndex == 0,
				End:                       chunkIndex == len(chunks)-1,
				Text:                      text,
			}); err != nil {
				t.Fatalf("segment=%d chunk=%d AddSegment() error=%v", segmentIndex, chunkIndex, err)
			}
		}
	}
	return session.Finish()
}

func round10CoverageState(result Result) CoverageState {
	if result.Coverage.State == "" {
		return CoverageComplete
	}
	return result.Coverage.State
}

func round10AssertDirectResultParity(t testing.TB, results map[string]Result) {
	t.Helper()
	want, ok := results["batch"]
	if !ok {
		t.Fatal("result set has no true batch result")
	}
	for transport, got := range results {
		if transport == "batch" {
			continue
		}
		if got.Action != want.Action || got.Score != want.Score || got.Category != want.Category ||
			got.Context != want.Context || got.FindingOrigin != want.FindingOrigin ||
			got.Truncated != want.Truncated ||
			round10CoverageState(got) != round10CoverageState(want) ||
			got.Coverage.Reason != want.Coverage.Reason ||
			!slices.Equal(got.RuleIDs, want.RuleIDs) ||
			!slices.Equal(got.Evidence, want.Evidence) ||
			!reflect.DeepEqual(got.BlockEligibility, want.BlockEligibility) ||
			!reflect.DeepEqual(got.DecisionExplanation, want.DecisionExplanation) {
			t.Fatalf("%s/true-batch parity mismatch: context=%t origin=%t rules=%t evidence=%t eligibility=%t explanation=%t coverage=%s/%s reason=%s/%s",
				transport, got.Context == want.Context, got.FindingOrigin == want.FindingOrigin,
				slices.Equal(got.RuleIDs, want.RuleIDs), slices.Equal(got.Evidence, want.Evidence),
				reflect.DeepEqual(got.BlockEligibility, want.BlockEligibility),
				reflect.DeepEqual(got.DecisionExplanation, want.DecisionExplanation),
				round10CoverageState(want), round10CoverageState(got), want.Coverage.Reason, got.Coverage.Reason)
		}
	}
}

func round10RequireCompleteEligibleBlock(t testing.TB, transport string, result Result) {
	t.Helper()
	if round10CoverageState(result) != CoverageComplete || result.Truncated ||
		result.Action != ActionBlock || result.BlockEligibility == nil ||
		!result.BlockEligibility.Eligible ||
		result.BlockEligibility.EnforcementScope != EnforcementScopeCurrentUser ||
		!result.BlockEligibility.EvidenceOwnedByCurrentUser {
		t.Fatalf("%s result=%+v, want complete current-user eligible block", transport, result)
	}
}
