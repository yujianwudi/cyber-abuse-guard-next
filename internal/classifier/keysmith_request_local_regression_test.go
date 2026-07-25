package classifier

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

func TestKeysmithRequestLocalSystemAndToolMiddleBackBlock(t *testing.T) {
	t.Parallel()
	guard := newDefaultClassifier(t)
	payload := loadPublicKeysmithMainPayload(t)
	for _, actor := range []struct {
		name      string
		role      extract.Role
		kind      extract.ContentKind
		wantScope EnforcementScope
	}{
		{name: "system", role: extract.RoleSystem, kind: extract.ContentKindNaturalLanguageDirective, wantScope: EnforcementScopeRequestLocalSystem},
		{name: "tool", role: extract.RoleTool, kind: extract.ContentKindToolResult, wantScope: EnforcementScopeRequestLocalTool},
	} {
		actor := actor
		for _, position := range []struct {
			name  string
			index int
		}{
			{name: "middle", index: 1},
			{name: "back", index: 2},
		} {
			position := position
			t.Run(actor.name+"/"+position.name, func(t *testing.T) {
				t.Parallel()
				segments := keysmithRequestLocalCarrierParts(actor.role, actor.kind, payload, position.index)
				batch, stream := round9ClassifyProfiledSegmentsBatchStreaming(t, guard, segments)
				for name, result := range map[string]Result{"batch": batch, "stream": stream} {
					if result.Action != ActionBlock || result.Category != "defense_evasion" ||
						!resultContainsRuleID(result, metaOverrideRuleID) || result.BlockEligibility == nil ||
						!result.BlockEligibility.Eligible || result.BlockEligibility.EnforcementScope != actor.wantScope ||
						result.BlockEligibility.EvidenceOwnedByCurrentUser ||
						result.FindingOrigin != FindingOriginNonUserOrUntrusted {
						t.Fatalf("%s result=%+v, want eligible %s Keysmith block", name, result, actor.wantScope)
					}
				}
				if batch.Category != stream.Category || batch.Score != stream.Score {
					t.Fatalf("batch/stream mismatch: batch=%+v stream=%+v", batch, stream)
				}
			})
		}
	}
}

func TestKeysmithRequestLocalCarrierAuthorityBoundaries(t *testing.T) {
	t.Parallel()
	guard := newDefaultClassifier(t)
	payload := loadPublicKeysmithMainPayload(t)
	cases := []struct {
		name     string
		segments []extract.Segment
	}{
		{
			name: "historical user",
			segments: []extract.Segment{{
				Role: extract.RoleUser, Provenance: extract.ProvenanceContent,
				UserAttribution: extract.UserAttributionTrusted, ConversationIndex: 0, TurnIndex: 0,
				ScopeID: 99_101, FieldPathHash: "keysmith-history", ContentKind: extract.ContentKindNaturalLanguageDirective,
				Text: payload,
			}},
		},
		{
			name: "historical system without request-local path proof",
			segments: []extract.Segment{
				{Role: extract.RoleSystem, Provenance: extract.ProvenanceContent, UserAttribution: extract.UserAttributionUntrusted,
					ConversationIndex: 0, TurnIndex: 0, ScopeID: 99_106,
					ContentKind: extract.ContentKindNaturalLanguageDirective, Text: payload},
				{Role: extract.RoleUser, Provenance: extract.ProvenanceContent, UserAttribution: extract.UserAttributionTrusted,
					ConversationIndex: 1, TurnIndex: 1, IsCurrentTurn: true, ScopeID: 99_107, FieldPathHash: "safe-after-system-history",
					ContentKind: extract.ContentKindNaturalLanguageDirective, Text: "summarize today's football result"},
			},
		},
		{
			name: "assistant history",
			segments: []extract.Segment{{
				Role: extract.RoleAssistant, Provenance: extract.ProvenanceContent,
				UserAttribution: extract.UserAttributionUntrusted, ConversationIndex: 0, TurnIndex: 0,
				ScopeID: 99_102, FieldPathHash: "keysmith-assistant", ContentKind: extract.ContentKindNaturalLanguageDirective,
				Text: payload,
			}},
		},
		{
			name: "nonterminal tool history",
			segments: []extract.Segment{
				{Role: extract.RoleTool, Provenance: extract.ProvenanceContent, UserAttribution: extract.UserAttributionUntrusted,
					ConversationIndex: 0, TurnIndex: 0, ScopeID: 99_103, FieldPathHash: "keysmith-tool-history",
					ContentKind: extract.ContentKindToolResult, Text: payload},
				{Role: extract.RoleUser, Provenance: extract.ProvenanceContent, UserAttribution: extract.UserAttributionTrusted,
					ConversationIndex: 1, TurnIndex: 1, IsCurrentTurn: true, ScopeID: 99_104, FieldPathHash: "safe-current-user",
					ContentKind: extract.ContentKindNaturalLanguageDirective, Text: "summarize today's football result"},
			},
		},
		{
			name: "inert system carrier",
			segments: []extract.Segment{{
				Role: extract.RoleSystem, Provenance: extract.ProvenanceContent,
				UserAttribution: extract.UserAttributionUntrusted, ConversationIndex: -1, TurnIndex: -1,
				ScopeID: 99_105, FieldPathHash: "keysmith-system-code", ContentKind: extract.ContentKindCodeBlock,
				Text: payload,
			}},
		},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			batch, stream := round9ClassifyProfiledSegmentsBatchStreaming(t, guard, testCase.segments)
			for name, result := range map[string]Result{"batch": batch, "stream": stream} {
				if result.Action == ActionBlock || result.BlockEligibility != nil && result.BlockEligibility.Eligible {
					t.Fatalf("%s activated %s: %+v", name, testCase.name, result)
				}
			}
		})
	}
}

func keysmithRequestLocalCarrierParts(role extract.Role, kind extract.ContentKind, payload string, payloadIndex int) []extract.Segment {
	parts := []string{"retain the ordinary football summary", "keep the response concise", "use the requested language"}
	parts[payloadIndex] = payload
	segments := make([]extract.Segment, len(parts))
	for index, text := range parts {
		segments[index] = extract.Segment{
			Role: role, Provenance: extract.ProvenanceContent, UserAttribution: extract.UserAttributionUntrusted,
			ConversationIndex: 0, TurnIndex: 0, ScopeID: 99_001,
			FieldPathHash: fmt.Sprintf("keysmith-carrier-part-%d", index), ContentKind: kind, Text: text,
		}
	}
	return segments
}

func loadPublicKeysmithMainPayload(t testing.TB) string {
	t.Helper()
	encoded, err := os.ReadFile("../../testdata/round9-public-adversarial-v10/payloads/keysmith-main-gpt-unrestricted.md.b64")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
	if err != nil {
		t.Fatal(err)
	}
	return string(payload)
}
