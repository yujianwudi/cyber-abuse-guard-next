package extract

import (
	"encoding/json"
	"testing"
)

func TestRound9OnlyTerminalHistoryUserCanBeCurrent(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		profile      SourceProfile
		body         string
		historical   string
		tail         string
		wantTailRole Role
		wantTailKind ContentKind
	}{
		{
			name: "openai chat assistant tail", profile: SourceProfileOpenAI,
			body:       `{"messages":[{"role":"user","content":"historical-openai-chat-assistant"},{"role":"assistant","content":"assistant-tail-openai-chat"}]}`,
			historical: "historical-openai-chat-assistant", tail: "assistant-tail-openai-chat",
			wantTailRole: RoleAssistant, wantTailKind: ContentKindNaturalLanguageDirective,
		},
		{
			name: "openai chat tool tail", profile: SourceProfileOpenAI,
			body:       `{"messages":[{"role":"user","content":"historical-openai-chat-tool"},{"role":"tool","tool_call_id":"call_1","content":"tool-tail-openai-chat"}]}`,
			historical: "historical-openai-chat-tool", tail: "tool-tail-openai-chat",
			wantTailRole: RoleTool, wantTailKind: ContentKindToolResult,
		},
		{
			name: "openai chat empty terminal item", profile: SourceProfileOpenAI,
			body:       `{"messages":[{"role":"user","content":"historical-openai-chat-empty"},{"role":"assistant","content":""}]}`,
			historical: "historical-openai-chat-empty",
		},
		{
			name: "openai responses assistant tail", profile: SourceProfileOpenAIResponse,
			body:       `{"input":[{"type":"message","role":"user","content":"historical-responses-assistant"},{"type":"message","role":"assistant","content":"assistant-tail-responses"}]}`,
			historical: "historical-responses-assistant", tail: "assistant-tail-responses",
			wantTailRole: RoleAssistant, wantTailKind: ContentKindNaturalLanguageDirective,
		},
		{
			name: "openai responses tool tail", profile: SourceProfileOpenAIResponse,
			body:       `{"input":[{"type":"message","role":"user","content":"historical-responses-tool"},{"type":"function_call_output","call_id":"call_1","output":"tool-tail-responses"}]}`,
			historical: "historical-responses-tool", tail: "tool-tail-responses",
			wantTailRole: RoleTool, wantTailKind: ContentKindToolResult,
		},
		{
			name: "openai responses empty terminal item", profile: SourceProfileOpenAIResponse,
			body:       `{"input":[{"type":"message","role":"user","content":"historical-responses-empty"},{"type":"message","role":"assistant","content":[]}]}`,
			historical: "historical-responses-empty",
		},
		{
			name: "claude assistant tail", profile: SourceProfileClaude,
			body:       `{"messages":[{"role":"user","content":"historical-claude-assistant"},{"role":"assistant","content":"assistant-tail-claude"}]}`,
			historical: "historical-claude-assistant", tail: "assistant-tail-claude",
			wantTailRole: RoleAssistant, wantTailKind: ContentKindNaturalLanguageDirective,
		},
		{
			name: "claude tool tail", profile: SourceProfileClaude,
			body:       `{"messages":[{"role":"user","content":"historical-claude-tool"},{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_1","content":"tool-tail-claude"}]}]}`,
			historical: "historical-claude-tool", tail: "tool-tail-claude",
			wantTailRole: RoleTool, wantTailKind: ContentKindToolResult,
		},
		{
			name: "claude empty terminal item", profile: SourceProfileClaude,
			body:       `{"messages":[{"role":"user","content":"historical-claude-empty"},{"role":"assistant","content":[]}]}`,
			historical: "historical-claude-empty",
		},
		{
			name: "gemini assistant tail", profile: SourceProfileGemini,
			body:       `{"contents":[{"role":"user","parts":[{"text":"historical-gemini-assistant"}]},{"role":"model","parts":[{"text":"assistant-tail-gemini"}]}]}`,
			historical: "historical-gemini-assistant", tail: "assistant-tail-gemini",
			wantTailRole: RoleAssistant, wantTailKind: ContentKindNaturalLanguageDirective,
		},
		{
			name: "gemini tool tail", profile: SourceProfileGemini,
			body:       `{"contents":[{"role":"user","parts":[{"text":"historical-gemini-tool"}]},{"role":"user","parts":[{"functionResponse":{"name":"scan","response":{"result":"tool-tail-gemini"}}}]}]}`,
			historical: "historical-gemini-tool", tail: "tool-tail-gemini",
			wantTailRole: RoleTool, wantTailKind: ContentKindToolResult,
		},
		{
			name: "gemini empty terminal item", profile: SourceProfileGemini,
			body:       `{"contents":[{"role":"user","parts":[{"text":"historical-gemini-empty"}]},{"role":"model","parts":[]}]}`,
			historical: "historical-gemini-empty",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			profile := RequestProfile{Source: test.profile}
			result, err := ExtractProfiledRequest(
				[]byte(test.body), round8JSONHeaders(), profile, Limits{},
			)
			if err != nil || !result.IsComplete() || !result.RoleAware {
				t.Fatalf("batch result=%#v err=%v", result, err)
			}
			historical := round8RequireSegment(t, result.Segments, test.historical)
			if historical.Role != RoleUser || historical.UserAttribution != UserAttributionTrusted ||
				historical.ConversationIndex != 0 || historical.TurnIndex != 0 ||
				historical.IsCurrentTurn || !historical.HasTerminalCoordinates ||
				historical.TerminalConversationIndex != 1 || historical.TerminalTurnIndex != 0 {
				t.Fatalf("historical user metadata=%#v", historical)
			}
			for _, segment := range result.Segments {
				if segment.IsCurrentTurn {
					t.Fatalf("non-user terminal history left a current segment: %#v", segment)
				}
			}
			if test.tail != "" {
				tail := round8RequireSegment(t, result.Segments, test.tail)
				if tail.Role != test.wantTailRole || tail.ContentKind != test.wantTailKind ||
					tail.UserAttribution != UserAttributionUntrusted ||
					tail.ConversationIndex != 1 || tail.TurnIndex != 0 || tail.IsCurrentTurn ||
					!tail.HasTerminalCoordinates || tail.TerminalConversationIndex != 1 ||
					tail.TerminalTurnIndex != 0 {
					t.Fatalf("terminal tail metadata=%#v", tail)
				}
			}

			sink := &round8RecordingSink{}
			streamed, err := ScanProfiledRequest(
				[]byte(test.body), round8JSONHeaders(), profile, Limits{}, sink,
			)
			if err != nil || !streamed.IsComplete() || !streamed.RoleAware || sink.aborted {
				t.Fatalf("stream result=%#v err=%v aborted=%v", streamed, err, sink.aborted)
			}
			for _, chunk := range sink.chunks {
				if chunk.IsCurrentTurn {
					t.Fatalf("streamed non-user terminal history left a current chunk: %#v", chunk)
				}
			}
			historicalChunk := round8RequireChunk(t, sink.chunks, test.historical)
			round8AssertChunkMatchesSegment(t, historicalChunk, historical)
		})
	}
}

func TestRound9OpenAIToolResultAssociationRequiresUniquePriorCall(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		body       string
		wantUnique bool
	}{
		{
			name: "matching id",
			body: `{"messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},` +
				`{"role":"tool","tool_call_id":"call_1","content":"association-result"}]}`,
			wantUnique: true,
		},
		{
			name: "isolated result",
			body: `{"messages":[{"role":"tool","tool_call_id":"call_1","content":"association-result"}]}`,
		},
		{
			name: "missing id",
			body: `{"messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},` +
				`{"role":"tool","content":"association-result"}]}`,
		},
		{
			name: "mismatched id",
			body: `{"messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},` +
				`{"role":"tool","tool_call_id":"call_2","content":"association-result"}]}`,
		},
		{
			name: "invalid id",
			body: `{"messages":[{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}}]},` +
				`{"role":"tool","tool_call_id":42,"content":"association-result"}]}`,
		},
		{
			name: "ambiguous duplicate call id",
			body: `{"messages":[{"role":"assistant","tool_calls":[` +
				`{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{}"}},` +
				`{"id":"call_1","type":"function","function":{"name":"lookup_again","arguments":"{}"}}]},` +
				`{"role":"tool","tool_call_id":"call_1","content":"association-result"}]}`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			profile := RequestProfile{Source: SourceProfileOpenAI}
			result, err := ExtractProfiledRequest(
				[]byte(test.body), round8JSONHeaders(), profile, Limits{},
			)
			if err != nil || !result.IsComplete() || !result.RoleAware {
				t.Fatalf("batch result=%#v err=%v", result, err)
			}
			toolResult := round8RequireSegment(t, result.Segments, "association-result")
			want := ToolResultAssociationNone
			if test.wantUnique {
				want = ToolResultAssociationUnique
			}
			if toolResult.ToolAssociation != want || !toolResult.HasTerminalCoordinates ||
				toolResult.TerminalConversationIndex != lenMessageHistory(test.body)-1 {
				t.Fatalf("tool result metadata=%#v, want association=%d", toolResult, want)
			}

			sink := &round8RecordingSink{}
			streamed, err := ScanProfiledRequest(
				[]byte(test.body), round8JSONHeaders(), profile, Limits{}, sink,
			)
			if err != nil || !streamed.IsComplete() || !streamed.RoleAware || sink.aborted {
				t.Fatalf("stream result=%#v err=%v aborted=%v", streamed, err, sink.aborted)
			}
			chunk := round8RequireChunk(t, sink.chunks, "association-result")
			round8AssertChunkMatchesSegment(t, chunk, toolResult)
		})
	}
}

func TestRound9ProviderToolResultAssociationContract(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		profile         SourceProfile
		body            string
		resultText      string
		additionalText  string
		wantAssociation ToolResultAssociation
		nonterminal     bool
	}{
		{
			name: "openai chat canonical", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-id","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-id","content":"chat-canonical-result"}
			]}`,
			resultText: "chat-canonical-result", wantAssociation: ToolResultAssociationUnique,
		},
		{
			name: "openai chat rejects anthropic id key", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-id","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_use_id":"chat-id","content":"chat-tool-use-id-result"}
			]}`,
			resultText: "chat-tool-use-id-result",
		},
		{
			name: "openai chat rejects responses id key", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-id","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","call_id":"chat-id","content":"chat-call-id-result"}
			]}`,
			resultText: "chat-call-id-result",
		},
		{
			name: "openai chat rejects user owned foreign result block", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-id","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"chat-id","content":"chat-user-result-block"}]}
			]}`,
			resultText: "chat-user-result-block",
		},
		{
			name: "responses canonical", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-id","name":"lookup","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-id","output":"responses-canonical-result"}
			]}`,
			resultText: "responses-canonical-result", wantAssociation: ToolResultAssociationUnique,
		},
		{
			name: "responses previous response continuation stays unassociated", profile: SourceProfileOpenAIResponse,
			body: `{"previous_response_id":"resp-1","input":[
				{"type":"function_call_output","call_id":"responses-id","output":"responses-continuation-result"}
			]}`,
			resultText: "responses-continuation-result",
		},
		{
			name: "responses custom previous response continuation stays unassociated", profile: SourceProfileOpenAIResponse,
			body: `{"previous_response_id":"resp-1","input":[
				{"type":"custom_tool_call_output","call_id":"responses-custom-id","output":"responses-custom-continuation-result"}
			]}`,
			resultText: "responses-custom-continuation-result",
		},
		{
			name: "responses orphan without previous response stays unassociated", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call_output","call_id":"responses-id","output":"responses-orphan-result"}
			]}`,
			resultText: "responses-orphan-result",
		},
		{
			name: "responses empty previous response stays unassociated", profile: SourceProfileOpenAIResponse,
			body: `{"previous_response_id":"","input":[
				{"type":"function_call_output","call_id":"responses-id","output":"responses-empty-previous-result"}
			]}`,
			resultText: "responses-empty-previous-result",
		},
		{
			name: "responses aliased previous response stays unassociated", profile: SourceProfileOpenAIResponse,
			body: `{"previousResponseId":"resp-1","input":[
				{"type":"function_call_output","call_id":"responses-id","output":"responses-aliased-previous-result"}
			]}`,
			resultText: "responses-aliased-previous-result",
		},
		{
			name: "responses duplicate previous response stays unassociated", profile: SourceProfileOpenAIResponse,
			body: `{"previous_response_id":"resp-1","previous_response_id":"resp-2","input":[
				{"type":"function_call_output","call_id":"responses-id","output":"responses-duplicate-previous-result"}
			]}`,
			resultText: "responses-duplicate-previous-result",
		},
		{
			name: "responses rejects generic chat tool message", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-id","name":"lookup","arguments":"{}"},
				{"type":"message","role":"tool","tool_call_id":"responses-id","content":"responses-generic-tool-result"}
			]}`,
			resultText: "responses-generic-tool-result",
		},
		{
			name: "responses rejects generic anthropic id key", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-id","name":"lookup","arguments":"{}"},
				{"type":"message","role":"tool","tool_use_id":"responses-id","content":"responses-tool-use-id-result"}
			]}`,
			resultText: "responses-tool-use-id-result",
		},
		{
			name: "responses rejects user owned foreign result block", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-id","name":"lookup","arguments":"{}"},
				{"type":"message","role":"user","content":[{"type":"tool_result","tool_use_id":"responses-id","content":"responses-user-result-block"}]}
			]}`,
			resultText: "responses-user-result-block",
		},
		{
			name: "claude canonical", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-id","name":"lookup","input":{}}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"claude-id","content":"claude-canonical-result"}]}
			]}`,
			resultText: "claude-canonical-result", wantAssociation: ToolResultAssociationUnique,
		},
		{
			name: "claude rejects generic openai tool message", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-id","name":"lookup","input":{}}]},
				{"role":"tool","tool_call_id":"claude-id","content":"claude-tool-call-id-result"}
			]}`,
			resultText: "claude-tool-call-id-result",
		},
		{
			name: "claude rejects generic responses id key", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-id","name":"lookup","input":{}}]},
				{"role":"tool","call_id":"claude-id","content":"claude-call-id-result"}
			]}`,
			resultText: "claude-call-id-result",
		},
		{
			name: "claude rejects assistant owned native result", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-id","name":"lookup","input":{}}]},
				{"role":"assistant","content":[{"type":"tool_result","tool_use_id":"claude-id","content":"claude-assistant-result"}]}
			]}`,
			resultText: "claude-assistant-result",
		},
		{
			name: "gemini canonical exact id", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-id","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-id","name":"lookup","response":{"result":"gemini-canonical-result"}}}]}
			]}`,
			resultText: "gemini-canonical-result", wantAssociation: ToolResultAssociationUnique,
		},
		{
			name: "gemini canonical exact call id", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"call_id":"gemini-call-id","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"call_id":"gemini-call-id","name":"lookup","response":{"result":"gemini-canonical-call-id-result"}}}]}
			]}`,
			resultText: "gemini-canonical-call-id-result", wantAssociation: ToolResultAssociationUnique,
		},
		{
			name: "gemini parallel explicit ids require a complete transaction", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[
					{"functionCall":{"id":"gemini-a","name":"lookup","args":{"q":"one"}}},
					{"functionCall":{"call_id":"gemini-b","name":"lookup","args":{"q":"two"}}}
				]},
				{"role":"user","parts":[
					{"functionResponse":{"id":"gemini-a","name":"lookup","response":{"result":"gemini-explicit-first-result"}}},
					{"functionResponse":{"call_id":"gemini-b","name":"lookup","response":{"result":"gemini-explicit-second-result"}}}
				]}
			]}`,
			resultText: "gemini-explicit-second-result", additionalText: "gemini-explicit-first-result",
			wantAssociation: ToolResultAssociationUnique,
		},
		{
			name: "gemini mixed explicit and implicit group stays unassociated", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[
					{"functionCall":{"id":"gemini-a","name":"lookup","args":{"q":"one"}}},
					{"functionCall":{"name":"lookup","args":{"q":"two"}}}
				]},
				{"role":"user","parts":[
					{"functionResponse":{"id":"gemini-a","name":"lookup","response":{"result":"gemini-mixed-explicit-result"}}},
					{"functionResponse":{"name":"lookup","response":{"result":"gemini-mixed-implicit-result"}}}
				]}
			]}`,
			resultText: "gemini-mixed-explicit-result", additionalText: "gemini-mixed-implicit-result",
		},
		{
			name: "gemini explicit id count mismatch stays unassociated", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[
					{"functionCall":{"id":"gemini-a","name":"lookup","args":{"q":"one"}}},
					{"functionCall":{"id":"gemini-b","name":"lookup","args":{"q":"two"}}}
				]},
				{"role":"user","parts":[
					{"functionResponse":{"id":"gemini-a","name":"lookup","response":{"result":"gemini-explicit-short-result"}}}
				]}
			]}`,
			resultText: "gemini-explicit-short-result",
		},
		{
			name: "gemini explicit id set mismatch stays unassociated", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[
					{"functionCall":{"id":"gemini-a","name":"lookup","args":{"q":"one"}}},
					{"functionCall":{"id":"gemini-b","name":"lookup","args":{"q":"two"}}}
				]},
				{"role":"user","parts":[
					{"functionResponse":{"id":"gemini-a","name":"lookup","response":{"result":"gemini-explicit-matched-result"}}},
					{"functionResponse":{"id":"gemini-c","name":"lookup","response":{"result":"gemini-explicit-foreign-result"}}}
				]}
			]}`,
			resultText: "gemini-explicit-matched-result", additionalText: "gemini-explicit-foreign-result",
		},
		{
			name: "gemini unique same name native pair", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"name":"lookup","response":{"result":"gemini-name-only-result"}}}]}
			]}`,
			resultText: "gemini-name-only-result", wantAssociation: ToolResultAssociationUnique,
		},
		{
			name: "gemini mixed id and name only response stays unassociated", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-id","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"name":"lookup","response":{"result":"gemini-id-call-name-result"}}}]}
			]}`,
			resultText: "gemini-id-call-name-result",
		},
		{
			name: "gemini repeated names pair strictly by ordinal", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[
					{"functionCall":{"name":"lookup","args":{"q":"one"}}},
					{"functionCall":{"name":"lookup","args":{"q":"two"}}}
				]},
				{"role":"user","parts":[
					{"functionResponse":{"name":"lookup","response":{"result":"gemini-repeated-first-result"}}},
					{"functionResponse":{"name":"lookup","response":{"result":"gemini-repeated-second-result"}}}
				]}
			]}`,
			resultText: "gemini-repeated-second-result", additionalText: "gemini-repeated-first-result",
			wantAssociation: ToolResultAssociationUnique,
		},
		{
			name: "gemini mismatched name stays unassociated", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"name":"other","response":{"result":"gemini-mismatched-name-result"}}}]}
			]}`,
			resultText: "gemini-mismatched-name-result",
		},
		{
			name: "gemini duplicate same name calls stay unassociated", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[
					{"functionCall":{"name":"lookup","args":{"q":"one"}}},
					{"functionCall":{"name":"lookup","args":{"q":"two"}}}
				]},
				{"role":"user","parts":[{"functionResponse":{"name":"lookup","response":{"result":"gemini-duplicate-name-result"}}}]}
			]}`,
			resultText: "gemini-duplicate-name-result",
		},
		{
			name: "gemini response before call stays unassociated", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"user","parts":[{"functionResponse":{"name":"lookup","response":{"result":"gemini-reversed-result"}}}]},
				{"role":"model","parts":[{"functionCall":{"name":"lookup","args":{}}}]}
			]}`,
			resultText: "gemini-reversed-result", nonterminal: true,
		},
		{
			name: "gemini nonadjacent groups stay unassociated", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"text":"intervening message"}]},
				{"role":"user","parts":[{"functionResponse":{"name":"lookup","response":{"result":"gemini-nonadjacent-result"}}}]}
			]}`,
			resultText: "gemini-nonadjacent-result",
		},
		{
			name: "gemini malformed explicit id cannot fall back to name", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":42,"name":"lookup","response":{"result":"gemini-malformed-id-result"}}}]}
			]}`,
			resultText: "gemini-malformed-id-result",
		},
		{
			name: "gemini rejects model owned native result", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-id","name":"lookup","args":{}}}]},
				{"role":"model","parts":[{"functionResponse":{"id":"gemini-id","name":"lookup","response":{"result":"gemini-model-result"}}}]}
			]}`,
			resultText: "gemini-model-result",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			profile := RequestProfile{Source: test.profile}
			batch, err := ExtractProfiledRequest(
				[]byte(test.body), round8JSONHeaders(), profile, Limits{},
			)
			if err != nil || !batch.IsComplete() || !batch.RoleAware {
				t.Fatalf("batch result=%#v err=%v", batch, err)
			}
			result := round8RequireSegment(t, batch.Segments, test.resultText)
			want := test.wantAssociation
			atTerminal := result.ConversationIndex == result.TerminalConversationIndex
			if result.Role != RoleTool || result.ContentKind != ContentKindToolResult ||
				result.ToolAssociation != want || !result.HasTerminalCoordinates ||
				atTerminal == test.nonterminal {
				t.Fatalf("tool result=%#v, want association=%d at terminal item", result, want)
			}
			if test.additionalText != "" {
				additional := round8RequireSegment(t, batch.Segments, test.additionalText)
				if additional.Role != RoleTool || additional.ContentKind != ContentKindToolResult ||
					additional.ToolAssociation != want || !additional.HasTerminalCoordinates ||
					additional.ConversationIndex != additional.TerminalConversationIndex {
					t.Fatalf("additional tool result=%#v, want association=%d at terminal item", additional, want)
				}
			}

			sink := &round8RecordingSink{}
			streamed, err := ScanProfiledRequest(
				[]byte(test.body), round8JSONHeaders(), profile, Limits{}, sink,
			)
			if err != nil || !streamed.IsComplete() || !streamed.RoleAware || sink.aborted {
				t.Fatalf("stream result=%#v err=%v aborted=%v", streamed, err, sink.aborted)
			}
			chunk := round8RequireChunk(t, sink.chunks, test.resultText)
			round8AssertChunkMatchesSegment(t, chunk, result)
			if test.additionalText != "" {
				additionalChunk := round8RequireChunk(t, sink.chunks, test.additionalText)
				additional := round8RequireSegment(t, batch.Segments, test.additionalText)
				round8AssertChunkMatchesSegment(t, additionalChunk, additional)
			}
		})
	}
}

func TestRound9ToolAssociationFieldNamesRemainVisibleOutsideClosedProviderObjects(t *testing.T) {
	t.Parallel()

	body := []byte(`{
		"name":"visible-name-directive",
		"id":"visible-id-directive",
		"call_id":"visible-call-id-directive",
		"tool_call_id":"visible-tool-call-id-directive",
		"tool_use_id":"visible-tool-use-id-directive"
	}`)
	targets := []string{
		"visible-name-directive",
		"visible-id-directive",
		"visible-call-id-directive",
		"visible-tool-call-id-directive",
		"visible-tool-use-id-directive",
	}

	batch, err := ExtractUntrustedRequest(body, round8JSONHeaders(), Limits{})
	if err != nil || !batch.IsComplete() {
		t.Fatalf("batch result=%#v err=%v", batch, err)
	}
	for _, target := range targets {
		segment := round8RequireSegment(t, batch.Segments, target)
		if segment.Role != RoleUnknown || segment.UserAttribution != UserAttributionUntrusted ||
			segment.Provenance != ProvenanceContent {
			t.Fatalf("batch association-like field %q gained trusted metadata: %#v", target, segment)
		}
	}

	sink := &round8RecordingSink{}
	streamed, err := ScanUntrustedRequest(body, round8JSONHeaders(), Limits{}, sink)
	if err != nil || !streamed.IsComplete() || sink.aborted {
		t.Fatalf("stream result=%#v err=%v aborted=%v", streamed, err, sink.aborted)
	}
	for _, target := range targets {
		chunk := round8RequireChunk(t, sink.chunks, target)
		if chunk.Role != RoleUnknown || chunk.UserAttribution != UserAttributionUntrusted ||
			chunk.Provenance != ProvenanceContent {
			t.Fatalf("stream association-like field %q gained trusted metadata: %#v", target, chunk)
		}
	}
}

func lenMessageHistory(body string) int {
	var envelope struct {
		Messages []any `json:"messages"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return 0
	}
	return len(envelope.Messages)
}
