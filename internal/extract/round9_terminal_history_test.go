package extract

import "testing"

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
				historical.IsCurrentTurn {
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
					tail.ConversationIndex != 1 || tail.TurnIndex != 0 || tail.IsCurrentTurn {
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
