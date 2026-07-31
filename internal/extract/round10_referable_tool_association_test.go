package extract

import "testing"

func TestRound10ToolResultAssociationKeepsExistingNumericValues(t *testing.T) {
	if ToolResultAssociationNone != 0 || ToolResultAssociationUnique != 1 ||
		ToolResultAssociationReferableUnique != 2 {
		t.Fatalf(
			"tool association values none=%d unique=%d referable=%d",
			ToolResultAssociationNone,
			ToolResultAssociationUnique,
			ToolResultAssociationReferableUnique,
		)
	}
}

func TestRound10ProviderToolResultAssociationDistinguishesReferableAndTerminal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		profile SourceProfile
		body    string
		target  string
		want    ToolResultAssociation
	}{
		{
			name: "openai chat referable before current user", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-ref","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-ref","content":"chat-referable-result"},
				{"role":"user","content":"use the previous result"}
			]}`,
			target: "chat-referable-result", want: ToolResultAssociationReferableUnique,
		},
		{
			name: "openai chat terminal unique", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-terminal","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-terminal","content":"chat-terminal-result"}
			]}`,
			target: "chat-terminal-result", want: ToolResultAssociationUnique,
		},
		{
			name: "openai chat mismatch remains none", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-call","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-other","content":"chat-mismatch-result"},
				{"role":"user","content":"use the previous result"}
			]}`,
			target: "chat-mismatch-result", want: ToolResultAssociationNone,
		},
		{
			name: "responses referable before current user", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-ref","name":"lookup","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-ref","output":"responses-referable-result"},
				{"type":"message","role":"user","content":"use the previous result"}
			]}`,
			target: "responses-referable-result", want: ToolResultAssociationReferableUnique,
		},
		{
			name: "responses terminal unique", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-terminal","name":"lookup","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-terminal","output":"responses-terminal-result"}
			]}`,
			target: "responses-terminal-result", want: ToolResultAssociationUnique,
		},
		{
			name: "responses mismatch remains none", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-call","name":"lookup","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-other","output":"responses-mismatch-result"},
				{"type":"message","role":"user","content":"use the previous result"}
			]}`,
			target: "responses-mismatch-result", want: ToolResultAssociationNone,
		},
		{
			name: "claude referable before current user", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-ref","name":"lookup","input":{}}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"claude-ref","content":"claude-referable-result"}]},
				{"role":"user","content":"use the previous result"}
			]}`,
			target: "claude-referable-result", want: ToolResultAssociationReferableUnique,
		},
		{
			name: "claude terminal unique", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-terminal","name":"lookup","input":{}}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"claude-terminal","content":"claude-terminal-result"}]}
			]}`,
			target: "claude-terminal-result", want: ToolResultAssociationUnique,
		},
		{
			name: "claude mismatch remains none", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-call","name":"lookup","input":{}}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"claude-other","content":"claude-mismatch-result"}]},
				{"role":"user","content":"use the previous result"}
			]}`,
			target: "claude-mismatch-result", want: ToolResultAssociationNone,
		},
		{
			name: "gemini referable before current user", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-ref","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-ref","name":"lookup","response":{"result":"gemini-referable-result"}}}]},
				{"role":"user","parts":[{"text":"use the previous result"}]}
			]}`,
			target: "gemini-referable-result", want: ToolResultAssociationReferableUnique,
		},
		{
			name: "gemini terminal unique", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-terminal","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-terminal","name":"lookup","response":{"result":"gemini-terminal-result"}}}]}
			]}`,
			target: "gemini-terminal-result", want: ToolResultAssociationUnique,
		},
		{
			name: "gemini mismatch remains none", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-call","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-other","name":"lookup","response":{"result":"gemini-mismatch-result"}}}]},
				{"role":"user","parts":[{"text":"use the previous result"}]}
			]}`,
			target: "gemini-mismatch-result", want: ToolResultAssociationNone,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			batch, chunks := round9ExtractToolAssociationParity(t, test.profile, test.body)
			segment := round8RequireSegment(t, batch.Segments, test.target)
			if segment.Role != RoleTool || segment.ContentKind != ContentKindToolResult ||
				segment.ToolAssociation != test.want || !segment.HasTerminalCoordinates {
				t.Fatalf("tool result metadata=%#v want association=%d", segment, test.want)
			}
			isTerminal := segment.ConversationIndex == segment.TerminalConversationIndex
			switch test.want {
			case ToolResultAssociationReferableUnique:
				if isTerminal || segment.TerminalConversationIndex-segment.ConversationIndex != 1 {
					t.Fatalf("referable result is not immediately before terminal user: %#v", segment)
				}
			case ToolResultAssociationUnique:
				if !isTerminal {
					t.Fatalf("unique result is not terminal: %#v", segment)
				}
			}
			round8AssertChunkMatchesSegment(t, round8RequireChunk(t, chunks, test.target), segment)
		})
	}
}

func TestRound10ReferableToolResultAssociationFailsClosedAtNewBoundary(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		profile      SourceProfile
		body         string
		expectations []round9ToolAssociationExpectation
	}{
		{
			name: "openai chat assistant tail is not a referent", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-assistant-tail","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-assistant-tail","content":"chat-assistant-tail-result"},
				{"role":"assistant","content":"ordinary assistant tail"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"chat-assistant-tail-result", ToolResultAssociationNone}},
		},
		{
			name: "responses assistant tail is not a referent", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-assistant-tail","name":"lookup","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-assistant-tail","output":"responses-assistant-tail-result"},
				{"type":"message","role":"assistant","content":"ordinary assistant tail"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"responses-assistant-tail-result", ToolResultAssociationNone}},
		},
		{
			name: "claude assistant tail is not a referent", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-assistant-tail","name":"lookup","input":{}}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"claude-assistant-tail","content":"claude-assistant-tail-result"}]},
				{"role":"assistant","content":"ordinary assistant tail"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"claude-assistant-tail-result", ToolResultAssociationNone}},
		},
		{
			name: "gemini model tail is not a referent", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-model-tail","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-model-tail","name":"lookup","response":{"result":"gemini-model-tail-result"}}}]},
				{"role":"model","parts":[{"text":"ordinary model tail"}]}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"gemini-model-tail-result", ToolResultAssociationNone}},
		},
		{
			name: "empty current user cannot refer", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-empty-tail","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-empty-tail","content":"chat-empty-tail-result"},
				{"role":"user","content":""}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"chat-empty-tail-result", ToolResultAssociationNone}},
		},
		{
			name: "incomplete parallel chat transaction", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[
					{"id":"chat-count-a","type":"function","function":{"name":"lookup_a","arguments":"{}"}},
					{"id":"chat-count-b","type":"function","function":{"name":"lookup_b","arguments":"{}"}}
				]},
				{"role":"tool","tool_call_id":"chat-count-a","content":"chat-count-mismatch-result"},
				{"role":"user","content":"use the previous result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"chat-count-mismatch-result", ToolResultAssociationNone}},
		},
		{
			name: "duplicate chat call id", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[
					{"id":"chat-duplicate","type":"function","function":{"name":"lookup_a","arguments":"{}"}},
					{"id":"chat-duplicate","type":"function","function":{"name":"lookup_b","arguments":"{}"}}
				]},
				{"role":"tool","tool_call_id":"chat-duplicate","content":"chat-duplicate-result"},
				{"role":"user","content":"use the previous result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"chat-duplicate-result", ToolResultAssociationNone}},
		},
		{
			name: "excessive chat result group", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-extra","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-extra","content":"chat-extra-first-result"},
				{"role":"tool","tool_call_id":"chat-extra","content":"chat-extra-second-result"},
				{"role":"user","content":"use the previous result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"chat-extra-first-result", ToolResultAssociationNone},
				{"chat-extra-second-result", ToolResultAssociationNone},
			},
		},
		{
			name: "claude wrong result owner", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-owner","name":"lookup","input":{}}]},
				{"role":"assistant","content":[{"type":"tool_result","tool_use_id":"claude-owner","content":"claude-wrong-owner-result"}]},
				{"role":"user","content":"use the previous result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"claude-wrong-owner-result", ToolResultAssociationNone}},
		},
		{
			name: "responses subtype mismatch", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-subtype","name":"lookup","arguments":"{}"},
				{"type":"custom_tool_call_output","call_id":"responses-subtype","output":"responses-subtype-result"},
				{"type":"message","role":"user","content":"use the previous result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"responses-subtype-result", ToolResultAssociationNone}},
		},
		{
			name: "intervening assistant is a transaction barrier", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-barrier","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-barrier","content":"chat-barrier-result"},
				{"role":"assistant","content":"intervening assistant"},
				{"role":"user","content":"use the previous result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"chat-barrier-result", ToolResultAssociationNone}},
		},
		{
			name: "reused id does not revive stale transaction", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-reused","type":"function","function":{"name":"lookup_old","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-reused","content":"chat-reused-stale-result"},
				{"role":"user","content":"old boundary"},
				{"role":"assistant","tool_calls":[{"id":"chat-reused","type":"function","function":{"name":"lookup_new","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-reused","content":"chat-reused-nearest-result"},
				{"role":"user","content":"use the previous result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"chat-reused-stale-result", ToolResultAssociationNone},
				{"chat-reused-nearest-result", ToolResultAssociationReferableUnique},
			},
		},
		{
			name: "gemini result count mismatch", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[
					{"functionCall":{"id":"gemini-count-a","name":"lookup_a","args":{}}},
					{"functionCall":{"id":"gemini-count-b","name":"lookup_b","args":{}}}
				]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-count-a","name":"lookup_a","response":{"result":"gemini-count-result"}}}]},
				{"role":"user","parts":[{"text":"use the previous result"}]}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"gemini-count-result", ToolResultAssociationNone}},
		},
		{
			name: "claude historical result with user text sibling is ambiguous", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-sibling","name":"lookup","input":{}}]},
				{"role":"user","content":[
					{"type":"tool_result","tool_use_id":"claude-sibling","content":"claude-sibling-result"},
					{"type":"text","text":"ordinary sibling user text"}
				]},
				{"role":"user","content":"use the previous result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"claude-sibling-result", ToolResultAssociationNone}},
		},
		{
			name: "gemini historical response with user text sibling is ambiguous", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-sibling","name":"lookup","args":{}}}]},
				{"role":"user","parts":[
					{"functionResponse":{"id":"gemini-sibling","name":"lookup","response":{"result":"gemini-sibling-result"}}},
					{"text":"ordinary sibling user text"}
				]},
				{"role":"user","parts":[{"text":"use the previous result"}]}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"gemini-sibling-result", ToolResultAssociationNone}},
		},
		{
			name: "gemini terminal orphan is an ambiguity barrier", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-prior","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-prior","name":"lookup","response":{"result":"gemini-prior-result"}}}]},
				{"role":"user","parts":[
					{"text":"use the previous result"},
					{"functionResponse":{"id":"gemini-orphan","name":"other","response":{"result":"gemini-orphan-result"}}}
				]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"gemini-prior-result", ToolResultAssociationNone},
				{"gemini-orphan-result", ToolResultAssociationNone},
			},
		},
		{
			name: "gemini terminal mismatched response is an ambiguity barrier", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-mismatch-prior","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-mismatch-prior","name":"lookup","response":{"result":"gemini-mismatch-prior-result"}}}]},
				{"role":"user","parts":[
					{"functionResponse":{"id":"gemini-mismatch-prior","name":"other","response":{"result":"gemini-terminal-mismatch-result"}}},
					{"text":"use the previous result"}
				]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"gemini-mismatch-prior-result", ToolResultAssociationNone},
				{"gemini-terminal-mismatch-result", ToolResultAssociationNone},
			},
		},
		{
			name: "gemini terminal wrong owner call is an ambiguity barrier", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-owner-prior","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-owner-prior","name":"lookup","response":{"result":"gemini-owner-prior-result"}}}]},
				{"role":"user","parts":[
					{"text":"use the previous result"},
					{"functionCall":{"id":"gemini-wrong-owner","name":"other","args":{"query":"gemini-wrong-owner-argument"}}}
				]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"gemini-owner-prior-result", ToolResultAssociationNone},
				{"gemini-wrong-owner-argument", ToolResultAssociationNone},
			},
		},
		{
			name: "gemini terminal ambiguous id is an ambiguity barrier", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-ambiguous-prior","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-ambiguous-prior","name":"lookup","response":{"result":"gemini-ambiguous-prior-result"}}}]},
				{"role":"user","parts":[
					{"text":"use the previous result"},
					{"functionResponse":{"id":"gemini-shadow-a","id":"gemini-shadow-b","name":"other","response":{"result":"gemini-ambiguous-terminal-result"}}}
				]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"gemini-ambiguous-prior-result", ToolResultAssociationNone},
				{"gemini-ambiguous-terminal-result", ToolResultAssociationNone},
			},
		},
		{
			name: "gemini terminal duplicate wrappers are an ambiguity barrier", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-duplicate-prior","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-duplicate-prior","name":"lookup","response":{"result":"gemini-duplicate-prior-result"}}}]},
				{"role":"user","parts":[
					{"text":"use the previous result"},
					{
						"functionResponse":{"id":"gemini-shadow-first","name":"other","response":{"result":"gemini-duplicate-terminal-first"}},
						"functionResponse":{"id":"gemini-shadow-second","name":"other","response":{"result":"gemini-duplicate-terminal-second"}}
					}
				]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"gemini-duplicate-prior-result", ToolResultAssociationNone},
				{"gemini-duplicate-terminal-first", ToolResultAssociationNone},
				{"gemini-duplicate-terminal-second", ToolResultAssociationNone},
			},
		},
		{
			name: "gemini terminal non object wrapper attempts are an ambiguity barrier", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-non-object-prior","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-non-object-prior","name":"lookup","response":{"result":"gemini-non-object-prior-result"}}}]},
				{"role":"user","parts":[
					{"text":"use the previous result"},
					{"functionResponse":null,"functionResponse":null}
				]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"gemini-non-object-prior-result", ToolResultAssociationNone},
			},
		},
		{
			name: "gemini wrong owner historical result remains unreferable", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-history-owner","name":"lookup","args":{}}}]},
				{"role":"model","parts":[{"functionResponse":{"id":"gemini-history-owner","name":"lookup","response":{"result":"gemini-history-wrong-owner-result"}}}]},
				{"role":"user","parts":[{"text":"use the previous result"}]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"gemini-history-wrong-owner-result", ToolResultAssociationNone},
			},
		},
		{
			name: "gemini duplicate historical wrappers remain unreferable", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{
					"functionCall":{"id":"gemini-history-first","name":"lookup","args":{}},
					"functionCall":{"id":"gemini-history-second","name":"lookup","args":{}}
				}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-history-second","name":"lookup","response":{"result":"gemini-history-duplicate-result"}}}]},
				{"role":"user","parts":[{"text":"use the previous result"}]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"gemini-history-duplicate-result", ToolResultAssociationNone},
			},
		},
		{
			name: "gemini valid terminal response with user text remains terminal unique", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-terminal-with-text","name":"lookup","args":{}}}]},
				{"role":"user","parts":[
					{"functionResponse":{"id":"gemini-terminal-with-text","name":"lookup","response":{"result":"gemini-terminal-with-text-result"}}},
					{"text":"summarize this result"}
				]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"gemini-terminal-with-text-result", ToolResultAssociationUnique},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			round9AssertToolAssociationParity(t, test.profile, test.body, test.expectations)
		})
	}
}

func TestRound10RoleAmbiguousTerminalItemCannotCreateReferableAssociation(t *testing.T) {
	t.Parallel()
	body := `{"messages":[
		{"role":"assistant","tool_calls":[{"id":"chat-role-tail","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
		{"role":"tool","tool_call_id":"chat-role-tail","content":"chat-role-tail-result"},
		{"content":"missing terminal role"}
	]}`
	profile := RequestProfile{Source: SourceProfileOpenAI}
	batch, err := ExtractProfiledRequest([]byte(body), round8JSONHeaders(), profile, Limits{})
	if err != nil || !batch.IsComplete() || batch.RoleAware {
		t.Fatalf("batch result=%#v err=%v", batch, err)
	}
	segment := round8RequireSegment(t, batch.Segments, "chat-role-tail-result")
	if segment.ToolAssociation != ToolResultAssociationNone {
		t.Fatalf("role-ambiguous tail created batch association: %#v", segment)
	}
	sink := &round8RecordingSink{}
	streamed, err := ScanProfiledRequest(
		[]byte(body), round8JSONHeaders(), profile, Limits{}, sink,
	)
	if err != nil || !streamed.IsComplete() || streamed.RoleAware || sink.aborted {
		t.Fatalf("stream result=%#v err=%v aborted=%v", streamed, err, sink.aborted)
	}
	chunk := round8RequireChunk(t, sink.chunks, "chat-role-tail-result")
	round8AssertChunkMatchesSegment(t, chunk, segment)
}
