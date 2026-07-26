package extract

import (
	"strings"
	"testing"
)

func TestRound9StructuredToolResultTextLeavesAreAtomicAndProviderExact(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		profile    SourceProfile
		body       string
		authorized []string
		denied     []string
	}{
		{
			name:    "chat text blocks with media",
			profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-structured","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-structured","content":[
					{"type":"text","text":"chat-structured-first"},
					{"type":"image_url","image_url":{"url":"https://example.test/chat-media"}},
					{"text":"chat-structured-second","type":"text"}
				],"attacker":"chat-structured-sibling"}
			]}`,
			authorized: []string{"chat-structured-first", "chat-structured-second"},
			denied:     []string{"chat-structured-sibling"},
		},
		{
			name:    "responses function typed output blocks",
			profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-structured-function","name":"lookup","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-structured-function","output":[
					{"type":"input_text","text":"responses-function-first"},
					{"type":"input_image","image_url":"https://example.test/responses-media"},
					{"type":"output_text","text":"responses-function-second"}
				],"attacker":"responses-function-sibling"}
			]}`,
			authorized: []string{"responses-function-first", "responses-function-second"},
			denied:     []string{"responses-function-sibling"},
		},
		{
			name:    "responses custom typed output blocks",
			profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"custom_tool_call","call_id":"responses-structured-custom","name":"lookup","input":"{}"},
				{"type":"custom_tool_call_output","call_id":"responses-structured-custom","output":[
					{"type":"output_text","text":"responses-custom-first"},
					{"type":"input_text","text":"responses-custom-second"}
				],"attacker":"responses-custom-sibling"}
			]}`,
			authorized: []string{"responses-custom-first", "responses-custom-second"},
			denied:     []string{"responses-custom-sibling"},
		},
		{
			name:    "claude text blocks with media",
			profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-structured","name":"lookup","input":{}}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"claude-structured","content":[
					{"type":"text","text":"claude-structured-first"},
					{"type":"image","source":{"type":"url","url":"https://example.test/claude-media"}},
					{"type":"text","text":"claude-structured-second","cache_control":{"type":"ephemeral","ttl":"5m"}}
				],"attacker":"claude-structured-sibling"}]}
			]}`,
			authorized: []string{"claude-structured-first", "claude-structured-second"},
			denied:     []string{"claude-structured-sibling", "ephemeral", "5m"},
		},
		{
			name:    "gemini response object and array descendants",
			profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-structured","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-structured","name":"lookup","response":{
					"result":{"type":"gemini-result-type","summary":"gemini-structured-object","items":["gemini-structured-array",{"detail":"gemini-structured-nested"}]},
					"parts":[{"text":"gemini-structured-sibling"}],"note":"gemini-structured-note"
				},"attacker":"gemini-outside-response"}}]}
			]}`,
			authorized: []string{
				"gemini-result-type", "gemini-structured-object", "gemini-structured-array",
				"gemini-structured-nested", "gemini-structured-sibling", "gemini-structured-note",
			},
			denied: []string{"gemini-outside-response"},
		},
		{
			name:    "gemini root result array",
			profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-root-array","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-root-array","name":"lookup","response":{"result":["gemini-root-array-leaf",{"message":"gemini-root-object-leaf"}],"other":"gemini-root-array-sibling"},"attacker":"gemini-root-outside-response"}}]}
			]}`,
			authorized: []string{"gemini-root-array-leaf", "gemini-root-object-leaf", "gemini-root-array-sibling"},
			denied:     []string{"gemini-root-outside-response"},
		},
		{
			name:    "gemini output descendants",
			profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-output","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-output","name":"lookup","response":{"output":{"summary":"gemini-output-object","items":["gemini-output-array"]},"status":"gemini-output-status"},"note":"gemini-output-outside-response"}}]}
			]}`,
			authorized: []string{"gemini-output-object", "gemini-output-array", "gemini-output-status"},
			denied:     []string{"gemini-output-outside-response"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			batch, chunks := round9ExtractToolAssociationParity(t, test.profile, test.body)
			var scope uint64
			paths := make(map[string]struct{})
			for _, target := range test.authorized {
				segment := round8RequireSegment(t, batch.Segments, target)
				if segment.ToolAssociation != ToolResultAssociationUnique ||
					segment.Role != RoleTool || segment.Provenance != ProvenanceContent ||
					segment.ContentKind != ContentKindToolResult || segment.FieldPathHash == "" {
					t.Fatalf("authorized structured leaf %q metadata=%#v", target, segment)
				}
				if scope == 0 {
					scope = segment.ScopeID
				} else if segment.ScopeID != scope {
					t.Fatalf("structured leaves crossed result scope: first=%d %q=%d", scope, target, segment.ScopeID)
				}
				if _, duplicate := paths[segment.FieldPathHash]; duplicate {
					t.Fatalf("structured leaves reused FieldPathHash: %q metadata=%#v", target, segment)
				}
				paths[segment.FieldPathHash] = struct{}{}
				chunk := round8RequireChunk(t, chunks, target)
				round8AssertChunkMatchesSegment(t, chunk, segment)
			}
			for _, target := range test.denied {
				round9AssertNoToolAssociationForText(t, batch.Segments, chunks, target)
			}
		})
	}
}

func TestRound9StructuredToolResultAuthorityFailsClosedAndDoesNotPartiallyCommit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		profile SourceProfile
		body    string
		targets []string
	}{
		{
			name:    "chat duplicate type",
			profile: SourceProfileOpenAI,
			body:    `{"messages":[{"role":"assistant","tool_calls":[{"id":"bad-chat","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"bad-chat","content":[{"type":"text","type":"text","text":"bad-chat-duplicate-type"}]}]}`,
			targets: []string{"bad-chat-duplicate-type"},
		},
		{
			name:    "chat duplicate text",
			profile: SourceProfileOpenAI,
			body:    `{"messages":[{"role":"assistant","tool_calls":[{"id":"bad-chat-text","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"bad-chat-text","content":[{"type":"text","text":"bad-chat-duplicate-text-first","text":"bad-chat-duplicate-text-second"}]}]}`,
			targets: []string{"bad-chat-duplicate-text-first", "bad-chat-duplicate-text-second"},
		},
		{
			name:    "responses alias and unknown field",
			profile: SourceProfileOpenAIResponse,
			body:    `{"input":[{"type":"function_call","call_id":"bad-responses","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"bad-responses","output":[{"Type":"input_text","text":"bad-responses-alias"},{"type":"output_text","text":"bad-responses-unknown","extra":true}]}]}`,
			targets: []string{"bad-responses-alias", "bad-responses-unknown"},
		},
		{
			name:    "claude unknown field",
			profile: SourceProfileClaude,
			body:    `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"bad-claude","name":"lookup","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"bad-claude","content":[{"type":"text","text":"bad-claude-unknown","extra":"collision"}]}]}]}`,
			targets: []string{"bad-claude-unknown"},
		},
		{
			name:    "claude cache control must be an object",
			profile: SourceProfileClaude,
			body:    `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"bad-claude-cache","name":"lookup","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"bad-claude-cache","content":[{"type":"text","text":"bad-claude-cache-value","cache_control":"ephemeral"}]}]}]}`,
			targets: []string{"bad-claude-cache-value"},
		},
		{
			name:    "claude cache control alias is rejected",
			profile: SourceProfileClaude,
			body:    `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"bad-claude-cache-alias","name":"lookup","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"bad-claude-cache-alias","content":[{"type":"text","text":"bad-claude-cache-alias-value","cacheControl":{"type":"ephemeral"}}]}]}]}`,
			targets: []string{"bad-claude-cache-alias-value"},
		},
		{
			name:    "claude duplicate cache control is rejected",
			profile: SourceProfileClaude,
			body:    `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"bad-claude-cache-duplicate","name":"lookup","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"bad-claude-cache-duplicate","content":[{"type":"text","text":"bad-claude-cache-duplicate-value","cache_control":{"type":"ephemeral"},"cache_control":{"type":"ephemeral"}}]}]}]}`,
			targets: []string{"bad-claude-cache-duplicate-value"},
		},
		{
			name:    "responses carrier alias collision",
			profile: SourceProfileOpenAIResponse,
			body:    `{"input":[{"type":"function_call","call_id":"bad-carrier","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"bad-carrier","output":[{"type":"output_text","text":"bad-carrier-exact"}],"out_put":[{"type":"output_text","text":"bad-carrier-alias"}]}]}`,
			targets: []string{"bad-carrier-exact", "bad-carrier-alias"},
		},
		{
			name:    "gemini duplicate result key",
			profile: SourceProfileGemini,
			body:    `{"contents":[{"role":"model","parts":[{"functionCall":{"id":"bad-gemini","name":"lookup","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"id":"bad-gemini","name":"lookup","response":{"result":{"safe":"bad-gemini-first","result":"bad-gemini-second","result":"bad-gemini-duplicate"}}}}]}]}`,
			targets: []string{"bad-gemini-first", "bad-gemini-second", "bad-gemini-duplicate"},
		},
		{
			name:    "gemini response must be an object",
			profile: SourceProfileGemini,
			body:    `{"contents":[{"role":"model","parts":[{"functionCall":{"id":"bad-gemini-response","name":"lookup","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"id":"bad-gemini-response","name":"lookup","response":"bad-gemini-response-value"}}]}]}`,
			targets: []string{"bad-gemini-response-value"},
		},
		{
			name:    "gemini response alias collision is rejected",
			profile: SourceProfileGemini,
			body:    `{"contents":[{"role":"model","parts":[{"functionCall":{"id":"bad-gemini-response-alias","name":"lookup","args":{}}}]},{"role":"user","parts":[{"functionResponse":{"id":"bad-gemini-response-alias","name":"lookup","response":{"result":"bad-gemini-response-exact"},"Response":{"result":"bad-gemini-response-alias"}}}]}]}`,
			targets: []string{"bad-gemini-response-exact", "bad-gemini-response-alias"},
		},
		{
			name:    "chat one invalid leaf atomically denies valid sibling",
			profile: SourceProfileOpenAI,
			body:    `{"messages":[{"role":"assistant","tool_calls":[{"id":"atomic-a","type":"function","function":{"name":"lookup_a","arguments":"{}"}},{"id":"atomic-b","type":"function","function":{"name":"lookup_b","arguments":"{}"}}]},{"role":"tool","tool_call_id":"atomic-a","content":[{"type":"text","text":"atomic-valid"}]},{"role":"tool","tool_call_id":"atomic-b","content":[{"type":"text","text":"atomic-invalid","unknown":true}]}]}`,
			targets: []string{"atomic-valid", "atomic-invalid"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			round9AssertStructuredToolAuthorityAbsent(t, test.profile, test.body, test.targets)
		})
	}
}

func round9AssertStructuredToolAuthorityAbsent(
	t *testing.T,
	profile SourceProfile,
	body string,
	targets []string,
) {
	t.Helper()
	requestProfile := RequestProfile{Source: profile}
	batch, err := ExtractProfiledRequest([]byte(body), round8JSONHeaders(), requestProfile, Limits{})
	if err != nil {
		t.Fatalf("batch extraction error=%v", err)
	}
	sink := &round8RecordingSink{}
	streamed, err := ScanProfiledRequest([]byte(body), round8JSONHeaders(), requestProfile, Limits{}, sink)
	if err != nil {
		t.Fatalf("stream extraction error=%v", err)
	}
	if batch.IsComplete() != streamed.IsComplete() || batch.TextCoverage != streamed.TextCoverage {
		t.Fatalf("batch/stream fail-closed parity mismatch: batch=%#v stream=%#v", batch, streamed)
	}
	for _, target := range targets {
		round9AssertNoToolAssociationForText(t, batch.Segments, sink.chunks, target)
	}
}

func TestRound9StructuredToolResultAuthorityRejectsNonterminalAndMismatchedTransactions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		profile SourceProfile
		body    string
		target  string
	}{
		{
			name:    "chat nonterminal structured result",
			profile: SourceProfileOpenAI,
			body:    `{"messages":[{"role":"assistant","tool_calls":[{"id":"nonterminal-chat","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"nonterminal-chat","content":[{"type":"text","text":"nonterminal-chat-result"}]},{"role":"user","content":"nonterminal-boundary"}]}`,
			target:  "nonterminal-chat-result",
		},
		{
			name:    "responses id mismatch",
			profile: SourceProfileOpenAIResponse,
			body:    `{"input":[{"type":"function_call","call_id":"responses-call","name":"lookup","arguments":"{}"},{"type":"function_call_output","call_id":"responses-other","output":[{"type":"output_text","text":"responses-id-mismatch"}]}]}`,
			target:  "responses-id-mismatch",
		},
		{
			name:    "chat result count mismatch",
			profile: SourceProfileOpenAI,
			body:    `{"messages":[{"role":"assistant","tool_calls":[{"id":"chat-count","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"chat-count","content":[{"type":"text","text":"chat-count-first"}]},{"role":"tool","tool_call_id":"chat-count","content":[{"type":"text","text":"chat-count-second"}]}]}`,
			target:  "chat-count-first",
		},
		{
			name:    "claude wrong owner",
			profile: SourceProfileClaude,
			body:    `{"messages":[{"role":"assistant","content":[{"type":"tool_use","id":"claude-owner","name":"lookup","input":{}}]},{"role":"assistant","content":[{"type":"tool_result","tool_use_id":"claude-owner","content":[{"type":"text","text":"claude-wrong-owner"}]}]}]}`,
			target:  "claude-wrong-owner",
		},
		{
			name:    "gemini orphan",
			profile: SourceProfileGemini,
			body:    `{"contents":[{"role":"user","parts":[{"functionResponse":{"id":"gemini-orphan","name":"lookup","response":{"result":["gemini-orphan-result"]}}}]}]}`,
			target:  "gemini-orphan-result",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			batch, chunks := round9ExtractToolAssociationParity(t, test.profile, test.body)
			round9AssertNoToolAssociationForText(t, batch.Segments, chunks, test.target)
		})
	}
}

func TestRound9StructuredToolResultAuthorityDoesNotCrossTerminalTransactionBoundary(t *testing.T) {
	t.Parallel()
	body := `{"messages":[
		{"role":"assistant","tool_calls":[{"id":"boundary-old","type":"function","function":{"name":"lookup_old","arguments":"{}"}}]},
		{"role":"tool","tool_call_id":"boundary-old","content":[{"type":"text","text":"boundary-old-result"}]},
		{"role":"user","content":"start a new transaction"},
		{"role":"assistant","tool_calls":[{"id":"boundary-new","type":"function","function":{"name":"lookup_new","arguments":"{}"}}]},
		{"role":"tool","tool_call_id":"boundary-new","content":[{"type":"text","text":"boundary-new-result"}]}
	]}`
	batch, chunks := round9ExtractToolAssociationParity(t, SourceProfileOpenAI, body)
	oldResult := round8RequireSegment(t, batch.Segments, "boundary-old-result")
	newResult := round8RequireSegment(t, batch.Segments, "boundary-new-result")
	if oldResult.ToolAssociation != ToolResultAssociationNone ||
		newResult.ToolAssociation != ToolResultAssociationUnique {
		t.Fatalf("terminal transaction authority old=%#v new=%#v", oldResult, newResult)
	}
	if oldResult.ScopeID == newResult.ScopeID || oldResult.FieldPathHash == newResult.FieldPathHash {
		t.Fatalf("separate result transactions shared identity old=%#v new=%#v", oldResult, newResult)
	}
	round8AssertChunkMatchesSegment(t, round8RequireChunk(t, chunks, "boundary-old-result"), oldResult)
	round8AssertChunkMatchesSegment(t, round8RequireChunk(t, chunks, "boundary-new-result"), newResult)
}

func TestRound9StructuredToolResultAuthorityBudgetTruncationFailsClosed(t *testing.T) {
	t.Parallel()
	body := `{"messages":[{"role":"assistant","tool_calls":[{"id":"budget-structured","type":"function","function":{"name":"lookup","arguments":"{}"}}]},{"role":"tool","tool_call_id":"budget-structured","content":[{"type":"text","text":"budget-structured-result"}]}]}`
	tests := []struct {
		name   string
		limits Limits
		reason IncompleteReason
	}{
		{name: "depth", limits: Limits{MaxJSONDepth: 5}, reason: IncompleteJSONDepthLimit},
		{name: "tokens", limits: Limits{MaxJSONTokens: 20}, reason: IncompleteJSONTokenLimit},
		{name: "nodes", limits: Limits{MaxJSONNodes: 10}, reason: IncompleteJSONNodeLimit},
		{name: "spans", limits: Limits{MaxTextParts: 1}, reason: IncompleteTextPartLimit},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			profile := RequestProfile{Source: SourceProfileOpenAI}
			result, err := ExtractProfiledRequest([]byte(body), round8JSONHeaders(), profile, test.limits)
			if err != nil {
				t.Fatalf("ExtractProfiledRequest error=%v", err)
			}
			if result.IsComplete() || !result.HasIncompleteReason(test.reason) {
				t.Fatalf("budget result=%#v", result)
			}
			sink := &round8RecordingSink{}
			streamed, err := ScanProfiledRequest([]byte(body), round8JSONHeaders(), profile, test.limits, sink)
			if err != nil || streamed.IsComplete() || !streamed.HasIncompleteReason(test.reason) || !sink.aborted {
				t.Fatalf("streamed budget result=%#v err=%v aborted=%v", streamed, err, sink.aborted)
			}
			for _, segment := range result.Segments {
				if strings.Contains(segment.Text, "budget-structured-result") && segment.ToolAssociation != ToolResultAssociationNone {
					t.Fatalf("budget-truncated structured result gained authority=%#v", segment)
				}
			}
			for _, chunk := range sink.chunks {
				if strings.Contains(string(chunk.Text), "budget-structured-result") && chunk.ToolAssociation != ToolResultAssociationNone {
					t.Fatalf("stream budget-truncated structured result gained authority=%#v", chunk)
				}
			}
		})
	}
}
