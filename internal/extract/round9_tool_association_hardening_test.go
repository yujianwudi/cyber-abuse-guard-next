package extract

import (
	"strings"
	"testing"
)

type round9ToolAssociationExpectation struct {
	text string
	want ToolResultAssociation
}

func TestRound9ProviderToolAssociationTransactionsAreAdjacentAndComplete(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		profile      SourceProfile
		body         string
		expectations []round9ToolAssociationExpectation
	}{
		{
			name: "openai chat rejects an intervening conversation item", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-gap","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"user","content":"chat-intervening-boundary"},
				{"role":"tool","tool_call_id":"chat-gap","content":"chat-gap-result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"chat-gap-result", ToolResultAssociationNone}},
		},
		{
			name: "openai chat rejects an incomplete parallel result group", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[
					{"id":"chat-a","type":"function","function":{"name":"lookup_a","arguments":"{}"}},
					{"id":"chat-b","type":"function","function":{"name":"lookup_b","arguments":"{}"}}
				]},
				{"role":"tool","tool_call_id":"chat-a","content":"chat-partial-result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"chat-partial-result", ToolResultAssociationNone}},
		},
		{
			name: "openai chat rejects an excessive result group", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-extra","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-extra","content":"chat-extra-first"},
				{"role":"tool","tool_call_id":"chat-extra","content":"chat-extra-second"}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"chat-extra-first", ToolResultAssociationNone},
				{"chat-extra-second", ToolResultAssociationNone},
			},
		},
		{
			name: "openai chat accepts a complete adjacent parallel transaction", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[
					{"id":"chat-a","type":"function","function":{"name":"lookup_a","arguments":"{}"}},
					{"id":"chat-b","type":"function","function":{"name":"lookup_b","arguments":"{}"}}
				]},
				{"role":"tool","tool_call_id":"chat-b","content":"chat-complete-second"},
				{"role":"tool","tool_call_id":"chat-a","content":"chat-complete-first"}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"chat-complete-first", ToolResultAssociationUnique},
				{"chat-complete-second", ToolResultAssociationUnique},
			},
		},
		{
			name: "openai chat scopes reused ids to each adjacent transaction", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-reused","type":"function","function":{"name":"lookup_old","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-reused","content":"chat-reused-old-result"},
				{"role":"user","content":"chat-reused-boundary"},
				{"role":"assistant","tool_calls":[{"id":"chat-reused","type":"function","function":{"name":"lookup_new","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-reused","content":"chat-reused-new-result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"chat-reused-old-result", ToolResultAssociationNone},
				{"chat-reused-new-result", ToolResultAssociationUnique},
			},
		},
		{
			name: "responses rejects an intervening conversation item", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-gap","name":"lookup","arguments":"{}"},
				{"type":"message","role":"user","content":"responses-intervening-boundary"},
				{"type":"function_call_output","call_id":"responses-gap","output":"responses-gap-result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"responses-gap-result", ToolResultAssociationNone}},
		},
		{
			name: "responses rejects an incomplete parallel result group", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-a","name":"lookup_a","arguments":"{}"},
				{"type":"function_call","call_id":"responses-b","name":"lookup_b","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-a","output":"responses-partial-result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"responses-partial-result", ToolResultAssociationNone}},
		},
		{
			name: "responses rejects an excessive result group", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-extra","name":"lookup","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-extra","output":"responses-extra-first"},
				{"type":"function_call_output","call_id":"responses-extra","output":"responses-extra-second"}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"responses-extra-first", ToolResultAssociationNone},
				{"responses-extra-second", ToolResultAssociationNone},
			},
		},
		{
			name: "responses accepts a complete adjacent parallel transaction", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-a","name":"lookup_a","arguments":"{}"},
				{"type":"function_call","call_id":"responses-b","name":"lookup_b","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-b","output":"responses-complete-second"},
				{"type":"function_call_output","call_id":"responses-a","output":"responses-complete-first"}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"responses-complete-first", ToolResultAssociationUnique},
				{"responses-complete-second", ToolResultAssociationUnique},
			},
		},
		{
			name: "responses scopes reused ids to each adjacent transaction", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-reused","name":"lookup_old","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-reused","output":"responses-reused-old-result"},
				{"type":"message","role":"user","content":"responses-reused-boundary"},
				{"type":"function_call","call_id":"responses-reused","name":"lookup_new","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-reused","output":"responses-reused-new-result"}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"responses-reused-old-result", ToolResultAssociationNone},
				{"responses-reused-new-result", ToolResultAssociationUnique},
			},
		},
		{
			name: "claude rejects an intervening conversation item", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-gap","name":"lookup","input":{}}]},
				{"role":"user","content":"claude-intervening-boundary"},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"claude-gap","content":"claude-gap-result"}]}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"claude-gap-result", ToolResultAssociationNone}},
		},
		{
			name: "claude rejects an incomplete parallel result group", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[
					{"type":"tool_use","id":"claude-a","name":"lookup_a","input":{}},
					{"type":"tool_use","id":"claude-b","name":"lookup_b","input":{}}
				]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"claude-a","content":"claude-partial-result"}]}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"claude-partial-result", ToolResultAssociationNone}},
		},
		{
			name: "claude accepts a complete adjacent parallel transaction", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[
					{"type":"tool_use","id":"claude-a","name":"lookup_a","input":{}},
					{"type":"tool_use","id":"claude-b","name":"lookup_b","input":{}}
				]},
				{"role":"user","content":[
					{"type":"tool_result","tool_use_id":"claude-b","content":"claude-complete-second"},
					{"type":"tool_result","tool_use_id":"claude-a","content":"claude-complete-first"}
				]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"claude-complete-first", ToolResultAssociationUnique},
				{"claude-complete-second", ToolResultAssociationUnique},
			},
		},
		{
			name: "claude scopes reused ids to each adjacent transaction", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-reused","name":"lookup_old","input":{}}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"claude-reused","content":"claude-reused-old-result"}]},
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-reused","name":"lookup_new","input":{}}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"claude-reused","content":"claude-reused-new-result"}]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"claude-reused-old-result", ToolResultAssociationNone},
				{"claude-reused-new-result", ToolResultAssociationUnique},
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

func TestRound9ResponsesToolAssociationRequiresExactSubtype(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		body         string
		expectations []round9ToolAssociationExpectation
	}{
		{
			name: "function call cannot authorize custom output",
			body: `{"input":[
				{"type":"function_call","call_id":"responses-cross","name":"lookup","arguments":"{}"},
				{"type":"custom_tool_call_output","call_id":"responses-cross","output":"responses-function-to-custom"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"responses-function-to-custom", ToolResultAssociationNone}},
		},
		{
			name: "custom call cannot authorize function output",
			body: `{"input":[
				{"type":"custom_tool_call","call_id":"responses-cross","name":"lookup","input":"{}"},
				{"type":"function_call_output","call_id":"responses-cross","output":"responses-custom-to-function"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"responses-custom-to-function", ToolResultAssociationNone}},
		},
		{
			name: "custom call authorizes only custom output",
			body: `{"input":[
				{"type":"custom_tool_call","call_id":"responses-custom","name":"lookup","input":"{}"},
				{"type":"custom_tool_call_output","call_id":"responses-custom","output":"responses-custom-valid"}
			]}`,
			expectations: []round9ToolAssociationExpectation{{"responses-custom-valid", ToolResultAssociationUnique}},
		},
		{
			name: "mixed parallel subtypes require exact per id pairing",
			body: `{"input":[
				{"type":"function_call","call_id":"responses-function","name":"lookup_function","arguments":"{}"},
				{"type":"custom_tool_call","call_id":"responses-custom","name":"lookup_custom","input":"{}"},
				{"type":"custom_tool_call_output","call_id":"responses-custom","output":"responses-mixed-custom"},
				{"type":"function_call_output","call_id":"responses-function","output":"responses-mixed-function"}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"responses-mixed-function", ToolResultAssociationUnique},
				{"responses-mixed-custom", ToolResultAssociationUnique},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			round9AssertToolAssociationParity(
				t, SourceProfileOpenAIResponse, test.body, test.expectations,
			)
		})
	}
}

func TestRound9GeminiExplicitToolAssociationRequiresMatchingNames(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		body   string
		target string
		want   ToolResultAssociation
	}{
		{
			name: "missing call name",
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-name","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-name","name":"lookup","response":{"result":"gemini-missing-call-name"}}}]}
			]}`,
			target: "gemini-missing-call-name",
		},
		{
			name: "missing result name",
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-name","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-name","response":{"result":"gemini-missing-result-name"}}}]}
			]}`,
			target: "gemini-missing-result-name",
		},
		{
			name: "mismatched names",
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-name","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-name","name":"other","response":{"result":"gemini-mismatched-explicit-name"}}}]}
			]}`,
			target: "gemini-mismatched-explicit-name",
		},
		{
			name: "matching nonempty names",
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-name","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-name","name":"lookup","response":{"result":"gemini-matching-explicit-name"}}}]}
			]}`,
			target: "gemini-matching-explicit-name",
			want:   ToolResultAssociationUnique,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			round9AssertToolAssociationParity(
				t,
				SourceProfileGemini,
				test.body,
				[]round9ToolAssociationExpectation{{test.target, test.want}},
			)
		})
	}
}

func TestRound9OpenAIChatToolAssociationRequiresCanonicalFunctionShape(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		call string
		want ToolResultAssociation
	}{
		{name: "id only", call: `{"id":"chat-shape"}`},
		{name: "missing type", call: `{"id":"chat-shape","function":{"name":"lookup","arguments":"{}"}}`},
		{name: "wrong type", call: `{"id":"chat-shape","type":"custom","function":{"name":"lookup","arguments":"{}"}}`},
		{name: "missing function", call: `{"id":"chat-shape","type":"function"}`},
		{name: "missing function name", call: `{"id":"chat-shape","type":"function","function":{"arguments":"{}"}}`},
		{name: "missing function arguments", call: `{"id":"chat-shape","type":"function","function":{"name":"lookup"}}`},
		{
			name: "canonical function call",
			call: `{"id":"chat-shape","type":"function","function":{"name":"lookup","arguments":"{}"}}`,
			want: ToolResultAssociationUnique,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			body := `{"messages":[
				{"role":"assistant","tool_calls":[` + test.call + `]},
				{"role":"tool","tool_call_id":"chat-shape","content":"chat-shape-result"}
			]}`
			round9AssertToolAssociationParity(
				t,
				SourceProfileOpenAI,
				body,
				[]round9ToolAssociationExpectation{{"chat-shape-result", test.want}},
			)
		})
	}

	t.Run("legacy function call id cannot authorize a tool result", func(t *testing.T) {
		t.Parallel()
		body := `{"messages":[
			{"role":"assistant","function_call":{"id":"chat-legacy","name":"lookup","arguments":"{}"}},
			{"role":"tool","tool_call_id":"chat-legacy","content":"chat-legacy-result"}
		]}`
		round9AssertToolAssociationParity(
			t,
			SourceProfileOpenAI,
			body,
			[]round9ToolAssociationExpectation{{"chat-legacy-result", ToolResultAssociationNone}},
		)
	})
}

func TestRound9ToolAssociationDuplicateKeysFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		profile SourceProfile
		body    string
		target  string
	}{
		{
			name: "openai chat duplicate tool calls container", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant",
				 "tool_calls":[{"id":"chat-duplicate-container","type":"function","function":{"name":"lookup","arguments":"{}"}}],
				 "tool_calls":[]},
				{"role":"tool","tool_call_id":"chat-duplicate-container","content":"chat-duplicate-container-result"}
			]}`,
			target: "chat-duplicate-container-result",
		},
		{
			name: "openai chat duplicate function container", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{
					"id":"chat-duplicate-function","type":"function",
					"function":{"name":"lookup","arguments":"{}"},"function":{}
				}]},
				{"role":"tool","tool_call_id":"chat-duplicate-function","content":"chat-duplicate-function-result"}
			]}`,
			target: "chat-duplicate-function-result",
		},
		{
			name: "openai chat duplicate function name", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{
					"id":"chat-duplicate-name","type":"function",
					"function":{"name":"lookup","name":"","arguments":"{}"}
				}]},
				{"role":"tool","tool_call_id":"chat-duplicate-name","content":"chat-duplicate-name-result"}
			]}`,
			target: "chat-duplicate-name-result",
		},
		{
			name: "openai chat duplicate function arguments", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{
					"id":"chat-duplicate-arguments","type":"function",
					"function":{"name":"lookup","arguments":"{}","arguments":""}
				}]},
				{"role":"tool","tool_call_id":"chat-duplicate-arguments","content":"chat-duplicate-arguments-result"}
			]}`,
			target: "chat-duplicate-arguments-result",
		},
		{
			name: "responses duplicate output carrier", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-duplicate-output","name":"lookup","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-duplicate-output",
				 "output":"responses-duplicate-output-result","output":""}
			]}`,
			target: "responses-duplicate-output-result",
		},
		{
			name: "gemini duplicate response carrier", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-duplicate-response","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{
					"id":"gemini-duplicate-response","name":"lookup",
					"response":{"result":"gemini-duplicate-response-result"},"response":{}
				}}]}
			]}`,
			target: "gemini-duplicate-response-result",
		},
		{
			name: "gemini duplicate result carrier", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-duplicate-result","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{
					"id":"gemini-duplicate-result","name":"lookup",
					"response":{"result":"gemini-duplicate-result-result","result":""}
				}}]}
			]}`,
			target: "gemini-duplicate-result-result",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			round9AssertToolAssociationParity(
				t,
				test.profile,
				test.body,
				[]round9ToolAssociationExpectation{{test.target, ToolResultAssociationNone}},
			)
		})
	}
}

func TestRound9GeminiDuplicateWrappersFailClosed(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		body         string
		expectations []round9ToolAssociationExpectation
	}{
		{
			name: "different duplicate call and response wrappers",
			body: `{"contents":[
				{"role":"model","parts":[{
					"functionCall":{"id":"x","name":"alpha","args":{}},
					"functionCall":{"id":"y","name":"beta","args":{}}
				}]},
				{"role":"user","parts":[{
					"functionResponse":{"id":"x","name":"alpha","response":{"result":"probe-shadowed"}},
					"functionResponse":{"id":"y","name":"beta","response":{"result":"probe-visible"}}
				}]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"probe-shadowed", ToolResultAssociationNone},
				{"probe-visible", ToolResultAssociationNone},
			},
		},
		{
			name: "duplicate response wrappers only",
			body: `{"contents":[
				{"role":"model","parts":[
					{"functionCall":{"id":"response-x","name":"alpha","args":{}}},
					{"functionCall":{"id":"response-y","name":"beta","args":{}}}
				]},
				{"role":"user","parts":[{
					"functionResponse":{"id":"response-x","name":"alpha","response":{"result":"duplicate-response-first"}},
					"functionResponse":{"id":"response-y","name":"beta","response":{"result":"duplicate-response-second"}}
				}]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"duplicate-response-first", ToolResultAssociationNone},
				{"duplicate-response-second", ToolResultAssociationNone},
			},
		},
		{
			name: "duplicate call wrappers only",
			body: `{"contents":[
				{"role":"model","parts":[{
					"functionCall":{"id":"call-x","name":"alpha","args":{}},
					"functionCall":{"id":"call-y","name":"beta","args":{}}
				}]},
				{"role":"user","parts":[
					{"functionResponse":{"id":"call-x","name":"alpha","response":{"result":"duplicate-call-first"}}},
					{"functionResponse":{"id":"call-y","name":"beta","response":{"result":"duplicate-call-second"}}}
				]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"duplicate-call-first", ToolResultAssociationNone},
				{"duplicate-call-second", ToolResultAssociationNone},
			},
		},
		{
			name: "same name duplicate wrappers",
			body: `{"contents":[
				{"role":"model","parts":[{
					"functionCall":{"name":"lookup","args":{}},
					"functionCall":{"name":"lookup","args":{}}
				}]},
				{"role":"user","parts":[{
					"functionResponse":{"name":"lookup","response":{"result":"same-name-first"}},
					"functionResponse":{"name":"lookup","response":{"result":"same-name-second"}}
				}]}
			]}`,
			expectations: []round9ToolAssociationExpectation{
				{"same-name-first", ToolResultAssociationNone},
				{"same-name-second", ToolResultAssociationNone},
			},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			round9AssertToolAssociationParity(t, SourceProfileGemini, test.body, test.expectations)
		})
	}
}

func TestRound9GeminiWrapperMultiplicityIsScopedPerPart(t *testing.T) {
	t.Parallel()
	body := `{"contents":[
		{"role":"model","parts":[
			{"functionCall":{"id":"separate-x","name":"alpha","args":{}}},
			{"functionCall":{"id":"separate-y","name":"beta","args":{}}}
		]},
		{"role":"user","parts":[
			{"functionResponse":{"id":"separate-x","name":"alpha","response":{"result":"separate-first"}}},
			{"functionResponse":{"id":"separate-y","name":"beta","response":{"result":"separate-second"}}}
		]}
	]}`
	round9AssertToolAssociationParity(
		t,
		SourceProfileGemini,
		body,
		[]round9ToolAssociationExpectation{
			{"separate-first", ToolResultAssociationUnique},
			{"separate-second", ToolResultAssociationUnique},
		},
	)
}

func TestRound9ToolAssociationAuthorityUsesExactProviderTextPath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		profile     SourceProfile
		body        string
		authorized  string
		denied      []string
		mayBeOpaque []string
	}{
		{
			name: "openai chat content only", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"assistant","tool_calls":[{"id":"chat-path","type":"function","function":{"name":"lookup","arguments":"{}"}}]},
				{"role":"tool","tool_call_id":"chat-path","content":"chat-path-content","attacker":"chat-path-attacker","note":"chat-path-note","metadata":{"detail":"chat-path-metadata"}}
			]}`,
			authorized:  "chat-path-content",
			denied:      []string{"chat-path-attacker", "chat-path-note"},
			mayBeOpaque: []string{"chat-path-metadata"},
		},
		{
			name: "responses output only", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"function_call","call_id":"responses-path","name":"lookup","arguments":"{}"},
				{"type":"function_call_output","call_id":"responses-path","output":"responses-path-output","attacker":"responses-path-attacker","note":"responses-path-note","metadata":{"detail":"responses-path-metadata"}}
			]}`,
			authorized:  "responses-path-output",
			denied:      []string{"responses-path-attacker", "responses-path-note"},
			mayBeOpaque: []string{"responses-path-metadata"},
		},
		{
			name: "claude content only", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"claude-path","name":"lookup","input":{}}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"claude-path","content":"claude-path-content","attacker":"claude-path-attacker","note":"claude-path-note","metadata":{"detail":"claude-path-metadata"}}]}
			]}`,
			authorized:  "claude-path-content",
			denied:      []string{"claude-path-attacker", "claude-path-note"},
			mayBeOpaque: []string{"claude-path-metadata"},
		},
		{
			name: "gemini response object boundary", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"model","parts":[{"functionCall":{"id":"gemini-path","name":"lookup","args":{}}}]},
				{"role":"user","parts":[{"functionResponse":{"id":"gemini-path","name":"lookup","response":{"result":"gemini-path-result"},"attacker":"gemini-path-attacker","note":"gemini-path-note","metadata":{"detail":"gemini-path-metadata"}}}]}
			]}`,
			authorized:  "gemini-path-result",
			denied:      []string{"gemini-path-attacker", "gemini-path-note"},
			mayBeOpaque: []string{"gemini-path-metadata"},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			batch, chunks := round9ExtractToolAssociationParity(t, test.profile, test.body)
			authorized := round8RequireSegment(t, batch.Segments, test.authorized)
			if authorized.ToolAssociation != ToolResultAssociationUnique ||
				authorized.Role != RoleTool || authorized.ContentKind != ContentKindToolResult {
				t.Fatalf("authorized provider result metadata=%#v", authorized)
			}
			authorizedChunk := round8RequireChunk(t, chunks, test.authorized)
			round8AssertChunkMatchesSegment(t, authorizedChunk, authorized)

			for _, target := range test.denied {
				denied := round8RequireSegment(t, batch.Segments, target)
				if denied.ToolAssociation != ToolResultAssociationNone {
					t.Fatalf("unknown sibling %q gained batch authority: %#v", target, denied)
				}
				deniedChunk := round8RequireChunk(t, chunks, target)
				round8AssertChunkMatchesSegment(t, deniedChunk, denied)
			}
			for _, target := range test.mayBeOpaque {
				round9AssertNoToolAssociationForText(t, batch.Segments, chunks, target)
			}
		})
	}
}

func round9AssertToolAssociationParity(
	t *testing.T,
	profile SourceProfile,
	body string,
	expectations []round9ToolAssociationExpectation,
) {
	t.Helper()
	batch, chunks := round9ExtractToolAssociationParity(t, profile, body)
	for _, expectation := range expectations {
		segment := round8RequireSegment(t, batch.Segments, expectation.text)
		if segment.ToolAssociation != expectation.want {
			t.Fatalf(
				"batch association for %q=%d want=%d metadata=%#v",
				expectation.text, segment.ToolAssociation, expectation.want, segment,
			)
		}
		chunk := round8RequireChunk(t, chunks, expectation.text)
		round8AssertChunkMatchesSegment(t, chunk, segment)
	}
}

func round9ExtractToolAssociationParity(
	t *testing.T,
	profile SourceProfile,
	body string,
) (Result, []SegmentChunk) {
	t.Helper()
	requestProfile := RequestProfile{Source: profile}
	batch, err := ExtractProfiledRequest([]byte(body), round8JSONHeaders(), requestProfile, Limits{})
	if err != nil || !batch.IsComplete() || !batch.RoleAware {
		t.Fatalf("batch result=%#v err=%v", batch, err)
	}
	sink := &round8RecordingSink{}
	streamed, err := ScanProfiledRequest(
		[]byte(body), round8JSONHeaders(), requestProfile, Limits{}, sink,
	)
	if err != nil || !streamed.IsComplete() || !streamed.RoleAware || sink.aborted {
		t.Fatalf("stream result=%#v err=%v aborted=%v", streamed, err, sink.aborted)
	}
	return batch, sink.chunks
}

func round9AssertNoToolAssociationForText(
	t *testing.T,
	segments []Segment,
	chunks []SegmentChunk,
	target string,
) {
	t.Helper()
	for _, segment := range segments {
		if strings.Contains(segment.Text, target) && segment.ToolAssociation != ToolResultAssociationNone {
			t.Fatalf("text %q gained batch authority: %#v", target, segment)
		}
	}
	for _, chunk := range chunks {
		if strings.Contains(string(chunk.Text), target) && chunk.ToolAssociation != ToolResultAssociationNone {
			t.Fatalf("text %q gained stream authority: %#v", target, chunk)
		}
	}
}
