package extract

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
)

type round8RecordingSink struct {
	chunks  []SegmentChunk
	aborted bool
}

func (sink *round8RecordingSink) AddSegment(chunk SegmentChunk) error {
	copyChunk := chunk
	copyChunk.Text = append([]byte(nil), chunk.Text...)
	sink.chunks = append(sink.chunks, copyChunk)
	return nil
}

func (sink *round8RecordingSink) Abort() { sink.aborted = true }

func TestRound8ContentKindNamesAreClosed(t *testing.T) {
	t.Parallel()

	want := map[ContentKind]string{
		ContentKindUnknown:                  "unknown",
		ContentKindNaturalLanguageDirective: "natural_language_directive",
		ContentKindQuotedText:               "quoted_text",
		ContentKindCodeBlock:                "code_block",
		ContentKindLogOutput:                "log_output",
		ContentKindToolSchema:               "tool_schema",
		ContentKindToolCallArguments:        "tool_call_arguments",
		ContentKindToolResult:               "tool_result",
		ContentKindConfiguration:            "configuration",
		ContentKindDocumentation:            "documentation",
		ContentKindSecurityAnalysis:         "security_analysis",
	}
	for kind, name := range want {
		if got := kind.String(); got != name {
			t.Fatalf("ContentKind(%d).String()=%q want %q", kind, got, name)
		}
	}
	if got := ContentKind(255).String(); got != "unknown" {
		t.Fatalf("out-of-range ContentKind.String()=%q", got)
	}
}

func TestRound8ProtocolTurnScopeAndSchemaMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		profile         SourceProfile
		body            string
		oldUser         string
		assistant       string
		currentA        string
		currentB        string
		schema          string
		schemaNested    string
		oldConversation int
		assistantIndex  int
		currentIndex    int
	}{
		{
			name: "openai chat", profile: SourceProfileOpenAI,
			body: `{
				"tools":[{"type":"function","function":{"name":"scan","description":"schema-openai","parameters":{"type":"object","properties":{"arguments":{"type":"string","description":"schema-nested-openai"}}}}}],
				"messages":[
					{"role":"system","content":"system-openai"},
					{"role":"user","content":"old-user-openai"},
					{"role":"assistant","content":"assistant-openai"},
					{"role":"user","content":[{"type":"text","text":"current-a-openai"},{"type":"text","text":"current-b-openai"}]}
				]}`,
			oldUser: "old-user-openai", assistant: "assistant-openai",
			currentA: "current-a-openai", currentB: "current-b-openai",
			schema: "schema-openai", schemaNested: "schema-nested-openai",
			oldConversation: 1, assistantIndex: 2, currentIndex: 3,
		},
		{
			name: "openai responses", profile: SourceProfileOpenAIResponse,
			body: `{
				"instructions":"system-responses",
				"tools":[{"type":"function","name":"scan","description":"schema-responses","parameters":{"type":"object","properties":{"arguments":{"type":"string","description":"schema-nested-responses"}}}}],
				"input":[
					{"type":"message","role":"developer","content":"developer-responses"},
					{"type":"message","role":"user","content":"old-user-responses"},
					{"type":"message","role":"assistant","content":"assistant-responses"},
					{"type":"message","role":"user","content":[{"type":"input_text","text":"current-a-responses"},{"type":"input_text","text":"current-b-responses"}]}
				]}`,
			oldUser: "old-user-responses", assistant: "assistant-responses",
			currentA: "current-a-responses", currentB: "current-b-responses",
			schema: "schema-responses", schemaNested: "schema-nested-responses",
			oldConversation: 1, assistantIndex: 2, currentIndex: 3,
		},
		{
			name: "anthropic messages", profile: SourceProfileClaude,
			body: `{
				"system":"system-claude",
				"tools":[{"name":"scan","description":"schema-claude","input_schema":{"type":"object","properties":{"arguments":{"type":"string","description":"schema-nested-claude"}}}}],
				"messages":[
					{"role":"user","content":"old-user-claude"},
					{"role":"assistant","content":"assistant-claude"},
					{"role":"user","content":[{"type":"text","text":"current-a-claude"},{"type":"text","text":"current-b-claude"}]}
				]}`,
			oldUser: "old-user-claude", assistant: "assistant-claude",
			currentA: "current-a-claude", currentB: "current-b-claude",
			schema: "schema-claude", schemaNested: "schema-nested-claude",
			oldConversation: 0, assistantIndex: 1, currentIndex: 2,
		},
		{
			name: "gemini generate content", profile: SourceProfileGemini,
			body: `{
				"systemInstruction":{"parts":[{"text":"system-gemini"}]},
				"tools":[{"functionDeclarations":[{"name":"scan","description":"schema-gemini","parameters":{"type":"OBJECT","properties":{"arguments":{"type":"STRING","description":"schema-nested-gemini"}}}}]}],
				"contents":[
					{"role":"user","parts":[{"text":"old-user-gemini"}]},
					{"role":"model","parts":[{"text":"assistant-gemini"}]},
					{"role":"user","parts":[{"text":"current-a-gemini"},{"text":"current-b-gemini"}]}
				]}`,
			oldUser: "old-user-gemini", assistant: "assistant-gemini",
			currentA: "current-a-gemini", currentB: "current-b-gemini",
			schema: "schema-gemini", schemaNested: "schema-nested-gemini",
			oldConversation: 0, assistantIndex: 1, currentIndex: 2,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			body := []byte(test.body)
			profile := RequestProfile{Source: test.profile}
			result, err := ExtractProfiledRequest(body, round8JSONHeaders(), profile, Limits{})
			if err != nil || !result.IsComplete() || !result.RoleAware {
				t.Fatalf("result=%#v err=%v", result, err)
			}

			oldUser := round8RequireSegment(t, result.Segments, test.oldUser)
			assistant := round8RequireSegment(t, result.Segments, test.assistant)
			currentA := round8RequireSegment(t, result.Segments, test.currentA)
			currentB := round8RequireSegment(t, result.Segments, test.currentB)
			schema := round8RequireSegment(t, result.Segments, test.schema)
			schemaNested := round8RequireSegment(t, result.Segments, test.schemaNested)

			round8AssertConversationMetadata(t, oldUser, test.oldConversation, 0, false)
			round8AssertConversationMetadata(t, assistant, test.assistantIndex, 0, false)
			round8AssertConversationMetadata(t, currentA, test.currentIndex, 1, true)
			round8AssertConversationMetadata(t, currentB, test.currentIndex, 1, true)
			for name, segment := range map[string]Segment{
				"old user": oldUser, "assistant": assistant, "current a": currentA, "current b": currentB,
			} {
				if segment.ContentKind != ContentKindNaturalLanguageDirective {
					t.Fatalf("%s ContentKind=%s", name, segment.ContentKind)
				}
			}
			if oldUser.ScopeID == 0 || currentA.ScopeID == 0 || oldUser.ScopeID == currentA.ScopeID {
				t.Fatalf("message scopes old=%d current=%d", oldUser.ScopeID, currentA.ScopeID)
			}
			if currentA.ScopeID != currentB.ScopeID {
				t.Fatalf("multipart message blocks crossed scope: %d != %d", currentA.ScopeID, currentB.ScopeID)
			}
			if currentA.FieldPathHash == currentB.FieldPathHash {
				t.Fatalf("distinct content fields share FieldPathHash=%q", currentA.FieldPathHash)
			}
			for name, segment := range map[string]Segment{"schema": schema, "nested schema": schemaNested} {
				if segment.ContentKind != ContentKindToolSchema || segment.ConversationIndex != -1 ||
					segment.TurnIndex != -1 || segment.IsCurrentTurn || segment.ScopeID == 0 ||
					segment.FieldPathHash == "" {
					t.Fatalf("%s metadata=%#v", name, segment)
				}
			}
			if schema.ScopeID != schemaNested.ScopeID {
				t.Fatalf("one tool declaration split scopes: %d != %d", schema.ScopeID, schemaNested.ScopeID)
			}

			sink := &round8RecordingSink{}
			scanResult, err := ScanProfiledRequest(body, round8JSONHeaders(), profile, Limits{}, sink)
			if err != nil || !scanResult.IsComplete() || sink.aborted {
				t.Fatalf("stream result=%#v err=%v aborted=%v", scanResult, err, sink.aborted)
			}
			chunk := round8RequireChunk(t, sink.chunks, test.currentA)
			round8AssertChunkMatchesSegment(t, chunk, currentA)
			schemaChunk := round8RequireChunk(t, sink.chunks, test.schemaNested)
			round8AssertChunkMatchesSegment(t, schemaChunk, schemaNested)
		})
	}
}

func TestRound8ToolCallAndResultContentKindMatrix(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		profile SourceProfile
		body    string
		args    string
		result  string
		current string
	}{
		{
			name: "openai chat", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"user","content":"seed-openai"},
				{"role":"assistant","tool_calls":[{"id":"call_1","type":"function","function":{"name":"scan","arguments":"{\"command\":\"args-openai\"}"}}]},
				{"role":"tool","tool_call_id":"call_1","content":"result-openai"},
				{"role":"user","content":"current-openai"}
			]}`,
			args: "args-openai", result: "result-openai", current: "current-openai",
		},
		{
			name: "openai responses", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"message","role":"user","content":"seed-responses"},
				{"type":"function_call","call_id":"call_1","name":"scan","arguments":"{\"command\":\"args-responses\"}"},
				{"type":"function_call_output","call_id":"call_1","output":"result-responses"},
				{"type":"message","role":"user","content":"current-responses"}
			]}`,
			args: "args-responses", result: "result-responses", current: "current-responses",
		},
		{
			name: "anthropic messages", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"user","content":"seed-claude"},
				{"role":"assistant","content":[{"type":"tool_use","id":"call_1","name":"scan","input":{"command":"args-claude"}}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"call_1","content":"result-claude"}]},
				{"role":"user","content":"current-claude"}
			]}`,
			args: "args-claude", result: "result-claude", current: "current-claude",
		},
		{
			name: "gemini generate content", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"user","parts":[{"text":"seed-gemini"}]},
				{"role":"model","parts":[{"functionCall":{"name":"scan","args":{"command":"args-gemini"}}}]},
				{"role":"user","parts":[{"functionResponse":{"name":"scan","response":{"result":"result-gemini"}}}]},
				{"role":"user","parts":[{"text":"current-gemini"}]}
			]}`,
			args: "args-gemini", result: "result-gemini", current: "current-gemini",
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			result, err := ExtractProfiledRequest(
				[]byte(test.body), round8JSONHeaders(), RequestProfile{Source: test.profile}, Limits{},
			)
			if err != nil || !result.IsComplete() || !result.RoleAware {
				t.Fatalf("result=%#v err=%v", result, err)
			}
			args := round8RequireSegment(t, result.Segments, test.args)
			toolResult := round8RequireSegment(t, result.Segments, test.result)
			current := round8RequireSegment(t, result.Segments, test.current)
			if args.ContentKind != ContentKindToolCallArguments || args.Provenance != ProvenanceToolPayload ||
				args.UserAttribution != UserAttributionUntrusted || args.IsCurrentTurn {
				t.Fatalf("tool args metadata=%#v", args)
			}
			if toolResult.ContentKind != ContentKindToolResult || toolResult.Role != RoleTool ||
				toolResult.UserAttribution != UserAttributionUntrusted || toolResult.IsCurrentTurn {
				t.Fatalf("tool result metadata=%#v", toolResult)
			}
			if current.ContentKind != ContentKindNaturalLanguageDirective || current.Role != RoleUser ||
				current.UserAttribution != UserAttributionTrusted || !current.IsCurrentTurn {
				t.Fatalf("current user metadata=%#v", current)
			}
			if args.ScopeID == 0 || toolResult.ScopeID == 0 || current.ScopeID == 0 ||
				args.ScopeID == toolResult.ScopeID || args.ScopeID == current.ScopeID ||
				toolResult.ScopeID == current.ScopeID {
				t.Fatalf("tool/current scopes args=%d result=%d current=%d", args.ScopeID, toolResult.ScopeID, current.ScopeID)
			}
			if args.FieldPathHash == "" || toolResult.FieldPathHash == "" || current.FieldPathHash == "" {
				t.Fatalf("empty field hash args=%#v result=%#v current=%#v", args, toolResult, current)
			}
		})
	}
}

func TestRound8IndependentToolCallsHaveIsolatedScopes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		profile SourceProfile
		body    string
	}{
		{
			name: "openai chat", profile: SourceProfileOpenAI,
			body: `{"messages":[
				{"role":"user","content":"tool-scope-seed-openai"},
				{"role":"assistant","tool_calls":[
					{"id":"call_a","type":"function","function":{"name":"scan","arguments":"call-a-left","parameters":"call-a-right"}},
					{"id":"call_b","type":"function","function":{"name":"scan","arguments":"call-b-left","parameters":"call-b-right"}}
				]}
			]}`,
		},
		{
			name: "openai responses", profile: SourceProfileOpenAIResponse,
			body: `{"input":[
				{"type":"message","role":"user","content":"tool-scope-seed-responses"},
				{"type":"function_call","call_id":"call_a","name":"scan","arguments":{"left":"call-a-left","right":"call-a-right"}},
				{"type":"function_call","call_id":"call_b","name":"scan","arguments":{"left":"call-b-left","right":"call-b-right"}}
			]}`,
		},
		{
			name: "anthropic messages", profile: SourceProfileClaude,
			body: `{"messages":[
				{"role":"user","content":"tool-scope-seed-claude"},
				{"role":"assistant","content":[
					{"type":"tool_use","id":"call_a","name":"scan","input":{"left":"call-a-left","right":"call-a-right"}},
					{"type":"tool_use","id":"call_b","name":"scan","input":{"left":"call-b-left","right":"call-b-right"}}
				]}
			]}`,
		},
		{
			name: "gemini generate content", profile: SourceProfileGemini,
			body: `{"contents":[
				{"role":"user","parts":[{"text":"tool-scope-seed-gemini"}]},
				{"role":"model","parts":[
					{"functionCall":{"name":"scan","args":{"left":"call-a-left","right":"call-a-right"}}},
					{"functionCall":{"name":"scan","args":{"left":"call-b-left","right":"call-b-right"}}}
				]}
			]}`,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			body := []byte(test.body)
			profile := RequestProfile{Source: test.profile}
			result, err := ExtractProfiledRequest(body, round8JSONHeaders(), profile, Limits{})
			if err != nil || !result.IsComplete() || !result.RoleAware {
				t.Fatalf("result=%#v err=%v", result, err)
			}

			callALeft := round8RequireSegment(t, result.Segments, "call-a-left")
			callARight := round8RequireSegment(t, result.Segments, "call-a-right")
			callBLeft := round8RequireSegment(t, result.Segments, "call-b-left")
			callBRight := round8RequireSegment(t, result.Segments, "call-b-right")
			for name, segment := range map[string]Segment{
				"call a left": callALeft, "call a right": callARight,
				"call b left": callBLeft, "call b right": callBRight,
			} {
				if segment.ContentKind != ContentKindToolCallArguments ||
					segment.Provenance != ProvenanceToolPayload || segment.ScopeID == 0 ||
					segment.FieldPathHash == "" {
					t.Fatalf("%s metadata=%#v", name, segment)
				}
			}
			if callALeft.ScopeID != callARight.ScopeID {
				t.Fatalf("one call split scopes: left=%d right=%d", callALeft.ScopeID, callARight.ScopeID)
			}
			if callBLeft.ScopeID != callBRight.ScopeID {
				t.Fatalf("one call split scopes: left=%d right=%d", callBLeft.ScopeID, callBRight.ScopeID)
			}
			if callALeft.ScopeID == callBLeft.ScopeID {
				t.Fatalf("independent calls share scope=%d", callALeft.ScopeID)
			}

			sink := &round8RecordingSink{}
			scanResult, err := ScanProfiledRequest(body, round8JSONHeaders(), profile, Limits{}, sink)
			if err != nil || !scanResult.IsComplete() || sink.aborted {
				t.Fatalf("stream result=%#v err=%v aborted=%v", scanResult, err, sink.aborted)
			}
			for target, segment := range map[string]Segment{
				"call-a-left": callALeft, "call-a-right": callARight,
				"call-b-left": callBLeft, "call-b-right": callBRight,
			} {
				round8AssertChunkMatchesSegment(t, round8RequireChunk(t, sink.chunks, target), segment)
			}
		})
	}
}

func TestRound8MultipartTextFieldsHaveIndependentScopes(t *testing.T) {
	t.Parallel()

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for name, value := range map[string]string{
		"prompt":          "multipart-current-prompt",
		"negative_prompt": "multipart-current-negative",
	} {
		part, err := writer.CreateFormField(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(value)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	header := http.Header{"Content-Type": []string{writer.FormDataContentType()}}
	result, err := ExtractProfiledRequest(
		body.Bytes(), header, RequestProfile{Source: SourceProfileOpenAIImage}, Limits{},
	)
	if err != nil || !result.IsComplete() {
		t.Fatalf("result=%#v err=%v", result, err)
	}
	prompt := round8RequireSegment(t, result.Segments, "multipart-current-prompt")
	negative := round8RequireSegment(t, result.Segments, "multipart-current-negative")
	for name, segment := range map[string]Segment{"prompt": prompt, "negative": negative} {
		if segment.ContentKind != ContentKindNaturalLanguageDirective || !segment.IsCurrentTurn ||
			segment.TurnIndex != 0 || segment.ScopeID == 0 || segment.FieldPathHash == "" {
			t.Fatalf("%s metadata=%#v", name, segment)
		}
	}
	if prompt.ScopeID == negative.ScopeID || prompt.FieldPathHash == negative.FieldPathHash {
		t.Fatalf("multipart fields were not isolated: prompt=%#v negative=%#v", prompt, negative)
	}
}

func TestRound8ExactProtocolTextPartCounts(t *testing.T) {
	t.Parallel()

	profiles := []struct {
		name    string
		profile SourceProfile
	}{
		{name: "openai chat", profile: SourceProfileOpenAI},
		{name: "openai responses", profile: SourceProfileOpenAIResponse},
		{name: "anthropic messages", profile: SourceProfileClaude},
		{name: "gemini generate content", profile: SourceProfileGemini},
	}
	for _, profile := range profiles {
		profile := profile
		for _, count := range []int{1, 2, 70, 512} {
			count := count
			t.Run(fmt.Sprintf("%s/%d-parts", profile.name, count), func(t *testing.T) {
				t.Parallel()
				body := round8ProtocolPartsBody(t, profile.profile, count)
				requestProfile := RequestProfile{Source: profile.profile}
				result, err := ExtractProfiledRequest(body, round8JSONHeaders(), requestProfile, Limits{})
				if err != nil || !result.IsComplete() || !result.RoleAware {
					t.Fatalf("batch result=%#v err=%v", result, err)
				}
				round8AssertExactPartMetadata(t, result, count)

				sink := &round8RecordingSink{}
				streamed, err := ScanProfiledRequest(body, round8JSONHeaders(), requestProfile, Limits{}, sink)
				if err != nil || !streamed.IsComplete() || !streamed.RoleAware || sink.aborted {
					t.Fatalf("stream result=%#v err=%v aborted=%v", streamed, err, sink.aborted)
				}
				if streamed.LogicalTextParts != count || len(sink.chunks) != count {
					t.Fatalf("stream parts/chunks=%d/%d, want %d/%d", streamed.LogicalTextParts, len(sink.chunks), count, count)
				}
				for index, chunk := range sink.chunks {
					if !chunk.Start || !chunk.End || chunk.Role != RoleUser ||
						chunk.UserAttribution != UserAttributionTrusted || !chunk.IsCurrentTurn ||
						chunk.ContentKind != ContentKindNaturalLanguageDirective {
						t.Fatalf("chunk %d metadata=%#v", index, chunk)
					}
				}
			})
		}
	}
}

func TestRound8Exact16KiBAnd300KiBStreamingTextPlacement(t *testing.T) {
	t.Parallel()

	const canary = "ROUND8_EXACT_SIZE_CANARY"
	for _, size := range []int{16 << 10, 300 << 10} {
		size := size
		for _, placement := range []string{"front", "middle", "end"} {
			placement := placement
			t.Run(fmt.Sprintf("%d-bytes/%s", size, placement), func(t *testing.T) {
				t.Parallel()
				prompt := round8ExactSizedText(t, size, canary, placement)
				body, err := json.Marshal(map[string]any{
					"input": []any{map[string]any{
						"type": "message", "role": "user",
						"content": []any{map[string]any{"type": "input_text", "text": prompt}},
					}},
				})
				if err != nil {
					t.Fatal(err)
				}
				limits := Limits{
					MaxScanBytes:       size + 4096,
					MaxTextWindowBytes: MinTextWindowBytes,
					MaxTotalTextBytes:  maxInt(size, MinTextWindowBytes),
				}
				sink := newRound6RecordingSink()
				result, err := ScanProfiledRequest(
					body, round8JSONHeaders(), RequestProfile{Source: SourceProfileOpenAIResponse}, limits, sink,
				)
				if err != nil || !result.IsComplete() || !result.RoleAware || sink.aborted {
					t.Fatalf("result=%#v err=%v aborted=%v", result, err, sink.aborted)
				}
				wantChunks := (size + DefaultMaxTextPartBytes - 1) / DefaultMaxTextPartBytes
				if result.TextBytesScanned != size || result.LogicalTextParts != 1 ||
					result.ClassificationChunks != wantChunks || sink.joined() != prompt ||
					!strings.Contains(sink.joined(), canary) {
					t.Fatalf(
						"bytes/parts/chunks/streamed=%d/%d/%d/%d want=%d/1/%d/%d",
						result.TextBytesScanned, result.LogicalTextParts, result.ClassificationChunks,
						len(sink.joined()), size, wantChunks, size,
					)
				}
			})
		}
	}
}

func round8ProtocolPartsBody(t testing.TB, profile SourceProfile, count int) []byte {
	t.Helper()
	parts := make([]any, count)
	for index := range parts {
		text := fmt.Sprintf("round8-part-%03d", index)
		switch profile {
		case SourceProfileOpenAI, SourceProfileClaude:
			parts[index] = map[string]any{"type": "text", "text": text}
		case SourceProfileOpenAIResponse:
			parts[index] = map[string]any{"type": "input_text", "text": text}
		case SourceProfileGemini:
			parts[index] = map[string]any{"text": text}
		default:
			t.Fatalf("unsupported Round 8 parts profile %d", profile)
		}
	}
	var envelope any
	switch profile {
	case SourceProfileOpenAI, SourceProfileClaude:
		envelope = map[string]any{"messages": []any{map[string]any{"role": "user", "content": parts}}}
	case SourceProfileOpenAIResponse:
		envelope = map[string]any{"input": []any{map[string]any{"type": "message", "role": "user", "content": parts}}}
	case SourceProfileGemini:
		envelope = map[string]any{"contents": []any{map[string]any{"role": "user", "parts": parts}}}
	}
	body, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func round8AssertExactPartMetadata(t testing.TB, result Result, count int) {
	t.Helper()
	if result.LogicalTextParts != count || len(result.Parts) != count || len(result.Segments) != count {
		t.Fatalf(
			"batch logical/parts/segments=%d/%d/%d, want %d each",
			result.LogicalTextParts, len(result.Parts), len(result.Segments), count,
		)
	}
	scopeID := result.Segments[0].ScopeID
	fieldHashes := make(map[string]struct{}, count)
	for index, segment := range result.Segments {
		if segment.Role != RoleUser || segment.UserAttribution != UserAttributionTrusted ||
			!segment.IsCurrentTurn || segment.ContentKind != ContentKindNaturalLanguageDirective ||
			segment.ScopeID == 0 || segment.ScopeID != scopeID || segment.FieldPathHash == "" {
			t.Fatalf("segment %d metadata=%#v", index, segment)
		}
		if _, duplicate := fieldHashes[segment.FieldPathHash]; duplicate {
			t.Fatalf("segment %d duplicates field hash %q", index, segment.FieldPathHash)
		}
		fieldHashes[segment.FieldPathHash] = struct{}{}
	}
}

func round8ExactSizedText(t testing.TB, size int, marker, placement string) string {
	t.Helper()
	if len(marker)+2 > size {
		t.Fatalf("marker=%d exceeds target size=%d", len(marker), size)
	}
	remaining := size - len(marker)
	prefixBytes := 0
	switch placement {
	case "front":
		prefixBytes = 0
	case "middle":
		prefixBytes = remaining / 2
	case "end":
		prefixBytes = remaining
	default:
		t.Fatalf("unknown placement %q", placement)
	}
	prefix := strings.Repeat("a", prefixBytes)
	suffix := strings.Repeat("z", remaining-prefixBytes)
	text := prefix + marker + suffix
	if len(text) != size {
		t.Fatalf("sized text bytes=%d, want %d", len(text), size)
	}
	return text
}

func round8JSONHeaders() http.Header {
	return http.Header{"Content-Type": []string{"application/json"}}
}

func round8RequireSegment(t *testing.T, segments []Segment, target string) Segment {
	t.Helper()
	for _, segment := range segments {
		if strings.Contains(segment.Text, target) {
			return segment
		}
	}
	t.Fatalf("segment containing %q not found in %s", target, round8SegmentSummary(segments))
	return Segment{}
}

func round8RequireChunk(t *testing.T, chunks []SegmentChunk, target string) SegmentChunk {
	t.Helper()
	for _, chunk := range chunks {
		if strings.Contains(string(chunk.Text), target) {
			return chunk
		}
	}
	t.Fatalf("chunk containing %q not found", target)
	return SegmentChunk{}
}

func round8AssertConversationMetadata(t *testing.T, segment Segment, conversationIndex, turnIndex int, current bool) {
	t.Helper()
	if segment.ConversationIndex != conversationIndex || segment.TurnIndex != turnIndex ||
		segment.IsCurrentTurn != current || segment.ScopeID == 0 || segment.FieldPathHash == "" {
		t.Fatalf(
			"metadata conv=%d turn=%d current=%v scope=%d hash=%q want conv=%d turn=%d current=%v",
			segment.ConversationIndex, segment.TurnIndex, segment.IsCurrentTurn,
			segment.ScopeID, segment.FieldPathHash, conversationIndex, turnIndex, current,
		)
	}
}

func round8AssertChunkMatchesSegment(t *testing.T, chunk SegmentChunk, segment Segment) {
	t.Helper()
	if chunk.Role != segment.Role || chunk.Provenance != segment.Provenance ||
		chunk.UserAttribution != segment.UserAttribution ||
		chunk.ConversationIndex != segment.ConversationIndex || chunk.TurnIndex != segment.TurnIndex ||
		chunk.IsCurrentTurn != segment.IsCurrentTurn || chunk.ScopeID != segment.ScopeID ||
		chunk.ContentKind != segment.ContentKind || chunk.FieldPathHash != segment.FieldPathHash {
		t.Fatalf("chunk metadata=%#v segment metadata=%#v", chunk, segment)
	}
}

func round8SegmentSummary(segments []Segment) string {
	var summary strings.Builder
	for index, segment := range segments {
		if index != 0 {
			summary.WriteString("; ")
		}
		fmt.Fprintf(
			&summary, "%q(role=%s kind=%s conv=%d turn=%d current=%v scope=%d)",
			segment.Text, segment.Role, segment.ContentKind,
			segment.ConversationIndex, segment.TurnIndex, segment.IsCurrentTurn, segment.ScopeID,
		)
	}
	return summary.String()
}
