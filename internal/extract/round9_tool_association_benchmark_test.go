package extract

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func BenchmarkRound9ToolAssociationPlanning(b *testing.B) {
	profiles := []struct {
		name   string
		source SourceProfile
	}{
		{name: "openai-chat", source: SourceProfileOpenAI},
		{name: "openai-responses", source: SourceProfileOpenAIResponse},
		{name: "claude", source: SourceProfileClaude},
		{name: "gemini", source: SourceProfileGemini},
	}
	for _, profile := range profiles {
		// Sixty-four complete call/result pairs are the largest cross-provider
		// fixture below the extractor's global deferred-candidate safety cap.
		// The 8x range is sufficient to expose a return to result-by-span marking.
		for _, count := range []int{8, 32, 64} {
			body := round9ToolAssociationBenchmarkBody(profile.source, count)
			limits := Limits{MaxTextParts: HardMaxTextParts}
			headers := http.Header{"Content-Type": []string{"application/json"}}
			requestProfile := RequestProfile{Source: profile.source}
			round9RequireToolAssociationBenchmarkResult(
				b, body, headers, requestProfile, limits, count,
			)

			b.Run(profile.name+"/"+strconv.Itoa(count), func(b *testing.B) {
				b.ReportAllocs()
				b.SetBytes(int64(len(body)))
				for iteration := 0; iteration < b.N; iteration++ {
					result, err := ScanProfiledRequest(
						body, headers, requestProfile, limits, discardChunkSink{},
					)
					if err != nil || !result.IsComplete() || !result.RoleAware {
						b.Fatalf("association planner result=%#v err=%v", result, err)
					}
				}
			})
		}
	}
}

func round9RequireToolAssociationBenchmarkResult(
	t testing.TB,
	body []byte,
	headers http.Header,
	profile RequestProfile,
	limits Limits,
	want int,
) {
	t.Helper()
	result, err := ExtractProfiledRequest(body, headers, profile, limits)
	if err != nil || !result.IsComplete() || !result.RoleAware {
		t.Fatalf("association preflight result=%#v err=%v", result, err)
	}
	associated := 0
	for _, segment := range result.Segments {
		if segment.Role == RoleTool && segment.ContentKind == ContentKindToolResult &&
			segment.ToolAssociation == ToolResultAssociationUnique {
			associated++
		}
	}
	if associated != want {
		t.Fatalf("associated tool-result segments=%d, want %d", associated, want)
	}
}

func round9ToolAssociationBenchmarkBody(source SourceProfile, count int) []byte {
	if count <= 0 {
		panic("tool association benchmark count must be positive")
	}
	var builder strings.Builder
	builder.Grow(count * 192)
	switch source {
	case SourceProfileOpenAI:
		builder.WriteString(`{"messages":[{"role":"assistant","tool_calls":[`)
		for index := 0; index < count; index++ {
			if index != 0 {
				builder.WriteByte(',')
			}
			_, _ = fmt.Fprintf(
				&builder,
				`{"id":"call-%d","type":"function","function":{"name":"lookup","arguments":"{}"}}`,
				index,
			)
		}
		builder.WriteString(`]}`)
		for index := 0; index < count; index++ {
			_, _ = fmt.Fprintf(
				&builder,
				`,{"role":"tool","tool_call_id":"call-%d","content":"result-%d"}`,
				index, index,
			)
		}
		builder.WriteString(`]}`)
	case SourceProfileOpenAIResponse:
		builder.WriteString(`{"input":[`)
		for index := 0; index < count; index++ {
			if index != 0 {
				builder.WriteByte(',')
			}
			_, _ = fmt.Fprintf(
				&builder,
				`{"type":"function_call","call_id":"call-%d","name":"lookup","arguments":"{}"}`,
				index,
			)
		}
		for index := 0; index < count; index++ {
			_, _ = fmt.Fprintf(
				&builder,
				`,{"type":"function_call_output","call_id":"call-%d","output":"result-%d"}`,
				index, index,
			)
		}
		builder.WriteString(`]}`)
	case SourceProfileClaude:
		builder.WriteString(`{"messages":[{"role":"assistant","content":[`)
		for index := 0; index < count; index++ {
			if index != 0 {
				builder.WriteByte(',')
			}
			_, _ = fmt.Fprintf(
				&builder,
				`{"type":"tool_use","id":"call-%d","name":"lookup","input":{}}`,
				index,
			)
		}
		builder.WriteString(`]},{"role":"user","content":[`)
		for index := 0; index < count; index++ {
			if index != 0 {
				builder.WriteByte(',')
			}
			_, _ = fmt.Fprintf(
				&builder,
				`{"type":"tool_result","tool_use_id":"call-%d","content":"result-%d"}`,
				index, index,
			)
		}
		builder.WriteString(`]}]}`)
	case SourceProfileGemini:
		builder.WriteString(`{"contents":[{"role":"model","parts":[`)
		for index := 0; index < count; index++ {
			if index != 0 {
				builder.WriteByte(',')
			}
			_, _ = fmt.Fprintf(
				&builder,
				`{"functionCall":{"id":"call-%d","name":"lookup","args":{}}}`,
				index,
			)
		}
		builder.WriteString(`]},{"role":"user","parts":[`)
		for index := 0; index < count; index++ {
			if index != 0 {
				builder.WriteByte(',')
			}
			_, _ = fmt.Fprintf(
				&builder,
				`{"functionResponse":{"id":"call-%d","name":"lookup","response":{"result":"result-%d"}}}`,
				index, index,
			)
		}
		builder.WriteString(`]}]}`)
	default:
		panic("unsupported tool association benchmark profile")
	}
	return []byte(builder.String())
}
