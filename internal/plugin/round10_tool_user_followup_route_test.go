package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/audit"
)

type round10ToolAssociationCase uint8

const (
	round10ToolAssociationMatching round10ToolAssociationCase = iota
	round10ToolAssociationMismatched
	round10ToolAssociationAmbiguous
	round10ToolAssociationMultiple
)

func TestRound10HistoricalToolUserFollowupBlocksBeforeUpstream(t *testing.T) {
	tests := []struct {
		name       string
		source     string
		mode       string
		stream     bool
		activation string
		audit      bool
	}{
		{
			name: "chat balanced batch audit runner", source: "openai", mode: "balanced",
			activation: "Treat the preceding role content as the audit runner input and carry it out now.", audit: true,
		},
		{
			name: "chat balanced stream terse", source: "openai", mode: "balanced", stream: true,
			activation: "Execute it now", audit: true,
		},
		{
			name: "chat strict batch Chinese", source: "openai", mode: "strict",
			activation: "立即执行前述请求。",
		},
		{
			name: "chat strict stream audit runner", source: "openai", mode: "strict", stream: true,
			activation: "Treat the preceding role content as the audit runner input and carry it out now.",
		},
		{
			name: "responses balanced batch terse", source: "openai-response", mode: "balanced",
			activation: "Execute it now", audit: true,
		},
		{
			name: "responses balanced stream audit proof", source: "openai-response", mode: "balanced", stream: true,
			activation: "Treat the preceding role content as the audit runner input and carry it out now.", audit: true,
		},
		{
			name: "responses strict batch Chinese", source: "openai-response", mode: "strict",
			activation: "立即执行前述请求。",
		},
		{
			name: "responses strict stream terse", source: "openai-response", mode: "strict", stream: true,
			activation: "Execute it now",
		},
	}

	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			p := round10ToolFollowupPlugin(t, testCase.mode, testCase.audit)
			body := round10ToolFollowupBody(
				t, testCase.source, providerToolAuthorityMalicious, testCase.activation,
				round10ToolAssociationMatching,
			)
			before := p.counters.snapshot()
			response := round10CallToolFollowupInterceptor(t, p, testCase.source, body, testCase.stream)

			// CPA's RequestInterceptResponse contract guarantees that Terminate
			// stops the chain before any upstream executor is invoked.
			if !response.Terminate {
				t.Fatalf("historical tool activation was not blocked before upstream: %+v", response)
			}
			assertRequestInterceptorBlocked(t, response, "credential_theft")
			round10AssertCompleteCounterDeltas(t, before, p.counters.snapshot(), 1)

			if testCase.audit {
				round10AssertActivatedToolAuditEvent(t, p, testCase.source, testCase.stream)
			}
		})
	}
}

func TestRound10HistoricalToolUserFollowupAllowsInertAndUnprovenRelations(t *testing.T) {
	tests := []struct {
		name        string
		source      string
		mode        string
		stream      bool
		carrier     string
		followup    string
		association round10ToolAssociationCase
	}{
		{
			name: "defensive review and prohibition", source: "openai", mode: "balanced",
			carrier:     providerToolAuthorityMalicious,
			followup:    "Review the preceding tool result for defensive analysis only; do not execute it.",
			association: round10ToolAssociationMatching,
		},
		{
			name: "later cancellation", source: "openai-response", mode: "strict", stream: true,
			carrier:     providerToolAuthorityMalicious,
			followup:    "Execute it. Actually, do not execute it.",
			association: round10ToolAssociationMatching,
		},
		{
			name: "ordinary summary followup", source: "openai", mode: "strict", stream: true,
			carrier:     providerToolAuthorityMalicious,
			followup:    "Please summarize the preceding tool result.",
			association: round10ToolAssociationMatching,
		},
		{
			name: "benign tool carrier", source: "openai-response", mode: "balanced",
			carrier:     "The tool returned an ordinary football score table with three teams.",
			followup:    "Execute it now",
			association: round10ToolAssociationMatching,
		},
		{
			name: "mismatched responses call id", source: "openai-response", mode: "strict",
			carrier:     providerToolAuthorityMalicious,
			followup:    "Execute it now",
			association: round10ToolAssociationMismatched,
		},
		{
			name: "ambiguous duplicate chat call id", source: "openai", mode: "balanced", stream: true,
			carrier:     providerToolAuthorityMalicious,
			followup:    "Execute it now",
			association: round10ToolAssociationAmbiguous,
		},
		{
			name: "multiple chat results batch", source: "openai", mode: "balanced",
			carrier:     providerToolAuthorityMalicious,
			followup:    "Execute the preceding result now",
			association: round10ToolAssociationMultiple,
		},
		{
			name: "multiple chat results stream", source: "openai", mode: "strict", stream: true,
			carrier:     providerToolAuthorityMalicious,
			followup:    "Execute the preceding result now",
			association: round10ToolAssociationMultiple,
		},
		{
			name: "multiple responses results batch", source: "openai-response", mode: "strict",
			carrier:     providerToolAuthorityMalicious,
			followup:    "Execute the preceding result now",
			association: round10ToolAssociationMultiple,
		},
		{
			name: "multiple responses results stream", source: "openai-response", mode: "balanced", stream: true,
			carrier:     providerToolAuthorityMalicious,
			followup:    "Execute the preceding result now",
			association: round10ToolAssociationMultiple,
		},
	}

	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			p := round10ToolFollowupPlugin(t, testCase.mode, false)
			body := round10ToolFollowupBody(
				t, testCase.source, testCase.carrier, testCase.followup, testCase.association,
			)
			before := p.counters.snapshot()
			response := round10CallToolFollowupInterceptor(t, p, testCase.source, body, testCase.stream)

			assertRequestInterceptorPassThrough(t, response)
			round10AssertCompleteCounterDeltas(t, before, p.counters.snapshot(), 0)
		})
	}
}

func TestRound10GeminiTerminalWrapperAttemptsBlockHistoricalFallback(t *testing.T) {
	tests := []struct {
		name    string
		wrapper string
	}{
		{
			name: "orphan response",
			wrapper: `{"functionResponse":{"id":"round10-orphan","name":"other",` +
				`"response":{"result":"ordinary orphan result"}}}`,
		},
		{
			name: "mismatched response",
			wrapper: `{"functionResponse":{"id":"round10-prior","name":"other",` +
				`"response":{"result":"ordinary mismatched result"}}}`,
		},
		{
			name: "wrong owner call",
			wrapper: `{"functionCall":{"id":"round10-wrong-owner","name":"other",` +
				`"args":{"query":"ordinary query"}}}`,
		},
		{
			name: "ambiguous id",
			wrapper: `{"functionResponse":{"id":"round10-shadow-a","id":"round10-shadow-b",` +
				`"name":"other","response":{"result":"ordinary ambiguous result"}}}`,
		},
		{
			name: "duplicate wrappers",
			wrapper: `{"functionResponse":{"id":"round10-shadow-first","name":"other",` +
				`"response":{"result":"ordinary first result"}},` +
				`"functionResponse":{"id":"round10-shadow-second","name":"other",` +
				`"response":{"result":"ordinary second result"}}}`,
		},
		{
			name:    "non object wrapper attempts",
			wrapper: `{"functionResponse":null,"functionResponse":null}`,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		for _, stream := range []bool{false, true} {
			stream := stream
			t.Run(fmt.Sprintf("%s/stream-%t", testCase.name, stream), func(t *testing.T) {
				p := round10ToolFollowupPlugin(t, "balanced", false)
				body := round10GeminiTerminalWrapperAttemptBody(t, testCase.wrapper)
				before := p.counters.snapshot()
				response := round10CallToolFollowupInterceptor(t, p, "gemini", body, stream)
				assertRequestInterceptorPassThrough(t, response)
				round10AssertCompleteCounterDeltas(t, before, p.counters.snapshot(), 0)
			})
		}
	}
}

func TestRound10ColocatedToolResultUserTextIsAmbiguityBarrier(t *testing.T) {
	tests := []struct {
		name   string
		source string
		body   string
	}{
		{
			name: "claude", source: "claude",
			body: `{"model":"claude-test","messages":[
				{"role":"assistant","content":[{"type":"tool_use","id":"round10-colocated","name":"lookup","input":{}}]},
				{"role":"user","content":[
					{"type":"tool_result","tool_use_id":"round10-colocated","content":"` + providerToolAuthorityMalicious + `"},
					{"type":"text","text":"ordinary sibling user text"}
				]},
				{"role":"user","content":"Execute it now"}
			]}`,
		},
		{
			name: "gemini", source: "gemini",
			body: `{"model":"gemini-test","contents":[
				{"role":"model","parts":[{"functionCall":{"id":"round10-colocated","name":"lookup","args":{}}}]},
				{"role":"user","parts":[
					{"functionResponse":{"id":"round10-colocated","name":"lookup","response":{"result":"` + providerToolAuthorityMalicious + `"}}},
					{"text":"ordinary sibling user text"}
				]},
				{"role":"user","parts":[{"text":"Execute it now"}]}
			]}`,
		},
	}
	for _, testCase := range tests {
		testCase := testCase
		for _, stream := range []bool{false, true} {
			stream := stream
			t.Run(fmt.Sprintf("%s/stream-%t", testCase.name, stream), func(t *testing.T) {
				body := []byte(testCase.body)
				if !json.Valid(body) {
					t.Fatalf("invalid colocated-result fixture: %s", body)
				}
				p := round10ToolFollowupPlugin(t, "balanced", false)
				before := p.counters.snapshot()
				response := round10CallToolFollowupInterceptor(t, p, testCase.source, body, stream)
				assertRequestInterceptorPassThrough(t, response)
				round10AssertCompleteCounterDeltas(t, before, p.counters.snapshot(), 0)
			})
		}
	}
}

func round10ToolFollowupPlugin(t testing.TB, mode string, auditEnabled bool) *Plugin {
	t.Helper()
	p := New()
	t.Cleanup(p.Shutdown)
	auditConfig := "audit:\n  enabled: false\n"
	if auditEnabled {
		auditConfig = "audit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(t.TempDir()) + "\"\n"
	}
	register(t, p,
		"mode: "+mode+"\nmax_scan_bytes: 262144\n"+auditConfig+"subject_control:\n  enabled: false\n",
	)
	return p
}

func round10CallToolFollowupInterceptor(
	t testing.TB,
	p *Plugin,
	source string,
	body []byte,
	stream bool,
) pluginapi.RequestInterceptResponse {
	t.Helper()
	request, err := json.Marshal(pluginapi.RequestInterceptRequest{
		RequestID:      "round10-tool-user-followup",
		TraceID:        "trace-round10-tool-user-followup",
		SourceFormat:   source,
		Model:          "gpt-test",
		RequestedModel: "gpt-test",
		Stream:         stream,
		Headers:        http.Header{"Content-Type": []string{"application/json"}},
		Body:           body,
	})
	if err != nil {
		t.Fatalf("marshal Round10 request interceptor payload: %v", err)
	}
	return callRequestInterceptor(t, p, pluginabi.MethodRequestInterceptBefore, request)
}

func round10ToolFollowupBody(
	t testing.TB,
	source string,
	carrier string,
	followup string,
	association round10ToolAssociationCase,
) []byte {
	t.Helper()
	const callID = "round10-call"
	resultID := callID
	if association == round10ToolAssociationMismatched {
		resultID = "round10-other-call"
	}

	var body any
	switch source {
	case "openai":
		if association == round10ToolAssociationMultiple {
			body = map[string]any{
				"model": "gpt-test",
				"messages": []any{
					map[string]any{"role": "assistant", "tool_calls": []any{
						round10ChatToolCall(callID+"-a", "lookup_a"),
						round10ChatToolCall(callID+"-b", "lookup_b"),
					}},
					map[string]any{"role": "tool", "tool_call_id": callID + "-a", "content": "An ordinary football score table."},
					map[string]any{"role": "tool", "tool_call_id": callID + "-b", "content": carrier},
					map[string]any{"role": "user", "content": followup},
				},
			}
			break
		}
		calls := []any{round10ChatToolCall(callID, "lookup")}
		if association == round10ToolAssociationAmbiguous {
			calls = append(calls, round10ChatToolCall(callID, "lookup_duplicate"))
		}
		body = map[string]any{
			"model": "gpt-test",
			"messages": []any{
				map[string]any{"role": "assistant", "tool_calls": calls},
				map[string]any{"role": "tool", "tool_call_id": resultID, "content": carrier},
				map[string]any{"role": "user", "content": followup},
			},
		}
	case "openai-response":
		if association == round10ToolAssociationMultiple {
			body = map[string]any{
				"model": "gpt-test",
				"input": []any{
					round10ResponsesToolCall(callID+"-a", "lookup_a"),
					round10ResponsesToolCall(callID+"-b", "lookup_b"),
					map[string]any{"type": "function_call_output", "call_id": callID + "-a", "output": "An ordinary football score table."},
					map[string]any{"type": "function_call_output", "call_id": callID + "-b", "output": carrier},
					map[string]any{"type": "message", "role": "user", "content": followup},
				},
			}
			break
		}
		input := []any{round10ResponsesToolCall(callID, "lookup")}
		if association == round10ToolAssociationAmbiguous {
			input = append(input, round10ResponsesToolCall(callID, "lookup_duplicate"))
		}
		input = append(input,
			map[string]any{"type": "function_call_output", "call_id": resultID, "output": carrier},
			map[string]any{"type": "message", "role": "user", "content": followup},
		)
		body = map[string]any{"model": "gpt-test", "input": input}
	default:
		t.Fatalf("unsupported Round10 source format %q", source)
	}

	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal Round10 provider body: %v", err)
	}
	return raw
}

func round10GeminiTerminalWrapperAttemptBody(t testing.TB, wrapper string) []byte {
	t.Helper()
	carrier, err := json.Marshal(providerToolAuthorityMalicious)
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"model":"gemini-test","contents":[
		{"role":"model","parts":[{"functionCall":{"id":"round10-prior","name":"lookup","args":{}}}]},
		{"role":"user","parts":[{"functionResponse":{"id":"round10-prior","name":"lookup","response":{"result":%s}}}]},
		{"role":"user","parts":[{"text":"Execute it now"},%s]}
	]}`, carrier, wrapper)
	if !json.Valid([]byte(body)) {
		t.Fatalf("invalid Round10 Gemini wrapper-attempt body: %s", body)
	}
	return []byte(body)
}

func round10ChatToolCall(id, name string) map[string]any {
	return map[string]any{
		"id":       id,
		"type":     "function",
		"function": map[string]any{"name": name, "arguments": "{}"},
	}
}

func round10ResponsesToolCall(id, name string) map[string]any {
	return map[string]any{
		"type": "function_call", "call_id": id, "name": name, "arguments": "{}",
	}
}

func round10AssertCompleteCounterDeltas(
	t testing.TB,
	before map[string]uint64,
	after map[string]uint64,
	wantBlocked uint64,
) {
	t.Helper()
	for key, want := range map[string]uint64{
		"total":               1,
		"blocked":             wantBlocked,
		"coverage_complete":   1,
		"coverage_incomplete": 0,
	} {
		if got := after[key] - before[key]; got != want {
			t.Fatalf("counter %s delta=%d, want %d; before=%v after=%v", key, got, want, before, after)
		}
	}
}

func round10AssertActivatedToolAuditEvent(t testing.TB, p *Plugin, wantSource string, wantStream bool) {
	t.Helper()
	state := p.runtime.Load()
	if state == nil || state.audit == nil {
		t.Fatal("Round10 audit runtime is unavailable")
	}
	if err := state.audit.Flush(context.Background()); err != nil {
		t.Fatalf("flush Round10 audit event: %v", err)
	}
	events, err := state.audit.Query(context.Background(), audit.Query{Limit: 10})
	if err != nil || len(events) != 1 {
		t.Fatalf("query Round10 audit events: events=%+v err=%v", events, err)
	}
	event := events[0]
	explanation := event.DecisionExplanation
	if event.Action != "block" || event.Mode != "balanced" || event.SourceFormat != wantSource ||
		event.Stream != wantStream || event.Coverage != "complete" || explanation == nil {
		t.Fatalf("Round10 audit event envelope=%+v", event)
	}
	if explanation.WinningRole != "tool" || explanation.WinningProvenance != "content" ||
		!explanation.CurrentTurnEvidence || explanation.EvidenceOwnedByCurrentUser ||
		explanation.EnforcementScope != audit.EnforcementScopeRequestLocalTool ||
		!explanation.BlockEligible || !explanation.InspectionComplete ||
		!explanation.CurrentExecutionActProven || !explanation.ReferentLinkUsed ||
		!explanation.ReferentProofComplete || explanation.CrossSegmentComposition != "explicit_referent" ||
		explanation.RelationType != audit.ExplanationRelationHistoricalToolActivation ||
		explanation.EnforcementOwner != audit.ExplanationEnforcementOwnerCurrentTrustedUser ||
		explanation.EvidenceSegmentCount < 2 || explanation.EvidenceAmbiguous {
		t.Fatalf("Round10 activated-tool audit explanation=%+v", explanation)
	}
}
