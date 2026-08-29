package plugin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestOversizedModelRouteUsesIncompleteInspectionContract(t *testing.T) {
	oversized := make([]byte, maxRPCRequestBytes+1)
	for _, testCase := range []struct {
		mode        string
		wantHandled bool
	}{
		{mode: "balanced", wantHandled: false},
		{mode: "strict", wantHandled: true},
		{mode: "audit", wantHandled: false},
		{mode: "observe", wantHandled: false},
		{mode: "off", wantHandled: false},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			p := New()
			register(t, p, "mode: "+testCase.mode+"\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
			raw, code := p.Call(pluginabi.MethodModelRoute, oversized)
			p.Shutdown()
			if code != 0 {
				t.Fatalf("oversized model.route code=%d envelope=%s", code, raw)
			}
			var route pluginapi.ModelRouteResponse
			decodeOKResult(t, raw, &route)
			if route.Handled != testCase.wantHandled {
				t.Fatalf("mode=%s oversized route Handled=%v, want %v; route=%+v", testCase.mode, route.Handled, testCase.wantHandled, route)
			}
			if testCase.wantHandled && route.Reason != "cyber_abuse_guard_rpc_body_limit" {
				t.Fatalf("mode=%s oversized route reason=%q", testCase.mode, route.Reason)
			}
			if testCase.mode != "off" {
				if got := p.counters.incompleteInspections.Load(); got != 1 {
					t.Fatalf("mode=%s incomplete_inspections=%d, want 1", testCase.mode, got)
				}
				if got := p.counters.incompleteRPCBodyLimit.Load(); got != 1 {
					t.Fatalf("mode=%s incomplete_rpc_body_limit=%d, want 1", testCase.mode, got)
				}
				if got := p.counters.coverageIncomplete.Load(); got != 1 {
					t.Fatalf("mode=%s coverage_incomplete=%d, want 1", testCase.mode, got)
				}
			}
		})
	}
}

func TestOversizedExecutorDoesNotTurnBalancedPassThroughIntoPolicy403(t *testing.T) {
	for _, testCase := range []struct {
		mode       string
		wantCode   string
		wantStatus int
	}{
		{mode: "balanced", wantCode: "request_too_large", wantStatus: http.StatusRequestEntityTooLarge},
		{mode: "strict", wantCode: blockedErrorCode, wantStatus: http.StatusForbidden},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			p := New()
			defer p.Shutdown()
			register(t, p, "mode: "+testCase.mode+"\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
			for _, method := range []string{pluginabi.MethodExecutorExecute, pluginabi.MethodExecutorExecuteStream, pluginabi.MethodExecutorCountTokens} {
				raw, code := p.CallOversized(method)
				if code != 0 {
					t.Fatalf("%s code=%d envelope=%s", method, code, raw)
				}
				var envelope struct {
					OK    bool `json:"ok"`
					Error struct {
						Code       string `json:"code"`
						HTTPStatus int    `json:"http_status"`
						Category   string `json:"category"`
					} `json:"error"`
				}
				if err := json.Unmarshal(raw, &envelope); err != nil {
					t.Fatal(err)
				}
				if envelope.OK || envelope.Error.Code != testCase.wantCode || envelope.Error.HTTPStatus != testCase.wantStatus || envelope.Error.Category != "rpc_body_limit" {
					t.Fatalf("%s oversized refusal=%s", method, raw)
				}
			}
		})
	}
}

func TestOversizedCallbacksHonorQuiesceGate(t *testing.T) {
	for _, modeCase := range requestInterceptorModeCases() {
		modeCase := modeCase
		t.Run(modeCase.mode, func(t *testing.T) {
			p := New()
			defer p.Shutdown()
			register(t, p, requestInterceptorModeConfig(modeCase.mode))
			if err := p.Quiesce(); err != nil {
				t.Fatalf("quiesce: %v", err)
			}

			raw, code := p.CallOversized(pluginabi.MethodModelRoute)
			if code != 0 {
				t.Fatalf("oversized model.route code=%d envelope=%s", code, raw)
			}
			var route pluginapi.ModelRouteResponse
			decodeOKResult(t, raw, &route)
			if route.Handled != modeCase.failClosed {
				t.Fatalf("quiesced oversized model.route handled=%t, want %t; route=%+v", route.Handled, modeCase.failClosed, route)
			}
			if route.Handled && route.Reason != "cyber_abuse_guard_quiesced" {
				t.Fatalf("quiesced oversized model.route reason=%q", route.Reason)
			}

			for _, method := range []string{pluginabi.MethodRequestInterceptBefore, pluginabi.MethodRequestInterceptAfter} {
				raw, code = p.CallOversized(method)
				if code != 0 {
					t.Fatalf("%s code=%d envelope=%s", method, code, raw)
				}
				var response pluginapi.RequestInterceptResponse
				decodeOKResult(t, raw, &response)
				assertRequestInterceptorPolicyResult(t, response, modeCase.failClosed, "inspection_failure")
			}

			for _, method := range []string{pluginabi.MethodExecutorExecute, pluginabi.MethodExecutorExecuteStream, pluginabi.MethodExecutorCountTokens} {
				raw, code = p.CallOversized(method)
				if code != 0 {
					t.Fatalf("%s code=%d envelope=%s", method, code, raw)
				}
				var envelope rpcEnvelope
				if err := json.Unmarshal(raw, &envelope); err != nil {
					t.Fatalf("%s invalid envelope: %v", method, err)
				}
				if envelope.OK || envelope.Error == nil || envelope.Error.Code != "plugin_quiesced" {
					t.Fatalf("%s quiesced envelope=%s", method, raw)
				}
			}

			// The oversized quiesce path has no request body to inspect and must not
			// charge RPC-body-limit or incomplete-inspection counters.
			if got := p.counters.incompleteInspections.Load(); got != 0 {
				t.Fatalf("quiesced oversized callbacks recorded incomplete inspections=%d", got)
			}
			if got := p.counters.incompleteRPCBodyLimit.Load(); got != 0 {
				t.Fatalf("quiesced oversized callbacks recorded rpc-body-limit=%d", got)
			}
		})
	}
}

func TestOversizedNonRoutingRPCRemainsRejected(t *testing.T) {
	p := New()
	defer p.Shutdown()
	raw, code := p.CallOversized(pluginabi.MethodPluginRegister)
	if code != 0 || !json.Valid(raw) || string(raw) == "" {
		t.Fatalf("oversized non-routing RPC code=%d envelope=%s", code, raw)
	}
	var envelope struct {
		OK    bool `json:"ok"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil || envelope.OK || envelope.Error.Code != "request_too_large" {
		t.Fatalf("oversized non-routing RPC envelope=%s err=%v", raw, err)
	}
}

func TestOversizedRoutePersistsOnlyOutsideObserve(t *testing.T) {
	for _, testCase := range []struct {
		mode          string
		wantAction    string
		wantKind      string
		expectedCount int
	}{
		{mode: "balanced", wantAction: "audit", wantKind: "audit_ineligible_risk", expectedCount: 1},
		{mode: "audit", wantAction: "audit", wantKind: "audit_ineligible_risk", expectedCount: 1},
		{mode: "strict", wantAction: "block", wantKind: "block_incomplete_inspection", expectedCount: 1},
		{mode: "observe", expectedCount: 0},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			p := New()
			defer p.Shutdown()
			dataDir := filepath.ToSlash(t.TempDir())
			register(t, p, "mode: "+testCase.mode+"\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\nsubject_control:\n  enabled: false\n")
			if _, code := p.CallOversized(pluginabi.MethodModelRoute); code != 0 {
				t.Fatalf("oversized model.route code=%d", code)
			}
			events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
			items, ok := events["events"].([]any)
			if !ok || len(items) != testCase.expectedCount {
				t.Fatalf("oversized audit events=%#v, want count %d", events, testCase.expectedCount)
			}
			if testCase.expectedCount == 0 {
				return
			}
			event := items[0].(map[string]any)
			if event["action"] != testCase.wantAction || event["category"] != "rpc_body_limit" ||
				event["coverage"] != "incomplete" || event["incomplete_reason"] != "rpc_body_limit" ||
				event["decision_kind"] != testCase.wantKind || event["scanner"] != streamingScannerIdentity {
				t.Fatalf("oversized event=%#v", event)
			}
			wantDecision := "allow_due_to_incomplete_inspection"
			if testCase.mode == "audit" {
				wantDecision = "audit_incomplete_inspection"
			} else if testCase.mode == "strict" {
				wantDecision = "block_due_to_incomplete_inspection"
			}
			if event["decision"] != wantDecision {
				t.Fatalf("oversized event decision=%#v, want %q", event, wantDecision)
			}
			if testCase.mode == "strict" {
				if event["explanation_schema"] != "decision-explanation-v2" {
					t.Fatalf("strict oversized explanation schema=%#v", event)
				}
				explanation, ok := event["decision_explanation"].(map[string]any)
				if !ok || explanation["kind"] != "incomplete" ||
					explanation["incomplete_inspection_reason"] != "rpc_body_limit" {
					t.Fatalf("strict oversized explanation=%#v", event["decision_explanation"])
				}
			} else if event["explanation_schema"] != "none" {
				t.Fatalf("non-blocking oversized explanation schema=%#v", event)
			}
			for _, key := range []string{"request_hash", "model", "source_format"} {
				if value, exists := event[key]; exists && value != "" {
					t.Fatalf("oversized event invented unavailable %s: %#v", key, event)
				}
			}
			if scanned, ok := event["text_bytes_scanned"].(float64); !ok || scanned != 0 {
				t.Fatalf("oversized event claimed bytes were scanned: %#v", event)
			}
		})
	}
}
