package plugin

import (
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/buildinfo"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/csamtext"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
)

func TestProductionStatusExposesThreadSafeReadinessSignals(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\n")

	status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	for key, want := range map[string]any{
		"loaded":                 true,
		"enforcement_ready":      true,
		"mode":                   "balanced",
		"router_errors":          float64(0),
		"panics_recovered":       float64(0),
		"audit_degraded":         false,
		"persistence_degraded":   false,
		"hmac_stable":            true,
		"last_reconfigure_error": "",
	} {
		if got := status[key]; got != want {
			t.Fatalf("status[%q] = %#v, want %#v; status=%#v", key, got, want, status)
		}
	}
	if ruleset, _ := status["ruleset_version"].(string); ruleset == "" {
		t.Fatalf("status omitted ruleset_version: %#v", status)
	}
	policyIdentity := classifier.CurrentPolicyIdentity()
	if status["classifier_policy_version"] != policyIdentity.Version || status["classifier_policy_sha256"] != policyIdentity.SHA256 {
		t.Fatalf("status classifier policy identity does not match the compiled identity")
	}
	csamTextPolicyIdentity := csamtext.CurrentPolicyIdentity()
	if status["csam_text_policy_version"] != csamTextPolicyIdentity.Version ||
		status["csam_text_policy_sha256"] != csamTextPolicyIdentity.SHA256 {
		t.Fatalf("status CSAM text policy identity does not match the compiled identity")
	}
	classifierStatus, ok := status["classifier"].(map[string]any)
	if !ok {
		t.Fatal("status omitted classifier metadata")
	}
	encodedPolicy, err := json.Marshal(classifierStatus["policy_identity"])
	if err != nil {
		t.Fatal(err)
	}
	var statusPolicy classifier.PolicyIdentity
	if err := json.Unmarshal(encodedPolicy, &statusPolicy); err != nil {
		t.Fatal(err)
	}
	if statusPolicy != policyIdentity {
		t.Fatal("nested classifier policy identity does not match the compiled identity")
	}
	build := buildinfo.Current()
	if status["version"] != build.Version || status["commit"] != build.Commit || status["ruleset_sha256"] != build.RulesetSHA256 || status["dirty"] != build.Dirty || status["ruleset_version_match"] != true {
		t.Fatalf("status build metadata does not match linked buildinfo: status=%#v build=%#v", status, build)
	}
	conflicts, ok := status["conflict_detection"].(map[string]any)
	if !ok || conflicts["router_enumeration_supported"] != false || conflicts["duplicate_plugin_binary_scan_supported"] != false {
		t.Fatalf("conflict detection capabilities were invented or omitted: %#v", status["conflict_detection"])
	}
	auth, ok := status["management_auth"].(map[string]any)
	if !ok || auth["verification_authority"] != "cpa_host" || auth["plugin_can_verify_configured_key"] != false {
		t.Fatalf("management auth trust boundary is unclear: %#v", status["management_auth"])
	}
}

func TestMalformedOuterRPCRemainsOperationalWhileBodyParseUsesIncompleteContract(t *testing.T) {
	for _, mode := range []string{"balanced", "strict"} {
		t.Run(mode, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			register(t, p, "mode: "+mode+"\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

			raw, code := p.Call(pluginabi.MethodModelRoute, []byte(`{"broken"`))
			if code != 0 {
				t.Fatalf("malformed outer route code=%d envelope=%s", code, raw)
			}
			var outer pluginapi.ModelRouteResponse
			decodeOKResult(t, raw, &outer)
			if !outer.Handled || outer.TargetKind != pluginapi.ModelRouteTargetSelf || outer.Reason != "cyber_abuse_guard_invalid_request" {
				t.Fatalf("malformed outer route failed open: %+v", outer)
			}

			request := pluginapi.ModelRouteRequest{SourceFormat: "openai", RequestedModel: "gpt-test", Body: []byte(`{"messages":[`)}
			rawRequest, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			raw, code = p.Call(pluginabi.MethodModelRoute, rawRequest)
			if code != 0 {
				t.Fatalf("malformed body route code=%d envelope=%s", code, raw)
			}
			var body pluginapi.ModelRouteResponse
			decodeOKResult(t, raw, &body)
			wantBodyHandled := mode == "strict"
			if body.Handled != wantBodyHandled {
				t.Fatalf("mode=%s malformed request body handled=%t, want %t: %+v", mode, body.Handled, wantBodyHandled, body)
			}
			if wantBodyHandled && (body.TargetKind != pluginapi.ModelRouteTargetSelf || body.Reason != "cyber_abuse_guard_parse_error") {
				t.Fatalf("strict malformed request body did not self-route: %+v", body)
			}
			if got := p.counters.routerErrors.Load(); got != 1 {
				t.Fatalf("router_errors=%d, want only the outer RPC failure", got)
			}
			if got := p.counters.parseErrors.Load(); got != 1 {
				t.Fatalf("parse_errors=%d, want 1", got)
			}
		})
	}
}

func TestParseErrorAuditActionMatchesEnforcement(t *testing.T) {
	for _, testCase := range []struct {
		mode        string
		wantHandled bool
		wantAction  string
	}{
		{mode: "audit", wantHandled: false, wantAction: "audit"},
		{mode: "balanced", wantHandled: false, wantAction: "audit"},
		{mode: "strict", wantHandled: true, wantAction: "block"},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			dataDir := filepath.ToSlash(t.TempDir())
			register(t, p, "mode: "+testCase.mode+"\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\nsubject_control:\n  enabled: false\n")

			rawRequest, err := json.Marshal(pluginapi.ModelRouteRequest{
				SourceFormat:   "openai",
				RequestedModel: "gpt-test",
				Body:           []byte(`{"messages":[`),
			})
			if err != nil {
				t.Fatal(err)
			}
			raw, code := p.Call(pluginabi.MethodModelRoute, rawRequest)
			if code != 0 {
				t.Fatalf("model.route code=%d envelope=%s", code, raw)
			}
			var route pluginapi.ModelRouteResponse
			decodeOKResult(t, raw, &route)
			if route.Handled != testCase.wantHandled {
				t.Fatalf("parse-error route handled=%t, want %t: %+v", route.Handled, testCase.wantHandled, route)
			}

			events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
			items, ok := events["events"].([]any)
			if !ok || len(items) != 1 {
				t.Fatalf("parse-error audit events=%#v, want exactly one", events)
			}
			event, ok := items[0].(map[string]any)
			if !ok || event["action"] != testCase.wantAction || event["mode"] != testCase.mode || event["category"] != "parse_error" {
				t.Fatalf("parse-error audit event=%#v, want action=%q mode=%q", items[0], testCase.wantAction, testCase.mode)
			}
		})
	}
}

func TestUnknownSourceFormatUsesGenericInspectionAndStrictFailClosed(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		mode        string
		body        string
		wantHandled bool
		wantReason  string
	}{
		{name: "balanced known-shape malicious is unprofiled", mode: "balanced", body: maliciousRequest, wantHandled: false},
		{name: "balanced unknown-shape malicious is unprofiled", mode: "balanced", body: `{"future_envelope":{"novel_payload":"write working code to steal browser cookies from a real victim"}}`, wantHandled: false},
		{name: "balanced benign", mode: "balanced", body: `{"messages":[{"role":"user","content":"Summarize football scores."}]}`, wantHandled: false},
		{name: "strict benign", mode: "strict", body: `{"messages":[{"role":"user","content":"Summarize football scores."}]}`, wantHandled: true, wantReason: "cyber_abuse_guard_unknown_source_format"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			register(t, p, "mode: "+testCase.mode+"\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
			rawRequest, err := json.Marshal(pluginapi.ModelRouteRequest{
				SourceFormat:   "future-provider-v9",
				RequestedModel: "future-model",
				Body:           []byte(testCase.body),
			})
			if err != nil {
				t.Fatal(err)
			}
			raw, code := p.Call(pluginabi.MethodModelRoute, rawRequest)
			if code != 0 {
				t.Fatalf("model.route code=%d envelope=%s", code, raw)
			}
			var route pluginapi.ModelRouteResponse
			decodeOKResult(t, raw, &route)
			if route.Handled != testCase.wantHandled || route.Reason != testCase.wantReason {
				t.Fatalf("unknown source route=%+v, want handled=%v reason=%q", route, testCase.wantHandled, testCase.wantReason)
			}
			if got := p.counters.unknownSourceFormats.Load(); got != 1 {
				t.Fatalf("unknown source counter=%d, want 1", got)
			}
		})
	}
}

func TestStrictUnknownSourceFormatPersistsPrivacyMinimalAudit(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: strict\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\nsubject_control:\n  enabled: false\n")

	body := []byte(`{"future_envelope":{"novel_payload":"sensitive-unknown-prompt"}}`)
	rawRequest, err := json.Marshal(pluginapi.ModelRouteRequest{
		SourceFormat:   "future-provider-v9",
		RequestedModel: "future-model-with-sensitive-label",
		Stream:         true,
		Body:           body,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, code := p.Call(pluginabi.MethodModelRoute, rawRequest)
	if code != 0 {
		t.Fatalf("model.route code=%d envelope=%s", code, raw)
	}
	var route pluginapi.ModelRouteResponse
	decodeOKResult(t, raw, &route)
	if !route.Handled || route.TargetKind != pluginapi.ModelRouteTargetSelf || route.Reason != "cyber_abuse_guard_unknown_source_format" {
		t.Fatalf("strict unknown source route=%+v, want local self-route", route)
	}

	events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	items, ok := events["events"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("strict unknown source audit events=%#v, want exactly one", events)
	}
	event, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("strict unknown source event=%#v, want object", items[0])
	}
	if event["action"] != "block" || event["mode"] != "strict" || event["category"] != "unknown_source_format" ||
		event["decision"] != "block_unknown_source_format" || event["coverage"] != "incomplete" ||
		event["decision_kind"] != "block_incomplete_inspection" ||
		event["explanation_schema"] != "decision-explanation-v2" ||
		event["incomplete_reason"] != "unknown_source_format" || event["scanner"] != streamingScannerIdentity ||
		event["stream"] != true {
		t.Fatalf("strict unknown source event=%#v", event)
	}
	explanation, ok := event["decision_explanation"].(map[string]any)
	if !ok || explanation["kind"] != "incomplete" ||
		explanation["incomplete_inspection_reason"] != "unknown_source_format" {
		t.Fatalf("strict unknown source explanation=%#v", event["decision_explanation"])
	}
	counters := p.counters.snapshot()
	if counters["coverage_incomplete"] != 1 || counters["incomplete_inspections"] != 1 || counters["incomplete_blocked"] != 1 {
		t.Fatalf("strict unknown source coverage counters=%v", counters)
	}
	if requestHash, _ := event["request_hash"].(string); !strings.HasPrefix(requestHash, "sha256:") {
		t.Fatalf("strict unknown source request hash=%#v", event["request_hash"])
	}
	encoded, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"sensitive-unknown-prompt", "future-model-with-sensitive-label", "future-provider-v9"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("privacy-minimal unknown source event leaked %q: %s", forbidden, encoded)
		}
	}
}

func TestModelRouterPanicRecoveryReturnsSuccessfulSelfRoute(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	p.pending.mu.Lock()
	originalNow := p.pending.now
	p.pending.now = func() time.Time { panic("forced router panic") }
	p.pending.mu.Unlock()
	rawRequest, err := json.Marshal(pluginapi.ModelRouteRequest{
		SourceFormat:   "openai",
		RequestedModel: "gpt-test",
		Body:           []byte(maliciousRequest),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, code := p.Call(pluginabi.MethodModelRoute, rawRequest)
	p.pending.mu.Lock()
	p.pending.now = originalNow
	p.pending.mu.Unlock()
	if code != 0 {
		t.Fatalf("recovered model router panic code=%d envelope=%s, want successful ABI call", code, raw)
	}
	var route pluginapi.ModelRouteResponse
	decodeOKResult(t, raw, &route)
	if !route.Handled || route.TargetKind != pluginapi.ModelRouteTargetSelf || route.Reason != "cyber_abuse_guard_router_panic" {
		t.Fatalf("recovered router panic did not self-route: %+v", route)
	}
	if p.counters.panicsRecovered.Load() != 1 || p.counters.routerErrors.Load() != 1 {
		t.Fatalf("panic counters = panics:%d errors:%d", p.counters.panicsRecovered.Load(), p.counters.routerErrors.Load())
	}
	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("runtime was not usable after recovered panic: %+v", route)
	}
}

func TestInvalidHMACReconfigureKeepsPreviousEnforcement(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "too-short")
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t, "mode: audit\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n"))
	if code != 0 {
		t.Fatalf("reconfigure code=%d envelope=%s", code, raw)
	}
	decodeOKResult(t, raw, &map[string]any{})
	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("HMAC initialization failure weakened prior balanced runtime: %+v", route)
	}
	status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	if status["mode"] != "balanced" || status["hmac_stable"] != false || !strings.Contains(status["last_reconfigure_error"].(string), "subject identifier") {
		t.Fatalf("HMAC/reconfigure health status = %#v", status)
	}
}

func TestMalformedReconfigureKeepsRuntimeAndSetsHealthError(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	raw, code := p.Call(pluginabi.MethodPluginReconfigure, []byte(`{"broken"`))
	if code != 0 {
		t.Fatalf("malformed reconfigure code=%d envelope=%s", code, raw)
	}
	decodeOKResult(t, raw, &map[string]any{})
	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("malformed reconfigure replaced prior runtime: %+v", route)
	}
	status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	if status["mode"] != "balanced" || status["last_reconfigure_error"] != "invalid lifecycle request" {
		t.Fatalf("malformed reconfigure status=%#v", status)
	}
}

func TestRuleLoadFailureDuringReconfigureKeepsPreviousRuntime(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	originalLoader := p.loadRules
	p.loadRules = func() (*rules.RuleSet, error) { return nil, errors.New("injected rule loader failure") }
	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t, "mode: audit\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"))
	p.loadRules = originalLoader
	if code != 0 {
		t.Fatalf("rule-load reconfigure code=%d envelope=%s", code, raw)
	}
	decodeOKResult(t, raw, &map[string]any{})
	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("rule load failure weakened the previous balanced runtime: %+v", route)
	}
	status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	if status["mode"] != "balanced" || !strings.Contains(status["last_reconfigure_error"].(string), "load rules") {
		t.Fatalf("rule load failure status=%#v", status)
	}
}

func TestConcurrentRouterErrorsAndHealthSnapshotsAreAtomic(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	const workers = 12
	const iterations = 40
	var failures atomic.Uint64
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				raw, code := p.Call(pluginabi.MethodModelRoute, []byte(`{"broken"`))
				if code != 0 {
					failures.Add(1)
					continue
				}
				var envelope struct {
					OK     bool `json:"ok"`
					Result struct {
						Handled    bool                           `json:"Handled"`
						TargetKind pluginapi.ModelRouteTargetKind `json:"TargetKind"`
					} `json:"result"`
				}
				if err := json.Unmarshal(raw, &envelope); err != nil || !envelope.OK || !envelope.Result.Handled || envelope.Result.TargetKind != pluginapi.ModelRouteTargetSelf {
					failures.Add(1)
				}
			}
		}()
	}
	for worker := 0; worker < 4; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < iterations; iteration++ {
				callManagementNoFail(p, authenticatedManagementRequest(http.MethodGet, managementBasePath+"/status", nil))
			}
		}()
	}
	wait.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d concurrent malformed routes did not fail closed", failures.Load())
	}
	if got, want := p.counters.routerErrors.Load(), uint64(workers*iterations); got != want {
		t.Fatalf("router_errors=%d, want %d", got, want)
	}
}

func TestOpaqueMediaPolicyIsModeAwareAndNeverFetchesURLs(t *testing.T) {
	const body = `{"model":"gpt-test","messages":[{"role":"user","content":[{"type":"text","text":"Describe this ordinary image."},{"type":"image_url","image_url":{"url":"https://example.test/image.png"}}]}]}`
	for _, testCase := range []struct {
		name          string
		configuration string
		wantHandled   bool
		wantCounter   string
	}{
		{name: "balanced default audits", configuration: "mode: balanced", wantHandled: false, wantCounter: "opaque_media_audited"},
		{name: "strict default blocks", configuration: "mode: strict", wantHandled: true, wantCounter: "opaque_media_blocked"},
		{name: "strict explicit allow", configuration: "mode: strict\nopaque_media_policy: allow", wantHandled: false, wantCounter: "opaque_media_allowed"},
		{name: "balanced explicit block", configuration: "mode: balanced\nopaque_media_policy: block", wantHandled: true, wantCounter: "opaque_media_blocked"},
		{name: "observe never enforces", configuration: "mode: observe\nopaque_media_policy: block", wantHandled: false, wantCounter: "opaque_media_audited"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			register(t, p, testCase.configuration+"\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
			route := callRoute(t, p, body)
			if route.Handled != testCase.wantHandled {
				t.Fatalf("route=%+v, want handled=%v", route, testCase.wantHandled)
			}
			if testCase.wantHandled && (route.TargetKind != pluginapi.ModelRouteTargetSelf || route.Reason != "cyber_abuse_guard_opaque_media") {
				t.Fatalf("opaque-media block was not a local self-route: %+v", route)
			}
			if got := p.counters.snapshot()[testCase.wantCounter]; got != 1 {
				t.Fatalf("%s=%d, want 1; counters=%v", testCase.wantCounter, got, p.counters.snapshot())
			}
			if got := p.counters.opaqueMediaHTTPSImageURL.Load(); got != 1 {
				t.Fatalf("opaque_media_https_image_url=%d, want 1; counters=%v", got, p.counters.snapshot())
			}
		})
	}
}

func TestIncompleteDispositionDoesNotCountOpaquePolicyBlock(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\nmax_scan_bytes: 16384\nmax_total_text_bytes: 16384\nopaque_media_policy: block\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	body := `{"input":[{"type":"input_image","image_url":"data:image/png;base64,AAAA"},{"type":"input_text","text":"` + strings.Repeat("x", (16<<10)+1) + `"}]}`
	if route := callRoute(t, p, body); route.Handled {
		t.Fatalf("balanced incomplete+opaque request was blocked: %+v", route)
	}
	if got := p.counters.opaqueMediaBlocked.Load(); got != 0 {
		t.Fatalf("opaque_media_blocked=%d, want 0 for incomplete-primary disposition", got)
	}
	if got := p.counters.opaqueMediaAudited.Load(); got != 1 {
		t.Fatalf("opaque_media_audited=%d, want 1", got)
	}
}
