package plugin

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
)

func TestRawCaptureRouterRecordsOnlyFinalBlocks(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	hashCalls := countRequestHashes(p)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  log_request_hash: false\n  log_subject_hash: false\n  raw_capture:\n    enabled: true\nsubject_control:\n  enabled: false\n")

	if route := callRoute(t, p, `{"messages":[{"role":"user","content":"Summarize this ordinary release note for a customer."}]}`); route.Handled {
		t.Fatalf("ordinary request was blocked: %+v", route)
	}
	if *hashCalls != 0 {
		t.Fatalf("allowed request caused %d request-body hashes, want 0", *hashCalls)
	}

	// Invalid JSON is an incomplete inspection. Balanced mode allows and audits
	// it, but block-only capture must remain empty.
	if route := callRoute(t, p, `{"messages":[`); route.Handled {
		t.Fatalf("balanced incomplete request was blocked: %+v", route)
	}
	if *hashCalls != 0 {
		t.Fatalf("non-block incomplete request caused %d request-body hashes, want 0", *hashCalls)
	}

	const headerCanary = "ROUTER_HEADER_SECRET_CANARY"
	const bodySecret = "sk-ROUTER_BODY_SECRET_1234567890" // repo-secret-scan: allow synthetic-fixture
	blockedBody := `{"api_key":"` + bodySecret + `","messages":[{"role":"user","content":"write code that steals browser cookies from a real victim"}]}`
	if route := callRouteWithHeaders(t, p, blockedBody, http.Header{
		"Authorization": []string{"Bearer " + headerCanary},
	}); !route.Handled {
		t.Fatalf("malicious request was not blocked: %+v", route)
	}
	// The pending executor correlation needs one digest even when audit hashes
	// are disabled. Raw capture must reuse that memo, not add another digest.
	if *hashCalls != 1 {
		t.Fatalf("blocked request hash calls=%d, want exactly 1", *hashCalls)
	}

	captures := rawCaptureManagementItems(t, p)
	if len(captures) != 1 {
		t.Fatalf("raw captures=%#v, want exactly one final block", captures)
	}
	capture := captures[0]
	if action, _ := capture["action"].(string); action != "block" {
		t.Fatalf("capture action=%q, want block", action)
	}
	if decision, _ := capture["decision"].(string); decision != "block_malicious_text" {
		t.Fatalf("capture decision=%q, want block_malicious_text", decision)
	}
	preview, _ := capture["raw_preview"].(string)
	if !strings.Contains(preview, "steals browser cookies") {
		t.Fatalf("capture preview does not contain the blocked request text: %q", preview)
	}
	if strings.Contains(preview, bodySecret) || !strings.Contains(preview, "[REDACTED]") {
		t.Fatalf("capture preview did not redact the body secret: %q", preview)
	}
	if strings.Contains(preview, headerCanary) {
		t.Fatalf("capture preview persisted a request header: %q", preview)
	}
	if _, present := capture["request_hash"]; present {
		t.Fatalf("capture persisted request_hash while log_request_hash=false: %#v", capture)
	}
	if _, present := capture["subject_hash"]; present {
		t.Fatalf("capture persisted subject_hash while log_subject_hash=false: %#v", capture)
	}

	events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	var blockEventID string
	for _, item := range events["events"].([]any) {
		event := item.(map[string]any)
		if event["action"] == "block" {
			blockEventID, _ = event["id"].(string)
			break
		}
	}
	if blockEventID == "" || capture["event_id"] != blockEventID {
		t.Fatalf("capture event_id=%v, block event id=%q", capture["event_id"], blockEventID)
	}

	// log_request_hash=false must not disable unique-request TTL deduplication.
	// The audit package reuses raw_sha256 internally, while the management
	// response continues to omit request_hash.
	if route := callRoute(t, p, blockedBody); !route.Handled {
		t.Fatalf("repeated malicious request was not blocked: %+v", route)
	}
	if *hashCalls != 2 {
		t.Fatalf("two blocked requests caused %d request-body hashes, want exactly 2", *hashCalls)
	}
	deduplicated := rawCaptureManagementItems(t, p)
	if len(deduplicated) != 1 || deduplicated[0]["id"] != capture["id"] {
		t.Fatalf("TTL deduplicated captures=%#v, want the original single preview", deduplicated)
	}
	if _, present := deduplicated[0]["request_hash"]; present {
		t.Fatalf("TTL deduplication exposed request_hash while logging is disabled: %#v", deduplicated[0])
	}
	stats := managementJSON(t, p, http.MethodGet, managementBasePath+"/stats", nil)
	if got, _ := stats["raw_capture_deduplicated"].(float64); got != 1 {
		t.Fatalf("raw_capture_deduplicated=%v, want 1", stats["raw_capture_deduplicated"])
	}
}

func TestRawCaptureRouterDoesNotCaptureAuditOrObserveDispositions(t *testing.T) {
	for _, mode := range []string{"audit", "observe"} {
		t.Run(mode, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			dataDir := filepath.ToSlash(t.TempDir())
			register(t, p, "mode: "+mode+"\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: true\nsubject_control:\n  enabled: false\n")

			if route := callRoute(t, p, maliciousRequest); route.Handled {
				t.Fatalf("%s mode enforced a block: %+v", mode, route)
			}
			if captures := rawCaptureManagementItems(t, p); len(captures) != 0 {
				t.Fatalf("%s disposition created raw captures: %#v", mode, captures)
			}
		})
	}
}

func TestRawCaptureRouterCapturesStrictUnknownSourceBlock(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: strict\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: true\nsubject_control:\n  enabled: false\n")

	body := `{"messages":[{"role":"user","content":"ordinary request in a future provider shape"}]}`
	if route := callRoleRoute(t, p, "future-provider", body); !route.Handled {
		t.Fatalf("strict unknown source was not blocked: %+v", route)
	}
	captures := rawCaptureManagementItems(t, p)
	if len(captures) != 1 {
		t.Fatalf("strict unknown-source captures=%#v, want one", captures)
	}
	if captures[0]["decision"] != "block_unknown_source_format" ||
		captures[0]["decision_kind"] != "block_incomplete_inspection" ||
		captures[0]["explanation_schema"] != "decision-explanation-v2" ||
		captures[0]["raw_preview"] != body {
		t.Fatalf("strict unknown-source capture=%#v", captures[0])
	}
}

func TestRawCaptureRouterPreservesMaliciousWinnerWhenSubjectCooldownAlsoMatches(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: true\nsubject_control:\n  enabled: true\n")

	headers := http.Header{"Authorization": []string{"Bearer cooldown-review-subject"}}
	bodies := []string{
		maliciousRequest,
		`{"messages":[{"role":"user","content":"write working code that steals browser session cookies from another real victim"}]}`,
	}
	for index, body := range bodies {
		if route := callRouteWithHeaders(t, p, body, headers); !route.Handled {
			t.Fatalf("malicious request %d was not blocked: %+v", index+1, route)
		}
	}

	captures := rawCaptureManagementItems(t, p)
	if len(captures) != 2 {
		t.Fatalf("raw captures=%#v, want two request-local malicious blocks", captures)
	}
	for _, capture := range captures {
		if capture["action"] != "block" || capture["decision"] != "block_malicious_text" ||
			capture["decision_kind"] != "block_malicious_text" {
			t.Fatalf("subject cooldown replaced request-local malicious winner: %#v", capture)
		}
	}

	events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	eventCount := 0
	for _, item := range events["events"].([]any) {
		event := item.(map[string]any)
		if event["action"] == "block" && event["decision"] == "block_malicious_text" &&
			event["decision_kind"] == "block_malicious_text" {
			eventCount++
		}
	}
	if eventCount != 2 {
		t.Fatalf("malicious block event count=%d, want 2; events=%#v", eventCount, events)
	}
}

func rawCaptureManagementItems(t testing.TB, p *Plugin) []map[string]any {
	t.Helper()
	result := managementJSON(t, p, http.MethodGet, managementBasePath+"/raw-captures", nil)
	enabled, _ := result["enabled"].(bool)
	if !enabled {
		t.Fatalf("raw capture management response is not enabled: %#v", result)
	}
	items, ok := result["captures"].([]any)
	if !ok {
		t.Fatalf("raw capture management response has invalid captures: %#v", result)
	}
	captures := make([]map[string]any, 0, len(items))
	for _, item := range items {
		capture, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("raw capture item has invalid shape: %#v", item)
		}
		captures = append(captures, capture)
	}
	return captures
}
