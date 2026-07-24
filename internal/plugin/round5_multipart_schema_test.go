package plugin

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
)

func TestBalancedMultipartUnknownFileFieldAllowsAndAuditsWithoutClassification(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := t.TempDir()
	register(t, p, round5MultipartConfig("balanced", dataDir, true))
	disableClassifierForIncompletePath(t, p)

	body, contentType, canaries := round5UnknownFileMultipartBody(t, true)
	headers := round5MultipartHeaders(contentType)
	subjectHash := p.identifier.FromHeaders(headers).Hash
	route, raw := round5CallMultipartRoute(t, p, body, headers)
	if route.Handled || route.Reason != "" {
		t.Fatalf("balanced route=%+v, want allow+audit", route)
	}
	if _, present := p.runtime.Load().subject.Snapshot(subjectHash); present {
		t.Fatal("balanced multipart incomplete request mutated subject state")
	}
	if got := p.counters.incompleteMultipartSchema.Load(); got != 1 {
		t.Fatalf("incomplete multipart schema=%d, want 1", got)
	}
	if got := p.counters.incompleteAllowed.Load(); got != 1 {
		t.Fatalf("incomplete allowed=%d, want 1", got)
	}
	if got := p.counters.incompleteBlocked.Load(); got != 0 {
		t.Fatalf("incomplete blocked=%d, want 0", got)
	}
	if got := p.counters.opaqueMedia.Load(); got != 1 {
		t.Fatalf("opaque media=%d, want 1", got)
	}
	if got := p.counters.opaqueMediaAllowed.Load(); got != 1 {
		t.Fatalf("opaque media allowed=%d, want 1", got)
	}
	events := round5AssertMultipartSchemaAudit(t, p, "audit")
	round5AssertMultipartPrivacy(t, canaries, raw, events, p.counters.snapshot())
}

func TestStrictMultipartUnknownFileFieldBlocksEvenWhenOpaquePolicyAllows(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, round5MultipartConfig("strict", t.TempDir(), false))
	disableClassifierForIncompletePath(t, p)

	body, contentType, canaries := round5UnknownFileMultipartBody(t, false)
	headers := round5MultipartHeaders(contentType)
	subjectHash := p.identifier.FromHeaders(headers).Hash
	route, raw := round5CallMultipartRoute(t, p, body, headers)
	if !route.Handled || route.TargetKind != pluginapi.ModelRouteTargetSelf || route.Reason != "cyber_abuse_guard_multipart_schema" {
		t.Fatalf("strict route=%+v, want local multipart schema block", route)
	}
	if _, present := p.runtime.Load().subject.Snapshot(subjectHash); present {
		t.Fatal("strict multipart incomplete request mutated subject state")
	}
	if got := p.counters.incompleteMultipartSchema.Load(); got != 1 {
		t.Fatalf("incomplete multipart schema=%d, want 1", got)
	}
	if got := p.counters.incompleteBlocked.Load(); got != 1 {
		t.Fatalf("incomplete blocked=%d, want 1", got)
	}
	if got := p.counters.opaqueMedia.Load(); got != 1 {
		t.Fatalf("opaque media=%d, want 1", got)
	}
	if got := p.counters.opaqueMediaAllowed.Load(); got != 1 {
		t.Fatalf("opaque media allowed=%d, want 1", got)
	}
	if got := p.counters.parseErrors.Load(); got != 0 {
		t.Fatalf("parse errors=%d, want 0", got)
	}
	round5AssertMultipartPrivacy(t, canaries, raw, p.counters.snapshot())
}

func TestMultipartUnknownFileFieldAuditIsFixedAndPrivate(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	for _, testCase := range []struct {
		mode         string
		unknownFirst bool
		wantAction   string
		wantHandled  bool
		wantReason   string
	}{
		{mode: "balanced", unknownFirst: true, wantAction: "audit"},
		{mode: "strict", unknownFirst: false, wantAction: "block", wantHandled: true, wantReason: "cyber_abuse_guard_multipart_schema"},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			dataDir := t.TempDir()
			register(t, p, round5MultipartConfig(testCase.mode, dataDir, true))
			disableClassifierForIncompletePath(t, p)

			body, contentType, canaries := round5UnknownFileMultipartBody(t, testCase.unknownFirst)
			route, raw := round5CallMultipartRoute(t, p, body, round5MultipartHeaders(contentType))
			if route.Handled != testCase.wantHandled || route.Reason != testCase.wantReason {
				t.Fatalf("route=%+v, want handled=%t reason=%q", route, testCase.wantHandled, testCase.wantReason)
			}
			events := round5AssertMultipartSchemaAudit(t, p, testCase.wantAction)
			status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
			round5AssertMultipartPrivacy(t, canaries, raw, events, status, p.counters.snapshot())

			p.Shutdown()
			artifacts, err := filepath.Glob(filepath.Join(dataDir, "events.db*"))
			if err != nil {
				t.Fatal(err)
			}
			if len(artifacts) == 0 {
				t.Fatal("audit database artifacts were not created")
			}
			for _, artifact := range artifacts {
				data, err := os.ReadFile(artifact)
				if err != nil {
					t.Fatalf("read audit artifact %q: %v", artifact, err)
				}
				round5AssertNoMultipartCanaries(t, canaries, data)
			}
		})
	}
}

func round5MultipartConfig(mode, dataDir string, auditEnabled bool) string {
	enabled := "false"
	if auditEnabled {
		enabled = "true"
	}
	return "mode: " + mode + "\n" +
		"opaque_media_policy: allow\n" +
		"audit:\n" +
		"  enabled: " + enabled + "\n" +
		"  data_dir: \"" + filepath.ToSlash(dataDir) + "\"\n" +
		"subject_control:\n" +
		"  enabled: true\n"
}

func round5UnknownFileMultipartBody(t testing.TB, unknownFirst bool) ([]byte, string, []string) {
	t.Helper()
	const (
		boundary      = "round5-private-boundary-canary"
		fieldName     = "round5_private_unknown_field_canary"
		filename      = "round5-private-filename-canary.bin"
		mediaType     = "application/x-round5-private-mime-canary"
		payload       = "ROUND5_PRIVATE_MULTIPART_PAYLOAD_CANARY"
		headerName    = "X-Round5-Private-Header-Canary"
		headerValue   = "ROUND5_PRIVATE_MULTIPART_HEADER_VALUE_CANARY"
		prompt        = "ROUND5_PRIVATE_SAFE_PROMPT_CANARY"
		authorization = "ROUND5_PRIVATE_AUTHORIZATION_CANARY"
		model         = "ROUND5_PRIVATE_MODEL_CANARY"
	)

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	if err := writer.SetBoundary(boundary); err != nil {
		t.Fatal(err)
	}
	writeUnknown := func() {
		header := make(textproto.MIMEHeader)
		header.Set("Content-Disposition", `form-data; name="`+fieldName+`"; filename="`+filename+`"`)
		header.Set("Content-Type", mediaType)
		header.Set(headerName, headerValue)
		part, err := writer.CreatePart(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(payload)); err != nil {
			t.Fatal(err)
		}
	}
	writePrompt := func() {
		header := make(textproto.MIMEHeader)
		header.Set("Content-Disposition", `form-data; name="prompt"`)
		header.Set("Content-Type", "text/plain; charset=utf-8")
		part, err := writer.CreatePart(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(prompt)); err != nil {
			t.Fatal(err)
		}
	}
	if unknownFirst {
		writeUnknown()
		writePrompt()
	} else {
		writePrompt()
		writeUnknown()
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), writer.FormDataContentType(), []string{
		boundary,
		fieldName,
		filename,
		mediaType,
		payload,
		headerName,
		headerValue,
		prompt,
		authorization,
		model,
	}
}

func round5MultipartHeaders(contentType string) http.Header {
	return http.Header{
		"Content-Type":  []string{contentType},
		"Authorization": []string{"Bearer ROUND5_PRIVATE_AUTHORIZATION_CANARY"},
	}
}

func round5CallMultipartRoute(t testing.TB, p *Plugin, body []byte, headers http.Header) (pluginapi.ModelRouteResponse, []byte) {
	t.Helper()
	req := pluginapi.ModelRouteRequest{
		SourceFormat:   "openai-image",
		RequestedModel: "ROUND5_PRIVATE_MODEL_CANARY",
		Headers:        headers,
		Body:           body,
	}
	rawReq, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, code := p.Call(pluginabi.MethodModelRoute, rawReq)
	if code != 0 {
		t.Fatalf("model.route code=%d envelope_bytes=%d", code, len(raw))
	}
	var route pluginapi.ModelRouteResponse
	decodeOKResult(t, raw, &route)
	return route, raw
}

func round5AssertMultipartSchemaAudit(t testing.TB, p *Plugin, wantAction string) map[string]any {
	t.Helper()
	events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	items, ok := events["events"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("audit event list valid=%t count=%d, want one", ok, len(items))
	}
	event, ok := items[0].(map[string]any)
	if !ok {
		t.Fatal("audit event was not an object")
	}
	if event["category"] != "multipart_schema" || event["action"] != wantAction || event["source_format"] != "openai-image" || event["risk_score"] != float64(0) {
		t.Fatalf(
			"audit event mismatch category_ok=%t action_ok=%t source_ok=%t score_ok=%t",
			event["category"] == "multipart_schema",
			event["action"] == wantAction,
			event["source_format"] == "openai-image",
			event["risk_score"] == float64(0),
		)
	}
	if rawRuleIDs, present := event["rule_ids"]; present {
		if ruleIDs, ok := rawRuleIDs.([]any); !ok || len(ruleIDs) != 0 {
			t.Fatalf("multipart incomplete event persisted rule IDs: %#v", rawRuleIDs)
		}
	}
	return events
}

func round5AssertMultipartPrivacy(t testing.TB, canaries []string, surfaces ...any) {
	t.Helper()
	for _, surface := range surfaces {
		var encoded []byte
		switch value := surface.(type) {
		case []byte:
			encoded = value
		case string:
			encoded = []byte(value)
		default:
			var err error
			encoded, err = json.Marshal(surface)
			if err != nil {
				t.Fatal(err)
			}
		}
		round5AssertNoMultipartCanaries(t, canaries, encoded)
	}
}

func round5AssertNoMultipartCanaries(t testing.TB, canaries []string, data []byte) {
	t.Helper()
	for index, canary := range canaries {
		if canary != "" && bytes.Contains(data, []byte(canary)) {
			t.Fatalf("privacy surface leaked multipart canary index %d", index)
		}
	}
}
