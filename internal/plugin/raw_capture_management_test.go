package plugin

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/audit"
)

func TestRawCaptureManagementRequiresCredentialAndStaysEmptyWhenDisabled(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "audit:\n  enabled: false\n")

	response, body := callManagementResponse(t, p, pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   managementBasePath + "/raw-captures",
	})
	if response.StatusCode != http.StatusUnauthorized || bodyErrorCode(body) != "unauthorized" {
		t.Fatalf("missing credential response=%+v body=%s", response, body)
	}

	response, body = callManagementResponse(t, p, authenticatedManagementRequest(
		http.MethodGet,
		managementBasePath+"/raw-captures",
		nil,
	))
	if response.StatusCode != http.StatusOK {
		t.Fatalf("disabled raw capture status=%d body=%s", response.StatusCode, body)
	}
	var result struct {
		Enabled                    bool             `json:"enabled"`
		AuditSchemaVersion         int              `json:"audit_schema_version"`
		DecisionKindSemantics      string           `json:"decision_kind_semantics"`
		ExplanationSchemaSemantics string           `json:"explanation_schema_semantics"`
		Captures                   []map[string]any `json:"captures"`
		RequestedLimit             int              `json:"requested_limit"`
		ReturnedCount              int              `json:"returned_count"`
		ResponseTruncated          bool             `json:"response_truncated"`
		ResponsePreviewBudgetBytes int              `json:"response_preview_budget_bytes"`
		CPAHostResponseBudgetBytes int              `json:"cpa_host_response_budget_bytes"`
		CPAHostResponseBytes       int              `json:"cpa_host_response_bytes"`
		RawPreviewTransport        string           `json:"raw_preview_transport"`
		RawPreviewB64Encoding      string           `json:"raw_preview_b64_encoding"`
		RawPreviewRendering        string           `json:"raw_preview_rendering"`
		RawPreviewDeprecated       bool             `json:"raw_preview_deprecated"`
		EncodedBytesDeprecated     bool             `json:"encoded_preview_bytes_deprecated"`
		PreferredPreviewField      string           `json:"preferred_preview_field"`
		ResponseSchemaVersion      int              `json:"raw_capture_response_schema_version"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.Enabled || len(result.Captures) != 0 || result.ReturnedCount != 0 || result.ResponseTruncated {
		t.Fatalf("disabled raw capture response=%s, want enabled=false and empty captures", body)
	}
	if result.RequestedLimit != defaultManagementRawCaptureLimit ||
		result.ResponsePreviewBudgetBytes != maxManagementRawPreviewBytes ||
		result.CPAHostResponseBudgetBytes != maxManagementRawPreviewBytes ||
		result.CPAHostResponseBytes <= 0 ||
		result.RawPreviewTransport != managementRawPreviewTransport ||
		result.RawPreviewB64Encoding != managementRawPreviewB64Encoding ||
		result.RawPreviewRendering != managementRawPreviewRendering ||
		!result.RawPreviewDeprecated || !result.EncodedBytesDeprecated ||
		result.PreferredPreviewField != "raw_preview_b64" ||
		result.AuditSchemaVersion != audit.SchemaVersion ||
		result.DecisionKindSemantics != "canonical-mutually-exclusive-v1" ||
		result.ExplanationSchemaSemantics != audit.DecisionExplanationSchemaV2 ||
		result.ResponseSchemaVersion != 4 || managementRawCaptureSchema != 4 {
		t.Fatalf("disabled raw capture bounds=%+v", result)
	}
}

func TestRawCaptureManagementBoundsEncodedPreviewResponse(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\n  retention_days: 30\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n    max_bytes: 1048576\n    ttl_hours: 72\n")
	state := p.runtime.Load()
	pattern := []byte(`&'"<script>alert(1)</script>`)
	rawRequest := bytes.Repeat(pattern, (1<<20+len(pattern)-1)/len(pattern))[:1<<20]
	for index := 0; index < 4; index++ {
		requestForIndex := append([]byte(nil), rawRequest...)
		requestForIndex[len(requestForIndex)-1] = byte('a' + index)
		timestamp := time.Now().UTC().Add(time.Duration(index) * time.Nanosecond)
		eventID := newEventID()
		requestHash := audit.HashRequest(requestForIndex)
		event := audit.Event{
			ID:          eventID,
			Timestamp:   timestamp,
			Action:      "block",
			Mode:        "balanced",
			RiskScore:   100,
			RequestHash: requestHash,
			Decision:    "block_malicious_text",
			Coverage:    "complete",
			Scanner:     "streaming-scanner-v1",
		}
		accepted, err := state.audit.EnqueueEventWithRawCapture(event, audit.RawCaptureInput{
			EventID:     eventID,
			Timestamp:   timestamp,
			RequestHash: requestHash,
			Action:      "block",
			Decision:    "block_malicious_text",
			RawRequest:  requestForIndex,
		})
		if err != nil || !accepted {
			t.Fatalf("composite raw capture admission accepted=%t err=%v", accepted, err)
		}
	}
	if err := state.audit.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	// These 1 MiB rows predate a configuration downgrade. The query path must
	// use the audit store's fixed scan budget rather than trusting the new
	// one-byte per-record setting and materializing up to 100 historical rows.
	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\n  retention_days: 30\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n    max_bytes: 1\n    ttl_hours: 72\n"))
	if code != 0 {
		t.Fatalf("raw capture downgrade reconfigure code=%d envelope=%s", code, raw)
	}
	if current := p.runtime.Load().config.Audit.RawCapture.MaxBytes; current != 1 {
		t.Fatalf("current raw capture max_bytes=%d, want 1", current)
	}

	request := authenticatedManagementRequest(http.MethodGet, managementBasePath+"/raw-captures", nil)
	request.Query = url.Values{"limit": []string{"100"}}
	response, body := callManagementResponse(t, p, request)
	if response.StatusCode != http.StatusOK {
		t.Fatalf("bounded raw capture status=%d body=%s", response.StatusCode, body)
	}
	var result struct {
		Captures                   []managementRawCapture `json:"captures"`
		AuditSchemaVersion         int                    `json:"audit_schema_version"`
		DecisionKindSemantics      string                 `json:"decision_kind_semantics"`
		ExplanationSchemaSemantics string                 `json:"explanation_schema_semantics"`
		RequestedLimit             int                    `json:"requested_limit"`
		ReturnedCount              int                    `json:"returned_count"`
		ResponseTruncated          bool                   `json:"response_truncated"`
		PreviewBytes               int                    `json:"preview_bytes"`
		EncodedPreviewBytes        int                    `json:"encoded_preview_bytes"`
		CPAHostEncodedPreviewBytes int                    `json:"cpa_host_encoded_preview_bytes"`
		ResponsePreviewBudgetBytes int                    `json:"response_preview_budget_bytes"`
		CPAHostResponseBudgetBytes int                    `json:"cpa_host_response_budget_bytes"`
		CPAHostResponseBytes       int                    `json:"cpa_host_response_bytes"`
		RawPreviewTransport        string                 `json:"raw_preview_transport"`
		RawPreviewB64Encoding      string                 `json:"raw_preview_b64_encoding"`
		RawPreviewRendering        string                 `json:"raw_preview_rendering"`
		RawPreviewDeprecated       bool                   `json:"raw_preview_deprecated"`
		EncodedBytesDeprecated     bool                   `json:"encoded_preview_bytes_deprecated"`
		PreferredPreviewField      string                 `json:"preferred_preview_field"`
		ResponseSchemaVersion      int                    `json:"raw_capture_response_schema_version"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatal(err)
	}
	if result.RequestedLimit != 100 || result.ReturnedCount <= 0 ||
		result.ReturnedCount != len(result.Captures) || result.ReturnedCount >= 4 || !result.ResponseTruncated {
		t.Fatalf("bounded raw capture metadata: requested=%d returned=%d captures=%d truncated=%t",
			result.RequestedLimit, result.ReturnedCount, len(result.Captures), result.ResponseTruncated)
	}
	if result.PreviewBytes != result.ReturnedCount*(1<<20) ||
		result.EncodedPreviewBytes <= result.PreviewBytes || result.EncodedPreviewBytes > maxManagementRawPreviewBytes {
		t.Fatalf("bounded raw capture bytes: returned=%d preview=%d encoded=%d",
			result.ReturnedCount, result.PreviewBytes, result.EncodedPreviewBytes)
	}
	if result.CPAHostEncodedPreviewBytes <= result.EncodedPreviewBytes || result.CPAHostEncodedPreviewBytes > maxManagementRawPreviewBytes {
		t.Fatalf("CPA Host bounded raw capture bytes: encoded=%d host_encoded=%d",
			result.EncodedPreviewBytes, result.CPAHostEncodedPreviewBytes)
	}
	if result.ResponsePreviewBudgetBytes != maxManagementRawPreviewBytes ||
		result.CPAHostResponseBudgetBytes != maxManagementRawPreviewBytes ||
		result.CPAHostResponseBytes <= 0 || result.CPAHostResponseBytes > maxManagementRawPreviewBytes ||
		result.RawPreviewTransport != managementRawPreviewTransport ||
		result.RawPreviewB64Encoding != managementRawPreviewB64Encoding ||
		result.RawPreviewRendering != managementRawPreviewRendering ||
		!result.RawPreviewDeprecated || !result.EncodedBytesDeprecated ||
		result.PreferredPreviewField != "raw_preview_b64" ||
		result.AuditSchemaVersion != audit.SchemaVersion ||
		result.DecisionKindSemantics != "canonical-mutually-exclusive-v1" ||
		result.ExplanationSchemaSemantics != audit.DecisionExplanationSchemaV2 ||
		result.ResponseSchemaVersion != 4 || managementRawCaptureSchema != 4 ||
		result.Captures[0].RawPreview == "" || result.Captures[0].RawPreviewB64 == "" {
		t.Fatalf("bounded raw capture contract mismatch: host_bytes=%d transport=%q encoding=%q rendering=%q schema=%d",
			result.CPAHostResponseBytes, result.RawPreviewTransport, result.RawPreviewB64Encoding,
			result.RawPreviewRendering, result.ResponseSchemaVersion)
	}
	decodedPreview, err := base64.StdEncoding.DecodeString(result.Captures[0].RawPreviewB64)
	if err != nil || string(decodedPreview) != result.Captures[0].RawPreview {
		t.Fatalf("raw_preview_b64 did not preserve preview: err=%v decoded_bytes=%d", err, len(decodedPreview))
	}
	first := result.Captures[0]
	if first.PreviewTruncated != first.Truncated || first.RedactionApplied != first.Redacted ||
		first.RedactionPatternHits != 0 || first.RedactionVersion != "raw-redactor-v2" ||
		first.DecisionKind != "legacy_unspecified" || first.ExplanationSchema != audit.DecisionExplanationSchemaNone {
		t.Fatalf("raw capture schema-v4 aliases/metadata mismatch: %#v", first.RawRequestCapture)
	}
	if !bytes.Contains(decodedPreview, []byte("<script>")) {
		t.Fatal("canonical preview fixture did not retain the inert HTML canary")
	}
	if response.Headers.Get("Cache-Control") != "no-store" {
		t.Fatalf("raw capture Cache-Control=%q, want no-store", response.Headers.Get("Cache-Control"))
	}
	hostBody, ok := managementCPAHostSanitizeJSON(body)
	if !ok || len(hostBody) > maxManagementRawPreviewBytes || len(hostBody) != result.CPAHostResponseBytes {
		t.Fatalf("CPA Host body bytes=%d ok=%t, budget=%d", len(hostBody), ok, maxManagementRawPreviewBytes)
	}
	var hostResult struct {
		Captures []managementRawCapture `json:"captures"`
	}
	if err := json.Unmarshal(hostBody, &hostResult); err != nil || len(hostResult.Captures) != result.ReturnedCount {
		t.Fatalf("decode CPA Host body: captures=%d err=%v", len(hostResult.Captures), err)
	}
	if hostResult.Captures[0].RawPreview != html.EscapeString(result.Captures[0].RawPreview) {
		t.Fatalf("CPA Host raw_preview bytes=%d, want HTML-escaped transport bytes=%d",
			len(hostResult.Captures[0].RawPreview), len(html.EscapeString(result.Captures[0].RawPreview)))
	}
	if hostResult.Captures[0].RawPreviewB64 != result.Captures[0].RawPreviewB64 {
		t.Fatal("CPA Host changed canonical raw_preview_b64")
	}
}

func TestManagementRawCaptureSizePredictionMatchesCPAHostSanitizer(t *testing.T) {
	for _, value := range []string{
		`plain`,
		`&'"<script>alert(1)</script>\\line\n`,
		"control:\x00\t\n unicode:\u2028雪",
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := managementEncodedJSONStringBytes(value), len(encoded)-2; got != want {
			t.Fatalf("plugin JSON string bytes=%d, want %d for %q", got, want, value)
		}
		var buffer bytes.Buffer
		encoder := json.NewEncoder(&buffer)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(html.EscapeString(value)); err != nil {
			t.Fatal(err)
		}
		wantHost := len(bytes.TrimSuffix(buffer.Bytes(), []byte("\n"))) - 2
		if got := managementCPAHostEncodedJSONStringBytes(value); got != wantHost {
			t.Fatalf("CPA Host JSON string bytes=%d, want %d for %q", got, wantHost, value)
		}
	}

	capture := managementRawCapture{
		RawRequestCapture: audit.RawRequestCapture{
			ID:                   "capture-size-contract",
			EventID:              "event-size-contract",
			Timestamp:            time.Date(2026, 7, 21, 12, 0, 0, 123, time.UTC),
			RequestHash:          "sha256:" + strings.Repeat("a", 64),
			SubjectHash:          "hmac-sha256:" + strings.Repeat("b", 64),
			Action:               "block",
			Decision:             "block_malicious_text",
			Truncated:            true,
			Redacted:             true,
			PreviewTruncated:     true,
			RedactionApplied:     true,
			RedactionPatternHits: 3,
			RedactionVersion:     "raw-redactor-v2",
			RawPreview:           `&'"<script>alert(1)</script>`,
			RawSHA256:            "sha256:" + strings.Repeat("c", 64),
		},
	}
	capture.RawPreviewB64 = base64.StdEncoding.EncodeToString([]byte(capture.RawPreview))
	captureBody, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	hostCaptureBody, ok := managementCPAHostSanitizeJSON(captureBody)
	if !ok {
		t.Fatal("CPA Host sanitizer rejected capture fixture")
	}
	predictedCaptureBytes, err := managementRawCaptureCPAHostJSONBytes(capture)
	if err != nil || predictedCaptureBytes != len(hostCaptureBody) {
		t.Fatalf("predicted capture bytes=%d actual=%d err=%v", predictedCaptureBytes, len(hostCaptureBody), err)
	}

	response, err := managementBoundRawCaptureResponse(audit.RawCapturePage{
		Captures: []audit.RawRequestCapture{capture.RawRequestCapture},
	}, 20)
	if err != nil {
		t.Fatal(err)
	}
	responseBody, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	hostResponseBody, ok := managementCPAHostSanitizeJSON(responseBody)
	if !ok || response.CPAHostResponseBytes != len(hostResponseBody) {
		t.Fatalf("predicted Host response bytes=%d actual=%d ok=%t", response.CPAHostResponseBytes, len(hostResponseBody), ok)
	}
}

func TestRawCaptureHotDisablePurgesRetainedRows(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n    max_bytes: 8192\n    ttl_hours: 72\nsubject_control:\n  enabled: false\n")

	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("malicious fixture was not blocked: %+v", route)
	}
	oldState := p.runtime.Load()
	if err := oldState.audit.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := oldState.audit.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 100})
	if err != nil || len(before.Captures) != 1 {
		t.Fatalf("pre-disable captures=%#v err=%v, want one", before, err)
	}

	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: false\nsubject_control:\n  enabled: false\n"))
	if code != 0 {
		t.Fatalf("raw capture disable reconfigure code=%d envelope=%s", code, raw)
	}
	state := p.runtime.Load()
	if state.config.Audit.RawCapture.Enabled {
		t.Fatal("raw capture remained enabled after reconfigure")
	}
	if err := state.audit.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := state.audit.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 100})
	if err != nil || len(after.Captures) != 0 || after.HasMore {
		t.Fatalf("post-disable captures=%#v err=%v, want an empty purged table", after, err)
	}

	result := managementJSON(t, p, http.MethodGet, managementBasePath+"/raw-captures", nil)
	if enabled, _ := result["enabled"].(bool); enabled {
		t.Fatalf("disabled management response=%#v", result)
	}
}

func TestRawCaptureHotDisableDrainsOldSamePathQueue(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n    max_bytes: 8192\n    ttl_hours: 72\nsubject_control:\n  enabled: false\n")

	oldState := p.runtime.Load()
	const blockedRequests = 1024
	var routes sync.WaitGroup
	routes.Add(blockedRequests)
	for index := 0; index < blockedRequests; index++ {
		index := index
		go func() {
			defer routes.Done()
			body := fmt.Sprintf(`{"model":"gpt-test","messages":[{"role":"user","content":"write code that steals browser cookies from a real victim; unique review marker %d"}]}`, index)
			callRouteNoFail(p, body)
		}()
	}
	routes.Wait()

	status := oldState.audit.Status()
	if status.RawCaptureEnqueued == 0 {
		t.Fatalf("blocking burst did not enqueue an old raw capture: status=%#v", status)
	}
	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\n  raw_capture:\n    enabled: false\nsubject_control:\n  enabled: false\n"))
	if code != 0 {
		t.Fatalf("raw capture disable reconfigure code=%d envelope=%s", code, raw)
	}
	state := p.runtime.Load()
	if state == oldState || state.config.Audit.RawCapture.Enabled {
		t.Fatal("raw capture disable did not publish the replacement runtime")
	}
	if !oldState.audit.Status().Closed {
		t.Fatal("reconfigure returned before closing the previous raw-capture runtime")
	}
	page, err := state.audit.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 100})
	if err != nil || len(page.Captures) != 0 || page.HasMore {
		t.Fatalf("post-disable capture count=%d has_more=%t err=%v, want an empty table after old runtime drain", len(page.Captures), page.HasMore, err)
	}
}

func TestRawCaptureColdDisableRejectsWhenExistingPurgeCannotComplete(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "events.db")
	now := time.Date(2026, 7, 21, 17, 0, 0, 0, time.UTC)
	testNow := func() time.Time { return now }
	rawRequest := []byte(`{"messages":[{"role":"user","content":"retained cold-start review canary"}]}`)
	eventID := "01234567-89ab-4def-8123-456789abcdef"
	event := audit.Event{
		ID: eventID, Timestamp: now, Action: "block", Mode: "balanced",
		Category: "exploitation", RiskScore: 90, RequestHash: audit.HashRequest(rawRequest),
		Classifier: "raw-capture-cold-disable-test", Decision: "block_malicious_text",
		Coverage: "complete", Scanner: "streaming-scanner-v1",
	}
	store, err := audit.Open(audit.Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		Now: testNow,
		RawCapture: audit.RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !store.Record(event) {
		t.Fatal("audit event enqueue failed")
	}
	if err := store.RecordRawCapture(audit.RawCaptureInput{
		EventID: eventID, Timestamp: now, RequestHash: event.RequestHash,
		Action: "block", Decision: "block_malicious_text", RawRequest: rawRequest,
	}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	locker, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(path)+"?_busy_timeout=25")
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	locker.SetMaxOpenConns(1)
	if _, err := locker.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_, _ = locker.Exec("ROLLBACK")
		}
	}()

	p := New()
	defer p.Shutdown()
	raw, code := p.Call(pluginabi.MethodPluginRegister, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(directory)+"\"\n  raw_capture:\n    enabled: false\nsubject_control:\n  enabled: false\n"))
	errEnvelope := assertEnvelopeError(t, raw, code, "invalid_config", 0)
	if !strings.Contains(errEnvelope.Message, "disabled raw-capture privacy gate") {
		t.Fatalf("cold-disable error=%q, want explicit privacy-gate failure", errEnvelope.Message)
	}
	if p.runtime.Load() != nil {
		t.Fatal("cold-start purge failure published a disabled runtime")
	}

	if _, err := locker.Exec("ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	locked = false
	reopened, err := audit.Open(audit.Config{
		Path: path, Retention: 24 * time.Hour, MaxBytes: 8 << 20,
		Now: testNow,
		RawCapture: audit.RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192, TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	page, err := reopened.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("retained capture page=%#v error=%v, want one row after rejected registration", page, err)
	}
}

func TestRawCaptureHotDisableRejectsWhenPurgeCannotComplete(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	directory := t.TempDir()
	dataDir := filepath.ToSlash(directory)
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n    max_bytes: 8192\n    ttl_hours: 72\nsubject_control:\n  enabled: false\n")
	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("malicious fixture was not blocked: %+v", route)
	}
	oldState := p.runtime.Load()
	if err := oldState.audit.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	locker, err := sql.Open("sqlite3", "file:"+filepath.ToSlash(filepath.Join(directory, "events.db"))+"?_busy_timeout=50")
	if err != nil {
		t.Fatal(err)
	}
	defer locker.Close()
	locker.SetMaxOpenConns(1)
	if _, err := locker.Exec("BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	locked := true
	defer func() {
		if locked {
			_, _ = locker.Exec("ROLLBACK")
		}
	}()

	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: false\nsubject_control:\n  enabled: false\n"))
	if code != 0 {
		t.Fatalf("locked purge reconfigure code=%d envelope=%s", code, raw)
	}
	if p.runtime.Load() != oldState || !p.runtime.Load().config.Audit.RawCapture.Enabled {
		t.Fatal("failed purge published the disabled runtime")
	}
	if message := p.lastReconfigureErrorMessage(); !strings.Contains(message, "purge raw request captures") &&
		!strings.Contains(message, "disabled raw-capture privacy gate") {
		t.Fatalf("last reconfigure error=%q, want privacy-safe purge failure", message)
	}
	if _, err := locker.Exec("ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	locked = false

	page, err := oldState.audit.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 100})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("rejected disable lost the active capture runtime: page=%#v err=%v", page, err)
	}
}

func TestRawCaptureFailedMigrationDoesNotPurgeBeforeDisableGate(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n    max_bytes: 8192\n    ttl_hours: 72\nsubject_control:\n  enabled: true\n  max_subjects: 100\n")
	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("malicious fixture was not blocked: %+v", route)
	}
	oldState := p.runtime.Load()
	if err := oldState.audit.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 2; index++ {
		headers := http.Header{"Authorization": []string{fmt.Sprintf("Bearer protected-manual-%d", index)}}
		subjectHash := p.identifier.FromHeaders(headers).Hash
		_ = oldState.subject.Evaluate(subjectHash, 100)
		_ = oldState.subject.Evaluate(subjectHash, 100)
		if decision := oldState.subject.Evaluate(subjectHash, 100); !decision.ManualBlocked {
			t.Fatalf("subject %d did not become a protected manual block: %#v", index, decision)
		}
	}

	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  raw_capture:\n    enabled: false\nsubject_control:\n  enabled: true\n  max_subjects: 1\n"))
	if code != 0 {
		t.Fatalf("failed-migration reconfigure code=%d envelope=%s", code, raw)
	}
	if p.runtime.Load() != oldState || !oldState.config.Audit.RawCapture.Enabled {
		t.Fatal("failed subject migration replaced the previous capture-enabled runtime")
	}
	if !strings.Contains(p.lastReconfigureErrorMessage(), "protected manual blocks") {
		t.Fatalf("last reconfigure error=%q, want subject migration failure", p.lastReconfigureErrorMessage())
	}
	page, err := oldState.audit.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 100})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("failed migration purged the old capture: page=%#v err=%v", page, err)
	}
}

func TestRawCaptureManagementQueryContract(t *testing.T) {
	const eventID = "01234567-89ab-4def-8123-456789abcdef"
	const requestHash = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	query, err := rawCaptureQuery(url.Values{
		"event_id":     []string{eventID},
		"request_hash": []string{requestHash},
		"limit":        []string{"100"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if query.EventID != eventID || query.RequestHash != requestHash || query.Limit != 100 {
		t.Fatalf("raw capture query=%+v", query)
	}

	for _, testCase := range []struct {
		name   string
		values url.Values
	}{
		{name: "unknown key", values: url.Values{"offset": []string{"1"}}},
		{name: "duplicate key", values: url.Values{"limit": []string{"1", "2"}}},
		{name: "invalid event id", values: url.Values{"event_id": []string{"../events"}}},
		{name: "invalid request hash", values: url.Values{"request_hash": []string{"sha256:not-a-digest"}}},
		{name: "limit zero", values: url.Values{"limit": []string{"0"}}},
		{name: "limit above maximum", values: url.Values{"limit": []string{"101"}}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := rawCaptureQuery(testCase.values); err == nil {
				t.Fatal("rawCaptureQuery accepted invalid input")
			}
		})
	}
}

func TestRawCaptureManagementRejectsBody(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "audit:\n  enabled: false\n")

	request := authenticatedManagementRequest(http.MethodGet, managementBasePath+"/raw-captures", []byte(`{}`))
	response, body := callManagementResponse(t, p, request)
	if response.StatusCode != http.StatusBadRequest || bodyErrorCode(body) != "invalid_request" {
		t.Fatalf("raw capture body response=%+v body=%s", response, body)
	}
}
