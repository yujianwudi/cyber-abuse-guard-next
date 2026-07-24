package cpalatestcontract

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const rawCaptureManagementHostOverlayTest = `package pluginhost

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
)

func TestCyberAbuseGuardRawCaptureManagementHostContract(t *testing.T) {
	preview := strings.Repeat("&'\"<>", ((1<<20)+4)/5)[:1<<20]
	previewB64 := base64.StdEncoding.EncodeToString([]byte(preview))
	body, err := json.Marshal(map[string]any{
		"enabled": true,
		"captures": []map[string]any{{
			"id": "capture-id",
			"event_id": "01234567-89ab-4def-8123-456789abcdef",
			"raw_preview": preview,
			"raw_preview_b64": previewB64,
		}},
		"raw_preview_transport": "cpa-json-html-escaped-utf8",
		"raw_preview_b64_encoding": "base64-standard-utf8",
		"raw_preview_rendering": "text-only-never-html",
		"raw_preview_deprecated": true,
		"encoded_preview_bytes_deprecated": true,
		"preferred_preview_field": "raw_preview_b64",
		"raw_capture_response_schema_version": 2,
		"cpa_host_response_budget_bytes": 8 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}

	host := newHostWithRecords(capabilityRecord{
		id: "cyber-abuse-guard",
		priority: 300,
		plugin: pluginapi.Plugin{Capabilities: pluginapi.Capabilities{
			ManagementAPI: &managementPluginDouble{routes: []pluginapi.ManagementRoute{{
				Method: http.MethodGet,
				Path: "/plugins/cyber-abuse-guard/raw-captures",
				Handler: managementHandlerFunc(func(context.Context, pluginapi.ManagementRequest) (pluginapi.ManagementResponse, error) {
					return pluginapi.ManagementResponse{
						StatusCode: http.StatusOK,
						Headers: http.Header{
							"Content-Type": []string{"application/json; charset=utf-8"},
							"Cache-Control": []string{"no-store"},
						},
						Body: body,
					}, nil
				}),
			}}},
		}},
	})
	host.RegisterManagementRoutes(context.Background(), nil)

	req := httptest.NewRequest(http.MethodGet, "/v0/management/plugins/cyber-abuse-guard/raw-captures", nil)
	rec := httptest.NewRecorder()
	if !host.ServeManagementHTTP(rec, req) {
		t.Fatal("ServeManagementHTTP() = false, want true")
	}
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response status=%d cache-control=%q", rec.Code, rec.Header().Get("Cache-Control"))
	}
	if rec.Body.Len() <= len(body) {
		t.Fatalf("Host body bytes=%d, want HTML-sanitizer expansion beyond plugin bytes=%d", rec.Body.Len(), len(body))
	}
	if rec.Body.Len() > 8<<20 {
		t.Fatalf("single maximum preview Host body bytes=%d, want <=8MiB", rec.Body.Len())
	}

	var response map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode Host response: %v", err)
	}
	captures, ok := response["captures"].([]any)
	if !ok || len(captures) != 1 {
		t.Fatalf("Host captures=%#v", response["captures"])
	}
	capture, ok := captures[0].(map[string]any)
	if !ok {
		t.Fatalf("Host capture=%#v", captures[0])
	}
	gotPreview, _ := capture["raw_preview"].(string)
	gotPreviewB64, _ := capture["raw_preview_b64"].(string)
	if gotPreview != html.EscapeString(preview) {
		t.Fatal("Host did not apply the expected HTML transport escaping")
	}
	if gotPreviewB64 != previewB64 {
		t.Fatal("Host changed raw_preview_b64")
	}
	decoded, err := base64.StdEncoding.DecodeString(gotPreviewB64)
	if err != nil || string(decoded) != preview {
		t.Fatalf("decode raw_preview_b64: bytes=%d err=%v", len(decoded), err)
	}
	if response["raw_preview_transport"] != "cpa-json-html-escaped-utf8" ||
		response["raw_preview_b64_encoding"] != "base64-standard-utf8" ||
		response["raw_preview_rendering"] != "text-only-never-html" ||
		response["raw_preview_deprecated"] != true ||
		response["encoded_preview_bytes_deprecated"] != true ||
		response["preferred_preview_field"] != "raw_preview_b64" ||
		response["raw_capture_response_schema_version"] != float64(2) {
		t.Fatalf("transport metadata=%+v", response)
	}

	body, err = json.Marshal(map[string]any{
		"enabled": true,
		"captures": []map[string]any{
			{"id": "capture-one", "event_id": "event-one", "raw_preview": preview, "raw_preview_b64": previewB64},
			{"id": "capture-two", "event_id": "event-two", "raw_preview": preview, "raw_preview_b64": previewB64},
		},
		"raw_preview_transport": "cpa-json-html-escaped-utf8",
		"raw_preview_b64_encoding": "base64-standard-utf8",
		"raw_preview_rendering": "text-only-never-html",
		"cpa_host_response_budget_bytes": 8 << 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	if !host.ServeManagementHTTP(rec, req) {
		t.Fatal("ServeManagementHTTP(two previews) = false, want true")
	}
	if rec.Body.Len() <= 8<<20 {
		t.Fatalf("two maximum previews Host body bytes=%d, want >8MiB to exercise plugin truncation boundary", rec.Body.Len())
	}
}
`

func TestLatestCPARawCaptureManagementHostContract(t *testing.T) {
	goBinary, _, module := prepareLatestCPAModule(t)
	moduleCopy := filepath.Join(t.TempDir(), "cpa-raw-capture-management-host-contract")
	if err := os.CopyFS(moduleCopy, os.DirFS(module.Dir)); err != nil {
		t.Fatalf("copy CPA module for raw-capture Host contract: %v", err)
	}
	target := filepath.Join(moduleCopy, "internal", "pluginhost", "cyber_abuse_guard_raw_capture_management_test.go")
	if err := os.WriteFile(target, []byte(strings.ReplaceAll(rawCaptureManagementHostOverlayTest, "\r\n", "\n")), 0o600); err != nil {
		t.Fatalf("write raw-capture Host overlay: %v", err)
	}
	const testName = "TestCyberAbuseGuardRawCaptureManagementHostContract"
	listed := runLatestGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=readonly", "-list", "^"+testName+"$", "./internal/pluginhost")
	if !linePresent(listed, testName) {
		t.Fatalf("CPA Host overlay does not list %q", testName)
	}
	runLatestGoCommandInDir(t, moduleCopy, goBinary,
		"test", "-mod=readonly", "-count=1", "-v", "-run", "^"+testName+"$", "./internal/pluginhost")
}
