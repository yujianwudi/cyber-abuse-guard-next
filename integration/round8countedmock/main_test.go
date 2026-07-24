package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func request(t *testing.T, client *http.Client, method, url, body string) (int, string) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, string(raw)
}

func TestContractHealthResetAndStats(t *testing.T) {
	mock := &countedMock{}
	server := httptest.NewServer(mock)
	defer server.Close()

	status, raw := request(t, server.Client(), http.MethodGet, server.URL+"/healthz", "")
	if status != http.StatusOK {
		t.Fatalf("health status=%d", status)
	}
	var health map[string]any
	if err := json.Unmarshal([]byte(raw), &health); err != nil {
		t.Fatal(err)
	}
	if health["contract"] != contractName || health["healthy"] != true || health["request_body_retention"] != false {
		t.Fatalf("unexpected health contract: %#v", health)
	}

	mock.total.Store(9)
	status, raw = request(t, server.Client(), http.MethodPost, server.URL+"/__cag/reset", "")
	if status != http.StatusOK || strings.TrimSpace(raw) != `{"total":0}` {
		t.Fatalf("unexpected reset response: status=%d body=%q", status, raw)
	}
	status, raw = request(t, server.Client(), http.MethodGet, server.URL+"/__cag/stats", "")
	if status != http.StatusOK || strings.TrimSpace(raw) != `{"total":0}` {
		t.Fatalf("unexpected stats response: status=%d body=%q", status, raw)
	}
}

func TestBothProtocolsAndTransportsIncrementExactlyOnceWithoutEcho(t *testing.T) {
	mock := &countedMock{}
	server := httptest.NewServer(mock)
	defer server.Close()
	canary := "raw-body-must-never-be-echoed-or-retained"

	for _, path := range []string{"/v1/chat/completions", "/v1/responses"} {
		for _, stream := range []bool{false, true} {
			body := `{"model":"round8-test-model","stream":` + map[bool]string{false: "false", true: "true"}[stream] + `,"input":"` + canary + `"}`
			status, response := request(t, server.Client(), http.MethodPost, server.URL+path, body)
			if status != http.StatusOK {
				t.Fatalf("path=%s stream=%v status=%d", path, stream, status)
			}
			if strings.Contains(response, canary) {
				t.Fatalf("path=%s stream=%v echoed request body", path, stream)
			}
			if stream {
				if !strings.HasSuffix(response, "\n\n") {
					t.Fatalf("path=%s stream has no terminal frame boundary: %q", path, response)
				}
				if path == "/v1/chat/completions" {
					if !strings.HasSuffix(response, "data: [DONE]\n\n") || !strings.Contains(response, `"finish_reason":"stop"`) {
						t.Fatalf("chat stream termination contract mismatch: %q", response)
					}
				} else if !strings.Contains(response, "event: response.output_text.delta\n") || !strings.Contains(response, "event: response.completed\n") || strings.LastIndex(response, "event: response.completed\n") < strings.LastIndex(response, "event: response.output_text.delta\n") {
					t.Fatalf("Responses stream event/termination contract mismatch: %q", response)
				}
				continue
			}
			var payload map[string]any
			if err := json.Unmarshal([]byte(response), &payload); err != nil {
				t.Fatalf("path=%s invalid non-stream JSON: %v", path, err)
			}
			if path == "/v1/chat/completions" {
				choices, ok := payload["choices"].([]any)
				if payload["object"] != "chat.completion" || !ok || len(choices) != 1 || choices[0].(map[string]any)["finish_reason"] != "stop" {
					t.Fatalf("chat non-stream completion contract mismatch: %#v", payload)
				}
			} else if payload["object"] != "response" || payload["status"] != "completed" {
				t.Fatalf("Responses non-stream completion contract mismatch: %#v", payload)
			}
		}
	}
	if got := mock.total.Load(); got != 4 {
		t.Fatalf("total=%d want=4", got)
	}
}

func TestInvalidJSONDoesNotIncrement(t *testing.T) {
	mock := &countedMock{}
	server := httptest.NewServer(mock)
	defer server.Close()
	status, _ := request(t, server.Client(), http.MethodPost, server.URL+"/v1/chat/completions", `{`)
	if status != http.StatusBadRequest || mock.total.Load() != 0 {
		t.Fatalf("status=%d total=%d", status, mock.total.Load())
	}
}

func TestUnknownRouteDoesNotIncrement(t *testing.T) {
	mock := &countedMock{}
	server := httptest.NewServer(mock)
	defer server.Close()
	status, _ := request(t, server.Client(), http.MethodPost, server.URL+"/v1/unknown", `{}`)
	if status != http.StatusNotFound || mock.total.Load() != 0 {
		t.Fatalf("status=%d total=%d", status, mock.total.Load())
	}
}
