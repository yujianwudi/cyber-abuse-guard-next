package plugin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/audit"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/config"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
)

const safeDefaultsBenignRequest = `{"model":"gpt-test","messages":[{"role":"user","content":"summarize this meeting agenda"}]}`

func TestDefaultRuntimeObservesWithoutSubjectControlOrRequestHash(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	hashCalls := countRequestHashes(p)
	register(t, p, "audit:\n  enabled: false\n")

	state := p.runtime.Load()
	if state.config.Mode != config.ModeObserve || state.config.SubjectControl.Enabled {
		t.Fatalf("default runtime mode=%q subject_enabled=%t", state.config.Mode, state.config.SubjectControl.Enabled)
	}
	if route := callRoute(t, p, maliciousRequest); route.Handled {
		t.Fatalf("default observe runtime blocked request: %+v", route)
	}
	if *hashCalls != 0 {
		t.Fatalf("default observe route hashed request body %d times, want 0", *hashCalls)
	}
	if got := p.counters.observed.Load(); got != 1 {
		t.Fatalf("default observe counter=%d, want 1", got)
	}
}

func TestRequestBodyHashIsLazyAcrossRouteOutcomes(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		configuration func(t *testing.T) string
		body          string
		headers       http.Header
		wantHandled   bool
		wantHashes    int
	}{
		{
			name: "clean balanced request without subject or audit",
			configuration: func(*testing.T) string {
				return "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"
			},
			body: safeDefaultsBenignRequest,
		},
		{
			name: "ineligible authenticated subject observation",
			configuration: func(*testing.T) string {
				return "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n"
			},
			body:       safeDefaultsBenignRequest,
			headers:    http.Header{"Authorization": []string{"Bearer downstream-key"}},
			wantHashes: 0,
		},
		{
			name: "final balanced block pending key",
			configuration: func(*testing.T) string {
				return "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"
			},
			body:        maliciousRequest,
			wantHandled: true,
			wantHashes:  1,
		},
		{
			name: "subject audit and pending share one hash",
			configuration: func(t *testing.T) string {
				return "mode: balanced\naudit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(t.TempDir()) + "\"\n  log_request_hash: true\nsubject_control:\n  enabled: true\n"
			},
			body:        maliciousRequest,
			headers:     http.Header{"Authorization": []string{"Bearer downstream-key"}},
			wantHandled: true,
			wantHashes:  1,
		},
		{
			name: "persisted audit request hash",
			configuration: func(t *testing.T) string {
				return "mode: audit\naudit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(t.TempDir()) + "\"\n  log_request_hash: true\nsubject_control:\n  enabled: false\n"
			},
			body:       maliciousRequest,
			wantHashes: 1,
		},
		{
			name: "audit persistence without request hash field",
			configuration: func(t *testing.T) string {
				return "mode: audit\naudit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(t.TempDir()) + "\"\n  log_request_hash: false\nsubject_control:\n  enabled: false\n"
			},
			body: maliciousRequest,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			hashCalls := countRequestHashes(p)
			register(t, p, testCase.configuration(t))

			var route pluginapi.ModelRouteResponse
			if testCase.headers != nil {
				route = callRouteWithHeaders(t, p, testCase.body, testCase.headers)
			} else {
				route = callRoute(t, p, testCase.body)
			}
			if route.Handled != testCase.wantHandled {
				t.Fatalf("route handled=%t, want %t; route=%+v", route.Handled, testCase.wantHandled, route)
			}
			if *hashCalls != testCase.wantHashes {
				t.Fatalf("request body hash calls=%d, want %d", *hashCalls, testCase.wantHashes)
			}
		})
	}
}

func TestStrictUnknownSourceReusesHashAndPersistsAuditIdentity(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	hashCalls := countRequestHashes(p)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: strict\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  log_request_hash: true\n  log_subject_hash: true\nsubject_control:\n  enabled: false\n")

	headers := http.Header{"Authorization": []string{"Bearer downstream-key"}}
	expectedSubject := p.identifier.FromHeaders(headers).Hash
	rawRequest, err := json.Marshal(pluginapi.ModelRouteRequest{
		SourceFormat: "future-provider",
		Headers:      headers,
		Body:         []byte(safeDefaultsBenignRequest),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, code := p.Call(pluginabi.MethodModelRoute, rawRequest)
	if code != 0 {
		t.Fatalf("strict unknown model.route code=%d envelope=%s", code, raw)
	}
	var route pluginapi.ModelRouteResponse
	decodeOKResult(t, raw, &route)
	if !route.Handled {
		t.Fatalf("strict unknown source was not locally blocked: %+v", route)
	}
	if *hashCalls != 1 {
		t.Fatalf("strict unknown source request hash calls=%d, want 1", *hashCalls)
	}

	events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	items, ok := events["events"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("strict unknown source events=%#v, want one", events)
	}
	event, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("strict unknown source event=%#v, want object", items[0])
	}
	requestHash, _ := event["request_hash"].(string)
	subjectHash, _ := event["subject_hash"].(string)
	if !strings.HasPrefix(requestHash, "sha256:") || subjectHash != expectedSubject {
		t.Fatalf("strict unknown source event request_hash=%q subject_hash=%q, want subject %q", requestHash, subjectHash, expectedSubject)
	}
}

func TestObserveStreamingIncompleteRouteWritesNoSQLiteEvent(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	hashCalls := countRequestHashes(p)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: observe\nmax_scan_bytes: 16384\nmax_total_text_bytes: 16384\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  log_request_hash: true\nsubject_control:\n  enabled: false\n")

	body := []byte(`{"messages":[{"role":"user","content":"` + strings.Repeat("A", (16<<10)+1) + `"}]}`)
	rawRequest, err := json.Marshal(pluginapi.ModelRouteRequest{
		SourceFormat: "openai",
		Stream:       true,
		Body:         body,
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, code := p.Call(pluginabi.MethodModelRoute, rawRequest)
	if code != 0 {
		t.Fatalf("streaming model.route code=%d envelope=%s", code, raw)
	}
	var route pluginapi.ModelRouteResponse
	decodeOKResult(t, raw, &route)
	if route.Handled {
		t.Fatalf("observe streaming route blocked: %+v", route)
	}
	if *hashCalls != 0 {
		t.Fatalf("observe streaming route hashed request body %d times, want 0", *hashCalls)
	}

	events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	items, ok := events["events"].([]any)
	if !ok || len(items) != 0 {
		t.Fatalf("observe streaming events=%#v, want none", events)
	}
}

func TestSubjectDisabledAuditStillPersistsIdentityWithoutSubjectState(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: audit\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  log_subject_hash: true\nsubject_control:\n  enabled: false\n")

	headers := http.Header{"Authorization": []string{"Bearer downstream-key"}}
	expectedSubject := p.identifier.FromHeaders(headers).Hash
	route := callRouteWithHeaders(t, p, maliciousRequest, headers)
	if route.Handled {
		t.Fatalf("audit route blocked request: %+v", route)
	}

	events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	items, ok := events["events"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("audit events=%#v, want one", events)
	}
	event, ok := items[0].(map[string]any)
	if !ok {
		t.Fatalf("audit event=%#v, want object", items[0])
	}
	subjectHash, _ := event["subject_hash"].(string)
	if subjectHash != expectedSubject || !strings.HasPrefix(subjectHash, "hmac-sha256:") {
		t.Fatalf("audit subject_hash=%q, want %q", subjectHash, expectedSubject)
	}
	if state, found := p.runtime.Load().subject.Snapshot(expectedSubject); found {
		t.Fatalf("disabled subject controller created state: %+v", state)
	}
}

func countRequestHashes(p *Plugin) *int {
	count := 0
	p.requestHasher = func(body []byte) string {
		count++
		return audit.HashRequest(body)
	}
	return &count
}
