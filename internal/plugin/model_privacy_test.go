package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/audit"
)

func TestCallerControlledAuditMetadataIsPrivateAcrossEventsSQLiteAndManagementAPI(t *testing.T) {
	dataDir := t.TempDir()
	p := New()
	register(t, p, "mode: audit\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(dataDir)+"\"\nsubject_control:\n  enabled: false\n")

	const decisionCanary = "MODEL_PRIVACY_DECISION_CANARY_secret-model-name"
	const parseCanary = "MODEL_PRIVACY_PARSE_CANARY_secret-model-name"
	const sourceCanary = "SOURCE_FORMAT_PRIVACY_CANARY_secret-provider-name"
	callPrivacyModelRoute(t, p, decisionCanary, sourceCanary, []byte(maliciousRequest))
	callPrivacyModelRoute(t, p, parseCanary, sourceCanary, []byte(`{"messages":[`))

	management := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	managementRaw, err := json.Marshal(management)
	if err != nil {
		t.Fatal(err)
	}
	assertNoAuditCanary(t, managementRaw, decisionCanary, parseCanary, sourceCanary)

	items, ok := management["events"].([]any)
	if !ok || len(items) != 2 {
		t.Fatal("management API did not return exactly two privacy-safe events")
	}
	wantHashes := map[string]bool{
		audit.HashModel(decisionCanary): false,
		audit.HashModel(parseCanary):    false,
	}
	for _, item := range items {
		event, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("management event has type %T", item)
		}
		model, _ := event["model"].(string)
		if _, exists := wantHashes[model]; !exists {
			t.Fatal("management event model was not an expected domain-separated digest")
		}
		if event["source_format"] != audit.SourceFormatUnknown {
			t.Fatal("management event retained a caller-controlled source format")
		}
		wantHashes[model] = true
	}
	for model, seen := range wantHashes {
		if !seen {
			_ = model
			t.Fatal("management API omitted an expected model digest")
		}
	}

	state := p.runtime.Load()
	if state == nil || state.audit == nil {
		t.Fatal("audit runtime is unavailable")
	}
	if err := state.audit.Flush(context.Background()); err != nil {
		t.Fatalf("Flush() error = %v", err)
	}
	events, err := state.audit.Query(context.Background(), audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	eventRaw, err := json.Marshal(events)
	if err != nil {
		t.Fatal(err)
	}
	assertNoAuditCanary(t, eventRaw, decisionCanary, parseCanary, sourceCanary)
	for _, event := range events {
		if _, exists := wantHashes[event.Model]; !exists {
			t.Fatal("persisted model was not an expected domain-separated digest")
		}
		if event.SourceFormat != audit.SourceFormatUnknown {
			t.Fatal("persisted event retained a caller-controlled source format")
		}
	}

	p.Shutdown()
	databaseFiles, err := filepath.Glob(filepath.Join(dataDir, "events.db*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(databaseFiles) == 0 {
		t.Fatal("audit SQLite database was not created")
	}
	for _, name := range databaseFiles {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", name, err)
		}
		assertNoAuditCanary(t, data, decisionCanary, parseCanary, sourceCanary)
	}
}

func callPrivacyModelRoute(t testing.TB, p *Plugin, requestedModel, sourceFormat string, body []byte) {
	t.Helper()
	rawRequest, err := json.Marshal(pluginapi.ModelRouteRequest{
		SourceFormat:   sourceFormat,
		RequestedModel: requestedModel,
		Body:           body,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, code := p.Call(pluginabi.MethodModelRoute, rawRequest)
	if code != 0 {
		t.Fatalf("privacy model.route return code = %d", code)
	}
}

func assertNoAuditCanary(t testing.TB, data []byte, canaries ...string) {
	t.Helper()
	for index, canary := range canaries {
		if bytes.Contains(data, []byte(canary)) {
			t.Fatalf("privacy surface retained plaintext canary index %d", index)
		}
	}
}
