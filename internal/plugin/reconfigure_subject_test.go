package plugin

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
)

func TestReconfigurePreservesSubjectRiskState(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n  max_subjects: 32\n")

	headers := http.Header{"Authorization": []string{"Bearer persistent-subject"}}
	routeRequest := pluginapi.ModelRouteRequest{
		SourceFormat:   "openai",
		RequestedModel: "gpt-test",
		Headers:        headers,
		Body:           []byte(maliciousRequest),
	}
	rawRoute, err := json.Marshal(routeRequest)
	if err != nil {
		t.Fatal(err)
	}
	raw, code := p.Call(pluginabi.MethodModelRoute, rawRoute)
	if code != 0 {
		t.Fatalf("model.route code=%d envelope=%s", code, raw)
	}

	subjectHash := p.identifier.FromHeaders(headers).Hash
	beforeController := p.runtime.Load().subject
	before, ok := beforeController.Snapshot(subjectHash)
	if !ok || before.HitCount != 1 {
		t.Fatalf("subject state before reconfigure = (%+v, %v), want one logical hit", before, ok)
	}

	raw, code = p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: audit\nmax_scan_bytes: 131072\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n  max_subjects: 64\n"))
	if code != 0 {
		t.Fatalf("plugin.reconfigure code=%d envelope=%s", code, raw)
	}
	decodeOKResult(t, raw, &map[string]any{})

	afterController := p.runtime.Load().subject
	if afterController != beforeController {
		t.Fatal("compatible reconfigure replaced the subject controller")
	}
	after, ok := afterController.Snapshot(subjectHash)
	if !ok || after.HitCount != before.HitCount || after.Score <= 0 {
		t.Fatalf("subject state after reconfigure = (%+v, %v), before=%+v", after, ok, before)
	}
	status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	control, ok := status["subject_control"].(map[string]any)
	if !ok || control["max_subjects"] != float64(64) || control["subjects"] != float64(1) {
		t.Fatalf("subject-control status = %#v", status["subject_control"])
	}
}
