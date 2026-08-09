package plugin

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
	if afterController == beforeController {
		t.Fatal("compatible reconfigure reused the active subject controller instead of publishing an independent prepared clone")
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
	if oldStats := beforeController.Stats(); oldStats.MaxSubjects != 32 || oldStats.Subjects != 1 {
		t.Fatalf("published reconfigure mutated the retired subject controller: %+v", oldStats)
	}
}

func TestRejectedSubjectMigrationDoesNotTouchCandidateAuditStorage(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n  max_subjects: 100\n")

	oldState := p.runtime.Load()
	for index := 0; index < 2; index++ {
		headers := http.Header{"Authorization": []string{"Bearer protected-candidate-storage-" + string(rune('a'+index))}}
		subjectHash := p.identifier.FromHeaders(headers).Hash
		for hit := 0; hit < 3; hit++ {
			_ = oldState.subject.Evaluate(subjectHash, 100)
		}
		state, ok := oldState.subject.Snapshot(subjectHash)
		if !ok || !state.ManualBlocked {
			t.Fatalf("subject %d did not become a protected manual block: (%+v, %v)", index, state, ok)
		}
	}

	candidateParent := t.TempDir()
	candidateDataDir := filepath.Join(candidateParent, "must-not-be-created", "audit")
	if _, err := os.Lstat(candidateDataDir); !os.IsNotExist(err) {
		t.Fatalf("candidate audit directory unexpectedly exists before reconfigure: %v", err)
	}

	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(candidateDataDir)+"\"\n  require_persistent_storage: true\nsubject_control:\n  enabled: true\n  max_subjects: 1\n"))
	if code != 0 {
		t.Fatalf("rejected subject migration code=%d envelope=%s", code, raw)
	}
	if p.runtime.Load() != oldState {
		t.Fatal("rejected subject migration published a candidate runtime")
	}
	if !strings.Contains(p.lastReconfigureErrorMessage(), "protected manual blocks") {
		t.Fatalf("last reconfigure error=%q, want protected-manual-block rejection", p.lastReconfigureErrorMessage())
	}
	if _, err := os.Lstat(candidateDataDir); !os.IsNotExist(err) {
		t.Fatalf("rejected subject migration touched candidate audit storage: %v", err)
	}
	entries, err := os.ReadDir(candidateParent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected subject migration created candidate side effects: %v", entries)
	}
}

func TestReconfigureRejectsAuditDataDirChangeBeforeCandidateSideEffects(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	activeDataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+activeDataDir+"\"\n  require_persistent_storage: true\nsubject_control:\n  enabled: true\n  max_subjects: 100\n")
	oldState := p.runtime.Load()

	candidateParent := t.TempDir()
	candidateDataDir := filepath.Join(candidateParent, "must-not-be-created", "audit")
	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t,
		"mode: audit\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(candidateDataDir)+"\"\n  require_persistent_storage: true\nsubject_control:\n  enabled: true\n  max_subjects: 100\n"))
	if code != 0 {
		t.Fatalf("audit data-dir reconfigure code=%d envelope=%s", code, raw)
	}
	if p.runtime.Load() != oldState {
		t.Fatal("audit data-dir change published a candidate runtime")
	}
	if !strings.Contains(p.lastReconfigureErrorMessage(), "audit.data_dir changes require a plugin restart") {
		t.Fatalf("last reconfigure error=%q, want restart-required rejection", p.lastReconfigureErrorMessage())
	}
	if _, err := os.Lstat(candidateDataDir); !os.IsNotExist(err) {
		t.Fatalf("rejected audit data-dir change touched candidate storage: %v", err)
	}
	entries, err := os.ReadDir(candidateParent)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("rejected audit data-dir change created candidate side effects: %v", entries)
	}
}
