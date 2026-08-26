package plugin

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/audit"
)

func TestQuiesceIsModeAwareAndExactRegisterRestoresRuntime(t *testing.T) {
	for _, testCase := range []struct {
		mode        string
		wantHandled bool
	}{
		{mode: "observe", wantHandled: false},
		{mode: "audit", wantHandled: false},
		{mode: "balanced", wantHandled: true},
		{mode: "strict", wantHandled: true},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			configYAML := "mode: " + testCase.mode + "\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"
			register(t, p, configYAML)
			before := p.runtime.Load()

			raw, code := p.Call(pluginabi.MethodPluginQuiesce, nil)
			if code != 0 {
				t.Fatalf("plugin.quiesce code=%d envelope=%s", code, raw)
			}
			decodeOKResult(t, raw, &struct{}{})
			if !p.quiescing.Load() || p.runtime.Load() != before {
				t.Fatalf("quiesce state=%t runtime_changed=%t", p.quiescing.Load(), p.runtime.Load() != before)
			}
			route := callRoute(t, p, maliciousRequest)
			if route.Handled != testCase.wantHandled {
				t.Fatalf("quiesced %s route=%+v, want handled=%t", testCase.mode, route, testCase.wantHandled)
			}
			if route.Handled && route.Reason != "cyber_abuse_guard_quiesced" {
				t.Fatalf("quiesced enforcing route reason=%q", route.Reason)
			}

			raw, code = p.Call(pluginabi.MethodPluginRegister, lifecyclePayload(t, configYAML))
			if code != 0 {
				t.Fatalf("rollback plugin.register code=%d envelope=%s", code, raw)
			}
			decodeOKResult(t, raw, &registration{})
			if p.quiescing.Load() || p.runtime.Load() != before {
				t.Fatalf("rollback restore quiescing=%t runtime_changed=%t", p.quiescing.Load(), p.runtime.Load() != before)
			}
			if got := p.counters.quiesceTransitions.Load(); got != 1 {
				t.Fatalf("quiesce transitions=%d, want 1", got)
			}
			if got := p.counters.quiesceRestores.Load(); got != 1 {
				t.Fatalf("quiesce restores=%d, want 1", got)
			}
		})
	}
}

func TestQuiesceRejectsConfigDriftAndRemainsReversible(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	configYAML := "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"
	register(t, p, configYAML)
	before := p.runtime.Load()

	for iteration := 0; iteration < 2; iteration++ {
		raw, code := p.Call(pluginabi.MethodPluginQuiesce, nil)
		if code != 0 {
			t.Fatalf("quiesce %d code=%d envelope=%s", iteration, code, raw)
		}
		decodeOKResult(t, raw, &struct{}{})
	}
	if got := p.counters.quiesceTransitions.Load(); got != 1 {
		t.Fatalf("idempotent quiesce transitions=%d, want 1", got)
	}

	raw, code := p.Call(pluginabi.MethodPluginRegister, lifecyclePayload(t,
		"mode: audit\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"))
	if code != 0 {
		t.Fatalf("mismatched rollback code=%d envelope=%s", code, raw)
	}
	var envelope rpcEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != "plugin_quiesce_restore_mismatch" {
		t.Fatalf("mismatched rollback envelope=%s", raw)
	}
	if !p.quiescing.Load() || p.runtime.Load() != before {
		t.Fatal("mismatched rollback changed the quiesced runtime")
	}

	raw, code = p.Call(pluginabi.MethodPluginRegister, lifecyclePayload(t, configYAML))
	if code != 0 {
		t.Fatalf("exact rollback code=%d envelope=%s", code, raw)
	}
	decodeOKResult(t, raw, &registration{})
	if p.quiescing.Load() || p.runtime.Load() != before {
		t.Fatal("exact rollback did not reactivate the original runtime")
	}
	if got := p.counters.quiesceRestoreRejected.Load(); got != 1 {
		t.Fatalf("rejected restore counter=%d, want 1", got)
	}
}

func TestQuiesceBeforeRegisterFailsWithoutPoisoningRegistration(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	if err := p.Quiesce(); err == nil || p.quiescing.Load() {
		t.Fatalf("unregistered quiesce err=%v state=%t", err, p.quiescing.Load())
	}
	register(t, p, "mode: observe\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
	if p.runtime.Load() == nil || p.quiescing.Load() {
		t.Fatal("failed pre-register quiesce poisoned registration")
	}
}

func TestShutdownAfterQuiesceIsIrreversible(t *testing.T) {
	p := New()
	configYAML := "mode: strict\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"
	register(t, p, configYAML)
	if err := p.Quiesce(); err != nil {
		t.Fatal(err)
	}
	p.Shutdown()
	if !p.shutdown.Load() || p.runtime.Load() != nil {
		t.Fatalf("shutdown=%t runtime=%#v", p.shutdown.Load(), p.runtime.Load())
	}
	raw, code := p.Call(pluginabi.MethodPluginRegister, lifecyclePayload(t, configYAML))
	if code != 0 {
		t.Fatalf("post-shutdown register code=%d envelope=%s", code, raw)
	}
	var envelope rpcEnvelope
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.OK || envelope.Error == nil || envelope.Error.Code != "plugin_shutdown" {
		t.Fatalf("post-shutdown register envelope=%s", raw)
	}
}

func TestQuiesceWaitsForInflightRequest(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n")

	hashEntered := make(chan struct{})
	releaseHash := make(chan struct{})
	p.requestHasher = func(body []byte) string {
		close(hashEntered)
		<-releaseHash
		return audit.HashRequest(body)
	}
	routeDone := make(chan struct{})
	go func() {
		defer close(routeDone)
		_ = callRoute(t, p, maliciousRequest)
	}()
	select {
	case <-hashEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not enter the protected operation")
	}

	quiesceDone := make(chan error, 1)
	go func() { quiesceDone <- p.Quiesce() }()
	select {
	case err := <-quiesceDone:
		t.Fatalf("quiesce completed before in-flight request: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseHash)
	select {
	case <-routeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("in-flight request did not finish")
	}
	select {
	case err := <-quiesceDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("quiesce did not finish after the request drained")
	}
}

func TestQuiesceFlushesAuditAndPreservesRawCaptureAcrossRollback(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	p.auditStorageInspect = verifiedAuditStorageInspectorForTest
	dataDir := filepath.ToSlash(t.TempDir())
	configYAML := "mode: balanced\naudit:\n  enabled: true\n  data_dir: \"" + dataDir + "\"\n" +
		"  require_persistent_storage: true\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\n" +
		"subject_control:\n  enabled: false\n"
	register(t, p, configYAML)
	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("setup request was not blocked: %+v", route)
	}
	state := p.runtime.Load()
	if err := p.Quiesce(); err != nil {
		t.Fatal(err)
	}
	page, err := state.audit.QueryRawCapturesPage(context.Background(), audit.RawCaptureQuery{Limit: 10})
	if err != nil || len(page.Captures) != 1 {
		t.Fatalf("quiesced capture page=%#v err=%v", page, err)
	}
	raw, code := p.Call(pluginabi.MethodPluginRegister, lifecyclePayload(t, configYAML))
	if code != 0 {
		t.Fatalf("rollback register code=%d envelope=%s", code, raw)
	}
	decodeOKResult(t, raw, &registration{})
	if p.runtime.Load() != state || !state.audit.IsActive() {
		t.Fatal("rollback replaced or closed the audit runtime")
	}
}
