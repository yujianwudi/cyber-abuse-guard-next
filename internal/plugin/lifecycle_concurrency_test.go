package plugin

import (
	"encoding/json"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
)

func TestConcurrentRegisterRouteManagementReconfigureAndShutdown(t *testing.T) {
	p := New()
	registerPayload := lifecyclePayload(t, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
	reconfigurePayload := lifecyclePayload(t, "mode: strict\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
	routePayload := modelRouteRequest(t, []byte(maliciousRequest))
	managementPayload, err := json.Marshal(authenticatedManagementRequest(http.MethodGet, managementBasePath+"/status", nil))
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	var failures atomic.Uint64
	var wait sync.WaitGroup
	launch := func(method string, payload []byte, iterations int) {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			for iteration := 0; iteration < iterations; iteration++ {
				raw, _ := p.Call(method, payload)
				if !json.Valid(raw) {
					failures.Add(1)
				}
			}
		}()
	}
	for worker := 0; worker < 4; worker++ {
		launch(pluginabi.MethodPluginRegister, registerPayload, 4)
		launch(pluginabi.MethodPluginReconfigure, reconfigurePayload, 4)
		launch(pluginabi.MethodModelRoute, routePayload, 40)
		launch(pluginabi.MethodManagementHandle, managementPayload, 40)
	}
	wait.Add(1)
	go func() {
		defer wait.Done()
		<-start
		time.Sleep(time.Millisecond)
		p.Shutdown()
		p.Shutdown()
	}()
	close(start)
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("concurrent lifecycle operations did not finish")
	}
	if failures.Load() != 0 {
		t.Fatalf("concurrent lifecycle returned %d malformed envelopes", failures.Load())
	}
}

func TestLoggerPanicsNeverEscapeLifecycleOrFailurePaths(t *testing.T) {
	p := New()
	p.SetLogger(func(string, string, map[string]any) { panic("logger panic value must stay local") })
	raw, code := p.Call(pluginabi.MethodPluginRegister, lifecyclePayload(t,
		"mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"))
	if code != 0 || !json.Valid(raw) {
		t.Fatal("logger panic escaped plugin registration")
	}
	raw, code = p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t, "mode: invalid\n"))
	if code != 0 || !json.Valid(raw) {
		t.Fatal("logger panic escaped rejected reconfiguration")
	}
	raw, code = p.Call(pluginabi.MethodModelRoute, []byte(`{"broken"`))
	if code != 0 || !json.Valid(raw) {
		t.Fatal("logger panic escaped router failure recovery")
	}
	done := make(chan struct{})
	go func() {
		p.Shutdown()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("shutdown deadlocked after logger panics")
	}
}
