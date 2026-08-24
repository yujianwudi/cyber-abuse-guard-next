package main

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	guardplugin "github.com/yujianwudi/cyber-abuse-guard-next/internal/plugin"
)

func TestClearHostAPIWaitsForInFlightCallback(t *testing.T) {
	const timeout = 2 * time.Second

	callbackEntered := make(chan struct{})
	releaseCallback := make(chan struct{})
	callbackDone := make(chan bool, 1)
	go func() {
		released := false
		withHostAPICallback(func() {
			close(callbackEntered)
			select {
			case <-releaseCallback:
				released = true
			case <-time.After(timeout):
			}
		})
		callbackDone <- released
	}()
	select {
	case <-callbackEntered:
	case <-time.After(timeout):
		t.Fatal("host callback did not acquire the read lock")
	}

	clearDone := make(chan struct{})
	go func() {
		clearHostAPIAndWait()
		close(clearDone)
	}()

	// A pending RWMutex writer prevents new readers. Since the callback still
	// holds the initial read lock, a failed TryRLock proves that clear has
	// reached the synchronization wait rather than merely starting its goroutine.
	deadline := time.Now().Add(timeout)
	for hostAPIMu.TryRLock() {
		hostAPIMu.RUnlock()
		if time.Now().After(deadline) {
			t.Fatal("native host API clear did not enter the synchronization wait")
		}
		time.Sleep(time.Millisecond)
	}

	close(releaseCallback)
	select {
	case released := <-callbackDone:
		if !released {
			t.Fatal("in-flight host callback timed out waiting for release")
		}
	case <-time.After(timeout):
		t.Fatal("in-flight host callback did not report completion")
	}
	select {
	case <-clearDone:
	case <-time.After(timeout):
		t.Fatal("native host API clear did not resume after callback completion")
	}
}

func TestABIEnvelopeRegistrationAndModeAwareOversize(t *testing.T) {
	if abiVersion != pluginabi.ABIVersion {
		t.Fatalf("abiVersion = %d, want %d", abiVersion, pluginabi.ABIVersion)
	}
	previous := activePlugin
	activePlugin = guardplugin.New()
	t.Cleanup(func() {
		activePlugin.Shutdown()
		activePlugin = previous
	})

	lifecycle, _ := json.Marshal(map[string]any{
		"schema_version": pluginabi.SchemaVersion,
		"config_yaml":    []byte("audit:\n  enabled: false\n"),
	})
	raw, code := handlePluginCall(pluginabi.MethodPluginRegister, lifecycle)
	if code != 0 {
		t.Fatalf("plugin.register code=%d envelope=%s", code, raw)
	}
	var registerEnvelope struct {
		OK     bool `json:"ok"`
		Result struct {
			SchemaVersion uint32 `json:"schema_version"`
			Capabilities  struct {
				ModelRouter            bool `json:"model_router"`
				Executor               bool `json:"executor"`
				RequestInterceptor     bool `json:"request_interceptor"`
				RequestLifecycle       bool `json:"request_lifecycle_plugin"`
				ResponseInterceptor    bool `json:"response_interceptor"`
				StreamChunkInterceptor bool `json:"response_stream_interceptor"`
				ManagementAPI          bool `json:"management_api"`
			} `json:"capabilities"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &registerEnvelope); err != nil || !registerEnvelope.OK ||
		pluginabi.SchemaVersion != 3 || registerEnvelope.Result.SchemaVersion != pluginabi.SchemaVersion {
		t.Fatalf("invalid registration envelope %s: %v", raw, err)
	}
	capabilities := registerEnvelope.Result.Capabilities
	if !capabilities.ModelRouter || !capabilities.Executor || !capabilities.RequestInterceptor ||
		!capabilities.RequestLifecycle || !capabilities.ManagementAPI {
		t.Fatalf("invalid schema-v3 registration capabilities: %+v", capabilities)
	}
	if capabilities.ResponseInterceptor || capabilities.StreamChunkInterceptor {
		t.Fatalf("native registration unexpectedly enables response interceptor chains: %+v", capabilities)
	}

	// This is the method-specific path used by the native C boundary before it
	// attempts C.GoBytes on an RPC larger than maxNativeRequestBytes.
	raw, code = handleOversizedPluginCall(pluginabi.MethodModelRoute)
	if code != 0 {
		t.Fatalf("oversized model.route code=%d envelope=%s", code, raw)
	}
	var oversizedEnvelope struct {
		OK     bool                         `json:"ok"`
		Result pluginapi.ModelRouteResponse `json:"result"`
	}
	if err := json.Unmarshal(raw, &oversizedEnvelope); err != nil || !oversizedEnvelope.OK || oversizedEnvelope.Result.Handled {
		t.Fatalf("balanced oversized native route envelope=%s err=%v", raw, err)
	}

	strictLifecycle, _ := json.Marshal(map[string]any{
		"schema_version": pluginabi.SchemaVersion,
		"config_yaml":    []byte("mode: strict\naudit:\n  enabled: false\n"),
	})
	raw, code = handlePluginCall(pluginabi.MethodPluginReconfigure, strictLifecycle)
	if code != 0 {
		t.Fatalf("plugin.reconfigure strict code=%d envelope=%s", code, raw)
	}
	raw, code = handleOversizedPluginCall(pluginabi.MethodModelRoute)
	if code != 0 {
		t.Fatalf("strict oversized model.route code=%d envelope=%s", code, raw)
	}
	if err := json.Unmarshal(raw, &oversizedEnvelope); err != nil || !oversizedEnvelope.OK ||
		!oversizedEnvelope.Result.Handled || oversizedEnvelope.Result.Reason != "cyber_abuse_guard_rpc_body_limit" {
		t.Fatalf("strict oversized native route envelope=%s err=%v", raw, err)
	}

	for _, method := range []string{pluginabi.MethodExecutorExecuteStream, pluginabi.MethodExecutorCountTokens} {
		raw, code = handlePluginCall(method, []byte(`{"OriginalRequest":"e30="}`))
		if code != 0 {
			t.Fatalf("%s controlled block code=%d envelope=%s", method, code, raw)
		}
		var blockEnvelope struct {
			OK    bool `json:"ok"`
			Error struct {
				Code       string `json:"code"`
				HTTPStatus int    `json:"http_status"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &blockEnvelope); err != nil {
			t.Fatalf("decode block envelope: %v", err)
		}
		if blockEnvelope.OK || blockEnvelope.Error.Code != "cyber_abuse_guard_blocked" || blockEnvelope.Error.HTTPStatus != http.StatusForbidden {
			t.Fatalf("%s block envelope = %s", method, raw)
		}
	}
}

func TestABIUnknownMethodAndMalformedRequestAreContained(t *testing.T) {
	previous := activePlugin
	activePlugin = guardplugin.New()
	t.Cleanup(func() {
		activePlugin.Shutdown()
		activePlugin = previous
	})

	for _, tc := range []struct {
		method  string
		request []byte
		code    string
	}{
		{method: "not.a.real.method", request: []byte(`{}`), code: "unknown_method"},
		{method: pluginabi.MethodModelRoute, request: []byte(`{"Body":`), code: "invalid_request"},
	} {
		raw, callCode := handlePluginCall(tc.method, tc.request)
		if callCode != 0 {
			t.Fatalf("%s controlled error call code=%d envelope=%s", tc.method, callCode, raw)
		}
		var envelope struct {
			OK    bool `json:"ok"`
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(raw, &envelope); err != nil || envelope.OK || envelope.Error.Code != tc.code {
			t.Fatalf("%s envelope=%s err=%v", tc.method, raw, err)
		}
	}
}
