package plugin

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/config"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

func TestParseFailureAdmittedBeforeShutdownRetainsFailClosedPolicy(t *testing.T) {
	p := New()
	register(t, p, "mode: strict\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	failureEntered := make(chan struct{})
	releaseFailure := make(chan struct{})
	p.pending.mu.Lock()
	p.pending.now = func() time.Time {
		close(failureEntered)
		<-releaseFailure
		return time.Now()
	}
	p.pending.mu.Unlock()

	routeDone := make(chan routeCallResult, 1)
	go func() {
		raw, code := p.Call(pluginabi.MethodModelRoute, malformedBodyRouteRequest(t))
		routeDone <- routeCallResult{raw: raw, code: code}
	}()
	waitForSignal(t, failureEntered, "route parse-failure barrier")

	shutdownDone := make(chan struct{})
	go func() {
		p.Shutdown()
		close(shutdownDone)
	}()
	waitForCondition(t, "shutdown publication", p.shutdown.Load)
	close(releaseFailure)

	result := waitForRouteResult(t, routeDone)
	assertSuccessfulSelfRoute(t, result, "cyber_abuse_guard_parse_error")
	waitForSignal(t, shutdownDone, "shutdown completion")
}

func TestRouterPanicAdmittedBeforeShutdownRetainsFailClosedPolicy(t *testing.T) {
	p := New()
	register(t, p, "mode: strict\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	panicEntered := make(chan struct{})
	releasePanic := make(chan struct{})
	p.pending.mu.Lock()
	p.pending.now = func() time.Time {
		close(panicEntered)
		<-releasePanic
		panic("barrier-controlled router panic")
	}
	p.pending.mu.Unlock()

	routeDone := make(chan routeCallResult, 1)
	go func() {
		rawRequest := modelRouteRequest(t, []byte(maliciousRequest))
		raw, code := p.Call(pluginabi.MethodModelRoute, rawRequest)
		routeDone <- routeCallResult{raw: raw, code: code}
	}()
	waitForSignal(t, panicEntered, "router panic barrier")

	shutdownDone := make(chan struct{})
	go func() {
		p.Shutdown()
		close(shutdownDone)
	}()
	waitForCondition(t, "shutdown publication", p.shutdown.Load)
	close(releasePanic)

	result := waitForRouteResult(t, routeDone)
	assertSuccessfulSelfRoute(t, result, "cyber_abuse_guard_router_panic")
	waitForSignal(t, shutdownDone, "shutdown completion")
}

func TestRouterPanicRetainsAdmissionPolicyAcrossReconfigure(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	register(t, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

	originalLoadRules := p.loadRules
	buildEntered := make(chan struct{})
	releaseBuild := make(chan struct{})
	var buildOnce sync.Once
	p.loadRules = func() (*rules.RuleSet, error) {
		buildOnce.Do(func() {
			close(buildEntered)
			<-releaseBuild
		})
		return originalLoadRules()
	}

	failureReported := make(chan struct{})
	releaseFailureReport := make(chan struct{})
	var reportOnce sync.Once
	p.SetLogger(func(level, message string, fields map[string]any) {
		if fields["code"] != "panic_recovered" {
			return
		}
		reportOnce.Do(func() {
			close(failureReported)
			<-releaseFailureReport
		})
	})

	panicEntered := make(chan struct{})
	releasePanic := make(chan struct{})
	p.pending.mu.Lock()
	p.pending.now = func() time.Time {
		close(panicEntered)
		<-releasePanic
		panic("barrier-controlled router panic")
	}
	p.pending.mu.Unlock()

	routeDone := make(chan routeCallResult, 1)
	go func() {
		raw, code := p.Call(pluginabi.MethodModelRoute, modelRouteRequest(t, []byte(maliciousRequest)))
		routeDone <- routeCallResult{raw: raw, code: code}
	}()
	waitForSignal(t, panicEntered, "router panic barrier")

	reconfigureDone := make(chan struct{})
	go func() {
		p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t, "mode: audit\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"))
		close(reconfigureDone)
	}()
	waitForSignal(t, buildEntered, "reconfigure build barrier")
	close(releaseBuild)
	close(releasePanic)
	waitForSignal(t, failureReported, "router failure reporting barrier")
	// The panic has unwound the operation lock, so the reconfiguration can now
	// complete before the failure response is encoded. The response must still
	// use the balanced policy captured at callback admission.
	waitForSignal(t, reconfigureDone, "reconfigure completion")
	if state := p.runtime.Load(); state == nil || state.config.Mode != config.ModeAudit {
		t.Fatalf("reconfiguration did not publish audit mode: %#v", state)
	}
	close(releaseFailureReport)

	result := waitForRouteResult(t, routeDone)
	assertSuccessfulSelfRoute(t, result, "cyber_abuse_guard_router_panic")
}

func TestModelRouteAfterShutdownUsesTerminalSuccessfulPolicy(t *testing.T) {
	for _, testCase := range []struct {
		mode        string
		wantHandled bool
	}{
		{mode: "balanced", wantHandled: true},
		{mode: "strict", wantHandled: true},
		{mode: "audit", wantHandled: false},
		{mode: "observe", wantHandled: false},
		{mode: "off", wantHandled: false},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			p := New()
			register(t, p, "mode: "+testCase.mode+"\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")
			p.Shutdown()

			for _, call := range []struct {
				name string
				fn   func() ([]byte, int)
			}{
				{name: "regular", fn: func() ([]byte, int) {
					return p.Call(pluginabi.MethodModelRoute, []byte(`{"broken"`))
				}},
				{name: "oversized", fn: func() ([]byte, int) {
					return p.CallOversized(pluginabi.MethodModelRoute)
				}},
			} {
				t.Run(call.name, func(t *testing.T) {
					raw, code := call.fn()
					if code != 0 {
						t.Fatalf("post-shutdown model.route ABI code=%d envelope=%s", code, raw)
					}
					var route pluginapi.ModelRouteResponse
					decodeOKResult(t, raw, &route)
					if route.Handled != testCase.wantHandled {
						t.Fatalf("post-shutdown mode=%s route=%+v, want handled=%v", testCase.mode, route, testCase.wantHandled)
					}
					if testCase.wantHandled && (route.TargetKind != pluginapi.ModelRouteTargetSelf || route.Reason != "cyber_abuse_guard_shutdown") {
						t.Fatalf("post-shutdown enforcing route is not a local self-route: %+v", route)
					}
				})
			}
		})
	}
}

func TestRecoverNativeCallbackPanicUsesModeAwarePolicyBeforeAndAfterShutdown(t *testing.T) {
	for _, testCase := range []struct {
		mode        string
		wantHandled bool
	}{
		{mode: "balanced", wantHandled: true},
		{mode: "strict", wantHandled: true},
		{mode: "audit", wantHandled: false},
		{mode: "observe", wantHandled: false},
		{mode: "off", wantHandled: false},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			register(t, p, "mode: "+testCase.mode+"\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

			raw, code := p.RecoverNativeCallbackPanic(pluginabi.MethodModelRoute)
			assertSuccessfulNativeRecovery(t, routeCallResult{raw: raw, code: code}, testCase.wantHandled)
			p.Shutdown()
			raw, code = p.RecoverNativeCallbackPanic(pluginabi.MethodModelRoute)
			assertSuccessfulNativeRecovery(t, routeCallResult{raw: raw, code: code}, testCase.wantHandled)
		})
	}
}

func TestRecoverNativeCallbackPanicConcurrentWithShutdown(t *testing.T) {
	const workers = 64
	for _, testCase := range []struct {
		mode        string
		wantHandled bool
	}{
		{mode: "balanced", wantHandled: true},
		{mode: "strict", wantHandled: true},
		{mode: "audit", wantHandled: false},
		{mode: "observe", wantHandled: false},
		{mode: "off", wantHandled: false},
	} {
		t.Run(testCase.mode, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			register(t, p, "mode: "+testCase.mode+"\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n")

			start := make(chan struct{})
			results := make(chan routeCallResult, workers)
			var calls sync.WaitGroup
			calls.Add(workers)
			for range workers {
				go func() {
					defer calls.Done()
					<-start
					raw, code := p.RecoverNativeCallbackPanic(pluginabi.MethodModelRoute)
					results <- routeCallResult{raw: raw, code: code}
				}()
			}
			shutdownDone := make(chan struct{})
			go func() {
				<-start
				p.Shutdown()
				close(shutdownDone)
			}()

			close(start)
			calls.Wait()
			close(results)
			waitForSignal(t, shutdownDone, "native recovery concurrent shutdown")
			for result := range results {
				assertSuccessfulNativeRecovery(t, result, testCase.wantHandled)
			}
		})
	}
}

type routeCallResult struct {
	raw  []byte
	code int
}

func malformedBodyRouteRequest(t testing.TB) []byte {
	t.Helper()
	return modelRouteRequest(t, []byte(`{"messages":[`))
}

func modelRouteRequest(t testing.TB, body []byte) []byte {
	t.Helper()
	raw, err := json.Marshal(pluginapi.ModelRouteRequest{
		SourceFormat:   "openai",
		RequestedModel: "gpt-test",
		Body:           body,
	})
	if err != nil {
		t.Fatalf("marshal model.route request: %v", err)
	}
	return raw
}

func waitForSignal(t testing.TB, signal <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", description)
	}
}

func waitForCondition(t testing.TB, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", description)
		}
		time.Sleep(time.Millisecond)
	}
}

func waitForRouteResult(t testing.TB, result <-chan routeCallResult) routeCallResult {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for model.route response")
		return routeCallResult{}
	}
}

func assertSuccessfulSelfRoute(t testing.TB, result routeCallResult, wantReason string) {
	t.Helper()
	if result.code != 0 {
		t.Fatalf("model.route ABI code=%d envelope=%s", result.code, result.raw)
	}
	var route pluginapi.ModelRouteResponse
	decodeOKResult(t, result.raw, &route)
	if !route.Handled || route.TargetKind != pluginapi.ModelRouteTargetSelf || route.Reason != wantReason {
		t.Fatalf("model.route failed open: %+v", route)
	}
}

func assertSuccessfulNativeRecovery(t testing.TB, result routeCallResult, wantHandled bool) {
	t.Helper()
	if result.code != 0 {
		t.Fatalf("native model.route recovery ABI code=%d envelope=%s", result.code, result.raw)
	}
	var route pluginapi.ModelRouteResponse
	decodeOKResult(t, result.raw, &route)
	if route.Handled != wantHandled {
		t.Fatalf("native model.route recovery=%+v, want handled=%v", route, wantHandled)
	}
	if wantHandled && (route.TargetKind != pluginapi.ModelRouteTargetSelf || route.Reason != "cyber_abuse_guard_router_panic") {
		t.Fatalf("native enforcing recovery is not a local self-route: %+v", route)
	}
}
