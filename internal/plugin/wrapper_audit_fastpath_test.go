package plugin

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/config"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
)

func TestBalancedAuditOnWrapperOnlyCounterFastPath(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	wrapper := repositoryNeutralSizedText(t, 17166, fourRepoSurrogateProfiles[2].core)
	body, _ := fourRepoMarshalAndCheckBytes(t, fourRepoAdditionalNamespace, wrapper, fourRepoBenignUser)
	headers := http.Header{"Authorization": []string{"Bearer wrapper-audit-fast-path"}}

	for _, testCase := range []struct {
		name       string
		optIn      bool
		wantHashes int
		wantEvents int
	}{
		{name: "default counter only"},
		{name: "explicit per-request persistence", optIn: true, wantHashes: 1, wantEvents: 1},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			hashCalls := countRequestHashes(p)
			configuration := "mode: balanced\naudit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(t.TempDir()) + "\"\n  log_request_hash: true\n  log_subject_hash: true\n"
			if testCase.optIn {
				configuration += "  persist_wrapper_only: true\n"
			}
			configuration += "subject_control:\n  enabled: true\n  max_subjects: 64\n"
			register(t, p, configuration)

			route := callSubjectAdmissionRoute(t, p, fourRepoCarrierFormat(fourRepoAdditionalNamespace), string(body), headers)
			if route.Handled || route.Reason != "" {
				t.Fatalf("wrapper-only benign request route=%+v", route)
			}
			snapshot := p.counters.snapshot()
			if snapshot["audited"] != 1 || snapshot["control_plane_meta_override"] != 1 || snapshot["blocked"] != 0 {
				t.Fatalf("wrapper-only counters=%v", snapshot)
			}
			if *hashCalls != testCase.wantHashes {
				t.Fatalf("request hash calls=%d, want %d", *hashCalls, testCase.wantHashes)
			}

			subjectHash := p.identifier.FromHeaders(headers).Hash
			if state, present := p.runtime.Load().subject.Snapshot(subjectHash); present {
				t.Fatalf("wrapper-only audit created subject state: %+v", state)
			}
			events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
			items, ok := events["events"].([]any)
			if !ok || len(items) != testCase.wantEvents {
				t.Fatalf("wrapper-only events=%#v, want %d", events, testCase.wantEvents)
			}
			status := p.runtime.Load().audit.Status()
			if status.Enqueued != uint64(testCase.wantEvents) || status.Written != uint64(testCase.wantEvents) {
				t.Fatalf("audit status=%+v, want enqueued/written=%d", status, testCase.wantEvents)
			}
			if testCase.wantEvents == 0 {
				return
			}
			event, ok := items[0].(map[string]any)
			if !ok || event["action"] != "audit" || event["decision"] != "audit_suspicious_text" || event["coverage"] != "complete" {
				t.Fatalf("wrapper-only persisted event=%#v", items[0])
			}
			requestHash, _ := event["request_hash"].(string)
			if !strings.HasPrefix(requestHash, "sha256:") || event["subject_hash"] != subjectHash {
				t.Fatalf("wrapper-only persisted identities=%#v", event)
			}
		})
	}
}

func TestWrapperAuditFastPathPreservesSecurityEvents(t *testing.T) {
	completeWrapper := inspectionOutcome{
		Classification: classifier.Result{
			Action:        classifier.ActionAudit,
			FindingOrigin: classifier.FindingOriginNonUserOrUntrusted,
			Coverage:      classifier.Coverage{State: classifier.CoverageComplete},
			Behavior:      &classifier.BehaviorGraph{Wrapper: true},
		},
	}
	wrapperDecision := inspectionDisposition(config.ModeBalanced, completeWrapper, config.OpaqueMediaPolicyAudit)
	if shouldPersistInspectionDecision(config.Default(), completeWrapper, wrapperDecision) {
		t.Fatal("complete category-free wrapper-only audit should use counters by default")
	}
	optIn := config.Default()
	optIn.Audit.PersistWrapperOnly = true
	if !shouldPersistInspectionDecision(optIn, completeWrapper, wrapperDecision) {
		t.Fatal("persist_wrapper_only did not restore per-request persistence")
	}
	trustedWrapper := completeWrapper
	trustedWrapper.Classification.FindingOrigin = classifier.FindingOriginUserContent
	trustedDecision := inspectionDisposition(config.ModeBalanced, trustedWrapper, config.OpaqueMediaPolicyAudit)
	if !shouldPersistInspectionDecision(config.Default(), trustedWrapper, trustedDecision) {
		t.Fatal("trusted-user wrapper audit lost per-request attribution")
	}

	tests := []struct {
		name    string
		mode    config.Mode
		outcome inspectionOutcome
	}{
		{
			name: "complete base cyber audit",
			mode: config.ModeBalanced,
			outcome: inspectionOutcome{Classification: classifier.Result{
				Action: classifier.ActionAudit, Category: "malware",
				Coverage: classifier.Coverage{State: classifier.CoverageComplete},
				Behavior: &classifier.BehaviorGraph{BaseBehavior: true},
			}},
		},
		{
			name: "category-free base cyber audit",
			mode: config.ModeBalanced,
			outcome: inspectionOutcome{Classification: classifier.Result{
				Action:   classifier.ActionAudit,
				Coverage: classifier.Coverage{State: classifier.CoverageComplete},
				Behavior: &classifier.BehaviorGraph{Wrapper: true, BaseBehavior: true},
			}},
		},
		{
			name: "complete block",
			mode: config.ModeBalanced,
			outcome: inspectionOutcome{Classification: classifier.Result{
				Action:   classifier.ActionBlock,
				Coverage: classifier.Coverage{State: classifier.CoverageComplete},
				Behavior: &classifier.BehaviorGraph{Wrapper: true},
			}},
		},
		{
			name: "incomplete wrapper",
			mode: config.ModeBalanced,
			outcome: inspectionOutcome{
				Classification: completeWrapper.Classification,
				Incomplete:     []extract.IncompleteReason{extract.IncompleteParseError},
			},
		},
		{
			name: "opaque media wrapper",
			mode: config.ModeBalanced,
			outcome: inspectionOutcome{
				Classification: completeWrapper.Classification,
				OpaqueMedia:    true,
			},
		},
		{
			name: "subject cooldown audit",
			mode: config.ModeAudit,
			outcome: inspectionOutcome{
				Classification: completeWrapper.Classification,
				SubjectBlocked: true,
			},
		},
		{
			name: "subject cooldown balanced",
			mode: config.ModeBalanced,
			outcome: inspectionOutcome{
				Classification: completeWrapper.Classification,
				SubjectBlocked: true,
			},
		},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			decision := inspectionDisposition(testCase.mode, testCase.outcome, config.OpaqueMediaPolicyAudit)
			if !shouldPersistInspectionDecision(config.Default(), testCase.outcome, decision) {
				t.Fatalf("security-relevant decision was suppressed: outcome=%+v decision=%+v", testCase.outcome, decision)
			}
		})
	}

	observeDecision := inspectionDisposition(config.ModeObserve, completeWrapper, config.OpaqueMediaPolicyAudit)
	if shouldPersistInspectionDecision(config.Default(), completeWrapper, observeDecision) {
		t.Fatalf("observe-only wrapper unexpectedly entered persistence: %+v", observeDecision)
	}
	disabledAudit := config.Default()
	disabledAudit.Audit.Enabled = false
	if shouldPersistInspectionDecision(disabledAudit, completeWrapper, wrapperDecision) {
		t.Fatal("disabled audit unexpectedly persisted a wrapper-only observation")
	}

	t.Run("full route wrapper plus trusted-user base behavior", func(t *testing.T) {
		p := New()
		t.Cleanup(p.Shutdown)
		hashCalls := countRequestHashes(p)
		register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(t.TempDir())+"\"\n  log_request_hash: true\nsubject_control:\n  enabled: false\n")

		wrapper := repositoryNeutralSizedText(t, 17166, fourRepoSurrogateProfiles[2].core)
		body, _ := fourRepoMarshalAndCheckBytes(t, fourRepoAdditionalNamespace, wrapper, fourRepoAbuseUser)
		route := callRoleRoute(t, p, fourRepoCarrierFormat(fourRepoAdditionalNamespace), string(body))
		if !route.Handled || route.Reason != "cyber_abuse_guard_hard_policy" {
			t.Fatalf("wrapper plus trusted-user base behavior route=%+v", route)
		}
		if *hashCalls != 1 {
			t.Fatalf("block and audit did not share one request hash: calls=%d", *hashCalls)
		}
		events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
		items, ok := events["events"].([]any)
		if !ok || len(items) != 1 {
			t.Fatalf("wrapper plus base behavior events=%#v, want one", events)
		}
		event, ok := items[0].(map[string]any)
		category, _ := event["category"].(string)
		if !ok || event["action"] != "block" || event["decision"] != "block_malicious_text" || category == "" {
			t.Fatalf("wrapper plus base behavior event=%#v", items[0])
		}
	})
}

func TestBalancedAuditOnTrustedUserWrapperPersists(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	hashCalls := countRequestHashes(p)
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(t.TempDir())+"\"\n  log_request_hash: true\n  log_subject_hash: false\nsubject_control:\n  enabled: false\n")

	wrapper := repositoryNeutralSizedText(t, 5137, fourRepoSurrogateProfiles[2].core)
	body, _ := fourRepoMarshalAndCheckBytes(t, fourRepoChatUser, wrapper, "")
	if route := callRoleRoute(t, p, fourRepoCarrierFormat(fourRepoChatUser), string(body)); route.Handled || route.Reason != "" {
		t.Fatalf("trusted-user wrapper-only request route=%+v", route)
	}
	snapshot := p.counters.snapshot()
	if snapshot["audited"] != 1 || snapshot["control_plane_meta_override"] != 1 || snapshot["blocked"] != 0 {
		t.Fatalf("trusted-user wrapper counters=%v", snapshot)
	}
	if *hashCalls != 1 {
		t.Fatalf("trusted-user wrapper request hash calls=%d, want 1", *hashCalls)
	}
	events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	items, ok := events["events"].([]any)
	if !ok || len(items) != 1 {
		t.Fatalf("trusted-user wrapper events=%#v, want one", events)
	}
	event, ok := items[0].(map[string]any)
	requestHash, _ := event["request_hash"].(string)
	if !ok || event["action"] != "audit" || event["decision"] != "audit_suspicious_text" || !strings.HasPrefix(requestHash, "sha256:") {
		t.Fatalf("trusted-user wrapper event=%#v", items[0])
	}
}

func TestBalancedAuditOnWrapperOnlyAllocationAcceptance(t *testing.T) {
	if pluginRaceEnabled {
		t.Skip("allocation acceptance is not meaningful under the race detector")
	}
	previousProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previousProcs)
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	wrapper := repositoryNeutralSizedText(t, 17166, fourRepoSurrogateProfiles[2].core)
	body, _ := fourRepoMarshalAndCheckBytes(t, fourRepoAdditionalNamespace, wrapper, fourRepoBenignUser)

	run := func(enabled bool) testing.BenchmarkResult {
		return testing.Benchmark(func(b *testing.B) {
			p := New()
			defer p.Shutdown()
			hashCalls := countRequestHashes(p)
			auditEnqueued := func() uint64 {
				state := p.runtime.Load()
				if state == nil || state.audit == nil {
					return 0
				}
				return state.audit.Status().Enqueued
			}
			configuration := "mode: balanced\naudit:\n  enabled: false\n"
			if enabled {
				configuration = "mode: balanced\naudit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(b.TempDir()) + "\"\n  log_request_hash: true\n  log_subject_hash: true\n"
			}
			configuration += "subject_control:\n  enabled: true\n  max_subjects: 64\n"
			register(b, p, configuration)
			if enabled {
				state := p.runtime.Load()
				if state == nil || state.audit == nil {
					b.Fatal("audit-on benchmark runtime is unavailable")
				}
				// Store.Open starts its writer asynchronously. Complete a barrier
				// before ResetTimer so one-time worker/ticker setup is not charged
				// as per-request audit overhead by process-wide benchmark stats.
				if err := state.audit.Flush(context.Background()); err != nil {
					b.Fatalf("initialize audit-on benchmark worker: %v", err)
				}
			}

			request, err := json.Marshal(pluginapi.ModelRouteRequest{
				SourceFormat:   fourRepoCarrierFormat(fourRepoAdditionalNamespace),
				RequestedModel: "wrapper-audit-allocation-acceptance",
				Headers:        http.Header{"Authorization": []string{"Bearer wrapper-audit-allocation-acceptance"}},
				Body:           body,
			})
			if err != nil {
				b.Fatal(err)
			}
			raw, code := p.Call(pluginabi.MethodModelRoute, request)
			if code != 0 || len(raw) == 0 {
				b.Fatalf("warmup model.route code=%d envelope=%s", code, raw)
			}
			if *hashCalls != 0 || auditEnqueued() != 0 {
				b.Fatalf("warmup entered per-request audit path: hashes=%d enqueued=%d", *hashCalls, auditEnqueued())
			}

			b.ReportAllocs()
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				raw, code = p.Call(pluginabi.MethodModelRoute, request)
				if code != 0 || len(raw) == 0 {
					b.Fatalf("model.route code=%d envelope=%s", code, raw)
				}
			}
			b.StopTimer()
			if *hashCalls != 0 || auditEnqueued() != 0 {
				b.Fatalf("benchmark entered per-request audit path: hashes=%d enqueued=%d", *hashCalls, auditEnqueued())
			}
		})
	}

	const allocationSampleCount = 3
	byteDeltas := make([]int64, 0, allocationSampleCount)
	allocationDeltas := make([]int64, 0, allocationSampleCount)
	for sample := 0; sample < allocationSampleCount; sample++ {
		var off, on testing.BenchmarkResult
		// Alternate order so process-wide allocator drift cannot consistently
		// favor either configuration across the paired samples.
		if sample%2 == 0 {
			off = run(false)
			on = run(true)
		} else {
			on = run(true)
			off = run(false)
		}
		byteDelta := on.AllocedBytesPerOp() - off.AllocedBytesPerOp()
		allocationDelta := on.AllocsPerOp() - off.AllocsPerOp()
		byteDeltas = append(byteDeltas, byteDelta)
		allocationDeltas = append(allocationDeltas, allocationDelta)
		t.Logf("wrapper audit allocation sample=%d/%d off=%d B/op %d allocs/op N=%d on=%d B/op %d allocs/op N=%d delta=%d B/op %d allocs/op",
			sample+1, allocationSampleCount,
			off.AllocedBytesPerOp(), off.AllocsPerOp(), off.N,
			on.AllocedBytesPerOp(), on.AllocsPerOp(), on.N,
			byteDelta, allocationDelta)
		if bytesPerOp := on.AllocedBytesPerOp(); bytesPerOp >= 1536<<10 {
			t.Fatalf("audit-on counter-only allocation=%d B/op, want <1.5MiB", bytesPerOp)
		}
		if allocations := on.AllocsPerOp(); allocations >= 3000 {
			t.Fatalf("audit-on counter-only allocations=%d/op, want <3000", allocations)
		}
	}
	slices.Sort(byteDeltas)
	slices.Sort(allocationDeltas)
	medianByteDelta := byteDeltas[len(byteDeltas)/2]
	medianAllocationDelta := allocationDeltas[len(allocationDeltas)/2]
	t.Logf("wrapper audit allocation median delta=%d B/op %d allocs/op sorted-byte-deltas=%v sorted-allocation-deltas=%v",
		medianByteDelta, medianAllocationDelta, byteDeltas, allocationDeltas)
	// testing.Benchmark derives B/op from process-wide MemStats and independently
	// calibrates N for each arm. GC and per-P sync.Pool state can therefore dominate
	// a single difference. One P follows testing.AllocsPerRun's stabilization model;
	// the median of three alternating pairs rejects residual noise while retaining
	// the exact 4 KiB product budget and the per-sample absolute gates above.
	if medianByteDelta > 4<<10 {
		t.Fatalf("median audit-on counter-only overhead=%d B/op, want <=4KiB over audit-off across %d alternating paired samples", medianByteDelta, allocationSampleCount)
	}
	if medianAllocationDelta > 24 {
		t.Fatalf("median audit-on counter-only overhead=%d allocs/op, want <=24 over audit-off across %d alternating paired samples", medianAllocationDelta, allocationSampleCount)
	}
}

func BenchmarkBalancedAuditOnWrapperOnly17166ModelRoute(b *testing.B) {
	b.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	wrapper := repositoryNeutralSizedText(b, 17166, fourRepoSurrogateProfiles[2].core)
	body, _ := fourRepoMarshalAndCheckBytes(b, fourRepoAdditionalNamespace, wrapper, fourRepoBenignUser)
	for _, benchmark := range []struct {
		name  string
		optIn bool
	}{
		{name: "counter-only-default"},
		{name: "persist-wrapper-only-opt-in", optIn: true},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			p := New()
			b.Cleanup(p.Shutdown)
			hashCalls := countRequestHashes(p)
			configuration := "mode: balanced\naudit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(b.TempDir()) + "\"\n  log_request_hash: true\n  log_subject_hash: true\n"
			if benchmark.optIn {
				configuration += "  persist_wrapper_only: true\n"
			}
			configuration += "subject_control:\n  enabled: true\n  max_subjects: 64\n"
			register(b, p, configuration)

			request, err := json.Marshal(pluginapi.ModelRouteRequest{
				SourceFormat:   fourRepoCarrierFormat(fourRepoAdditionalNamespace),
				RequestedModel: "wrapper-audit-fast-path-benchmark",
				Headers:        http.Header{"Authorization": []string{"Bearer wrapper-audit-fast-path-benchmark"}},
				Body:           body,
			})
			if err != nil {
				b.Fatal(err)
			}
			raw, code := p.Call(pluginabi.MethodModelRoute, request)
			if code != 0 {
				b.Fatalf("model.route code=%d envelope=%s", code, raw)
			}
			var route pluginapi.ModelRouteResponse
			decodeOKResult(b, raw, &route)
			if route.Handled {
				b.Fatalf("wrapper-only benign benchmark was handled: %+v", route)
			}
			status := p.runtime.Load().audit.Status()
			if !benchmark.optIn && (*hashCalls != 0 || status.Enqueued != 0) {
				b.Fatalf("counter-only warmup used per-request audit path: hashes=%d status=%+v", *hashCalls, status)
			}
			if benchmark.optIn && (*hashCalls != 1 || status.Enqueued != 1) {
				b.Fatalf("opt-in warmup missed per-request audit path: hashes=%d status=%+v", *hashCalls, status)
			}

			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				raw, code = p.Call(pluginabi.MethodModelRoute, request)
				if code != 0 || len(raw) == 0 {
					b.Fatalf("model.route code=%d envelope=%s", code, raw)
				}
			}
			b.StopTimer()
			status = p.runtime.Load().audit.Status()
			if !benchmark.optIn && (*hashCalls != 0 || status.Enqueued != 0) {
				b.Fatalf("counter-only benchmark used per-request audit path: hashes=%d status=%+v", *hashCalls, status)
			}
			if benchmark.optIn && *hashCalls != b.N+1 {
				b.Fatalf("opt-in benchmark request hashes=%d, want %d", *hashCalls, b.N+1)
			}
			b.ReportMetric(float64(*hashCalls)/float64(b.N+1), "hashes/route")
			b.ReportMetric(float64(status.Enqueued)/float64(b.N+1), "events/route")
		})
	}
}
