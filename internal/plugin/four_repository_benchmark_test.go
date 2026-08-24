package plugin

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
)

func BenchmarkFourRepositoryModelRoute(b *testing.B) {
	b.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	balancedConfig := "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: false\n"
	subjectConfig := "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n  max_subjects: 64\n"

	shortChat, _ := fourRepoMarshalAndCheckBytes(b, fourRepoChatUser, fourRepoBenignUser, "")
	shortResponses, _ := fourRepoMarshalAndCheckBytes(b, fourRepoResponsesUser, fourRepoBenignUser, "")
	additionalWrapper := repositoryNeutralSizedText(b, 17166, fourRepoSurrogateProfiles[2].core)
	additionalTools, _ := fourRepoMarshalAndCheckBytes(
		b, fourRepoAdditionalNamespace, additionalWrapper, fourRepoBenignUser,
	)
	benignNearNeighbor := repositoryNeutralSizedText(b, 17166, fourRepoSurrogateProfiles[4].core)
	nearNeighbor, _ := fourRepoMarshalAndCheckBytes(b, fourRepoResponsesUser, benignNearNeighbor, "")

	benchmarks := []struct {
		name    string
		config  string
		format  string
		body    []byte
		headers http.Header
	}{
		{
			name: "off/chat-clean",
			// Keep the disabled fast-path benchmark hermetic. Audit defaults to
			// enabled, which would otherwise open the operator-style default path
			// under $HOME and make the result depend on a database left by another
			// checkout or schema version.
			config: "mode: off\naudit:\n  enabled: false\n",
			format: "openai",
			body:   shortChat,
		},
		{name: "balanced/chat-clean", config: balancedConfig, format: "openai", body: shortChat},
		{name: "balanced/responses-clean", config: balancedConfig, format: "openai-response", body: shortResponses},
		{
			name: "balanced/chat-clean-subject-enabled", config: subjectConfig, format: "openai", body: shortChat,
			headers: http.Header{"Authorization": []string{"Bearer benchmark-clean-subject"}},
		},
		{name: "balanced/additional-tools-wrapper-17166B", config: balancedConfig, format: "openai-response", body: additionalTools},
		{name: "balanced/trusted-benign-neighbor-17166B", config: balancedConfig, format: "openai-response", body: nearNeighbor},
	}

	for _, benchmark := range benchmarks {
		benchmark := benchmark
		b.Run(benchmark.name, func(b *testing.B) {
			p := New()
			b.Cleanup(p.Shutdown)
			register(b, p, benchmark.config)

			request, err := json.Marshal(pluginapi.ModelRouteRequest{
				SourceFormat:   benchmark.format,
				RequestedModel: "four-repository-benchmark",
				Headers:        benchmark.headers,
				Body:           benchmark.body,
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
				b.Fatalf("benign benchmark fixture was handled: %+v", route)
			}

			b.ReportAllocs()
			b.SetBytes(int64(len(benchmark.body)))
			b.ResetTimer()
			for index := 0; index < b.N; index++ {
				raw, code = p.Call(pluginabi.MethodModelRoute, request)
				if code != 0 || len(raw) == 0 {
					b.Fatalf("model.route code=%d envelope=%s", code, raw)
				}
			}
		})
	}
}

func BenchmarkFourRepositoryParallelCleanSubjectEnabled(b *testing.B) {
	b.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	b.Cleanup(p.Shutdown)
	register(b, p, "mode: balanced\naudit:\n  enabled: false\nsubject_control:\n  enabled: true\n  max_subjects: 1024\n")
	body, _ := fourRepoMarshalAndCheckBytes(b, fourRepoChatUser, fourRepoBenignUser, "")
	request, err := json.Marshal(pluginapi.ModelRouteRequest{
		SourceFormat:   "openai",
		RequestedModel: "four-repository-parallel-benchmark",
		Headers:        http.Header{"Authorization": []string{"Bearer benchmark-parallel-clean"}},
		Body:           body,
	})
	if err != nil {
		b.Fatal(err)
	}

	b.ReportAllocs()
	b.SetBytes(int64(len(body)))
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			raw, code := p.Call(pluginabi.MethodModelRoute, request)
			if code != 0 || len(raw) == 0 {
				b.Errorf("model.route code=%d envelope=%s", code, raw)
				return
			}
		}
	})
}

func TestFourRepositoryFullRoutePerformanceAcceptance(t *testing.T) {
	if pluginRaceEnabled {
		t.Skip("wall-clock and allocation acceptance is not meaningful under the race detector")
	}
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")

	shortBody, _ := fourRepoMarshalAndCheckBytes(t, fourRepoChatUser, fourRepoBenignUser, "")
	wrapper := repositoryNeutralSizedText(t, 17166, fourRepoSurrogateProfiles[2].core)
	wrapperBody, _ := fourRepoMarshalAndCheckBytes(
		t, fourRepoAdditionalNamespace, wrapper, fourRepoBenignUser,
	)
	auditDir := filepath.ToSlash(t.TempDir())

	tests := []struct {
		name           string
		configuration  string
		format         string
		body           []byte
		headers        http.Header
		parallel       bool
		maxNSPerOp     int64
		maxBytesPerOp  int64
		maxAllocsPerOp int64
	}{
		{
			name: "ordinary clean subject enabled",
			configuration: "mode: balanced\naudit:\n  enabled: false\n" +
				"subject_control:\n  enabled: true\n  max_subjects: 1024\n",
			format: "openai", body: shortBody,
			headers:    http.Header{"Authorization": []string{"Bearer performance-clean-subject"}},
			maxNSPerOp: 2_000_000, maxBytesPerOp: 512 << 10, maxAllocsPerOp: 1000,
		},
		{
			name: "wrapper audit counter fast path",
			configuration: "mode: balanced\naudit:\n  enabled: true\n  data_dir: \"" + auditDir + "\"\n" +
				"  log_request_hash: true\n  log_subject_hash: true\n" +
				"subject_control:\n  enabled: true\n  max_subjects: 64\n",
			format: "openai-response", body: wrapperBody,
			headers:    http.Header{"Authorization": []string{"Bearer performance-wrapper-audit"}},
			maxNSPerOp: 50_000_000, maxBytesPerOp: 1536 << 10, maxAllocsPerOp: 3000,
		},
		{
			name: "parallel ordinary clean subject enabled",
			configuration: "mode: balanced\naudit:\n  enabled: false\n" +
				"subject_control:\n  enabled: true\n  max_subjects: 1024\n",
			format: "openai", body: shortBody,
			headers:    http.Header{"Authorization": []string{"Bearer performance-parallel-clean"}},
			parallel:   true,
			maxNSPerOp: 1_000_000, maxBytesPerOp: 512 << 10, maxAllocsPerOp: 1000,
		},
	}

	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			result := testing.Benchmark(func(b *testing.B) {
				p := New()
				defer p.Shutdown()
				register(b, p, testCase.configuration)
				request, err := json.Marshal(pluginapi.ModelRouteRequest{
					SourceFormat: testCase.format, RequestedModel: "four-repository-performance-acceptance",
					Headers: testCase.headers, Body: testCase.body,
				})
				if err != nil {
					b.Fatal(err)
				}
				raw, code := p.Call(pluginabi.MethodModelRoute, request)
				if code != 0 {
					b.Fatalf("warmup model.route code=%d envelope=%s", code, raw)
				}
				var route pluginapi.ModelRouteResponse
				decodeOKResult(b, raw, &route)
				if route.Handled {
					b.Fatalf("benign acceptance fixture was handled: %+v", route)
				}

				b.ReportAllocs()
				b.ResetTimer()
				if testCase.parallel {
					b.RunParallel(func(pb *testing.PB) {
						for pb.Next() {
							routeRaw, routeCode := p.Call(pluginabi.MethodModelRoute, request)
							if routeCode != 0 || len(routeRaw) == 0 {
								b.Errorf("parallel model.route code=%d envelope=%s", routeCode, routeRaw)
								return
							}
						}
					})
					return
				}
				for index := 0; index < b.N; index++ {
					routeRaw, routeCode := p.Call(pluginabi.MethodModelRoute, request)
					if routeCode != 0 || len(routeRaw) == 0 {
						b.Fatalf("model.route code=%d envelope=%s", routeCode, routeRaw)
					}
				}
			})

			t.Logf("route acceptance: %d ns/op, %d B/op, %d allocs/op",
				result.NsPerOp(), result.AllocedBytesPerOp(), result.AllocsPerOp())
			if got := result.NsPerOp(); got > testCase.maxNSPerOp {
				t.Fatalf("route latency=%d ns/op, want <=%d", got, testCase.maxNSPerOp)
			}
			if got := result.AllocedBytesPerOp(); got > testCase.maxBytesPerOp {
				t.Fatalf("route allocation=%d B/op, want <=%d", got, testCase.maxBytesPerOp)
			}
			if got := result.AllocsPerOp(); got > testCase.maxAllocsPerOp {
				t.Fatalf("route allocations=%d/op, want <=%d", got, testCase.maxAllocsPerOp)
			}
		})
	}
}
