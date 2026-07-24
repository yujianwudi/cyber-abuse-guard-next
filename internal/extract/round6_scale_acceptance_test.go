package extract

import (
	"testing"
	"time"
)

// TestRound6LongTextScaleAcceptance retains its gate-stable historical name,
// but covers text-heavy, key-rich, and semantic-field-rich long JSON shapes.
func TestRound6LongTextScaleAcceptance(t *testing.T) {
	if extractRaceEnabled {
		t.Skip("wall-clock and allocation acceptance is not meaningful under the race detector")
	}

	type sizeLimit struct {
		name          string
		size          int
		maxLatency    time.Duration
		maxBytesPerOp int64
		maxAllocs     int64
	}
	type fixture struct {
		name  string
		body  func(int) []byte
		sizes []sizeLimit
	}
	fixtures := []fixture{
		{
			name: "Text",
			body: round6LongTextBenchmarkBody,
			sizes: []sizeLimit{
				{name: "1MiB", size: 1 << 20, maxLatency: 150 * time.Millisecond, maxBytesPerOp: 512 << 10, maxAllocs: 64},
				{name: "Near8MiB", size: HardMaxTotalTextBytes - 4096, maxLatency: 1200 * time.Millisecond, maxBytesPerOp: 512 << 10, maxAllocs: 64},
			},
		},
		{
			name: "KeyRich",
			body: round6KeyRichBenchmarkBody,
			sizes: []sizeLimit{
				{name: "1MiB", size: 1 << 20, maxLatency: 150 * time.Millisecond, maxBytesPerOp: 768 << 10, maxAllocs: 25_000},
				{name: "Near8MiB", size: HardMaxTotalTextBytes - 4096, maxLatency: 1200 * time.Millisecond, maxBytesPerOp: 3 << 20, maxAllocs: 160_000},
			},
		},
		{
			name: "SemanticRich",
			body: round6SemanticRichBenchmarkBody,
			sizes: []sizeLimit{
				{name: "1MiB", size: 1 << 20, maxLatency: 150 * time.Millisecond, maxBytesPerOp: 512 << 10, maxAllocs: 10_000},
				{name: "Near8MiB", size: HardMaxTotalTextBytes - 4096, maxLatency: 1200 * time.Millisecond, maxBytesPerOp: 1 << 20, maxAllocs: 60_000},
			},
		},
	}

	for _, fixture := range fixtures {
		fixture := fixture
		t.Run(fixture.name, func(t *testing.T) {
			results := make([]testing.BenchmarkResult, 0, len(fixture.sizes))
			bodySizes := make([]int, 0, len(fixture.sizes))
			for _, limit := range fixture.sizes {
				limit := limit
				t.Run(limit.name, func(t *testing.T) {
					body := fixture.body(limit.size)
					result := testing.Benchmark(func(b *testing.B) {
						benchmarkRound6ScanBody(b, body)
					})
					results = append(results, result)
					bodySizes = append(bodySizes, len(body))
					t.Logf(
						"round6 long JSON acceptance: fixture=%s bytes=%d ns/op=%d B/op=%d allocs/op=%d",
						fixture.name, len(body), result.NsPerOp(), result.AllocedBytesPerOp(), result.AllocsPerOp(),
					)
					if latency := time.Duration(result.NsPerOp()); latency > limit.maxLatency {
						t.Fatalf("latency=%s, want <=%s", latency, limit.maxLatency)
					}
					if bytesPerOp := result.AllocedBytesPerOp(); bytesPerOp > limit.maxBytesPerOp {
						t.Fatalf("allocation=%d B/op, want <=%d", bytesPerOp, limit.maxBytesPerOp)
					}
					if allocs := result.AllocsPerOp(); allocs > limit.maxAllocs {
						t.Fatalf("allocations=%d/op, want <=%d", allocs, limit.maxAllocs)
					}
				})
			}

			if len(results) != 2 || len(bodySizes) != 2 {
				t.Fatalf("measurements=%d body_sizes=%d, want 2", len(results), len(bodySizes))
			}
			smallNSPerByte := float64(results[0].NsPerOp()) / float64(bodySizes[0])
			largeNSPerByte := float64(results[1].NsPerOp()) / float64(bodySizes[1])
			if largeNSPerByte > smallNSPerByte*2.5 {
				t.Fatalf(
					"near-8MiB CPU slope regressed: 1MiB=%0.2f ns/byte near8MiB=%0.2f ns/byte",
					smallNSPerByte, largeNSPerByte,
				)
			}
		})
	}
}
