package plugin

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/audit"
)

func TestRawCaptureManagementResponsePerformanceAcceptance(t *testing.T) {
	if pluginRaceEnabled {
		t.Skip("wall-clock and allocation acceptance is not meaningful under the race detector")
	}
	page := rawCaptureManagementPerformancePage("&'\"<script>alert(1)</script>")
	result := testing.Benchmark(func(b *testing.B) {
		benchmarkRawCaptureManagementResponse(b, page)
	})
	t.Logf("raw capture management acceptance: ns/op=%d B/op=%d allocs/op=%d", result.NsPerOp(), result.AllocedBytesPerOp(), result.AllocsPerOp())
	if latency := time.Duration(result.NsPerOp()); latency > 500*time.Millisecond {
		t.Fatalf("raw capture management latency=%s, want <=500ms", latency)
	}
	if bytesPerOp := result.AllocedBytesPerOp(); bytesPerOp > 16<<20 {
		t.Fatalf("raw capture management allocation=%d B/op, want <=%d", bytesPerOp, 16<<20)
	}
	if allocs := result.AllocsPerOp(); allocs > 1600 {
		t.Fatalf("raw capture management allocations=%d/op, want <=1600", allocs)
	}
}

func BenchmarkRawCaptureManagementResponseBudget(b *testing.B) {
	for _, fixture := range []struct {
		name    string
		pattern string
	}{
		{name: "Plain8MiB", pattern: "ordinary-review-text-"},
		{name: "WorstHTML8MiB", pattern: "&'\"<script>alert(1)</script>"},
	} {
		fixture := fixture
		b.Run(fixture.name, func(b *testing.B) {
			benchmarkRawCaptureManagementResponse(b, rawCaptureManagementPerformancePage(fixture.pattern))
		})
	}
}

func benchmarkRawCaptureManagementResponse(b *testing.B, page audit.RawCapturePage) {
	b.Helper()
	b.ReportAllocs()
	b.SetBytes(int64(page.PreviewBytes))
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		response, err := managementBoundRawCaptureResponse(page, maxManagementRawCaptureLimit)
		if err != nil {
			b.Fatal(err)
		}
		if response.ReturnedCount == 0 || response.CPAHostResponseBytes > maxManagementRawPreviewBytes {
			b.Fatalf("invalid bounded response: count=%d bytes=%d", response.ReturnedCount, response.CPAHostResponseBytes)
		}
	}
}

func rawCaptureManagementPerformancePage(pattern string) audit.RawCapturePage {
	const previewBytes = 1 << 20
	preview := strings.Repeat(pattern, (previewBytes+len(pattern)-1)/len(pattern))[:previewBytes]
	captures := make([]audit.RawRequestCapture, 8)
	for index := range captures {
		captures[index] = audit.RawRequestCapture{
			ID:         fmt.Sprintf("capture-performance-%02d", index),
			EventID:    fmt.Sprintf("event-performance-%02d", index),
			Timestamp:  time.Date(2026, 7, 21, 12, 0, 0, index, time.UTC),
			Action:     "block",
			Decision:   "block_malicious_text",
			Truncated:  true,
			Redacted:   false,
			RawPreview: preview,
			RawSHA256:  "sha256:" + strings.Repeat("a", 64),
		}
	}
	return audit.RawCapturePage{
		Captures:     captures,
		PreviewBytes: len(captures) * previewBytes,
	}
}
