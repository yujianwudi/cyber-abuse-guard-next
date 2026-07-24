package audit

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

var rawCaptureBenchmarkSizes = []struct {
	name string
	size int
}{
	{name: "1KiB", size: 1 << 10},
	{name: "64KiB", size: 64 << 10},
	{name: "1MiB", size: 1 << 20},
	{name: "Near8MiB", size: (8 << 20) - (64 << 10)},
}

func TestRawCapturePerformanceAcceptance(t *testing.T) {
	if auditRaceEnabled {
		t.Skip("wall-clock and allocation acceptance is not meaningful under the race detector")
	}
	const size = (8 << 20) - (64 << 10)
	raw := rawCaptureBenchmarkBody(size)
	input := benchmarkRawCaptureInput(raw)
	cfg := RawCaptureConfig{
		Enabled: true, OnlyBlocked: true, MaxBytes: maxRawCaptureBytes,
		TTL: 72 * time.Hour, RedactSecrets: true,
	}
	now := time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC)
	prepare := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for iteration := 0; iteration < b.N; iteration++ {
			if _, err := prepareRawCapture(input, cfg, now); err != nil {
				b.Fatal(err)
			}
		}
	})
	t.Logf("near-8MiB raw capture prepare: ns/op=%d B/op=%d allocs/op=%d", prepare.NsPerOp(), prepare.AllocedBytesPerOp(), prepare.AllocsPerOp())
	if latency := time.Duration(prepare.NsPerOp()); latency > 1200*time.Millisecond {
		t.Fatalf("near-8MiB raw capture prepare latency=%s, want <=1.2s", latency)
	}
	if bytesPerOp := prepare.AllocedBytesPerOp(); bytesPerOp > 4<<20 {
		t.Fatalf("near-8MiB raw capture prepare allocation=%d B/op, want <=%d", bytesPerOp, 4<<20)
	}
	if allocs := prepare.AllocsPerOp(); allocs > 160 {
		t.Fatalf("near-8MiB raw capture prepare allocations=%d/op, want <=160", allocs)
	}

	event := rawCaptureEvent("composite-acceptance", now, "block", "block_malicious_text", raw)
	compositeInput := RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
		RawRequest: raw,
	}
	composite := testing.Benchmark(func(b *testing.B) {
		store := benchmarkRawCaptureStore(1)
		b.ReportAllocs()
		for iteration := 0; iteration < b.N; iteration++ {
			accepted, err := store.EnqueueEventWithRawCapture(event, compositeInput)
			if err != nil || !accepted {
				b.Fatalf("accepted=%t error=%v", accepted, err)
			}
			<-store.queue
			store.releaseQueueSlot()
		}
	})
	t.Logf("near-8MiB composite admission: ns/op=%d B/op=%d allocs/op=%d", composite.NsPerOp(), composite.AllocedBytesPerOp(), composite.AllocsPerOp())
	if latency := time.Duration(composite.NsPerOp()); latency > 1500*time.Millisecond {
		t.Fatalf("near-8MiB composite latency=%s, want <=1.5s", latency)
	}
	if bytesPerOp := composite.AllocedBytesPerOp(); bytesPerOp > 5<<20 {
		t.Fatalf("near-8MiB composite allocation=%d B/op, want <=%d", bytesPerOp, 5<<20)
	}
	if allocs := composite.AllocsPerOp(); allocs > 200 {
		t.Fatalf("near-8MiB composite allocations=%d/op, want <=200", allocs)
	}

	queueFull := testing.Benchmark(func(b *testing.B) {
		store := benchmarkRawCaptureStore(1)
		store.queueSlots <- struct{}{}
		b.ReportAllocs()
		for iteration := 0; iteration < b.N; iteration++ {
			if err := store.RecordRawCapture(input); !errors.Is(err, ErrQueueFull) {
				b.Fatalf("RecordRawCapture() error=%v", err)
			}
		}
	})
	t.Logf("near-8MiB queue-full rejection: ns/op=%d B/op=%d allocs/op=%d", queueFull.NsPerOp(), queueFull.AllocedBytesPerOp(), queueFull.AllocsPerOp())
	if latency := time.Duration(queueFull.NsPerOp()); latency > 50*time.Microsecond {
		t.Fatalf("near-8MiB queue-full latency=%s, want <=50us", latency)
	}
	if queueFull.AllocedBytesPerOp() != 0 || queueFull.AllocsPerOp() != 0 {
		t.Fatalf("near-8MiB queue-full allocation=%d B/op allocs=%d/op, want zero", queueFull.AllocedBytesPerOp(), queueFull.AllocsPerOp())
	}
}

func BenchmarkPrepareRawCapture(b *testing.B) {
	cfg := RawCaptureConfig{
		Enabled: true, OnlyBlocked: true, MaxBytes: maxRawCaptureBytes,
		TTL: 72 * time.Hour, RedactSecrets: true,
	}
	now := time.Date(2026, 7, 21, 20, 0, 0, 0, time.UTC)
	for _, fixture := range rawCaptureBenchmarkSizes {
		fixture := fixture
		b.Run(fixture.name, func(b *testing.B) {
			raw := rawCaptureBenchmarkBody(fixture.size)
			input := benchmarkRawCaptureInput(raw)
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if _, err := prepareRawCapture(input, cfg, now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkRecordRawCaptureQueue(b *testing.B) {
	for _, fixture := range rawCaptureBenchmarkSizes {
		fixture := fixture
		b.Run("Admitted/"+fixture.name, func(b *testing.B) {
			raw := rawCaptureBenchmarkBody(fixture.size)
			input := benchmarkRawCaptureInput(raw)
			store := benchmarkRawCaptureStore(1)
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := store.RecordRawCapture(input); err != nil {
					b.Fatal(err)
				}
				<-store.queue
				store.releaseQueueSlot()
			}
		})

		b.Run("QueueFull/"+fixture.name, func(b *testing.B) {
			raw := rawCaptureBenchmarkBody(fixture.size)
			input := benchmarkRawCaptureInput(raw)
			store := benchmarkRawCaptureStore(1)
			store.queueSlots <- struct{}{}
			b.Cleanup(func() { <-store.queueSlots })
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				if err := store.RecordRawCapture(input); !errors.Is(err, ErrQueueFull) {
					b.Fatalf("RecordRawCapture() error = %v", err)
				}
			}
		})
	}
}

func BenchmarkEnqueueEventWithRawCapture(b *testing.B) {
	now := time.Date(2026, 7, 21, 20, 30, 0, 0, time.UTC)
	for _, fixture := range rawCaptureBenchmarkSizes {
		fixture := fixture
		b.Run(fixture.name, func(b *testing.B) {
			raw := rawCaptureBenchmarkBody(fixture.size)
			event := rawCaptureEvent("composite-benchmark", now, "block", "block_malicious_text", raw)
			input := RawCaptureInput{
				EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
				SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
				RawRequest: raw,
			}
			store := benchmarkRawCaptureStore(1)
			b.ReportAllocs()
			b.SetBytes(int64(len(raw)))
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				accepted, err := store.EnqueueEventWithRawCapture(event, input)
				if err != nil || !accepted {
					b.Fatalf("accepted=%t error=%v", accepted, err)
				}
				<-store.queue
				store.releaseQueueSlot()
			}
		})
	}
}

func benchmarkRawCaptureStore(queueSize int) *Store {
	cfg := withDefaults(Config{
		QueueSize: queueSize,
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: maxRawCaptureBytes,
			TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	store := &Store{
		cfg:        cfg,
		queue:      make(chan workItem, queueSize),
		queueSlots: make(chan struct{}, queueSize),
	}
	store.lastErr.Store("")
	return store
}

func benchmarkRawCaptureInput(raw []byte) RawCaptureInput {
	return RawCaptureInput{
		EventID: "raw-capture-benchmark", Action: "block",
		Decision: "block_malicious_text", RawRequest: raw,
	}
}

func rawCaptureBenchmarkBody(size int) []byte {
	prefix := []byte(`{"password":"benchmark-secret","content":"`)
	suffix := []byte(`"}`)
	if size < len(prefix)+len(suffix) {
		panic(fmt.Sprintf("raw capture benchmark size %d is too small", size))
	}
	body := make([]byte, size)
	copy(body, prefix)
	for index := len(prefix); index < size-len(suffix); index++ {
		body[index] = 'x'
	}
	copy(body[size-len(suffix):], suffix)
	return body
}
