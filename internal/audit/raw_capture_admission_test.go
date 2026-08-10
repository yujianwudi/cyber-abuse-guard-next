package audit

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRawCaptureDedicatedCountersReachStatusAndStats(t *testing.T) {
	now := time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
	store, err := Open(Config{
		Path:      filepath.Join(t.TempDir(), "raw-capture-counters.db"),
		QueueSize: 8,
		Now:       func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192,
			TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	raw := []byte(`{"messages":[{"role":"user","content":"password is dedicated-counter-secret"}]}`)
	event := rawCaptureEvent("dedicated-counter-event", now, "block", "block_malicious_text", raw)
	accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
		RawRequest: raw,
	})
	if err != nil || !accepted {
		t.Fatal(err)
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}

	status := store.Status()
	if status.RawCaptureEnqueued != 1 || status.RawCaptureWritten != 1 ||
		status.RawCaptureDropped != 0 || status.RawCaptureFailed != 0 || status.RawCaptureRejected != 0 {
		t.Fatalf("dedicated raw capture status = %#v", status)
	}
	if status.RawCaptureQueueHighWater == 0 || status.RawCapturePrepareCount != 1 ||
		status.RawCapturePrepareTotalUS == 0 || status.RawCapturePrepareLastUS == 0 ||
		status.RawCapturePrepareMaxUS == 0 || status.RawCapturePrepareTotalUS < status.RawCapturePrepareMaxUS {
		t.Fatalf("raw capture observability status = %#v", status)
	}
	stats, err := store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if stats.RawCaptureEnqueued != status.RawCaptureEnqueued ||
		stats.RawCaptureWritten != status.RawCaptureWritten ||
		stats.RawCaptureDropped != status.RawCaptureDropped ||
		stats.RawCaptureFailed != status.RawCaptureFailed ||
		stats.RawCaptureRejected != status.RawCaptureRejected ||
		stats.RawCaptureQueueHighWater != status.RawCaptureQueueHighWater ||
		stats.RawCapturePrepareCount != status.RawCapturePrepareCount ||
		stats.RawCapturePrepareTotalUS != status.RawCapturePrepareTotalUS ||
		stats.RawCapturePrepareLastUS != status.RawCapturePrepareLastUS ||
		stats.RawCapturePrepareMaxUS != status.RawCapturePrepareMaxUS {
		t.Fatalf("raw capture stats=%#v status=%#v", stats, status)
	}
}

func TestRawCaptureQueueFullWinsBeforeBodyPreparation(t *testing.T) {
	cfg := withDefaults(Config{
		QueueSize: 1,
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: maxRawCaptureBytes,
			TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	store := &Store{
		cfg:        cfg,
		queue:      make(chan workItem, 1),
		queueSlots: make(chan struct{}, 1),
	}
	store.lastErr.Store("")
	store.activated.Store(true)
	store.queueSlots <- struct{}{}

	input := RawCaptureInput{
		EventID: "queue-full-before-prepare", Action: "audit",
		Decision: "audit_malicious_text", RawRequest: []byte(strings.Repeat("x", 8<<20)),
	}
	if err := store.RecordRawCapture(input); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("RecordRawCapture(queue full) error = %v", err)
	}
	status := store.Status()
	if status.RawCaptureDropped != 1 || status.RawCaptureRejected != 0 || status.RawCaptureEnqueued != 0 ||
		status.RawCaptureQueueHighWater != 1 || status.RawCapturePrepareCount != 0 {
		t.Fatalf("queue-full raw capture status = %#v", status)
	}

	<-store.queueSlots
	if err := store.RecordRawCapture(input); !errors.Is(err, ErrInvalidRawCapture) {
		t.Fatalf("RecordRawCapture(invalid after capacity freed) error = %v", err)
	}
	status = store.Status()
	if status.RawCaptureRejected != 1 || status.RawCapturePrepareCount != 1 || len(store.queueSlots) != 0 {
		t.Fatalf("invalid raw capture leaked admission: %#v", status)
	}
}

func TestBlockEventAndCapturePublishAsOneWorkItem(t *testing.T) {
	now := time.Date(2026, 7, 21, 18, 30, 0, 0, time.UTC)
	store := benchmarkRawCaptureStore(4)

	raw := []byte(`{"messages":[{"role":"user","content":"composite work item"}]}`)
	blocked := rawCaptureEvent("composite-block", now, "block", "block_malicious_text", raw)
	accepted, err := store.EnqueueEventWithRawCapture(blocked, RawCaptureInput{
		EventID: blocked.ID, Timestamp: blocked.Timestamp, RequestHash: blocked.RequestHash,
		SubjectHash: blocked.SubjectHash, Action: blocked.Action, Decision: blocked.Decision,
		RawRequest: raw,
	})
	if err != nil || !accepted {
		t.Fatal(err)
	}
	if got := len(store.queue); got != 1 {
		t.Fatalf("composite queue items=%d, want 1", got)
	}
	item := <-store.queue
	store.releaseQueueSlot()
	if item.event == nil || item.rawCapture == nil ||
		item.event.ID != blocked.ID || item.rawCapture.EventID != blocked.ID {
		t.Fatalf("block/capture were not composite: %#v", item)
	}
}

func TestCompositeRawCaptureQueueFullCounters(t *testing.T) {
	now := time.Date(2026, 7, 21, 18, 35, 0, 0, time.UTC)
	store := benchmarkRawCaptureStore(1)
	store.queueSlots <- struct{}{}
	raw := []byte(`{"messages":[{"role":"user","content":"queue full composite"}]}`)
	event := rawCaptureEvent("queue-full-composite", now, "block", "block_malicious_text", raw)
	accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
		RawRequest: raw,
	})
	if accepted || !errors.Is(err, ErrQueueFull) {
		t.Fatalf("accepted=%t error=%v", accepted, err)
	}
	status := store.Status()
	if status.Dropped != 2 || status.RawCaptureDropped != 1 ||
		status.RawCaptureQueueHighWater != 1 || status.RawCapturePrepareCount != 0 {
		t.Fatalf("composite queue-full status = %#v", status)
	}
	<-store.queueSlots
}

func TestRawCaptureSaturatedAttemptRecordsCapacityAfterConcurrentRelease(t *testing.T) {
	store := benchmarkRawCaptureStore(4)
	for range cap(store.queueSlots) {
		store.queueSlots <- struct{}{}
	}

	err := store.reserveAdmission()
	if !errors.Is(err, ErrQueueFull) {
		t.Fatalf("reserveAdmission() error = %v, want queue full", err)
	}
	// Model the writer releasing capacity in the interval between the full
	// channel select and the raw-capture observability update.
	<-store.queueSlots
	store.observeRawCaptureAdmission(err)
	if got, want := store.Status().RawCaptureQueueHighWater, uint64(cap(store.queueSlots)); got != want {
		t.Fatalf("raw capture queue high-water = %d, want saturated capacity %d", got, want)
	}
	for len(store.queueSlots) != 0 {
		<-store.queueSlots
	}
}

func TestCompositeRawCaptureRejectsMismatchedEventMetadata(t *testing.T) {
	now := time.Date(2026, 7, 21, 18, 40, 0, 0, time.UTC)
	raw := []byte(`{"messages":[{"role":"user","content":"pair metadata"}]}`)
	baseEvent := rawCaptureEvent("pair-metadata", now, "block", "block_malicious_text", raw)
	baseInput := RawCaptureInput{
		EventID: baseEvent.ID, Timestamp: baseEvent.Timestamp, RequestHash: baseEvent.RequestHash,
		SubjectHash: baseEvent.SubjectHash, Action: baseEvent.Action, Decision: baseEvent.Decision,
		RawRequest: raw,
	}
	tests := map[string]func(*RawCaptureInput){
		"event id": func(input *RawCaptureInput) { input.EventID = "different-event" },
		"action":   func(input *RawCaptureInput) { input.Action = "cooldown" },
		"decision": func(input *RawCaptureInput) { input.Decision = "block_subject_risk" },
		"timestamp": func(input *RawCaptureInput) {
			input.Timestamp = input.Timestamp.Add(time.Nanosecond)
		},
		"request hash": func(input *RawCaptureInput) { input.RequestHash = HashRequest([]byte("different")) },
		"subject hash": func(input *RawCaptureInput) { input.SubjectHash = testSubjectHash("different") },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			store := benchmarkRawCaptureStore(2)
			input := baseInput
			mutate(&input)
			accepted, err := store.EnqueueEventWithRawCapture(baseEvent, input)
			if !accepted || !errors.Is(err, ErrInvalidRawCapture) {
				t.Fatalf("accepted=%t error=%v", accepted, err)
			}
			item := <-store.queue
			store.releaseQueueSlot()
			if item.event == nil || item.rawCapture != nil || item.event.ID != baseEvent.ID {
				t.Fatalf("mismatched pair work item = %#v", item)
			}
			status := store.Status()
			if status.RawCaptureRejected != 1 || status.RawCaptureEnqueued != 0 || status.RawCapturePrepareCount != 0 {
				t.Fatalf("mismatched pair status = %#v", status)
			}
		})
	}
}

func TestPrepareRawCaptureUsesBoundedWindowWithBoundaryOverlap(t *testing.T) {
	const maxBytes = 1024
	now := time.Date(2026, 7, 21, 18, 45, 0, 0, time.UTC)
	prefix := strings.Repeat("x", maxBytes-96)
	privateKey := "-----BEGIN PRIVATE KEY-----\nBOUNDARY-PRIVATE-KEY-CANARY\n" + // repo-secret-scan: allow synthetic-fixture
		strings.Repeat("A", rawCaptureRedactionOverlapBytes+2048)
	raw := []byte(prefix + privateKey)
	window, beyond := rawCaptureRedactionWindow(raw, maxBytes)
	if !beyond || len(window) != maxBytes+rawCaptureRedactionOverlapBytes {
		t.Fatalf("redaction window bytes=%d beyond=%t", len(window), beyond)
	}
	capture, err := prepareRawCapture(RawCaptureInput{
		EventID: "bounded-redaction-window", Action: "block",
		Decision: "block_malicious_text", RawRequest: raw,
	}, RawCaptureConfig{
		Enabled: true, OnlyBlocked: true, MaxBytes: maxBytes,
		TTL: 72 * time.Hour, RedactSecrets: true,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !capture.Redacted || !capture.Truncated || len(capture.RawPreview) > maxBytes {
		t.Fatalf("bounded capture flags/size = %#v", capture)
	}
	if strings.Contains(capture.RawPreview, "BOUNDARY-PRIVATE-KEY-CANARY") ||
		!strings.Contains(capture.RawPreview, "[REDACTED]") {
		t.Fatalf("boundary private key was not redacted: %q", capture.RawPreview)
	}
}

func TestFlushAndCloseObserveUnpublishedAdmission(t *testing.T) {
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "admission-lifecycle.db"), QueueSize: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.reserveAdmission(); err != nil {
		t.Fatal(err)
	}

	flushCtx, cancelFlush := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancelFlush()
	if err := store.Flush(flushCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Flush with unpublished admission error = %v", err)
	}
	// A timed-out waiter must not poison the admission generation or race a
	// subsequent Add, as a reused sync.WaitGroup would.
	if err := store.reserveAdmission(); err != nil {
		t.Fatalf("reserve after timed-out Flush: %v", err)
	}
	store.cancelAdmission()

	closed := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		closed <- store.CloseContext(ctx)
	}()
	select {
	case err := <-closed:
		t.Fatalf("CloseContext returned before admission resolved: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	store.cancelAdmission()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CloseContext did not finish after admission cancellation")
	}
}

func TestCloseTimeoutAccountsForAdmissionPublishedAfterDeadline(t *testing.T) {
	now := time.Date(2026, 7, 21, 18, 50, 0, 0, time.UTC)
	store, err := Open(Config{
		Path:      filepath.Join(t.TempDir(), "admission-deadline.db"),
		QueueSize: 2,
		Now:       func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192,
			TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	raw := []byte(`{"messages":[{"role":"user","content":"publish after deadline"}]}`)
	event, err := prepareEvent(rawCaptureEvent(
		"publish-after-deadline", now, "block", "block_malicious_text", raw,
	), now)
	if err != nil {
		t.Fatal(err)
	}
	capture, err := prepareRawCapture(RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
		RawRequest: raw,
	}, store.cfg.RawCapture, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.reserveAdmission(); err != nil {
		t.Fatal(err)
	}

	closeCtx, cancelClose := context.WithTimeout(context.Background(), 10*time.Millisecond)
	err = store.CloseContext(closeCtx)
	cancelClose()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CloseContext() error = %v, want deadline exceeded", err)
	}
	select {
	case <-store.closedDone:
		t.Fatal("store closed while a pre-close admission was still unpublished")
	default:
	}

	store.enqueued.Add(2)
	store.rawEnqueued.Add(1)
	store.publishAdmission(workItem{event: &event, rawCapture: &capture})

	finishCtx, cancelFinish := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelFinish()
	if err := store.CloseContext(finishCtx); err != nil {
		t.Fatalf("CloseContext() after publishing admission = %v", err)
	}
	status := store.Status()
	if status.QueueDepth != 0 {
		t.Fatalf("queue depth after resumed close = %d, want 0", status.QueueDepth)
	}
	if status.Dropped != 0 || status.RawCaptureDropped != 0 {
		t.Fatalf("deadline silently dropped accepted work: dropped=%d raw_dropped=%d",
			status.Dropped, status.RawCaptureDropped)
	}
	if accounted := status.Written + status.Failed + status.Dropped; accounted != status.Enqueued {
		t.Fatalf("logical work accounting: written=%d failed=%d dropped=%d enqueued=%d",
			status.Written, status.Failed, status.Dropped, status.Enqueued)
	}
	if accounted := status.RawCaptureWritten + status.RawCaptureFailed + status.RawCaptureDropped; accounted != status.RawCaptureEnqueued {
		t.Fatalf("raw capture accounting: written=%d failed=%d dropped=%d enqueued=%d",
			status.RawCaptureWritten, status.RawCaptureFailed, status.RawCaptureDropped, status.RawCaptureEnqueued)
	}
}

func TestAdjacentEventCaptureTransactionKeepsEventOnCaptureFailure(t *testing.T) {
	now := time.Date(2026, 7, 21, 19, 0, 0, 0, time.UTC)
	store, err := Open(Config{
		Path: filepath.Join(t.TempDir(), "raw-capture-pair.db"),
		Now:  func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192,
			TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	raw := []byte(`{"messages":[{"role":"user","content":"pair transaction"}]}`)
	event, err := prepareEvent(rawCaptureEvent(
		"pair-event", now, "block", "block_malicious_text", raw,
	), now)
	if err != nil {
		t.Fatal(err)
	}
	capture := RawRequestCapture{
		ID: "pair-capture", EventID: event.ID, Timestamp: now,
		Action: "audit", Decision: "block_malicious_text", RawPreview: "pair preview",
		RawSHA256: HashRequest(raw),
	}
	store.handleBatch([]workItem{{event: &event, rawCapture: &capture}})

	events, err := store.Query(context.Background(), Query{Limit: 10})
	if err != nil || len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("paired event persistence events=%#v err=%v", events, err)
	}
	captures, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{EventID: event.ID})
	if err != nil || len(captures) != 0 {
		t.Fatalf("invalid paired capture persisted=%#v err=%v", captures, err)
	}
	status := store.Status()
	if status.Written != 1 || status.Failed != 1 || status.RawCaptureWritten != 0 || status.RawCaptureFailed != 1 {
		t.Fatalf("paired write status = %#v", status)
	}
}
