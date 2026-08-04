package audit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRuntimeCapacityEnforcedAfterBoundedWriteBatchesAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime-capacity.db")
	probe, err := Open(Config{Path: path, MaxBytes: 64 << 20})
	if err != nil {
		t.Fatal(err)
	}
	baseStatus := probe.Status()
	if !baseStatus.CapacityMeasurementAvailable || baseStatus.CurrentLiveBytes <= 0 {
		t.Fatalf("initial capacity measurement = %#v", baseStatus)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	maxBytes := baseStatus.CurrentLiveBytes + 96<<10
	store, err := Open(Config{
		Path: path, MaxBytes: maxBytes, QueueSize: 4096,
		CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1600; i++ {
		event := testEvent(fmt.Sprintf("runtime-capacity-%04d", i), time.Now().UTC().Add(time.Duration(i)))
		event.Model = strings.Repeat("m", 200)
		event.RuleIDs = []string{strings.Repeat("R", 120)}
		if err := store.Enqueue(event); err != nil {
			t.Fatalf("enqueue %d: %v", i, err)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	status := store.Status()
	if !status.CapacityMeasurementAvailable || status.OverLimit || status.Degraded {
		t.Fatalf("runtime capacity status = %#v", status)
	}
	if status.ConfiguredMaxBytes != maxBytes || status.CurrentLiveBytes > maxBytes {
		t.Fatalf("runtime live bytes = %d, configured = %d", status.CurrentLiveBytes, maxBytes)
	}
	if status.CapacityCleanupRuns == 0 || status.CapacityCleanupDeleted == 0 || status.CapacityRejected != 0 {
		t.Fatalf("runtime capacity counters = %#v", status)
	}
	var quickCheck string
	if err := store.db.QueryRow("PRAGMA quick_check").Scan(&quickCheck); err != nil || quickCheck != "ok" {
		t.Fatalf("quick_check = %q, %v", quickCheck, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	restarted, err := Open(Config{Path: path, MaxBytes: maxBytes, CleanupInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = restarted.Close() })
	restartedStatus := restarted.Status()
	if !restartedStatus.CapacityMeasurementAvailable || restartedStatus.OverLimit ||
		restartedStatus.CurrentLiveBytes > maxBytes {
		t.Fatalf("restarted capacity status = %#v", restartedStatus)
	}
}

func TestCapacityCleanupDeletesRawCapturesBeforeAuditEvents(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 0, 0, 0, time.UTC)
	store, err := Open(Config{
		Path: filepath.Join(t.TempDir(), "capacity-priority.db"), MaxBytes: 64 << 20,
		QueueSize: 32, Now: func() time.Time { return now },
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192,
			TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	for i := 0; i < 3; i++ {
		raw := []byte(fmt.Sprintf(`{"messages":[{"role":"user","content":"%s"}]}`,
			strings.Repeat(fmt.Sprintf("capacity-raw-%d-", i), 700)))
		event := rawCaptureEvent(fmt.Sprintf("capacity-pair-%d", i), now.Add(time.Duration(i)), "block", "block_malicious_text", raw)
		accepted, enqueueErr := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
			RawRequest: raw,
		})
		if enqueueErr != nil || !accepted {
			t.Fatalf("pair %d accepted=%t error=%v", i, accepted, enqueueErr)
		}
	}
	if err := store.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := store.liveDatabaseBytes(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	store.cfg.MaxBytes = before - 1
	if err := store.enforceCapacity(context.Background()); err != nil {
		t.Fatal(err)
	}

	events, err := store.Query(context.Background(), Query{Limit: 10})
	if err != nil || len(events) != 3 {
		t.Fatalf("events after capacity cleanup = %d, %v", len(events), err)
	}
	captures, err := store.QueryRawCaptures(context.Background(), RawCaptureQuery{Limit: 10})
	if err != nil || len(captures) != 0 {
		t.Fatalf("captures after capacity cleanup = %d, %v", len(captures), err)
	}
	status := store.Status()
	if status.CapacityCleanupDeleted != 3 || status.OverLimit || status.CurrentLiveBytes > status.ConfiguredMaxBytes {
		t.Fatalf("raw-first capacity status = %#v", status)
	}
}

func TestRuntimeCapacityBoundsMaximumRawCaptureAfterEveryFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "maximum-raw-capacity.db")
	probe, err := Open(Config{
		Path: path, MaxBytes: 64 << 20,
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: maxRawCaptureBytes,
			TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	base := probe.Status().CurrentLiveBytes
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}

	configured := base + (2 << 20)
	store, err := Open(Config{
		Path: path, MaxBytes: configured, QueueSize: 8, CleanupInterval: time.Hour,
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: maxRawCaptureBytes,
			TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	now := time.Date(2026, 8, 4, 12, 15, 0, 0, time.UTC)
	for i := 0; i < 6; i++ {
		raw := bytes.Repeat([]byte{byte('a' + i)}, maxRawCaptureBytes)
		event := rawCaptureEvent(fmt.Sprintf("maximum-raw-%d", i), now.Add(time.Duration(i)), "block", "block_malicious_text", raw)
		accepted, enqueueErr := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
			RawRequest: raw,
		})
		if enqueueErr != nil || !accepted {
			t.Fatalf("maximum raw %d accepted=%t error=%v", i, accepted, enqueueErr)
		}
		if err := store.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		status := store.Status()
		if !status.CapacityMeasurementAvailable || status.OverLimit ||
			status.CurrentLiveBytes > configured {
			t.Fatalf("maximum raw %d capacity status=%#v", i, status)
		}
	}
	if status := store.Status(); status.CapacityCleanupRuns == 0 || status.CapacityCleanupDeleted == 0 {
		t.Fatalf("maximum raw writes did not exercise runtime cleanup: %#v", status)
	}
}

func TestCapacityGateRejectsCompositeBeforeRawPreparation(t *testing.T) {
	now := time.Date(2026, 8, 4, 12, 30, 0, 0, time.UTC)
	store, err := Open(Config{
		Path: filepath.Join(t.TempDir(), "capacity-reject.db"), MaxBytes: 1,
		RawCapture: RawCaptureConfig{
			Enabled: true, OnlyBlocked: true, MaxBytes: 8192,
			TTL: 72 * time.Hour, RedactSecrets: true,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	raw := []byte(`{"messages":[{"role":"user","content":"capacity gate"}]}`)
	event := rawCaptureEvent("capacity-reject-pair", now, "block", "block_malicious_text", raw)
	accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
		EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
		SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
		RawRequest: raw,
	})
	if accepted || !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("accepted=%t error=%v", accepted, err)
	}
	status := store.Status()
	if status.Enqueued != 0 || status.Rejected != 2 || status.RawCaptureRejected != 1 ||
		status.CapacityRejected != 2 || status.RawCapturePrepareCount != 0 {
		t.Fatalf("capacity composite rejection = %#v", status)
	}
	stats, statsErr := store.Stats(context.Background())
	if statsErr != nil {
		t.Fatal(statsErr)
	}
	if stats.ConfiguredMaxBytes != status.ConfiguredMaxBytes ||
		stats.CurrentLiveBytes != status.CurrentLiveBytes ||
		stats.CapacityMeasurementAvailable != status.CapacityMeasurementAvailable ||
		stats.OverLimit != status.OverLimit ||
		stats.CapacityCleanupRuns != status.CapacityCleanupRuns ||
		stats.CapacityCleanupDeleted != status.CapacityCleanupDeleted ||
		stats.CapacityRejected != status.CapacityRejected {
		t.Fatalf("capacity stats=%#v status=%#v", stats, status)
	}
}

func TestCapacityMeasurementFailureUsesLowCardinalityError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capacity-check-secret-canary.db")
	store, err := Open(Config{Path: path, MaxBytes: 8 << 20})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := store.enforceCapacity(context.Background()); !errors.Is(err, ErrCapacityCheckFailed) {
		t.Fatalf("enforceCapacity() error = %v", err)
	}
	status := store.Status()
	if status.CapacityMeasurementAvailable || !status.OverLimit || !status.Degraded ||
		status.LastError != ErrCapacityCheckFailed.Error() {
		t.Fatalf("failed capacity measurement status = %#v", status)
	}
	if strings.Contains(status.LastError, path) || strings.Contains(status.LastError, "secret-canary") {
		t.Fatalf("capacity error exposed path-derived text: %q", status.LastError)
	}
	_ = store.Discard()
}
