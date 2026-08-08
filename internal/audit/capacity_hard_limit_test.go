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

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
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
	store.capacityMu.Lock()
	store.cfg.MaxBytes = before - 1
	store.capacityMu.Unlock()
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

func TestCommittedMaintenanceDoesNotMisreportResidualCapacityAsRollback(t *testing.T) {
	t.Run("delete", func(t *testing.T) {
		store, err := Open(Config{
			Path:     filepath.Join(t.TempDir(), "delete-residual-capacity.db"),
			MaxBytes: 64 << 20, CleanupInterval: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		target := testEvent("delete-residual-capacity-target", time.Now().UTC())
		retained := testEvent("delete-residual-capacity-retained", time.Now().UTC().Add(time.Nanosecond))
		if err := store.Enqueue(target); err != nil {
			t.Fatal(err)
		}
		if err := store.Enqueue(retained); err != nil {
			t.Fatal(err)
		}
		if err := store.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		store.capacityMu.Lock()
		store.cfg.MaxBytes = 1
		store.capacityMu.Unlock()
		deleted, err := store.Delete(context.Background(), Query{SubjectHash: target.SubjectHash})
		if err != nil || deleted != 1 {
			t.Fatalf("Delete() deleted=%d error=%v", deleted, err)
		}
		events, err := store.Query(context.Background(), Query{Limit: 10})
		if err != nil || len(events) != 1 || events[0].ID != retained.ID {
			t.Fatalf("Delete() residual audit evidence = %#v, %v", events, err)
		}
		status := store.Status()
		if !status.OverLimit || !status.Degraded || status.LastError != ErrCapacityExceeded.Error() {
			t.Fatalf("Delete() residual capacity status = %#v", status)
		}
	})

	t.Run("raw-capture-purge", func(t *testing.T) {
		now := time.Date(2026, 8, 5, 0, 0, 0, 0, time.UTC)
		store, err := Open(Config{
			Path:     filepath.Join(t.TempDir(), "purge-residual-capacity.db"),
			MaxBytes: 64 << 20, CleanupInterval: time.Hour,
			RawCapture: RawCaptureConfig{
				Enabled: true, OnlyBlocked: true, MaxBytes: 8192,
				TTL: 72 * time.Hour, RedactSecrets: true,
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = store.Close() })
		raw := []byte(`{"messages":[{"role":"user","content":"purge residual capacity"}]}`)
		event := rawCaptureEvent("purge-residual-capacity", now, "block", "block_malicious_text", raw)
		accepted, err := store.EnqueueEventWithRawCapture(event, RawCaptureInput{
			EventID: event.ID, Timestamp: event.Timestamp, RequestHash: event.RequestHash,
			SubjectHash: event.SubjectHash, Action: event.Action, Decision: event.Decision,
			RawRequest: raw,
		})
		if err != nil || !accepted {
			t.Fatalf("EnqueueEventWithRawCapture() accepted=%t error=%v", accepted, err)
		}
		if err := store.Flush(context.Background()); err != nil {
			t.Fatal(err)
		}
		store.capacityMu.Lock()
		store.cfg.MaxBytes = 1
		store.capacityMu.Unlock()
		deleted, err := store.PurgeRawCaptures(context.Background())
		if err != nil || deleted != 1 {
			t.Fatalf("PurgeRawCaptures() deleted=%d error=%v", deleted, err)
		}
		events, err := store.Query(context.Background(), Query{Limit: 10})
		if err != nil || len(events) != 1 || events[0].ID != event.ID {
			t.Fatalf("PurgeRawCaptures() residual audit evidence = %#v, %v", events, err)
		}
		status := store.Status()
		if !status.OverLimit || !status.Degraded || status.LastError != ErrCapacityExceeded.Error() {
			t.Fatalf("PurgeRawCaptures() residual capacity status = %#v", status)
		}
	})
}

func TestSubjectSnapshotReplacementCannotExceedCapacityOrDeleteAuditEvidence(t *testing.T) {
	store, err := Open(Config{
		Path:     filepath.Join(t.TempDir(), "subject-capacity-rejection.db"),
		MaxBytes: 64 << 20, CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	keyID := persistenceTestDigest("sha256:", "subject-capacity-key")
	originalHash := persistenceTestDigest("hmac-sha256:", "subject-capacity-original")
	original := subject.PersistentSnapshot{
		Version: subject.PersistenceVersion, HMACKeyID: keyID, SavedAt: time.Now().UTC(),
		Subjects: []subject.PersistentSubject{{SubjectHash: originalHash, ManualBlocked: true}},
	}
	if err := store.SaveSubjectSnapshot(ctx, original); err != nil {
		t.Fatal(err)
	}
	if err := store.Enqueue(testEvent("subject-capacity-audit-evidence", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := store.liveDatabaseBytes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	store.capacityMu.Lock()
	store.cfg.MaxBytes = before + 4096
	store.capacityMu.Unlock()

	largeHash := persistenceTestDigest("hmac-sha256:", "subject-capacity-large")
	large := subject.PersistentSnapshot{
		Version: subject.PersistenceVersion, HMACKeyID: keyID, SavedAt: time.Now().UTC(),
		Subjects: []subject.PersistentSubject{{SubjectHash: largeHash}},
	}
	for i := 0; i < 1024; i++ {
		large.Subjects[0].Hits = append(large.Subjects[0].Hits, subject.PersistentHit{
			At: time.Now().UTC(), Score: 42,
			RequestHash: persistenceTestDigest("sha256:", fmt.Sprintf("subject-capacity-hit-%04d", i)),
		})
	}
	if err := store.SaveSubjectSnapshot(ctx, large); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("SaveSubjectSnapshot() error = %v, want capacity exceeded", err)
	}
	loaded, ok, err := store.LoadSubjectSnapshot(ctx, keyID)
	if err != nil || !ok || len(loaded.Subjects) != 1 || loaded.Subjects[0].SubjectHash != originalHash {
		t.Fatalf("prior subject snapshot after rejected replacement = %#v, %t, %v", loaded, ok, err)
	}
	events, err := store.Query(ctx, Query{Limit: 10})
	if err != nil || len(events) != 1 || events[0].ID != "subject-capacity-audit-evidence" {
		t.Fatalf("audit evidence after rejected subject snapshot = %#v, %v", events, err)
	}
	used, err := store.liveDatabaseBytes(ctx)
	if err != nil {
		t.Fatal(err)
	}
	status := store.Status()
	if used > status.ConfiguredMaxBytes || status.OverLimit || status.CapacityRejected != 1 {
		t.Fatalf("subject snapshot rejection capacity status = %#v, live=%d", status, used)
	}
}

func TestSubjectSnapshotDeleteImmediatelyClearsInheritedCapacityGate(t *testing.T) {
	store, err := Open(Config{
		Path:     filepath.Join(t.TempDir(), "subject-capacity-recovery.db"),
		MaxBytes: 64 << 20, CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	base := store.Status().CurrentLiveBytes
	keyID := persistenceTestDigest("sha256:", "subject-recovery-key")
	snapshot := subject.PersistentSnapshot{
		Version: subject.PersistenceVersion, HMACKeyID: keyID, SavedAt: time.Now().UTC(),
		Subjects: []subject.PersistentSubject{{
			SubjectHash: persistenceTestDigest("hmac-sha256:", "subject-recovery"),
		}},
	}
	for i := 0; i < 1024; i++ {
		snapshot.Subjects[0].Hits = append(snapshot.Subjects[0].Hits, subject.PersistentHit{
			At: time.Now().UTC(), Score: 42,
			RequestHash: persistenceTestDigest("sha256:", fmt.Sprintf("subject-recovery-hit-%04d", i)),
		})
	}
	if err := store.SaveSubjectSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	afterSave := store.Status().CurrentLiveBytes
	if afterSave <= base+4096 {
		t.Fatalf("subject snapshot did not exercise capacity pages: base=%d after=%d", base, afterSave)
	}
	store.capacityMu.Lock()
	store.cfg.MaxBytes = base + 4096
	store.capacityMu.Unlock()
	if err := store.enforceCapacity(ctx); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("enforceCapacity() error = %v, want capacity exceeded", err)
	}
	if !store.Status().OverLimit {
		t.Fatal("subject snapshot capacity gate was not latched")
	}
	if err := store.DeleteSubjectSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	status := store.Status()
	if status.OverLimit || status.Degraded || status.CurrentLiveBytes > status.ConfiguredMaxBytes {
		t.Fatalf("subject snapshot deletion did not clear capacity gate = %#v", status)
	}
}

func TestSubjectSnapshotDeleteNeverEvictsResidualAuditEvidence(t *testing.T) {
	store, err := Open(Config{
		Path:     filepath.Join(t.TempDir(), "subject-capacity-residual.db"),
		MaxBytes: 64 << 20, CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	keyID := persistenceTestDigest("sha256:", "subject-residual-key")
	snapshot := subject.PersistentSnapshot{
		Version: subject.PersistenceVersion, HMACKeyID: keyID, SavedAt: time.Now().UTC(),
		Subjects: []subject.PersistentSubject{{
			SubjectHash:   persistenceTestDigest("hmac-sha256:", "subject-residual"),
			ManualBlocked: true,
		}},
	}
	if err := store.SaveSubjectSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	if err := store.Enqueue(testEvent("subject-residual-audit-evidence", time.Now().UTC())); err != nil {
		t.Fatal(err)
	}
	if err := store.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	store.capacityMu.Lock()
	store.cfg.MaxBytes = 1
	store.capacityMu.Unlock()
	if err := store.DeleteSubjectSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	events, err := store.Query(ctx, Query{Limit: 10})
	if err != nil || len(events) != 1 || events[0].ID != "subject-residual-audit-evidence" {
		t.Fatalf("residual audit evidence after subject deletion = %#v, %v", events, err)
	}
	status := store.Status()
	if !status.OverLimit || !status.Degraded || status.LastError != ErrCapacityExceeded.Error() {
		t.Fatalf("residual subject deletion capacity status = %#v", status)
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

func TestStatusSynchronizesConfiguredMaxBytesWithCapacityUpdates(t *testing.T) {
	store := &Store{
		cfg: Config{
			Path:     filepath.Join(t.TempDir(), "status-capacity-lock.db"),
			MaxBytes: 1,
		},
		queueSlots: make(chan struct{}, 1),
	}
	store.lastErr.Store("")

	store.capacityMu.Lock()
	result := make(chan Status, 1)
	go func() {
		result <- store.Status()
	}()

	for value := int64(2); value <= 50; value++ {
		store.cfg.MaxBytes = value
		select {
		case <-result:
			store.capacityMu.Unlock()
			t.Fatal("Status returned while the configured capacity was being updated")
		default:
		}
		time.Sleep(time.Millisecond)
	}
	want := store.cfg.MaxBytes
	store.capacityMu.Unlock()
	select {
	case status := <-result:
		if status.ConfiguredMaxBytes != want {
			t.Fatalf("configured max bytes = %d, want %d", status.ConfiguredMaxBytes, want)
		}
	case <-time.After(time.Second):
		t.Fatal("Status did not resume after the capacity update completed")
	}
}
