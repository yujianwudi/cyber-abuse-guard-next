package subject

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestEvaluateRequestIsIdempotentAcrossRetriesAndConcurrency(t *testing.T) {
	t.Parallel()
	clock := &testClock{now: time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	subjectHash := riskHash("idempotent-subject")
	requestOne := riskRequestHash("logical-request-one")
	requestTwo := riskRequestHash("logical-request-two")

	first := controller.EvaluateRequest(subjectHash, requestOne, 60)
	if first.Duplicate || first.AddedScore != 60 || first.RepeatCount != 1 {
		t.Fatalf("first request accounting = %#v", first)
	}
	for iteration := 0; iteration < 8; iteration++ {
		duplicate := controller.EvaluateRequest(subjectHash, requestOne, 60)
		if !duplicate.Duplicate || duplicate.AddedScore != 0 || duplicate.RepeatCount != 1 {
			t.Fatalf("sequential duplicate accounting = %#v", duplicate)
		}
	}

	const workers = 64
	var recorded atomic.Int64
	var duplicates atomic.Int64
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			decision := controller.EvaluateRequest(subjectHash, requestTwo, 60)
			if decision.Duplicate {
				duplicates.Add(1)
			} else if decision.AddedScore > 0 {
				recorded.Add(1)
			}
		}()
	}
	wait.Wait()
	if recorded.Load() != 1 || duplicates.Load() != workers-1 {
		t.Fatalf("concurrent accounting recorded=%d duplicates=%d", recorded.Load(), duplicates.Load())
	}
	state, ok := controller.Snapshot(subjectHash)
	if !ok || state.HitCount != 2 {
		t.Fatalf("idempotent state = (%#v, %v), want two logical hits", state, ok)
	}

	clock.Add(61 * time.Minute)
	afterWindow := controller.EvaluateRequest(subjectHash, requestOne, 60)
	if afterWindow.Duplicate || afterWindow.AddedScore != 60 || afterWindow.RepeatCount != 1 {
		t.Fatalf("request after idempotency window = %#v", afterWindow)
	}
}

func TestEvaluateRequestReceiptSurvivesPersistenceRoundTrip(t *testing.T) {
	t.Parallel()
	clock := &testClock{now: time.Date(2026, 7, 14, 1, 0, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	subjectHash := riskHash("persisted-idempotent-subject")
	requestHash := riskRequestHash("persisted-logical-request")
	keyID := riskRequestHash("stable-key-id")

	if got := controller.EvaluateRequest(subjectHash, requestHash, 60); got.Duplicate {
		t.Fatalf("initial request was marked duplicate: %#v", got)
	}
	snapshot, err := controller.ExportPersistent(keyID)
	if err != nil {
		t.Fatal(err)
	}
	restored := newTestController(t, clock)
	if _, err := restored.RestorePersistent(snapshot, keyID); err != nil {
		t.Fatal(err)
	}
	duplicate := restored.EvaluateRequest(subjectHash, requestHash, 60)
	if !duplicate.Duplicate || duplicate.AddedScore != 0 || duplicate.RepeatCount != 1 {
		t.Fatalf("restored duplicate accounting = %#v", duplicate)
	}
	state, ok := restored.Snapshot(subjectHash)
	if !ok || state.HitCount != 1 {
		t.Fatalf("restored state = (%#v, %v), want one hit", state, ok)
	}
}

func TestEvaluateRequestReceiptSurvivesRaisedAuditThreshold(t *testing.T) {
	t.Parallel()
	clock := &testClock{now: time.Date(2026, 7, 14, 1, 30, 0, 0, time.UTC)}
	controller := newTestController(t, clock)
	subjectHash := riskHash("threshold-idempotent-subject")
	requestHash := riskRequestHash("threshold-idempotent-request")

	first := controller.EvaluateRequest(subjectHash, requestHash, 60)
	if first.Duplicate || first.AddedScore != 60 || first.Reason != ReasonRisk {
		t.Fatalf("initial request = %#v", first)
	}
	updated := controller.cfg
	updated.AuditThreshold = 80
	if err := controller.Reconfigure(updated); err != nil {
		t.Fatal(err)
	}

	duplicate := controller.EvaluateRequest(subjectHash, requestHash, 60)
	if !duplicate.Duplicate || duplicate.AddedScore != 0 || duplicate.Reason != ReasonRisk || duplicate.Blocked {
		t.Fatalf("duplicate below raised threshold = %#v", duplicate)
	}
	state, ok := controller.Snapshot(subjectHash)
	if !ok || state.HitCount != 1 || state.Score != 60 {
		t.Fatalf("state after duplicate below raised threshold = (%#v, %v)", state, ok)
	}
}

func TestRestorePersistentRejectsInvalidOrDuplicateRequestReceipts(t *testing.T) {
	t.Parallel()
	clock := &testClock{now: time.Date(2026, 7, 14, 2, 0, 0, 0, time.UTC)}
	keyID := riskRequestHash("stable-key-id")
	subjectHash := riskHash("invalid-receipt-subject")
	validRequest := riskRequestHash("valid-request")

	for _, testCase := range []struct {
		name string
		hits []PersistentHit
	}{
		{name: "invalid", hits: []PersistentHit{{At: clock.Now(), Score: 60, RequestHash: "sha256:not-a-digest"}}},
		{name: "duplicate", hits: []PersistentHit{
			{At: clock.Now(), Score: 60, RequestHash: validRequest},
			{At: clock.Now(), Score: 60, RequestHash: validRequest},
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			controller := newTestController(t, clock)
			_, err := controller.RestorePersistent(PersistentSnapshot{
				Version:   PersistenceVersion,
				HMACKeyID: keyID,
				SavedAt:   clock.Now(),
				Subjects:  []PersistentSubject{{SubjectHash: subjectHash, Hits: testCase.hits}},
			}, keyID)
			if err == nil {
				t.Fatal("invalid request receipt was restored")
			}
		})
	}
}

func BenchmarkControllerEvaluateRequestDuplicateParallel(b *testing.B) {
	clock := &testClock{now: time.Date(2026, 7, 14, 3, 0, 0, 0, time.UTC)}
	controller := newTestController(b, clock)
	subjectHash := riskHash("benchmark-subject")
	requestHash := riskRequestHash("benchmark-request")
	_ = controller.EvaluateRequest(subjectHash, requestHash, 60)
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = controller.EvaluateRequest(subjectHash, requestHash, 60)
		}
	})
}

func riskRequestHash(value string) string {
	sum := sha256.Sum256([]byte("cyber-abuse-guard:request:v1\x00" + value))
	return "sha256:" + hex.EncodeToString(sum[:])
}
