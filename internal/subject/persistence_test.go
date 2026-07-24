package subject

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestIdentifierKeyIDIsStableAndSecretFree(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	identifier := newIdentifier(key, IdentifierStatus{Stable: true})
	first := identifier.KeyID()
	second := identifier.KeyID()
	if !validDigest(first, "sha256:") || first != second {
		t.Fatalf("KeyID = %q, %q", first, second)
	}
	if strings.Contains(first, string(key)) {
		t.Fatal("KeyID exposed key material")
	}
	other := newIdentifier([]byte("abcdef0123456789abcdef0123456789"), IdentifierStatus{Stable: true})
	if first == other.KeyID() {
		t.Fatal("different HMAC keys produced the same key identifier")
	}
}

func TestPersistentSnapshotRestoresDecayCooldownAndManualBlock(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newPersistenceController(t, clock, 10)
	cooling := persistenceHash("cooling")
	manual := persistenceHash("manual")
	_ = controller.Evaluate(cooling, 80)
	if got := controller.Evaluate(cooling, 80); got.Reason != ReasonCooldown {
		t.Fatalf("cooldown decision = %#v", got)
	}
	_ = controller.Evaluate(manual, 100)
	if got := controller.Evaluate(manual, 100); got.Reason != ReasonManualBlock {
		t.Fatalf("manual decision = %#v", got)
	}

	keyID := newIdentifier([]byte("0123456789abcdef0123456789abcdef"), IdentifierStatus{Stable: true}).KeyID()
	snapshot, err := controller.ExportPersistent(keyID)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "0123456789abcdef") {
		t.Fatal("persistent snapshot exposed HMAC key material")
	}

	clock.Add(20 * time.Minute)
	restored := newPersistenceController(t, clock, 10)
	result, err := restored.RestorePersistent(snapshot, keyID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Loaded != 2 || result.DroppedExpired != 0 || result.DroppedCapacity != 0 {
		t.Fatalf("restore result = %#v", result)
	}
	coolingState, ok := restored.Snapshot(cooling)
	if !ok || coolingState.Score <= 0 || coolingState.Score >= 200 || coolingState.CooldownUntil.IsZero() {
		t.Fatalf("restored cooling state = %#v, %v", coolingState, ok)
	}
	manualState, ok := restored.Snapshot(manual)
	if !ok || !manualState.ManualBlocked || manualState.Score <= 0 || manualState.Score >= 250 {
		t.Fatalf("restored manual state = %#v, %v", manualState, ok)
	}
}

func TestPersistentRestoreRejectsKeyMismatchWithoutMutation(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 7, 12, 0, 0, 0, 0, time.UTC)}
	controller := newPersistenceController(t, clock, 10)
	existing := persistenceHash("existing")
	_ = controller.Evaluate(existing, 80)

	keyOne := newIdentifier([]byte("0123456789abcdef0123456789abcdef"), IdentifierStatus{Stable: true}).KeyID()
	keyTwo := newIdentifier([]byte("abcdef0123456789abcdef0123456789"), IdentifierStatus{Stable: true}).KeyID()
	snapshot := PersistentSnapshot{
		Version:   PersistenceVersion,
		HMACKeyID: keyOne,
		SavedAt:   clock.Now(),
		Subjects: []PersistentSubject{{
			SubjectHash: persistenceHash("foreign"),
			Hits:        []PersistentHit{{At: clock.Now(), Score: 80}},
		}},
	}
	if _, err := controller.RestorePersistent(snapshot, keyTwo); !errors.Is(err, ErrPersistenceKeyMismatch) {
		t.Fatalf("key mismatch error = %v", err)
	}
	if _, ok := controller.Snapshot(existing); !ok {
		t.Fatal("failed restore mutated existing controller state")
	}
}

func TestPersistentRestoreAppliesCapacityAndExpiration(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 7, 12, 2, 0, 0, 0, time.UTC)}
	controller := newPersistenceController(t, clock, 2)
	keyID := newIdentifier([]byte("0123456789abcdef0123456789abcdef"), IdentifierStatus{Stable: true}).KeyID()
	manual := persistenceHash("manual")
	old := persistenceHash("old")
	newest := persistenceHash("newest")
	expired := persistenceHash("expired")
	snapshot := PersistentSnapshot{
		Version:   PersistenceVersion,
		HMACKeyID: keyID,
		SavedAt:   clock.Now().Add(-time.Minute),
		Subjects: []PersistentSubject{
			{SubjectHash: manual, ManualBlocked: true},
			{SubjectHash: old, Hits: []PersistentHit{{At: clock.Now().Add(-30 * time.Minute), Score: 60}}},
			{SubjectHash: newest, Hits: []PersistentHit{{At: clock.Now().Add(-time.Minute), Score: 60}}},
			{SubjectHash: expired, Hits: []PersistentHit{{At: clock.Now().Add(-2 * time.Hour), Score: 60}}},
		},
	}
	result, err := controller.RestorePersistent(snapshot, keyID)
	if err != nil {
		t.Fatal(err)
	}
	if result.Loaded != 2 || result.DroppedExpired != 1 || result.DroppedCapacity != 1 {
		t.Fatalf("restore result = %#v", result)
	}
	if _, ok := controller.Snapshot(manual); !ok {
		t.Fatal("manual block was not restored")
	}
	if _, ok := controller.Snapshot(newest); !ok {
		t.Fatal("newest active subject was not restored")
	}
	if _, ok := controller.Snapshot(old); ok {
		t.Fatal("older subject survived capacity restore")
	}
}

func TestPersistentRestoreClampsClockSkewAndSortsHits(t *testing.T) {
	t.Parallel()
	clock := &testClock{now: time.Date(2026, 7, 12, 2, 0, 0, 0, time.UTC)}
	controller := newPersistenceController(t, clock, 2)
	keyID := newIdentifier([]byte("0123456789abcdef0123456789abcdef"), IdentifierStatus{Stable: true}).KeyID()
	hash := persistenceHash("clock-skew")
	snapshot := PersistentSnapshot{
		Version:   PersistenceVersion,
		HMACKeyID: keyID,
		SavedAt:   clock.Now(),
		Subjects: []PersistentSubject{{
			SubjectHash: hash,
			Hits: []PersistentHit{
				{At: clock.Now().Add(2 * time.Minute), Score: 100},
				{At: clock.Now().Add(-10 * time.Minute), Score: 50},
			},
		}},
	}
	if _, err := controller.RestorePersistent(snapshot, keyID); err != nil {
		t.Fatal(err)
	}
	state, ok := controller.Snapshot(hash)
	if !ok || state.HitCount != 2 || state.Score > 150 {
		t.Fatalf("restored skewed state = %#v, %v", state, ok)
	}
	exported, err := controller.ExportPersistent(keyID)
	if err != nil {
		t.Fatal(err)
	}
	if len(exported.Subjects) != 1 || len(exported.Subjects[0].Hits) != 2 ||
		exported.Subjects[0].Hits[0].At.After(exported.Subjects[0].Hits[1].At) ||
		exported.Subjects[0].Hits[1].At.After(clock.Now()) {
		t.Fatalf("exported skewed hits were not normalized: %#v", exported)
	}
}

func newPersistenceController(t *testing.T, clock *testClock, maxSubjects int) *Controller {
	t.Helper()
	controller, err := NewController(Config{
		Enabled:          true,
		Window:           time.Hour,
		AuditThreshold:   35,
		CooldownScore:    150,
		ManualBlockScore: 250,
		Cooldown:         30 * time.Minute,
		RepeatMultiplier: 1.5,
		MaxMultiplier:    3,
		MaxSubjects:      maxSubjects,
		Now:              clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return controller
}

func persistenceHash(value string) string {
	return riskHash("persistence-" + value)
}
