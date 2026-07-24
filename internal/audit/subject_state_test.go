package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
)

func TestSubjectSnapshotRoundTripAndDelete(t *testing.T) {
	t.Parallel()
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "audit.db"), Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	keyID := persistenceTestDigest("sha256:", "key")
	snapshot := subject.PersistentSnapshot{
		Version:   subject.PersistenceVersion,
		HMACKeyID: keyID,
		SavedAt:   fixedMigrationTime(),
		Subjects: []subject.PersistentSubject{{
			SubjectHash: persistenceTestDigest("hmac-sha256:", "subject"),
			Hits: []subject.PersistentHit{{
				At:          fixedMigrationTime().Add(-time.Minute),
				Score:       42,
				RequestHash: persistenceTestDigest("sha256:", "request"),
			}},
			CooldownUntil: fixedMigrationTime().Add(time.Minute),
		}},
	}
	if err := store.SaveSubjectSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	loaded, ok, err := store.LoadSubjectSnapshot(ctx, keyID)
	if err != nil || !ok {
		t.Fatalf("LoadSubjectSnapshot = %#v, %v, %v", loaded, ok, err)
	}
	if loaded.Version != snapshot.Version || loaded.HMACKeyID != keyID || !loaded.SavedAt.Equal(snapshot.SavedAt) || len(loaded.Subjects) != 1 {
		t.Fatalf("loaded snapshot = %#v", loaded)
	}
	if loaded.Subjects[0].SubjectHash != snapshot.Subjects[0].SubjectHash || len(loaded.Subjects[0].Hits) != 1 || loaded.Subjects[0].Hits[0].RequestHash != snapshot.Subjects[0].Hits[0].RequestHash {
		t.Fatalf("loaded subject = %#v", loaded.Subjects[0])
	}
	if err := store.DeleteSubjectSnapshot(ctx); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := store.LoadSubjectSnapshot(ctx, keyID); err != nil || ok {
		t.Fatalf("load after delete: ok=%v err=%v", ok, err)
	}
}

func TestSubjectSnapshotKeyMismatchIsExplicit(t *testing.T) {
	t.Parallel()
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "audit.db"), Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	keyID := persistenceTestDigest("sha256:", "key-one")
	snapshot := subject.PersistentSnapshot{Version: subject.PersistenceVersion, HMACKeyID: keyID, SavedAt: fixedMigrationTime()}
	if err := store.SaveSubjectSnapshot(context.Background(), snapshot); err != nil {
		t.Fatal(err)
	}
	_, _, err = store.LoadSubjectSnapshot(context.Background(), persistenceTestDigest("sha256:", "key-two"))
	if !errors.Is(err, subject.ErrPersistenceKeyMismatch) {
		t.Fatalf("key mismatch error = %v", err)
	}
}

func TestInvalidSubjectSnapshotCannotReplacePriorState(t *testing.T) {
	t.Parallel()
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "audit.db"), Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	keyID := persistenceTestDigest("sha256:", "key")
	originalHash := persistenceTestDigest("hmac-sha256:", "original")
	original := subject.PersistentSnapshot{
		Version:   subject.PersistenceVersion,
		HMACKeyID: keyID,
		SavedAt:   fixedMigrationTime(),
		Subjects:  []subject.PersistentSubject{{SubjectHash: originalHash, ManualBlocked: true}},
	}
	if err := store.SaveSubjectSnapshot(ctx, original); err != nil {
		t.Fatal(err)
	}
	duplicateHash := persistenceTestDigest("hmac-sha256:", "duplicate")
	invalid := subject.PersistentSnapshot{
		Version:   subject.PersistenceVersion,
		HMACKeyID: keyID,
		SavedAt:   fixedMigrationTime(),
		Subjects: []subject.PersistentSubject{
			{SubjectHash: duplicateHash},
			{SubjectHash: duplicateHash},
		},
	}
	if err := store.SaveSubjectSnapshot(ctx, invalid); err == nil {
		t.Fatal("duplicate subject snapshot unexpectedly succeeded")
	}
	loaded, ok, err := store.LoadSubjectSnapshot(ctx, keyID)
	if err != nil || !ok || len(loaded.Subjects) != 1 || loaded.Subjects[0].SubjectHash != originalHash {
		t.Fatalf("prior snapshot after failed replacement = %#v, %v, %v", loaded, ok, err)
	}

	plaintext := original
	plaintext.Subjects = []subject.PersistentSubject{{SubjectHash: "live-api-key-must-not-persist"}}
	if err := store.SaveSubjectSnapshot(ctx, plaintext); err == nil {
		t.Fatal("plaintext subject identifier was accepted")
	}

	requestHash := persistenceTestDigest("sha256:", "duplicate-request")
	invalidRequestReceipts := original
	invalidRequestReceipts.Subjects = []subject.PersistentSubject{{
		SubjectHash: originalHash,
		Hits: []subject.PersistentHit{
			{At: fixedMigrationTime(), Score: 40, RequestHash: requestHash},
			{At: fixedMigrationTime(), Score: 40, RequestHash: requestHash},
		},
	}}
	if err := store.SaveSubjectSnapshot(ctx, invalidRequestReceipts); err == nil {
		t.Fatal("duplicate request receipts were accepted")
	}
}

func TestSubjectSnapshotRejectsRowAndPayloadHashMismatch(t *testing.T) {
	t.Parallel()
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "audit.db"), Now: fixedMigrationTime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	ctx := context.Background()
	keyID := persistenceTestDigest("sha256:", "key")
	originalHash := persistenceTestDigest("hmac-sha256:", "original")
	snapshot := subject.PersistentSnapshot{
		Version:   subject.PersistenceVersion,
		HMACKeyID: keyID,
		SavedAt:   fixedMigrationTime(),
		Subjects:  []subject.PersistentSubject{{SubjectHash: originalHash, ManualBlocked: true}},
	}
	if err := store.SaveSubjectSnapshot(ctx, snapshot); err != nil {
		t.Fatal(err)
	}
	tampered := snapshot.Subjects[0]
	tampered.SubjectHash = persistenceTestDigest("hmac-sha256:", "tampered")
	raw, err := json.Marshal(tampered)
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.availableDB()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE subject_state SET state_json = ? WHERE subject_hash = ?`, string(raw), originalHash); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.LoadSubjectSnapshot(ctx, keyID); err == nil {
		t.Fatal("row/payload subject hash mismatch was accepted")
	}
}

func persistenceTestDigest(prefix, value string) string {
	digest := sha256.Sum256([]byte(value))
	return prefix + hex.EncodeToString(digest[:])
}
