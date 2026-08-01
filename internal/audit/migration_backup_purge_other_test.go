//go:build !linux

package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestMigrationBackupPurgeNonLinuxChecksCancellationAfterVerifier(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "events.db")
	backup := databasePath + ".pre-v6-20260731T010203.000000000Z.bak"
	manifest := backup + ".manifest.json"
	for _, path := range []string{backup, manifest} {
		if err := os.WriteFile(path, []byte("must-survive"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	verifierCalled := false
	result, err := PurgeMigrationBackupsAtPathVerified(ctx, databasePath, func(context.Context, string) error {
		verifierCalled = true
		cancel()
		return nil
	})
	if !verifierCalled {
		t.Fatal("cleanup did not invoke the storage verifier")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cleanup error=%v, want context cancellation after verifier", err)
	}
	if result != (MigrationBackupCleanupResult{}) {
		t.Fatalf("canceled cleanup constructed a nonzero result: %+v", result)
	}
	for _, path := range []string{backup, manifest} {
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("canceled cleanup removed %s: %v", filepath.Base(path), statErr)
		}
	}
}
