package audit

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestRound9MigrationBackupsAreVisibleAndRequireSeparateCleanup(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "events.db")
	oldBackup := databasePath + ".pre-v6-20260720T010203.000000000Z.bak"
	newBackup := databasePath + ".pre-v5-20260721T010203.000000000Z.bak"
	orphanManifest := databasePath + ".pre-v6-20260719T010203.000000000Z.bak.manifest.json"
	unrelated := filepath.Join(directory, "other-events.db.pre-v6-20260718T010203.000000000Z.bak")
	for path, data := range map[string]string{
		oldBackup:                    "old-sensitive-preview",
		oldBackup + ".manifest.json": `{"schema":"test"}`,
		newBackup:                    "new-sensitive-preview-longer",
		newBackup + ".manifest.json": `{"schema":"test"}`,
		orphanManifest:               `{"schema":"orphan"}`,
		unrelated:                    "must-survive",
	} {
		if err := os.WriteFile(path, []byte(data), 0o400); err != nil {
			t.Fatal(err)
		}
	}

	store, err := Open(Config{
		Path: databasePath,
		RawCapture: RawCaptureConfig{
			Enabled: false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	status := store.Status().MigrationBackups
	if !status.InventoryAvailable || status.Count != 2 || status.ManifestCount != 2 || status.OrphanManifestCount != 1 {
		t.Fatalf("migration backup status=%+v", status)
	}
	if status.PotentialRawCaptureBackupCount != 1 || !status.MayContainSensitiveRequestData ||
		status.SensitiveDataWarning != MigrationBackupSensitiveDataWarning {
		t.Fatalf("migration backup privacy status=%+v", status)
	}
	if status.OldestCreatedAt != "2026-07-20T01:02:03Z" {
		t.Fatalf("oldest_created_at=%q", status.OldestCreatedAt)
	}
	if status.TotalBytes != int64(len("old-sensitive-preview")+len("new-sensitive-preview-longer")) {
		t.Fatalf("total_bytes=%d", status.TotalBytes)
	}

	// Disabling Raw Capture purges only active-table rows. Exact migration
	// backups remain available for rollback until the separate cleanup action is
	// explicitly confirmed.
	if _, err := store.PurgeRawCaptures(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(oldBackup); err != nil {
		t.Fatalf("Raw Capture purge removed migration backup: %v", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.PurgeMigrationBackups(canceled); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled cleanup error=%v", err)
	}
	if _, err := os.Stat(oldBackup); err != nil {
		t.Fatalf("canceled cleanup removed migration backup: %v", err)
	}

	result, err := store.PurgeMigrationBackups(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.DeletedBackups != 2 || result.DeletedManifests != 3 || result.FreedBytes != status.TotalBytes {
		t.Fatalf("cleanup result=%+v", result)
	}
	if result.Remaining.Count != 0 || !result.Remaining.InventoryAvailable {
		t.Fatalf("remaining inventory=%+v", result.Remaining)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("cleanup removed another database's backup: %v", err)
	}
}

func TestRound9MigrationBackupCleanupRejectsSymlinkArtifacts(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("migration backup symlink contract is Linux-only")
	}
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "events.db")
	target := filepath.Join(directory, "target.db")
	if err := os.WriteFile(target, []byte("must-survive"), 0o600); err != nil {
		t.Fatal(err)
	}
	backup := databasePath + ".pre-v6-20260720T010203.000000000Z.bak"
	if err := os.Symlink(target, backup); err != nil {
		t.Fatal(err)
	}
	status, err := InspectMigrationBackups(databasePath)
	if err == nil || status.InventoryAvailable || status.SensitiveDataWarning != MigrationBackupInventoryWarning {
		t.Fatalf("symlink inventory status=%+v err=%v", status, err)
	}
	if _, err := PurgeMigrationBackupsAtPath(context.Background(), databasePath); err == nil {
		t.Fatal("cleanup accepted a symlink migration backup")
	}
	if content, err := os.ReadFile(target); err != nil || string(content) != "must-survive" {
		t.Fatalf("symlink target changed: content=%q err=%v", content, err)
	}
}
