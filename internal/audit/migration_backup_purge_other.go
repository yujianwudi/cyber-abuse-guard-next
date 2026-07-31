//go:build !linux

package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

func purgeMigrationBackupArtifactsPlatform(ctx context.Context, databasePath string, verifier MigrationBackupPurgeVerifier) (MigrationBackupCleanupResult, error) {
	directory := filepath.Dir(databasePath)
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return MigrationBackupCleanupResult{}, fmt.Errorf("audit: resolve migration-backup directory: %w", err)
	}
	absDirectory, err := filepath.Abs(directory)
	if err != nil {
		return MigrationBackupCleanupResult{}, fmt.Errorf("audit: resolve migration-backup directory: %w", err)
	}
	absResolved, err := filepath.Abs(resolved)
	if err != nil || !sameMigrationBackupPath(absDirectory, absResolved) {
		return MigrationBackupCleanupResult{}, errors.New("audit: migration-backup directory must not contain symlinks")
	}
	inventory, err := inspectMigrationBackupArtifacts(databasePath)
	if err != nil {
		return MigrationBackupCleanupResult{}, err
	}
	if err := verifier(ctx, databasePath); err != nil {
		return MigrationBackupCleanupResult{}, fmt.Errorf("audit: migration-backup storage verification failed: %w", err)
	}
	result := MigrationBackupCleanupResult{}
	remove := func(path, kind string, bytes int64) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := requireRegularMigrationArtifact(path, kind); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("remove migration-backup %s: %w", kind, err)
		}
		if kind == "backup" {
			result.DeletedBackups++
			result.FreedBytes += bytes
		} else {
			result.DeletedManifests++
		}
		return nil
	}
	for _, backup := range inventory.backups {
		if _, statErr := os.Lstat(backup.manifestPath); statErr == nil {
			if err := remove(backup.manifestPath, "manifest", 0); err != nil {
				return migrationBackupCleanupFailure(databasePath, result, err)
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return migrationBackupCleanupFailure(databasePath, result, statErr)
		}
		if err := remove(backup.backupPath, "backup", backup.bytes); err != nil {
			return migrationBackupCleanupFailure(databasePath, result, err)
		}
	}
	for _, manifest := range inventory.orphanManifests {
		if err := remove(manifest, "manifest", 0); err != nil {
			return migrationBackupCleanupFailure(databasePath, result, err)
		}
	}
	if result.DeletedBackups > 0 || result.DeletedManifests > 0 {
		if err := syncMigrationBackupDirectory(directory); err != nil {
			return migrationBackupCleanupFailure(databasePath, result, err)
		}
	}
	remaining, err := InspectMigrationBackups(databasePath)
	result.Remaining = remaining
	return result, err
}

func sameMigrationBackupPath(left, right string) bool {
	return filepath.Clean(left) == filepath.Clean(right)
}
