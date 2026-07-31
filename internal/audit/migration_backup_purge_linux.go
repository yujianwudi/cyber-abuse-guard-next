//go:build linux

package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

type pinnedMigrationArtifact struct {
	name     string
	bytes    int64
	device   uint64
	inode    uint64
	isBackup bool
}

type pinnedMigrationInventory struct {
	status    MigrationBackupStatus
	artifacts []pinnedMigrationArtifact
}

func purgeMigrationBackupArtifactsPlatform(ctx context.Context, databasePath string, verifier MigrationBackupPurgeVerifier) (MigrationBackupCleanupResult, error) {
	directory := filepath.Dir(databasePath)
	databaseName := filepath.Base(databasePath)
	fd, err := openMigrationBackupDirectoryNoFollow(directory)
	if err != nil {
		return MigrationBackupCleanupResult{}, err
	}
	parent := os.NewFile(uintptr(fd), directory)
	if parent == nil {
		_ = unix.Close(fd)
		return MigrationBackupCleanupResult{}, errors.New("audit: open migration-backup directory: invalid directory handle")
	}
	defer parent.Close()

	inventory, err := inspectPinnedMigrationBackups(parent, databaseName)
	if err != nil {
		return MigrationBackupCleanupResult{}, err
	}
	if err := verifier(ctx, databasePath); err != nil {
		return MigrationBackupCleanupResult{}, fmt.Errorf("audit: migration-backup storage verification failed: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return MigrationBackupCleanupResult{}, fmt.Errorf("audit: migration-backup cleanup canceled: %w", err)
	}

	result := MigrationBackupCleanupResult{}
	for _, artifact := range inventory.artifacts {
		if err := ctx.Err(); err != nil {
			return pinnedMigrationBackupCleanupFailure(parent, databaseName, result, err)
		}
		var current unix.Stat_t
		if err := unix.Fstatat(fd, artifact.name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return pinnedMigrationBackupCleanupFailure(parent, databaseName, result, fmt.Errorf("inspect migration-backup artifact before deletion: %w", err))
		}
		if current.Mode&unix.S_IFMT != unix.S_IFREG || uint64(current.Dev) != artifact.device || current.Ino != artifact.inode {
			return pinnedMigrationBackupCleanupFailure(parent, databaseName, result, errors.New("migration-backup artifact changed after verified inventory"))
		}
		if err := unix.Unlinkat(fd, artifact.name, 0); err != nil {
			return pinnedMigrationBackupCleanupFailure(parent, databaseName, result, fmt.Errorf("remove migration-backup artifact: %w", err))
		}
		if artifact.isBackup {
			result.DeletedBackups++
			result.FreedBytes += artifact.bytes
		} else {
			result.DeletedManifests++
		}
	}
	if len(inventory.artifacts) > 0 {
		if err := unix.Fsync(fd); err != nil {
			return pinnedMigrationBackupCleanupFailure(parent, databaseName, result, fmt.Errorf("sync migration-backup directory: %w", err))
		}
	}
	remaining, err := inspectPinnedMigrationBackups(parent, databaseName)
	result.Remaining = remaining.status
	if err != nil {
		return result, err
	}
	return result, nil
}

// openMigrationBackupDirectoryNoFollow walks one directory component at a
// time. O_NOFOLLOW on only the final path is insufficient because an ancestor
// could otherwise redirect the purge before the directory is pinned.
func openMigrationBackupDirectoryNoFollow(directory string) (int, error) {
	if strings.TrimSpace(directory) == "" {
		return -1, errors.New("audit: migration-backup directory is empty")
	}
	clean := filepath.Clean(directory)
	start := "."
	if filepath.IsAbs(clean) {
		start = string(filepath.Separator)
		clean = strings.TrimPrefix(clean, string(filepath.Separator))
	}
	fd, err := unix.Open(start, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, fmt.Errorf("audit: open migration-backup directory without symlinks: %w", err)
	}
	for _, component := range strings.Split(clean, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		if component == ".." {
			_ = unix.Close(fd)
			return -1, errors.New("audit: migration-backup directory must not contain parent traversal")
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if openErr != nil {
			return -1, fmt.Errorf("audit: open migration-backup directory component without symlinks: %w", openErr)
		}
		fd = next
	}
	return fd, nil
}

func inspectPinnedMigrationBackups(parent *os.File, databaseName string) (pinnedMigrationInventory, error) {
	fd := int(parent.Fd())
	if _, err := parent.Seek(0, 0); err != nil {
		return pinnedMigrationInventory{}, fmt.Errorf("audit: rewind migration-backup directory: %w", err)
	}
	entries, err := parent.ReadDir(-1)
	if err != nil {
		return pinnedMigrationInventory{}, fmt.Errorf("audit: read pinned migration-backup directory: %w", err)
	}
	status := MigrationBackupStatus{InventoryAvailable: true}
	artifacts := make([]pinnedMigrationArtifact, 0, 8)
	backupNames := make(map[string]struct{})
	manifestNames := make(map[string]pinnedMigrationArtifact)
	for _, entry := range entries {
		name := entry.Name()
		isBackup := isMigrationBackupName(databaseName, name)
		isManifest := strings.HasSuffix(name, ".bak.manifest.json") && isMigrationBackupName(databaseName, strings.TrimSuffix(name, ".manifest.json"))
		if !isBackup && !isManifest {
			continue
		}
		var stat unix.Stat_t
		if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return pinnedMigrationInventory{}, fmt.Errorf("audit: inspect pinned migration-backup artifact: %w", err)
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFREG {
			return pinnedMigrationInventory{}, errors.New("audit: migration backup inventory contains a non-regular artifact")
		}
		artifact := pinnedMigrationArtifact{name: name, bytes: stat.Size, device: uint64(stat.Dev), inode: stat.Ino, isBackup: isBackup}
		if isManifest {
			manifestNames[name] = artifact
			continue
		}
		backupNames[name] = struct{}{}
		artifacts = append(artifacts, artifact)
		status.Count++
		status.TotalBytes += stat.Size
		target, stamp := parseMigrationBackupIdentity(databaseName, name)
		if target >= 6 {
			status.PotentialRawCaptureBackupCount++
		}
		createdAt := time.Unix(stat.Mtim.Sec, stat.Mtim.Nsec).UTC()
		if parsed, parseErr := time.Parse("20060102T150405.000000000Z", stamp); parseErr == nil {
			createdAt = parsed.UTC()
		}
		if status.OldestCreatedAt == "" || createdAt.Before(parseStatusTime(status.OldestCreatedAt)) {
			status.OldestCreatedAt = createdAt.Format(time.RFC3339Nano)
		}
	}
	for name, artifact := range manifestNames {
		backupName := strings.TrimSuffix(name, ".manifest.json")
		if _, paired := backupNames[backupName]; paired {
			status.ManifestCount++
		} else {
			status.OrphanManifestCount++
		}
		artifacts = append(artifacts, artifact)
	}
	if status.Count > 0 {
		status.MayContainSensitiveRequestData = true
		status.SensitiveDataWarning = MigrationBackupSensitiveDataWarning
	}
	// Preserve the historical manifest-before-backup behavior for paired files;
	// all ordering is deterministic and scoped to recognized artifacts.
	sort.Slice(artifacts, func(i, j int) bool {
		leftBackup := artifacts[i].isBackup
		rightBackup := artifacts[j].isBackup
		leftBase := strings.TrimSuffix(artifacts[i].name, ".manifest.json")
		rightBase := strings.TrimSuffix(artifacts[j].name, ".manifest.json")
		if leftBase == rightBase && leftBackup != rightBackup {
			return !leftBackup
		}
		return artifacts[i].name < artifacts[j].name
	})
	return pinnedMigrationInventory{status: status, artifacts: artifacts}, nil
}

func pinnedMigrationBackupCleanupFailure(parent *os.File, databaseName string, result MigrationBackupCleanupResult, cause error) (MigrationBackupCleanupResult, error) {
	remaining, inspectErr := inspectPinnedMigrationBackups(parent, databaseName)
	result.Remaining = remaining.status
	if inspectErr != nil {
		return result, errors.Join(fmt.Errorf("audit: migration-backup cleanup failed: %w", cause), inspectErr)
	}
	return result, fmt.Errorf("audit: migration-backup cleanup failed: %w", cause)
}
