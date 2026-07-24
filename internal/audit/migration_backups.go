package audit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	// MigrationBackupSensitiveDataWarning is deliberately path-free and safe to
	// expose through the authenticated management API. Schema-v6 migration
	// backups are exact rollback snapshots, so a pre-v6 database can retain the
	// bounded Raw Capture previews that existed when migration started.
	MigrationBackupSensitiveDataWarning = "migration backups are exact rollback snapshots and may retain sensitive request previews; disabling Raw Capture does not delete them"
	MigrationBackupInventoryWarning     = "migration backup inventory is unavailable; sensitive rollback snapshots may still exist"
)

// MigrationBackupStatus is a bounded, path-free inventory suitable for
// management responses. It never exposes backup names, hashes, or request
// preview content.
type MigrationBackupStatus struct {
	InventoryAvailable             bool   `json:"inventory_available"`
	Count                          int    `json:"count"`
	ManifestCount                  int    `json:"manifest_count"`
	OrphanManifestCount            int    `json:"orphan_manifest_count"`
	TotalBytes                     int64  `json:"total_bytes"`
	OldestCreatedAt                string `json:"oldest_created_at,omitempty"`
	PotentialRawCaptureBackupCount int    `json:"potential_raw_capture_backup_count"`
	MayContainSensitiveRequestData bool   `json:"may_contain_sensitive_request_data"`
	SensitiveDataWarning           string `json:"sensitive_data_warning,omitempty"`
}

// MigrationBackupCleanupResult reports only bounded operational metadata.
// Deleted backup names and filesystem paths are intentionally not returned.
type MigrationBackupCleanupResult struct {
	DeletedBackups   int                   `json:"deleted_backups"`
	DeletedManifests int                   `json:"deleted_manifests"`
	FreedBytes       int64                 `json:"freed_bytes"`
	Remaining        MigrationBackupStatus `json:"remaining"`
}

type migrationBackupArtifact struct {
	backupPath   string
	manifestPath string
	bytes        int64
	createdAt    time.Time
	target       int
}

type migrationBackupInventory struct {
	status          MigrationBackupStatus
	backups         []migrationBackupArtifact
	orphanManifests []string
}

// InspectMigrationBackups returns a fresh, path-free inventory. A missing
// parent directory is an empty, available inventory rather than an error.
func InspectMigrationBackups(databasePath string) (MigrationBackupStatus, error) {
	inventory, err := inspectMigrationBackupArtifacts(databasePath)
	if err != nil {
		return MigrationBackupStatus{
			InventoryAvailable:   false,
			SensitiveDataWarning: MigrationBackupInventoryWarning,
		}, err
	}
	return inventory.status, nil
}

// PurgeMigrationBackupsAtPath is the filesystem form used when auditing is
// disabled and no Store exists. Callers must enforce their own authorization
// and explicit destructive confirmation before invoking it.
func PurgeMigrationBackupsAtPath(ctx context.Context, databasePath string) (MigrationBackupCleanupResult, error) {
	return purgeMigrationBackupArtifacts(ctx, databasePath)
}

// PurgeMigrationBackups removes migration snapshots and their manifests. It is
// intentionally separate from PurgeRawCaptures: disabling Raw Capture must not
// silently destroy the exact database required for an older-SO rollback.
func (s *Store) PurgeMigrationBackups(ctx context.Context) (MigrationBackupCleanupResult, error) {
	if s == nil {
		return MigrationBackupCleanupResult{}, ErrUnavailable
	}
	s.migrationBackupMu.Lock()
	defer s.migrationBackupMu.Unlock()
	return purgeMigrationBackupArtifacts(ctx, s.cfg.Path)
}

func inspectMigrationBackupArtifacts(databasePath string) (migrationBackupInventory, error) {
	if strings.TrimSpace(databasePath) == "" {
		return migrationBackupInventory{}, errors.New("audit: database path is empty")
	}
	directory := filepath.Dir(databasePath)
	databaseName := filepath.Base(databasePath)
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return migrationBackupInventory{status: MigrationBackupStatus{InventoryAvailable: true}}, nil
	}
	if err != nil {
		return migrationBackupInventory{}, fmt.Errorf("audit: inspect migration-backup directory: %w", err)
	}

	backups := make([]migrationBackupArtifact, 0, 4)
	backupNames := make(map[string]struct{})
	manifestNames := make(map[string]string)
	for _, entry := range entries {
		name := entry.Name()
		if isMigrationBackupName(databaseName, name) {
			path := filepath.Join(directory, name)
			info, statErr := os.Lstat(path)
			if statErr != nil {
				return migrationBackupInventory{}, fmt.Errorf("audit: inspect migration backup: %w", statErr)
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				return migrationBackupInventory{}, errors.New("audit: migration backup inventory contains a non-regular artifact")
			}
			target, stamp := parseMigrationBackupIdentity(databaseName, name)
			createdAt := info.ModTime().UTC()
			if parsed, parseErr := time.Parse("20060102T150405.000000000Z", stamp); parseErr == nil {
				createdAt = parsed.UTC()
			}
			backups = append(backups, migrationBackupArtifact{
				backupPath:   path,
				manifestPath: path + ".manifest.json",
				bytes:        info.Size(),
				createdAt:    createdAt,
				target:       target,
			})
			backupNames[name] = struct{}{}
			continue
		}
		if strings.HasSuffix(name, ".bak.manifest.json") {
			backupName := strings.TrimSuffix(name, ".manifest.json")
			if isMigrationBackupName(databaseName, backupName) {
				manifestNames[name] = filepath.Join(directory, name)
			}
		}
	}

	status := MigrationBackupStatus{InventoryAvailable: true}
	for index := range backups {
		backup := &backups[index]
		status.Count++
		status.TotalBytes += backup.bytes
		if backup.target >= 6 {
			status.PotentialRawCaptureBackupCount++
		}
		if status.OldestCreatedAt == "" || backup.createdAt.Before(parseStatusTime(status.OldestCreatedAt)) {
			status.OldestCreatedAt = backup.createdAt.Format(time.RFC3339Nano)
		}
		manifestName := filepath.Base(backup.manifestPath)
		manifestPath, ok := manifestNames[manifestName]
		if !ok {
			continue
		}
		if err := requireRegularMigrationArtifact(manifestPath, "manifest"); err != nil {
			return migrationBackupInventory{}, err
		}
		status.ManifestCount++
		delete(manifestNames, manifestName)
	}
	for name, path := range manifestNames {
		backupName := strings.TrimSuffix(name, ".manifest.json")
		if _, paired := backupNames[backupName]; paired {
			continue
		}
		if err := requireRegularMigrationArtifact(path, "manifest"); err != nil {
			return migrationBackupInventory{}, err
		}
		status.OrphanManifestCount++
	}
	if status.Count > 0 {
		status.MayContainSensitiveRequestData = true
		status.SensitiveDataWarning = MigrationBackupSensitiveDataWarning
	}
	sort.Slice(backups, func(i, j int) bool {
		if backups[i].createdAt.Equal(backups[j].createdAt) {
			return backups[i].backupPath < backups[j].backupPath
		}
		return backups[i].createdAt.Before(backups[j].createdAt)
	})
	orphanManifests := make([]string, 0, len(manifestNames))
	for _, path := range manifestNames {
		orphanManifests = append(orphanManifests, path)
	}
	sort.Strings(orphanManifests)
	return migrationBackupInventory{status: status, backups: backups, orphanManifests: orphanManifests}, nil
}

func purgeMigrationBackupArtifacts(ctx context.Context, databasePath string) (MigrationBackupCleanupResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return MigrationBackupCleanupResult{}, fmt.Errorf("audit: migration-backup cleanup canceled: %w", err)
	}
	inventory, err := inspectMigrationBackupArtifacts(databasePath)
	if err != nil {
		return MigrationBackupCleanupResult{}, err
	}
	result := MigrationBackupCleanupResult{}
	for _, backup := range inventory.backups {
		if err := ctx.Err(); err != nil {
			return migrationBackupCleanupFailure(databasePath, result, err)
		}
		if _, statErr := os.Lstat(backup.manifestPath); statErr == nil {
			if err := requireRegularMigrationArtifact(backup.manifestPath, "manifest"); err != nil {
				return migrationBackupCleanupFailure(databasePath, result, err)
			}
			if err := os.Remove(backup.manifestPath); err != nil {
				return migrationBackupCleanupFailure(databasePath, result, fmt.Errorf("remove migration-backup manifest: %w", err))
			}
			result.DeletedManifests++
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return migrationBackupCleanupFailure(databasePath, result, statErr)
		}
		if err := requireRegularMigrationArtifact(backup.backupPath, "backup"); err != nil {
			return migrationBackupCleanupFailure(databasePath, result, err)
		}
		if err := os.Remove(backup.backupPath); err != nil {
			return migrationBackupCleanupFailure(databasePath, result, fmt.Errorf("remove migration backup: %w", err))
		}
		result.DeletedBackups++
		result.FreedBytes += backup.bytes
	}
	for _, manifestPath := range inventory.orphanManifests {
		if err := ctx.Err(); err != nil {
			return migrationBackupCleanupFailure(databasePath, result, err)
		}
		if err := requireRegularMigrationArtifact(manifestPath, "manifest"); err != nil {
			return migrationBackupCleanupFailure(databasePath, result, err)
		}
		if err := os.Remove(manifestPath); err != nil {
			return migrationBackupCleanupFailure(databasePath, result, fmt.Errorf("remove orphan migration-backup manifest: %w", err))
		}
		result.DeletedManifests++
	}
	if result.DeletedBackups > 0 || result.DeletedManifests > 0 {
		if err := syncMigrationBackupDirectory(filepath.Dir(databasePath)); err != nil {
			return migrationBackupCleanupFailure(databasePath, result, err)
		}
	}
	remaining, err := InspectMigrationBackups(databasePath)
	result.Remaining = remaining
	if err != nil {
		return result, err
	}
	return result, nil
}

func migrationBackupCleanupFailure(databasePath string, result MigrationBackupCleanupResult, cause error) (MigrationBackupCleanupResult, error) {
	remaining, inspectErr := InspectMigrationBackups(databasePath)
	result.Remaining = remaining
	if inspectErr != nil {
		return result, errors.Join(fmt.Errorf("audit: migration-backup cleanup failed: %w", cause), inspectErr)
	}
	return result, fmt.Errorf("audit: migration-backup cleanup failed: %w", cause)
}

func requireRegularMigrationArtifact(path, kind string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("audit: inspect migration-backup %s: %w", kind, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("audit: migration-backup %s must be a regular non-symlink file", kind)
	}
	return nil
}

func parseMigrationBackupIdentity(databaseName, candidate string) (target int, stamp string) {
	remainder := strings.TrimSuffix(strings.TrimPrefix(candidate, databaseName+".pre-v"), ".bak")
	separator := strings.IndexByte(remainder, '-')
	if separator < 1 {
		return 0, ""
	}
	target, _ = strconv.Atoi(remainder[:separator])
	return target, remainder[separator+1:]
}

func parseStatusTime(raw string) time.Time {
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}
	}
	return parsed
}

func syncMigrationBackupDirectory(directory string) error {
	parent, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("audit: open migration-backup directory for sync: %w", err)
	}
	if err := parent.Sync(); err != nil {
		_ = parent.Close()
		return fmt.Errorf("audit: sync migration-backup directory: %w", err)
	}
	if err := parent.Close(); err != nil {
		return fmt.Errorf("audit: close migration-backup directory: %w", err)
	}
	return nil
}
