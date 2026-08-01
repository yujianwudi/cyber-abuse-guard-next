package plugin

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/config"
)

type auditStorageVerification struct {
	StorageType         string `json:"storage_type"`
	State               string `json:"storage_state"`
	PathSource          string `json:"path_source"`
	DatabasePath        string `json:"database_path"`
	PersistenceExpected bool   `json:"persistence_expected"`
	PersistenceVerified bool   `json:"persistence_verified"`
	PersistenceReason   string `json:"persistence_reason,omitempty"`
	SeparateMount       bool   `json:"separate_mount"`
	Writable            bool   `json:"writable"`
	CapacityOK          bool   `json:"capacity_ok"`
	identity            auditStorageIdentity
}

// auditStorageIdentity is intentionally absent from management JSON. Device,
// inode, and mount identifiers are local comparison material, not stable API
// fields. Linux populates them from opened file descriptors and mountinfo.
type auditStorageIdentity struct {
	directory auditStorageObjectIdentity
	database  auditStorageObjectIdentity
	wal       auditStorageObjectIdentity
	shm       auditStorageObjectIdentity
	mount     string
}

type auditStorageObjectIdentity struct {
	present bool
	device  uint64
	inode   uint64
}

// One second bounds the interval in which a newly failed mount can still use
// the last verified result, while keeping mountinfo/statfs and object identity
// probes out of the per-write hot path. time.Time carries its monotonic reading
// through Add, so wall-clock adjustments cannot extend this interval.
const auditStorageMinimumReprobeInterval = time.Second

// auditStorageGate binds every production storage access to the identity
// captured after SQLite Open. The first failed live verification is permanent
// for this runtime: a later probe cannot silently turn writes back on. An
// explicit reconfigure/reopen constructs a new gate and is the only recovery
// boundary.
type auditStorageGate struct {
	mu          sync.Mutex
	baseline    auditStorageVerification
	current     auditStorageVerification
	maxBytes    int64
	inspect     func(string, bool, bool, int64) auditStorageVerification
	now         func() time.Time
	nextProbeAt time.Time
	armed       bool
	latched     bool
}

func newAuditStorageGate(
	baseline auditStorageVerification,
	maxBytes int64,
	inspect func(string, bool, bool, int64) auditStorageVerification,
) *auditStorageGate {
	return &auditStorageGate{
		baseline: baseline,
		current:  baseline,
		maxBytes: maxBytes,
		inspect:  inspect,
		now:      time.Now,
	}
}

func (gate *auditStorageGate) arm(baseline auditStorageVerification) {
	if gate == nil {
		return
	}
	gate.mu.Lock()
	gate.baseline = baseline
	gate.current = baseline
	gate.nextProbeAt = time.Time{}
	gate.armed = true
	gate.latched = baseline.blocksOperationalReadiness()
	gate.mu.Unlock()
}

func (gate *auditStorageGate) latch(status auditStorageVerification) {
	if gate == nil {
		return
	}
	gate.mu.Lock()
	gate.current = status
	gate.nextProbeAt = time.Time{}
	gate.armed = true
	gate.latched = true
	gate.mu.Unlock()
}

func (gate *auditStorageGate) verification() auditStorageVerification {
	if gate == nil {
		return disabledAuditStorageVerification()
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.latched || !gate.armed {
		return gate.current
	}
	now := time.Now
	if gate.now != nil {
		now = gate.now
	}
	if probeTime := now(); !gate.nextProbeAt.IsZero() && probeTime.Before(gate.nextProbeAt) {
		return gate.current
	}
	fresh := recheckAuditStorageWithInspector(gate.baseline, gate.maxBytes, false, gate.inspect)
	gate.current = fresh
	if fresh.blocksOperationalReadiness() {
		gate.latched = true
	} else {
		// Start the minimum interval after the potentially slow live probe. This
		// guarantees back-to-back callers cannot immediately repeat it.
		gate.nextProbeAt = now().Add(auditStorageMinimumReprobeInterval)
	}
	return gate.current
}

func (gate *auditStorageGate) access() error {
	status := gate.verification()
	if !status.blocksOperationalReadiness() {
		return nil
	}
	reason := status.PersistenceReason
	if reason == "" {
		reason = "unverified"
	}
	return fmt.Errorf("persistent audit storage gate is latched: %s", reason)
}

func disabledAuditStorageVerification() auditStorageVerification {
	return auditStorageVerification{
		StorageType: "disabled",
		State:       "disabled",
		PathSource:  "disabled",
	}
}

func (status auditStorageVerification) blocksOperationalReadiness() bool {
	return status.PersistenceExpected && !status.PersistenceVerified
}

// preventsDatabaseOpen is the final SQLite-open gate. When the operator opted
// into the production persistence contract, every unverified state is a hard
// storage boundary: tmpfs, container layers, read-only/capacity failures, and
// unknown mounts must not receive a database open. Without that explicit
// contract, ordinary development audit storage remains compatible, while
// unsafe path/object states are still rejected unconditionally.
func (status auditStorageVerification) preventsDatabaseOpen() bool {
	if status.blocksOperationalReadiness() {
		return true
	}
	return status.hasUnsafeDatabasePath()
}

// hasUnsafeDatabasePath is narrower than the production durability gate. It is
// used by identity rechecks so a tmpfs/capacity classification does not mask a
// more specific directory/DB/WAL/SHM replacement detected against the startup
// baseline.
func (status auditStorageVerification) hasUnsafeDatabasePath() bool {
	switch status.PersistenceReason {
	case "path_unavailable", "path_resolution_failed", "symlinked_directory",
		"unsafe_sqlite_file", "database_stat_failed", "statfs_failed",
		"unsafe_storage_owner", "unsafe_storage_permissions", "storage_open_failed",
		"directory_identity_changed", "mount_identity_changed",
		"database_identity_changed", "wal_identity_changed", "shm_identity_changed",
		"filesystem_type_mismatch":
		return true
	case "path_not_absolute":
		return status.PersistenceExpected
	default:
		return false
	}
}

func (state *runtimeState) currentAuditStorageVerification() auditStorageVerification {
	if state == nil {
		return disabledAuditStorageVerification()
	}
	var status auditStorageVerification
	if state.auditStorageGate != nil {
		status = state.auditStorageGate.verification()
	} else if state.auditStorageProbe != nil {
		status = state.auditStorageProbe(state.auditStorage)
	} else {
		status = state.auditStorage
	}
	if status.blocksOperationalReadiness() {
		state.blockSubjectPersistenceForStorage()
	}
	return status
}

// recheckAuditStorage performs a new pathname/mount/permission/capacity probe
// and then binds it to the identities captured at startup. allowNewArtifacts is
// true only for the immediate post-Open pass because SQLite is expected to
// create a previously absent DB/WAL/SHM set during that one boundary.
func recheckAuditStorage(baseline auditStorageVerification, maxBytes int64, allowNewArtifacts bool) auditStorageVerification {
	return recheckAuditStorageWithInspector(baseline, maxBytes, allowNewArtifacts, inspectAuditStorage)
}

func recheckAuditStorageWithInspector(
	baseline auditStorageVerification,
	maxBytes int64,
	allowNewArtifacts bool,
	inspect func(string, bool, bool, int64) auditStorageVerification,
) auditStorageVerification {
	fresh := inspect(
		baseline.DatabasePath,
		baseline.PathSource == "explicit",
		baseline.PersistenceExpected,
		maxBytes,
	)
	if fresh.hasUnsafeDatabasePath() {
		return fresh
	}
	if reason := changedAuditStorageIdentity(baseline.identity, fresh.identity, allowNewArtifacts); reason != "" {
		fresh.State = "identity_changed"
		fresh.PersistenceVerified = false
		fresh.PersistenceReason = reason
	}
	return fresh
}

func changedAuditStorageIdentity(baseline, fresh auditStorageIdentity, allowNewArtifacts bool) string {
	if baseline.directory.present && !sameAuditStorageObject(baseline.directory, fresh.directory) {
		return "directory_identity_changed"
	}
	if baseline.mount != "" && fresh.mount != baseline.mount {
		return "mount_identity_changed"
	}
	for _, candidate := range []struct {
		name     string
		baseline auditStorageObjectIdentity
		fresh    auditStorageObjectIdentity
	}{
		{name: "database_identity_changed", baseline: baseline.database, fresh: fresh.database},
		{name: "wal_identity_changed", baseline: baseline.wal, fresh: fresh.wal},
		{name: "shm_identity_changed", baseline: baseline.shm, fresh: fresh.shm},
	} {
		if candidate.baseline.present {
			if !sameAuditStorageObject(candidate.baseline, candidate.fresh) {
				return candidate.name
			}
			continue
		}
		if candidate.fresh.present && !allowNewArtifacts {
			return candidate.name
		}
	}
	return ""
}

func sameAuditStorageObject(left, right auditStorageObjectIdentity) bool {
	return left.present == right.present && (!left.present || left.device == right.device && left.inode == right.inode)
}

func auditPersistenceExpected(cfg config.Config) bool {
	return cfg.Audit.Enabled && cfg.Audit.RequirePersistentStorage
}

func inspectAuditStorage(
	databasePath string,
	explicit bool,
	expected bool,
	maxBytes int64,
) auditStorageVerification {
	status := auditStorageVerification{
		StorageType:         "unknown",
		State:               "unverified",
		PathSource:          "default_home",
		DatabasePath:        databasePath,
		PersistenceExpected: expected,
	}
	if explicit {
		status.PathSource = "explicit"
	}
	if strings.TrimSpace(databasePath) == "" {
		status.PersistenceReason = "path_unavailable"
		return status
	}
	abs, err := filepath.Abs(databasePath)
	if err != nil || filepath.Clean(abs) != filepath.Clean(databasePath) {
		status.PersistenceReason = "path_not_absolute"
		return status
	}
	status.DatabasePath = abs
	directory := filepath.Dir(abs)
	resolved, err := filepath.EvalSymlinks(directory)
	if err != nil {
		status.PersistenceReason = "path_resolution_failed"
		return status
	}
	resolvedAbs, err := filepath.Abs(resolved)
	if err != nil || !sameAuditStoragePath(resolvedAbs, directory) {
		status.PersistenceReason = "symlinked_directory"
		return status
	}
	for _, candidate := range []string{abs, abs + "-wal", abs + "-shm"} {
		if info, statErr := os.Lstat(candidate); statErr == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
				status.PersistenceReason = "unsafe_sqlite_file"
				return status
			}
		} else if !errors.Is(statErr, os.ErrNotExist) {
			status.PersistenceReason = "database_stat_failed"
			return status
		}
	}
	return inspectAuditStoragePlatform(status, directory, maxBytes)
}

func sameAuditStoragePath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}
