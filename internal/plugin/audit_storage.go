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

const auditStorageGateUnarmedReason = "storage_gate_unarmed"

const auditStoragePriorStoreCloseFailedReason = "prior_store_close_failed"

// auditStorageGate binds every production storage access to the identity
// captured after SQLite Open. The first failed live verification is permanent
// for this runtime: a later probe cannot silently turn writes back on. An
// explicit reconfigure/reopen constructs a new gate and is the only recovery
// boundary.
type auditStorageGate struct {
	mu                               sync.Mutex
	baseline                         auditStorageVerification
	current                          auditStorageVerification
	maxBytes                         int64
	inspect                          func(string, bool, bool, int64) auditStorageVerification
	now                              func() time.Time
	nextProbeAt                      time.Time
	armed                            bool
	latched                          bool
	priorStoreSidecarsPendingRelease bool
}

func newAuditStorageGate(
	baseline auditStorageVerification,
	maxBytes int64,
	inspect func(string, bool, bool, int64) auditStorageVerification,
) *auditStorageGate {
	gate := &auditStorageGate{
		baseline: baseline,
		maxBytes: maxBytes,
		inspect:  inspect,
		now:      time.Now,
	}
	if baseline.preventsDatabaseOpen() {
		gate.current = baseline
		gate.armed = true
		gate.latched = true
		return gate
	}
	gate.current = baseline
	gate.current.State = "unarmed"
	gate.current.PersistenceVerified = false
	gate.current.PersistenceReason = auditStorageGateUnarmedReason
	return gate
}

// authorizePriorStoreSidecarRelease signs the single hot-reconfiguration
// boundary where a successfully flushed/checkpointed/closed prior Store may
// have removed its bound WAL/SHM objects. Candidate construction must never
// call this method: the authorization exists only after CloseContext returns
// nil. Directory, mount, database, and sidecar replacement identities remain
// strict, and activationAccess consumes the authorization exactly once.
func (gate *auditStorageGate) authorizePriorStoreSidecarRelease() {
	if gate == nil {
		return
	}
	gate.mu.Lock()
	gate.priorStoreSidecarsPendingRelease = true
	gate.mu.Unlock()
}

// latchPriorStoreCloseFailure prevents a prepared candidate from opening or
// mutating SQLite after the prior Store failed its bounded durability boundary.
// The candidate remains available as a degraded status witness, but it cannot
// turn a close/checkpoint timeout into a fresh healthy baseline.
func (gate *auditStorageGate) latchPriorStoreCloseFailure() auditStorageVerification {
	if gate == nil {
		return disabledAuditStorageVerification()
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	status := gate.baseline
	status.State = "close_failed"
	status.PersistenceVerified = false
	status.PersistenceReason = auditStoragePriorStoreCloseFailedReason
	gate.current = status
	gate.nextProbeAt = time.Time{}
	gate.armed = true
	gate.latched = true
	gate.priorStoreSidecarsPendingRelease = false
	return status
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
	gate.latched = baseline.preventsDatabaseOpen()
	gate.priorStoreSidecarsPendingRelease = false
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
	gate.priorStoreSidecarsPendingRelease = false
	gate.mu.Unlock()
}

func (gate *auditStorageGate) verification() auditStorageVerification {
	if gate == nil {
		return disabledAuditStorageVerification()
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.verificationLocked()
}

// latchedBeforeClose reports whether the runtime had already exposed a
// permanent storage failure before a reconfiguration began closing it. That
// distinction lets an explicit recovery reconfigure discard an already-failed
// Store, while a failure discovered during this close cannot be laundered into
// a healthy candidate.
func (gate *auditStorageGate) latchedBeforeClose() bool {
	if gate == nil {
		return false
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	return gate.latched
}

// verificationLocked returns a live or cached verdict while the caller holds
// gate.mu. Keeping the access decision under the same lock prevents a
// concurrent arm or latch transition from pairing one status with another
// gate state.
func (gate *auditStorageGate) verificationLocked() auditStorageVerification {
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
	if fresh.preventsDatabaseOpen() {
		gate.latched = true
	} else {
		// Start the minimum interval after the potentially slow live probe. This
		// guarantees back-to-back callers cannot immediately repeat it.
		gate.nextProbeAt = now().Add(auditStorageMinimumReprobeInterval)
	}
	return gate.current
}

func (gate *auditStorageGate) access() error {
	if gate == nil {
		return errors.New("persistent audit storage gate is unavailable")
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	status := gate.verificationLocked()
	blocked := !gate.armed || gate.latched || status.preventsDatabaseOpen()
	if !blocked {
		return nil
	}
	return auditStorageAccessError(status)
}

// activationAccess is deliberately independent from verification's one-second
// write-hot-path cache. It is called only after runtime Swap and before SQLite
// open/create, and it never arms the gate: the opened DB/WAL/SHM identity must
// still be captured by bindAfterOpen.
func (gate *auditStorageGate) activationAccess() error {
	if gate == nil {
		return errors.New("persistent audit storage activation gate is unavailable")
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.latched {
		return auditStorageAccessError(gate.current)
	}
	fresh := recheckAuditStorageWithInspectorTransition(
		gate.baseline,
		gate.maxBytes,
		false,
		gate.priorStoreSidecarsPendingRelease,
		gate.inspect,
	)
	gate.current = fresh
	gate.nextProbeAt = time.Time{}
	if fresh.preventsDatabaseOpen() {
		gate.armed = true
		gate.latched = true
		gate.priorStoreSidecarsPendingRelease = false
		return auditStorageAccessError(fresh)
	}
	if gate.priorStoreSidecarsPendingRelease {
		// Normalize the baseline after the prior Store has closed but before the
		// candidate opens SQLite. bindAfterOpen may then admit only absent-to-new
		// sidecar creation; a present replacement is never treated as lifecycle.
		gate.baseline = fresh
		gate.priorStoreSidecarsPendingRelease = false
	}
	gate.armed = false
	return nil
}

// bindAfterOpen captures the exact artifact identities produced by SQLite open
// before migrations or cleanup execute. It also bypasses the cached probe and
// is the sole transition from an unarmed candidate to an admission-capable
// Store.
func (gate *auditStorageGate) bindAfterOpen() (auditStorageVerification, error) {
	if gate == nil {
		return disabledAuditStorageVerification(), errors.New("persistent audit storage bind gate is unavailable")
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if gate.latched {
		return gate.current, auditStorageAccessError(gate.current)
	}
	fresh := recheckAuditStorageWithInspector(gate.baseline, gate.maxBytes, true, gate.inspect)
	gate.current = fresh
	gate.nextProbeAt = time.Time{}
	if fresh.preventsDatabaseOpen() {
		gate.armed = true
		gate.latched = true
		return fresh, auditStorageAccessError(fresh)
	}
	gate.baseline = fresh
	gate.armed = true
	gate.latched = false
	gate.priorStoreSidecarsPendingRelease = false
	return fresh, nil
}

// readAccess performs a fresh probe for every sensitive read. A successful
// write-cache verdict is intentionally irrelevant; a failure permanently
// latches this runtime until reconfigure/reopen.
func (gate *auditStorageGate) readAccess() error {
	if gate == nil {
		return errors.New("persistent audit storage read gate is unavailable")
	}
	gate.mu.Lock()
	defer gate.mu.Unlock()
	if !gate.armed || gate.latched {
		return auditStorageAccessError(gate.current)
	}
	fresh := recheckAuditStorageWithInspector(gate.baseline, gate.maxBytes, false, gate.inspect)
	gate.current = fresh
	if fresh.preventsDatabaseOpen() {
		gate.latched = true
		gate.nextProbeAt = time.Time{}
		return auditStorageAccessError(fresh)
	}
	return nil
}

func auditStorageAccessError(status auditStorageVerification) error {
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
		"filesystem_type_mismatch", auditStoragePriorStoreCloseFailedReason:
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
	return recheckAuditStorageWithInspectorTransition(
		baseline,
		maxBytes,
		allowNewArtifacts,
		false,
		inspect,
	)
}

func recheckAuditStorageWithInspectorTransition(
	baseline auditStorageVerification,
	maxBytes int64,
	allowNewArtifacts bool,
	allowPriorStoreSidecarRelease bool,
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
	if reason := changedAuditStorageIdentity(
		baseline.identity,
		fresh.identity,
		allowNewArtifacts,
		allowPriorStoreSidecarRelease,
	); reason != "" {
		fresh.State = "identity_changed"
		fresh.PersistenceVerified = false
		fresh.PersistenceReason = reason
	}
	return fresh
}

func changedAuditStorageIdentity(
	baseline,
	fresh auditStorageIdentity,
	allowNewArtifacts bool,
	allowPriorStoreSidecarRelease bool,
) string {
	if baseline.directory.present && !sameAuditStorageObject(baseline.directory, fresh.directory) {
		return "directory_identity_changed"
	}
	if baseline.mount != "" && fresh.mount != baseline.mount {
		return "mount_identity_changed"
	}
	for _, candidate := range []struct {
		name              string
		baseline          auditStorageObjectIdentity
		fresh             auditStorageObjectIdentity
		priorStoreSidecar bool
	}{
		{name: "database_identity_changed", baseline: baseline.database, fresh: fresh.database},
		{name: "wal_identity_changed", baseline: baseline.wal, fresh: fresh.wal, priorStoreSidecar: true},
		{name: "shm_identity_changed", baseline: baseline.shm, fresh: fresh.shm, priorStoreSidecar: true},
	} {
		if candidate.baseline.present {
			if allowPriorStoreSidecarRelease && candidate.priorStoreSidecar && !candidate.fresh.present {
				continue
			}
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
