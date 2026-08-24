package plugin

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/pluginapi"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/audit"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/config"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/subject"
)

func TestAuditPersistenceVerificationLatchesOperationalReadiness(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	p.auditStorageInspect = verifiedAuditStorageInspectorForTest
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\n  require_persistent_storage: true\nsubject_control:\n  enabled: false\n")

	state := p.runtime.Load()
	if state == nil || state.audit == nil {
		t.Fatal("audit runtime was not initialized")
	}
	databasePath := filepath.Join(filepath.FromSlash(dataDir), "events.db")
	live := auditStorageVerification{
		StorageType:         "overlay",
		State:               "container_layer",
		PathSource:          "explicit",
		DatabasePath:        databasePath,
		PersistenceExpected: true,
		PersistenceReason:   "container_layer",
		Writable:            true,
		CapacityOK:          true,
	}
	if state.auditStorageGate == nil {
		t.Fatal("required persistence runtime did not install a storage gate")
	}
	state.auditStorageGate.latch(live)

	status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	if status["enforcement_ready"] != true || status["operational_ready"] != false || status["audit_degraded"] != true {
		t.Fatalf("unverified persistence readiness=%#v", status)
	}
	if reasons, ok := status["readiness_reasons"].([]any); !ok || !reflect.DeepEqual(reasons, []any{"audit_runtime_degraded", "audit_persistence_unverified"}) {
		t.Fatalf("readiness reasons=%#v", status["readiness_reasons"])
	}
	auditStatus, ok := status["audit"].(map[string]any)
	if !ok || auditStatus["degraded"] != true || auditStatus["persistence_expected"] != true || auditStatus["persistence_verified"] != false ||
		auditStatus["persistence_reason"] != "container_layer" || auditStatus["database_path"] != databasePath {
		t.Fatalf("audit persistence status=%#v", status["audit"])
	}

	// Even if the path later looks healthy, this runtime stays latched. Only an
	// explicit reconfigure/reopen may construct a fresh gate.
	status = managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	if status["operational_ready"] != false || status["audit_degraded"] != true {
		t.Fatalf("latched persistence recovered without reconfigure: %#v", status)
	}

	response, body := callManagementResponse(t, p, pluginapi.ManagementRequest{
		Method: http.MethodGet,
		Path:   managementBasePath + "/status",
	})
	if response.StatusCode != http.StatusUnauthorized || strings.Contains(string(body), databasePath) {
		t.Fatalf("unauthenticated status leaked database path: status=%d body=%s", response.StatusCode, body)
	}
}

func TestAuditStorageDisabledDoesNotRequirePersistence(t *testing.T) {
	t.Parallel()
	status := disabledAuditStorageVerification()
	if status.blocksOperationalReadiness() || status.PersistenceExpected || status.PersistenceVerified {
		t.Fatalf("disabled storage verification=%#v", status)
	}
}

func TestAuditStorageGateCachesSuccessfulProbeUntilMinimumInterval(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "events.db")
	baseline := verifiedAuditStorageInspectorForTest(databasePath, true, true, 1)
	var calls atomic.Uint64
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	gate := newAuditStorageGate(baseline, 1, func(path string, explicit, expected bool, maxBytes int64) auditStorageVerification {
		calls.Add(1)
		return verifiedAuditStorageInspectorForTest(path, explicit, expected, maxBytes)
	})
	gate.now = func() time.Time { return now }
	gate.arm(baseline)

	if status := gate.verification(); !status.PersistenceVerified || calls.Load() != 1 {
		t.Fatalf("first verification status=%#v calls=%d", status, calls.Load())
	}
	if err := gate.access(); err != nil || calls.Load() != 1 {
		t.Fatalf("cached access error=%v calls=%d", err, calls.Load())
	}
	now = now.Add(auditStorageMinimumReprobeInterval - time.Nanosecond)
	if status := gate.verification(); !status.PersistenceVerified || calls.Load() != 1 {
		t.Fatalf("pre-expiry verification status=%#v calls=%d", status, calls.Load())
	}
	now = now.Add(time.Nanosecond)
	if status := gate.verification(); !status.PersistenceVerified || calls.Load() != 2 {
		t.Fatalf("expired verification status=%#v calls=%d", status, calls.Load())
	}

	// Re-arming is a fresh open boundary and must not inherit a cached deadline.
	gate.arm(baseline)
	if status := gate.verification(); !status.PersistenceVerified || calls.Load() != 3 {
		t.Fatalf("re-armed verification status=%#v calls=%d", status, calls.Load())
	}
}

func TestAuditStorageGateExpiredFailureLatchesPermanently(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "events.db")
	baseline := verifiedAuditStorageInspectorForTest(databasePath, true, true, 1)
	var calls atomic.Uint64
	healthy := true
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	gate := newAuditStorageGate(baseline, 1, func(path string, explicit, expected bool, maxBytes int64) auditStorageVerification {
		calls.Add(1)
		status := verifiedAuditStorageInspectorForTest(path, explicit, expected, maxBytes)
		if !healthy {
			status.State = "read_only"
			status.PersistenceVerified = false
			status.PersistenceReason = "read_only"
			status.Writable = false
		}
		return status
	})
	gate.now = func() time.Time { return now }
	gate.arm(baseline)

	if err := gate.access(); err != nil {
		t.Fatalf("initial verified access: %v", err)
	}
	healthy = false
	now = now.Add(auditStorageMinimumReprobeInterval)
	if err := gate.access(); err == nil || !strings.Contains(err.Error(), "read_only") {
		t.Fatalf("expired failure access error=%v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("failure probe calls=%d, want 2", calls.Load())
	}

	healthy = true
	now = now.Add(10 * auditStorageMinimumReprobeInterval)
	if err := gate.access(); err == nil || !strings.Contains(err.Error(), "read_only") {
		t.Fatalf("latched access error=%v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("latched gate re-probed %d times", calls.Load())
	}
}

func TestAuditStorageGateConcurrentAccessSharesOneLiveProbe(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "events.db")
	baseline := verifiedAuditStorageInspectorForTest(databasePath, true, true, 1)
	var calls atomic.Uint64
	probeStarted := make(chan struct{})
	releaseProbe := make(chan struct{})
	var signalProbe sync.Once
	gate := newAuditStorageGate(baseline, 1, func(path string, explicit, expected bool, maxBytes int64) auditStorageVerification {
		calls.Add(1)
		signalProbe.Do(func() { close(probeStarted) })
		<-releaseProbe
		return verifiedAuditStorageInspectorForTest(path, explicit, expected, maxBytes)
	})
	gate.arm(baseline)

	const callers = 64
	start := make(chan struct{})
	errorsSeen := make(chan error, callers)
	var callersDone sync.WaitGroup
	callersDone.Add(callers)
	for range callers {
		go func() {
			defer callersDone.Done()
			<-start
			errorsSeen <- gate.access()
		}()
	}
	close(start)
	<-probeStarted
	close(releaseProbe)
	callersDone.Wait()
	close(errorsSeen)
	for err := range errorsSeen {
		if err != nil {
			t.Fatalf("concurrent access error=%v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent inspector calls=%d, want 1", calls.Load())
	}
}

func TestAuditStorageGateNilUnarmedAndLatchedPathsDoNotProbe(t *testing.T) {
	baseline := verifiedAuditStorageInspectorForTest(filepath.Join(t.TempDir(), "events.db"), true, true, 1)
	var calls atomic.Uint64
	gate := newAuditStorageGate(baseline, 1, func(string, bool, bool, int64) auditStorageVerification {
		calls.Add(1)
		return baseline
	})
	if status := gate.verification(); status.PersistenceVerified || status.PersistenceReason != auditStorageGateUnarmedReason || calls.Load() != 0 {
		t.Fatalf("unarmed verification status=%#v calls=%d", status, calls.Load())
	}
	if err := gate.access(); err == nil || calls.Load() != 0 {
		t.Fatalf("unarmed access error=%v calls=%d, want fail-closed without cached/baseline admission", err, calls.Load())
	}
	failure := baseline
	failure.PersistenceVerified = false
	failure.PersistenceReason = "read_only"
	gate.latch(failure)
	if status := gate.verification(); status.PersistenceReason != "read_only" || calls.Load() != 0 {
		t.Fatalf("latched verification status=%#v calls=%d", status, calls.Load())
	}
	var nilGate *auditStorageGate
	if status := nilGate.verification(); status.State != "disabled" {
		t.Fatalf("nil gate verification=%#v", status)
	}
}

func TestAuditStorageActivationGateForcesRealtimeProbeFromUnarmedAndCachedStates(t *testing.T) {
	baseline := verifiedAuditStorageInspectorForTest(filepath.Join(t.TempDir(), "events.db"), true, true, 1)
	failure := baseline
	failure.State = "read_only"
	failure.PersistenceVerified = false
	failure.PersistenceReason = "read_only"
	failure.Writable = false

	t.Run("unarmed", func(t *testing.T) {
		var calls atomic.Uint64
		gate := newAuditStorageGate(baseline, 1, func(string, bool, bool, int64) auditStorageVerification {
			calls.Add(1)
			return failure
		})
		if err := gate.activationAccess(); err == nil || calls.Load() != 1 {
			t.Fatalf("unarmed activation error=%v calls=%d, want one forced failing probe", err, calls.Load())
		}
		if err := gate.access(); err == nil {
			t.Fatal("failed activation gate did not latch ordinary storage access")
		}
	})

	t.Run("cached-write-verdict", func(t *testing.T) {
		var calls atomic.Uint64
		var failed atomic.Bool
		gate := newAuditStorageGate(baseline, 1, func(string, bool, bool, int64) auditStorageVerification {
			calls.Add(1)
			if failed.Load() {
				return failure
			}
			return baseline
		})
		gate.arm(baseline)
		if err := gate.access(); err != nil || calls.Load() != 1 {
			t.Fatalf("prime cached write verdict error=%v calls=%d", err, calls.Load())
		}
		failed.Store(true)
		if err := gate.activationAccess(); err == nil || calls.Load() != 2 {
			t.Fatalf("cached activation error=%v calls=%d, want cache-bypassing probe", err, calls.Load())
		}
	})
}

func TestAuditStorageActivationGateRebindsOnlyReleasedPriorStoreSidecars(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "events.db")
	baseline := verifiedAuditStorageInspectorForTest(databasePath, true, true, 1)
	baseline.identity = auditStorageIdentity{
		directory: auditStorageObjectIdentity{present: true, device: 7, inode: 11},
		database:  auditStorageObjectIdentity{present: true, device: 7, inode: 21},
		wal:       auditStorageObjectIdentity{present: true, device: 7, inode: 31},
		shm:       auditStorageObjectIdentity{present: true, device: 7, inode: 41},
		mount:     "42:8:1",
	}
	live := baseline
	live.identity.wal = auditStorageObjectIdentity{}
	live.identity.shm = auditStorageObjectIdentity{}
	gate := newAuditStorageGate(baseline, 1, func(string, bool, bool, int64) auditStorageVerification {
		return live
	})
	gate.authorizePriorStoreSidecarRelease()

	if err := gate.activationAccess(); err != nil {
		t.Fatalf("released prior Store sidecars blocked activation: %v", err)
	}
	gate.mu.Lock()
	normalized := gate.baseline
	pendingRelease := gate.priorStoreSidecarsPendingRelease
	gate.mu.Unlock()
	if normalized.identity.wal.present || normalized.identity.shm.present || pendingRelease {
		t.Fatalf("activation baseline was not normalized after prior Store close: baseline=%#v pending=%t", normalized.identity, pendingRelease)
	}

	live.identity.wal = auditStorageObjectIdentity{present: true, device: 7, inode: 32}
	live.identity.shm = auditStorageObjectIdentity{present: true, device: 7, inode: 42}
	bound, err := gate.bindAfterOpen()
	if err != nil || !bound.PersistenceVerified {
		t.Fatalf("candidate sidecar bind status=%#v error=%v", bound, err)
	}

	live.identity.wal = auditStorageObjectIdentity{present: true, device: 7, inode: 33}
	if err := gate.readAccess(); err == nil || !strings.Contains(err.Error(), "wal_identity_changed") {
		t.Fatalf("post-bind WAL replacement error=%v", err)
	}
}

func TestAuditStorageActivationGatePriorStoreReleaseDoesNotMaskReplacement(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "events.db")
	baseline := verifiedAuditStorageInspectorForTest(databasePath, true, true, 1)
	baseline.identity = auditStorageIdentity{
		directory: auditStorageObjectIdentity{present: true, device: 7, inode: 11},
		database:  auditStorageObjectIdentity{present: true, device: 7, inode: 21},
		wal:       auditStorageObjectIdentity{present: true, device: 7, inode: 31},
		shm:       auditStorageObjectIdentity{present: true, device: 7, inode: 41},
		mount:     "42:8:1",
	}

	for _, test := range []struct {
		name   string
		reason string
		mutate func(*auditStorageVerification)
	}{
		{name: "directory", reason: "directory_identity_changed", mutate: func(status *auditStorageVerification) {
			status.identity.directory.inode++
		}},
		{name: "mount", reason: "mount_identity_changed", mutate: func(status *auditStorageVerification) {
			status.identity.mount = "42:8:2"
		}},
		{name: "database", reason: "database_identity_changed", mutate: func(status *auditStorageVerification) {
			status.identity.database.inode++
		}},
		{name: "wal-replacement", reason: "wal_identity_changed", mutate: func(status *auditStorageVerification) {
			status.identity.wal.inode++
		}},
		{name: "shm-replacement", reason: "shm_identity_changed", mutate: func(status *auditStorageVerification) {
			status.identity.shm.inode++
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			live := baseline
			test.mutate(&live)
			gate := newAuditStorageGate(baseline, 1, func(string, bool, bool, int64) auditStorageVerification {
				return live
			})
			gate.authorizePriorStoreSidecarRelease()
			if err := gate.activationAccess(); err == nil || !strings.Contains(err.Error(), test.reason) {
				t.Fatalf("activation replacement error=%v, want %s", err, test.reason)
			}
		})
	}
}

func TestAuditStoragePriorStoreSidecarReleaseRequiresSuccessfulClose(t *testing.T) {
	databasePath := filepath.Join(t.TempDir(), "events.db")
	baseline := verifiedAuditStorageInspectorForTest(databasePath, true, true, 1)
	baseline.identity = auditStorageIdentity{
		directory: auditStorageObjectIdentity{present: true, device: 7, inode: 11},
		database:  auditStorageObjectIdentity{present: true, device: 7, inode: 21},
		wal:       auditStorageObjectIdentity{present: true, device: 7, inode: 31},
		shm:       auditStorageObjectIdentity{present: true, device: 7, inode: 41},
		mount:     "42:8:1",
	}
	live := baseline
	live.identity.wal = auditStorageObjectIdentity{}
	live.identity.shm = auditStorageObjectIdentity{}
	newGate := func() *auditStorageGate {
		return newAuditStorageGate(baseline, 1, func(string, bool, bool, int64) auditStorageVerification {
			return live
		})
	}

	t.Run("candidate-construction-has-no-release-grant", func(t *testing.T) {
		gate := newGate()
		if err := gate.activationAccess(); err == nil || !strings.Contains(err.Error(), "wal_identity_changed") {
			t.Fatalf("ungranted sidecar disappearance error=%v, want wal_identity_changed", err)
		}
	})

	t.Run("failed-close-latches-candidate", func(t *testing.T) {
		gate := newGate()
		state := &runtimeState{auditStorage: baseline, auditStorageGate: gate}
		state.completePriorAuditStoreClose(true, false, context.DeadlineExceeded)
		status := gate.verification()
		if status.PersistenceVerified || status.PersistenceReason != auditStoragePriorStoreCloseFailedReason ||
			state.auditStorage.PersistenceReason != auditStoragePriorStoreCloseFailedReason {
			t.Fatalf("failed prior close storage state=%#v gate=%#v", state.auditStorage, status)
		}
		if !state.auditStorageActivationDiscardRequired || state.auditStorageNeedsPostActivationCheck {
			t.Fatalf("failed prior close discard=%t postActivation=%t",
				state.auditStorageActivationDiscardRequired, state.auditStorageNeedsPostActivationCheck)
		}
		if err := gate.activationAccess(); err == nil || !strings.Contains(err.Error(), auditStoragePriorStoreCloseFailedReason) {
			t.Fatalf("failed prior close activation error=%v", err)
		}
	})

	t.Run("prelatched-recovery-discard-releases-without-durability", func(t *testing.T) {
		store, err := audit.Open(audit.Config{Path: filepath.Join(t.TempDir(), "prior-events.db")})
		if err != nil {
			t.Fatalf("open prior SQLite Store: %v", err)
		}
		priorGate := newAuditStorageGate(baseline, 1, func(string, bool, bool, int64) auditStorageVerification {
			return baseline
		})
		failedPrior := baseline
		failedPrior.PersistenceVerified = false
		failedPrior.PersistenceReason = "read_only"
		priorGate.latch(failedPrior)
		outcome := (&runtimeState{audit: store, auditStorageGate: priorGate}).close()
		if outcome.err != nil || outcome.durable || !outcome.sidecarsReleased {
			t.Fatalf("pre-latched recovery discard outcome=%#v, want release without durability claim", outcome)
		}

		gate := newGate()
		state := &runtimeState{auditStorage: baseline, auditStorageGate: gate}
		state.completePriorAuditStoreClose(true, outcome.sidecarsReleased, outcome.err)
		if err := gate.activationAccess(); err != nil || state.auditStorageActivationDiscardRequired {
			t.Fatalf("explicit recovery discard did not release prior sidecars: error=%v discard=%t",
				err, state.auditStorageActivationDiscardRequired)
		}
	})

	t.Run("failure-discovered-during-close-cannot-release", func(t *testing.T) {
		store, err := audit.Open(audit.Config{Path: filepath.Join(t.TempDir(), "prior-events.db")})
		if err != nil {
			t.Fatalf("open prior SQLite Store: %v", err)
		}
		failedPrior := baseline
		failedPrior.PersistenceVerified = false
		failedPrior.PersistenceReason = "read_only"
		priorGate := newAuditStorageGate(baseline, 1, func(string, bool, bool, int64) auditStorageVerification {
			return failedPrior
		})
		priorGate.arm(baseline)
		outcome := (&runtimeState{audit: store, auditStorageGate: priorGate}).close()
		if outcome.err != nil || outcome.durable || outcome.sidecarsReleased {
			t.Fatalf("newly failed discard outcome=%#v, want no release grant", outcome)
		}

		gate := newGate()
		state := &runtimeState{auditStorage: baseline, auditStorageGate: gate}
		state.completePriorAuditStoreClose(true, outcome.sidecarsReleased, outcome.err)
		if status := gate.verification(); status.PersistenceReason != auditStoragePriorStoreCloseFailedReason ||
			!state.auditStorageActivationDiscardRequired {
			t.Fatalf("new close failure authorized candidate: storage=%#v discard=%t",
				status, state.auditStorageActivationDiscardRequired)
		}
		if err := gate.activationAccess(); err == nil || !strings.Contains(err.Error(), auditStoragePriorStoreCloseFailedReason) {
			t.Fatalf("new close failure activation error=%v", err)
		}
	})

	t.Run("successful-close-signs-one-release", func(t *testing.T) {
		gate := newGate()
		state := &runtimeState{auditStorage: baseline, auditStorageGate: gate}
		state.completePriorAuditStoreClose(true, true, nil)
		if err := gate.activationAccess(); err != nil {
			t.Fatalf("successfully closed prior Store did not release sidecars: %v", err)
		}
		gate.mu.Lock()
		pending := gate.priorStoreSidecarsPendingRelease
		normalized := gate.baseline.identity
		gate.mu.Unlock()
		if pending || normalized.wal.present || normalized.shm.present || state.auditStorageActivationDiscardRequired {
			t.Fatalf("release was not consumed exactly once: pending=%t identity=%#v discard=%t",
				pending, normalized, state.auditStorageActivationDiscardRequired)
		}
	})

	t.Run("unrelated-close-cannot-authorize-release", func(t *testing.T) {
		gate := newGate()
		state := &runtimeState{auditStorage: baseline, auditStorageGate: gate}
		state.completePriorAuditStoreClose(false, true, nil)
		if err := gate.activationAccess(); err == nil || !strings.Contains(err.Error(), "wal_identity_changed") {
			t.Fatalf("unrelated close authorized sidecar disappearance: %v", err)
		}
	})
}

func TestAuditStorageGateRealSQLiteSidecarHandoff(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("real inode-bound SQLite sidecar handoff is a Linux contract")
	}
	dataDir := t.TempDir()
	databasePath := filepath.Join(dataDir, "events.db")
	const maxBytes = int64(8 << 20)
	event := func(id string) audit.Event {
		return audit.Event{ID: id, Timestamp: time.Now().UTC(), Action: "allow", Mode: "balanced"}
	}

	prior, err := audit.Open(audit.Config{Path: databasePath, MaxBytes: maxBytes})
	if err != nil {
		t.Fatalf("open prior SQLite Store: %v", err)
	}
	if err := prior.Enqueue(event("prior-event")); err != nil {
		t.Fatalf("enqueue prior event: %v", err)
	}
	if err := prior.Flush(context.Background()); err != nil {
		t.Fatalf("flush prior event: %v", err)
	}
	baseline := inspectAuditStorage(databasePath, true, false, maxBytes)
	if !baseline.identity.database.present || !baseline.identity.wal.present || !baseline.identity.shm.present {
		t.Fatalf("prior SQLite identities were incomplete before close: %#v", baseline.identity)
	}
	gate := newAuditStorageGate(baseline, maxBytes, inspectAuditStorage)
	if err := prior.Close(); err != nil {
		t.Fatalf("durably close prior SQLite Store: %v", err)
	}
	afterClose := inspectAuditStorage(databasePath, true, false, maxBytes)
	if afterClose.identity.wal.present || afterClose.identity.shm.present {
		t.Fatalf("prior SQLite sidecars survived last-owner close: %#v", afterClose.identity)
	}

	gate.authorizePriorStoreSidecarRelease()
	if err := gate.activationAccess(); err != nil {
		t.Fatalf("consume successful prior close release: %v", err)
	}
	candidate, err := audit.Open(audit.Config{Path: databasePath, MaxBytes: maxBytes})
	if err != nil {
		t.Fatalf("open candidate SQLite Store: %v", err)
	}
	bound, err := gate.bindAfterOpen()
	if err != nil || !bound.identity.wal.present || !bound.identity.shm.present {
		_ = candidate.Close()
		t.Fatalf("bind candidate SQLite sidecars status=%#v error=%v", bound, err)
	}
	if err := candidate.Enqueue(event("candidate-event")); err != nil {
		_ = candidate.Close()
		t.Fatalf("enqueue candidate event: %v", err)
	}
	if err := candidate.Flush(context.Background()); err != nil {
		_ = candidate.Close()
		t.Fatalf("flush candidate event: %v", err)
	}
	if err := candidate.Close(); err != nil {
		t.Fatalf("close candidate SQLite Store: %v", err)
	}

	reopened, err := audit.Open(audit.Config{Path: databasePath, MaxBytes: maxBytes})
	if err != nil {
		t.Fatalf("reopen handed-off SQLite Store: %v", err)
	}
	defer reopened.Close()
	events, err := reopened.Query(context.Background(), audit.Query{Limit: 10})
	if err != nil {
		t.Fatalf("query handed-off audit events: %v", err)
	}
	seen := map[string]bool{}
	for _, persisted := range events {
		seen[persisted.ID] = true
	}
	if !seen["prior-event"] || !seen["candidate-event"] {
		t.Fatalf("SQLite handoff lost events: seen=%v", seen)
	}
}

func TestRuntimeCloseDoesNotReleaseSidecarsForFinalPersistenceLatch(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := t.TempDir()
	var failProbe atomic.Bool
	p.auditStorageInspect = func(path string, explicit, expected bool, maxBytes int64) auditStorageVerification {
		status := verifiedAuditStorageInspectorForTest(path, explicit, expected, maxBytes)
		if failProbe.Load() {
			status.State = "read_only"
			status.PersistenceVerified = false
			status.PersistenceReason = "read_only"
			status.Writable = false
		}
		return status
	}
	configYAML := "mode: balanced\naudit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(dataDir) + "\"\n" +
		"  require_persistent_storage: true\n  max_db_mb: 8\nsubject_control:\n  enabled: true\n  persistence: true\n"
	register(t, p, configYAML)
	state := p.runtime.Load()
	if state == nil || state.audit == nil || state.persistence == nil || !state.persistence.started.Load() ||
		state.auditStorageGate == nil || state.auditStorageGate.latchedBeforeClose() {
		t.Fatalf("subject-persistent runtime was not ready before close: %#v", state)
	}
	state.auditStorageGate.mu.Lock()
	state.auditStorageGate.nextProbeAt = time.Time{}
	state.auditStorageGate.mu.Unlock()
	failProbe.Store(true)
	outcome := state.close()
	if outcome.err != nil || outcome.durable || outcome.sidecarsReleased {
		t.Fatalf("final persistence latch close outcome=%#v, want newly failed discard without release", outcome)
	}
	if status := state.auditStorageGate.verification(); status.PersistenceReason != "read_only" {
		t.Fatalf("final persistence failure did not latch old gate: %#v", status)
	}
}

func TestRuntimeCloseWorkerDrainFirstLatchCannotReleaseOrRebaseline(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("worker-drain SQLite sidecar lifecycle is a Linux contract")
	}
	databasePath := filepath.Join(t.TempDir(), "events.db")
	const maxBytes = int64(8 << 20)
	baseline := verifiedAuditStorageInspectorForTest(databasePath, true, true, maxBytes)
	baseline.identity = auditStorageIdentity{
		directory: auditStorageObjectIdentity{present: true, device: 7, inode: 11},
		database:  auditStorageObjectIdentity{present: true, device: 7, inode: 21},
		wal:       auditStorageObjectIdentity{present: true, device: 7, inode: 31},
		shm:       auditStorageObjectIdentity{present: true, device: 7, inode: 41},
		mount:     "42:8:1",
	}
	failure := baseline
	failure.State = "identity_changed"
	failure.PersistenceVerified = false
	failure.PersistenceReason = "wal_identity_changed"
	failure.Writable = false
	var failProbe atomic.Bool
	var priorProbeCalls atomic.Int32
	priorGate := newAuditStorageGate(baseline, maxBytes, func(string, bool, bool, int64) auditStorageVerification {
		priorProbeCalls.Add(1)
		if failProbe.Load() {
			return failure
		}
		return baseline
	})
	// Freeze the gate clock so the close-time verification deterministically
	// observes the healthy one-second cache. The worker expires it explicitly
	// only after close has entered its drain boundary.
	fixedNow := time.Unix(1_700_000_000, 0)
	priorGate.mu.Lock()
	priorGate.now = func() time.Time { return fixedNow }
	priorGate.mu.Unlock()
	priorGate.arm(baseline)
	if err := priorGate.access(); err != nil || priorProbeCalls.Load() != 1 {
		t.Fatalf("prime prior storage cache error=%v probes=%d", err, priorProbeCalls.Load())
	}

	workerAtGate := make(chan struct{})
	releaseWorker := make(chan struct{})
	var releaseOnce sync.Once
	var interceptWorker atomic.Bool
	var accessCalls atomic.Int32
	storageAccess := func() error {
		if !interceptWorker.Load() {
			return nil
		}
		switch accessCalls.Add(1) {
		case 1:
			// Admission uses the primed healthy cache.
			return priorGate.access()
		case 2:
			// The writer owns the queued item here. Hold it until runtime close has
			// either published the legacy CloseContext state or queued the new
			// explicit Flush barrier, then make this the first failing live probe.
			close(workerAtGate)
			<-releaseWorker
			failProbe.Store(true)
			priorGate.mu.Lock()
			priorGate.nextProbeAt = time.Time{}
			priorGate.mu.Unlock()
			return priorGate.access()
		default:
			return priorGate.access()
		}
	}

	var store *audit.Store
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseWorker) })
		if store != nil {
			_ = store.Discard()
		}
	})
	var err error
	store, err = audit.Open(audit.Config{
		Path:                     databasePath,
		MaxBytes:                 maxBytes,
		QueueSize:                4,
		CleanupInterval:          time.Hour,
		RequirePersistentStorage: true,
		StorageAccessGate:        storageAccess,
	})
	if err != nil {
		t.Fatalf("open prior SQLite Store: %v", err)
	}
	interceptWorker.Store(true)
	if err := store.Enqueue(audit.Event{
		ID:        "drain-first-latch",
		Timestamp: time.Now().UTC(),
		Action:    "allow",
		Mode:      "balanced",
	}); err != nil {
		t.Fatalf("enqueue drain-first-latch event: %v", err)
	}
	select {
	case <-workerAtGate:
	case <-time.After(5 * time.Second):
		t.Fatal("writer did not reach the drain storage gate")
	}

	outcomeCh := make(chan runtimeCloseOutcome, 1)
	go func() {
		outcomeCh <- (&runtimeState{audit: store, auditStorageGate: priorGate}).close()
	}()
	// Both the vulnerable CloseContext path and the fixed quiesce phase publish
	// Closed before waiting for this in-flight worker. Releasing only after that
	// boundary guarantees the initial cached verdict was already consumed and
	// makes the worker drain the first operation that can latch storage.
	deadline := time.NewTimer(5 * time.Second)
	poll := time.NewTicker(time.Millisecond)
	boundaryReached := false
	for !boundaryReached {
		select {
		case <-poll.C:
			boundaryReached = store.Status().Closed
		case <-deadline.C:
			poll.Stop()
			t.Fatal("runtime close did not publish the terminal admission boundary")
		}
	}
	poll.Stop()
	if !deadline.Stop() {
		select {
		case <-deadline.C:
		default:
		}
	}
	releaseOnce.Do(func() { close(releaseWorker) })

	var outcome runtimeCloseOutcome
	select {
	case outcome = <-outcomeCh:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime close did not finish after releasing the drain gate")
	}
	if outcome.err != nil || outcome.durable || outcome.sidecarsReleased {
		t.Fatalf("drain-first latch close outcome=%#v, want discard without durability or release", outcome)
	}
	if priorProbeCalls.Load() != 2 {
		t.Fatalf("drain-first latch probes=%d, want cache prime plus worker live failure", priorProbeCalls.Load())
	}
	if status := priorGate.verification(); status.PersistenceReason != "wal_identity_changed" {
		t.Fatalf("worker failure did not latch prior gate: %#v", status)
	}

	candidateLive := baseline
	candidateLive.identity.wal = auditStorageObjectIdentity{}
	candidateLive.identity.shm = auditStorageObjectIdentity{}
	var candidateProbeCalls atomic.Int32
	candidateGate := newAuditStorageGate(baseline, maxBytes, func(string, bool, bool, int64) auditStorageVerification {
		candidateProbeCalls.Add(1)
		return candidateLive
	})
	candidate := &runtimeState{
		auditStorage:                         baseline,
		auditStorageGate:                     candidateGate,
		auditStorageNeedsPostActivationCheck: true,
	}
	candidate.completePriorAuditStoreClose(true, outcome.sidecarsReleased, outcome.err)
	candidateGate.mu.Lock()
	pendingRelease := candidateGate.priorStoreSidecarsPendingRelease
	candidateBaseline := candidateGate.baseline.identity
	candidateGate.mu.Unlock()
	if pendingRelease || !reflect.DeepEqual(candidateBaseline, baseline.identity) || candidateProbeCalls.Load() != 0 {
		t.Fatalf("failed drain close rebased candidate: pending=%t baseline=%#v probes=%d",
			pendingRelease, candidateBaseline, candidateProbeCalls.Load())
	}
	if candidate.auditStorage.PersistenceReason != auditStoragePriorStoreCloseFailedReason ||
		!candidate.auditStorageActivationDiscardRequired || candidate.auditStorageNeedsPostActivationCheck {
		t.Fatalf("candidate lifecycle state=%#v discard=%t postActivation=%t",
			candidate.auditStorage, candidate.auditStorageActivationDiscardRequired,
			candidate.auditStorageNeedsPostActivationCheck)
	}
	if err := candidateGate.activationAccess(); err == nil ||
		!strings.Contains(err.Error(), auditStoragePriorStoreCloseFailedReason) {
		t.Fatalf("candidate activation error=%v, want %s", err, auditStoragePriorStoreCloseFailedReason)
	}
}

func TestRuntimeCloseMaintenanceDrainFirstLatchCannotRelease(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("maintenance-drain SQLite sidecar lifecycle is a Linux contract")
	}
	databasePath := filepath.Join(t.TempDir(), "events.db")
	const maxBytes = int64(8 << 20)
	baseline := verifiedAuditStorageInspectorForTest(databasePath, true, true, maxBytes)
	baseline.identity = auditStorageIdentity{
		directory: auditStorageObjectIdentity{present: true, device: 7, inode: 11},
		database:  auditStorageObjectIdentity{present: true, device: 7, inode: 21},
		wal:       auditStorageObjectIdentity{present: true, device: 7, inode: 31},
		shm:       auditStorageObjectIdentity{present: true, device: 7, inode: 41},
		mount:     "42:8:1",
	}
	failure := baseline
	failure.State = "identity_changed"
	failure.PersistenceVerified = false
	failure.PersistenceReason = "mount_identity_changed"
	failure.Writable = false
	var failProbe atomic.Bool
	var probeCalls atomic.Int32
	gate := newAuditStorageGate(baseline, maxBytes, func(string, bool, bool, int64) auditStorageVerification {
		probeCalls.Add(1)
		if failProbe.Load() {
			return failure
		}
		return baseline
	})
	fixedNow := time.Unix(1_700_000_100, 0)
	gate.mu.Lock()
	gate.now = func() time.Time { return fixedNow }
	gate.mu.Unlock()
	gate.arm(baseline)
	if err := gate.access(); err != nil || probeCalls.Load() != 1 {
		t.Fatalf("prime maintenance storage cache error=%v probes=%d", err, probeCalls.Load())
	}

	maintenanceAtGate := make(chan struct{})
	releaseMaintenance := make(chan struct{})
	var releaseOnce sync.Once
	var interceptMaintenance atomic.Bool
	var maintenanceCalls atomic.Int32
	storageAccess := func() error {
		if !interceptMaintenance.Load() {
			return nil
		}
		if maintenanceCalls.Add(1) == 1 {
			close(maintenanceAtGate)
			<-releaseMaintenance
			failProbe.Store(true)
			gate.mu.Lock()
			gate.nextProbeAt = time.Time{}
			gate.mu.Unlock()
		}
		return gate.access()
	}

	var store *audit.Store
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(releaseMaintenance) })
		if store != nil {
			_ = store.Discard()
		}
	})
	var err error
	store, err = audit.Open(audit.Config{
		Path:                     databasePath,
		MaxBytes:                 maxBytes,
		QueueSize:                4,
		CleanupInterval:          time.Millisecond,
		RequirePersistentStorage: true,
		StorageAccessGate:        storageAccess,
	})
	if err != nil {
		t.Fatalf("open prior SQLite Store: %v", err)
	}
	interceptMaintenance.Store(true)
	select {
	case <-maintenanceAtGate:
	case <-time.After(5 * time.Second):
		t.Fatal("maintenance ticker did not reach the storage gate")
	}

	outcomeCh := make(chan runtimeCloseOutcome, 1)
	go func() {
		outcomeCh <- (&runtimeState{audit: store, auditStorageGate: gate}).close()
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !store.Status().Closed && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if !store.Status().Closed {
		t.Fatal("runtime close did not stop admission before draining maintenance")
	}
	select {
	case outcome := <-outcomeCh:
		t.Fatalf("runtime close returned before maintenance drain release: %#v", outcome)
	default:
	}
	releaseOnce.Do(func() { close(releaseMaintenance) })

	var outcome runtimeCloseOutcome
	select {
	case outcome = <-outcomeCh:
	case <-time.After(5 * time.Second):
		t.Fatal("runtime close did not finish after maintenance drain release")
	}
	if outcome.err != nil || outcome.durable || outcome.sidecarsReleased {
		t.Fatalf("maintenance-first latch close outcome=%#v, want discard without durability or release", outcome)
	}
	if maintenanceCalls.Load() != 1 || probeCalls.Load() != 2 {
		t.Fatalf("maintenance calls=%d probes=%d, want one tick and its first live failure",
			maintenanceCalls.Load(), probeCalls.Load())
	}
	if status := gate.verification(); status.PersistenceReason != "mount_identity_changed" {
		t.Fatalf("maintenance failure did not latch prior gate: %#v", status)
	}
}

func TestSamePathHotReconfigureRebindsSidecarsOwnedByPreviousStore(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := t.TempDir()
	databasePath := filepath.Join(dataDir, "events.db")
	live := verifiedAuditStorageInspectorForTest(databasePath, true, true, 8<<20)
	live.identity = auditStorageIdentity{
		directory: auditStorageObjectIdentity{present: true, device: 7, inode: 11},
		database:  auditStorageObjectIdentity{present: true, device: 7, inode: 21},
		wal:       auditStorageObjectIdentity{present: true, device: 7, inode: 31},
		shm:       auditStorageObjectIdentity{present: true, device: 7, inode: 41},
		mount:     "42:8:1",
	}
	var liveMu sync.RWMutex
	p.auditStorageInspect = func(path string, explicit, expected bool, _ int64) auditStorageVerification {
		liveMu.RLock()
		status := live
		liveMu.RUnlock()
		status.DatabasePath = path
		status.PersistenceExpected = expected
		if explicit {
			status.PathSource = "explicit"
		}
		return status
	}
	var reconfiguring atomic.Bool
	p.auditActivationHook = func(stage auditActivationStage) {
		if !reconfiguring.Load() {
			return
		}
		liveMu.Lock()
		defer liveMu.Unlock()
		switch stage {
		case auditActivationAfterPriorCloseBeforeOpen:
			live.identity.wal = auditStorageObjectIdentity{}
			live.identity.shm = auditStorageObjectIdentity{}
		case auditActivationAfterOpenBeforeBind:
			live.identity.wal = auditStorageObjectIdentity{present: true, device: 7, inode: 32}
			live.identity.shm = auditStorageObjectIdentity{present: true, device: 7, inode: 42}
		}
	}
	configYAML := "mode: balanced\naudit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(dataDir) + "\"\n" +
		"  require_persistent_storage: true\n  max_db_mb: 8\nsubject_control:\n  enabled: false\n"
	register(t, p, configYAML)
	previous := p.runtime.Load()
	if previous == nil || previous.audit == nil || !previous.audit.IsActive() {
		t.Fatalf("initial audit Store is not active: %#v", previous)
	}

	reconfiguring.Store(true)
	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t, configYAML))
	if code != 0 {
		t.Fatalf("same-path reconfigure code=%d envelope=%s", code, raw)
	}
	decodeOKResult(t, raw, &map[string]any{})
	state := p.runtime.Load()
	if state == nil || state == previous || state.audit == nil || !state.audit.IsActive() || !state.audit.DatabaseAvailable() {
		t.Fatalf("same-path reconfigure did not publish an active replacement: old=%p new=%#v", previous, state)
	}
	storage := state.currentAuditStorageVerification()
	if state.audit.Status().Degraded || !storage.PersistenceVerified || storage.PersistenceReason != "" {
		t.Fatalf("same-path reconfigure audit=%#v storage=%#v", state.audit.Status(), storage)
	}
	if message := p.lastReconfigureErrorMessage(); message != "" {
		t.Fatalf("same-path reconfigure retained error=%q", message)
	}
}

func TestAuditStorageSensitiveReadGateIsIndependentFromWriteCache(t *testing.T) {
	baseline := verifiedAuditStorageInspectorForTest(filepath.Join(t.TempDir(), "events.db"), true, true, 1)
	failure := baseline
	failure.State = "identity_changed"
	failure.PersistenceVerified = false
	failure.PersistenceReason = "database_identity_changed"
	var calls atomic.Uint64
	var replaced atomic.Bool
	gate := newAuditStorageGate(baseline, 1, func(string, bool, bool, int64) auditStorageVerification {
		calls.Add(1)
		if replaced.Load() {
			return failure
		}
		return baseline
	})
	gate.arm(baseline)
	if err := gate.access(); err != nil || calls.Load() != 1 {
		t.Fatalf("prime write cache error=%v calls=%d", err, calls.Load())
	}
	replaced.Store(true)
	if err := gate.readAccess(); err == nil || calls.Load() != 2 {
		t.Fatalf("sensitive read error=%v calls=%d, want independent realtime probe", err, calls.Load())
	}
	if err := gate.access(); err == nil {
		t.Fatal("sensitive read identity failure did not latch later writes")
	}
}

func TestRequiredUnverifiedStorageNeverOpensSQLiteOrSubjectPersistence(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	tests := []struct {
		name        string
		storageType string
		state       string
		reason      string
		capacityOK  bool
	}{
		{name: "tmpfs", storageType: "tmpfs", state: "ephemeral", reason: "ephemeral_filesystem", capacityOK: true},
		{name: "overlay", storageType: "overlay", state: "container_layer", reason: "container_layer", capacityOK: true},
		{name: "insufficient capacity", storageType: "ext4", state: "insufficient_capacity", reason: "insufficient_capacity"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			p := New()
			dataDir := t.TempDir()
			databasePath := filepath.Join(dataDir, "events.db")
			p.auditStorageInspect = func(path string, explicit, expected bool, _ int64) auditStorageVerification {
				return auditStorageVerification{
					StorageType:         test.storageType,
					State:               test.state,
					PathSource:          "explicit",
					DatabasePath:        path,
					PersistenceExpected: expected,
					PersistenceReason:   test.reason,
					SeparateMount:       true,
					Writable:            true,
					CapacityOK:          test.capacityOK,
				}
			}
			configYAML := "mode: balanced\naudit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(dataDir) + "\"\n" +
				"  require_persistent_storage: true\n  raw_capture:\n    enabled: true\n" +
				"subject_control:\n  enabled: true\n  persistence: true\n"
			register(t, p, configYAML)

			state := p.runtime.Load()
			if state == nil || state.audit != nil {
				t.Fatalf("required unverified audit runtime=%#v", state)
			}
			persistence := state.persistence.status()
			if !persistence.Enabled || !persistence.Degraded || !persistence.WritesBlocked || persistence.Restored != 0 || persistence.SuccessfulSaves != 0 {
				t.Fatalf("unverified subject persistence=%#v", persistence)
			}
			if route := callRoute(t, p, maliciousRequest); !route.Handled {
				t.Fatalf("storage degradation weakened enforcement: %+v", route)
			}
			state.saveSubjectPersistence(p)

			status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
			if status["audit_degraded"] != true || status["persistence_degraded"] != true || status["operational_ready"] != false {
				t.Fatalf("unverified storage status=%#v", status)
			}
			auditStatus, ok := status["audit"].(map[string]any)
			if !ok || auditStatus["persistence_reason"] != test.reason || auditStatus["persistence_verified"] != false || auditStatus["degraded"] != true {
				t.Fatalf("unverified audit status=%#v", status["audit"])
			}
			for _, want := range []string{"audit_runtime_degraded", "audit_persistence_unverified", "subject_persistence_degraded"} {
				if !containsReadinessReason(status["readiness_reasons"], want) {
					t.Fatalf("readiness reasons=%#v, missing %q", status["readiness_reasons"], want)
				}
			}

			p.Shutdown()
			if _, err := os.Lstat(databasePath); !os.IsNotExist(err) {
				t.Fatalf("required unverified storage created SQLite artifact: %v", err)
			}
		})
	}
}

func TestRequiredSymlinkStorageNeverOpensSQLiteTarget(t *testing.T) {
	root := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(root, "audit-link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	p := New()
	p.auditStorageInspect = inspectAuditStorage
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(link)+"\"\n  require_persistent_storage: true\nsubject_control:\n  enabled: false\n")
	state := p.runtime.Load()
	if state.auditStorage.PersistenceReason != "symlinked_directory" || state.audit != nil {
		t.Fatalf("required symlink storage=%#v audit=%#v", state.auditStorage, state.audit)
	}
	p.Shutdown()
	if _, err := os.Lstat(filepath.Join(target, "events.db")); !os.IsNotExist(err) {
		t.Fatalf("SQLite opened through symlinked data directory: %v", err)
	}
}

func TestRequiredMissingStorageDirectoryIsNotCreated(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "operator-volume", "audit")
	p := New()
	p.auditStorageInspect = inspectAuditStorage
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(dataDir)+"\"\n  require_persistent_storage: true\nsubject_control:\n  enabled: false\n")
	state := p.runtime.Load()
	if state == nil || state.audit != nil || state.auditStorage.PersistenceReason != "path_resolution_failed" {
		t.Fatalf("missing required storage runtime=%#v", state)
	}
	p.Shutdown()
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		t.Fatalf("plugin created an operator-owned required volume path: %v", err)
	}
}

func TestRequiredStorageReconfigureRecoversAfterVerifiedVolumeAppears(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := t.TempDir()
	databasePath := filepath.Join(dataDir, "events.db")
	var verified atomic.Bool
	p.auditStorageInspect = func(path string, explicit, expected bool, maxBytes int64) auditStorageVerification {
		if verified.Load() {
			return verifiedAuditStorageInspectorForTest(path, explicit, expected, maxBytes)
		}
		return auditStorageVerification{
			StorageType:         "overlay",
			State:               "container_layer",
			PathSource:          "explicit",
			DatabasePath:        path,
			PersistenceExpected: expected,
			PersistenceReason:   "container_layer",
			Writable:            true,
			CapacityOK:          true,
		}
	}
	configYAML := "mode: balanced\naudit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(dataDir) + "\"\n" +
		"  require_persistent_storage: true\nsubject_control:\n  enabled: false\n"
	register(t, p, configYAML)
	if _, err := os.Lstat(databasePath); !os.IsNotExist(err) {
		t.Fatalf("unverified startup created SQLite artifact: %v", err)
	}

	verified.Store(true)
	raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t, configYAML))
	if code != 0 {
		t.Fatalf("verified-volume reconfigure code=%d envelope=%s", code, raw)
	}
	decodeOKResult(t, raw, &map[string]any{})
	state := p.runtime.Load()
	if state == nil || state.audit == nil {
		t.Fatalf("verified-volume runtime was not published: %#v", state)
	}
	if state.audit.Status().Degraded || !state.auditStorage.PersistenceVerified {
		t.Fatalf("verified-volume runtime audit=%#v storage=%#v", state.audit.Status(), state.auditStorage)
	}
	if _, err := os.Stat(databasePath); err != nil {
		t.Fatalf("verified-volume SQLite database missing: %v", err)
	}
	if route := callRoute(t, p, maliciousRequest); !route.Handled {
		t.Fatalf("verified-volume runtime did not enforce: %+v", route)
	}
	events := managementJSON(t, p, http.MethodGet, managementBasePath+"/events", nil)
	if rows, ok := events["events"].([]any); !ok || len(rows) == 0 {
		t.Fatalf("verified-volume audit rows=%#v", events)
	}
	status := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	if status["audit_degraded"] != false || status["operational_ready"] != true {
		t.Fatalf("verified-volume status=%#v", status)
	}

	verified.Store(false)
	forceAuditStorageGateReprobeForTest(state.auditStorageGate)
	status = managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	if status["audit_degraded"] != true || status["operational_ready"] != false {
		t.Fatalf("live storage failure status=%#v", status)
	}
	verified.Store(true)
	status = managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	if status["audit_degraded"] != true || status["operational_ready"] != false {
		t.Fatalf("latched storage recovered without reconfigure: %#v", status)
	}
	raw, code = p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t, configYAML))
	if code != 0 {
		t.Fatalf("recovery reconfigure code=%d envelope=%s", code, raw)
	}
	decodeOKResult(t, raw, &map[string]any{})
	status = managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	if status["audit_degraded"] != false || status["operational_ready"] != true {
		t.Fatalf("explicit reconfigure did not recover storage: %#v", status)
	}
}

func TestPostOpenStorageIdentityReplacementDiscardsStoreBeforePublication(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := t.TempDir()
	var calls atomic.Uint64
	p.auditStorageInspect = func(path string, explicit, expected bool, _ int64) auditStorageVerification {
		call := calls.Add(1)
		inode := uint64(101)
		if call >= 2 {
			inode = 202
		}
		return auditStorageVerification{
			StorageType:         "ext4",
			State:               "persistent_candidate",
			PathSource:          "explicit",
			DatabasePath:        path,
			PersistenceExpected: expected,
			PersistenceVerified: true,
			SeparateMount:       true,
			Writable:            true,
			CapacityOK:          true,
			identity: auditStorageIdentity{
				directory: auditStorageObjectIdentity{present: true, device: 7, inode: inode},
				mount:     "42:8:1",
			},
		}
	}
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(dataDir)+"\"\n  require_persistent_storage: true\nsubject_control:\n  enabled: false\n")
	state := p.runtime.Load()
	if state == nil || state.audit != nil {
		t.Fatalf("post-open replacement published Store: %#v", state)
	}
	if state.auditStorage.PersistenceReason != "directory_identity_changed" || state.auditStorage.PersistenceVerified {
		t.Fatalf("post-open replacement status=%#v", state.auditStorage)
	}
	if calls.Load() < 2 {
		t.Fatalf("storage inspector calls=%d, want pre- and post-open verification", calls.Load())
	}
}

func TestRawCapturePostOpenStorageBlockPublishesDiscardedErrorState(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := t.TempDir()
	var calls atomic.Uint64
	p.auditStorageInspect = func(path string, explicit, expected bool, _ int64) auditStorageVerification {
		call := calls.Add(1)
		inode := uint64(401)
		if call >= 2 {
			inode = 402
		}
		return auditStorageVerification{
			StorageType:         "ext4",
			State:               "persistent_candidate",
			PathSource:          "explicit",
			DatabasePath:        path,
			PersistenceExpected: expected,
			PersistenceVerified: true,
			SeparateMount:       true,
			Writable:            true,
			CapacityOK:          true,
			identity: auditStorageIdentity{
				directory: auditStorageObjectIdentity{present: true, device: 7, inode: inode},
				mount:     "42:8:1",
			},
		}
	}
	register(t, p, "mode: balanced\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(dataDir)+"\"\n  require_persistent_storage: true\n  raw_capture:\n    enabled: true\n    only_blocked: true\n    redact_secrets: true\nsubject_control:\n  enabled: false\n")

	state := p.runtime.Load()
	if state == nil || state.audit == nil {
		t.Fatalf("storage-blocked raw-capture runtime lost its audit error state: %#v", state)
	}
	status := state.audit.Status()
	if !status.Closed || !status.Degraded || !strings.Contains(status.LastError, audit.ErrStorageBlocked.Error()) {
		t.Fatalf("discarded storage-blocked audit status=%#v", status)
	}
	if state.audit.IsActive() || state.audit.DatabaseAvailable() {
		t.Fatalf("discarded audit remained active=%t available=%t", state.audit.IsActive(), state.audit.DatabaseAvailable())
	}
	management := managementJSON(t, p, http.MethodGet, managementBasePath+"/status", nil)
	if management["audit_degraded"] != true || management["operational_ready"] != false {
		t.Fatalf("storage-blocked management status=%#v", management)
	}
}

func TestDevelopmentPostOpenUnsafeIdentityReplacementAlsoDiscardsStore(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := t.TempDir()
	var calls atomic.Uint64
	p.auditStorageInspect = func(path string, explicit, expected bool, _ int64) auditStorageVerification {
		call := calls.Add(1)
		inode := uint64(301)
		if call >= 2 {
			inode = 302
		}
		return auditStorageVerification{
			StorageType:         "ext4",
			State:               "persistent_candidate",
			PathSource:          "explicit",
			DatabasePath:        path,
			PersistenceExpected: expected,
			PersistenceVerified: true,
			SeparateMount:       true,
			Writable:            true,
			CapacityOK:          true,
			identity: auditStorageIdentity{
				directory: auditStorageObjectIdentity{present: true, device: 7, inode: inode},
				mount:     "42:8:1",
			},
		}
	}
	register(t, p, "mode: observe\naudit:\n  enabled: true\n  data_dir: \""+filepath.ToSlash(dataDir)+"\"\nsubject_control:\n  enabled: false\n")
	state := p.runtime.Load()
	if state == nil || state.audit != nil || state.auditStorage.PersistenceReason != "directory_identity_changed" {
		t.Fatalf("development unsafe post-open replacement was published: %#v", state)
	}
}

func TestRuntimeStorageFailureLatchesAllPersistenceWritesUntilReconfigure(t *testing.T) {
	t.Setenv(subject.HMACKeyEnvironment, "0123456789abcdef0123456789abcdef")
	for _, failure := range []auditStorageVerification{
		{
			StorageType:       "ext4",
			State:             "read_only",
			PersistenceReason: "read_only",
			SeparateMount:     true,
			CapacityOK:        true,
		},
		{
			StorageType:       "ext4",
			State:             "insufficient_capacity",
			PersistenceReason: "insufficient_capacity",
			SeparateMount:     true,
			Writable:          true,
		},
	} {
		failure := failure
		t.Run(failure.PersistenceReason, func(t *testing.T) {
			p := New()
			t.Cleanup(p.Shutdown)
			dataDir := t.TempDir()
			databasePath := filepath.Join(dataDir, "events.db")
			live := verifiedAuditStorageInspectorForTest(databasePath, true, true, 1)
			var liveMu sync.RWMutex
			p.auditStorageInspect = func(path string, explicit, expected bool, _ int64) auditStorageVerification {
				liveMu.RLock()
				status := live
				liveMu.RUnlock()
				status.DatabasePath = path
				status.PersistenceExpected = expected
				if explicit {
					status.PathSource = "explicit"
				}
				return status
			}
			configYAML := "mode: balanced\naudit:\n  enabled: true\n  data_dir: \"" + filepath.ToSlash(dataDir) + "\"\n" +
				"  require_persistent_storage: true\n  raw_capture:\n    enabled: true\n" +
				"subject_control:\n  enabled: true\n  persistence: true\n"
			register(t, p, configYAML)
			state := p.runtime.Load()
			if state == nil || state.audit == nil || state.persistence == nil {
				t.Fatalf("verified runtime=%#v", state)
			}

			failure.DatabasePath = databasePath
			failure.PathSource = "explicit"
			failure.PersistenceExpected = true
			liveMu.Lock()
			live = failure
			liveMu.Unlock()
			forceAuditStorageGateReprobeForTest(state.auditStorageGate)

			before := state.audit.Status()
			if route := callRoute(t, p, maliciousRequest); !route.Handled {
				t.Fatalf("storage failure weakened enforcement: %+v", route)
			}
			after := state.audit.Status()
			if after.Rejected < before.Rejected+2 || after.RawCaptureRejected < before.RawCaptureRejected+1 || after.Written != before.Written {
				t.Fatalf("valid event/Raw Capture was not synchronously blocked: before=%#v after=%#v", before, after)
			}
			if err := state.audit.Enqueue(audit.Event{}); !errors.Is(err, audit.ErrStorageBlocked) {
				t.Fatalf("audit event gate error=%v", err)
			}
			if err := state.audit.RecordRawCapture(audit.RawCaptureInput{}); !errors.Is(err, audit.ErrStorageBlocked) {
				t.Fatalf("Raw Capture gate error=%v", err)
			}
			if _, _, err := state.audit.LoadSubjectSnapshot(context.Background(), state.persistence.keyID); !errors.Is(err, audit.ErrStorageBlocked) {
				t.Fatalf("subject restore gate error=%v", err)
			}
			snapshot, exportErr := state.subject.ExportPersistent(state.persistence.keyID)
			if exportErr != nil {
				t.Fatalf("export valid subject snapshot: %v", exportErr)
			}
			if err := state.audit.SaveSubjectSnapshot(context.Background(), snapshot); !errors.Is(err, audit.ErrStorageBlocked) {
				t.Fatalf("subject save gate error=%v", err)
			}
			state.saveSubjectPersistence(p)
			if persistence := state.persistence.status(); !persistence.WritesBlocked || !persistence.Degraded {
				t.Fatalf("latched subject persistence=%#v", persistence)
			}

			liveMu.Lock()
			live = verifiedAuditStorageInspectorForTest(databasePath, true, true, 1)
			liveMu.Unlock()
			if err := state.audit.Enqueue(audit.Event{}); !errors.Is(err, audit.ErrStorageBlocked) {
				t.Fatalf("latched gate auto-recovered: %v", err)
			}

			raw, code := p.Call(pluginabi.MethodPluginReconfigure, lifecyclePayload(t, configYAML))
			if code != 0 {
				t.Fatalf("reconfigure code=%d envelope=%s", code, raw)
			}
			decodeOKResult(t, raw, &map[string]any{})
			recovered := p.runtime.Load()
			if recovered == nil || recovered == state || recovered.audit == nil {
				t.Fatalf("reconfigure did not replace runtime: old=%p new=%p", state, recovered)
			}
			if err := recovered.audit.Enqueue(audit.Event{}); !errors.Is(err, audit.ErrInvalidEvent) {
				t.Fatalf("fresh runtime remained storage-blocked: %v", err)
			}
		})
	}
}

func containsReadinessReason(value any, want string) bool {
	reasons, ok := value.([]any)
	if !ok {
		return false
	}
	for _, reason := range reasons {
		if reason == want {
			return true
		}
	}
	return false
}

func TestRequiredAuditStorageRejectsRelativeDatabasePath(t *testing.T) {
	t.Parallel()
	status := inspectAuditStorage(filepath.Join("relative", "events.db"), true, true, 1)
	if status.PersistenceReason != "path_not_absolute" || status.PersistenceVerified || !status.preventsDatabaseOpen() {
		t.Fatalf("relative required storage verification=%#v", status)
	}
}

func TestAuditPersistenceExpectationMatchesDurabilityDependencies(t *testing.T) {
	t.Parallel()
	base := config.Default()
	base.Mode = config.ModeObserve
	if auditPersistenceExpected(base) {
		t.Fatal("observe-only default unexpectedly requires persistence")
	}

	for name, mutate := range map[string]func(*config.Config){
		"explicit":      func(*config.Config) {},
		"raw-capture":   func(cfg *config.Config) { cfg.Audit.RawCapture.Enabled = true },
		"subject-state": func(cfg *config.Config) { cfg.SubjectControl.Persistence = true },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := base
			mutate(&cfg)
			if auditPersistenceExpected(cfg) {
				t.Fatal("feature implicitly enabled the production persistence contract")
			}
			cfg.Audit.RequirePersistentStorage = true
			if !auditPersistenceExpected(cfg) {
				t.Fatal("explicit persistence contract was not honored")
			}
		})
	}

	for _, mode := range []config.Mode{config.ModeAudit, config.ModeBalanced, config.ModeStrict} {
		cfg := base
		cfg.Mode = mode
		if auditPersistenceExpected(cfg) {
			t.Fatalf("mode %q silently enabled the explicit persistence contract", mode)
		}
	}
}

func TestRequiredAuditStoragePolicyPreventsEveryUnverifiedOpen(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		status auditStorageVerification
	}{
		{name: "tmpfs", status: auditStorageVerification{StorageType: "tmpfs", State: "ephemeral", PersistenceReason: "ephemeral_filesystem"}},
		{name: "overlay", status: auditStorageVerification{StorageType: "overlay", State: "container_layer", PersistenceReason: "container_layer"}},
		{name: "read only", status: auditStorageVerification{StorageType: "ext4", State: "read_only", PersistenceReason: "read_only"}},
		{name: "insufficient capacity", status: auditStorageVerification{StorageType: "ext4", State: "insufficient_capacity", PersistenceReason: "insufficient_capacity"}},
		{name: "unknown mount", status: auditStorageVerification{StorageType: "unknown", State: "unverified", PersistenceReason: "filesystem_not_allowlisted"}},
		{name: "relative path", status: auditStorageVerification{State: "unverified", PersistenceReason: "path_not_absolute"}},
		{name: "symlink", status: auditStorageVerification{State: "unsafe", PersistenceReason: "symlinked_directory"}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			test.status.PersistenceExpected = true
			if !test.status.preventsDatabaseOpen() {
				t.Fatalf("required unverified storage could open SQLite: %#v", test.status)
			}
		})
	}

	development := auditStorageVerification{
		StorageType:       "overlay",
		State:             "container_layer",
		PersistenceReason: "container_layer",
	}
	if development.preventsDatabaseOpen() {
		t.Fatalf("default-off development audit storage was rejected: %#v", development)
	}
}

func forceAuditStorageGateReprobeForTest(gate *auditStorageGate) {
	if gate == nil {
		return
	}
	gate.mu.Lock()
	gate.nextProbeAt = time.Time{}
	gate.mu.Unlock()
}

func verifiedAuditStorageInspectorForTest(
	databasePath string,
	explicit bool,
	expected bool,
	_ int64,
) auditStorageVerification {
	pathSource := "default_home"
	if explicit {
		pathSource = "explicit"
	}
	return auditStorageVerification{
		StorageType:         "ext4",
		State:               "persistent_candidate",
		PathSource:          pathSource,
		DatabasePath:        databasePath,
		PersistenceExpected: expected,
		PersistenceVerified: true,
		SeparateMount:       true,
		Writable:            true,
		CapacityOK:          true,
	}
}
