package plugin

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

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
			auditStatus := status["audit"].(map[string]any)
			if auditStatus["persistence_reason"] != test.reason || auditStatus["persistence_verified"] != false || auditStatus["degraded"] != true {
				t.Fatalf("unverified audit status=%#v", auditStatus)
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
	if state == nil || state.audit == nil || state.audit.Status().Degraded || !state.auditStorage.PersistenceVerified {
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
			if recovered == state || recovered.audit == nil {
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
