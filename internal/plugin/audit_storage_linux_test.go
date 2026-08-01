//go:build linux

package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAuditMountInfoChoosesDeepestMountAndPreservesReadOnly(t *testing.T) {
	t.Parallel()
	raw := []byte("36 25 0:32 / / rw,relatime - overlay overlay rw,lowerdir=/lower\n" +
		"42 36 8:1 /srv/cag /plugin-data/cyber-abuse-guard rw,nosuid,nodev - ext4 /dev/vdb1 rw,errors=remount-ro\n" +
		"43 42 8:1 /readonly /plugin-data/cyber-abuse-guard/readonly ro,nosuid - ext4 /dev/vdb1 ro\n")

	mount, ok := parseAuditMountInfo(raw, "/plugin-data/cyber-abuse-guard/events.db")
	if !ok || mount.mountPoint != "/plugin-data/cyber-abuse-guard" || mount.fsType != "ext4" || mount.readOnly || mount.identity != "42:8:1" {
		t.Fatalf("writable mount=%#v ok=%v", mount, ok)
	}
	mount, ok = parseAuditMountInfo(raw, "/plugin-data/cyber-abuse-guard/readonly/events.db")
	if !ok || mount.mountPoint != "/plugin-data/cyber-abuse-guard/readonly" || !mount.readOnly {
		t.Fatalf("read-only mount=%#v ok=%v", mount, ok)
	}
}

func TestParseAuditMountInfoLaterDuplicateMountOverridesEarlierEntry(t *testing.T) {
	t.Parallel()
	raw := []byte("36 25 0:32 / / rw,relatime - overlay overlay rw,lowerdir=/lower\n" +
		"42 36 0:32 /volume /plugin-data/cyber-abuse-guard rw,nosuid,nodev - overlay overlay rw\n" +
		"43 36 8:1 /srv/cag /plugin-data/cyber-abuse-guard rw,nosuid,nodev - ext4 /dev/vdb1 rw,errors=remount-ro\n")

	mount, ok := parseAuditMountInfo(raw, "/plugin-data/cyber-abuse-guard/events.db")
	if !ok || mount.mountPoint != "/plugin-data/cyber-abuse-guard" || mount.fsType != "ext4" || mount.identity != "43:8:1" {
		t.Fatalf("duplicate mount=%#v ok=%v", mount, ok)
	}
}

func TestParseAuditMountInfoDecodesEscapedMountPoint(t *testing.T) {
	t.Parallel()
	raw := []byte("42 36 8:1 /srv/cag /plugin-data/cyber\\040guard rw - xfs /dev/vdb1 rw\n")
	mount, ok := parseAuditMountInfo(raw, "/plugin-data/cyber guard/events.db")
	if !ok || mount.mountPoint != "/plugin-data/cyber guard" || mount.fsType != "xfs" {
		t.Fatalf("escaped mount=%#v ok=%v", mount, ok)
	}
}

func TestUnescapeAuditMountFieldDoesNotDecodeEscapedEscapeTwice(t *testing.T) {
	t.Parallel()
	if got := unescapeAuditMountField(`/plugin-data/literal\134040name`); got != `/plugin-data/literal\040name` {
		t.Fatalf("unescapeAuditMountField()=%q", got)
	}
}

func TestAuditStorageFilesystemClassification(t *testing.T) {
	t.Parallel()
	for _, value := range []string{"ext4", "xfs", "btrfs", "zfs"} {
		if !persistentAuditFilesystem(value) {
			t.Fatalf("persistent filesystem %q rejected", value)
		}
		if boundedAuditFilesystemType(value) != value {
			t.Fatalf("bounded filesystem type %q rejected", value)
		}
	}
	for _, value := range []string{"tmpfs", "ramfs", "overlay", "proc", "unknown"} {
		if persistentAuditFilesystem(value) {
			t.Fatalf("ephemeral or unverified filesystem %q accepted", value)
		}
	}
}

func TestFinalizeAuditStoragePlatformRejectsUnverifiedLocations(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		status   auditStorageVerification
		state    string
		reason   string
		verified bool
	}{
		{name: "tmpfs", status: auditStorageVerification{StorageType: "tmpfs", Writable: true, CapacityOK: true, SeparateMount: true}, state: "ephemeral", reason: "ephemeral_filesystem"},
		{name: "ramfs", status: auditStorageVerification{StorageType: "ramfs", Writable: true, CapacityOK: true, SeparateMount: true}, state: "ephemeral", reason: "ephemeral_filesystem"},
		{name: "overlay", status: auditStorageVerification{StorageType: "overlay", Writable: true, CapacityOK: true, SeparateMount: true}, state: "container_layer", reason: "container_layer"},
		{name: "read-only", status: auditStorageVerification{StorageType: "ext4", Writable: false, CapacityOK: true, SeparateMount: true}, state: "read_only", reason: "read_only"},
		{name: "insufficient-capacity", status: auditStorageVerification{StorageType: "ext4", Writable: true, CapacityOK: false, SeparateMount: true}, state: "insufficient_capacity", reason: "insufficient_capacity"},
		{name: "root-mount", status: auditStorageVerification{StorageType: "ext4", Writable: true, CapacityOK: true}, state: "unverified", reason: "not_separate_mount"},
		{name: "unknown", status: auditStorageVerification{StorageType: "nfs", Writable: true, CapacityOK: true, SeparateMount: true}, state: "unverified", reason: "filesystem_not_allowlisted"},
		{name: "verified-bind", status: auditStorageVerification{StorageType: "ext4", Writable: true, CapacityOK: true, SeparateMount: true}, state: "persistent_candidate", verified: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := finalizeAuditStoragePlatform(test.status)
			if got.State != test.state || got.PersistenceReason != test.reason || got.PersistenceVerified != test.verified {
				t.Fatalf("finalizeAuditStoragePlatform()=%#v", got)
			}
		})
	}
}

func TestReconcileAuditStorageFilesystemCrossChecksMountAndDescriptor(t *testing.T) {
	t.Parallel()
	base := auditStorageVerification{
		PersistenceExpected: true,
		Writable:            true,
		CapacityOK:          true,
	}
	volume := auditMountInfo{
		mountPoint: "/plugin-data/cyber-abuse-guard",
		fsType:     "ext4",
		identity:   "43:8:1",
	}
	status, consistent := reconcileAuditStorageFilesystem(base, volume, true, 0xef53)
	if !consistent {
		t.Fatalf("matching bind/volume was rejected: %#v", status)
	}
	status = finalizeAuditStoragePlatform(status)
	if !status.PersistenceVerified || status.PersistenceReason != "" || status.StorageType != "ext4" || !status.SeparateMount {
		t.Fatalf("matching bind/volume status=%#v", status)
	}

	mismatch := volume
	mismatch.fsType = "overlay"
	status, consistent = reconcileAuditStorageFilesystem(base, mismatch, true, 0xef53)
	if consistent || status.State != "unverified" || status.PersistenceReason != "filesystem_type_mismatch" ||
		status.StorageType != "unknown" || status.PersistenceVerified || !status.blocksOperationalReadiness() {
		t.Fatalf("filesystem mismatch status=%#v consistent=%v", status, consistent)
	}

	development := base
	development.PersistenceExpected = false
	status, consistent = reconcileAuditStorageFilesystem(development, mismatch, true, 0xef53)
	if consistent || !status.preventsDatabaseOpen() {
		t.Fatalf("development mismatch did not fail closed: %#v consistent=%v", status, consistent)
	}
}

func TestAuditStorageFilesystemTypeAgreementAllowsKernelAliases(t *testing.T) {
	t.Parallel()
	tests := []struct {
		mountType string
		magic     int64
	}{
		{mountType: "ext2", magic: 0xef53},
		{mountType: "ext3", magic: 0xef53},
		{mountType: "ext4", magic: 0xef53},
		{mountType: "overlayfs", magic: auditStorageOverlayMagic},
		{mountType: "zfs", magic: auditStorageZFSMagic},
	}
	for _, test := range tests {
		if magicType := auditFilesystemTypeFromMagic(test.magic); !auditStorageFilesystemTypesMatch(test.mountType, magicType) {
			t.Errorf("mount type %q did not match statfs type %q", test.mountType, magicType)
		}
	}
}

func TestAuditStorageCapacityUsesBoundedBlockArithmetic(t *testing.T) {
	t.Parallel()
	if auditStorageCapacityOK(1, 4096, 4097) {
		t.Fatal("one block satisfied a two-block capacity requirement")
	}
	if !auditStorageCapacityOK(2, 4096, 4097) {
		t.Fatal("two blocks did not satisfy a two-block capacity requirement")
	}
	if auditStorageCapacityOK(^uint64(0), 0, 1) {
		t.Fatal("zero block size was accepted")
	}
}

func TestPrepareAuditStorageDirectoryDoesNotCreateThroughSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	escaped := filepath.Join(target, "must-not-be-created")
	if err := prepareAuditStorageDirectory(filepath.Join(link, "must-not-be-created")); err == nil {
		t.Fatal("symlinked directory chain was accepted")
	}
	if _, err := os.Lstat(escaped); !os.IsNotExist(err) {
		t.Fatalf("unsafe directory creation escaped through symlink: %v", err)
	}
}

func TestSuccessfulAuditOpenCapturesPostOpenIdentityForLiveRechecks(t *testing.T) {
	p := New()
	t.Cleanup(p.Shutdown)
	dataDir := filepath.ToSlash(t.TempDir())
	register(t, p, "mode: observe\naudit:\n  enabled: true\n  data_dir: \""+dataDir+"\"\nsubject_control:\n  enabled: false\n")
	state := p.runtime.Load()
	if state == nil || state.audit == nil {
		t.Fatal("audit runtime did not open")
	}
	if !state.auditStorage.identity.directory.present || !state.auditStorage.identity.database.present {
		t.Fatalf("post-open storage identities were not captured: %#v", state.auditStorage.identity)
	}
	live := state.currentAuditStorageVerification()
	if live.PersistenceReason == "directory_identity_changed" || live.PersistenceReason == "database_identity_changed" {
		t.Fatalf("unchanged post-open storage failed its first live recheck: %#v", live)
	}
}

func TestInspectAuditStorageRejectsSQLiteSidecarSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	databasePath := filepath.Join(root, "events.db")
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, databasePath+"-wal"); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	status := inspectAuditStorage(databasePath, true, true, 1)
	if status.PersistenceReason != "unsafe_sqlite_file" || !status.preventsDatabaseOpen() {
		t.Fatalf("sidecar symlink status=%#v", status)
	}
}

func TestRecheckAuditStorageDetectsDirectoryIdentityReplacement(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "audit")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	databasePath := filepath.Join(directory, "events.db")
	baseline := inspectAuditStorage(databasePath, true, true, 1)
	oldDirectory := filepath.Join(root, "audit-old")
	if err := os.Rename(directory, oldDirectory); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}

	status := recheckAuditStorage(baseline, 1, false)
	if status.PersistenceReason != "directory_identity_changed" || status.PersistenceVerified {
		t.Fatalf("directory replacement status=%#v", status)
	}
}

func TestRecheckAuditStorageDetectsWALIdentityReplacement(t *testing.T) {
	directory := t.TempDir()
	databasePath := filepath.Join(directory, "events.db")
	if err := os.WriteFile(databasePath, []byte("db"), 0o600); err != nil {
		t.Fatal(err)
	}
	walPath := databasePath + "-wal"
	if err := os.WriteFile(walPath, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	baseline := inspectAuditStorage(databasePath, true, true, 1)
	if err := os.Rename(walPath, walPath+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(walPath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	status := recheckAuditStorage(baseline, 1, false)
	if status.PersistenceReason != "wal_identity_changed" || status.PersistenceVerified {
		t.Fatalf("WAL replacement status=%#v", status)
	}
}

func TestInspectAuditStorageRejectsUnsafePermissionsAndOwner(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "audit")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o770); err != nil {
		t.Fatal(err)
	}
	status := inspectAuditStorage(filepath.Join(directory, "events.db"), true, true, 1)
	if status.PersistenceReason != "unsafe_storage_permissions" || !status.preventsDatabaseOpen() {
		t.Fatalf("group-writable directory status=%#v", status)
	}

	foreignUID := uint32(os.Geteuid()) ^ 0x80000000
	if foreignUID == 0 {
		foreignUID = 1
	}
	if auditStorageOwnerAllowed(foreignUID) {
		t.Fatalf("foreign owner uid %d was accepted for audit storage", foreignUID)
	}
}

func TestInspectAuditStorageDetectsLiveTmpfs(t *testing.T) {
	root, err := os.MkdirTemp("/dev/shm", "cyber-abuse-guard-audit-storage-")
	if err != nil {
		t.Skipf("tmpfs fixture unavailable: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	status := inspectAuditStorage(filepath.Join(root, "events.db"), true, true, 1)
	if status.StorageType != "tmpfs" || status.State != "ephemeral" ||
		status.PersistenceReason != "ephemeral_filesystem" || status.PersistenceVerified {
		t.Fatalf("live tmpfs storage verification=%#v", status)
	}
}
