//go:build linux

package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// prepareAuditStorageDirectory creates only missing directory components and
// opens every component relative to an already verified parent. O_NOFOLLOW
// prevents Mkdirat from being redirected through an operator-controlled
// symlink before persistence verification runs.
func prepareAuditStorageDirectory(directory string) error {
	abs, err := filepath.Abs(directory)
	if err != nil {
		return fmt.Errorf("resolve audit data directory: %w", err)
	}
	clean := filepath.Clean(abs)
	fd, err := unix.Open(string(filepath.Separator), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open audit data root: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()

	for _, component := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		next, openErr := unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if openErr == unix.ENOENT {
			if mkdirErr := unix.Mkdirat(fd, component, 0o700); mkdirErr != nil && mkdirErr != unix.EEXIST {
				return fmt.Errorf("create audit data directory component: %w", mkdirErr)
			}
			next, openErr = unix.Openat(fd, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			return fmt.Errorf("open audit data directory component without following symlinks: %w", openErr)
		}
		_ = unix.Close(fd)
		fd = next
	}
	return nil
}

const (
	auditStorageTmpfsMagic   = 0x01021994
	auditStorageRamfsMagic   = 0x858458f6
	auditStorageOverlayMagic = 0x794c7630
)

type auditMountInfo struct {
	mountPoint string
	fsType     string
	readOnly   bool
	identity   string
}

func inspectAuditStoragePlatform(
	status auditStorageVerification,
	directory string,
	maxBytes int64,
) auditStorageVerification {
	if reason := auditStorageAncestorSafety(directory); reason != "" {
		status.State = "unsafe"
		status.PersistenceReason = reason
		return status
	}

	directoryFD, err := unix.Open(directory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		status.State = "unavailable"
		status.PersistenceReason = "storage_open_failed"
		return status
	}
	defer func() { _ = unix.Close(directoryFD) }()
	var directoryStat unix.Stat_t
	if err := unix.Fstat(directoryFD, &directoryStat); err != nil {
		status.State = "unavailable"
		status.PersistenceReason = "database_stat_failed"
		return status
	}
	status.identity.directory = auditStorageIdentityFromStat(directoryStat)
	if !auditStorageOwnerAllowed(directoryStat.Uid) {
		status.State = "unsafe"
		status.PersistenceReason = "unsafe_storage_owner"
		return status
	}
	if auditStorageGroupOrWorldWritable(directoryStat.Mode) {
		status.State = "unsafe"
		status.PersistenceReason = "unsafe_storage_permissions"
		return status
	}

	var stats unix.Statfs_t
	if err := unix.Fstatfs(directoryFD, &stats); err != nil {
		status.PersistenceReason = "statfs_failed"
		return status
	}
	status.CapacityOK = auditStorageCapacityOK(uint64(stats.Bavail), uint64(stats.Bsize), maxBytes)
	status.Writable = stats.Flags&unix.ST_RDONLY == 0 && unix.Faccessat(directoryFD, ".", unix.W_OK, unix.AT_EACCESS) == nil
	for _, candidate := range []struct {
		name     string
		identity *auditStorageObjectIdentity
	}{
		{name: filepath.Base(status.DatabasePath), identity: &status.identity.database},
		{name: filepath.Base(status.DatabasePath) + "-wal", identity: &status.identity.wal},
		{name: filepath.Base(status.DatabasePath) + "-shm", identity: &status.identity.shm},
	} {
		identity, writable, reason := inspectAuditStorageObjectAt(
			directoryFD,
			candidate.name,
			status.PersistenceExpected,
		)
		*candidate.identity = identity
		if reason != "" {
			status.State = "unsafe"
			status.PersistenceReason = reason
			return status
		}
		if identity.present && !writable {
			status.Writable = false
		}
	}

	mount, ok := auditMountForPath(directory)
	if ok {
		status.StorageType = boundedAuditFilesystemType(mount.fsType)
		status.SeparateMount = filepath.Clean(mount.mountPoint) != string(filepath.Separator)
		status.identity.mount = mount.identity
		if mount.readOnly {
			status.Writable = false
		}
	} else {
		status.StorageType = auditFilesystemTypeFromMagic(int64(stats.Type))
	}
	if status.StorageType == "unknown" {
		status.StorageType = auditFilesystemTypeFromMagic(int64(stats.Type))
	}

	return finalizeAuditStoragePlatform(status)
}

func auditStorageIdentityFromStat(stat unix.Stat_t) auditStorageObjectIdentity {
	return auditStorageObjectIdentity{present: true, device: uint64(stat.Dev), inode: stat.Ino}
}

func inspectAuditStorageObjectAt(directoryFD int, name string, requirePrivate bool) (auditStorageObjectIdentity, bool, string) {
	fd, err := unix.Openat(directoryFD, name, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == unix.ENOENT {
		return auditStorageObjectIdentity{}, true, ""
	}
	if err != nil {
		return auditStorageObjectIdentity{}, false, "database_stat_failed"
	}
	defer func() { _ = unix.Close(fd) }()
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return auditStorageObjectIdentity{}, false, "database_stat_failed"
	}
	identity := auditStorageIdentityFromStat(stat)
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return identity, false, "unsafe_sqlite_file"
	}
	if !auditStorageOwnerAllowed(stat.Uid) {
		return identity, false, "unsafe_storage_owner"
	}
	if requirePrivate && stat.Mode&(unix.S_IRWXG|unix.S_IRWXO) != 0 {
		return identity, false, "unsafe_storage_permissions"
	}
	if auditStorageGroupOrWorldWritable(stat.Mode) {
		return identity, false, "unsafe_storage_permissions"
	}
	return identity, unix.Faccessat(directoryFD, name, unix.W_OK, unix.AT_EACCESS) == nil, ""
}

func auditStorageAncestorSafety(directory string) string {
	directory = filepath.Clean(directory)
	for current := directory; ; current = filepath.Dir(current) {
		var stat unix.Stat_t
		if err := unix.Lstat(current, &stat); err != nil {
			return "database_stat_failed"
		}
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return "symlinked_directory"
		}
		if !auditStorageOwnerAllowed(stat.Uid) {
			return "unsafe_storage_owner"
		}
		if auditStorageGroupOrWorldWritable(stat.Mode) {
			// A root-owned sticky ancestor such as /tmp prevents one tenant from
			// renaming another tenant's private child. The final data directory is
			// never exempt from the no group/world-write rule.
			stickyAncestor := current != directory && stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0
			if !stickyAncestor {
				return "unsafe_storage_permissions"
			}
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return ""
}

func auditStorageOwnerAllowed(uid uint32) bool {
	effective := uint32(os.Geteuid())
	return uid == 0 || uid == effective
}

func auditStorageGroupOrWorldWritable(mode uint32) bool {
	return mode&(unix.S_IWGRP|unix.S_IWOTH) != 0
}

func finalizeAuditStoragePlatform(status auditStorageVerification) auditStorageVerification {
	// Current operability outranks the underlying filesystem classification so
	// a formerly healthy volume that becomes read-only or capacity-constrained
	// reports the live failure instead of only its static mount type.
	if !status.Writable {
		status.State = "read_only"
		status.PersistenceReason = "read_only"
		return status
	}
	if !status.CapacityOK {
		status.State = "insufficient_capacity"
		status.PersistenceReason = "insufficient_capacity"
		return status
	}
	switch status.StorageType {
	case "tmpfs", "ramfs":
		status.State = "ephemeral"
		status.PersistenceReason = "ephemeral_filesystem"
		return status
	case "overlay", "overlayfs":
		status.State = "container_layer"
		status.PersistenceReason = "container_layer"
		return status
	}
	if !status.SeparateMount {
		status.State = "unverified"
		status.PersistenceReason = "not_separate_mount"
		return status
	}
	if !persistentAuditFilesystem(status.StorageType) {
		status.State = "unverified"
		status.PersistenceReason = "filesystem_not_allowlisted"
		return status
	}
	status.State = "persistent_candidate"
	status.PersistenceVerified = true
	status.PersistenceReason = ""
	return status
}

func auditStorageCapacityOK(availableBlocks, blockSize uint64, maxBytes int64) bool {
	if maxBytes <= 0 {
		return true
	}
	if blockSize == 0 {
		return false
	}
	requiredBlocks := (uint64(maxBytes)-1)/blockSize + 1
	return availableBlocks >= requiredBlocks
}

func auditMountForPath(path string) (auditMountInfo, bool) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return auditMountInfo{}, false
	}
	return parseAuditMountInfo(raw, path)
}

func parseAuditMountInfo(raw []byte, path string) (auditMountInfo, bool) {
	path = filepath.Clean(path)
	best := auditMountInfo{}
	bestLength := -1
	for _, line := range strings.Split(string(raw), "\n") {
		leftRight := strings.SplitN(line, " - ", 2)
		if len(leftRight) != 2 {
			continue
		}
		left := strings.Fields(leftRight[0])
		right := strings.Fields(leftRight[1])
		if len(left) < 6 || len(right) < 3 {
			continue
		}
		mountPoint := filepath.Clean(unescapeAuditMountField(left[4]))
		if !auditPathWithinMount(path, mountPoint) || len(mountPoint) <= bestLength {
			continue
		}
		best = auditMountInfo{
			mountPoint: mountPoint,
			fsType:     right[0],
			readOnly:   auditMountOptionsReadOnly(left[5]) || auditMountOptionsReadOnly(right[2]),
			identity:   left[0] + ":" + left[2],
		}
		bestLength = len(mountPoint)
	}
	return best, bestLength >= 0
}

func auditPathWithinMount(path, mountPoint string) bool {
	if path == mountPoint {
		return true
	}
	if mountPoint == string(filepath.Separator) {
		return filepath.IsAbs(path)
	}
	return strings.HasPrefix(path, mountPoint+string(filepath.Separator))
}

func unescapeAuditMountField(value string) string {
	var decoded strings.Builder
	decoded.Grow(len(value))
	for index := 0; index < len(value); {
		if index+4 <= len(value) && value[index] == '\\' {
			switch value[index : index+4] {
			case `\040`:
				decoded.WriteByte(' ')
				index += 4
				continue
			case `\011`:
				decoded.WriteByte('\t')
				index += 4
				continue
			case `\012`:
				decoded.WriteByte('\n')
				index += 4
				continue
			case `\134`:
				decoded.WriteByte('\\')
				index += 4
				continue
			}
		}
		decoded.WriteByte(value[index])
		index++
	}
	return decoded.String()
}

func auditMountOptionsReadOnly(options string) bool {
	for _, option := range strings.Split(options, ",") {
		if option == "ro" {
			return true
		}
	}
	return false
}

func boundedAuditFilesystemType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" || len(value) > 32 {
		return "unknown"
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-') {
			return "unknown"
		}
	}
	return value
}

func auditFilesystemTypeFromMagic(value int64) string {
	switch uint64(value) {
	case auditStorageTmpfsMagic:
		return "tmpfs"
	case auditStorageRamfsMagic:
		return "ramfs"
	case auditStorageOverlayMagic:
		return "overlay"
	case 0xef53:
		return "ext4"
	case 0x58465342:
		return "xfs"
	case 0x9123683e:
		return "btrfs"
	default:
		return "unknown_" + strconv.FormatUint(uint64(value), 16)
	}
}

func persistentAuditFilesystem(value string) bool {
	switch value {
	case "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs":
		return true
	default:
		return false
	}
}
