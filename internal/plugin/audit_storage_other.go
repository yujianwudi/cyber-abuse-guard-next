//go:build !linux

package plugin

import "os"

func prepareAuditStorageDirectory(directory string) error {
	return os.MkdirAll(directory, 0o700)
}

func inspectAuditStoragePlatform(
	status auditStorageVerification,
	_ string,
	_ int64,
) auditStorageVerification {
	status.StorageType = "unsupported"
	status.State = "unsupported"
	status.PersistenceReason = "linux_verification_required"
	return status
}
