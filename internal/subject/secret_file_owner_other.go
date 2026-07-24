//go:build !unix

package subject

import "os"

// Windows file ownership is enforced by ACLs rather than Unix uid bits. The
// descriptor identity and regular-file checks still prevent link/device swaps.
func validateSecretFileOwner(os.FileInfo) error { return nil }
