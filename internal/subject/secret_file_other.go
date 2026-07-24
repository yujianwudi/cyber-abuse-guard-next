//go:build !unix

package subject

import (
	"errors"
	"fmt"
	"os"
)

func openSecretFile(path string) (*os.File, error) {
	// Platforms without Unix open flags use a best-effort identity check around
	// open. This rejects an existing link and detects replacement with a
	// different file between inspection and open.
	before, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("subject: inspect HMAC secret file: %w", err)
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("subject: HMAC secret file must not be a symbolic link")
	}
	if !before.Mode().IsRegular() {
		return nil, errors.New("subject: HMAC secret file must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("subject: open HMAC secret file: %w", err)
	}
	after, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("subject: inspect opened HMAC secret file: %w", err)
	}
	if !os.SameFile(before, after) {
		_ = file.Close()
		return nil, errors.New("subject: HMAC secret file changed while it was being opened")
	}
	return file, nil
}
