//go:build unix

package subject

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func openSecretFile(path string) (*os.File, error) {
	// O_NOFOLLOW makes opening the final path component and obtaining its file
	// descriptor one atomic operation. O_NONBLOCK prevents a malicious FIFO from
	// blocking before fstat rejects it as non-regular.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if isNoFollowLinkError(err) {
			return nil, errors.New("subject: HMAC secret file must not be a symbolic link")
		}
		return nil, fmt.Errorf("subject: open HMAC secret file: %w", err)
	}
	return file, nil
}
