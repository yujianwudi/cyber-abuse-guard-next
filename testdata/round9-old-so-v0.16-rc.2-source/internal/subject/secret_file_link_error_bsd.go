//go:build darwin || dragonfly || freebsd || ios || netbsd || openbsd

package subject

import (
	"errors"
	"syscall"
)

func isNoFollowLinkError(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK) || errors.Is(err, syscall.EFTYPE)
}
