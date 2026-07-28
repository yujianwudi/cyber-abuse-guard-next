//go:build unix && !darwin && !dragonfly && !freebsd && !ios && !netbsd && !openbsd

package subject

import (
	"errors"
	"syscall"
)

func isNoFollowLinkError(err error) bool {
	return errors.Is(err, syscall.ELOOP) || errors.Is(err, syscall.EMLINK)
}
