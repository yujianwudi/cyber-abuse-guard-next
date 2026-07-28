//go:build unix

package subject

import (
	"errors"
	"os"
	"syscall"
)

func validateSecretFileOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("subject: HMAC secret file owner could not be verified")
	}
	if stat.Uid != uint32(os.Geteuid()) {
		return errors.New("subject: HMAC secret file must be owned by the current user")
	}
	return nil
}
