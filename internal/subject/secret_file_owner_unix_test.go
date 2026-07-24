//go:build unix

package subject

import (
	"os"
	"syscall"
	"testing"
)

type ownerOverrideFileInfo struct {
	os.FileInfo
	stat *syscall.Stat_t
}

func (info ownerOverrideFileInfo) Sys() any { return info.stat }

func TestSecretFileOwnerMustMatchEffectiveUser(t *testing.T) {
	path := t.TempDir()
	base, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	wrongOwner := uint32(os.Geteuid()) + 1
	if wrongOwner == uint32(os.Geteuid()) {
		wrongOwner++
	}
	err = validateSecretFileOwner(ownerOverrideFileInfo{FileInfo: base, stat: &syscall.Stat_t{Uid: wrongOwner}})
	if err == nil {
		t.Fatal("HMAC secret file owned by another uid was accepted")
	}
}
