//go:build unix

package fixturepublish

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPublishKeepsStagingPrivateUntilComplete(t *testing.T) {
	t.Parallel()
	destination := filepath.Join(t.TempDir(), "holdout")
	err := PublishWithWriter(destination, []File{{Name: "one", Data: []byte("x")}}, func(path string, data []byte) error {
		if _, err := os.Lstat(destination); !os.IsNotExist(err) {
			return fmt.Errorf("destination visible before publication: %v", err)
		}
		info, err := os.Lstat(filepath.Dir(path))
		if err != nil {
			return err
		}
		if mode := info.Mode().Perm(); mode != 0o700 {
			return fmt.Errorf("staging mode=%#o want=0700", mode)
		}
		return WriteSyncedFile(path, data)
	})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(destination)
	if err != nil {
		t.Fatal(err)
	}
	if mode := info.Mode().Perm(); mode != 0o755 {
		t.Fatalf("published mode=%#o want=0755", mode)
	}
}
