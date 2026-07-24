//go:build linux || darwin || ios || windows

package fixturepublish

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRenameNoReplaceAllowsExactlyOneConcurrentPublisher(t *testing.T) {
	parent := t.TempDir()
	destination := filepath.Join(parent, "destination")
	staging := []string{filepath.Join(parent, "staging-one"), filepath.Join(parent, "staging-two")}
	for index, path := range staging {
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "fixture"), []byte{byte('1' + index)}, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	start := make(chan struct{})
	results := make(chan error, len(staging))
	for _, path := range staging {
		path := path
		go func() {
			<-start
			results <- renameNoReplace(path, destination)
		}()
	}
	close(start)

	successes := 0
	for range staging {
		if err := <-results; err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("concurrent no-replace successes=%d want=1", successes)
	}
	data, err := os.ReadFile(filepath.Join(destination, "fixture"))
	if err != nil || (string(data) != "1" && string(data) != "2") {
		t.Fatalf("published fixture=%q err=%v", data, err)
	}
}
