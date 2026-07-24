//go:build unix

package subject

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSecretFileDeviceIsRejectedWithoutBlocking(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skip("/dev/null is unavailable")
	}
	result := make(chan error, 1)
	go func() {
		_, err := readSecretFile("/dev/null")
		result <- err
	}()
	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatal("device-backed HMAC key was not rejected as a regular-file violation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("device-backed HMAC key read blocked")
	}
}

func TestSecretFileFIFOIsRejectedWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.fifo")
	mkfifo, err := exec.LookPath("mkfifo")
	if err != nil {
		t.Skipf("mkfifo is unavailable: %v", err)
	}
	if output, err := exec.Command(mkfifo, path).CombinedOutput(); err != nil {
		t.Skipf("create FIFO: %v (%s)", err, output)
	}

	result := make(chan error, 1)
	go func() {
		_, err := readSecretFile(path)
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil || !strings.Contains(err.Error(), "regular file") {
			t.Fatalf("readSecretFile(FIFO) error = %v, want regular-file rejection", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("readSecretFile(FIFO) blocked")
	}
}
