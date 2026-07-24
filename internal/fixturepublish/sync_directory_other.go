//go:build !unix

package fixturepublish

import (
	"fmt"
	"os"
)

// The standard library cannot portably flush a directory handle on non-Unix
// platforms. Files are still synced before the atomic rename; validate both
// directories so unsupported metadata flushing cannot hide a path error.
func syncDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("fixturepublish: %s is not a directory", path)
	}
	return nil
}
