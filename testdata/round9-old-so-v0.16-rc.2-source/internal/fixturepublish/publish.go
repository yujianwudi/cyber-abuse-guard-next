// Package fixturepublish atomically publishes generated fixture sets without
// overwriting an existing destination.
package fixturepublish

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// File is one top-level file in a generated fixture directory.
type File struct {
	Name string
	Data []byte
}

// Writer writes and durably closes one staged file.
type Writer func(string, []byte) error

// Publish stages and syncs a complete set before making the destination name
// visible with one directory rename.
func Publish(destination string, files []File) error {
	return PublishWithWriter(destination, files, WriteSyncedFile)
}

// PublishWithWriter is Publish with an injectable file writer for fault tests.
func PublishWithWriter(destination string, files []File, writer Writer) error {
	if writer == nil {
		return errors.New("fixture publication writer is nil")
	}
	if len(files) == 0 {
		return errors.New("fixture publication is empty")
	}
	base := filepath.Base(destination)
	if destination == "" || base == "." || base == ".." {
		return fmt.Errorf("invalid fixture destination %q", destination)
	}
	seen := make(map[string]struct{}, len(files))
	for _, item := range files {
		if invalidFilename(item.Name) {
			return fmt.Errorf("invalid fixture filename %q", item.Name)
		}
		if _, exists := seen[item.Name]; exists {
			return fmt.Errorf("duplicate fixture filename %q", item.Name)
		}
		seen[item.Name] = struct{}{}
	}

	parent := filepath.Dir(destination)
	if err := os.MkdirAll(parent, 0o755); err != nil {
		return fmt.Errorf("create fixture parent: %w", err)
	}
	if err := requireMissing(destination); err != nil {
		return err
	}
	staging, err := os.MkdirTemp(parent, "."+base+".tmp-")
	if err != nil {
		return fmt.Errorf("create fixture staging directory: %w", err)
	}
	published := false
	defer func() {
		if !published {
			_ = os.RemoveAll(staging)
		}
	}()

	// MkdirTemp creates mode 0700 on Unix. Keep the incomplete set private;
	// widen it only after every file has been written and synced.
	for _, item := range files {
		if err := writer(filepath.Join(staging, item.Name), item.Data); err != nil {
			return fmt.Errorf("stage %s: %w", item.Name, err)
		}
	}
	if err := os.Chmod(staging, 0o755); err != nil {
		return fmt.Errorf("set fixture directory permissions: %w", err)
	}
	if err := syncDirectory(staging); err != nil {
		return fmt.Errorf("sync fixture staging directory: %w", err)
	}
	if err := requireMissing(destination); err != nil {
		return err
	}
	if err := renameNoReplace(staging, destination); err != nil {
		return fmt.Errorf("publish fixture directory: %w", err)
	}
	published = true
	if err := syncDirectory(parent); err != nil {
		return fmt.Errorf("sync fixture parent directory: %w", err)
	}
	return nil
}

func invalidFilename(name string) bool {
	return name == "" || name == "." || name == ".." || filepath.IsAbs(name) ||
		filepath.Base(name) != name || strings.ContainsAny(name, `/\`)
}

func requireMissing(path string) error {
	_, err := os.Lstat(path)
	if err == nil {
		return fmt.Errorf("refusing to overwrite existing fixture directory %s", path)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("inspect fixture destination: %w", err)
	}
	return nil
}

// WriteSyncedFile creates one new staged file, writes all bytes, syncs it, and
// closes it before publication can proceed.
func WriteSyncedFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	written, err := file.Write(data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	closed = true
	return nil
}
