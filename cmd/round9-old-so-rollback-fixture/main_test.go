package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateSandboxPathsRejectsDatabaseOutsideRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "events.db")
	if err := os.WriteFile(outside, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := validateSandboxPaths(root, outside); err == nil {
		t.Fatal("validateSandboxPaths accepted a database outside the sandbox")
	}
}

func TestValidateSandboxPathsAcceptsPrivateContainedFile(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	database := filepath.Join(root, "data", "events.db")
	if err := os.Mkdir(filepath.Dir(database), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(database, []byte("fixture"), 0o600); err != nil {
		t.Fatal(err)
	}
	gotRoot, gotDatabase, err := validateSandboxPaths(root, database)
	if err != nil {
		t.Fatal(err)
	}
	if gotRoot != root || gotDatabase != database {
		t.Fatalf("paths = %q, %q; want %q, %q", gotRoot, gotDatabase, root, database)
	}
}

func TestRequireMarkerRejectsWrongIdentity(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, sandboxMarkerName)
	if err := os.WriteFile(marker, []byte("not-the-reviewed-marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := requireMarker(root); err == nil {
		t.Fatal("requireMarker accepted an unreviewed marker")
	}
}
