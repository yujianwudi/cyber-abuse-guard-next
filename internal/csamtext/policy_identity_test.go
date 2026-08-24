package csamtext

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var csamTextPolicySourceFiles = []string{
	"go.mod",
	"go.sum",
	"internal/csamtext/classifier.go",
	"internal/csamtext/policy_identity_test.go",
	"internal/extract/content_kind.go",
	"internal/extract/decoding.go",
	"internal/extract/extract.go",
	"internal/extract/multipart.go",
	"internal/extract/profile.go",
	"internal/extract/provenance.go",
	"internal/extract/request.go",
	"internal/extract/roles.go",
	"internal/extract/state.go",
	"internal/extract/stream.go",
	"internal/extract/stream_multipart.go",
	"internal/extract/stream_scan.go",
	"internal/plugin/csam_stream.go",
	"internal/plugin/decision_explanation.go",
	"internal/plugin/disposition.go",
	"internal/plugin/management.go",
	"internal/plugin/plugin.go",
	"internal/plugin/router.go",
}

var csamTextPolicyInventoryDirectories = []string{
	"internal/csamtext",
	"internal/extract",
}

func TestCSAMTextPolicySourceInventoryClosure(t *testing.T) {
	t.Parallel()
	root := csamTextPolicyRepositoryRoot(t)
	listed := csamTextPolicyListedSources(t)

	if _, ok := listed["internal/csamtext/policy_identity_test.go"]; !ok {
		t.Fatal("CSAM text policy source inventory must bind its own definition")
	}
	if _, recursive := listed["internal/csamtext/policy_identity.go"]; recursive {
		t.Fatal("CSAM text policy identity declaration must stay outside its own digest")
	}
	for _, required := range []string{
		"internal/csamtext/classifier.go",
		"internal/plugin/csam_stream.go",
		"internal/plugin/decision_explanation.go",
		"internal/plugin/disposition.go",
		"internal/plugin/router.go",
	} {
		if _, ok := listed[required]; !ok {
			t.Fatalf("CSAM text policy source inventory omitted required source %q", required)
		}
	}

	missing, err := csamTextPolicyMissingProductionSources(root, listed)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("CSAM text policy production sources missing from identity inventory: %s", strings.Join(missing, ", "))
	}

	t.Run("unlisted package production source fails closed", func(t *testing.T) {
		fixture := t.TempDir()
		if err := os.MkdirAll(filepath.Join(fixture, "internal", "csamtext"), 0o700); err != nil {
			t.Fatal(err)
		}
		probe := "internal/csamtext/new_policy_source.go"
		if err := os.WriteFile(filepath.Join(fixture, filepath.FromSlash(probe)), []byte("package csamtext\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		missing, err := csamTextPolicyMissingProductionSources(fixture, map[string]struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		if len(missing) != 1 || missing[0] != probe {
			t.Fatalf("unlisted CSAM package source did not fail closed: %v", missing)
		}
	})

	t.Run("unlisted plugin production source fails closed", func(t *testing.T) {
		fixture := t.TempDir()
		if err := os.MkdirAll(filepath.Join(fixture, "internal", "plugin"), 0o700); err != nil {
			t.Fatal(err)
		}
		probe := "internal/plugin/new_csam_policy_source.go"
		data := []byte("package plugin\n\nimport _ \"github.com/yujianwudi/cyber-abuse-guard-next/internal/csamtext\"\n")
		if err := os.WriteFile(filepath.Join(fixture, filepath.FromSlash(probe)), data, 0o600); err != nil {
			t.Fatal(err)
		}
		missing, err := csamTextPolicyMissingProductionSources(fixture, map[string]struct{}{})
		if err != nil {
			t.Fatal(err)
		}
		if len(missing) != 1 || missing[0] != probe {
			t.Fatalf("unlisted CSAM plugin source did not fail closed: %v", missing)
		}
	})
}

func csamTextPolicyListedSources(t *testing.T) map[string]struct{} {
	t.Helper()
	listed := make(map[string]struct{}, len(csamTextPolicySourceFiles))
	for _, name := range csamTextPolicySourceFiles {
		name = filepath.ToSlash(filepath.Clean(name))
		if name == "." || strings.HasPrefix(name, "../") || filepath.IsAbs(name) {
			t.Fatalf("CSAM text policy source path is not repository-relative: %q", name)
		}
		if _, duplicate := listed[name]; duplicate {
			t.Fatalf("CSAM text policy source path is duplicated: %q", name)
		}
		listed[name] = struct{}{}
	}
	return listed
}

func csamTextPolicyMissingProductionSources(root string, listed map[string]struct{}) ([]string, error) {
	var missing []string
	for _, directory := range csamTextPolicyInventoryDirectories {
		path := filepath.Join(root, filepath.FromSlash(directory))
		entries, err := os.ReadDir(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("read CSAM text policy inventory directory %q: %w", directory, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasSuffix(entry.Name(), "_test.go") || filepath.Ext(entry.Name()) != ".go" {
				continue
			}
			relative := filepath.ToSlash(filepath.Join(directory, entry.Name()))
			if relative == "internal/csamtext/policy_identity.go" {
				continue
			}
			if err := csamTextPolicyRequireRegularSource(entry, relative); err != nil {
				return nil, err
			}
			if _, ok := listed[relative]; !ok {
				missing = append(missing, relative)
			}
		}
	}

	pluginDirectory := filepath.Join(root, "internal", "plugin")
	entries, err := os.ReadDir(pluginDirectory)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("read CSAM text plugin policy inventory: %w", err)
		}
	} else {
		for _, entry := range entries {
			if entry.IsDir() || strings.HasSuffix(entry.Name(), "_test.go") || filepath.Ext(entry.Name()) != ".go" {
				continue
			}
			relative := filepath.ToSlash(filepath.Join("internal/plugin", entry.Name()))
			if err := csamTextPolicyRequireRegularSource(entry, relative); err != nil {
				return nil, err
			}
			data, err := os.ReadFile(filepath.Join(pluginDirectory, entry.Name()))
			if err != nil {
				return nil, fmt.Errorf("read CSAM text plugin policy source %q: %w", relative, err)
			}
			if !bytes.Contains(bytes.ToLower(data), []byte("csam")) {
				continue
			}
			if _, ok := listed[relative]; !ok {
				missing = append(missing, relative)
			}
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func csamTextPolicyRequireRegularSource(entry os.DirEntry, relative string) error {
	info, err := entry.Info()
	if err != nil {
		return fmt.Errorf("inspect CSAM text policy source %q: %w", relative, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("CSAM text policy source is not a regular file: %q", relative)
	}
	return nil
}

func TestCSAMTextPolicyIdentity(t *testing.T) {
	t.Parallel()
	root := csamTextPolicyRepositoryRoot(t)
	files := append([]string(nil), csamTextPolicySourceFiles...)
	sort.Strings(files)
	hash := sha256.New()
	seen := make(map[string]struct{}, len(files))
	for _, name := range files {
		name = filepath.ToSlash(filepath.Clean(name))
		if name == "." || strings.HasPrefix(name, "../") || filepath.IsAbs(name) {
			t.Fatalf("CSAM text policy source path is not repository-relative: %q", name)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("CSAM text policy source path is duplicated: %q", name)
		}
		seen[name] = struct{}{}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read CSAM text policy source %q: %v", name, err)
		}
		fmt.Fprintf(hash, "%s\x00%d\x00", name, len(data))
		_, _ = hash.Write(data)
		_, _ = hash.Write([]byte{0})
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != CSAMTextPolicySHA256 {
		t.Fatalf("CSAM text policy identity mismatch: got %s want %s", actual, CSAMTextPolicySHA256)
	}
	identity := CurrentPolicyIdentity()
	if identity.Version != CSAMTextPolicyVersion || identity.SHA256 != CSAMTextPolicySHA256 {
		t.Fatalf("compiled CSAM text policy identity is inconsistent: %+v", identity)
	}
}

func csamTextPolicyRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve CSAM text policy source root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
