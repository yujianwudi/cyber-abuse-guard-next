package classifier

import (
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

var classifierPolicySourceFiles = []string{
	"go.mod",
	"go.sum",
	"internal/classifier/behavior.go",
	"internal/classifier/classifier.go",
	"internal/classifier/eligibility.go",
	"internal/classifier/matcher.go",
	"internal/classifier/meta_override.go",
	"internal/classifier/meta_override_structure.go",
	"internal/classifier/normalize.go",
	"internal/classifier/ownership.go",
	"internal/classifier/policy_identity_test.go",
	"internal/classifier/roles.go",
	"internal/classifier/semantic.go",
	"internal/classifier/signal_pool.go",
	"internal/classifier/streaming.go",
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
	"internal/explanation/hard_floor.go",
	"internal/plugin/counters.go",
	"internal/rules/loader.go",
	"internal/rules/types.go",
	"rules/contexts.yaml",
	"rules/credentials.yaml",
	"rules/disruption.yaml",
	"rules/embed.go",
	"rules/evasion.yaml",
	"rules/exfiltration.yaml",
	"rules/exploitation.yaml",
	"rules/malware.yaml",
	"rules/manifest.yaml",
	"rules/phishing.yaml",
	"rules/ransomware.yaml",
	"rules/semantics.yaml",
}

var classifierPolicyInventoryDirectories = []struct {
	directory  string
	extensions []string
}{
	{directory: "internal/classifier", extensions: []string{".go"}},
	{directory: "internal/extract", extensions: []string{".go"}},
	{directory: "internal/explanation", extensions: []string{".go"}},
	{directory: "internal/rules", extensions: []string{".go"}},
	{directory: "rules", extensions: []string{".go", ".yaml", ".yml"}},
}

func TestClassifierPolicySourceInventoryClosure(t *testing.T) {
	t.Parallel()
	root := classifierPolicyRepositoryRoot(t)
	listed := make(map[string]struct{}, len(classifierPolicySourceFiles))
	for _, name := range classifierPolicySourceFiles {
		name = filepath.ToSlash(filepath.Clean(name))
		if name == "." || strings.HasPrefix(name, "../") || filepath.IsAbs(name) {
			t.Fatalf("classifier policy source path is not repository-relative: %q", name)
		}
		if _, duplicate := listed[name]; duplicate {
			t.Fatalf("classifier policy source path is duplicated: %q", name)
		}
		listed[name] = struct{}{}
	}

	if _, ok := listed["internal/classifier/policy_identity_test.go"]; !ok {
		t.Fatal("classifier policy source inventory must bind its own definition")
	}
	if _, recursive := listed["internal/classifier/policy_identity.go"]; recursive {
		t.Fatal("classifier policy identity declaration must stay outside its own digest")
	}

	missing, err := classifierPolicyMissingProductionSources(root, listed)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("classifier policy production sources missing from identity inventory: %s", strings.Join(missing, ", "))
	}

	t.Run("unlisted production source fails closed", func(t *testing.T) {
		fixture := t.TempDir()
		for _, inventory := range classifierPolicyInventoryDirectories {
			if err := os.MkdirAll(filepath.Join(fixture, filepath.FromSlash(inventory.directory)), 0o700); err != nil {
				t.Fatalf("create policy inventory fixture directory: %v", err)
			}
		}
		probe := "internal/explanation/new_policy_source.go"
		if err := os.WriteFile(
			filepath.Join(fixture, filepath.FromSlash(probe)),
			[]byte("package explanation\n"),
			0o600,
		); err != nil {
			t.Fatalf("create unlisted policy source fixture: %v", err)
		}
		missing, err := classifierPolicyMissingProductionSources(fixture, map[string]struct{}{})
		if err != nil {
			t.Fatalf("inventory unlisted policy source fixture: %v", err)
		}
		if len(missing) != 1 || missing[0] != probe {
			t.Fatalf("unlisted production source did not fail closed: %v", missing)
		}
	})
}

func classifierPolicyMissingProductionSources(root string, listed map[string]struct{}) ([]string, error) {
	var missing []string
	for _, inventory := range classifierPolicyInventoryDirectories {
		directory := filepath.Join(root, filepath.FromSlash(inventory.directory))
		entries, err := os.ReadDir(directory)
		if err != nil {
			return nil, fmt.Errorf("read classifier policy inventory directory %q: %w", inventory.directory, err)
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			extension := strings.ToLower(filepath.Ext(entry.Name()))
			includedExtension := false
			for _, allowed := range inventory.extensions {
				if extension == allowed {
					includedExtension = true
					break
				}
			}
			if !includedExtension {
				continue
			}

			relative := filepath.ToSlash(filepath.Join(inventory.directory, entry.Name()))
			if relative == "internal/classifier/policy_identity.go" {
				continue
			}
			info, err := entry.Info()
			if err != nil {
				return nil, fmt.Errorf("inspect classifier policy inventory source %q: %w", relative, err)
			}
			if !info.Mode().IsRegular() {
				return nil, fmt.Errorf("classifier policy inventory source is not a regular file: %q", relative)
			}
			if _, ok := listed[relative]; !ok {
				missing = append(missing, relative)
			}
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func TestClassifierPolicyIdentity(t *testing.T) {
	t.Parallel()
	root := classifierPolicyRepositoryRoot(t)
	files := append([]string(nil), classifierPolicySourceFiles...)
	sort.Strings(files)
	hash := sha256.New()
	seen := make(map[string]struct{}, len(files))
	for _, name := range files {
		name = filepath.ToSlash(filepath.Clean(name))
		if name == "." || strings.HasPrefix(name, "../") || filepath.IsAbs(name) {
			t.Fatalf("classifier policy source path is not repository-relative: %q", name)
		}
		if strings.Contains(name, "evaluation-v10") {
			t.Fatalf("classifier policy identity must not access consumed evaluation data: %q", name)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("classifier policy source path is duplicated: %q", name)
		}
		seen[name] = struct{}{}
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
		if err != nil {
			t.Fatalf("read classifier policy source %q: %v", name, err)
		}
		fmt.Fprintf(hash, "%s\x00%d\x00", name, len(data))
		_, _ = hash.Write(data)
		_, _ = hash.Write([]byte{0})
	}
	actual := hex.EncodeToString(hash.Sum(nil))
	if actual != ClassifierPolicySHA256 {
		t.Fatalf("classifier policy identity mismatch: got %s want %s", actual, ClassifierPolicySHA256)
	}
	identity := CurrentPolicyIdentity()
	if identity.Version != ClassifierPolicyVersion || identity.SHA256 != ClassifierPolicySHA256 {
		t.Fatalf("compiled classifier policy identity is inconsistent: %+v", identity)
	}
}

func classifierPolicyRepositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve classifier policy source root")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}
