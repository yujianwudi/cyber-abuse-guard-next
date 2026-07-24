package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDevelopmentPublicJailbreakPatternsV1Corpus(t *testing.T) {
	t.Parallel()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve repository root")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	metrics, err := validateDevelopmentCorpus(root)
	if err != nil {
		t.Fatal(err)
	}
	if metrics.Total < 36 || metrics.Allow == 0 || metrics.Audit == 0 || metrics.RoleAware == 0 || metrics.Untrusted == 0 {
		t.Fatalf("unexpected development metrics: %+v", metrics)
	}
}

func TestDevelopmentPublicJailbreakPatternsRejectsLiveMaterial(t *testing.T) {
	t.Parallel()
	for _, value := range [][]byte{
		[]byte(`{"input":"https://target.invalid"}`),
		[]byte(`{"forbidden_marker":"malware"}`),
		[]byte(`{"forbidden_marker":"real victim"}`),
		[]byte(`{"input":"203.0.113.10"}`),
		[]byte(`{"repository_owner":"Jia-Ethan"}`),
		[]byte(`{"repository_name":"codex-keysmith"}`),
		[]byte(`{"repository_owner":"MDX-Tom"}`),
		[]byte(`{"repository_name":"gpt-5.6-instruct"}`),
		[]byte(`{"repository_owner":"yynxxxxx"}`),
		[]byte(`{"repository_name":"Codex-X"}`),
		[]byte(`{"repository_name":"Codex-5.5-codex-instruct-5.5"}`),
		[]byte(`{"commit":"f699b9bd2cb59eb0d54e69139c68f7808d869b6d"}`),
		[]byte(`{"commit":"5f469e43ef66f540cadb475039fd9ed469aef654"}`),
		[]byte(`{"commit":"7d0e0064d54f860d4bf12b557fd9f8c489043a35"}`),
		[]byte(`{"commit":"ed0b6dc37d1994e93788d92f7af63f58bf0b9e2d"}`),
	} {
		if err := validateCorpusSafety(value); err == nil {
			t.Fatalf("unsafe development material was accepted: %s", value)
		}
	}
	for _, value := range []json.RawMessage{
		json.RawMessage(`{"input":"\u006d\u0061\u006c\u0077\u0061\u0072\u0065"}`),
		json.RawMessage(`{"\u006d\u0061\u006c\u0077\u0061\u0072\u0065":true}`),
		json.RawMessage(`{"input":"\u0068\u0074\u0074\u0070\u0073\u003a\u002f\u002ftarget.invalid"}`),
		json.RawMessage(`{"input":"\u0032\u0030\u0033\u002e\u0030\u002e\u0031\u0031\u0033\u002e\u0031\u0030"}`),
	} {
		if err := validateDecodedJSONSafety(value); err == nil {
			t.Fatalf("escaped unsafe development material was accepted: %s", value)
		}
	}
	if err := validateCorpusSafety([]byte("decoded marker malware")); err == nil {
		t.Fatal("decoded semantic material was accepted")
	}

	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve repository root")
	}
	sourceRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	for _, test := range []struct {
		name   string
		file   string
		marker string
	}{
		{name: "README", file: "README.md", marker: "Jia-Ethan"},
		{name: "manifest", file: "manifest.json", marker: "f699b9bd2cb59eb0d54e69139c68f7808d869b6d"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			directory := filepath.Join(root, "testdata", developmentDatasetID)
			if err := os.MkdirAll(directory, 0o700); err != nil {
				t.Fatal(err)
			}
			for _, name := range canonicalDevelopmentFiles {
				data, err := os.ReadFile(filepath.Join(sourceRoot, "testdata", developmentDatasetID, name))
				if err != nil {
					t.Fatal(err)
				}
				if name == test.file {
					if name == "README.md" {
						data = append(data, []byte("\n"+test.marker+"\n")...)
					} else {
						var descriptor manifest
						if err := json.Unmarshal(data, &descriptor); err != nil {
							t.Fatal(err)
						}
						descriptor.Notice += " " + test.marker
						data, err = json.MarshalIndent(descriptor, "", "  ")
						if err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := os.WriteFile(filepath.Join(directory, name), data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := validateDevelopmentCorpus(root)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(test.marker)) {
				t.Fatalf("unsafe %s material was not rejected by the corpus scan: %v", test.file, err)
			}
		})
	}
}

func TestDevelopmentPublicJailbreakPatternsRejectsManifestCoverageDrift(t *testing.T) {
	t.Parallel()
	valid := canonicalManifestForTest()
	if err := validateManifest(valid); err != nil {
		t.Fatalf("canonical manifest was rejected: %v", err)
	}

	missing := valid
	missing.RequiredFamilies = append([]string(nil), valid.RequiredFamilies[1:]...)
	if err := validateManifest(missing); err == nil {
		t.Fatal("manifest with a missing canonical family was accepted")
	}

	extra := valid
	extra.RequiredProtocols = append(append([]string(nil), valid.RequiredProtocols...), "unapproved_protocol")
	if err := validateManifest(extra); err == nil {
		t.Fatal("manifest with an extra protocol was accepted")
	}

	wrongCases := valid
	wrongCases.Cases = "alternate.jsonl"
	if err := validateManifest(wrongCases); err == nil {
		t.Fatal("manifest with a non-canonical case path was accepted")
	}

	roleAware := true
	record := fixtureRecord{
		ID:                "pubjail-test-record",
		Dataset:           developmentDatasetID,
		Family:            canonicalDevelopmentFamilies[0],
		Label:             "allow",
		Protocol:          canonicalDevelopmentProtocols[0],
		Carrier:           canonicalDevelopmentCarriers[0],
		Transform:         canonicalDevelopmentTransforms[0],
		PairID:            "pair-test-record",
		Purpose:           "Harmless metadata membership regression canary.",
		HarmlessCanary:    true,
		ExpectedRoleAware: &roleAware,
		Input:             json.RawMessage(`{"messages":[{"role":"user","content":"CANARY"}]}`),
	}
	for label, mutate := range map[string]func(*fixtureRecord){
		"family":         func(value *fixtureRecord) { value.Family = "unapproved_family" },
		"protocol":       func(value *fixtureRecord) { value.Protocol = "unapproved_protocol" },
		"carrier":        func(value *fixtureRecord) { value.Carrier = "unapproved_carrier" },
		"transform":      func(value *fixtureRecord) { value.Transform = "unapproved_transform" },
		"source context": func(value *fixtureRecord) { value.SourceContext = "unapproved_source" },
	} {
		t.Run(label, func(t *testing.T) {
			invalid := record
			mutate(&invalid)
			if err := validateRecord(invalid, map[string]struct{}{}, valid); err == nil {
				t.Fatalf("case %s outside the canonical manifest was accepted", label)
			}
		})
	}
}

func TestDevelopmentPublicJailbreakPatternsRejectsDirectoryDrift(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	for _, name := range canonicalDevelopmentFiles {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("development canary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := validateCorpusDirectory(directory); err != nil {
		t.Fatalf("canonical development directory was rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "unexpected-prompt-bank.txt"), []byte("CANARY\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateCorpusDirectory(directory); err == nil {
		t.Fatal("development directory with an extra file was accepted")
	}
}

func TestDevelopmentPublicJailbreakPatternsRejectsSymlink(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	for _, name := range []string{"README.md", "manifest.json"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("development canary\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("README.md", filepath.Join(directory, "cases.jsonl")); err != nil {
		t.Skipf("symbolic links are unavailable in this test environment: %v", err)
	}
	if err := validateCorpusDirectory(directory); err == nil {
		t.Fatal("development directory with a symbolic-link case file was accepted")
	}
}

func canonicalManifestForTest() manifest {
	return manifest{
		SchemaVersion:                        1,
		Dataset:                              developmentDatasetID,
		DevelopmentOnly:                      true,
		FutureHoldoutEligible:                false,
		DerivedFromPublicAdversarialTaxonomy: true,
		ContainsLivePayloads:                 false,
		Notice:                               "Visible development-only canaries must never become a future holdout.",
		Cases:                                "cases.jsonl",
		RequiredFamilies:                     append([]string(nil), canonicalDevelopmentFamilies...),
		RequiredProtocols:                    append([]string(nil), canonicalDevelopmentProtocols...),
		RequiredCarriers:                     append([]string(nil), canonicalDevelopmentCarriers...),
		RequiredTransforms:                   append([]string(nil), canonicalDevelopmentTransforms...),
		RequiredSourceContexts:               append([]string(nil), canonicalDevelopmentSourceContexts...),
	}
}
