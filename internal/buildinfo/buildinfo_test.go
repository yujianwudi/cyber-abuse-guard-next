package buildinfo

import "testing"

func TestCurrentReturnsNormalizedCopy(t *testing.T) {
	originalVersion, originalCommit := Version, Commit
	originalRulesetVersion, originalRulesetSHA := RulesetVersion, RulesetSHA256
	originalDirty := Dirty
	t.Cleanup(func() {
		Version, Commit = originalVersion, originalCommit
		RulesetVersion, RulesetSHA256 = originalRulesetVersion, originalRulesetSHA
		Dirty = originalDirty
	})

	Version = " 1.0.0 "
	Commit = " abc123 "
	RulesetVersion = " 1.0.7 "
	RulesetSHA256 = " AABBCC "
	Dirty = " FALSE "

	got := Current()
	if got.Version != "1.0.0" || got.Commit != "abc123" || got.RulesetVersion != "1.0.7" || got.RulesetSHA256 != "aabbcc" ||
		got.StreamingScanner != StreamingScannerIdentity || got.Dirty {
		t.Fatalf("Current() = %#v", got)
	}
}

func TestDefaultVersionMatchesV100Release(t *testing.T) {
	if Version != "1.0.0" {
		t.Fatalf("Version = %q, want release version 1.0.0", Version)
	}
}
