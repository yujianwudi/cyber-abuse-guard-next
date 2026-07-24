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

	Version = " 0.16 "
	Commit = " abc123 "
	RulesetVersion = " 1.0.7 "
	RulesetSHA256 = " AABBCC "
	Dirty = " FALSE "

	got := Current()
	if got.Version != "0.16" || got.Commit != "abc123" || got.RulesetVersion != "1.0.7" || got.RulesetSHA256 != "aabbcc" ||
		got.StreamingScanner != StreamingScannerIdentity || got.Dirty {
		t.Fatalf("Current() = %#v", got)
	}
}

func TestDefaultVersionUsesExactTwoPartV016(t *testing.T) {
	switch Version {
	case "0.16":
		return
	case "0.16.0":
		t.Fatal("Version must not use the unsupported 0.16.0 alias")
	default:
		t.Fatalf("Version = %q, want exact two-part release version 0.16", Version)
	}
}
