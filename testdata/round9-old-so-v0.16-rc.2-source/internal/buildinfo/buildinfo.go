// Package buildinfo exposes immutable-at-runtime release metadata. The string
// variables are intentionally set only by Go linker -X flags in release builds.
package buildinfo

import "strings"

const StreamingScannerIdentity = "streaming-scanner-v1"

var (
	Version        = "0.16"
	Commit         = "unknown"
	RulesetVersion = "1.0.9"
	RulesetSHA256  = "unknown"
	Dirty          = "true"
)

// Info is the management-safe build metadata snapshot.
type Info struct {
	Version          string `json:"version"`
	Commit           string `json:"commit"`
	RulesetVersion   string `json:"ruleset_version"`
	RulesetSHA256    string `json:"ruleset_sha256"`
	StreamingScanner string `json:"streaming_scanner"`
	Dirty            bool   `json:"dirty"`
}

// Current returns a copy so callers cannot mutate package metadata through a
// shared reference.
func Current() Info {
	return Info{
		Version:          strings.TrimSpace(Version),
		Commit:           strings.TrimSpace(Commit),
		RulesetVersion:   strings.TrimSpace(RulesetVersion),
		RulesetSHA256:    strings.ToLower(strings.TrimSpace(RulesetSHA256)),
		StreamingScanner: StreamingScannerIdentity,
		Dirty:            strings.EqualFold(strings.TrimSpace(Dirty), "true"),
	}
}
