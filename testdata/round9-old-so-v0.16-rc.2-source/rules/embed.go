// Package ruledata owns the versioned default YAML assets embedded in the
// plugin. Parsing and validation live in internal/rules.
package ruledata

import "embed"

// FS contains only the checked-in default YAML rule documents.
//
//go:embed contexts.yaml credentials.yaml disruption.yaml evasion.yaml exfiltration.yaml exploitation.yaml malware.yaml manifest.yaml phishing.yaml ransomware.yaml semantics.yaml
var FS embed.FS
