package csamtext

// CSAMTextPolicyVersion identifies the independent CSAM text behavior
// contract. It is deliberately separate from the legacy classifier policy and
// YAML ruleset versions.
const CSAMTextPolicyVersion = "csam-text-policy-v1"

// CSAMTextPolicySHA256 binds the deterministic CSAM classifier, its private
// result proof, bounded extractor/stream handoff, plugin disposition, audit
// explanation, persistence, counters, and management projection sources listed
// in policy_identity_test.go. The declaration file itself stays outside the
// digest so the compiled hash is not recursive.
const CSAMTextPolicySHA256 = "cf5ec76e6d5ac7a50decebd5d74b1a5f81fb6d077693b8a2f5736591ca1211b3"

// PolicyIdentity contains only stable, low-sensitivity compiled identifiers.
// It never contains request text, evidence spans, offsets, or request hashes.
type PolicyIdentity struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// CurrentPolicyIdentity returns the compiled CSAM text policy identity.
func CurrentPolicyIdentity() PolicyIdentity {
	return PolicyIdentity{Version: CSAMTextPolicyVersion, SHA256: CSAMTextPolicySHA256}
}
