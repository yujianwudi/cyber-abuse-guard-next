package classifier

// ClassifierPolicyVersion identifies the behavior-model contract independently
// from the separately versioned YAML ruleset.
const ClassifierPolicyVersion = "classifier-policy-v7"

// ClassifierPolicySHA256 binds the deterministic classifier, role handling,
// bounded extractor, rules schema, and embedded policy sources listed in
// policy_identity_test.go. It is updated only when one of those sources changes.
const ClassifierPolicySHA256 = "ea8c4dcfacacc6478f86fd2ca5de96d667ae98f2fc6ff0c83d8e6092e9f6a82d"

// PolicyIdentity is safe to expose through management or audit metadata: it
// contains only stable identifiers and never includes request text.
type PolicyIdentity struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

// CurrentPolicyIdentity returns the compiled classifier behavior identity.
func CurrentPolicyIdentity() PolicyIdentity {
	return PolicyIdentity{Version: ClassifierPolicyVersion, SHA256: ClassifierPolicySHA256}
}
