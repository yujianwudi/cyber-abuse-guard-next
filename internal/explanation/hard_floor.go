// Package explanation defines closed, privacy-safe decision explanation codes
// shared by the classifier and the audit persistence boundary.
package explanation

// HardFloorReason identifies the exact admission path that allowed a score to
// be raised to a rule hard floor. Values are stable identifiers only; they must
// never contain request text or caller-controlled metadata.
type HardFloorReason string

const (
	HardFloorReasonNone HardFloorReason = ""

	HardFloorReasonCompleteCoreOwnedActiveScopeWithTwoStrongQualifiers HardFloorReason = "complete_core_owned_active_scope_with_two_strong_qualifiers"
	HardFloorReasonExplicitCredentialTheftCore                         HardFloorReason = "explicit_credential_theft_core"
	HardFloorReasonExplicitCredentialHostileAccessCore                 HardFloorReason = "explicit_credential_hostile_access_core"
	HardFloorReasonExplicitDisruptionHostileOutcomeCore                HardFloorReason = "explicit_disruption_hostile_outcome_core"
	HardFloorReasonExplicitDisruptionOperationalCore                   HardFloorReason = "explicit_disruption_operational_core"
	HardFloorReasonImplementationFollowUpToOwnedPriorCore              HardFloorReason = "implementation_follow_up_to_owned_prior_core"
	HardFloorReasonCompleteCoreWithIndependentQualifier                HardFloorReason = "complete_core_with_independent_qualifier"

	HardFloorReasonOutcomeCompleteCoreWithTwoQualifiers  HardFloorReason = "outcome_complete_core_with_two_qualifiers"
	HardFloorReasonComposedCompleteCoreWithTwoQualifiers HardFloorReason = "composed_complete_core_with_two_qualifiers"
	HardFloorReasonSemanticCompleteCoreWithTwoRiskAxes   HardFloorReason = "semantic_complete_core_with_two_risk_axes"
	HardFloorReasonPersistentControlPlaneBlockThreshold  HardFloorReason = "persistent_control_plane_block_threshold"
)

// IsKnownAppliedHardFloorReason reports whether reason is one of the closed,
// non-empty codes that may accompany hard_floor_applied=true.
func IsKnownAppliedHardFloorReason(reason HardFloorReason) bool {
	switch reason {
	case HardFloorReasonCompleteCoreOwnedActiveScopeWithTwoStrongQualifiers,
		HardFloorReasonExplicitCredentialTheftCore,
		HardFloorReasonExplicitCredentialHostileAccessCore,
		HardFloorReasonExplicitDisruptionHostileOutcomeCore,
		HardFloorReasonExplicitDisruptionOperationalCore,
		HardFloorReasonImplementationFollowUpToOwnedPriorCore,
		HardFloorReasonCompleteCoreWithIndependentQualifier,
		HardFloorReasonOutcomeCompleteCoreWithTwoQualifiers,
		HardFloorReasonComposedCompleteCoreWithTwoQualifiers,
		HardFloorReasonSemanticCompleteCoreWithTwoRiskAxes,
		HardFloorReasonPersistentControlPlaneBlockThreshold:
		return true
	default:
		return false
	}
}
