package plugin

import (
	"strings"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/config"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

// inspectionOutcome contains only bounded, request-independent policy inputs.
// In particular, parser errors and multipart metadata never cross this policy
// boundary as strings.
type inspectionOutcome struct {
	Classification classifier.Result
	Incomplete     []extract.IncompleteReason
	OpaqueMedia    bool
	SubjectBlocked bool
}

// decisionKind is the mutually exclusive top-level reason for the transport
// disposition. It is deliberately separate from the mode-specific Code: an
// incomplete, opaque-media, or subject-risk block must never masquerade as a
// malicious-text classifier decision.
type decisionKind string

const (
	decisionAllowClean                 decisionKind = "allow_clean"
	decisionAuditIneligibleRisk        decisionKind = "audit_ineligible_risk"
	decisionAuditEligibleMaliciousText decisionKind = "audit_eligible_malicious_text"
	decisionBlockMaliciousText         decisionKind = "block_malicious_text"
	decisionBlockIncomplete            decisionKind = "block_incomplete_inspection"
	decisionBlockOpaqueMedia           decisionKind = "block_opaque_media"
	decisionBlockSubjectRisk           decisionKind = "block_subject_risk"
)

// inspectionDecision is the complete transport disposition for an inspected
// request. Exactly one of Block, Audit, or Observe is normally set; all three
// are false for a clean allow. EvaluateSubject is deliberately false for
// incomplete inspection, a complete clean allow, and wrapper-only control
// evidence, so neither a prefix nor non-risk traffic enters subject state.
type inspectionDecision struct {
	Block           bool
	Audit           bool
	Observe         bool
	EvaluateSubject bool
	Code            string
	Kind            decisionKind
	Category        string
	RouteReason     string
}

// eligibleMaliciousWinner is the final plugin-side fail-closed contract for a
// malicious-text block. A legacy/bare ActionBlock, a score-only hard floor, or
// a result without a closed candidate explanation is not sufficient.
func eligibleMaliciousWinner(result classifier.Result) bool {
	gate := result.BlockEligibility
	explanation := result.DecisionExplanation
	if result.Truncated || (result.Coverage.State != "" && result.Coverage.State != classifier.CoverageComplete) ||
		gate == nil || explanation == nil || !result.CandidateIdentityBlockingProofComplete() ||
		!candidateOccurrencesComplete(result) {
		return false
	}
	winnerCount := 0
	for _, ruleID := range result.RuleIDs {
		if ruleID == explanation.WinningRuleID {
			winnerCount++
		}
	}
	return winnerCount == 1 && gate.Eligible && gate.PrimaryReason == classifier.GateEligibleExplicitMalice &&
		gate.InspectionComplete && gate.RequestBlockAuthorityProven() &&
		gate.CurrentExecutionActProven && gate.HarmfulCoreComplete && gate.OperationallyActionable &&
		!gate.DefensiveScopeConflict && !gate.QuotedOrAnalyticalScope && !gate.CrossScopeComposition &&
		gate.ReferentProofComplete && !gate.EvidenceAmbiguous &&
		explanation.BlockEligible && eligibilityExplanationMatches(*gate, *explanation) &&
		explanation.PrimaryEligibilityReason == classifier.GateEligibleExplicitMalice &&
		explanation.WinningRuleID != "" && explanation.WinningCategory != "" &&
		string(result.Category) == explanation.WinningCategory
}

// candidateOccurrencesComplete validates the public, content-free side of the
// classifier's private candidate identity. The private proof prevents callers
// from manufacturing a blockable Result; these checks additionally keep the
// winner, explanation counts, and exported occurrences in one closed contract.
func candidateOccurrencesComplete(result classifier.Result) bool {
	gate := result.BlockEligibility
	explanation := result.DecisionExplanation
	if gate == nil || explanation == nil || len(result.EvidenceOccurrences) == 0 ||
		explanation.EvidenceOccurrenceCount != len(result.EvidenceOccurrences) ||
		explanation.EvidenceSegmentCount <= 0 {
		return false
	}
	ruleIDs := make(map[string]struct{}, len(result.RuleIDs))
	for _, ruleID := range result.RuleIDs {
		ruleID = strings.TrimSpace(ruleID)
		if ruleID == "" {
			return false
		}
		ruleIDs[ruleID] = struct{}{}
	}
	seenEvidence := make(map[string]struct{}, len(result.EvidenceOccurrences))
	for _, occurrence := range result.EvidenceOccurrences {
		evidenceID := strings.TrimSpace(occurrence.EvidenceID)
		ruleID := strings.TrimSpace(occurrence.RuleID)
		// Provider-native top-level system envelopes and the explicit unindexed
		// terminal-tool fallback do not belong to a numbered conversation item, so
		// -1 is their valid SegmentID sentinel. Accept it only when the closed
		// request-local scope, role, provenance, attribution, current-turn marker,
		// and directive owner all agree; every other negative coordinate remains
		// fail-closed as unbound evidence.
		unindexedRequestLocalCarrier := occurrence.SegmentID == -1 &&
			occurrence.Provenance == extract.ProvenanceContent &&
			occurrence.UserAttribution == extract.UserAttributionUntrusted &&
			!occurrence.CurrentTurn &&
			(gate.EnforcementScope == classifier.EnforcementScopeRequestLocalSystem &&
				occurrence.Role == extract.RoleSystem &&
				occurrence.DirectiveOwner == classifier.DirectiveOwnerSystem ||
				gate.EnforcementScope == classifier.EnforcementScopeRequestLocalTool &&
					occurrence.Role == extract.RoleTool &&
					occurrence.DirectiveOwner == classifier.DirectiveOwnerTool)
		if evidenceID == "" || ruleID == "" || strings.TrimSpace(occurrence.Dimension) == "" ||
			occurrence.SegmentID < 0 && !unindexedRequestLocalCarrier || occurrence.FieldID < 0 ||
			occurrence.DirectiveOwner == classifier.DirectiveOwnerUnknown ||
			occurrence.Polarity == "" {
			return false
		}
		switch occurrence.Role {
		case extract.RoleUser, extract.RoleSystem, extract.RoleAssistant, extract.RoleTool:
		default:
			return false
		}
		switch occurrence.Provenance {
		case extract.ProvenanceContent, extract.ProvenanceToolPayload:
		default:
			return false
		}
		if _, duplicate := seenEvidence[evidenceID]; duplicate {
			return false
		}
		seenEvidence[evidenceID] = struct{}{}
		if _, present := ruleIDs[ruleID]; !present {
			return false
		}
	}
	return true
}

func eligibilityExplanationMatches(
	gate classifier.CandidateBlockEligibility,
	explanation classifier.DecisionExplanation,
) bool {
	return explanation.BlockEligible == gate.Eligible &&
		explanation.PrimaryEligibilityReason == gate.PrimaryReason &&
		explanation.EligibilityReasonFlags == gate.ReasonFlags &&
		explanation.InspectionComplete == gate.InspectionComplete &&
		explanation.EvidenceOwnedByCurrentUser == gate.EvidenceOwnedByCurrentUser &&
		explanation.EnforcementScope == gate.EnforcementScope &&
		explanation.CurrentExecutionActProven == gate.CurrentExecutionActProven &&
		explanation.HarmfulCoreComplete == gate.HarmfulCoreComplete &&
		explanation.OperationallyActionable == gate.OperationallyActionable &&
		explanation.AuthorizationClaimState == gate.AuthorizationClaim &&
		explanation.ExplicitVictimOrNonConsent == gate.ExplicitVictimOrNonConsent &&
		explanation.CovertAcquisition == gate.CovertAcquisition &&
		explanation.ExfiltrationOrTakeover == gate.ExfiltrationOrTakeover &&
		explanation.MaliciousPersistence == gate.MaliciousPersistence &&
		explanation.DestructiveOutcome == gate.DestructiveOutcome &&
		explanation.SecurityControlEvasion == gate.SecurityControlEvasion &&
		explanation.DefensiveScopeConflict == gate.DefensiveScopeConflict &&
		explanation.QuotedOrAnalyticalScope == gate.QuotedOrAnalyticalScope &&
		explanation.CrossScopeComposition == gate.CrossScopeComposition &&
		explanation.ReferentProofComplete == gate.ReferentProofComplete &&
		explanation.EvidenceAmbiguous == gate.EvidenceAmbiguous
}

const metaOverrideRuleID = "META-OVERRIDE-001"

// standaloneMetaControlResult identifies the narrow Round 9 case where an
// active current-user control-plane request is itself the eligible malicious
// winner. It remains a local malicious-text block with the defense-evasion
// taxonomy, but it is not cross-request subject-risk evidence. An ordinary
// Cyber Abuse winner merely amplified by META-OVERRIDE-001 retains its own rule
// ID and therefore does not match this predicate.
func standaloneMetaControlResult(result classifier.Result) bool {
	if len(result.RuleIDs) != 1 || result.RuleIDs[0] != metaOverrideRuleID {
		return false
	}
	if result.Category != "" && result.Category != rules.CategoryEvasion {
		return false
	}
	explanation := result.DecisionExplanation
	return explanation == nil || explanation.WinningRuleID == metaOverrideRuleID
}

func inspectionDisposition(mode config.Mode, outcome inspectionOutcome, opaquePolicy config.OpaqueMediaPolicy) inspectionDecision {
	if len(outcome.Incomplete) != 0 {
		category := incompleteCategory(outcome.Incomplete)
		switch mode {
		case config.ModeObserve:
			return inspectionDecision{
				Observe:     true,
				Code:        "observe_incomplete_inspection",
				Kind:        decisionAuditIneligibleRisk,
				Category:    category,
				RouteReason: incompleteRouteReason(category),
			}
		case config.ModeAudit:
			return inspectionDecision{
				Audit:       true,
				Code:        "audit_incomplete_inspection",
				Kind:        decisionAuditIneligibleRisk,
				Category:    category,
				RouteReason: incompleteRouteReason(category),
			}
		case config.ModeBalanced:
			return inspectionDecision{
				Audit:       true,
				Code:        "allow_due_to_incomplete_inspection",
				Kind:        decisionAuditIneligibleRisk,
				Category:    category,
				RouteReason: incompleteRouteReason(category),
			}
		case config.ModeStrict:
			return inspectionDecision{
				Block:       true,
				Code:        "block_due_to_incomplete_inspection",
				Kind:        decisionBlockIncomplete,
				Category:    category,
				RouteReason: incompleteRouteReason(category),
			}
		default:
			return inspectionDecision{
				Code:        "allow_incomplete_inspection_off",
				Kind:        decisionAuditIneligibleRisk,
				Category:    category,
				RouteReason: incompleteRouteReason(category),
			}
		}
	}

	decision := inspectionDecision{Code: "allow_clean", Kind: decisionAllowClean}
	eligibleWinner := eligibleMaliciousWinner(outcome.Classification)
	if eligibleWinner && outcome.Classification.Action != classifier.ActionAllow &&
		outcome.Classification.BlockEligibility != nil &&
		outcome.Classification.BlockEligibility.EvidenceOwnedByCurrentUser {
		switch mode {
		case config.ModeAudit, config.ModeBalanced, config.ModeStrict:
			decision.EvaluateSubject = true
		}
	}
	if behavior := outcome.Classification.Behavior; standaloneMetaControlResult(outcome.Classification) ||
		behavior != nil && behavior.Wrapper && !behavior.BaseBehavior {
		// Ineligible wrapper-only evidence and the narrow eligible standalone META
		// winner are observable/enforceable at request level, but neither is
		// cross-request subject-risk evidence. The classification and local block
		// remain unchanged; this flag controls only subject accounting.
		decision.EvaluateSubject = false
	}

	switch outcome.Classification.Action {
	case classifier.ActionBlock:
		decision.Category = string(outcome.Classification.Category)
		if !eligibleWinner {
			decision.EvaluateSubject = false
			switch mode {
			case config.ModeObserve:
				decision.Observe = true
				decision.Code = "observe_ineligible_risk"
				decision.Kind = decisionAuditIneligibleRisk
			case config.ModeAudit, config.ModeBalanced, config.ModeStrict:
				decision.Audit = true
				decision.Code = "audit_ineligible_risk"
				decision.Kind = decisionAuditIneligibleRisk
			}
			break
		}
		switch mode {
		case config.ModeObserve:
			decision.Observe = true
			decision.Code = "observe_malicious_text"
			decision.Kind = decisionAuditEligibleMaliciousText
		case config.ModeAudit:
			decision.Audit = true
			decision.Code = "audit_malicious_text"
			decision.Kind = decisionAuditEligibleMaliciousText
		case config.ModeBalanced, config.ModeStrict:
			decision.Block = true
			decision.Code = "block_malicious_text"
			decision.Kind = decisionBlockMaliciousText
			decision.RouteReason = "cyber_abuse_guard_policy"
		}
	case classifier.ActionAudit:
		decision.Category = string(outcome.Classification.Category)
		decision.Kind = decisionAuditIneligibleRisk
		if eligibleWinner {
			decision.Kind = decisionAuditEligibleMaliciousText
		}
		switch mode {
		case config.ModeObserve:
			decision.Observe = true
			decision.Code = "observe_suspicious_text"
			if eligibleWinner {
				decision.Code = "observe_malicious_text"
			}
		case config.ModeAudit, config.ModeBalanced, config.ModeStrict:
			decision.Audit = true
			decision.Code = "audit_suspicious_text"
			if eligibleWinner {
				decision.Code = "audit_malicious_text"
			}
		}
	case classifier.ActionObserve:
		if mode == config.ModeObserve {
			decision.Observe = true
			decision.Code = "observe_suspicious_text"
			decision.Category = string(outcome.Classification.Category)
			decision.Kind = decisionAuditIneligibleRisk
			if eligibleWinner {
				decision.Kind = decisionAuditEligibleMaliciousText
				decision.Code = "observe_malicious_text"
			}
		}
	}

	// A complete malicious-text block always wins and retains its taxonomy.
	// Otherwise an explicit opaque-media block wins over allow/audit/observe in
	// enforcing modes. This keeps the configured media disposition orthogonal to
	// wrapper-only control-plane audits instead of letting an audit downgrade a
	// required opaque-media block.
	if outcome.OpaqueMedia && !decision.Block {
		switch opaquePolicy {
		case config.OpaqueMediaPolicyBlock:
			switch mode {
			case config.ModeObserve:
				if outcome.Classification.Action == classifier.ActionAllow {
					decision.Observe = true
					decision.Code = "observe_opaque_media"
					decision.Kind = decisionAuditIneligibleRisk
					decision.Category = "opaque_media"
				}
			case config.ModeAudit:
				if outcome.Classification.Action == classifier.ActionAllow {
					decision.Audit = true
					decision.Code = "audit_opaque_media"
					decision.Kind = decisionAuditIneligibleRisk
					decision.Category = "opaque_media"
				}
			case config.ModeBalanced, config.ModeStrict:
				decision.Audit = false
				decision.Observe = false
				decision.Block = true
				decision.Code = "block_opaque_media"
				decision.Kind = decisionBlockOpaqueMedia
				decision.Category = "opaque_media"
				decision.RouteReason = "cyber_abuse_guard_opaque_media"
			}
		case config.OpaqueMediaPolicyAudit:
			if outcome.Classification.Action != classifier.ActionAllow {
				break
			}
			switch mode {
			case config.ModeObserve:
				decision.Observe = true
				decision.Code = "observe_opaque_media"
				decision.Kind = decisionAuditIneligibleRisk
				decision.Category = "opaque_media"
			case config.ModeAudit, config.ModeBalanced, config.ModeStrict:
				decision.Audit = true
				decision.Code = "allow_with_opaque_media_audit"
				decision.Kind = decisionAuditIneligibleRisk
				decision.Category = "opaque_media"
			}
		}
	}

	// A request-local, fully proven malicious-text block is the strongest and
	// most specific disposition. Subject state may independently say that the
	// caller is blocked, but it must not erase the classifier winner or replace
	// its category with the subject-risk taxonomy. Subject risk becomes the
	// top-level decision only when this request did not already establish a
	// malicious-text block of its own.
	if outcome.SubjectBlocked {
		decision.EvaluateSubject = false
		if decision.Kind == decisionBlockMaliciousText {
			return decision
		}
		switch mode {
		case config.ModeAudit:
			decision.Audit = true
			decision.Code = "audit_subject_risk"
			decision.Kind = decisionAuditIneligibleRisk
			decision.Category = "subject_risk"
		case config.ModeBalanced, config.ModeStrict:
			decision.Audit = false
			decision.Block = true
			decision.Code = "block_subject_risk"
			decision.Kind = decisionBlockSubjectRisk
			decision.Category = "subject_risk"
			if decision.RouteReason == "" {
				decision.RouteReason = "cyber_abuse_guard_policy"
			}
		}
	}

	return decision
}

func incompleteCategory(reasons []extract.IncompleteReason) string {
	contains := func(targets ...extract.IncompleteReason) bool {
		for _, reason := range reasons {
			for _, target := range targets {
				if reason == target {
					return true
				}
			}
		}
		return false
	}

	// Precedence is fixed rather than dependent on parser discovery order.
	switch {
	case contains(extract.IncompleteRPCBodyLimit):
		return "rpc_body_limit"
	case contains(extract.IncompleteUnsupportedMediaType, extract.IncompleteUnsupportedContentEncoding):
		return "unsupported_content_type"
	case contains(extract.IncompleteMultipartUnknownField,
		extract.IncompleteMultipartTextFieldTypeMismatch):
		return "multipart_schema"
	case contains(extract.IncompleteToolSchema):
		return "tool_schema"
	case contains(extract.IncompleteMultipartBoundaryLimit,
		extract.IncompleteMultipartPartLimit,
		extract.IncompleteMultipartHeaderLimit,
		extract.IncompleteMultipartTextLimit,
		extract.IncompleteMultipartParseError):
		return "multipart_limit"
	case contains(extract.IncompleteParseError):
		return "parse_error"
	case contains(extract.IncompleteJSONDepthLimit):
		return "json_depth_limit"
	case contains(extract.IncompleteTextPartLimit):
		return "text_part_limit"
	case contains(extract.IncompleteRoleAttribution):
		return "role_attribution"
	case contains(extract.IncompleteTotalTextLimit):
		return "total_text_limit"
	case contains(extract.IncompleteClassificationChunkLimit):
		return "classification_chunk_limit"
	case contains(extract.IncompleteDeferredTextCandidateLimit):
		return "deferred_text_limit"
	case contains(extract.IncompleteScanByteLimit,
		extract.IncompleteJSONTokenLimit,
		extract.IncompleteJSONNodeLimit,
		extract.IncompleteTextPartByteLimit,
		extract.IncompleteRawBodyLimit):
		return "scan_limit"
	default:
		return "incomplete_inspection"
	}
}

func incompleteRouteReason(category string) string {
	switch category {
	case "parse_error":
		return "cyber_abuse_guard_parse_error"
	case "scan_limit":
		return "cyber_abuse_guard_scan_limit"
	case "rpc_body_limit":
		return "cyber_abuse_guard_rpc_body_limit"
	case "json_depth_limit":
		return "cyber_abuse_guard_json_depth_limit"
	case "text_part_limit":
		return "cyber_abuse_guard_text_part_limit"
	case "role_attribution":
		return "cyber_abuse_guard_role_attribution"
	case "total_text_limit":
		return "cyber_abuse_guard_total_text_limit"
	case "classification_chunk_limit":
		return "cyber_abuse_guard_classification_chunk_limit"
	case "multipart_limit":
		return "cyber_abuse_guard_multipart_limit"
	case "multipart_schema":
		return "cyber_abuse_guard_multipart_schema"
	case "tool_schema":
		return "cyber_abuse_guard_tool_schema"
	case "deferred_text_limit":
		return "cyber_abuse_guard_deferred_text_limit"
	case "unsupported_content_type":
		return "cyber_abuse_guard_unsupported_content_type"
	default:
		return "cyber_abuse_guard_incomplete_inspection"
	}
}
