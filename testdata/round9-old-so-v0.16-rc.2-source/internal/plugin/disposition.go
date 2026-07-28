package plugin

import (
	"github.com/yujianwudi/cyber-abuse-guard/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard/internal/config"
	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
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
	Category        string
	RouteReason     string
}

func inspectionDisposition(mode config.Mode, outcome inspectionOutcome, opaquePolicy config.OpaqueMediaPolicy) inspectionDecision {
	if len(outcome.Incomplete) != 0 {
		category := incompleteCategory(outcome.Incomplete)
		switch mode {
		case config.ModeObserve:
			return inspectionDecision{
				Observe:     true,
				Code:        "observe_incomplete_inspection",
				Category:    category,
				RouteReason: incompleteRouteReason(category),
			}
		case config.ModeAudit:
			return inspectionDecision{
				Audit:       true,
				Code:        "audit_incomplete_inspection",
				Category:    category,
				RouteReason: incompleteRouteReason(category),
			}
		case config.ModeBalanced:
			return inspectionDecision{
				Audit:       true,
				Code:        "allow_due_to_incomplete_inspection",
				Category:    category,
				RouteReason: incompleteRouteReason(category),
			}
		case config.ModeStrict:
			return inspectionDecision{
				Block:       true,
				Code:        "block_due_to_incomplete_inspection",
				Category:    category,
				RouteReason: incompleteRouteReason(category),
			}
		default:
			return inspectionDecision{
				Code:        "allow_incomplete_inspection_off",
				Category:    category,
				RouteReason: incompleteRouteReason(category),
			}
		}
	}

	decision := inspectionDecision{Code: "allow_clean"}
	if outcome.Classification.Action != classifier.ActionAllow {
		switch mode {
		case config.ModeAudit, config.ModeBalanced, config.ModeStrict:
			decision.EvaluateSubject = true
		}
	}
	if behavior := outcome.Classification.Behavior; behavior != nil && behavior.Wrapper && !behavior.BaseBehavior {
		// Wrapper-only control-plane evidence is observable, but it is not a
		// cyber-abuse behavior and must not accumulate subject risk. A standalone
		// persistent-injection block remains enforced by the current classification
		// below; this flag controls only cross-request subject accounting.
		decision.EvaluateSubject = false
	}

	switch outcome.Classification.Action {
	case classifier.ActionBlock:
		decision.Category = string(outcome.Classification.Category)
		switch mode {
		case config.ModeObserve:
			decision.Observe = true
			decision.Code = "observe_malicious_text"
		case config.ModeAudit:
			decision.Audit = true
			decision.Code = "audit_malicious_text"
		case config.ModeBalanced, config.ModeStrict:
			decision.Block = true
			decision.Code = "block_malicious_text"
			decision.RouteReason = "cyber_abuse_guard_policy"
		}
	case classifier.ActionAudit:
		decision.Category = string(outcome.Classification.Category)
		switch mode {
		case config.ModeObserve:
			decision.Observe = true
			decision.Code = "observe_suspicious_text"
		case config.ModeAudit, config.ModeBalanced, config.ModeStrict:
			decision.Audit = true
			decision.Code = "audit_suspicious_text"
		}
	case classifier.ActionObserve:
		if mode == config.ModeObserve {
			decision.Observe = true
			decision.Code = "observe_suspicious_text"
			decision.Category = string(outcome.Classification.Category)
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
					decision.Category = "opaque_media"
				}
			case config.ModeAudit:
				if outcome.Classification.Action == classifier.ActionAllow {
					decision.Audit = true
					decision.Code = "audit_opaque_media"
					decision.Category = "opaque_media"
				}
			case config.ModeBalanced, config.ModeStrict:
				decision.Audit = false
				decision.Observe = false
				decision.Block = true
				decision.Code = "block_opaque_media"
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
				decision.Category = "opaque_media"
			case config.ModeAudit, config.ModeBalanced, config.ModeStrict:
				decision.Audit = true
				decision.Code = "allow_with_opaque_media_audit"
				decision.Category = "opaque_media"
			}
		}
	}

	if outcome.SubjectBlocked {
		switch mode {
		case config.ModeAudit:
			decision.Audit = true
			decision.Code = "audit_subject_risk"
		case config.ModeBalanced, config.ModeStrict:
			decision.Audit = false
			decision.Block = true
			decision.Code = "block_subject_risk"
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
