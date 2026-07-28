package plugin

import (
	"github.com/yujianwudi/cyber-abuse-guard/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard/internal/config"
)

// shouldPersistInspectionDecision keeps complete non-user or untrusted
// wrapper-only control-plane findings on the low-cardinality counter path by
// default. Trusted-user findings retain per-request audit attribution; the
// counter-only optimization is for provider/tool wrapper traffic, where an
// event adds write and hashing cost without adding a security disposition.
// Operators that need the legacy wrapper event stream can opt back in.
func shouldPersistInspectionDecision(cfg config.Config, outcome inspectionOutcome, decision inspectionDecision) bool {
	if !decision.Block && !decision.Audit {
		return false
	}
	if cfg.Audit.PersistWrapperOnly {
		return true
	}
	return !isCounterOnlyWrapperAudit(outcome, decision)
}

func isCounterOnlyWrapperAudit(outcome inspectionOutcome, decision inspectionDecision) bool {
	behavior := outcome.Classification.Behavior
	return decision.Audit && !decision.Block &&
		decision.Code == "audit_suspicious_text" && decision.Category == "" &&
		len(outcome.Incomplete) == 0 && !outcome.OpaqueMedia &&
		outcome.Classification.Action == classifier.ActionAudit &&
		outcome.Classification.Category == "" &&
		outcome.Classification.FindingOrigin == classifier.FindingOriginNonUserOrUntrusted &&
		outcome.Classification.Coverage.State == classifier.CoverageComplete &&
		behavior != nil && behavior.Wrapper && !behavior.BaseBehavior
}
