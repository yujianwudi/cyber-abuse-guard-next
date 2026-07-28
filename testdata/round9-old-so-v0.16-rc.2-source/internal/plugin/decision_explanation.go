package plugin

import (
	"sort"
	"strings"

	"github.com/yujianwudi/cyber-abuse-guard/internal/audit"
	"github.com/yujianwudi/cyber-abuse-guard/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
)

// auditDecisionExplanation converts the classifier's bounded explanation into
// the separately validated persistence contract. It deliberately ignores
// occurrence offsets and all request text.
func auditDecisionExplanation(result classifier.Result) *audit.DecisionExplanation {
	source := result.DecisionExplanation
	if source == nil {
		return nil
	}

	evidence := classifierEvidenceIDs(result.EvidenceOccurrences)
	// Keep this mapping closed and aligned with the classifier's scoring
	// contract. Semantic core dimensions are harm/object/action/outcome, while
	// ordinary and composed candidates use intent/object. Unknown kinds are
	// deliberately not persisted.
	coreEvidence := mergeEvidenceIDs(
		evidence["intent"], evidence["object"], evidence["harm"],
		evidence["action"], evidence["outcome"],
	)
	qualifierEvidence := mergeEvidenceIDs(
		evidence["operational"], evidence["target"], evidence["destination"],
		evidence["evasion"], evidence["scale"], evidence["sequence"],
		evidence["impact"], evidence["meta_override"],
	)

	crossSegment := "none"
	if source.CrossSegmentComposition {
		crossSegment = "bounded_same_scope"
		if source.ReferentLinkUsed {
			crossSegment = "explicit_referent"
		}
	}

	return &audit.DecisionExplanation{
		WinningRuleID:   source.WinningRuleID,
		WinningCategory: source.WinningCategory,
		ScoreBreakdown: []audit.ScoreComponent{
			{Dimension: "core_predicate_score", Points: source.ScoreBreakdown.CorePredicateScore, EvidenceIDs: coreEvidence},
			{Dimension: "qualifier_score", Points: source.ScoreBreakdown.QualifierScore, EvidenceIDs: qualifierEvidence},
			{Dimension: "scope_coherence_score", Points: source.ScoreBreakdown.ScopeCoherenceScore},
			{Dimension: "ownership_score", Points: source.ScoreBreakdown.OwnershipScore},
			{Dimension: "active_directive_score", Points: source.ScoreBreakdown.ActiveDirectiveScore},
			{Dimension: "context_adjustment", Points: source.ScoreBreakdown.ContextAdjustment},
			{Dimension: "contradiction_adjustment", Points: source.ScoreBreakdown.ContradictionAdjustment},
			{Dimension: "final_score", Points: source.ScoreBreakdown.FinalScore},
		},
		CorePredicateComplete:   source.CorePredicateComplete,
		EvidenceDimensionMask:   uint64(source.EvidenceDimensionMask),
		EvidenceOccurrenceCount: source.EvidenceOccurrenceCount,
		EvidenceSegmentCount:    source.EvidenceSegmentCount,
		WinningRole:             string(source.WinningRole),
		WinningProvenance:       auditProvenanceCode(source.WinningProvenance),
		CurrentTurnEvidence:     source.CurrentTurnEvidence,
		CrossSegmentComposition: crossSegment,
		ReferentLinkUsed:        source.ReferentLinkUsed,
		QuotedOrInertSuppressed: source.QuotedOrInertSuppressed,
		ContextAdjustment:       source.ContextAdjustment,
		HardFloorApplied:        source.HardFloorApplied,
		HardFloorReason:         string(source.HardFloorReason),
	}
}

// auditDecisionExplanationForDecision keeps the classifier explanation bound
// to the top-level decision it actually explains. Incomplete-inspection and
// opaque-media dispositions use separate categories and therefore must not be
// paired with a classifier winner from a different taxonomy.
func auditDecisionExplanationForDecision(
	result classifier.Result,
	decisionCategory string,
	complete bool,
) *audit.DecisionExplanation {
	if !complete || decisionCategory != string(result.Category) {
		return nil
	}
	return auditDecisionExplanation(result)
}

// applyAuditDecisionExplanationLoggingPolicy keeps the structured explanation
// inside the same disclosure boundary as the legacy audit fields. Score,
// provenance, ownership, and bounded counts remain useful when identifiers are
// disabled, but category, rule, and rule-derived evidence IDs must not bypass
// the operator's existing log_category/log_rule_ids choices.
func applyAuditDecisionExplanationLoggingPolicy(
	explanation *audit.DecisionExplanation,
	logCategory bool,
	logRuleIDs bool,
) *audit.DecisionExplanation {
	if explanation == nil {
		return nil
	}
	if !logCategory {
		explanation.WinningCategory = ""
	}
	if !logRuleIDs {
		explanation.WinningRuleID = ""
		for index := range explanation.ScoreBreakdown {
			explanation.ScoreBreakdown[index].EvidenceIDs = nil
		}
	}
	return explanation
}

func classifierEvidenceIDs(occurrences []classifier.EvidenceOccurrence) map[string][]string {
	byDimension := make(map[string][]string)
	seen := make(map[string]map[string]struct{})
	for _, occurrence := range occurrences {
		ruleID := strings.TrimSpace(occurrence.RuleID)
		dimension := strings.TrimSpace(occurrence.Dimension)
		if ruleID == "" || dimension == "" {
			continue
		}
		identifier := strings.TrimSpace(occurrence.EvidenceID)
		if identifier == "" {
			identifier = ruleID + ":" + dimension
		}
		if seen[dimension] == nil {
			seen[dimension] = make(map[string]struct{})
		}
		if _, duplicate := seen[dimension][identifier]; duplicate {
			continue
		}
		seen[dimension][identifier] = struct{}{}
		byDimension[dimension] = append(byDimension[dimension], identifier)
	}
	for dimension := range byDimension {
		sort.Strings(byDimension[dimension])
	}
	return byDimension
}

func mergeEvidenceIDs(groups ...[]string) []string {
	seen := make(map[string]struct{})
	merged := make([]string, 0)
	for _, group := range groups {
		for _, identifier := range group {
			if _, duplicate := seen[identifier]; duplicate {
				continue
			}
			seen[identifier] = struct{}{}
			merged = append(merged, identifier)
		}
	}
	sort.Strings(merged)
	return merged
}

func auditProvenanceCode(provenance extract.SegmentProvenance) string {
	switch provenance {
	case extract.ProvenanceContent:
		return "content"
	case extract.ProvenanceToolPayload:
		return "tool_payload"
	default:
		return "unknown"
	}
}
