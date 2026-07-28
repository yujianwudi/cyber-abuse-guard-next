package classifier

import (
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/yujianwudi/cyber-abuse-guard/internal/explanation"
	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard/internal/rules"
)

const (
	maxEvidenceOccurrencesPerClause = 256
	ruleDimensionCount              = 6
)

type HardFloorReason = explanation.HardFloorReason

const (
	hardFloorReasonNone = explanation.HardFloorReasonNone

	hardFloorReasonCompleteCoreOwnedActiveScopeWithTwoStrongQualifiers = explanation.HardFloorReasonCompleteCoreOwnedActiveScopeWithTwoStrongQualifiers
	hardFloorReasonExplicitCredentialTheftCore                         = explanation.HardFloorReasonExplicitCredentialTheftCore
	hardFloorReasonExplicitCredentialHostileAccessCore                 = explanation.HardFloorReasonExplicitCredentialHostileAccessCore
	hardFloorReasonExplicitDisruptionHostileOutcomeCore                = explanation.HardFloorReasonExplicitDisruptionHostileOutcomeCore
	hardFloorReasonExplicitDisruptionOperationalCore                   = explanation.HardFloorReasonExplicitDisruptionOperationalCore
	hardFloorReasonImplementationFollowUpToOwnedPriorCore              = explanation.HardFloorReasonImplementationFollowUpToOwnedPriorCore
	hardFloorReasonCompleteCoreWithIndependentQualifier                = explanation.HardFloorReasonCompleteCoreWithIndependentQualifier

	hardFloorReasonOutcomeCompleteCoreWithTwoQualifiers  = explanation.HardFloorReasonOutcomeCompleteCoreWithTwoQualifiers
	hardFloorReasonComposedCompleteCoreWithTwoQualifiers = explanation.HardFloorReasonComposedCompleteCoreWithTwoQualifiers
	hardFloorReasonSemanticCompleteCoreWithTwoRiskAxes   = explanation.HardFloorReasonSemanticCompleteCoreWithTwoRiskAxes
	hardFloorReasonPersistentControlPlaneBlockThreshold  = explanation.HardFloorReasonPersistentControlPlaneBlockThreshold
)

// Polarity is a privacy-safe description of whether an evidence occurrence is
// active or negated. It never carries the matched request text.
type Polarity string

const (
	PolarityAffirmative Polarity = "affirmative"
	PolarityNegated     Polarity = "negated"
)

// DirectiveOwner records the closed role class that owns an active directive.
type DirectiveOwner string

const (
	DirectiveOwnerUnknown   DirectiveOwner = "unknown"
	DirectiveOwnerUser      DirectiveOwner = "user"
	DirectiveOwnerSystem    DirectiveOwner = "system"
	DirectiveOwnerAssistant DirectiveOwner = "assistant"
	DirectiveOwnerTool      DirectiveOwner = "tool"
)

// TermStrength distinguishes core/strong evidence from generic development
// vocabulary. The value is safe to persist because it contains no prompt text.
type TermStrength string

const (
	TermStrengthWeak   TermStrength = "weak"
	TermStrengthStrong TermStrength = "strong"
)

// EvidenceOccurrence is the bounded ownership record for one winning
// occurrence. Offsets refer to the normalized transient directive unit and are
// never sufficient to reconstruct request text.
type EvidenceOccurrence struct {
	EvidenceID      string                    `json:"evidence_id"`
	RuleID          string                    `json:"rule_id"`
	Dimension       string                    `json:"dimension"`
	SegmentID       int                       `json:"segment_id"`
	FieldID         int                       `json:"field_id"`
	Role            extract.Role              `json:"role"`
	Provenance      extract.SegmentProvenance `json:"provenance"`
	UserAttribution extract.UserAttribution   `json:"user_attribution"`
	ClauseID        int                       `json:"clause_id"`
	SentenceID      int                       `json:"sentence_id"`
	Start           int                       `json:"start"`
	End             int                       `json:"end"`
	Polarity        Polarity                  `json:"polarity"`
	Quoted          bool                      `json:"quoted"`
	Inert           bool                      `json:"inert"`
	CurrentTurn     bool                      `json:"current_turn"`
	DirectiveOwner  DirectiveOwner            `json:"directive_owner"`
	TermStrength    TermStrength              `json:"term_strength"`
}

// ScoreBreakdown explains a decision using bounded numeric components only.
type ScoreBreakdown struct {
	CorePredicateScore      int `json:"core_predicate_score"`
	QualifierScore          int `json:"qualifier_score"`
	ScopeCoherenceScore     int `json:"scope_coherence_score"`
	OwnershipScore          int `json:"ownership_score"`
	ActiveDirectiveScore    int `json:"active_directive_score"`
	ContextAdjustment       int `json:"context_adjustment"`
	ContradictionAdjustment int `json:"contradiction_adjustment"`
	FinalScore              int `json:"final_score"`
}

// DecisionExplanation is safe for audit/status output. It intentionally
// contains only stable identifiers, enums, counters, masks, and booleans.
type DecisionExplanation struct {
	WinningRuleID           string                    `json:"winning_rule_id,omitempty"`
	WinningCategory         string                    `json:"winning_category,omitempty"`
	ScoreBreakdown          ScoreBreakdown            `json:"score_breakdown"`
	CorePredicateComplete   bool                      `json:"core_predicate_complete"`
	EvidenceDimensionMask   uint16                    `json:"evidence_dimension_mask"`
	EvidenceOccurrenceCount int                       `json:"evidence_occurrence_count"`
	EvidenceSegmentCount    int                       `json:"evidence_segment_count"`
	WinningRole             extract.Role              `json:"winning_role,omitempty"`
	WinningProvenance       extract.SegmentProvenance `json:"winning_provenance,omitempty"`
	CurrentTurnEvidence     bool                      `json:"current_turn_evidence"`
	CrossSegmentComposition bool                      `json:"cross_segment_composition"`
	ReferentLinkUsed        bool                      `json:"referent_link_used"`
	// QuotedOrInertSuppressed is request-level diagnostic metadata. It is true
	// when any non-empty quoted, inert, or trusted carrier content was excluded
	// from active evidence (or capped to audit) anywhere in the inspected
	// request. It does not mean that the winning evidence itself was suppressed;
	// WinningRole, WinningProvenance, and the evidence counters describe the
	// winning decision.
	QuotedOrInertSuppressed bool            `json:"quoted_or_inert_suppressed"`
	ContextAdjustment       int             `json:"context_adjustment"`
	HardFloorApplied        bool            `json:"hard_floor_applied"`
	HardFloorReason         HardFloorReason `json:"hard_floor_reason,omitempty"`
}

type signalOccurrence struct {
	// Classifier inputs are capped well below MaxInt32 runes, and the compiled
	// signal table is likewise bounded. Packing these transient offsets keeps a
	// candidate-rich occurrence buffer at 16 bytes per entry instead of 40 on
	// 64-bit hosts.
	signalID int32
	clauseID int32
	start    int32
	end      int32
	compact  bool
}

type ruleDimension uint8

const (
	ruleDimensionIntent ruleDimension = iota
	ruleDimensionObject
	ruleDimensionOperational
	ruleDimensionTarget
	ruleDimensionEvasion
	ruleDimensionScale
)

var ruleDimensionKinds = [ruleDimensionCount]string{
	"intent", "object", "operational", "target", "evasion", "scale",
}

type assignedRuleOccurrence struct {
	dimension  ruleDimension
	occurrence signalOccurrence
}

// ruleOccurrenceAssignments keeps the one-occurrence/one-dimension result on
// the stack. A rule has exactly six dimensions, so a growable slice only adds
// allocator pressure while providing no useful capacity.
type ruleOccurrenceAssignments struct {
	items [ruleDimensionCount]assignedRuleOccurrence
	count uint8
}

func (assignments *ruleOccurrenceAssignments) append(item assignedRuleOccurrence) bool {
	if int(assignments.count) >= len(assignments.items) {
		return false
	}
	assignments.items[assignments.count] = item
	assignments.count++
	return true
}

type ruleDirectiveMatch struct {
	found                 bool
	coreComplete          bool
	corePredicateComplete bool
	activeDirective       bool
	derivedIntent         bool
	scopeCoherent         bool
	ownershipValid        bool
	hardFloorEligible     bool
	hardFloorReason       HardFloorReason
	dimensionMask         uint16
	qualifierCount        int
	clauseCount           int
	text                  string
	assigned              ruleOccurrenceAssignments
}

func (match ruleDirectiveMatch) has(dimension ruleDimension) bool {
	return match.dimensionMask&(uint16(1)<<dimension) != 0
}

type occurrenceKey struct {
	clauseID int32
	start    int32
	end      int32
}

type occurrenceChoice struct {
	key        occurrenceKey
	dimensions uint16
	present    uint16
	signals    [ruleDimensionCount]signalOccurrence
}

func sortSignalOccurrencesByPhysicalLocation(occurrences []signalOccurrence) {
	for index := 1; index < len(occurrences); index++ {
		candidate := occurrences[index]
		position := index
		for position > 0 && signalOccurrenceLess(candidate, occurrences[position-1]) {
			occurrences[position] = occurrences[position-1]
			position--
		}
		occurrences[position] = candidate
	}
}

func signalOccurrenceLess(left, right signalOccurrence) bool {
	if left.clauseID != right.clauseID {
		return left.clauseID < right.clauseID
	}
	if left.start != right.start {
		return left.start < right.start
	}
	if left.end != right.end {
		return left.end < right.end
	}
	if left.signalID != right.signalID {
		return left.signalID < right.signalID
	}
	return !left.compact && right.compact
}

func (c *Classifier) bestRuleDirectiveMatch(ruleIndex int, rule compiledRule, analysis analyzedDirectives) ruleDirectiveMatch {
	best := ruleDirectiveMatch{}
	windows := semanticDirectiveWindows(analysis)
	for windowIndex := range windows {
		prepareSemanticSignalWindowCategory(&windows[windowIndex], rule.category)
		candidate := c.assessRuleDirectiveWindow(ruleIndex, rule, windows[windowIndex])
		if betterRuleDirectiveMatch(candidate, best) {
			best = candidate
		}
	}
	return best
}

func betterRuleDirectiveMatch(candidate, current ruleDirectiveMatch) bool {
	if candidate.hardFloorEligible != current.hardFloorEligible {
		return candidate.hardFloorEligible
	}
	if candidate.corePredicateComplete != current.corePredicateComplete {
		return candidate.corePredicateComplete
	}
	if candidate.coreComplete != current.coreComplete {
		return candidate.coreComplete
	}
	if candidate.qualifierCount != current.qualifierCount {
		return candidate.qualifierCount > current.qualifierCount
	}
	if candidate.assigned.count != current.assigned.count {
		return candidate.assigned.count > current.assigned.count
	}
	return candidate.clauseCount < current.clauseCount
}

func (c *Classifier) assessRuleDirectiveWindow(ruleIndex int, rule compiledRule, window semanticSignalWindow) ruleDirectiveMatch {
	prepareSemanticSignalWindow(&window)
	prepareSemanticSignalWindowCategory(&window, rule.category)
	text := strings.TrimSpace(window.text)
	harmConflict := window.harmConflict
	affirmativeSafety := window.affirmativeSafety
	credentialRule := rule.id == "CRED-001" || rule.id == "CRED-002"
	if credentialRule && (affirmativeSafety || window.legitimateMask&(uint16(1)<<categoryPriority(rule.category)) != 0) &&
		credentialMetadataHostileConflict(text) {
		// Protected secret material, takeover, victim scope, and exfiltration
		// override generic metadata/test/authorization language. Otherwise a
		// hostile request can append a benign marker before this rule is assessed.
		harmConflict = true
		affirmativeSafety = false
	}
	legitimate := window.legitimateMask&(uint16(1)<<categoryPriority(rule.category)) != 0
	if text == "" || (legitimate && !harmConflict) || affirmativeSafety {
		return ruleDirectiveMatch{}
	}
	mask, assigned := assignRuleOccurrences(rule, window)
	explicitCredentialAccess := credentialRule && credentialProtectedStoreLiteral(text) &&
		credentialProtectedStoreAccess(text) && credentialMetadataHostileConflict(text)
	derivedIntent := false
	if rule.id == "CRED-002" && mask&(uint16(1)<<ruleDimensionIntent) == 0 && explicitCredentialAccess {
		if occurrence, ok := credentialRequiredSecretAccessOccurrence(window, assigned); ok {
			mask |= uint16(1) << ruleDimensionIntent
			assigned.append(assignedRuleOccurrence{
				dimension:  ruleDimensionIntent,
				occurrence: occurrence,
			})
			derivedIntent = true
		}
	}
	if credentialRule && mask&(uint16(1)<<ruleDimensionOperational) == 0 && explicitCredentialAccess {
		if occurrence, ok := credentialOperationalRequestOccurrence(window, assigned, rule.independentOperational); ok {
			mask |= uint16(1) << ruleDimensionOperational
			assigned.append(assignedRuleOccurrence{
				dimension:  ruleDimensionOperational,
				occurrence: occurrence,
			})
		}
	}
	if credentialRule && mask&(uint16(1)<<ruleDimensionTarget) == 0 && explicitCredentialAccess {
		if occurrence, ok := credentialProtectedStoreTargetOccurrence(window, assigned, rule.independentTarget); ok {
			mask |= uint16(1) << ruleDimensionTarget
			assigned.append(assignedRuleOccurrence{
				dimension:  ruleDimensionTarget,
				occurrence: occurrence,
			})
		}
	}
	if rule.id == "DISRUPT-001" && mask&(uint16(1)<<ruleDimensionObject) == 0 {
		if occurrence, ok := disruptionServiceObjectOccurrence(window, assigned); ok {
			mask |= uint16(1) << ruleDimensionObject
			assigned.append(assignedRuleOccurrence{
				dimension:  ruleDimensionObject,
				occurrence: occurrence,
			})
		}
	}
	physicalOwnership := int(assigned.count) >= bitsInRuleMask(mask) && mask != 0
	if mask == 0 {
		mask = ruleDimensionMaskFromSignals(rule, window)
		assigned = syntheticRuleAssignments(rule, window, mask)
	}
	match := ruleDirectiveMatch{
		found:          mask != 0,
		dimensionMask:  mask,
		assigned:       assigned,
		text:           text,
		clauseCount:    max(1, window.clauseCount),
		derivedIntent:  derivedIntent,
		scopeCoherent:  true,
		ownershipValid: physicalOwnership,
	}
	match.coreComplete = match.has(ruleDimensionIntent) && match.has(ruleDimensionObject)
	if match.coreComplete && ruleIndex >= 0 && c.ruleDirectiveWindowIntentOnlyNegated(window, ruleIndex, rule) &&
		!(credentialRule && explicitCredentialAccess && credentialActiveHostileAccessAction(text)) {
		match.coreComplete = false
	}
	// Intent-scoped negation was already evaluated above. Broad boundary words
	// such as "without consent", "without alerts", "cannot detect", and
	// "cannot identify" describe hostile scope or outcome and must not negate
	// the active attack verb for the whole clause.
	match.activeDirective = match.coreComplete
	for _, dimension := range []ruleDimension{ruleDimensionOperational, ruleDimensionTarget, ruleDimensionEvasion, ruleDimensionScale} {
		if match.has(dimension) {
			match.qualifierCount++
		}
	}
	match.corePredicateComplete = match.coreComplete && match.ownershipValid && round8RuleCorePredicate(rule.id, text, match)
	eligibleScope := match.corePredicateComplete && match.activeDirective && match.scopeCoherent && match.ownershipValid
	if !eligibleScope {
		return match
	}
	strongQualifiers := strongRuleQualifierCount(rule.id, match)
	switch {
	case rule.id == "CRED-001" && explicitCredentialTheftMatch(match):
		match.hardFloorEligible = true
		match.hardFloorReason = hardFloorReasonExplicitCredentialTheftCore
	case rule.id == "CRED-001" && explicitCredentialHostileAccessMatch(match):
		match.hardFloorEligible = true
		match.hardFloorReason = hardFloorReasonExplicitCredentialHostileAccessCore
	case rule.id == "DISRUPT-001" && explicitDisruptionHostileCore(text, match):
		match.hardFloorEligible = true
		match.hardFloorReason = hardFloorReasonExplicitDisruptionHostileOutcomeCore
	case rule.id == "DISRUPT-001" && explicitDisruptionOperationalCore(text, match):
		match.hardFloorEligible = true
		match.hardFloorReason = hardFloorReasonExplicitDisruptionOperationalCore
	case eligibleScope && strongQualifiers >= 2:
		match.hardFloorEligible = true
		match.hardFloorReason = hardFloorReasonCompleteCoreOwnedActiveScopeWithTwoStrongQualifiers
	}
	return match
}

func (c *Classifier) ruleDirectiveWindowIntentOnlyNegated(window semanticSignalWindow, ruleIndex int, rule compiledRule) bool {
	if len(window.clauses) == 0 {
		return semanticIntentOnlyNegatedPrepared(window.text, rule.intentStarts, rule.intentPatterns)
	}
	found := false
	for _, clause := range window.clauses {
		if !clause.signals.matched(rule.intent) {
			continue
		}
		found = true
		if !clause.negatedRuleIntents.matched(ruleIndex) && !c.coordinatedCoreNegated(clause, rule) {
			return false
		}
	}
	return found
}

func disruptionServiceObjectOccurrence(window semanticSignalWindow, assigned ruleOccurrenceAssignments) (signalOccurrence, bool) {
	for _, clause := range window.clauses {
		text := strings.ToLower(clause.text)
		for _, literal := range []string{"service", "服务"} {
			for offset := 0; offset < len(text); {
				index := strings.Index(text[offset:], literal)
				if index < 0 {
					break
				}
				index += offset
				start := int32(utf8.RuneCountInString(text[:index]))
				end := start + int32(utf8.RuneCountInString(literal))
				candidate := signalOccurrence{signalID: 0, clauseID: clauseIDForOccurrence(clause), start: start, end: end}
				overlaps := false
				for assignedIndex := 0; assignedIndex < int(assigned.count); assignedIndex++ {
					item := assigned.items[assignedIndex]
					if item.occurrence.clauseID != candidate.clauseID || item.occurrence.start < 0 || item.occurrence.end <= candidate.start || item.occurrence.start >= candidate.end {
						continue
					}
					overlaps = true
					break
				}
				if !overlaps {
					return candidate, true
				}
				offset = index + len(literal)
			}
		}
	}
	return signalOccurrence{}, false
}

func clauseIDForOccurrence(clause analyzedDirectiveClause) int32 {
	if len(clause.occurrences) != 0 {
		return clause.occurrences[0].clauseID
	}
	return -1
}

func bitsInRuleMask(mask uint16) int {
	count := 0
	for mask != 0 {
		mask &= mask - 1
		count++
	}
	return count
}

func ruleDimensionMaskFromSignals(rule compiledRule, window semanticSignalWindow) uint16 {
	matched := func(signalID int) bool {
		for _, clause := range window.clauses {
			if clause.signals.matched(signalID) {
				return true
			}
		}
		for _, signals := range window.directiveSignals {
			if signals.matched(signalID) {
				return true
			}
		}
		for _, signals := range window.signals {
			if signalMatched(signals, signalID) {
				return true
			}
		}
		return false
	}
	var mask uint16
	for dimension, signalID := range [...]int{
		rule.intent, rule.object, rule.independentOperational,
		rule.independentTarget, rule.independentEvasion, rule.independentScale,
	} {
		if matched(signalID) {
			mask |= uint16(1) << ruleDimension(dimension)
		}
	}
	return mask
}

func ruleDimensionMaskForSignalSet(rule compiledRule, signals []bool) uint16 {
	var mask uint16
	for dimension, signalID := range [...]int{
		rule.intent, rule.object, rule.independentOperational,
		rule.independentTarget, rule.independentEvasion, rule.independentScale,
	} {
		if signalMatched(signals, signalID) {
			mask |= uint16(1) << ruleDimension(dimension)
		}
	}
	return mask
}

func syntheticRuleAssignments(rule compiledRule, window semanticSignalWindow, mask uint16) ruleOccurrenceAssignments {
	var assigned ruleOccurrenceAssignments
	signals := [...]int{
		rule.intent, rule.object, rule.independentOperational,
		rule.independentTarget, rule.independentEvasion, rule.independentScale,
	}
	for dimension, signalID := range signals {
		bit := uint16(1) << ruleDimension(dimension)
		if mask&bit == 0 {
			continue
		}
		assigned.append(assignedRuleOccurrence{
			dimension:  ruleDimension(dimension),
			occurrence: signalOccurrence{signalID: int32(signalID), clauseID: -1, start: -1, end: -1},
		})
	}
	return assigned
}

func assignRuleOccurrences(rule compiledRule, window semanticSignalWindow) (uint16, ruleOccurrenceAssignments) {
	if len(window.clauses) == 0 && len(window.occurrences) == 0 {
		return 0, ruleOccurrenceAssignments{}
	}
	signalIDs := [...]int{
		rule.intent, rule.object, rule.independentOperational,
		rule.independentTarget, rule.independentEvasion, rule.independentScale,
	}
	var simpleOccurrences [ruleDimensionCount]signalOccurrence
	var simpleMask uint16
	ambiguous := false
	choiceCount := 0
	walkRuleOccurrenceChoices(signalIDs, window, func(choice occurrenceChoice) {
		choiceCount++
		if choice.dimensions&(choice.dimensions-1) != 0 {
			ambiguous = true
		}
		for bits := choice.dimensions; bits != 0; bits &= bits - 1 {
			dimension := ruleDimension(trailingRuleDimension(bits))
			bit := uint16(1) << dimension
			if simpleMask&bit == 0 {
				simpleMask |= bit
				simpleOccurrences[dimension] = choice.signals[dimension]
			}
		}
	})
	if choiceCount == 0 {
		return 0, ruleOccurrenceAssignments{}
	}
	if !ambiguous {
		var assignments ruleOccurrenceAssignments
		for dimension := ruleDimension(0); dimension < ruleDimensionCount; dimension++ {
			if simpleMask&(uint16(1)<<dimension) == 0 {
				continue
			}
			assignments.append(assignedRuleOccurrence{
				dimension: dimension, occurrence: simpleOccurrences[dimension],
			})
		}
		return simpleMask, assignments
	}

	type state struct {
		valid          bool
		choiceOrdinals [ruleDimensionCount]uint16
	}
	var states [1 << ruleDimensionCount]state
	states[0] = state{valid: true}
	choiceOrdinal := uint16(0)
	walkRuleOccurrenceChoices(signalIDs, window, func(choice occurrenceChoice) {
		next := states
		for mask, current := range states {
			if !current.valid {
				continue
			}
			for bits := choice.dimensions; bits != 0; bits &= bits - 1 {
				dimension := ruleDimension(trailingRuleDimension(bits))
				bit := 1 << dimension
				if mask&bit != 0 {
					continue
				}
				candidateMask := mask | bit
				if next[candidateMask].valid {
					continue
				}
				candidate := current
				candidate.valid = true
				candidate.choiceOrdinals[dimension] = choiceOrdinal + 1
				next[candidateMask] = candidate
			}
		}
		states = next
		choiceOrdinal++
	})
	bestMask := 0
	bestUtility := -1
	for mask, candidate := range states {
		if !candidate.valid {
			continue
		}
		utility := bitsInRuleMask(uint16(mask)) * 100
		for dimension := ruleDimension(0); dimension < ruleDimensionCount; dimension++ {
			if mask&(1<<dimension) != 0 {
				utility += ruleDimensionUtility(dimension)
			}
		}
		if mask&(1<<ruleDimensionIntent) != 0 && mask&(1<<ruleDimensionObject) != 0 {
			utility += 1000
		}
		if utility > bestUtility {
			bestMask = mask
			bestUtility = utility
		}
	}
	selected := states[bestMask].choiceOrdinals
	var assignments ruleOccurrenceAssignments
	choiceOrdinal = 0
	walkRuleOccurrenceChoices(signalIDs, window, func(choice occurrenceChoice) {
		for dimension, ordinal := range selected {
			if ordinal == choiceOrdinal+1 {
				assignments.append(assignedRuleOccurrence{
					dimension: ruleDimension(dimension), occurrence: choice.signals[dimension],
				})
			}
		}
		choiceOrdinal++
	})
	return uint16(bestMask), assignments
}

func walkRuleOccurrenceChoices(
	signalIDs [ruleDimensionCount]int,
	window semanticSignalWindow,
	visit func(occurrenceChoice),
) {
	var choice occurrenceChoice
	haveChoice := false
	consumeOccurrence := func(occurrence signalOccurrence) {
		var dimensions uint16
		for dimension, signalID := range signalIDs {
			if signalID >= 0 && occurrence.signalID == int32(signalID) {
				dimensions |= uint16(1) << ruleDimension(dimension)
			}
		}
		if dimensions == 0 {
			return
		}
		key := occurrenceKey{clauseID: occurrence.clauseID, start: occurrence.start, end: occurrence.end}
		if haveChoice && choice.key != key {
			visit(choice)
			choice = occurrenceChoice{}
			haveChoice = false
		}
		if !haveChoice {
			choice.key = key
			haveChoice = true
		}
		choice.dimensions |= dimensions
		for bits := dimensions; bits != 0; bits &= bits - 1 {
			dimension := ruleDimension(trailingRuleDimension(bits))
			bit := uint16(1) << dimension
			previous := choice.signals[dimension]
			if choice.present&bit == 0 || previous.compact && !occurrence.compact {
				choice.signals[dimension] = occurrence
				choice.present |= bit
			}
		}
	}
	for _, clause := range window.clauses {
		for _, occurrence := range clause.occurrences {
			consumeOccurrence(occurrence)
		}
	}
	for _, occurrence := range window.occurrences {
		consumeOccurrence(occurrence)
	}
	if haveChoice {
		visit(choice)
	}
}

func trailingRuleDimension(mask uint16) int {
	index := 0
	for mask&1 == 0 {
		mask >>= 1
		index++
	}
	return index
}

func ruleDimensionUtility(dimension ruleDimension) int {
	switch dimension {
	case ruleDimensionIntent, ruleDimensionObject:
		return 30
	case ruleDimensionTarget, ruleDimensionEvasion:
		return 20
	default:
		return 10
	}
}

func round8RuleCorePredicate(ruleID, text string, match ruleDirectiveMatch) bool {
	// All callers pass classifier-normalized directive text. Avoid lowercasing
	// again here: this predicate runs once per candidate rule on the hot path.
	text = strings.TrimSpace(text)
	switch ruleID {
	case "EVADE-002":
		return (match.has(ruleDimensionOperational) || match.has(ruleDimensionTarget)) && match.has(ruleDimensionEvasion) &&
			containsAnyLiteral(text,
				"obfuscate", "obfuscated", "hide", "hidden", "bypass", "evade detection", "avoid detection", "规避检测", "绕过", "混淆", "隐藏",
			) && containsAnyLiteral(text,
			"malware", "malicious payload", "deployable malware", "implant", "trojan", "backdoor", "恶意载荷", "恶意程序", "木马", "后门", "植入程序",
		) && containsAnyLiteral(text,
			"edr", "antivirus", "anti-virus", "av scanner", "signature scanner", "sandbox detection", "detect sandboxes", "hide from monitoring", "security logs", "security telemetry", "undetected", "avoid detection", "cannot detect", "cannot identify", "miss it", "杀毒", "av 扫描", "av扫描", "沙箱检测", "安全日志", "签名扫描", "安全遥测", "无法识别", "不被检测",
		)
	case "CRED-001", "CRED-002":
		if credentialCollectionIsPhishing(text) {
			return false
		}
		protectedStore := credentialProtectedStoreAccess(text)
		strongScope := match.has(ruleDimensionTarget) || protectedStore || containsAnyLiteral(text,
			"victim", "other user", "other users", "someone else's", "employee account", "employee endpoint", "without consent", "account takeover", "exfiltrat", "受害", "其他用户", "员工账号", "未经同意", "接管", "外传",
		)
		strongScope = strongScope || credentialExplicitHostileScope(text)
		explicitTheft := explicitCredentialTheftMatch(match)
		if ruleID == "CRED-001" && explicitTheft {
			return true
		}
		if explicitCredentialHostileAccessMatch(match) {
			return true
		}
		return (match.has(ruleDimensionOperational) || match.has(ruleDimensionScale)) && strongScope
	case "MAL-002":
		return match.has(ruleDimensionOperational) &&
			(match.has(ruleDimensionTarget) || match.has(ruleDimensionEvasion) || match.has(ruleDimensionScale)) &&
			containsAnyLiteral(text,
				"trojan", "backdoor", "c2", "command beacon", "malware loader", "malicious loader", "implant", "webshell", "web shell", "木马", "后门", "恶意加载器", "植入程序", "信标",
			) && containsAnyLiteral(text,
			"connect back", "phone home", "phones home", "call back", "calls back", "persist", "automatic startup", "spread", "silently install", "after deployment", "回连", "自启动", "持久化", "传播", "静默安装", "部署后",
		)
	case "DISRUPT-001":
		if explicitDisruptionHostileCore(text, match) || explicitDisruptionOperationalCore(text, match) {
			return true
		}
		explicitDDoS := containsAnyLiteral(text,
			"distributed denial-of-service", "denial-of-service attack", "ddos attack", "分布式拒绝服务", "拒绝服务攻击",
		)
		scopeComplete := (match.has(ruleDimensionOperational) || match.has(ruleDimensionScale)) && match.has(ruleDimensionTarget) ||
			explicitDDoS && match.has(ruleDimensionOperational) && match.has(ruleDimensionScale)
		return scopeComplete &&
			containsAnyLiteral(text,
				"flood", "overload", "exhaust", "starve", "knock offline", "knock production", "knock the service", "take offline", "goes offline", "render unavailable", "make unavailable", "make the service unavailable", "force offline", "stops responding", "cannot access the service", "customers cannot access", "users cannot access", "overwhelm", "resource starvation", "drain connections", "denial-of-service", "淹没", "洪泛", "压垮", "占满", "耗尽", "资源耗尽", "使其离线", "服务不可用", "停止响应", "拒绝服务", "拖垮", "持续攻击",
			) && containsAnyLiteral(text,
			"flood", "request storm", "traffic storm", "distributed traffic", "distributed requests", "distributed denial-of-service", "botnet", "flooder", "connection exhaustion", "connection pool", "opening connections", "bandwidth exhaustion", "automated traffic", "automated requests", "high-concurrency", "high concurrency", "amplification", "请求风暴", "流量风暴", "分布式", "僵尸网络", "流量放大", "放大攻击", "连接耗尽", "连接池", "持续占满", "带宽耗尽", "消耗带宽", "自动化流量", "自动化请求", "高并发", "几千台",
		)
	default:
		return true
	}
}

var credentialExplicitTheftIntents = []string{
	"steal", "steals", "stealing", "stole", "stolen", "theft",
	"hijack", "take over",
	"dump", "dumped", "grab", "grabs", "harvest", "harvests", "capture", "captures", "extract", "extracts",
}

var credentialExplicitTheftIntentPatterns = compileCompactRuleIntentPatterns(credentialExplicitTheftIntents)

var credentialStrongTheftIntents = credentialExplicitTheftIntents[:8]

var credentialStrongTheftIntentPatterns = compileCompactRuleIntentPatterns(credentialStrongTheftIntents)

func containsUnnegatedCredentialIntent(
	text string,
	intents []string,
	patterns compactRuleIntentPatterns,
) bool {
	foundWord := false
	for _, term := range intents {
		if containsASCIIWord(text, term) {
			foundWord = true
			break
		}
	}
	return foundWord && containsUnnegatedRuleIntentPrepared(text, intents, patterns)
}

func explicitCredentialTheftAction(text string) bool {
	if containsUnnegatedCredentialIntent(text, credentialExplicitTheftIntents, credentialExplicitTheftIntentPatterns) {
		return true
	}
	if containsAnyLiteral(text, "窃取", "盗取", "偷取", "劫持", "接管", "冒用") {
		return true
	}
	return containsAnyLiteral(text,
		"dump", "dumped", "grab", "grabs", "harvest", "harvests", "capture", "captures", "extract", "extracts",
		"转储", "抓取", "攫取", "采集", "提取", "收集",
	) && explicitCredentialSecretMaterial(text)
}

func explicitCredentialStrongTheftAction(text string) bool {
	return containsUnnegatedCredentialIntent(text, credentialStrongTheftIntents, credentialStrongTheftIntentPatterns) ||
		containsAnyLiteral(text, "窃取", "盗取", "偷取", "劫持", "接管", "冒用")
}

func explicitCredentialTheftMatch(match ruleDirectiveMatch) bool {
	if containsAnyLiteral(match.text,
		"credential theft", "credential stealer", "credential dumper", "password dumper",
		"token grabber", "credential harvester", "session hijacker", "secret siphoner",
		"credential pilferer", "凭证窃取", "凭证盗取", "凭证转储", "凭证收割器", "会话劫持",
	) {
		return true
	}
	runes := []rune(match.text)
	for assignedIndex := 0; assignedIndex < int(match.assigned.count); assignedIndex++ {
		assigned := match.assigned.items[assignedIndex]
		occurrence := assigned.occurrence
		if assigned.dimension != ruleDimensionIntent || !occurrence.compact ||
			occurrence.start < 0 || int(occurrence.end) > len(runes) || occurrence.start >= occurrence.end {
			continue
		}
		switch compactString(runes[int(occurrence.start):int(occurrence.end)]) {
		case "steal", "steals", "stealing", "stole", "stolen", "theft",
			"hijack", "takeover", "credentialtheft", "credentialstealer", "credentialdumper",
			"passworddumper", "tokengrabber", "credentialharvester", "sessionhijacker",
			"secretsiphoner", "credentialpilferer", "窃取", "盗取", "偷取", "劫持", "接管":
			return true
		}
	}
	return explicitCredentialStrongTheftAction(match.text)
}

func explicitCredentialHostileAccessMatch(match ruleDirectiveMatch) bool {
	// Some target literals (for example "victim") are deliberately removed
	// from the independent qualifier signal when they overlap a longer core
	// object such as "victim cookies". The same-clause hostile ownership phrase
	// still completes the predicate; requiring the deduplicated target bit here
	// discarded terse but explicit victim-browser/host extraction requests.
	activeAccess := match.has(ruleDimensionIntent)
	if !activeAccess && !containsAnyLiteral(match.text,
		"转储", "抓取", "攫取", "采集", "提取", "收集",
	) {
		return false
	}
	if credentialExplicitHostileScope(match.text) {
		return true
	}
	return credentialProtectedStoreAccess(match.text) || containsAnyLiteral(match.text,
		"victim", "other user", "other users", "someone else's", "employee account", "employee accounts",
		"victim browser", "victim host", "without consent", "account takeover", "attacker-controlled",
		"external server", "exfiltrat", "受害", "其他用户", "员工账号", "未经同意", "接管", "攻击者控制", "外传",
	)
}

func credentialProtectedStoreAccess(text string) bool {
	return credentialProtectedStoreLiteral(text) &&
		!credentialApprovedStoreWorkflow(text) &&
		!credentialMetadataOnlyContext(text)
}

func credentialProtectedStoreLiteral(text string) bool {
	return containsAnyLiteral(text,
		"lsass", "sam database", "credential store", "credential-store", "password vault", "keychain",
		"browser credential database", "browser credentials database", "browser database",
		"浏览器凭证数据库", "浏览器凭据数据库",
	)
}

var credentialControlledDestinationIntents = []string{
	"read", "reads", "reading", "access", "accesses", "accessing",
	"collect", "collects", "collecting", "retrieve", "retrieves", "retrieving",
	"copy", "copies", "copying", "export", "exports", "exporting",
	"return", "returns", "returning", "extract", "extracts", "extracting",
	"capture", "captures", "capturing", "harvest", "harvests", "harvesting",
	"grab", "grabs", "grabbing", "steal", "steals", "stealing",
	"dump", "dumps", "dumping", "send", "sends", "sending",
	"forward", "forwards", "forwarding",
	"upload", "uploads", "uploading", "exfiltrate", "exfiltrates", "exfiltrating",
}

var credentialControlledDestinationIntentPatterns = compileCompactRuleIntentPatterns(credentialControlledDestinationIntents)

var credentialTargetedTheftIntents = []string{
	"steal", "steals", "stealing", "stole", "stolen", "hijack", "take over",
	"harvest", "harvests", "harvesting", "grab", "grabs", "grabbing",
	"dump", "dumps", "dumping", "siphon", "siphons", "pilfer", "pilfers",
}

var credentialTargetedTheftIntentPatterns = compileCompactRuleIntentPatterns(credentialTargetedTheftIntents)

var credentialSensitiveTargetTerms = []string{
	"real user", "real users", "real account", "real accounts",
	"employee", "employees", "employee account", "employee accounts",
	"employee device", "employee devices", "employee endpoint", "employee endpoints",
	"employee workstation", "employee workstations", "staff", "staff account", "staff accounts",
	"user workstation", "user workstations", "remote host", "remote hosts",
	"user browser", "user browsers", "user's browser", "user's browsers", "users' browser", "users' browsers",
	"employee's browser", "employee's browsers", "employees' browser", "employees' browsers",
	"target user", "target user's",
	"compromised account", "compromised accounts", "target account", "target accounts",
	"target machine", "target machines", "endpoint", "endpoints",
}

func credentialSensitiveTargetAcquisition(text string) bool {
	if !credentialSecretMaterialLiteral(text) && !credentialProtectedStoreLiteral(text) {
		return false
	}
	if containsAnyLiteral(text,
		"credential metadata", "credentials metadata", "version metadata", "inventory metadata", "alert metadata",
	) && containsAnyLiteral(text,
		"endpoints we own", "systems we own", "owned endpoints", "owned systems", "our approved",
	) && credentialMetadataNoSecretValueClaim(text) {
		return false
	}
	targetText := credentialTargetApostropheEquivalent(text)
	targetFound := false
	for _, target := range credentialSensitiveTargetTerms {
		if strings.Contains(targetText, target) {
			targetFound = true
			break
		}
	}
	if !targetFound {
		return false
	}
	if containsUnnegatedCredentialIntent(
		text,
		credentialTargetedTheftIntents,
		credentialTargetedTheftIntentPatterns,
	) {
		return true
	}
	for _, target := range credentialSensitiveTargetTerms {
		for offset := 0; offset < len(targetText); {
			index := strings.Index(targetText[offset:], target)
			if index < 0 {
				break
			}
			index += offset
			prefix := targetText[:index]
			from := strings.LastIndex(prefix, " from ")
			if from >= 0 {
				bridge := strings.TrimSpace(prefix[from+len(" from "):])
				if bridge == "" || bridge == "a" || bridge == "an" || bridge == "the" {
					clausePrefix := prefix[:from]
					if containsUnnegatedCredentialIntent(
						clausePrefix,
						credentialSecretCollectionIntents,
						credentialSecretCollectionIntentPatterns,
					) {
						return true
					}
				}
			}
			offset = index + len(target)
		}
	}
	return false
}

// credentialTargetApostropheEquivalent canonicalizes only the common Unicode
// apostrophes that can express a possessive credential target. Keeping this
// equivalence local avoids changing quote, negation, or carrier semantics for
// the rest of the classifier while closing ordinary users’/employees’ browser
// spelling variants.
func credentialTargetApostropheEquivalent(text string) string {
	if !strings.ContainsAny(text, "‘’ʼ") {
		return text
	}
	return strings.Map(func(value rune) rune {
		switch value {
		case '‘', '’', 'ʼ':
			return '\''
		default:
			return value
		}
	}, text)
}

func credentialApprovedRecoveryDestination(text string) bool {
	return containsAnyLiteral(text,
		"approved", "company-approved", "organization-approved", "our backup", "our recovery",
	) && containsAnyLiteral(text,
		"off-site backup vault", "offsite backup vault", "off site backup vault",
		"encrypted backup vault", "recovery vault",
	) && containsAnyLiteral(text,
		"disaster recovery", "credential backup", "credentials backup", "backup migration", "recovery migration",
	)
}

// credentialExplicitHostileScope recognizes ownership, destination, takeover,
// and stealth facts that an ordinary OAuth or approved-store workflow must not
// wash out. A first-party backend may legitimately send its returned token to
// its own application server, so ambiguous "my host"/"server I control"
// wording requires a simultaneous acquisition or off-site transfer verb.
func credentialExplicitHostileScope(text string) bool {
	if containsAnyLiteral(text,
		"victim", "other user", "other users", "someone else's", "other people's",
		"another tenant", "other tenant", "without consent", "without permission",
		"account takeover", "unauthorized", "attacker-controlled", "external server",
		"collection server", "webhook", "exfiltrat",
		"without their knowledge", "without the user's knowledge", "without the users' knowledge",
		"compromised user", "compromised profile", "compromised profiles",
		"compromised host", "compromised machine", "compromised workstation",
	) {
		return true
	}
	if containsAnyLiteral(text, "off site", "off-site", "offsite") &&
		!credentialApprovedRecoveryDestination(text) {
		return true
	}
	if credentialSensitiveTargetAcquisition(text) {
		return true
	}

	workforceScope := containsAnyLiteral(text,
		"employee account", "employee accounts", "employee endpoint", "employee endpoints",
		"employee device", "employee devices", "employee workstation", "employee workstations",
		"user workstation", "user workstations", "staff account", "staff accounts",
		"customer account", "customer accounts",
	)
	stealthScope := containsAnyLiteral(text,
		"without prompting", "without asking", "without notice", "without notification",
		"silently", "covertly", "undetected", "hide the collection", "hides the collection",
	)
	if workforceScope && stealthScope {
		return true
	}

	controlledDestination := containsAnyLiteral(text,
		"server i control", "server I control", "host i control", "host I control", "my host", "my receiver",
	)
	return controlledDestination && containsUnnegatedCredentialIntent(
		text,
		credentialControlledDestinationIntents,
		credentialControlledDestinationIntentPatterns,
	)
}

// credentialApprovedStoreWorkflow is a deliberately conjunctive exception for
// first-party service authentication and controlled credential lifecycle work.
// Explicit victim, unauthorized, takeover, stealth, or external-destination
// scope always wins before the exception is considered.
func credentialApprovedStoreWorkflow(text string) bool {
	ownedStore := containsAnyLiteral(text,
		"our approved credential store", "approved credential store",
		"our approved credential stores", "approved credential stores",
		"our approved password vault", "approved password vault",
		"our approved secret store", "approved secret store",
		"our approved secret stores", "approved secret stores",
		"our credential store", "our credential stores",
		"our password vault", "our secrets manager", "approved secrets manager",
		"our encrypted replacement vault", "encrypted replacement vault",
	)
	if !ownedStore {
		return false
	}
	if credentialExplicitHostileScope(text) {
		return false
	}
	lifecycleWorkflow := containsAnyLiteral(text,
		"service integration", "deployment agent", "at startup", "during startup",
		"service startup", "authenticate to the database", "authenticate with the database",
		"credential migration", "credentials migration", "migration job", "during our migration",
		"credential rotation", "credentials rotation", "rotation job", "rotate credentials",
		"credential backup", "credentials backup", "backup job",
		"encrypted replacement vault", "copy credentials between",
	)
	oauthAuthenticationWorkflow := containsAnyLiteral(text,
		"oauth callback", "OAuth callback", "token exchange response", "authorization server", "oidc refresh", "OIDC refresh",
	) && containsAnyLiteral(text,
		"after they authenticate", "after authentication", "authenticated session", "authenticated user",
		"after consent", "interactive consent", "returned access token", "returned access tokens",
		"returned refresh token", "returned refresh tokens",
	)
	return lifecycleWorkflow || oauthAuthenticationWorkflow
}

func credentialRequiredSecretAccess(text string) bool {
	for _, clause := range credentialSafetyClauses(text) {
		clause = strings.ToLower(strings.TrimSpace(normalizeNegationSyntax(clause)))
		for _, marker := range credentialRequiredAccessMarkers() {
			for offset := 0; offset <= len(clause)-len(marker); {
				index := strings.Index(clause[offset:], marker)
				if index < 0 {
					break
				}
				index += offset
				after := clause[index+len(marker):]
				if credentialNegationGovernorReversed(clause[:index]) && credentialSecretMaterialLiteral(after) {
					return true
				}
				offset = index + 1
			}
		}
	}
	return false
}

func credentialActiveHostileAccessAction(text string) bool {
	return containsUnnegatedRuleIntentPrepared(
		text,
		credentialHostileAccessIntents,
		credentialHostileAccessIntentPatterns,
	) || credentialRequiredSecretAccess(text)
}

func credentialRequiredAccessMarkers() []string {
	return []string{
		"without reading", "without accessing", "without collecting", "without retrieving",
		"without copying", "without exporting", "without returning",
	}
}

func credentialRequiredSecretAccessOccurrence(window semanticSignalWindow, assigned ruleOccurrenceAssignments) (signalOccurrence, bool) {
	for _, clause := range window.clauses {
		text := strings.ToLower(clause.text)
		for _, marker := range credentialRequiredAccessMarkers() {
			for offset := 0; offset <= len(text)-len(marker); {
				index := strings.Index(text[offset:], marker)
				if index < 0 {
					break
				}
				index += offset
				after := text[index+len(marker):]
				if credentialNegationGovernorReversed(text[:index]) && credentialSecretMaterialLiteral(after) {
					action := strings.TrimPrefix(marker, "without ")
					actionStart := index + len("without ")
					candidate := signalOccurrence{
						signalID: 0,
						clauseID: clauseIDForOccurrence(clause),
						start:    int32(utf8.RuneCountInString(text[:actionStart])),
						end:      int32(utf8.RuneCountInString(text[:actionStart+len(action)])),
					}
					if !ruleOccurrenceOverlapsAssignments(candidate, assigned) {
						return candidate, true
					}
				}
				offset = index + 1
			}
		}
	}
	return signalOccurrence{}, false
}

func credentialOperationalRequestOccurrence(window semanticSignalWindow, assigned ruleOccurrenceAssignments, signalID int) (signalOccurrence, bool) {
	for _, clause := range window.clauses {
		text := strings.ToLower(clause.text)
		for _, intent := range credentialOperationalRequestIntents {
			if !containsUnnegatedRuleIntentPrepared(text, intent.terms, intent.patterns) {
				continue
			}
			value := intent.terms[0]
			for offset := 0; offset <= len(text)-len(value); {
				index := strings.Index(text[offset:], value)
				if index < 0 {
					break
				}
				index += offset
				end := index + len(value)
				leftOK := index == 0 || !isASCIIWordByte(text[index-1])
				rightOK := end == len(text) || !isASCIIWordByte(text[end])
				candidate := signalOccurrence{
					signalID: int32(signalID),
					clauseID: clauseIDForOccurrence(clause),
					start:    int32(utf8.RuneCountInString(text[:index])),
					end:      int32(utf8.RuneCountInString(text[:end])),
				}
				if leftOK && rightOK && !ruleOccurrenceOverlapsAssignments(candidate, assigned) {
					return candidate, true
				}
				offset = index + 1
			}
		}
	}
	return signalOccurrence{}, false
}

func credentialProtectedStoreTargetOccurrence(window semanticSignalWindow, assigned ruleOccurrenceAssignments, signalID int) (signalOccurrence, bool) {
	for _, clause := range window.clauses {
		text := strings.ToLower(clause.text)
		for _, literal := range []string{
			"our approved", "approved",
			"credential store", "credential-store", "password vault", "keychain", "lsass", "sam database",
			"browser credential database", "browser credentials database", "browser database",
		} {
			for offset := 0; offset <= len(text)-len(literal); {
				index := strings.Index(text[offset:], literal)
				if index < 0 {
					break
				}
				index += offset
				candidate := signalOccurrence{
					signalID: int32(signalID),
					clauseID: clauseIDForOccurrence(clause),
					start:    int32(utf8.RuneCountInString(text[:index])),
					end:      int32(utf8.RuneCountInString(text[:index+len(literal)])),
				}
				if !ruleOccurrenceOverlapsAssignments(candidate, assigned) {
					return candidate, true
				}
				offset = index + 1
			}
		}
	}
	return signalOccurrence{}, false
}

func ruleOccurrenceOverlapsAssignments(candidate signalOccurrence, assigned ruleOccurrenceAssignments) bool {
	for assignedIndex := 0; assignedIndex < int(assigned.count); assignedIndex++ {
		occurrence := assigned.items[assignedIndex].occurrence
		if occurrence.clauseID != candidate.clauseID || occurrence.start < 0 || occurrence.end <= candidate.start || occurrence.start >= candidate.end {
			continue
		}
		return true
	}
	return false
}

func explicitCredentialSecretMaterial(text string) bool {
	if credentialMetadataOnlyContext(text) {
		return false
	}
	return credentialProtectedStoreLiteral(text) || credentialActiveSecretMaterial(text)
}

func credentialSecretMaterialLiteral(text string) bool {
	return containsAnyLiteral(text,
		"browser cookie", "browser cookies", "authentication cookies", "saved passwords", "login credentials",
		"session token", "session tokens", "access token", "access tokens", "refresh token", "refresh tokens", "api key", "api keys",
		"oauth token", "oauth tokens", "password hashes", "kerberos tickets", "ntlm hashes",
		"ssh private key", "ssh private keys", "session cookies", "login secrets", "credential material",
		"浏览器 cookie", "登录 token", "会话 token", "保存的密码", "登录凭证", "账号密码", "密码哈希", "认证材料",
	)
}

var credentialSecretMaterialNegationTerms = []string{
	"browser cookie", "browser cookies", "authentication cookies", "saved passwords", "login credentials",
	"session token", "session tokens", "access token", "access tokens", "refresh token", "refresh tokens", "api key", "api keys",
	"oauth token", "oauth tokens", "password hashes", "kerberos tickets", "ntlm hashes",
	"ssh private key", "ssh private keys", "session cookies", "login secrets", "credential material",
}

var credentialSecretCollectionIntents = []string{
	"read", "reads", "reading", "access", "accesses", "accessing",
	"collect", "collects", "collecting", "retrieve", "retrieves", "retrieving",
	"copy", "copies", "copying", "export", "exports", "exporting",
	"return", "returns", "returning", "harvest", "harvests", "harvesting",
	"dump", "dumps", "dumping", "grab", "grabs", "grabbing",
	"extract", "extracts", "extracting", "capture", "captures", "capturing",
	"steal", "steals", "stealing", "upload", "uploads", "uploading",
	"send", "sends", "sending", "exfiltrate", "exfiltrates", "exfiltrating",
	"use them", "use the",
}

var credentialSecretCollectionIntentPatterns = compileCompactRuleIntentPatterns(credentialSecretCollectionIntents)

var credentialHostileAccessIntents = []string{
	"dump", "dumped", "dumping", "grab", "grabs", "grabbing", "extract", "extracts", "extracting",
	"harvest", "harvests", "harvesting", "capture", "captures", "capturing",
	"collect", "collects", "collecting", "retrieve", "retrieves", "retrieving",
	"copy", "copies", "copying", "export", "exports", "exporting",
	"read", "reads", "reading", "return", "returns", "returning",
}

var credentialHostileAccessIntentPatterns = compileCompactRuleIntentPatterns(credentialHostileAccessIntents)

type preparedCredentialIntent struct {
	terms    []string
	patterns compactRuleIntentPatterns
}

var credentialOperationalRequestIntents = func() []preparedCredentialIntent {
	values := []string{"build", "create", "provide", "implement", "write", "make"}
	prepared := make([]preparedCredentialIntent, 0, len(values))
	for _, value := range values {
		terms := []string{value}
		prepared = append(prepared, preparedCredentialIntent{
			terms:    terms,
			patterns: compileCompactRuleIntentPatterns(terms),
		})
	}
	return prepared
}()

var credentialMetadataHostileIntents = []string{
	"steal", "steals", "stealing", "stole", "stolen", "theft", "hijack", "take over",
	"dump credentials from", "grab credentials from", "extract credentials from",
	"capture credentials from", "harvest credentials from", "collect credentials from",
	"retrieve credentials from", "copy credentials from", "export credentials from",
	"read credentials from", "return credentials from",
}

var credentialMetadataHostileIntentPatterns = compileCompactRuleIntentPatterns(credentialMetadataHostileIntents)

var smallHelperRemoteControlIntents = []string{
	"remote operator control", "accept commands", "issue tasks", "quiet command channel",
	"available to a controller", "remote tasks can be issued", "persistent command access",
	"make that machine available to an off-site controller",
}

var smallHelperRemoteControlIntentPatterns = compileCompactRuleIntentPatterns(smallHelperRemoteControlIntents)

var credentialSecretNegationGovernors = []string{
	"without reading", "without accessing", "without collecting", "without retrieving",
	"without copying", "without exporting", "without returning", "without using",
	"never reading", "never reads", "never accessing", "never accesses",
	"never collecting", "never collects", "never retrieving", "never retrieves",
	"does not read", "do not read", "must not read", "should not read", "will not read",
	"does not access", "do not access", "must not access", "should not access", "will not access",
	"does not collect", "do not collect", "must not collect", "should not collect", "will not collect",
	"no reading of", "no access to", "no collection of",
}

func credentialActiveSecretMaterial(text string) bool {
	if !credentialSecretMaterialLiteral(text) {
		return false
	}
	for _, clause := range credentialSafetyClauses(text) {
		if credentialSecretMaterialLiteral(clause) && !credentialSecretMaterialOnlyNegated(clause) {
			return true
		}
	}
	return false
}

func credentialSecretMaterialOnlyNegated(clause string) bool {
	clause = strings.ToLower(strings.TrimSpace(normalizeNegationSyntax(
		normalizeCredentialSecretListSeparators(clause),
	)))
	found := false
	for _, term := range credentialSecretMaterialNegationTerms {
		for offset := 0; offset <= len(clause)-len(term); {
			index := strings.Index(clause[offset:], term)
			if index < 0 {
				break
			}
			index += offset
			end := index + len(term)
			leftOK := index == 0 || !isASCIIWordByte(clause[index-1])
			rightOK := end == len(clause) || !isASCIIWordByte(clause[end])
			if leftOK && rightOK {
				found = true
				negationStart, negationEnd := credentialNegationGovernorBefore(clause, index)
				if negationEnd < 0 || negationScopeInterrupted(clause[negationEnd:index]) ||
					credentialNegationGovernorReversed(clause[:negationStart]) {
					return false
				}
				// A negative example list cannot authorize a coordinated action in
				// the same scope. Inspect the bounded tail with the classifier's
				// per-occurrence negation logic so "never steal" stays negative while
				// "while we collect" fails active.
				if containsUnnegatedRuleIntentPrepared(
					clause[negationEnd:],
					credentialSecretCollectionIntents,
					credentialSecretCollectionIntentPatterns,
				) {
					return false
				}
			}
			offset = index + 1
		}
	}
	return found
}

func credentialSafetyClauses(text string) []string {
	return splitStrongSafetyClauses(normalizeCredentialSecretListSeparators(text))
}

func normalizeCredentialSecretListSeparators(text string) string {
	if !strings.Contains(text, "/") {
		return text
	}
	lower := strings.ToLower(text)
	var normalized strings.Builder
	normalized.Grow(len(text) + 8)
	last := 0
	for index := 0; index < len(text); index++ {
		if text[index] != '/' || !credentialSecretListSlash(lower, index) {
			continue
		}
		normalized.WriteString(text[last:index])
		normalized.WriteString(" or ")
		last = index + 1
	}
	if last == 0 {
		return text
	}
	normalized.WriteString(text[last:])
	return normalized.String()
}

func credentialSecretListSlash(text string, slash int) bool {
	left := strings.TrimSpace(text[:slash])
	right := strings.TrimSpace(text[slash+1:])
	leftSecret := false
	for _, term := range credentialSecretMaterialNegationTerms {
		if strings.HasSuffix(left, term) {
			leftSecret = true
			break
		}
	}
	if !leftSecret {
		return false
	}
	for _, term := range credentialSecretMaterialNegationTerms {
		if strings.HasPrefix(right, term) {
			end := len(term)
			if end == len(right) || !isASCIIWordByte(right[end]) {
				return true
			}
		}
	}
	return false
}

func credentialNegationGovernorBefore(clause string, before int) (int, int) {
	bestStart, bestEnd := -1, -1
	prefix := clause[:before]
	for _, marker := range credentialSecretNegationGovernors {
		index := strings.LastIndex(prefix, marker)
		if index < 0 || index < bestStart {
			continue
		}
		end := index + len(marker)
		leftOK := index == 0 || !isASCIIWordByte(prefix[index-1])
		rightOK := end == len(prefix) || !isASCIIWordByte(prefix[end])
		if leftOK && rightOK {
			bestStart, bestEnd = index, end
		}
	}
	return bestStart, bestEnd
}

func credentialNegationGovernorReversed(prefix string) bool {
	prefix = strings.ToLower(strings.TrimSpace(normalizeNegationSyntax(prefix)))
	prefixRunes := []rune(prefix)
	if len(prefixRunes) > 160 {
		prefix = string(prefixRunes[len(prefixRunes)-160:])
	}
	for _, negator := range []string{
		"cannot ", "could not ", "does not ", "do not ", "will not ", "would not ",
		"must not ", "should not ", "unable to ", "fail to ", "fails to ", "failed to ",
	} {
		index := strings.LastIndex(prefix, negator)
		if index < 0 {
			continue
		}
		bridge := strings.Fields(prefix[index+len(negator):])
		if len(bridge) == 0 || len(bridge) > 7 {
			continue
		}
		for _, word := range bridge {
			switch strings.Trim(word, "'\".,:;!?()[]{}") {
			case "operate", "operates", "operating", "work", "works", "working",
				"function", "functions", "functioning", "run", "runs", "running",
				"proceed", "proceeds", "proceeding", "complete", "completes", "completing",
				"succeed", "succeeds", "succeeding":
				return true
			}
		}
	}
	return strings.HasSuffix(prefix, " not")
}

func credentialMetadataOnlyContext(text string) bool {
	text = strings.ToLower(text)
	// This exception is intentionally conjunctive and clause-local. A single
	// request-wide token such as "metadata only" or "test fixture" must never
	// suppress real secret material, victim scope, takeover, or exfiltration.
	if credentialMetadataHostileConflict(text) {
		return false
	}
	for _, clause := range credentialSafetyClauses(text) {
		metadata := containsAnyLiteral(clause,
			"credential metadata", "credentials metadata", "version metadata", "inventory metadata",
			"alert metadata",
		)
		noSecretValues := credentialMetadataNoSecretValueClaim(clause) ||
			credentialSecretMaterialLiteral(clause) && !credentialActiveSecretMaterial(clause)
		ownedOrSyntheticScope := containsAnyLiteral(clause,
			"our approved", "approved secret store", "approved credential store", "our secret store",
			"our credential store", "internal inventory", "internal test", "owned environment",
			"owned system", "owned store", "endpoints we own", "systems we own", "we own",
			"local fixture", "synthetic fixture", "synthetic test",
			"test fixture",
		)
		if metadata && noSecretValues && ownedOrSyntheticScope {
			return true
		}
	}
	return false
}

func credentialMetadataNoSecretValueClaim(clause string) bool {
	clause = strings.ToLower(normalizeNegationSyntax(clause))
	for _, marker := range []string{
		"without reading secret values", "without secret values", "never reads secret values",
		"does not read secret values", "no secret values",
	} {
		for offset := 0; offset <= len(clause)-len(marker); {
			index := strings.Index(clause[offset:], marker)
			if index < 0 {
				break
			}
			index += offset
			if !credentialNegationGovernorReversed(clause[:index]) {
				return true
			}
			offset = index + 1
		}
	}
	return false
}

func credentialMetadataHostileConflict(text string) bool {
	// Explicit theft/takeover vocabulary already encodes both the acquisition
	// action and the absence of authorization. Keep those terse hostile cores
	// effective even when a request appends a legitimate workflow marker.
	if explicitCredentialStrongTheftAction(text) || containsAnyLiteral(text,
		"credential theft", "credential stealer", "credential dumper", "password dumper",
		"token grabber", "credential harvester", "session hijacker", "secret siphoner",
		"credential pilferer",
	) {
		return true
	}

	// A live token/password noun is not a hostile conflict by itself. Ordinary
	// OAuth callbacks, token exchanges, refresh handlers, and response parsers
	// necessarily name and manipulate active secret material. Override those
	// legitimate workflows only when the same directive also establishes an
	// active acquisition/transfer relation and a hostile ownership, protected
	// store, takeover, or external-destination scope.
	hostileScope := credentialExplicitHostileScope(text) ||
		credentialProtectedStoreLiteral(text) && !credentialApprovedStoreWorkflow(text)
	if !hostileScope {
		return false
	}
	if containsUnnegatedRuleIntentPrepared(
		text,
		credentialMetadataHostileIntents,
		credentialMetadataHostileIntentPatterns,
	) {
		return true
	}
	activeSecretRelation := credentialActiveSecretMaterial(text) &&
		containsUnnegatedCredentialIntent(
			text,
			credentialSecretCollectionIntents,
			credentialSecretCollectionIntentPatterns,
		)
	return activeSecretRelation || credentialRequiredSecretAccess(text)
}

func smallHelperRemoteControlRelation(text string) bool {
	return containsUnnegatedRuleIntentPrepared(
		text,
		smallHelperRemoteControlIntents,
		smallHelperRemoteControlIntentPatterns,
	)
}

func explicitDisruptionHostileCore(text string, match ruleDirectiveMatch) bool {
	return match.has(ruleDimensionTarget) && containsAnyLiteral(text,
		"ddos", "distributed denial-of-service", "denial-of-service attack",
	) && containsAnyLiteral(text,
		"offline", "unavailable", "stops responding", "cannot access", "customers cannot access", "users cannot access",
	)
}

func explicitDisruptionOperationalCore(text string, match ruleDirectiveMatch) bool {
	return match.has(ruleDimensionOperational) && match.has(ruleDimensionTarget) &&
		explicitDisruptionTrafficMechanism(text) && containsAnyLiteral(text,
		"flood", "overload", "overwhelm", "swamp", "exhaust", "starve", "offline", "unavailable",
	)
}

func credentialCollectionIsPhishing(text string) bool {
	return containsAnyLiteral(text,
		"login page", "sign-in page", "login portal", "sign-in portal", "phishing page", "credential form",
		"登录页", "登录门户", "钓鱼页", "钓鱼站", "品牌页面", "表单",
	) && containsAnyLiteral(text,
		"deploy", "host", "launch", "clone", "copy", "publish", "上线", "部署", "复制", "搭建", "发布",
	)
}

func round8RuleBalancedEligible(ruleID string, match ruleDirectiveMatch, strongQualifiers int) bool {
	if !match.corePredicateComplete {
		return false
	}
	if strongQualifiers >= 2 {
		return true
	}
	// CRED-001 has a higher, curated base score. An unambiguous theft/hijack
	// relationship or a scoped protected-store/victim acquisition is already a
	// complete hostile core. Broad collection verbs remain subject to ownership
	// or protected-store proof instead of becoming theft by vocabulary alone.
	return (ruleID == "CRED-001" && explicitCredentialTheftMatch(match) ||
		(ruleID == "CRED-001" || ruleID == "CRED-002") && explicitCredentialHostileAccessMatch(match)) ||
		ruleID == "DISRUPT-001" && (explicitDisruptionHostileCore(match.text, match) ||
			explicitDisruptionOperationalCore(match.text, match))
}

const (
	round8SemanticCorePrimary uint8 = 1 << iota
	round8SemanticCoreSecondary
	round8SemanticCoreActiveRelation
)

func round8SemanticCoreEvidenceBits(category rules.Category, text string) uint8 {
	if !round8SemanticCoreCategory(category) {
		return 0
	}
	// Semantic windows are built from classifier-normalized directive clauses.
	text = strings.TrimSpace(text)
	var evidence uint8
	descriptiveOnly := round8SemanticDescriptiveOnly(text)
	switch category {
	case rules.CategoryEvasion:
		if containsAnyLiteral(text,
			"malware", "malicious payload", "implant", "trojan", "backdoor",
			"endpoint protection", "audit forwarding", "detection rules", "audit records", "security-control",
			"central monitoring", "forensic material", "log pipeline", "监控环境", "审计转发", "安全控制", "取证材料",
			"恶意载荷", "木马", "后门", "植入程序",
		) {
			evidence |= round8SemanticCorePrimary
		}
		if containsAnyLiteral(text,
			"edr", "antivirus", "signature scanner", "security telemetry", "undetected", "avoid detection", "evade detection", "bypass detection", "obfuscate",
			"disable", "deactivation", "weaken", "muting alerts", "mute", "suppress alerts", "alert suppression",
			"rewrite", "destroying evidence", "evidence destruction", "no trace", "disguise the intrusion", "traffic disguise",
			"blend into", "blends into", "blending into", "labeled as trusted maintenance", "attribution prevention",
			"reduce monitoring noise", "forensic material no longer gets in the way",
			"杀毒", "签名扫描", "安全遥测", "无法识别", "规避检测", "静默告警", "停掉", "改写时间线", "混进例行维护", "不留痕迹",
		) {
			evidence |= round8SemanticCoreSecondary
		}
	case rules.CategoryCredentialTheft:
		if containsAnyLiteral(text,
			"lsass", "sam database", "credential store", "password vault", "keychain", "browser cookies", "session cookies",
			"victim", "other user", "someone else's", "without consent", "account takeover", "exfiltrat",
			"operator workstation", "operator host", "operator-owned vault", "outsider device", "off-network operator host",
			"my workstation", "field staff", "contractor endpoints", "account owners", "without a fresh sign-in",
			"browser session data", "real accounts", "account access available", "entry into their real accounts",
			"受害", "其他用户", "未经同意", "接管", "外传", "操作端", "转到操作端", "另一台机器", "另一台电脑",
			"员工账号", "浏览器登录态", "登录状态", "外包人员", "直接使用", "不弹确认", "可直接进入账号",
		) {
			evidence |= round8SemanticCorePrimary
		}
	case rules.CategoryMalware:
		explicitMalwareObject := containsAnyLiteral(text,
			"trojan", "backdoor", "c2 beacon", "malware loader", "implant", "webshell", "web shell",
			"remote administration implant", "remote control implant", "command-capable payload", "credential-recording program",
			"keystroke-capturing implant", "木马", "后门", "恶意加载器", "植入程序", "信标",
			"远控植入程序", "按键记录程序", "外部控制端接收任务",
		)
		if !explicitMalwareObject && containsASCIIWord(text, "small helper") &&
			smallHelperRemoteControlRelation(text) {
			explicitMalwareObject = true
		}
		if explicitMalwareObject {
			evidence |= round8SemanticCorePrimary
		}
		if containsAnyLiteral(text,
			"deploy", "install", "connect back", "phone home", "persist", "spread", "resident",
			"accept commands", "issue tasks", "remote operator control", "off-site controller", "operator server",
			"after each reboot", "automatic startup", "covert installation", "startup persistent", "available to a controller",
			"回连", "安装", "部署", "持久化", "传播", "静默装到", "开机常驻", "自动回连", "远程操控", "持续受控",
		) {
			evidence |= round8SemanticCoreSecondary
		}
	case rules.CategoryDisruption:
		if containsAnyLiteral(text,
			"request storm", "traffic storm", "connection exhaustion", "bandwidth exhaustion", "distributed traffic", "resource starvation",
			"capacity exhaustion", "multi-source saturation", "saturate connections", "saturate-connections", "fill the critical queue",
			"critical queue is to be filled", "peak-hour traffic", "fanout sources", "fanout-sources", "dependency amplification",
			"failover prevention", "defeat failover", "rate-limit bypass", "bypass-rate-limit", "autoscaling and failover are ineffective",
			"ddos", "denial of service", "distributed requests", "distributed clients", "automated distributed requests",
			"connection pool has no free slots", "请求风暴", "流量风暴", "连接耗尽", "带宽耗尽", "资源耗尽", "打满", "多来源冲击",
			"拖垮备用节点", "避开限流", "绕过容量保护", "拒绝服务", "连接池没有剩余槽位", "分布式客户端",
		) {
			evidence |= round8SemanticCorePrimary
		}
		if containsAnyLiteral(text,
			"offline", "unavailable", "flood", "overload", "exhaust", "overwhelm", "outage", "refuses requests",
			"goes quiet", "cannot restore", "delayed recovery", "prolonged recovery", "recovery window", "dragged down",
			"repeatedly disturbed", "extend-outage", "extend outage", "stop an unapproved target", "keep customers from connecting",
			"离线", "不可用", "洪泛", "压垮", "耗尽", "拖垮", "无法恢复", "延长", "拒绝请求",
			"真实用户无法连接",
		) {
			evidence |= round8SemanticCoreSecondary
		}
	}
	if !descriptiveOnly && evidence&(round8SemanticCorePrimary|round8SemanticCoreSecondary) != 0 {
		evidence |= round8SemanticCoreActiveRelation
	}
	return evidence

}

func round8SemanticCorePredicateFromEvidence(category rules.Category, dimensions semanticDimensions, evidence uint8) bool {
	switch category {
	case rules.CategoryEvasion:
		if evidence&round8SemanticCoreActiveRelation == 0 {
			return false
		}
		return dimensions.object && (dimensions.action || dimensions.harm || dimensions.impact) &&
			evidence&(round8SemanticCorePrimary|round8SemanticCoreSecondary) ==
				round8SemanticCorePrimary|round8SemanticCoreSecondary
	case rules.CategoryCredentialTheft:
		if evidence&round8SemanticCoreActiveRelation == 0 {
			return false
		}
		return (dimensions.action || dimensions.harm || dimensions.outcome || dimensions.impact) &&
			(dimensions.target || dimensions.destination || evidence&round8SemanticCorePrimary != 0)
	case rules.CategoryMalware:
		if evidence&round8SemanticCoreActiveRelation == 0 {
			return false
		}
		return (dimensions.action || dimensions.harm || dimensions.outcome || dimensions.impact) &&
			(dimensions.target || dimensions.destination || dimensions.evasion || dimensions.sequence) &&
			evidence&(round8SemanticCorePrimary|round8SemanticCoreSecondary) ==
				round8SemanticCorePrimary|round8SemanticCoreSecondary
	case rules.CategoryDisruption:
		if evidence&round8SemanticCoreActiveRelation == 0 {
			return false
		}
		return dimensions.object && (dimensions.action || dimensions.impact || dimensions.outcome || dimensions.harm) &&
			evidence&(round8SemanticCorePrimary|round8SemanticCoreSecondary) ==
				round8SemanticCorePrimary|round8SemanticCoreSecondary
	default:
		return true
	}
}

func round8SemanticDescriptiveOnly(text string) bool {
	text = strings.TrimSpace(text)
	if !hasAnyPrefix(text,
		"summarize ", "describe ", "compare ", "a taxonomy ", "the taxonomy ", "a glossary ", "the glossary ",
		"taxonomy ", "glossary ", "documentation ", "the documentation ", "a report ", "the report ",
		"总结", "描述", "比较", "分类法", "术语表", "文档", "报告",
	) {
		return false
	}
	return !containsAnyLiteral(text,
		" now ", " then ", "launch ", "deploy ", "execute ", "implement ", "run ", "carry it out", "do it",
		"provide code", "working code", "give the steps", "execution plan", "deployment plan",
		"现在", "然后", "发起", "部署", "执行", "实现", "运行", "照做", "给出步骤", "执行计划", "部署计划",
	)
}

func round8SemanticCorePredicate(category rules.Category, text string, dimensions semanticDimensions) bool {
	if !round8SemanticCoreCategory(category) {
		return true
	}
	return round8SemanticCorePredicateFromEvidence(
		category, dimensions, round8SemanticCoreEvidenceBits(category, text),
	)
}

func round8SemanticCoreCategory(category rules.Category) bool {
	switch category {
	case rules.CategoryCredentialTheft, rules.CategoryMalware, rules.CategoryDisruption, rules.CategoryEvasion:
		return true
	default:
		return false
	}
}

func round8ComposedRuleCorePredicate(ruleID, text string, operational, target, evasion, scale bool) bool {
	if ruleID == "DISRUPT-001" && operational && target &&
		explicitHostileDisruptionTarget(text) && explicitDisruptionTrafficMechanism(text) &&
		containsAnyLiteral(text,
			"execution plan", "execution sequence", "implementation plan", "implementation sequence", "rollout plan", "deployment plan",
			"执行计划", "执行步骤", "实施计划", "实施步骤", "投放计划", "部署计划",
		) {
		return true
	}
	match := ruleDirectiveMatch{}
	if operational {
		match.dimensionMask |= uint16(1) << ruleDimensionOperational
	}
	if target {
		match.dimensionMask |= uint16(1) << ruleDimensionTarget
	}
	if evasion {
		match.dimensionMask |= uint16(1) << ruleDimensionEvasion
	}
	if scale {
		match.dimensionMask |= uint16(1) << ruleDimensionScale
	}
	return round8RuleCorePredicate(ruleID, text, match)
}

func explicitHostileDisruptionTarget(text string) bool {
	return containsAnyLiteral(text,
		"competitor", "third-party", "third party", "victim", "unapproved target", "do not own",
		"竞争对手", "第三方", "受害", "未授权目标",
	)
}

func explicitDisruptionTrafficMechanism(text string) bool {
	return containsAnyLiteral(text,
		"flood", "request storm", "traffic storm", "distributed traffic", "distributed requests", "connection exhaustion", "connection pool", "opening connections", "automated traffic", "automated requests", "high-concurrency", "high concurrency",
		"请求风暴", "流量风暴", "分布式流量", "分布式请求", "连接耗尽", "持续占满", "自动化流量", "自动化请求", "高并发",
	)
}

func evidenceOccurrencesForMatch(ruleID string, match ruleDirectiveMatch) []EvidenceOccurrence {
	assignedOccurrences := match.assigned.items
	assignedCount := int(match.assigned.count)
	for index := 1; index < assignedCount; index++ {
		candidate := assignedOccurrences[index]
		position := index
		for position > 0 && assignedRuleOccurrenceLess(candidate, assignedOccurrences[position-1]) {
			assignedOccurrences[position] = assignedOccurrences[position-1]
			position--
		}
		assignedOccurrences[position] = candidate
	}
	result := make([]EvidenceOccurrence, 0, assignedCount)
	var dimensionCounts [ruleDimensionCount]int
	for assignedIndex := 0; assignedIndex < assignedCount; assignedIndex++ {
		assigned := assignedOccurrences[assignedIndex]
		dimensionCounts[assigned.dimension]++
		dimension := ruleDimensionKinds[assigned.dimension]
		result = append(result, EvidenceOccurrence{
			EvidenceID:     fmt.Sprintf("%s:%s:signal-%d", ruleID, dimension, dimensionCounts[assigned.dimension]),
			RuleID:         ruleID,
			Dimension:      dimension,
			SegmentID:      -1,
			FieldID:        -1,
			ClauseID:       int(assigned.occurrence.clauseID),
			SentenceID:     int(assigned.occurrence.clauseID),
			Start:          int(assigned.occurrence.start),
			End:            int(assigned.occurrence.end),
			Polarity:       PolarityAffirmative,
			DirectiveOwner: DirectiveOwnerUnknown,
			TermStrength:   ruleOccurrenceStrength(ruleID, assigned.dimension, match.text),
		})
	}
	return result
}

func assignedRuleOccurrenceLess(left, right assignedRuleOccurrence) bool {
	if left.dimension != right.dimension {
		return left.dimension < right.dimension
	}
	if left.occurrence.clauseID != right.occurrence.clauseID {
		return left.occurrence.clauseID < right.occurrence.clauseID
	}
	return left.occurrence.start < right.occurrence.start
}

func ruleOccurrenceStrength(ruleID string, dimension ruleDimension, text string) TermStrength {
	text = strings.ToLower(text)
	switch dimension {
	case ruleDimensionIntent, ruleDimensionObject, ruleDimensionTarget, ruleDimensionEvasion:
		return TermStrengthStrong
	case ruleDimensionScale:
		if containsAnyLiteral(text,
			"at scale", "multiple", "distributed", "across multiple", "hundreds", "thousands", "bulk", "several", "many clients", "high-concurrency", "high concurrency", "automated attack",
			"大规模", "批量", "多台", "多个", "几百", "几千", "数百", "数千", "分布式", "自动化", "自动协调",
		) {
			return TermStrengthStrong
		}
	case ruleDimensionOperational:
		switch ruleID {
		case "EVADE-002":
			if containsAnyLiteral(text, "deployable", "deploy ", "deploy the payload", "deploy it", "production deployment", "ready-to-run", "silent deletion", "可部署", "生产部署", "静默删除") {
				return TermStrengthStrong
			}
		case "MAL-002":
			if containsAnyLiteral(text, "ready-to-run", "provide source", "source code", "deploy", "deployment", "可运行", "源码", "部署") {
				return TermStrengthStrong
			}
		case "CRED-001", "CRED-002":
			if containsAnyLiteral(text,
				"write code", "complete code", "working code", "working tool", "working software", "deployable", "software", "automated tool", "create a", "build a", "utility",
				"send them to an external server", "send to an external server", "forward them to an external server",
				"完整代码", "完整程序", "完整工具", "可直接运行", "可运行", "可部署", "自动读取", "自动化工具", "制作一个", "工具", "程序",
			) {
				return TermStrengthStrong
			}
		case "DISRUPT-001":
			// Generic tool vocabulary is strong only when this same directive also
			// binds it to an explicit traffic or resource-exhaustion mechanism.
			if explicitDisruptionTrafficMechanism(text) {
				return TermStrengthStrong
			}
		}
	}
	return TermStrengthWeak
}

func strongRuleQualifierCount(ruleID string, match ruleDirectiveMatch) int {
	var seen [ruleDimensionCount]bool
	for assignedIndex := 0; assignedIndex < int(match.assigned.count); assignedIndex++ {
		assigned := match.assigned.items[assignedIndex]
		if assigned.dimension < ruleDimensionOperational || seen[assigned.dimension] {
			continue
		}
		if ruleOccurrenceStrength(ruleID, assigned.dimension, match.text) != TermStrengthStrong {
			continue
		}
		seen[assigned.dimension] = true
	}
	count := 0
	for dimension := ruleDimensionOperational; dimension < ruleDimensionCount; dimension++ {
		if seen[dimension] {
			count++
		}
	}
	return count
}

func isRound8TargetedRule(ruleID string) bool {
	switch ruleID {
	case "EVADE-002", "CRED-001", "CRED-002", "MAL-002", "DISRUPT-001":
		return true
	default:
		return false
	}
}

func qualifierScoreForRuleMatch(operational, target, evasion, scale bool, qualifierCount int) int {
	score := 0
	if operational {
		score += 20
	}
	if target {
		score += 18
	}
	if evasion {
		score += 16
	}
	if scale {
		score += 16
	}
	if qualifierCount >= 2 {
		score += 5
	}
	return score
}

func boolScore(value bool, points int) int {
	if value {
		return points
	}
	return 0
}

// ensureResultDecisionExplanation gives every auditable winner a bounded,
// content-free explanation. Ordinary rule candidates already carry precise
// occurrences; semantic, composed, and meta candidates are represented by
// stable synthetic evidence identifiers only after scoring, so they can never
// be used to satisfy ownership or hard-floor predicates.
func ensureResultDecisionExplanation(result *Result) {
	if result == nil || (result.Score == 0 && len(result.RuleIDs) == 0 && len(result.Evidence) == 0) {
		return
	}
	if len(result.EvidenceOccurrences) == 0 {
		fallbackRuleID := ""
		if len(result.RuleIDs) != 0 {
			fallbackRuleID = result.RuleIDs[0]
		}
		counts := make(map[string]int, len(result.Evidence))
		for _, evidence := range result.Evidence {
			if evidence.Kind == "" || evidence.Kind == "context" {
				continue
			}
			ruleID := evidenceRuleID(evidence.ID, fallbackRuleID)
			key := ruleID + "\x00" + evidence.Kind
			counts[key]++
			result.EvidenceOccurrences = append(result.EvidenceOccurrences, EvidenceOccurrence{
				EvidenceID:     fmt.Sprintf("%s:%s:signal-%d", ruleID, evidence.Kind, counts[key]),
				RuleID:         ruleID,
				Dimension:      evidence.Kind,
				SegmentID:      -1,
				FieldID:        -1,
				ClauseID:       -1,
				SentenceID:     -1,
				Start:          -1,
				End:            -1,
				Polarity:       PolarityAffirmative,
				DirectiveOwner: DirectiveOwnerUnknown,
				TermStrength:   TermStrengthStrong,
			})
		}
	}
	ensureStableOccurrenceIDs(result.EvidenceOccurrences)

	explanation := DecisionExplanation{}
	if result.DecisionExplanation != nil {
		explanation = *result.DecisionExplanation
	}
	if explanation.WinningRuleID == "" && len(result.RuleIDs) != 0 {
		explanation.WinningRuleID = result.RuleIDs[0]
	}
	if explanation.WinningCategory == "" && result.Category != "" {
		explanation.WinningCategory = string(result.Category)
	}
	explanation.EvidenceDimensionMask = occurrenceDimensionMask(result.EvidenceOccurrences)
	explanation.EvidenceOccurrenceCount = len(result.EvidenceOccurrences)
	if explanation.EvidenceSegmentCount == 0 && len(result.EvidenceOccurrences) != 0 {
		explanation.EvidenceSegmentCount = 1
	}
	explanation.ScoreBreakdown.FinalScore = result.Score
	result.DecisionExplanation = &explanation
}

func evidenceRuleID(evidenceID, fallback string) string {
	if index := strings.LastIndex(evidenceID, ":"); index > 0 {
		return evidenceID[:index]
	}
	if fallback != "" {
		return fallback
	}
	return "UNSCOPED"
}

func ensureStableOccurrenceIDs(occurrences []EvidenceOccurrence) {
	counts := make(map[string]int, len(occurrences))
	for index := range occurrences {
		occurrence := &occurrences[index]
		if occurrence.RuleID == "" {
			occurrence.RuleID = "UNSCOPED"
		}
		if occurrence.Dimension == "" {
			occurrence.Dimension = "evidence"
		}
		key := occurrence.RuleID + "\x00" + occurrence.Dimension
		counts[key]++
		if occurrence.EvidenceID == "" {
			occurrence.EvidenceID = fmt.Sprintf(
				"%s:%s:signal-%d", occurrence.RuleID, occurrence.Dimension, counts[key],
			)
		}
	}
}

func occurrenceDimensionMask(occurrences []EvidenceOccurrence) uint16 {
	var mask uint16
	for _, occurrence := range occurrences {
		if dimension, ok := explanationDimensionIndex(occurrence.Dimension); ok {
			mask |= uint16(1) << dimension
		}
	}
	return mask
}

func explanationDimensionIndex(kind string) (uint, bool) {
	for index, candidate := range [...]string{
		"intent", "object", "operational", "target", "evasion", "scale",
		"harm", "action", "outcome", "destination", "sequence", "impact",
		"hierarchy", "refusal_suppression", "unrestricted_mode", "direct_completion",
	} {
		if kind == candidate {
			return uint(index), true
		}
	}
	return 0, false
}
