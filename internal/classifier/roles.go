package classifier

import (
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
)

const maxRoleClassifierSegments = 64

var roleSafetyPunctuation = strings.NewReplacer("’", "'", "‘", "'", "“", `"`, "”", `"`)

// AnalyzeSegments scores a role-aware conversation under balanced defaults.
// The classifier is stateless: text is retained only for this call.
func (c *Classifier) AnalyzeSegments(segments []extract.Segment) Result {
	return c.ClassifySegments(segments, ModeBalanced, DefaultThresholds())
}

// ClassifySegments scores a role-aware conversation under the default policy.
func (c *Classifier) ClassifySegments(segments []extract.Segment, mode Mode, thresholds Thresholds) Result {
	return c.ClassifySegmentsWithPolicy(segments, mode, thresholds, DefaultPolicy())
}

// ClassifyUntrustedPartsWithPolicy is the fallback for valid provider bodies
// whose role provenance is absent or ambiguous. It preserves the legacy joint
// decision while also scanning each part and adjacent pair so older explicit
// abuse cannot be hidden behind appended benign fields. Longer inputs use the
// bounded streaming adapter instead of silently retaining only the tail.
func (c *Classifier) ClassifyUntrustedPartsWithPolicy(parts []string, mode Mode, thresholds Thresholds, policy Policy) Result {
	if len(parts) > maxRoleClassifierSegments {
		segments := make([]extract.Segment, len(parts))
		for index, part := range parts {
			segments[index] = extract.Segment{Role: extract.RoleUnknown, Provenance: extract.ProvenanceContent, Text: part}
		}
		result := c.classifyStreamingSegmentsCompat(segments, mode, thresholds, policy)
		result = withRoleAwareFindingOrigin(result, FindingOriginNonUserOrUntrusted, mode, thresholds)
		clearRolelessMetaTaxonomy(&result)
		attachBehaviorGraph(&result, "untrusted_parts", "")
		return result
	}
	segments := make([]extract.Segment, len(parts))
	for index, part := range parts {
		segments[index] = extract.Segment{Role: extract.Role("untrusted"), Text: part}
	}
	result := c.ClassifySegmentsWithPolicy(segments, mode, thresholds, policy)
	for _, reconstructed := range reconstructedIsolatedPartRuns(parts) {
		candidate := withRoleAwareFindingOrigin(
			c.classifyWithPolicy([]string{reconstructed}, mode, thresholds, policy, false),
			FindingOriginNonUserOrUntrusted,
			mode,
			thresholds,
		)
		if roleResultBetter(candidate, result) {
			result = candidate
		}
	}
	clearRolelessMetaTaxonomy(&result)
	attachBehaviorGraph(&result, "untrusted_parts", "")
	return result
}

// clearRolelessMetaTaxonomy keeps the legacy parts-only fallback auditable
// without claiming that an unknown actor owns a defense-evasion behavior. A
// role-aware system/assistant/tool segment retains CategoryEvasion so operators
// can distinguish the observed control-plane technique; only this public
// provenance-free API is categoryless.
func clearRolelessMetaTaxonomy(result *Result) {
	if result == nil || !standaloneMetaControlResult(*result) || result.Category == "" {
		return
	}
	result.Category = ""
	result.candidateIdentity.category = ""
	if result.DecisionExplanation != nil {
		explanation := *result.DecisionExplanation
		explanation.WinningCategory = ""
		result.DecisionExplanation = &explanation
	}
}

// ClassifySegmentsWithPolicy keeps user-to-user follow-up semantics while
// preventing assistant/system/tool text from being combined with user evidence.
// Provider-native tool payloads are always scanned independently, even when an
// assistant emitted them. Clear assistant refusals and system safety policies
// are not attributed as user intent. Every other eligible segment is classified
// independently so older explicit abuse cannot be hidden by appended benign
// history. The sole exception is an immediately refused trusted-user attack
// followed by a narrow trusted safety-maintenance request; execution follow-ups
// reactivate the established block. Unknown roles or provenance use the legacy
// all-parts classifier as a conservative fallback.
func (c *Classifier) ClassifySegmentsWithPolicy(segments []extract.Segment, mode Mode, thresholds Thresholds, policy Policy) Result {
	if hasProfiledSegmentMetadata(segments) {
		return c.classifyProfiledSegmentsWithPolicy(
			normalizeLegacySegmentsForProfiledClassification(segments), mode, thresholds, policy,
		)
	}
	if len(segments) > maxRoleClassifierSegments {
		return c.classifyStreamingSegmentsCompat(segments, mode, thresholds, policy)
	}
	truncated := false
	if !knownSegmentRoles(segments) {
		parts := make([]string, 0, len(segments))
		for _, segment := range segments {
			parts = append(parts, segment.Text)
		}
		best := withRoleAwareFindingOrigin(
			c.classifyWithPolicy(parts, mode, thresholds, policy, false),
			FindingOriginNonUserOrUntrusted, mode, thresholds,
		)
		if resultIsNeutralClassifierIncomplete(best) {
			attachBehaviorGraph(&best, "unknown_role_fallback", "")
			return best
		}
		truncated = truncated || best.Truncated
		for index, segment := range segments {
			candidate := withRoleAwareFindingOrigin(
				c.classifyWithPolicy([]string{segment.Text}, mode, thresholds, policy, false),
				FindingOriginNonUserOrUntrusted,
				mode,
				thresholds,
			)
			if resultIsNeutralClassifierIncomplete(candidate) {
				attachBehaviorGraph(&candidate, "unknown_role_fallback", "")
				return candidate
			}
			truncated = truncated || candidate.Truncated
			if roleResultBetter(candidate, best) {
				best = candidate
			}
			if index > 0 {
				adjacent := withRoleAwareFindingOrigin(
					c.classifyWithPolicy([]string{segments[index-1].Text, segment.Text}, mode, thresholds, policy, false),
					FindingOriginNonUserOrUntrusted,
					mode,
					thresholds,
				)
				if resultIsNeutralClassifierIncomplete(adjacent) {
					attachBehaviorGraph(&adjacent, "unknown_role_fallback", "")
					return adjacent
				}
				truncated = truncated || adjacent.Truncated
				if roleResultBetter(adjacent, best) {
					best = adjacent
				}
			}
		}
		best.Truncated = best.Truncated || truncated
		enforceResultCandidateEligibility(&best, mode, thresholds)
		attachBehaviorGraph(&best, "unknown_role_fallback", "")
		return best
	}
	closedHistoryUser, closedHistoryRefusal, hasClosedHistory :=
		c.refusedHistoricalSafetyMaintenanceTail(segments, mode, thresholds, policy)

	best := c.classifyWithPolicy(nil, mode, thresholds, policy, false)
	previousUser := ""
	hasPreviousUser := false
	previousUserTrusted := false
	recentUsers := make([]string, 0, 3)
	recentUsersTrusted := make([]bool, 0, 3)
	linkedMetaUsers := make([]string, 0, 8)
	linkedMetaUsersTrusted := make([]bool, 0, 8)
	lastMetaUser := ""
	pendingNonUserControl := ""
	lastUserControl := ""
	considerControlPair := func(nonUser, user string) {
		if nonUser == "" || user == "" || !metaOverridePartsLinked(nonUser, user) {
			return
		}
		controlCandidate := withRoleAwareFindingOrigin(
			c.classifyWithPolicy([]string{nonUser, user}, mode, thresholds, policy, false),
			FindingOriginNonUserOrUntrusted,
			mode,
			thresholds,
		)
		truncated = truncated || controlCandidate.Truncated
		if standaloneMetaControlResult(controlCandidate) && roleResultBetter(controlCandidate, best) {
			best = controlCandidate
		}
	}
	for index, segment := range segments {
		if hasClosedHistory && index == closedHistoryUser {
			// This exact trusted-user block is the referent of the immediately
			// following clear assistant refusal. It is ignored only because the
			// final trusted-user turn is a narrow safety-maintenance request. Other
			// historical findings remain independently ranked.
			continue
		}
		classifySegment := shouldClassifyRoleSegment(segment)
		if classifySegment {
			candidate := c.classifyWithPolicy(
				[]string{segment.Text}, mode, thresholds, policy,
				segment.Provenance == extract.ProvenanceToolPayload,
			)
			candidate = withRoleAwareFindingOrigin(candidate, findingOriginForSegment(segment), mode, thresholds)
			truncated = truncated || candidate.Truncated
			if roleResultBetter(candidate, best) {
				best = candidate
			}
		}
		if segment.Role != extract.RoleUser || segment.Provenance != extract.ProvenanceContent {
			if classifySegment {
				considerControlPair(segment.Text, lastUserControl)
				pendingNonUserControl = segment.Text
			} else {
				pendingNonUserControl = ""
			}
		}
		if segment.Provenance == extract.ProvenanceContent && (segment.Role == extract.RoleAssistant || segment.Role == extract.RoleSystem) {
			if continuation := unscopedSafetyContinuation(segment.Role, strings.ToLower(roleSafetyPunctuation.Replace(segment.Text))); continuation != "" {
				candidate := withRoleAwareFindingOrigin(
					c.classifyWithPolicy([]string{continuation}, mode, thresholds, policy, false),
					FindingOriginNonUserOrUntrusted,
					mode,
					thresholds,
				)
				truncated = truncated || candidate.Truncated
				if roleResultBetter(candidate, best) {
					best = candidate
				}
			}
		}
		if hasClosedHistory && index == closedHistoryRefusal {
			// A proven refusal closes only its immediately preceding attack turn.
			// Clear the bounded user-composition state so the safe maintenance tail
			// cannot be recombined with that closed referent. Independently ranked
			// older findings in best are intentionally untouched.
			previousUser = ""
			hasPreviousUser = false
			previousUserTrusted = false
			clear(recentUsers)
			recentUsers = recentUsers[:0]
			clear(recentUsersTrusted)
			recentUsersTrusted = recentUsersTrusted[:0]
			clear(linkedMetaUsers)
			linkedMetaUsers = linkedMetaUsers[:0]
			clear(linkedMetaUsersTrusted)
			linkedMetaUsersTrusted = linkedMetaUsersTrusted[:0]
			lastMetaUser = ""
			lastUserControl = ""
		}
		if segment.Role != extract.RoleUser || segment.Provenance != extract.ProvenanceContent {
			continue
		}
		currentUserTrusted := segment.UserAttribution == extract.UserAttributionTrusted
		considerControlPair(pendingNonUserControl, segment.Text)
		pendingNonUserControl = ""
		lastUserControl = segment.Text
		if len(linkedMetaUsers) == 0 || metaOverridePartsLinked(lastMetaUser, segment.Text) {
			linkedMetaUsers = append(linkedMetaUsers, segment.Text)
			linkedMetaUsersTrusted = append(linkedMetaUsersTrusted, currentUserTrusted)
			if len(linkedMetaUsers) > maxRoleClassifierSegments {
				copy(linkedMetaUsers, linkedMetaUsers[len(linkedMetaUsers)-maxRoleClassifierSegments:])
				linkedMetaUsers = linkedMetaUsers[:maxRoleClassifierSegments]
				copy(linkedMetaUsersTrusted, linkedMetaUsersTrusted[len(linkedMetaUsersTrusted)-maxRoleClassifierSegments:])
				linkedMetaUsersTrusted = linkedMetaUsersTrusted[:maxRoleClassifierSegments]
			}
		} else {
			linkedMetaUsers = append(linkedMetaUsers[:0], segment.Text)
			linkedMetaUsersTrusted = append(linkedMetaUsersTrusted[:0], currentUserTrusted)
		}
		lastMetaUser = segment.Text
		if len(linkedMetaUsers) > 1 {
			metaCandidate := withRoleAwareFindingOrigin(
				c.classifyWithPolicy(linkedMetaUsers, mode, thresholds, policy, false),
				userCombinationFindingOrigin(allTrusted(linkedMetaUsersTrusted)),
				mode,
				thresholds,
			)
			truncated = truncated || metaCandidate.Truncated
			if roleResultBetter(metaCandidate, best) {
				best = metaCandidate
			}
		}
		if hasPreviousUser {
			origin := userCombinationFindingOrigin(previousUserTrusted && currentUserTrusted)
			followUp := withRoleAwareFindingOrigin(
				c.classifyWithPolicy([]string{previousUser, segment.Text}, mode, thresholds, policy, false),
				origin,
				mode,
				thresholds,
			)
			truncated = truncated || followUp.Truncated
			if roleResultBetter(followUp, best) {
				best = followUp
			}
			// Adjacent user turns may split an abuse intent from its object. Join
			// only user-authored text and only when the prior turn is eligible for
			// follow-up; system/assistant/tool examples can never contribute.
			joinEligible := followUpEligible([]rune(previousUser))
			if joinEligible && c.isRawInertQuotedSafetyReview(previousUser) {
				joinEligible = false
			}
			if joinEligible {
				joined := withRoleAwareFindingOrigin(
					c.classifyWithPolicy([]string{previousUser + "\n" + segment.Text}, mode, thresholds, policy, false),
					origin,
					mode,
					thresholds,
				)
				truncated = truncated || joined.Truncated
				if roleResultBetter(joined, best) {
					best = joined
				}
			}
		}
		recentUsers = append(recentUsers, segment.Text)
		recentUsersTrusted = append(recentUsersTrusted, currentUserTrusted)
		if len(recentUsers) > 3 {
			copy(recentUsers, recentUsers[len(recentUsers)-3:])
			recentUsers = recentUsers[:3]
			copy(recentUsersTrusted, recentUsersTrusted[len(recentUsersTrusted)-3:])
			recentUsersTrusted = recentUsersTrusted[:3]
		}
		if len(recentUsers) == 3 && threeTurnPlanWindowEligible(recentUsers) {
			joined := withRoleAwareFindingOrigin(
				c.classifyWithPolicy([]string{strings.Join(recentUsers, "\n")}, mode, thresholds, policy, false),
				userCombinationFindingOrigin(allTrusted(recentUsersTrusted)),
				mode,
				thresholds,
			)
			truncated = truncated || joined.Truncated
			if roleResultBetter(joined, best) {
				best = joined
			}
		}
		previousUser = segment.Text
		hasPreviousUser = true
		previousUserTrusted = currentUserTrusted
	}
	for _, reconstructed := range reconstructedIsolatedUserRuns(segments) {
		candidate := withRoleAwareFindingOrigin(
			c.classifyWithPolicy([]string{reconstructed.text}, mode, thresholds, policy, false),
			userCombinationFindingOrigin(reconstructed.trusted),
			mode,
			thresholds,
		)
		truncated = truncated || candidate.Truncated
		if roleResultBetter(candidate, best) {
			best = candidate
		}
	}
	// A bounded run of user-authored content parts may split one explicitly
	// quoted, inert review across segment boundaries. Prefixes are classified
	// conservatively while the run is incomplete; once the complete structural
	// boundary proves that the quoted sample is inert and the last effective
	// directive is analysis/non-execution, replace only a wrapper-only prefix
	// result. Base cyber-abuse behavior, tool text, non-user text, long runs, and
	// malformed quote boundaries can never be cleared by this path.
	if best.Behavior != nil && best.Behavior.Wrapper && !best.Behavior.BaseBehavior {
		if joined, ok := metaOverrideDefensiveUserSegmentRun(segments); ok {
			candidate := withRoleAwareFindingOrigin(
				c.classifyWithPolicy([]string{joined}, mode, thresholds, policy, false),
				FindingOriginUserContent,
				mode,
				thresholds,
			)
			truncated = truncated || candidate.Truncated
			if !truncated && candidate.Action == ActionAllow && candidate.Score < AuditThreshold &&
				(candidate.Behavior == nil || !candidate.Behavior.BaseBehavior) {
				best = candidate
			}
		}
	}
	best.Truncated = best.Truncated || truncated
	enforceResultCandidateEligibility(&best, mode, thresholds)
	attachBehaviorGraph(&best, "role_aware", "")
	return best
}

type profiledSegmentRef struct {
	index              int
	physicalOrdinal    int
	hasPhysicalOrdinal bool
	segment            extract.Segment
}

type profiledSegmentGroup struct {
	refs            []profiledSegmentRef
	parts           []string
	activeDirective bool
	structuredTool  bool
}

type profiledDeferredFieldCandidate struct {
	ref       profiledSegmentRef
	candidate Result
}

type profiledIncompleteCorrelation struct {
	reason       CoverageReason
	scope        EnforcementScope
	scopeID      uint64
	fieldID      int
	fieldSet     bool
	correlatable bool
}

func (pending *profiledIncompleteCorrelation) rememberUncorrelated(reason CoverageReason) {
	if pending == nil || reason == CoverageReasonNone {
		return
	}
	if pending.reason == CoverageReasonNone {
		pending.reason = reason
	}
	pending.scope = EnforcementScopeNone
	pending.scopeID = 0
	pending.fieldID = 0
	pending.fieldSet = false
	pending.correlatable = false
}

func (pending *profiledIncompleteCorrelation) rememberField(
	reason CoverageReason,
	ref profiledSegmentRef,
) {
	if pending == nil || reason == CoverageReasonNone {
		return
	}
	scope := enforcementScopeForProfiledGroup([]profiledSegmentRef{ref})
	if scope == EnforcementScopeNone || ref.segment.ScopeID == 0 || ref.index < 0 {
		pending.rememberUncorrelated(reason)
		return
	}
	if pending.reason == CoverageReasonNone {
		pending.reason = reason
		pending.scope = scope
		pending.scopeID = ref.segment.ScopeID
		pending.fieldID = ref.index
		pending.fieldSet = true
		pending.correlatable = true
		return
	}
	if pending.reason != reason || !pending.correlatable || !pending.fieldSet ||
		pending.scope != scope || pending.scopeID != ref.segment.ScopeID ||
		pending.fieldID != ref.index {
		pending.rememberUncorrelated(pending.reason)
	}
}

func (pending *profiledIncompleteCorrelation) merge(other profiledIncompleteCorrelation) {
	if pending == nil || other.reason == CoverageReasonNone {
		return
	}
	if !other.correlatable || !other.fieldSet {
		pending.rememberUncorrelated(other.reason)
		return
	}
	if pending.reason == CoverageReasonNone {
		*pending = other
		return
	}
	if pending.reason != other.reason || !pending.correlatable || !pending.fieldSet ||
		pending.scope != other.scope || pending.scopeID != other.scopeID ||
		pending.fieldID != other.fieldID {
		pending.rememberUncorrelated(pending.reason)
	}
}

func (pending profiledIncompleteCorrelation) resolvedBy(
	result Result,
	thresholds Thresholds,
) bool {
	return pending.reason != CoverageReasonNone && pending.correlatable && pending.fieldSet &&
		resultHasCompleteBlockForProfiledField(
			result, thresholds, pending.scope, pending.scopeID, pending.fieldID,
		)
}

type profiledSegmentGroupKey struct {
	role            extract.Role
	provenance      extract.SegmentProvenance
	attribution     extract.UserAttribution
	toolAssociation extract.ToolResultAssociation
	turnIndex       int
	currentTurn     bool
	scopeID         uint64
	zeroScopeUnique int
}

func profiledGroupAllowsExtendedGeneratedAgentWindow(group profiledSegmentGroup) bool {
	if len(group.refs) == 0 || len(group.refs) != len(group.parts) {
		return false
	}
	owner := group.refs[0].segment
	for _, ref := range group.refs {
		segment := ref.segment
		if !profiledTrustedCurrentUserNaturalLanguageDirective(segment) ||
			segment.TurnIndex != owner.TurnIndex || segment.ScopeID != owner.ScopeID ||
			segment.UserAttribution != owner.UserAttribution {
			return false
		}
	}
	return true
}

func (c *Classifier) classifyProfiledGroupWithPolicy(
	group profiledSegmentGroup,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) Result {
	if profiledGroupAllowsExtendedGeneratedAgentWindow(group) {
		return c.classifyTrustedCurrentUserWithPolicy(group.parts, mode, thresholds, policy)
	}
	return c.classifyWithPolicy(group.parts, mode, thresholds, policy, group.structuredTool)
}

func hasProfiledSegmentMetadata(segments []extract.Segment) bool {
	for _, segment := range segments {
		if segmentDeclaresProfiledMetadata(segment) {
			return true
		}
	}
	return false
}

func segmentUsesLegacyUntrustedFallback(segment extract.Segment) bool {
	return segment.Role == extract.RoleUnknown &&
		segment.Provenance == extract.ProvenanceContent &&
		segment.UserAttribution == extract.UserAttributionUntrusted &&
		!segment.IsCurrentTurn && !segment.HasTerminalCoordinates &&
		segment.ToolAssociation == extract.ToolResultAssociationNone
}

func segmentDeclaresProfiledMetadata(segment extract.Segment) bool {
	// Index values cannot signal presence: zero is a valid first conversation
	// item/turn, while -1 is also emitted by the legacy extractor for unknown
	// coordinates. Scope/path/content metadata describes structure, but cannot by
	// itself upgrade roleless untrusted content into profiled authority. Explicit
	// current/terminal/tool authority remains an opt-in boundary.
	if segmentUsesLegacyUntrustedFallback(segment) {
		return false
	}
	return segment.ContentKind != extract.ContentKindUnknown || segment.ScopeID != 0 ||
		segment.FieldPathHash != "" || segment.IsCurrentTurn ||
		segment.ToolAssociation != extract.ToolResultAssociationNone || segment.HasTerminalCoordinates
}

func segmentDeclaresProfiledCoordinates(segment extract.Segment) bool {
	// ContentKind alone describes syntax, not a position in provider history.
	// Scope/path ownership or an explicit current-turn marker is required before
	// zero-valued indexes can safely mean the first conversation item/turn.
	return segment.ScopeID != 0 || segment.FieldPathHash != "" || segment.IsCurrentTurn
}

func normalizeLegacySegmentsForProfiledClassification(segments []extract.Segment) []extract.Segment {
	normalized := segments
	copied := false
	for index, segment := range segments {
		if segmentDeclaresProfiledCoordinates(segment) ||
			segment.ConversationIndex == -1 && segment.TurnIndex == -1 {
			continue
		}
		if !copied {
			normalized = append([]extract.Segment(nil), segments...)
			copied = true
		}
		normalized[index].ConversationIndex = -1
		normalized[index].TurnIndex = -1
	}
	return normalized
}

// classifyProfiledSegmentsWithPolicy applies the Round 8 ownership contract to
// extractor-proven conversation metadata. Historical content is context, not a
// request-wide bag of evidence; only current user scopes, independent active
// system directives, and executable tool-call arguments are ranked. Legacy
// zero-value Segment callers continue through the established path above.
func (c *Classifier) classifyProfiledSegmentsWithPolicy(
	segments []extract.Segment,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) Result {
	if state, reason := profiledBatchInputCoverageFailure(segments); reason != CoverageReasonNone {
		return c.profiledCoverageFailureResult(mode, thresholds, policy, state, reason)
	}
	best := c.classifyWithPolicy(nil, mode, thresholds, policy, false)
	truncated := false
	quotedOrInertSuppressed := false
	carrierProofUnavailable := false
	var pendingClassifierIncomplete profiledIncompleteCorrelation
	for _, group := range buildProfiledCurrentMetaControlGroups(segments) {
		for _, run := range profiledDirectCompactionRuns(group) {
			if !run.hasCarrier || run.totalBytes == 0 {
				pendingClassifierIncomplete.rememberUncorrelated(CoverageReasonClassifierWindow)
				continue
			}
			if run.totalBytes > maxMetaOverrideDirectControlWindowBytes {
				proof, proofBytes, complete := profiledDirectCompactionBoundedProof(run.group)
				if !complete {
					pendingClassifierIncomplete.rememberUncorrelated(CoverageReasonClassifierWindow)
					continue
				}
				run.group = proof
				run.totalBytes = proofBytes
			}
			candidate := c.classifyProfiledGroupWithPolicy(run.group, mode, thresholds, policy)
			if resultIsNeutralClassifierIncomplete(candidate) {
				reason := classifierIncompleteReason(candidate)
				if classifierIncompleteCoverageReason(reason) {
					pendingClassifierIncomplete.rememberUncorrelated(reason)
				}
				continue
			}
			if !standaloneMetaControlResult(candidate) ||
				!resultHasEligibleBlockingCandidate(candidate, thresholds) {
				continue
			}
			candidate = withRoleAwareFindingOrigin(
				candidate, FindingOriginUserContent, mode, thresholds,
			)
			c.annotateProfiledResult(&candidate, run.group.refs, false, policy, mode, thresholds)
			truncated = truncated || candidate.Truncated
			if roleResultBetter(candidate, best) {
				best = candidate
			}
		}
		activeGroup, complete := c.profiledActiveMetaControlGroup(segments, group)
		if !complete {
			carrierProofUnavailable = true
			continue
		}
		activeGroup = profiledGroupWithoutDirectCompactionApplications(activeGroup)
		if !activeGroup.activeDirective || len(activeGroup.parts) < 2 {
			continue
		}
		candidate := c.classifyProfiledGroupWithPolicy(activeGroup, mode, thresholds, policy)
		if !standaloneMetaControlResult(candidate) ||
			!resultHasEligibleBlockingCandidate(candidate, thresholds) {
			continue
		}
		candidate = withRoleAwareFindingOrigin(
			candidate, FindingOriginUserContent, mode, thresholds,
		)
		c.annotateProfiledResult(&candidate, activeGroup.refs, false, policy, mode, thresholds)
		truncated = truncated || candidate.Truncated
		if roleResultBetter(candidate, best) {
			best = candidate
		}
	}
	for index := 0; index < len(segments); {
		segment := segments[index]
		if strings.TrimSpace(segment.Text) == "" {
			index++
			continue
		}
		if !profiledTrustedCurrentUserCarrier(segment) ||
			!profiledSelfContainedCarrierKind(segment.ContentKind) {
			if profiledContentInert(segment.ContentKind) || profiledTrustedCurrentUserCarrier(segment) {
				quotedOrInertSuppressed = true
			}
			index++
			continue
		}

		quotedOrInertSuppressed = true
		end := index + 1
		for end < len(segments) && profiledSelfContainedCarrierRunAdjacent(
			segments[end-1], segments[end],
		) {
			end++
		}
		refs, parts, imperative, complete := c.profiledSelfContainedCarrierRun(
			segments, index, end,
		)
		if !complete {
			carrierProofUnavailable = true
			index = end
			continue
		}
		if imperative {
			owner, localOwner := c.profiledSelfContainedCarrierRunLocalOwner(
				segments, index, end,
			)
			// A fenced carrier is evidence, not an execution speech act. One
			// carrier is handled by the ordinary direct/referent composition paths;
			// a split carrier run is admitted here only when an adjacent natural-
			// language owner explicitly reactivates it.
			if !localOwner || len(refs) == 1 {
				index = end
				continue
			}
			suppressed, reactivated, complete :=
				c.profiledCarrierLocalOwnerRunDisposition(owner.segment)
			if !complete {
				return c.profiledProofUnavailableResult(mode, thresholds, policy)
			}
			if suppressed || !reactivated {
				index = end
				continue
			}
			candidate := c.classifyWithPolicy(
				parts, mode, thresholds, policy, false,
			)
			if resultIsNeutralClassifierIncomplete(candidate) {
				reason := classifierIncompleteReason(candidate)
				if classifierIncompleteCoverageReason(reason) {
					pendingClassifierIncomplete.rememberUncorrelated(reason)
				}
				index = end
				continue
			}
			if profiledSelfContainedCarrierCandidate(candidate, thresholds) {
				if len(refs) > 1 {
					profiledCarrierRunClearOccurrenceOffsets(&candidate)
				}
				candidate = withRoleAwareFindingOrigin(
					candidate, FindingOriginUserContent, mode, thresholds,
				)
				c.annotateProfiledResult(&candidate, refs, false, policy, mode, thresholds)
				markResultReferentActivated(&candidate, true, true, mode, thresholds)
				bindResultCandidateReferentAnchor(&candidate, owner, true, mode, thresholds)
				if candidate.DecisionExplanation != nil {
					candidate.DecisionExplanation.CurrentTurnEvidence = true
					candidate.DecisionExplanation.CrossSegmentComposition = true
					candidate.DecisionExplanation.ReferentLinkUsed = true
					candidate.DecisionExplanation.EvidenceSegmentCount = len(refs) + 1
				}
				truncated = truncated || candidate.Truncated
				if roleResultBetter(candidate, best) {
					best = candidate
				}
			}
		}
		index = end
	}
	systemCarrierGroups := buildProfiledRequestLocalSystemReactivationGroups(segments)
	groups := buildProfiledSegmentGroups(segments, false)
	carrierOmissions, unresolvedCarriers, carrierSuppressed, carrierOwnershipComplete :=
		c.profiledRequestLocalSystemCarrierGenericPlan(systemCarrierGroups, true)
	if !carrierOwnershipComplete {
		carrierProofUnavailable = true
	}
	if carrierSuppressed {
		quotedOrInertSuppressed = true
	}
	if candidate, ok, complete := c.bestProfiledRequestLocalSystemReactivationCandidate(
		systemCarrierGroups, mode, thresholds, policy,
	); !complete {
		carrierProofUnavailable = true
	} else if ok {
		truncated = truncated || candidate.Truncated
		if roleResultBetter(candidate, best) {
			best = candidate
		}
	}
	var activationProofs map[int]profiledIndependentWindowRecoveryProof
	var activationCandidates []Result
	candidate, ok, incompleteCorrelation := c.bestProfiledCurrentNaturalLanguageCandidate(
		groups, mode, thresholds, policy, &activationProofs, &activationCandidates,
	)
	pendingClassifierIncomplete.merge(incompleteCorrelation)
	if ok {
		truncated = truncated || candidate.Truncated
		if roleResultBetter(candidate, best) {
			best = candidate
		}
	}
	for _, group := range groups {
		group = profiledGroupWithoutCarrierIndexes(group, carrierOmissions, unresolvedCarriers)
		group = profiledMultiFieldGroupWithRecoveryRangesMasked(group, activationProofs)
		if len(group.parts) == 0 {
			continue
		}
		if profiledHistoricalUserSharesToolResultConversation(group, segments) {
			// A provider item that mixes result payload and trusted-user text has
			// no unique generic referent. The text is a locality barrier, not an
			// independently rankable historical user request; retaining it as an
			// audit winner would also diverge from bounded streaming state.
			quotedOrInertSuppressed = true
			continue
		}
		candidate := c.classifyProfiledGroupWithPolicy(group, mode, thresholds, policy)
		origin := findingOriginForSegment(group.refs[0].segment)
		roleOwnedWrapper := profiledRoleOwnedWrapper(candidate, origin)
		if !group.activeDirective && !roleOwnedWrapper &&
			candidate.Score >= validThresholdsOrDefault(thresholds).BalancedBlock {
			// Code/configuration without an active natural-language execution
			// relation is reviewable evidence, but is not a balanced block by
			// itself under the Round 8 content-kind contract.
			originalScore := candidate.Score
			candidate.Score = validThresholdsOrDefault(thresholds).BalancedBlock - 1
			if candidate.DecisionExplanation != nil {
				// The content-kind boundary removes active-directive weight; keep the
				// numeric explanation conservative so every persisted component still
				// sums to the capped decision score before actor binding runs.
				candidate.DecisionExplanation.ScoreBreakdown.ActiveDirectiveScore += candidate.Score - originalScore
				candidate.DecisionExplanation.ScoreBreakdown.FinalScore = candidate.Score
			}
			markResultCandidateInactive(&candidate, mode, thresholds)
			if candidate.DecisionExplanation != nil {
				candidate.DecisionExplanation.CorePredicateComplete = false
				candidate.DecisionExplanation.HardFloorApplied = false
				candidate.DecisionExplanation.HardFloorReason = ""
			}
			markQuotedOrInertSuppressed(&candidate)
			quotedOrInertSuppressed = true
		}
		enforcementScope := enforcementScopeForProfiledGroup(group.refs)
		candidate = withRoleAwareFindingOriginAndScope(
			candidate, origin, enforcementScope, mode, thresholds,
		)
		c.annotateProfiledResult(&candidate, group.refs, false, policy, mode, thresholds)
		if len(group.refs) == 1 {
			ref := group.refs[0]
			if proof, ok := activationProofs[ref.index]; ok &&
				c.profiledOrdinaryWinnerWithinInertIndependentWindow(
					candidate, thresholds, policy, ref.segment.Text, proof,
				) {
				quotedOrInertSuppressed = true
				continue
			}
		}
		if candidate.DecisionExplanation != nil && candidate.DecisionExplanation.QuotedOrInertSuppressed {
			quotedOrInertSuppressed = true
		}
		classifierIncomplete := candidate.Truncated &&
			candidate.Coverage.State == CoverageUnavailable &&
			classifierIncompleteCoverageReason(candidate.Coverage.Reason)
		if classifierIncomplete {
			// Only a group with current request enforcement authority can make its
			// unresolved classifier proof request-wide. Historical assistant/user
			// audit groups remain inspectable evidence, but cannot change current
			// coverage. A later independent complete block still wins regardless of
			// physical field order.
			if enforcementScope != EnforcementScopeNone {
				if len(group.refs) == 1 {
					pendingClassifierIncomplete.rememberField(candidate.Coverage.Reason, group.refs[0])
				} else {
					pendingClassifierIncomplete.rememberUncorrelated(candidate.Coverage.Reason)
				}
			}
			continue
		}
		truncated = truncated || candidate.Truncated
		if roleResultBetter(candidate, best) {
			best = candidate
		}
	}
	// Code/configuration may complete an immediately adjacent active sentence in
	// the same current user scope (for example, "Create ..." followed by a code
	// continuation). This is distinct from referent reactivation: only the final
	// natural-language segment and one adjacent code/config carrier participate,
	// so benign review directives cannot activate an arbitrary payload elsewhere
	// in the scope.
	for _, group := range groups {
		directCandidates, proofComplete := c.classifyProfiledCurrentDirectCarriers(
			segments, group, mode, thresholds, policy,
		)
		if !proofComplete {
			// A winner from another field does not reconstruct the direct code/config
			// association whose proof was lost here. Keep ranking complete candidates,
			// but preserve the request-wide incomplete disposition independently.
			pendingClassifierIncomplete.rememberUncorrelated(CoverageReasonClassifierWindow)
			continue
		}
		for _, candidate := range directCandidates {
			truncated = truncated || candidate.Truncated
			if roleResultBetter(candidate, best) {
				best = candidate
			}
		}
	}

	// A terse affirmative referent such as "Execute it" first binds to a
	// referent-bearing carrier in the same non-zero current user scope. The local
	// carrier owns that speech act even when it is benign, so a bare referent
	// cannot skip it and jump backward to an unrelated historical attack. Only
	// when the current scope has no eligible carrier may the established nearest-
	// historical-scope rule run.
	if c.profiledReferentCarrierPossible(segments) {
		currentReferents, referentProofComplete := affirmativeCurrentReferents(c, groups)
		if !referentProofComplete {
			// Scope identity alone cannot prove that an independent winner covers the
			// exact field/occurrence whose referent ownership was lost.
			pendingClassifierIncomplete.rememberUncorrelated(CoverageReasonClassifierWindow)
			currentReferents = nil
		}
		for _, currentReferent := range currentReferents {
			anchor := currentReferent.anchor
			if carrier, localOwner := c.selectProfiledCurrentCarrier(segments, currentReferent.group, anchor); localOwner {
				if len(carrier.refs) != 0 {
					referent := c.classifyWithPolicy(carrier.parts, mode, thresholds, policy, false)
					truncated = truncated || referent.Truncated
					if referent.FindingConfidence != FindingNone {
						// The roleless carrier result cannot prove current-user ownership or
						// the referent chain yet. Bind the exact profiled actor, carrier
						// occurrences, and current speech-act anchor before asking the
						// candidate-level eligibility gate to admit it. Checking eligibility
						// first permanently discards an otherwise complete quoted/semantic
						// carrier merely because its provenance is still unbound.
						referent = withRoleAwareFindingOrigin(referent, FindingOriginUserContent, mode, thresholds)
						c.annotateProfiledResult(&referent, carrier.refs, false, policy, mode, thresholds)
						markResultReferentActivated(&referent, true, true, mode, thresholds)
						bindResultCandidateReferentAnchor(&referent, anchor, true, mode, thresholds)
						if !resultHasEligibleMaliciousWinner(referent, thresholds) {
							continue
						}
						if referent.DecisionExplanation != nil {
							referent.DecisionExplanation.CurrentTurnEvidence = true
							referent.DecisionExplanation.CrossSegmentComposition = true
							referent.DecisionExplanation.ReferentLinkUsed = true
							referent.DecisionExplanation.EvidenceSegmentCount = len(carrier.refs) + 1
						}
						if roleResultBetter(referent, best) {
							best = referent
						}
					}
				}
			} else if referent, _, claimed, ok, complete :=
				c.nearestProfiledHistoricalToolReferent(segments, anchor, mode, thresholds, policy); claimed {
				if !complete {
					return c.profiledProofUnavailableResult(mode, thresholds, policy)
				}
				if !ok {
					// The immediately preceding provider item owns the referent slot
					// even when it is benign or structurally ambiguous. Never skip it
					// and bind a current execution act to older history.
					continue
				}
				if roleResultBetter(referent, best) {
					best = referent
				}
			} else if referent, historical, evidenceRefs, ok := c.nearestProfiledHistoricalReferent(segments, mode, thresholds, policy); ok {
				referent = withRoleAwareFindingOrigin(referent, FindingOriginUserContent, mode, thresholds)
				c.annotateProfiledResult(&referent, evidenceRefs, false, policy, mode, thresholds)
				markResultReferentActivated(&referent, true, true, mode, thresholds)
				bindResultCandidateReferentAnchor(&referent, anchor, true, mode, thresholds)
				if referent.DecisionExplanation != nil {
					referent.DecisionExplanation.CurrentTurnEvidence = true
					referent.DecisionExplanation.CrossSegmentComposition = true
					referent.DecisionExplanation.ReferentLinkUsed = true
					referent.DecisionExplanation.EvidenceSegmentCount = len(historical.refs) + 1
				}
				if roleResultBetter(referent, best) {
					best = referent
				}
			}
		}
	}
	// Recovery is deliberately ranked after ordinary, direct-carrier, and
	// referent candidates. It still wins when it is strictly better or when those
	// paths found no eligible candidate, but an equal full-field winner retains
	// its more precise occurrence and eligibility proof.
	for _, candidate := range activationCandidates {
		if roleResultBetter(candidate, best) {
			best = candidate
		}
	}
	if carrierProofUnavailable {
		pendingClassifierIncomplete.rememberUncorrelated(CoverageReasonClassifierWindow)
	}
	if pendingClassifierIncomplete.reason != CoverageReasonNone &&
		!pendingClassifierIncomplete.resolvedBy(best, thresholds) {
		return c.profiledProofUnavailableResult(
			mode, thresholds, policy, pendingClassifierIncomplete.reason,
		)
	}
	best.Truncated = best.Truncated || truncated
	enforceResultCandidateEligibility(&best, mode, thresholds)
	ensureResultDecisionExplanation(&best)
	if quotedOrInertSuppressed {
		markQuotedOrInertSuppressed(&best)
	}
	attachBehaviorGraph(&best, "role_aware_profiled", "")
	return best
}

func profiledHistoricalUserSharesToolResultConversation(
	group profiledSegmentGroup,
	segments []extract.Segment,
) bool {
	if len(group.refs) == 0 {
		return false
	}
	owner := group.refs[0].segment
	if owner.IsCurrentTurn || owner.ConversationIndex < 0 || !trustedUserContentSegment(owner) {
		return false
	}
	for _, segment := range segments {
		if segment.ConversationIndex == owner.ConversationIndex &&
			segment.Role == extract.RoleTool && segment.Provenance == extract.ProvenanceContent &&
			segment.ContentKind == extract.ContentKindToolResult {
			return true
		}
	}
	return false
}

func profiledMultiFieldGroupWithRecoveryRangesMasked(
	group profiledSegmentGroup,
	proofs map[int]profiledIndependentWindowRecoveryProof,
) profiledSegmentGroup {
	if len(group.refs) <= 1 || len(proofs) == 0 || len(group.parts) != len(group.refs) {
		return group
	}
	masked := false
	for partIndex, ref := range group.refs {
		proof, ok := proofs[ref.index]
		if !ok || proof.startByte < 0 ||
			proof.endByte <= proof.startByte || proof.endByte > len(group.parts[partIndex]) {
			continue
		}
		if !masked {
			group.parts = append([]string(nil), group.parts...)
			masked = true
		}
		physical := []byte(group.parts[partIndex])
		for index := proof.startByte; index < proof.endByte; index++ {
			physical[index] = ' '
		}
		if !utf8.Valid(physical) {
			// Retain the original field when exact raw-byte masking cannot be
			// proven safe; conservative blocking is preferable to deleting an
			// unrelated Unicode occurrence.
			continue
		}
		group.parts[partIndex] = string(physical)
	}
	return group
}

// bestProfiledCurrentNaturalLanguageCandidate preserves candidate boundaries
// inside one current trusted-user scope. The ordinary grouped classifier still
// evaluates bounded cross-field composition, but it only retains the final raw
// field as its directive window. Without this independent pass, a later quoted
// review or benign field can replace the physical occurrences of an earlier
// complete hostile request and make the request-global winner ineligible.
//
// Only natural-language directive fields with exact current-user coordinates
// enter this path. Code, logs, configuration, tool carriers, historical text,
// and unknown ownership remain governed by their existing carrier contracts.
// The third return value preserves the first neutral classifier-local
// incomplete while independent eligible candidates continue competing.
func (c *Classifier) bestProfiledCurrentNaturalLanguageCandidate(
	groups []profiledSegmentGroup,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
	activationProofs *map[int]profiledIndependentWindowRecoveryProof,
	activationCandidates *[]Result,
) (Result, bool, profiledIncompleteCorrelation) {
	if c == nil || len(groups) == 0 {
		return Result{}, false, profiledIncompleteCorrelation{}
	}

	signals := takeClassifierSignalBuffer(c.signalCount)
	defer putClassifierSignalBuffer(signals)
	var normalizerScratch normalizationScratch
	var runeBuffer []rune
	maxRuneStorage := 0
	defer func() {
		putNormalizedRuneBuffer(runeBuffer, maxRuneStorage)
	}()
	var compactScratch []bool
	if c.compactMatcher != nil && c.compactMatcher.maxPatternLength > 0 {
		compactScratch = make([]bool, c.compactMatcher.maxPatternLength)
	}

	best := Result{}
	found := false
	var pendingClassifierIncomplete profiledIncompleteCorrelation
	consider := func(ref profiledSegmentRef, candidate Result) {
		if resultIsNeutralClassifierIncomplete(candidate) {
			reason := classifierIncompleteReason(candidate)
			if classifierIncompleteCoverageReason(reason) {
				pendingClassifierIncomplete.rememberField(reason, ref)
			}
			return
		}
		if !resultHasEligibleMaliciousWinner(candidate, thresholds) {
			return
		}
		if !found || roleResultBetter(candidate, best) {
			best = candidate
			found = true
		}
	}

	for _, group := range groups {
		preserveIndependentField := len(group.refs) > 1
		var seenIndependentFieldText map[string]struct{}
		var deferredFieldCandidates []profiledDeferredFieldCandidate
		var groupRecoveryProofs map[int]profiledIndependentWindowRecoveryProof
		var activeRecoveredFields map[int]struct{}
		var recoveredActivation Result
		var recoveredActivationRef profiledSegmentRef
		hasRecoveredActivation := false
		recoveredActivationAt := -1
		if preserveIndependentField {
			// Exact duplicate natural-language fields in one profiled group have
			// identical actor, turn, scope, content kind, and classification input.
			// roleResultBetter keeps the first equal candidate, so replaying the full
			// classifier for every later byte-identical field cannot change the
			// winner or its ownership proof. De-duplicate only within this group and
			// only by exact raw text: normalized lookalikes and distinct clauses must
			// still receive independent analysis.
			seenIndependentFieldText = make(map[string]struct{}, len(group.refs))
		}
		for _, ref := range group.refs {
			segment := ref.segment
			if segment.ContentKind != extract.ContentKindNaturalLanguageDirective ||
				findingOriginForSegment(segment) != FindingOriginUserContent ||
				strings.TrimSpace(segment.Text) == "" {
				continue
			}
			duplicateIndependentField := false
			if preserveIndependentField {
				_, duplicateIndependentField = seenIndependentFieldText[segment.Text]
				seenIndependentFieldText[segment.Text] = struct{}{}
			}
			recoveredThisField := false
			fieldRecoveryProofComplete := true
			if profiledLongActivationRecoveryCandidate(segment) {
				candidate, recovered, complete, proof := c.profiledLongActivationBatchCandidate(
					ref, mode, thresholds, policy,
				)
				if groupRecoveryProofs == nil {
					groupRecoveryProofs = make(map[int]profiledIndependentWindowRecoveryProof)
				}
				groupRecoveryProofs[ref.index] = proof
				if activationProofs != nil && (recovered || proof.inertCount != 0) {
					if *activationProofs == nil {
						*activationProofs = make(map[int]profiledIndependentWindowRecoveryProof)
					}
					(*activationProofs)[ref.index] = proof
				}
				if !complete {
					fieldRecoveryProofComplete = false
					pendingClassifierIncomplete.rememberField(CoverageReasonClassifierWindow, ref)
				} else if recovered {
					recoveredThisField = true
					if !hasRecoveredActivation || roleResultBetter(candidate, recoveredActivation) {
						recoveredActivation = candidate
						recoveredActivationRef = ref
					}
					hasRecoveredActivation = true
					if activeRecoveredFields == nil {
						activeRecoveredFields = make(map[int]struct{})
					}
					activeRecoveredFields[ref.index] = struct{}{}
					if ref.index > recoveredActivationAt {
						recoveredActivationAt = ref.index
					}
				}
				// Recovery is an additive bounded candidate search. The ordinary
				// field classifier below must still inspect and rank its own evidence:
				// a rejected, over-budget, or differently-owned activation cannot
				// erase an otherwise complete malicious occurrence in this field.
			}
			if !recoveredThisField && fieldRecoveryProofComplete && hasRecoveredActivation &&
				ref.index > recoveredActivationAt &&
				profiledEmbeddedMaterialCancellation(c, strings.ToLower(segment.Text)) {
				for cancelledField := range activeRecoveredFields {
					proof := groupRecoveryProofs[cancelledField]
					proof.cancelled = true
					groupRecoveryProofs[cancelledField] = proof
					if activationProofs != nil && *activationProofs != nil {
						(*activationProofs)[cancelledField] = proof
					}
				}
				clear(activeRecoveredFields)
				recoveredActivation = Result{}
				recoveredActivationRef = profiledSegmentRef{}
				hasRecoveredActivation = false
				recoveredActivationAt = -1
			}
			if duplicateIndependentField {
				// Classification is byte-identical, but recovery/cancellation is
				// sequence-sensitive. Apply the state transition above before skipping
				// the redundant ordinary classifier pass so cancellation followed by an
				// identical reactivation cannot disappear only in batch mode.
				continue
			}
			mayContainLocalSubcandidate := profiledNaturalLanguageMayContainLocalSubcandidate(segment.Text)
			if !preserveIndependentField && !mayContainLocalSubcandidate {
				// A singleton natural-language group is classified once by the
				// ordinary grouped path below. This pre-pass only needs to rescan a
				// singleton when it may contain a quoted referent reactivation or an
				// independently executable tail. Avoiding a second normalize/matcher
				// pass is material for long single-field requests.
				continue
			}

			views := normalizePartsInto([]string{segment.Text}, runeBuffer, &normalizerScratch)
			runeBuffer = views.standardRunes
			if views.storageUsed > maxRuneStorage {
				maxRuneStorage = views.storageUsed
			}
			if views.truncated || len(views.standardRunes) == 0 {
				continue
			}
			clear(signals)
			c.standardMatcher.match(views.standardRunes, signals)
			if c.compactMatcher != nil {
				c.compactMatcher.matchCompactWithScratch(views.standardRunes, signals, compactScratch)
			}
			if !profiledSignalBufferMatched(signals) {
				continue
			}

			ordinaryCandidateCore := c.profiledSignalBufferHasOrdinaryCandidateCore(signals)
			if preserveIndependentField &&
				(ordinaryCandidateCore || len(segment.Text) > maxCompactIntentProofBytes) {
				// Over-budget fields can end in a neutral classifier-local incomplete
				// even when their bounded signal summary cannot prove an ordinary
				// candidate core. Classify that field independently so a later benign
				// field in the same scope cannot erase the unresolved proof.
				candidate := c.classifyTrustedCurrentUserWithPolicy(
					[]string{segment.Text}, mode, thresholds, policy,
				)
				candidate = withRoleAwareFindingOrigin(
					candidate, FindingOriginUserContent, mode, thresholds,
				)
				c.annotateProfiledResult(
					&candidate, []profiledSegmentRef{ref}, false, policy, mode, thresholds,
				)
				if resultIsNeutralClassifierIncomplete(candidate) || ordinaryCandidateCore {
					deferredFieldCandidates = append(
						deferredFieldCandidates,
						profiledDeferredFieldCandidate{ref: ref, candidate: candidate},
					)
				}
			}
			if !mayContainLocalSubcandidate {
				// Most multi-field control-plane payloads contain only META signals.
				// Their grouped classifier pass below retains the complete control
				// chain, while neither quoted reactivation nor an independent hostile
				// tail can exist without one of the bounded raw-text cues checked
				// above. Avoid materializing a normalized string for every such field.
				continue
			}

			normalized := string(views.standardRunes)
			// A structurally proven inert review may contain sentence/connective
			// cues inside the quoted referent. Do not let the local-subcandidate
			// pre-pass reinterpret those quoted clauses as an independent tail;
			// a real directive appended outside the quote makes the full review
			// proof fail and therefore still reaches the checks below.
			if c.isInertQuotedSafetyReview(normalized) {
				continue
			}
			if referent, ok := c.quotedSafetyReviewReactivationReferent(normalized); ok {
				candidate := c.classifyWithPolicy([]string{referent}, mode, thresholds, policy, false)
				candidate = withRoleAwareFindingOrigin(
					candidate, FindingOriginUserContent, mode, thresholds,
				)
				c.annotateProfiledResult(
					&candidate, []profiledSegmentRef{ref}, false, policy, mode, thresholds,
				)
				markResultReferentActivated(&candidate, true, true, mode, thresholds)
				bindResultCandidateReferentAnchor(&candidate, ref, true, mode, thresholds)
				if candidate.DecisionExplanation != nil {
					candidate.DecisionExplanation.CurrentTurnEvidence = true
					candidate.DecisionExplanation.ReferentLinkUsed = true
					candidate.DecisionExplanation.EvidenceSegmentCount = 1
				}
				deferredFieldCandidates = append(
					deferredFieldCandidates,
					profiledDeferredFieldCandidate{ref: ref, candidate: candidate},
				)
			}

			if tail, ok := independentMaliciousExecutionTail(normalized); ok {
				candidate := c.classifyWithPolicy([]string{tail}, mode, thresholds, policy, false)
				candidate = withRoleAwareFindingOrigin(
					candidate, FindingOriginUserContent, mode, thresholds,
				)
				c.annotateProfiledResult(
					&candidate, []profiledSegmentRef{ref}, false, policy, mode, thresholds,
				)
				retainCandidateAuthorizationConflict(&candidate, segment.Text)
				deferredFieldCandidates = append(
					deferredFieldCandidates,
					profiledDeferredFieldCandidate{ref: ref, candidate: candidate},
				)
			}
		}
		for _, deferred := range deferredFieldCandidates {
			proof, recovered := groupRecoveryProofs[deferred.ref.index]
			if recovered && (proof.cancelled || len(group.refs) > 1) &&
				c.profiledOrdinaryWinnerWithinIndependentWindow(
					deferred.candidate, thresholds, policy, deferred.ref.segment.Text, proof,
				) {
				continue
			}
			consider(deferred.ref, deferred.candidate)
		}
		if hasRecoveredActivation {
			if activationCandidates != nil {
				*activationCandidates = append(*activationCandidates, recoveredActivation)
			} else {
				consider(recoveredActivationRef, recoveredActivation)
			}
		}
	}
	return best, found, pendingClassifierIncomplete
}

func (c *Classifier) profiledLongActivationBatchCandidate(
	ref profiledSegmentRef,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) (Result, bool, bool, profiledIndependentWindowRecoveryProof) {
	if c == nil || !profiledLongActivationRecoveryCandidate(ref.segment) {
		return Result{}, false, true, profiledIndependentWindowRecoveryProof{}
	}
	session, err := c.NewProfiledScanSession(mode, thresholds, policy, DefaultScanLimits())
	if err != nil {
		return Result{}, false, false, profiledIndependentWindowRecoveryProof{
			failureState: CoverageUnavailable, failureReason: CoverageReasonClassifierWindow,
		}
	}
	var proof profiledIndependentWindowRecoveryProof
	candidate, _, recovered, complete :=
		session.recoverProfiledIndependentWindowCandidateWithProof(ref.segment, &proof)
	if !complete || !recovered {
		return Result{}, false, complete, proof
	}
	candidate = withRoleAwareFindingOrigin(
		candidate, FindingOriginUserContent, mode, thresholds,
	)
	c.annotateProfiledResult(&candidate, []profiledSegmentRef{ref}, false, policy, mode, thresholds)
	return candidate, resultHasEligibleMaliciousWinner(candidate, thresholds), true, proof
}

type profiledRequestLocalSystemReactivationProof struct {
	carrierRefs []profiledSegmentRef
	parts       []string
	anchor      profiledSegmentRef
}

type profiledRequestLocalSystemCarrierOwnerState uint8

const (
	profiledRequestLocalSystemCarrierUnclaimed profiledRequestLocalSystemCarrierOwnerState = iota
	profiledRequestLocalSystemCarrierSuppressed
	profiledRequestLocalSystemCarrierActivated
)

type profiledRequestLocalSystemCarrierOwnerRun struct {
	first  int
	end    int
	anchor int
	state  profiledRequestLocalSystemCarrierOwnerState
}

// bestProfiledRequestLocalSystemReactivationCandidate supplies the narrow
// candidate producer that request-local system authority previously lacked.
// It accepts either one closed same-field quoted-review transaction or a
// content-kind split logical field whose exact fenced carrier is adjacent to an
// active system speech act. The carrier is classified alone; defensive frame
// text can neither donate the harmful core nor erase it.
func (c *Classifier) bestProfiledRequestLocalSystemReactivationCandidate(
	groups []profiledSegmentGroup,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) (Result, bool, bool) {
	if c == nil {
		return Result{}, false, true
	}
	best := Result{}
	found := false
	consider := func(candidate Result) {
		if !resultHasEligibleMaliciousWinner(candidate, thresholds) {
			return
		}
		if !found || roleResultBetter(candidate, best) {
			best = candidate
			found = true
		}
	}
	for _, group := range groups {
		for _, ref := range group.refs {
			segment := ref.segment
			if !profiledRequestLocalSystemDirective(segment) ||
				!profiledNaturalLanguageMayContainLocalSubcandidate(segment.Text) {
				continue
			}
			var scratch normalizationScratch
			views := normalizePartsInto([]string{segment.Text}, takeNormalizedRuneBuffer(), &scratch)
			if views.truncated {
				putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
				return Result{}, false, false
			}
			normalized := string(views.standardRunes)
			putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
			if c.isInertQuotedSafetyReview(normalized) {
				continue
			}
			referent, reactivated := c.quotedSafetyReviewReactivationReferent(normalized)
			if !reactivated {
				continue
			}
			candidate := c.classifyWithPolicy([]string{referent}, mode, thresholds, policy, false)
			if candidate.Truncated {
				return Result{}, false, false
			}
			candidate = c.bindProfiledRequestLocalSystemReactivation(
				candidate, []profiledSegmentRef{ref}, ref, policy, mode, thresholds,
			)
			consider(candidate)
		}

		proofs, complete := c.profiledRequestLocalSystemCarrierReactivationProofs(group.refs, true)
		if !complete {
			return Result{}, false, false
		}
		for _, proof := range proofs {
			candidate := c.classifyWithPolicy(proof.parts, mode, thresholds, policy, false)
			if candidate.Truncated {
				return Result{}, false, false
			}
			if !profiledSelfContainedCarrierCandidate(candidate, thresholds) {
				continue
			}
			if len(proof.carrierRefs) > 1 {
				profiledCarrierRunClearOccurrenceOffsets(&candidate)
			}
			candidate = c.bindProfiledRequestLocalSystemReactivation(
				candidate, proof.carrierRefs, proof.anchor, policy, mode, thresholds,
			)
			consider(candidate)
		}
	}
	return best, found, true
}

func (c *Classifier) bindProfiledRequestLocalSystemReactivation(
	candidate Result,
	carrierRefs []profiledSegmentRef,
	anchor profiledSegmentRef,
	policy Policy,
	mode Mode,
	thresholds Thresholds,
) Result {
	c.annotateProfiledResult(&candidate, carrierRefs, false, policy, mode, thresholds)
	markResultRequestLocalReferentActivated(
		&candidate, EnforcementScopeRequestLocalSystem, true, mode, thresholds,
	)
	candidate = withRoleAwareFindingOriginAndScope(
		candidate, FindingOriginNonUserOrUntrusted,
		EnforcementScopeRequestLocalSystem, mode, thresholds,
	)
	bindResultCandidateReferentAnchor(&candidate, anchor, true, mode, thresholds)
	if candidate.DecisionExplanation != nil {
		candidate.DecisionExplanation.CrossSegmentComposition = len(carrierRefs) > 1 ||
			anchor.index != carrierRefs[0].index
		candidate.DecisionExplanation.ReferentLinkUsed = true
		candidate.DecisionExplanation.EvidenceSegmentCount = len(carrierRefs) + 1
	}
	return candidate
}

func profiledNaturalLanguageMayContainLocalSubcandidate(text string) bool {
	if text == "" {
		return false
	}
	if strings.ContainsAny(text, "\"'`") && streamingContainsASCIIFold(text, "quoted ") {
		return true
	}
	for _, boundary := range [...]string{
		"; then ", ". then ", " but then ", " but also ", " and then ",
		" additionally ", " now ",
	} {
		if streamingContainsASCIIFold(text, boundary) {
			return true
		}
	}
	for index := 0; index+1 < len(text); index++ {
		switch text[index] {
		case '.', '!', '?':
			if text[index+1] == ' ' || text[index+1] == '\t' || text[index+1] == '\n' || text[index+1] == '\r' {
				return true
			}
		}
	}
	return strings.ContainsAny(text, "\u3002\uff01\uff1f")
}

func profiledSignalBufferMatched(signals []bool) bool {
	for _, matched := range signals {
		if matched {
			return true
		}
	}
	return false
}

// profiledSignalBufferHasOrdinaryCandidateCore is a conservative, allocation-
// free prefilter for the per-field preservation pass. Returning true may spend
// an extra full classification, but returning false must prove that neither an
// ordinary rule/category composition nor a semantic profile can form a local
// malicious core from this field. META-only signals are deliberately excluded:
// the grouped classifier owns their cross-field control-plane semantics.
func (c *Classifier) profiledSignalBufferHasOrdinaryCandidateCore(signals []bool) bool {
	if c == nil || len(signals) == 0 {
		return false
	}
	for _, category := range classifierCategoryOrder {
		hasIntent := false
		hasObject := false
		for _, ruleIndex := range c.categoryRules[category] {
			if ruleIndex < 0 || ruleIndex >= len(c.rules) {
				continue
			}
			rule := c.rules[ruleIndex]
			intent := signalMatched(signals, rule.intent)
			object := signalMatched(signals, rule.object)
			if intent && object {
				return true
			}
			hasIntent = hasIntent || intent
			hasObject = hasObject || object
			if object && isCredentialObjectQualifiedFallback(rule, signals) {
				return true
			}
		}
		if hasIntent && hasObject {
			return true
		}
	}
	for _, profile := range c.semanticProfiles {
		var mask uint16
		for _, evidence := range profile.evidence {
			if signalMatched(signals, evidence.signalID) {
				mask |= evidence.dimensionMask
			}
		}
		if semanticDimensionsPotential(semanticDimensionsFromMask(mask)) {
			return true
		}
	}
	return false
}

// quotedSafetyReviewReactivationReferent recognizes one closed quoted payload
// with a defensive assessment followed by a separately affirmative execution
// speech act in the same field. The exact inert-review parser remains stricter:
// malformed, unclosed, or multi-quote text never reaches this reactivation path.
func (c *Classifier) quotedSafetyReviewReactivationReferent(text string) (string, bool) {
	if c == nil || text == "" || !strings.Contains(text, "quoted ") ||
		!strings.ContainsAny(text, "\"'`") {
		return "", false
	}
	if !strings.Contains(text, "quoted request") && !strings.Contains(text, "quoted prompt") {
		return "", false
	}
	spans, complete := metaOverrideQuotedSpans(text)
	if !complete || len(spans) != 1 {
		return "", false
	}
	quoted := spans[0]
	if quoted.start <= 0 || quoted.end <= quoted.start+2 || quoted.end >= len(text) {
		return "", false
	}
	prefix := strings.TrimSpace(text[:quoted.start])
	if !inertQuotedSafetyReviewPrefix(prefix) {
		return "", false
	}
	clauses, overflow := metaOverrideDirectiveClausesBounded(strings.TrimSpace(text[quoted.end:]))
	if overflow || len(clauses) < 2 || !inertQuotedSafetyAssessment(clauses[0].text) {
		return "", false
	}
	followUpParts := make([]string, 0, len(clauses)-1)
	for _, clause := range clauses[1:] {
		followUpParts = append(followUpParts, clause.text)
	}
	if !c.hasAffirmativeQuotedReviewFollowUp(strings.Join(followUpParts, ". ")) {
		return "", false
	}
	referent, ok := quotedSafetyReviewSpanContent(text, quoted)
	return referent, ok
}

func (c *Classifier) profiledProofUnavailableResult(
	mode Mode,
	thresholds Thresholds,
	policy Policy,
	reasons ...CoverageReason,
) Result {
	reason := CoverageReasonClassifierWindow
	if len(reasons) != 0 && classifierIncompleteCoverageReason(reasons[0]) {
		reason = reasons[0]
	}
	result := c.classifyWithPolicy(nil, mode, thresholds, policy, false)
	result.Coverage = Coverage{
		State: CoverageUnavailable, Reason: reason,
	}
	result.Truncated = true
	result.FindingConfidence = FindingNone
	result.FindingOrigin = FindingOriginNone
	return result
}

func (c *Classifier) profiledCoverageFailureResult(
	mode Mode,
	thresholds Thresholds,
	policy Policy,
	state CoverageState,
	reason CoverageReason,
) Result {
	result := c.classifyWithPolicy(nil, mode, thresholds, policy, false)
	result.Coverage = Coverage{State: state, Reason: reason}
	result.Truncated = true
	result.FindingConfidence = FindingNone
	result.FindingOrigin = FindingOriginNone
	return result
}

func profiledBatchInputCoverageFailure(
	segments []extract.Segment,
) (CoverageState, CoverageReason) {
	remaining := int64(DefaultScanTotalTextBytes)
	for _, segment := range segments {
		bytes := int64(len(segment.Text))
		if bytes > remaining {
			return CoverageBudgetExhausted, CoverageReasonTotalTextLimit
		}
		remaining -= bytes
		if !utf8.ValidString(segment.Text) {
			return CoverageUnavailable, CoverageReasonInvalidUTF8
		}
	}
	return CoverageComplete, CoverageReasonNone
}

func buildProfiledSegmentGroups(segments []extract.Segment, historicalTrustedUsers bool) []profiledSegmentGroup {
	groups := make([]profiledSegmentGroup, 0, len(segments))
	indexes := make(map[profiledSegmentGroupKey]int, len(segments))
	activeTurnIndex := -1
	terminalConversationIndex := -1
	terminalTurnIndex := -1
	for _, segment := range segments {
		if segment.IsCurrentTurn && segment.TurnIndex > activeTurnIndex {
			activeTurnIndex = segment.TurnIndex
		}
		if segment.ConversationIndex > terminalConversationIndex {
			terminalConversationIndex = segment.ConversationIndex
		}
		if segment.TurnIndex > terminalTurnIndex {
			terminalTurnIndex = segment.TurnIndex
		}
		if segment.HasTerminalCoordinates {
			if segment.TerminalConversationIndex > terminalConversationIndex {
				terminalConversationIndex = segment.TerminalConversationIndex
			}
			if segment.TerminalTurnIndex > terminalTurnIndex {
				terminalTurnIndex = segment.TerminalTurnIndex
			}
		}
	}
	if activeTurnIndex < 0 {
		for _, segment := range segments {
			if segment.TurnIndex > activeTurnIndex {
				activeTurnIndex = segment.TurnIndex
			}
		}
	}
	for index, segment := range segments {
		if historicalTrustedUsers {
			if !trustedUserContentSegment(segment) || segment.IsCurrentTurn || profiledContentInert(segment.ContentKind) {
				continue
			}
		} else if !profiledSegmentClassifiable(segment, activeTurnIndex) &&
			!profiledRequestLocalToolResult(segment, terminalConversationIndex, terminalTurnIndex) {
			continue
		}
		effectiveCurrent := profiledEffectiveCurrentTurn(segment, activeTurnIndex)
		segment.IsCurrentTurn = effectiveCurrent
		key := profiledSegmentGroupKey{
			role: segment.Role, provenance: segment.Provenance, attribution: segment.UserAttribution,
			toolAssociation: segment.ToolAssociation,
			turnIndex:       segment.TurnIndex, currentTurn: effectiveCurrent, scopeID: segment.ScopeID,
		}
		if segment.ScopeID == 0 || segment.ContentKind == extract.ContentKindToolSchema {
			key.zeroScopeUnique = index + 1
		}
		groupIndex, exists := indexes[key]
		if !exists {
			groupIndex = len(groups)
			indexes[key] = groupIndex
			groups = append(groups, profiledSegmentGroup{})
		}
		group := &groups[groupIndex]
		group.refs = append(group.refs, profiledSegmentRef{index: index, segment: segment})
		group.parts = append(group.parts, segment.Text)
		group.activeDirective = group.activeDirective || profiledContentActiveDirective(segment.ContentKind) ||
			profiledRequestLocalToolResult(segment, terminalConversationIndex, terminalTurnIndex)
		group.structuredTool = group.structuredTool || segment.Provenance == extract.ProvenanceToolPayload ||
			segment.ContentKind == extract.ContentKindToolCallArguments
	}
	return groups
}

// buildProfiledRequestLocalSystemReactivationGroups is deliberately separate
// from the generic profiled group builder. Log and markdown fences remain inert
// to ordinary classification, but the narrow system reactivation producer must
// still see their exact same-field position next to an explicit system speech
// act. Original physical indexes are preserved so skipped content remains an
// adjacency barrier.
func buildProfiledRequestLocalSystemReactivationGroups(
	segments []extract.Segment,
) []profiledSegmentGroup {
	groups := make([]profiledSegmentGroup, 0, len(segments))
	indexes := make(map[profiledSegmentGroupKey]int, len(segments))
	for index, segment := range segments {
		if !profiledRequestLocalSystemDirective(segment) &&
			!(profiledRequestLocalSystemCarrier(segment) &&
				profiledSelfContainedCarrierKind(segment.ContentKind)) {
			continue
		}
		key := profiledSegmentGroupKey{
			role: segment.Role, provenance: segment.Provenance, attribution: segment.UserAttribution,
			toolAssociation: segment.ToolAssociation,
			turnIndex:       segment.TurnIndex, currentTurn: segment.IsCurrentTurn, scopeID: segment.ScopeID,
		}
		groupIndex, exists := indexes[key]
		if !exists {
			groupIndex = len(groups)
			indexes[key] = groupIndex
			groups = append(groups, profiledSegmentGroup{})
		}
		group := &groups[groupIndex]
		group.refs = append(group.refs, profiledSegmentRef{index: index, segment: segment})
		group.parts = append(group.parts, segment.Text)
		group.activeDirective = group.activeDirective ||
			profiledContentActiveDirective(segment.ContentKind)
	}
	return groups
}

// buildProfiledCurrentMetaControlGroups reconstructs only same-scope current
// trusted-user control-plane text. It includes fenced/documentation carriers so
// an active prompt override cannot hide one of its required control families in
// markup, while accepting only a category-free META-OVERRIDE winner prevents
// ordinary cyber evidence from borrowing inert carrier content.
func buildProfiledCurrentMetaControlGroups(segments []extract.Segment) []profiledSegmentGroup {
	groups := make([]profiledSegmentGroup, 0, len(segments))
	indexes := make(map[profiledSegmentGroupKey]int, len(segments))
	for index, segment := range segments {
		if !segment.IsCurrentTurn || !trustedUserContentSegment(segment) ||
			segment.ScopeID == 0 || !segmentDeclaresProfiledCoordinates(segment) {
			continue
		}
		switch segment.ContentKind {
		case extract.ContentKindToolSchema, extract.ContentKindToolCallArguments,
			extract.ContentKindToolResult:
			continue
		}
		key := profiledSegmentGroupKey{
			role: segment.Role, provenance: segment.Provenance, attribution: segment.UserAttribution,
			toolAssociation: segment.ToolAssociation,
			turnIndex:       segment.TurnIndex, currentTurn: true, scopeID: segment.ScopeID,
		}
		groupIndex, exists := indexes[key]
		if !exists {
			groupIndex = len(groups)
			indexes[key] = groupIndex
			groups = append(groups, profiledSegmentGroup{})
		}
		group := &groups[groupIndex]
		group.refs = append(group.refs, profiledSegmentRef{index: index, segment: segment})
		group.parts = append(group.parts, segment.Text)
		group.activeDirective = group.activeDirective || profiledContentActiveDirective(segment.ContentKind)
	}
	filtered := groups[:0]
	for _, group := range groups {
		if !group.activeDirective || len(group.refs) < 2 {
			continue
		}
		hasCarrier := false
		for _, ref := range group.refs {
			if profiledReferentCarrierKind(ref.segment.ContentKind) {
				hasCarrier = true
				break
			}
		}
		if hasCarrier {
			filtered = append(filtered, group)
		}
	}
	return filtered
}

func (c *Classifier) profiledActiveMetaControlGroup(
	segments []extract.Segment,
	group profiledSegmentGroup,
) (profiledSegmentGroup, bool) {
	active := profiledSegmentGroup{
		refs:            make([]profiledSegmentRef, 0, len(group.refs)),
		parts:           make([]string, 0, len(group.parts)),
		activeDirective: group.activeDirective,
	}
	for _, ref := range group.refs {
		if profiledReferentCarrierKind(ref.segment.ContentKind) {
			if owner, localOwner := c.profiledSelfContainedCarrierRunLocalOwner(
				segments, ref.index, ref.index+1,
			); localOwner {
				disposition, complete := c.profiledCarrierLocalOwnerDisposition(owner.segment)
				if !complete {
					return profiledSegmentGroup{}, false
				}
				if disposition == quotedReviewContinuationInert ||
					disposition == quotedReviewContinuationCancelled {
					continue
				}
			}
		}
		active.refs = append(active.refs, ref)
		active.parts = append(active.parts, ref.segment.Text)
	}
	return active, true
}

type profiledDirectCompactionRun struct {
	group      profiledSegmentGroup
	hasCarrier bool
	totalBytes int
}

// profiledDirectCompactionRuns partitions a current-user scope back into the
// physically contiguous logical text fields that the provider extractor proved.
// Direct compaction is a field-local quoted-carrier operation; a matching speech
// act in one JSON field must never lend authority to a carrier in another field
// or across an omitted/interleaved provider unit.
func profiledDirectCompactionRuns(group profiledSegmentGroup) []profiledDirectCompactionRun {
	if len(group.refs) == 0 || len(group.refs) != len(group.parts) {
		return nil
	}
	var runs []profiledDirectCompactionRun
	for start := 0; start < len(group.refs); {
		end := start + 1
		for end < len(group.refs) &&
			profiledSegmentRefsPhysicallyAdjacent(group.refs[end-1], group.refs[end]) &&
			profiledSegmentsShareLogicalTextField(
				group.refs[start].segment, group.refs[end].segment,
			) {
			end++
		}

		applicationIndex := -1
		hasCarrierAfterApplication := false
		totalBytes := 0
		for index := start; index < end; index++ {
			segment := group.refs[index].segment
			totalBytes += len(group.parts[index])
			if applicationIndex < 0 && profiledDirectCompactionDirectiveSegment(segment) &&
				profiledDirectCompactionApplicationText(group.parts[index]) {
				applicationIndex = index
				continue
			}
			if applicationIndex >= 0 && profiledReferentCarrierKind(segment.ContentKind) {
				hasCarrierAfterApplication = true
			}
		}
		if applicationIndex >= 0 {
			run := profiledSegmentGroup{
				refs:            append([]profiledSegmentRef(nil), group.refs[start:end]...),
				parts:           append([]string(nil), group.parts[start:end]...),
				activeDirective: true,
			}
			for _, ref := range run.refs {
				run.structuredTool = run.structuredTool ||
					ref.segment.Provenance == extract.ProvenanceToolPayload ||
					ref.segment.ContentKind == extract.ContentKindToolCallArguments
			}
			runs = append(runs, profiledDirectCompactionRun{
				group: run,
				// Direct compaction is a leading-boundary operation whose
				// referenced carrier must follow the application speech act.
				hasCarrier: applicationIndex == start && hasCarrierAfterApplication,
				totalBytes: totalBytes,
			})
		}
		start = end
	}
	return runs
}

// profiledDirectCompactionBoundedProof removes only trailing ASCII whitespace
// from each extractor-proven logical piece. Provider padding after a complete
// application/carrier is semantically inert and must not turn an otherwise
// bounded proof into a blanket classifier_window_incomplete result. Internal
// bytes and piece boundaries remain unchanged; if the non-padding proof still
// exceeds the reviewed 8 KiB cap, the caller fails closed as incomplete.
func profiledDirectCompactionBoundedProof(
	group profiledSegmentGroup,
) (profiledSegmentGroup, int, bool) {
	if len(group.parts) == 0 || len(group.parts) != len(group.refs) {
		return profiledSegmentGroup{}, 0, false
	}
	proof := group
	proof.parts = make([]string, len(group.parts))
	totalBytes := 0
	for index, part := range group.parts {
		end := len(part)
		for end > 0 && profiledDirectCompactionASCIISpace(part[end-1]) {
			end--
		}
		part = part[:end]
		if len(part) > maxMetaOverrideDirectControlWindowBytes-totalBytes {
			return profiledSegmentGroup{}, 0, false
		}
		proof.parts[index] = part
		totalBytes += len(part)
	}
	return proof, totalBytes, totalBytes > 0
}

func profiledDirectCompactionASCIISpace(value byte) bool {
	switch value {
	case ' ', '\t', '\n', '\r', '\f', '\v':
		return true
	default:
		return false
	}
}

func profiledDirectCompactionDirectiveSegment(segment extract.Segment) bool {
	if !segment.IsCurrentTurn || !trustedUserContentSegment(segment) ||
		segment.ScopeID == 0 || segment.FieldPathHash == "" {
		return false
	}
	switch segment.ContentKind {
	case extract.ContentKindNaturalLanguageDirective, extract.ContentKindUnknown:
		return true
	default:
		return false
	}
}

// The dedicated run producer above owns exact compaction speech acts. Remove
// only those application units from the generic same-scope META view so the
// latter can keep its established cross-field signal composition without using
// a compaction wrapper to activate an unrelated carrier.
func profiledGroupWithoutDirectCompactionApplications(
	group profiledSegmentGroup,
) profiledSegmentGroup {
	hasApplication := false
	for index, ref := range group.refs {
		if index >= len(group.parts) {
			break
		}
		if profiledDirectCompactionDirectiveSegment(ref.segment) &&
			profiledDirectCompactionApplicationText(group.parts[index]) {
			hasApplication = true
			break
		}
	}
	if !hasApplication {
		return group
	}
	filtered := profiledSegmentGroup{
		refs:  make([]profiledSegmentRef, 0, len(group.refs)),
		parts: make([]string, 0, len(group.parts)),
	}
	for index, ref := range group.refs {
		if index >= len(group.parts) {
			break
		}
		if profiledDirectCompactionDirectiveSegment(ref.segment) &&
			profiledDirectCompactionApplicationText(group.parts[index]) {
			continue
		}
		filtered.refs = append(filtered.refs, ref)
		filtered.parts = append(filtered.parts, group.parts[index])
		filtered.activeDirective = filtered.activeDirective ||
			profiledContentActiveDirective(ref.segment.ContentKind)
		filtered.structuredTool = filtered.structuredTool ||
			ref.segment.Provenance == extract.ProvenanceToolPayload ||
			ref.segment.ContentKind == extract.ContentKindToolCallArguments
	}
	return filtered
}

func buildProfiledHistoricalReferentGroups(segments []extract.Segment) []profiledSegmentGroup {
	groups := make([]profiledSegmentGroup, 0, len(segments))
	indexes := make(map[profiledSegmentGroupKey]int, len(segments))
	for index, segment := range segments {
		if !profiledHistoricalReferentEligible(segment) {
			continue
		}
		key := profiledSegmentGroupKey{
			role: segment.Role, provenance: segment.Provenance, attribution: segment.UserAttribution,
			toolAssociation: segment.ToolAssociation,
			turnIndex:       segment.TurnIndex, currentTurn: false, scopeID: segment.ScopeID,
		}
		if segment.ScopeID == 0 {
			key.zeroScopeUnique = index + 1
		}
		groupIndex, exists := indexes[key]
		if !exists {
			groupIndex = len(groups)
			indexes[key] = groupIndex
			groups = append(groups, profiledSegmentGroup{})
		}
		group := &groups[groupIndex]
		group.refs = append(group.refs, profiledSegmentRef{index: index, segment: segment})
		group.parts = append(group.parts, segment.Text)
	}
	if len(groups) > maxRoleClassifierSegments {
		groups = groups[len(groups)-maxRoleClassifierSegments:]
	}
	return groups
}

func profiledHistoricalReferentEligible(segment extract.Segment) bool {
	if segment.IsCurrentTurn || !segmentDeclaresProfiledCoordinates(segment) ||
		!trustedUserContentSegment(segment) {
		return false
	}
	switch segment.ContentKind {
	case extract.ContentKindToolSchema, extract.ContentKindToolCallArguments,
		extract.ContentKindToolResult:
		return false
	default:
		// Content kind is not an authority grant. A trusted historical user group
		// reaches the referent slot only after the complete group proves the exact
		// closed safety-review frame below. Tool schemas, tool-call arguments, and
		// tool results stay outside this path even when a provider labels them as
		// user content.
		return true
	}
}

func (c *Classifier) profiledReferentCarrierPossible(segments []extract.Segment) bool {
	if c == nil {
		return false
	}
	for _, segment := range segments {
		if profiledTrustedCurrentUserCarrier(segment) || profiledHistoricalReferentEligible(segment) ||
			profiledHistoricalToolResultCarrier(segment) {
			return true
		}
		if segment.IsCurrentTurn && trustedUserContentSegment(segment) &&
			(segment.ContentKind == extract.ContentKindNaturalLanguageDirective ||
				segment.ContentKind == extract.ContentKindUnknown) {
			if _, inert := c.rawInertQuotedSafetyReviewReferent(segment.Text); inert {
				return true
			}
		}
	}
	return false
}

var profiledHistoricalToolExplicitActivationIntents = []string{
	"execute the preceding tool output", "execute the preceding tool result",
	"execute the previous tool output", "execute the previous tool result",
	"carry out the preceding tool output", "carry out the preceding tool result",
	"carry out the previous tool output", "carry out the previous tool result",
	"proceed with the preceding tool output", "proceed with the preceding tool result",
	"proceed with the previous tool output", "proceed with the previous tool result",
	"continue with the preceding tool output", "continue with the preceding tool result",
	"continue with the previous tool output", "continue with the previous tool result",
}

// profiledHistoricalToolActivationDirective proves that one physical current-
// user directive contains both an affirmative execution/continuation act and
// an explicit anaphoric reference. The generic continuation parser intentionally
// recognizes useful direct requests such as "Provide code" and terse turns such
// as "Proceed"; those speech acts may activate a same-scope carrier, but cannot
// borrow an unrelated historical tool result without this stronger relation.
func (c *Classifier) profiledHistoricalToolActivationDirective(text string) (bool, bool) {
	if c == nil || strings.TrimSpace(text) == "" {
		return false, true
	}
	explicitIntents := make([]string, 0,
		len(c.implementationStarts)+len(profiledHistoricalToolExplicitActivationIntents))
	explicitIntents = append(explicitIntents, c.implementationStarts...)
	explicitIntents = append(explicitIntents, profiledHistoricalToolExplicitActivationIntents...)
	allIntents := make([]string, 0,
		len(quotedReviewSpecificContinuationIntents)+len(quotedReviewTerseContinuationIntents)+len(explicitIntents))
	allIntents = append(allIntents, quotedReviewSpecificContinuationIntents...)
	allIntents = append(allIntents, quotedReviewTerseContinuationIntents...)
	allIntents = append(allIntents, explicitIntents...)
	decisions, complete := profiledPartIntentDecisions(c, text, explicitIntents, allIntents, true)
	if !complete {
		return false, false
	}
	cancellations := make([]quotedReviewContinuationDecision, 0, 4)
	for _, decision := range decisions {
		switch decision.disposition {
		case quotedReviewContinuationActive:
			cancelled := false
			for _, cancellation := range cancellations {
				if quotedReviewContinuationIntentsEquivalent(decision.intent, cancellation.intent) {
					cancelled = true
					break
				}
			}
			if !cancelled && profiledHistoricalToolIntentHasExplicitReferent(decision.intent) {
				return true, true
			}
		case quotedReviewContinuationCancelled:
			if !decision.alternative {
				cancellations = append(cancellations, decision)
			}
		}
	}
	return false, true
}

func profiledHistoricalToolIntentHasExplicitReferent(intent string) bool {
	intent = strings.TrimSpace(intent)
	if containsASCIIWord(intent, "it") || containsASCIIWord(intent, "that") ||
		containsASCIIWord(intent, "above") {
		return true
	}
	return containsAnyLiteral(intent,
		"do so", "do likewise", "do the same", "the above",
		"the request", "quoted request", "the quoted instruction", "the quoted instructions",
		"the payload", "this payload", "that payload",
		"the output", "this output", "that output",
		"preceding tool output", "preceding tool result", "previous tool output", "previous tool result",
		"preceding role content", "previous role content",
		"它", "该内容", "上述", "上面", "前面", "前述", "照做",
	)
}

// nearestProfiledHistoricalToolReferent implements the deliberately narrow
// provider transaction used by tool-result activation:
//
//	uniquely associated non-terminal tool result -> immediately following
//	terminal trusted-user execution speech act
//
// The immediately preceding non-empty provider item owns the referent slot even
// when it is benign or malformed. This prevents a bare pronoun from skipping a
// nearer tool item and activating older user history. Tool evidence keeps its
// non-user origin; the current-user anchor supplies only the exact execution
// relation, so subject state cannot be poisoned by tool-provided text.
func (c *Classifier) nearestProfiledHistoricalToolReferent(
	segments []extract.Segment,
	anchor profiledSegmentRef,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) (Result, profiledSegmentGroup, bool, bool, bool) {
	if c == nil || anchor.index < 0 || anchor.index >= len(segments) ||
		!profiledHistoricalToolActivationAnchor(anchor.segment) {
		return Result{}, profiledSegmentGroup{}, false, false, true
	}
	targetConversation := anchor.segment.ConversationIndex - 1
	if targetConversation < 0 {
		return Result{}, profiledSegmentGroup{}, false, false, true
	}

	claimed := false
	for _, segment := range segments {
		if segment.ConversationIndex != targetConversation || strings.TrimSpace(segment.Text) == "" {
			continue
		}
		claimed = true
		if !profiledHistoricalToolResultCarrier(segment) {
			return Result{}, profiledSegmentGroup{}, true, false, true
		}
	}
	if !claimed {
		return Result{}, profiledSegmentGroup{}, false, false, true
	}
	active, activationComplete := c.profiledHistoricalToolActivationDirective(anchor.segment.Text)
	if !activationComplete {
		return Result{}, profiledSegmentGroup{}, true, false, false
	}
	if !active {
		return Result{}, profiledSegmentGroup{}, true, false, true
	}

	var (
		group             profiledSegmentGroup
		groupKey          profiledSegmentGroupKey
		groupConversation int
		keySet            bool
	)
	for index, segment := range segments {
		if strings.TrimSpace(segment.Text) == "" ||
			!profiledHistoricalToolResultCarrier(segment) {
			continue
		}
		key := profiledSegmentGroupKey{
			role: segment.Role, provenance: segment.Provenance, attribution: segment.UserAttribution,
			toolAssociation: segment.ToolAssociation,
			turnIndex:       segment.TurnIndex, currentTurn: false, scopeID: segment.ScopeID,
		}
		if !keySet {
			groupKey = key
			groupConversation = segment.ConversationIndex
			keySet = true
		} else if key != groupKey || segment.ConversationIndex != groupConversation {
			// Every ReferableUnique result belongs to the extractor-proven nearest
			// completed transaction. More than one result scope or provider item
			// therefore leaves a generic "preceding content" referent ambiguous;
			// never select the final payload merely because it is adjacent.
			return Result{}, profiledSegmentGroup{}, true, false, true
		}
		if len(group.refs) >= maxRoleClassifierSegments {
			return Result{}, profiledSegmentGroup{}, true, false, false
		}
		group.refs = append(group.refs, profiledSegmentRef{index: index, segment: segment})
		group.parts = append(group.parts, segment.Text)
	}
	if len(group.refs) == 0 || groupConversation != targetConversation {
		return Result{}, profiledSegmentGroup{}, true, false, true
	}

	candidate := c.classifyWithPolicy(group.parts, mode, thresholds, policy, false)
	if resultIsNeutralClassifierIncomplete(candidate) || candidate.Truncated ||
		candidate.Coverage.State != "" && candidate.Coverage.State != CoverageComplete {
		return Result{}, profiledSegmentGroup{}, true, false, false
	}
	if candidate.FindingConfidence == FindingNone || candidate.Category == "" {
		return Result{}, group, true, false, true
	}
	candidate = withRoleAwareFindingOrigin(
		candidate, FindingOriginNonUserOrUntrusted, mode, thresholds,
	)
	c.annotateProfiledResult(&candidate, group.refs, false, policy, mode, thresholds)
	markResultRequestLocalReferentActivated(
		&candidate, EnforcementScopeRequestLocalTool, true, mode, thresholds,
	)
	bindResultCandidateReferentAnchor(&candidate, anchor, true, mode, thresholds)
	markResultHistoricalToolActivationExplanation(&candidate, len(group.refs)+1)
	if !resultHasEligibleMaliciousWinner(candidate, thresholds) {
		return Result{}, group, true, false, true
	}
	return candidate, group, true, true, true
}

func profiledHistoricalToolActivationAnchor(segment extract.Segment) bool {
	return segment.IsCurrentTurn && trustedUserContentSegment(segment) &&
		segment.ScopeID != 0 && segment.FieldPathHash != "" &&
		segment.ContentKind == extract.ContentKindNaturalLanguageDirective &&
		segment.HasTerminalCoordinates && segment.ConversationIndex >= 0 &&
		segment.ConversationIndex == segment.TerminalConversationIndex &&
		segment.TurnIndex >= 0 && segment.TurnIndex == segment.TerminalTurnIndex
}

func markResultHistoricalToolActivationExplanation(result *Result, evidenceSegmentCount int) {
	if result == nil || result.DecisionExplanation == nil {
		return
	}
	explanation := result.DecisionExplanation
	explanation.CurrentTurnEvidence = true
	explanation.CrossSegmentComposition = true
	explanation.ReferentLinkUsed = true
	explanation.RelationType = ExplanationRelationHistoricalToolActivation
	explanation.EnforcementOwner = ExplanationEnforcementOwnerCurrentTrustedUser
	explanation.EvidenceSegmentCount = evidenceSegmentCount
}

func profiledHistoricalToolResultCarrier(segment extract.Segment) bool {
	return segment.Role == extract.RoleTool && segment.Provenance == extract.ProvenanceContent &&
		segment.UserAttribution != extract.UserAttributionTrusted &&
		segment.ContentKind == extract.ContentKindToolResult && segment.ScopeID != 0 &&
		segment.FieldPathHash != "" && !segment.IsCurrentTurn && segment.HasTerminalCoordinates &&
		segment.ConversationIndex >= 0 && segment.TurnIndex >= -1 &&
		segment.ToolAssociation == extract.ToolResultAssociationReferableUnique
}

func (c *Classifier) profiledHistoricalSafetyReviewReferent(
	group profiledSegmentGroup,
) (string, []profiledSegmentRef, bool) {
	if c == nil || len(group.refs) == 0 || len(group.refs) != len(group.parts) {
		return "", nil, false
	}
	for _, ref := range group.refs {
		if !profiledHistoricalReferentEligible(ref.segment) {
			return "", nil, false
		}
	}
	quoted, inert := c.rawInertQuotedSafetyReviewReferent(strings.Join(group.parts, "\n"))
	if !inert {
		return "", nil, false
	}
	return quoted, profiledHistoricalReviewEvidenceRefs(group, quoted), true
}

// profiledHistoricalReviewEvidenceRefs narrows a split defensive-review group
// to the one physical field that contains the complete normalized referent when
// such a field exists. CPA's fenced-content extraction emits the review frame
// and its closed code block as separate same-scope fields. The classifier runs
// the harmful core without the defensive frame, so binding its synthetic
// semantic occurrences against both fields is ambiguous even though the exact
// closed review already proved one referent. A unique containing field is a
// stronger physical owner; otherwise retain the full group and require the
// ordinary multi-field occurrence replay to prove every dimension.
func profiledHistoricalReviewEvidenceRefs(
	group profiledSegmentGroup,
	quoted string,
) []profiledSegmentRef {
	if quoted == "" || len(group.refs) <= 1 {
		return group.refs
	}
	maxBytes := 0
	for _, ref := range group.refs {
		if len(ref.segment.Text) > maxBytes {
			maxBytes = len(ref.segment.Text)
		}
	}
	if maxBytes > maxClassifierNormalizedRunes {
		maxBytes = maxClassifierNormalizedRunes
	}
	buffer := takeNormalizedRuneBuffer()
	if cap(buffer) < maxBytes {
		buffer = make([]rune, 0, maxBytes)
	}
	maxStorage := 0
	defer func() {
		putNormalizedRuneBuffer(buffer, maxStorage)
	}()

	var scratch normalizationScratch
	matches := make([]profiledSegmentRef, 0, 1)
	for _, ref := range group.refs {
		views := normalizePartsInto([]string{ref.segment.Text}, buffer, &scratch)
		buffer = views.standardRunes
		if views.storageUsed > maxStorage {
			maxStorage = views.storageUsed
		}
		if !views.truncated && strings.Contains(string(views.standardRunes), quoted) {
			matches = append(matches, ref)
		}
	}
	if len(matches) == 1 {
		return matches
	}
	return group.refs
}

func (c *Classifier) nearestProfiledHistoricalReferent(
	segments []extract.Segment,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) (Result, profiledSegmentGroup, []profiledSegmentRef, bool) {
	groups := buildProfiledHistoricalReferentGroups(segments)
	for index := len(groups) - 1; index >= 0; index-- {
		group := groups[index]
		if len(group.parts) == 0 || len(group.refs) == 0 {
			continue
		}
		// The nearest trusted historical user group owns the bare referent slot,
		// but it can populate that slot only as one exact, closed safety review.
		// Plain historical attacks and inert/non-user carriers never acquire a
		// present-tense execution act from a later pronoun.
		quoted, evidenceRefs, inert := c.profiledHistoricalSafetyReviewReferent(group)
		if !inert {
			return Result{}, profiledSegmentGroup{}, nil, false
		}
		candidate := c.classifyWithPolicy([]string{quoted}, mode, thresholds, policy, false)
		if !c.rebaseProfiledReconstructedCore(&candidate, evidenceRefs, quoted, policy) {
			// A closed review may populate the referent slot only when every winning
			// dimension can be rebound to the exact physical carrier fields. Never
			// publish reconstructed-core offsets as if they belonged to the wrapper.
			return Result{}, profiledSegmentGroup{}, nil, false
		}
		if !resultHasEligibleMaliciousWinner(candidate, thresholds) ||
			candidate.FindingConfidence == FindingNone {
			// A structurally valid but benign latest review still owns the slot. Do
			// not skip it and bind "Execute it" to an older malicious review.
			return Result{}, profiledSegmentGroup{}, nil, false
		}
		return candidate, group, evidenceRefs, true
	}
	return Result{}, profiledSegmentGroup{}, nil, false
}

func profiledSegmentClassifiable(segment extract.Segment, activeTurnIndex int) bool {
	if profiledTrustedCurrentUserCarrier(segment) {
		return false
	}
	if profiledContentInert(segment.ContentKind) {
		return false
	}
	if segment.ContentKind == extract.ContentKindToolCallArguments ||
		segment.Provenance == extract.ProvenanceToolPayload {
		return profiledEffectiveCurrentTurn(segment, activeTurnIndex)
	}
	switch segment.Role {
	case extract.RoleUser:
		if segment.UserAttribution == extract.UserAttributionTrusted {
			// Historical user directives remain independently auditable, but their
			// non-current origin prevents them from donating ownership or blocking.
			return true
		}
		// Model-visible text under an unknown/future field remains independently
		// inspectable, but its untrusted attribution prevents subject-state
		// accumulation. Scope IDs still prohibit it from donating dimensions to a
		// separate trusted user field.
		return segment.IsCurrentTurn || segment.TurnIndex < 0
	case extract.RoleSystem:
		return true
	case extract.RoleAssistant:
		// Assistant history may be retained as an independent audit candidate;
		// it never shares a scope with the current trusted-user candidate.
		return segment.ContentKind == extract.ContentKindNaturalLanguageDirective ||
			segment.ContentKind == extract.ContentKindUnknown
	case extract.RoleTool:
		return false
	default:
		// Envelope-level input arrays have no conversation turn but still describe
		// the current request. Scope metadata keeps their fields isolated or grouped
		// correctly; historical unknown-role content with a real turn index remains
		// non-current unless the extractor marks it explicitly.
		return segment.IsCurrentTurn || segment.TurnIndex < 0
	}
}

// profiledRequestLocalToolResult identifies a terminal provider-native tool
// result that directly feeds the model response being requested. Earlier tool
// results remain historical evidence and require an explicit current-user
// referent before they can become active.
func profiledRequestLocalToolResult(
	segment extract.Segment,
	terminalConversationIndex int,
	terminalTurnIndex int,
) bool {
	if !profiledRequestLocalToolResultCarrier(segment) {
		return false
	}
	return profiledTerminalConversationPosition(
		segment.ConversationIndex, segment.TurnIndex,
		terminalConversationIndex, terminalTurnIndex,
	)
}

func profiledRequestLocalToolResultCarrier(segment extract.Segment) bool {
	if segment.Role != extract.RoleTool || segment.Provenance != extract.ProvenanceContent ||
		segment.ContentKind != extract.ContentKindToolResult || segment.ScopeID == 0 ||
		segment.FieldPathHash == "" ||
		!authoritativeToolResultAssociation(segment.ToolAssociation) {
		return false
	}
	return true
}

func authoritativeToolResultAssociation(association extract.ToolResultAssociation) bool {
	switch association {
	case extract.ToolResultAssociationUnique:
		return true
	default:
		return false
	}
}

// profiledTerminalConversationPosition is shared by batch and streaming. A
// provider history item is authoritative whenever conversation coordinates are
// available. Only wholly unindexed inputs fall back to the highest turn; this
// keeps an earlier unindexed tool result historical even when it is physically
// emitted after the terminal turn.
func profiledTerminalConversationPosition(
	conversationIndex int,
	turnIndex int,
	terminalConversationIndex int,
	terminalTurnIndex int,
) bool {
	if conversationIndex >= 0 || terminalConversationIndex >= 0 {
		return conversationIndex >= 0 && conversationIndex == terminalConversationIndex
	}
	return turnIndex == terminalTurnIndex
}

func profiledEffectiveCurrentTurn(segment extract.Segment, activeTurnIndex int) bool {
	if segment.IsCurrentTurn {
		return true
	}
	structuredTool := segment.ContentKind == extract.ContentKindToolCallArguments ||
		segment.Provenance == extract.ProvenanceToolPayload
	if structuredTool && activeTurnIndex < 0 && segment.TurnIndex < 0 {
		return true
	}
	return activeTurnIndex >= 0 && segment.TurnIndex == activeTurnIndex &&
		structuredTool
}

func profiledContentInert(kind extract.ContentKind) bool {
	switch kind {
	case extract.ContentKindToolResult, extract.ContentKindQuotedText, extract.ContentKindLogOutput,
		extract.ContentKindDocumentation, extract.ContentKindSecurityAnalysis:
		return true
	default:
		return false
	}
}

// profiledReferentCarrierKind is intentionally a closed list. These content
// kinds enter the narrow trusted-current user carrier path and can become
// active only through a proven local directive relationship. Code/configuration
// from system or unknown owners retain their established independent grouping
// semantics. Tool schemas, tool-call arguments, and tool results have separate
// ownership rules and must never enter this carrier path.
func profiledReferentCarrierKind(kind extract.ContentKind) bool {
	switch kind {
	case extract.ContentKindQuotedText, extract.ContentKindCodeBlock,
		extract.ContentKindLogOutput, extract.ContentKindConfiguration,
		extract.ContentKindDocumentation, extract.ContentKindSecurityAnalysis:
		return true
	default:
		return false
	}
}

func profiledTrustedCurrentUserCarrier(segment extract.Segment) bool {
	return segment.IsCurrentTurn && trustedUserContentSegment(segment) &&
		profiledReferentCarrierKind(segment.ContentKind)
}

func profiledTrustedCurrentUserNaturalLanguageDirective(segment extract.Segment) bool {
	return segment.IsCurrentTurn && trustedUserContentSegment(segment) &&
		segment.ContentKind == extract.ContentKindNaturalLanguageDirective
}

func profiledRequestLocalSystemDirective(segment extract.Segment) bool {
	return enforcementScopeForSegment(segment) == EnforcementScopeRequestLocalSystem
}

func profiledRequestLocalSystemCarrier(segment extract.Segment) bool {
	return segment.Role == extract.RoleSystem &&
		segment.Provenance == extract.ProvenanceContent &&
		segment.ScopeID != 0 && segment.FieldPathHash != "" &&
		profiledReferentCarrierKind(segment.ContentKind)
}

// profiledSelfContainedCarrierKind is limited to content kinds produced by a
// caller-controlled fenced info string. Quoted text and security analysis keep
// their stronger inertness contract; a later explicit referent may still
// reactivate them through the established ownership path.
func profiledSelfContainedCarrierKind(kind extract.ContentKind) bool {
	switch kind {
	case extract.ContentKindCodeBlock, extract.ContentKindLogOutput,
		extract.ContentKindConfiguration, extract.ContentKindDocumentation:
		return true
	default:
		return false
	}
}

func profiledSelfContainedCarrierRunAdjacent(previous, current extract.Segment) bool {
	return previous.ScopeID != 0 && previous.ScopeID == current.ScopeID &&
		previous.TurnIndex == current.TurnIndex &&
		previous.ConversationIndex == current.ConversationIndex &&
		strings.TrimSpace(previous.Text) != "" && strings.TrimSpace(current.Text) != "" &&
		profiledTrustedCurrentUserCarrier(previous) && profiledTrustedCurrentUserCarrier(current) &&
		profiledSelfContainedCarrierKind(previous.ContentKind) &&
		profiledSelfContainedCarrierKind(current.ContentKind) &&
		profiledSelfContainedCarrierTextContinues(previous.Text, current.Text)
}

func profiledSelfContainedCarrierTextContinues(previous, current string) bool {
	previous = strings.TrimSpace(profiledClosedFenceBodyOrText(previous))
	current = strings.TrimSpace(profiledClosedFenceBodyOrText(current))
	if previous == "" || current == "" || strings.ContainsAny(previous, "\r\n") ||
		strings.ContainsAny(current, "\r\n") {
		return false
	}
	previousRunes := []rune(previous)
	currentRunes := []rune(current)
	last := previousRunes[len(previousRunes)-1]
	first := currentRunes[0]
	if unicode.IsPunct(last) || unicode.IsSymbol(last) {
		return false
	}
	return unicode.IsDigit(first) || unicode.IsLetter(first) && !unicode.IsUpper(first)
}

// profiledSelfContainedCarrierRun treats one bounded, physically contiguous
// run of caller-controlled fenced carriers as a single logical carrier. This
// closes the equivalent split-core relabeling bypass without composing across
// a natural-language owner, quoted/security-analysis material, role, turn, or
// scope boundary.
func (c *Classifier) profiledSelfContainedCarrierRun(
	segments []extract.Segment,
	start int,
	end int,
) (refs []profiledSegmentRef, parts []string, imperative bool, complete bool) {
	if c == nil || start < 0 || start >= end || end > len(segments) {
		return nil, nil, false, true
	}
	refs = make([]profiledSegmentRef, 0, end-start)
	for index := start; index < end; index++ {
		segment := segments[index]
		if !profiledTrustedCurrentUserCarrier(segment) ||
			!profiledSelfContainedCarrierKind(segment.ContentKind) {
			return nil, nil, false, true
		}
		refs = append(refs, profiledSegmentRef{index: index, segment: segment})
	}
	parts, imperative, complete = c.profiledSelfContainedCarrierRefs(refs)
	return refs, parts, imperative, complete
}

func (c *Classifier) profiledSelfContainedCarrierRefs(
	refs []profiledSegmentRef,
) (parts []string, imperative bool, complete bool) {
	if c == nil || len(refs) == 0 {
		return nil, false, true
	}
	proofParts := make([]string, 0, len(refs))
	for _, ref := range refs {
		segment := ref.segment
		if !profiledTrustedCurrentUserCarrier(segment) ||
			!profiledSelfContainedCarrierKind(segment.ContentKind) {
			return nil, false, true
		}
		proofParts = append(proofParts, profiledClosedFenceBodyOrText(segment.Text))
	}
	direct, complete := directProfiledPartIndexes(c, proofParts)
	if !complete || len(direct) == 0 {
		return proofParts, false, complete
	}
	if len(refs) == 1 {
		return []string{refs[0].segment.Text}, true, true
	}
	return []string{strings.Join(proofParts, " ")}, true, true
}

func (c *Classifier) profiledRequestLocalSystemCarrierRefs(
	refs []profiledSegmentRef,
) (parts []string, imperative bool, complete bool) {
	if c == nil || len(refs) == 0 {
		return nil, false, true
	}
	proofParts := make([]string, 0, len(refs))
	for _, ref := range refs {
		segment := ref.segment
		if !profiledRequestLocalSystemCarrier(segment) ||
			!profiledSelfContainedCarrierKind(segment.ContentKind) {
			return nil, false, true
		}
		proofParts = append(proofParts, profiledClosedFenceBodyOrText(segment.Text))
	}
	direct, complete := directProfiledPartIndexes(c, proofParts)
	if !complete || len(direct) == 0 {
		return proofParts, false, complete
	}
	if len(refs) == 1 {
		return []string{refs[0].segment.Text}, true, true
	}
	return []string{strings.Join(proofParts, " ")}, true, true
}

func (c *Classifier) profiledRequestLocalSystemSurvivingOwnerIndexes(
	refs []profiledSegmentRef,
) ([]bool, bool) {
	if c == nil || len(refs) == 0 {
		return nil, true
	}
	surviving := make([]bool, len(refs))
	// Cancellation is a field-local transaction decision. Partition before
	// building the reverse-scan ledger so a neighboring provider field, or the
	// same path reused after a physical gap, cannot revoke this owner's speech act.
	for first := 0; first < len(refs); {
		end := first + 1
		for end < len(refs) && profiledRequestLocalSystemOwnerTransactionContinues(
			refs[end-1], refs[end],
		) {
			end++
		}
		parts := make([]string, end-first)
		for index := first; index < end; index++ {
			if profiledRequestLocalSystemDirective(refs[index].segment) {
				parts[index-first] = refs[index].segment.Text
			}
		}
		indexes, complete := affirmativeProfiledPartIndexes(c, parts)
		if !complete {
			return nil, false
		}
		for _, index := range indexes {
			if index >= 0 && index < len(parts) {
				surviving[first+index] = true
			}
		}
		first = end
	}
	return surviving, true
}

func profiledSegmentRefsPhysicallyAdjacent(previous, current profiledSegmentRef) bool {
	if previous.hasPhysicalOrdinal || current.hasPhysicalOrdinal {
		return previous.hasPhysicalOrdinal && current.hasPhysicalOrdinal &&
			current.physicalOrdinal == previous.physicalOrdinal+1
	}
	return current.index == previous.index+1
}

func profiledRequestLocalSystemOwnerTransactionContinues(
	previous, current profiledSegmentRef,
) bool {
	return profiledSegmentRefsPhysicallyAdjacent(previous, current) &&
		profiledSegmentsShareLogicalTextField(previous.segment, current.segment)
}

// profiledRequestLocalSystemCarrierOwnerRuns resolves only bounded, physically
// adjacent carrier runs in one logical provider field. Natural-language text in
// another field or across an omitted physical unit can neither activate nor
// suppress the carrier. The owner disposition is shared by the dedicated
// reactivation producer and the generic group view so the two paths cannot
// disagree about who owns the fenced body.
func (c *Classifier) profiledRequestLocalSystemCarrierOwnerRuns(
	refs []profiledSegmentRef,
	requirePhysicalAdjacency bool,
) ([]profiledRequestLocalSystemCarrierOwnerRun, bool) {
	if c == nil || len(refs) == 0 {
		return nil, true
	}
	if !profiledRequestLocalSystemGroupHasCarrier(refs) {
		return nil, true
	}
	var survivingOwners []bool
	survivingOwnersLoaded := false
	ownerSurvives := func(index int) (bool, bool) {
		if !survivingOwnersLoaded {
			// Local inert/cancellation owners need no request-wide proof. Only an
			// affirmative owner requires the bounded cancellation scan.
			if len(refs) > maxRoleClassifierSegments {
				return false, false
			}
			var complete bool
			survivingOwners, complete = c.profiledRequestLocalSystemSurvivingOwnerIndexes(refs)
			if !complete {
				return false, false
			}
			survivingOwnersLoaded = true
		}
		return index >= 0 && index < len(survivingOwners) && survivingOwners[index], true
	}
	adjacent := func(previous, current profiledSegmentRef) bool {
		return (!requirePhysicalAdjacency || profiledSegmentRefsPhysicallyAdjacent(previous, current)) &&
			profiledSegmentsShareLogicalTextField(previous.segment, current.segment)
	}
	runs := make([]profiledRequestLocalSystemCarrierOwnerRun, 0, 1)
	for index := 0; index < len(refs); {
		first := refs[index]
		if !profiledRequestLocalSystemCarrier(first.segment) ||
			!profiledSelfContainedCarrierKind(first.segment.ContentKind) {
			index++
			continue
		}
		end := index + 1
		for end < len(refs) {
			previous := refs[end-1]
			current := refs[end]
			if !adjacent(previous, current) ||
				!profiledRequestLocalSystemCarrier(current.segment) ||
				!profiledSelfContainedCarrierKind(current.segment.ContentKind) ||
				!profiledSelfContainedCarrierTextContinues(previous.segment.Text, current.segment.Text) {
				break
			}
			end++
		}
		ownerAt := func(ownerIndex int, edge profiledSegmentRef) (profiledSegmentRef, bool) {
			if ownerIndex < 0 || ownerIndex >= len(refs) {
				return profiledSegmentRef{}, false
			}
			owner := refs[ownerIndex]
			if !(adjacent(edge, owner) || adjacent(owner, edge)) ||
				!profiledRequestLocalSystemDirective(owner.segment) {
				return profiledSegmentRef{}, false
			}
			return owner, true
		}
		beforeIndex := index - 1
		afterIndex := end
		before, beforeOK := ownerAt(beforeIndex, refs[index])
		after, afterOK := ownerAt(afterIndex, refs[end-1])
		beforeDisposition := quotedReviewContinuationNone
		afterDisposition := quotedReviewContinuationNone
		if beforeOK {
			var proofComplete bool
			beforeDisposition, proofComplete = c.profiledCarrierLocalOwnerDisposition(before.segment)
			if !proofComplete {
				return nil, false
			}
		}
		if afterOK {
			var proofComplete bool
			afterDisposition, proofComplete = c.profiledCarrierLocalOwnerDisposition(after.segment)
			if !proofComplete {
				return nil, false
			}
		}
		if beforeDisposition == quotedReviewContinuationActive {
			survives, proofComplete := ownerSurvives(beforeIndex)
			if !proofComplete {
				return nil, false
			}
			if !survives {
				beforeDisposition = quotedReviewContinuationNone
			}
		}
		if afterDisposition == quotedReviewContinuationActive {
			survives, proofComplete := ownerSurvives(afterIndex)
			if !proofComplete {
				return nil, false
			}
			if !survives {
				afterDisposition = quotedReviewContinuationNone
			}
		}

		run := profiledRequestLocalSystemCarrierOwnerRun{
			first: index, end: end, anchor: -1,
			state: profiledRequestLocalSystemCarrierUnclaimed,
		}
		switch {
		case afterDisposition == quotedReviewContinuationActive:
			run.anchor = afterIndex
			run.state = profiledRequestLocalSystemCarrierActivated
		case afterDisposition == quotedReviewContinuationCancelled:
			run.anchor = afterIndex
			run.state = profiledRequestLocalSystemCarrierSuppressed
		case beforeDisposition == quotedReviewContinuationActive:
			run.anchor = beforeIndex
			run.state = profiledRequestLocalSystemCarrierActivated
		case afterDisposition == quotedReviewContinuationInert:
			run.anchor = afterIndex
			run.state = profiledRequestLocalSystemCarrierSuppressed
		case beforeDisposition == quotedReviewContinuationCancelled ||
			beforeDisposition == quotedReviewContinuationInert:
			run.anchor = beforeIndex
			run.state = profiledRequestLocalSystemCarrierSuppressed
		}
		runs = append(runs, run)
		index = end
	}
	return runs, true
}

// profiledRequestLocalSystemGenericCarrierView removes only a carrier run whose
// adjacent same-field owner has been proven. Suppressed runs remain inert;
// activated runs are classified exclusively by the dedicated reactivation
// producer so the carrier body, anchor, scope, and referent proof stay exact.
func (c *Classifier) profiledRequestLocalSystemGenericCarrierView(
	parts []string,
	refs []profiledSegmentRef,
	requirePhysicalAdjacency bool,
) ([]string, []profiledSegmentRef, bool, bool) {
	if len(parts) != len(refs) {
		return nil, nil, false, false
	}
	if len(refs) == 0 ||
		enforcementScopeForProfiledGroup(refs) != EnforcementScopeRequestLocalSystem ||
		!profiledRequestLocalSystemGroupHasCarrier(refs) {
		return parts, refs, false, true
	}
	runs, complete := c.profiledRequestLocalSystemCarrierOwnerRuns(
		refs, requirePhysicalAdjacency,
	)
	if !complete {
		return nil, nil, false, false
	}
	excluded := make([]bool, len(refs))
	excludedAny := false
	suppressed := false
	for _, run := range runs {
		if run.state == profiledRequestLocalSystemCarrierUnclaimed {
			continue
		}
		if run.state == profiledRequestLocalSystemCarrierSuppressed {
			suppressed = true
		}
		for index := run.first; index < run.end; index++ {
			excluded[index] = true
			excludedAny = true
		}
	}
	if !excludedAny {
		return parts, refs, false, true
	}
	genericParts := make([]string, 0, len(parts))
	genericRefs := make([]profiledSegmentRef, 0, len(refs))
	for index, ref := range refs {
		if excluded[index] {
			continue
		}
		genericParts = append(genericParts, parts[index])
		genericRefs = append(genericRefs, ref)
	}
	return genericParts, genericRefs, suppressed, true
}

// profiledRequestLocalSystemCarrierGenericPlan evaluates the complete carrier
// groups, including inert log/documentation units omitted by the ordinary batch
// group builder. Physical segment indexes then remove the exact claimed run from
// generic groups without letting an omitted carrier member collapse a barrier.
// Unresolved carrier indexes are kept separate from semantic state: callers may
// still classify independent natural-language fields before returning the fixed
// classifier-window unavailable disposition.
func (c *Classifier) profiledRequestLocalSystemCarrierGenericPlan(
	groups []profiledSegmentGroup,
	requirePhysicalAdjacency bool,
) (map[int]struct{}, map[int]struct{}, bool, bool) {
	var omitted map[int]struct{}
	var unresolved map[int]struct{}
	suppressed := false
	complete := true
	for _, group := range groups {
		runs, groupComplete := c.profiledRequestLocalSystemCarrierOwnerRuns(
			group.refs, requirePhysicalAdjacency,
		)
		if !groupComplete {
			complete = false
			for _, ref := range group.refs {
				if profiledRequestLocalSystemCarrier(ref.segment) &&
					profiledSelfContainedCarrierKind(ref.segment.ContentKind) {
					if unresolved == nil {
						unresolved = make(map[int]struct{})
					}
					unresolved[ref.index] = struct{}{}
				}
			}
			continue
		}
		for _, run := range runs {
			if run.state == profiledRequestLocalSystemCarrierUnclaimed {
				continue
			}
			if run.state == profiledRequestLocalSystemCarrierSuppressed {
				suppressed = true
			}
			if omitted == nil {
				omitted = make(map[int]struct{})
			}
			for index := run.first; index < run.end; index++ {
				omitted[group.refs[index].index] = struct{}{}
			}
		}
	}
	return omitted, unresolved, suppressed, complete
}

func profiledGroupWithoutCarrierIndexes(
	group profiledSegmentGroup,
	omitted map[int]struct{},
	unresolved map[int]struct{},
) profiledSegmentGroup {
	if len(group.parts) == 0 || len(group.parts) != len(group.refs) ||
		len(omitted) == 0 && len(unresolved) == 0 {
		return group
	}
	filteredParts := make([]string, 0, len(group.parts))
	filteredRefs := make([]profiledSegmentRef, 0, len(group.refs))
	for index, ref := range group.refs {
		if _, excluded := omitted[ref.index]; excluded {
			continue
		}
		if _, excluded := unresolved[ref.index]; excluded {
			continue
		}
		filteredParts = append(filteredParts, group.parts[index])
		filteredRefs = append(filteredRefs, ref)
	}
	group.parts = filteredParts
	group.refs = filteredRefs
	return group
}

func (c *Classifier) profiledRequestLocalSystemCarrierReactivationProofs(
	refs []profiledSegmentRef,
	requirePhysicalAdjacency bool,
) ([]profiledRequestLocalSystemReactivationProof, bool) {
	if c == nil || len(refs) == 0 {
		return nil, true
	}
	runs, complete := c.profiledRequestLocalSystemCarrierOwnerRuns(
		refs, requirePhysicalAdjacency,
	)
	if !complete {
		return nil, false
	}
	proofs := make([]profiledRequestLocalSystemReactivationProof, 0, 1)
	for _, run := range runs {
		if run.state != profiledRequestLocalSystemCarrierActivated ||
			run.anchor < 0 || run.anchor >= len(refs) {
			continue
		}
		carrierRefs := append([]profiledSegmentRef(nil), refs[run.first:run.end]...)
		parts, imperative, proofComplete := c.profiledRequestLocalSystemCarrierRefs(carrierRefs)
		if !proofComplete {
			return nil, false
		}
		if !imperative {
			continue
		}
		proofs = append(proofs, profiledRequestLocalSystemReactivationProof{
			carrierRefs: carrierRefs,
			parts:       parts,
			anchor:      refs[run.anchor],
		})
	}
	return proofs, true
}

func profiledCarrierRunClearOccurrenceOffsets(result *Result) {
	if result == nil {
		return
	}
	for index := range result.EvidenceOccurrences {
		occurrence := &result.EvidenceOccurrences[index]
		occurrence.ClauseID = -1
		occurrence.SentenceID = -1
		occurrence.Start = -1
		occurrence.End = -1
	}
}

// rebaseProfiledReconstructedCore replaces offsets from a stripped quoted core
// with clause/span coordinates replayed against the original profiled fields.
// The reconstructed core is useful for classification, but its clause space is
// not the clause space of the surrounding safety-review wrapper. Failing to
// rebind every winning dimension therefore makes the referent proof ineligible.
func (c *Classifier) rebaseProfiledReconstructedCore(
	result *Result,
	refs []profiledSegmentRef,
	quoted string,
	policy Policy,
) bool {
	if c == nil || result == nil || len(result.EvidenceOccurrences) == 0 || len(refs) == 0 {
		return false
	}
	if c.rebaseProfiledReconstructedCoreWithinField(result, refs, quoted, policy) {
		return true
	}
	profiledCarrierRunClearOccurrenceOffsets(result)
	sources := c.profiledOccurrenceSourcesWithOptions(
		result.EvidenceOccurrences, refs, policy, true,
	)
	if len(sources) != len(result.EvidenceOccurrences) {
		return false
	}
	for index := range result.EvidenceOccurrences {
		if !sources[index].valid {
			return false
		}
		occurrence := &result.EvidenceOccurrences[index]
		occurrence.ClauseID = int(sources[index].occurrence.clauseID)
		occurrence.SentenceID = occurrence.ClauseID
		occurrence.Start = int(sources[index].occurrence.start)
		occurrence.End = int(sources[index].occurrence.end)
	}
	return true
}

type profiledClauseSpan struct {
	clauseID int32
	start    int
	end      int
}

func (c *Classifier) rebaseProfiledReconstructedCoreWithinField(
	result *Result,
	refs []profiledSegmentRef,
	quoted string,
	policy Policy,
) bool {
	if c == nil || result == nil || quoted == "" || len(refs) == 0 {
		return false
	}
	// rawInertQuotedSafetyReviewReferent already returns the normalized carrier
	// core. Re-normalizing its boundary sentinel can change that sentinel and
	// break exact fenced-field placement.
	coreRunes := []rune(quoted)
	if len(coreRunes) == 0 || len(coreRunes) > maxClassifierNormalizedRunes {
		return false
	}
	coreAnalysis := c.analyzeDirectives(coreRunes, policy)
	coreSpans, ok := profiledClauseSpans(coreRunes, coreAnalysis.clauses)
	if !ok {
		return false
	}

	ownerIndex := -1
	ownerOffset := -1
	var ownerRunes []rune
	var ownerStorage int
	var ownerAnalysis analyzedDirectives
	var ownerScratch normalizationScratch
	for index, ref := range refs {
		views := normalizePartsInto([]string{ref.segment.Text}, nil, &ownerScratch)
		if views.truncated {
			putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
			continue
		}
		analysis := c.analyzeDirectives(views.standardRunes, policy)
		offset := profiledRuneSliceIndex(views.standardRunes, coreRunes, 0)
		if offset < 0 {
			putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
			continue
		}
		if ownerIndex >= 0 {
			putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
			putNormalizedRuneBuffer(ownerRunes, ownerStorage)
			return false
		}
		ownerIndex = index
		ownerOffset = offset
		ownerRunes = views.standardRunes
		ownerStorage = views.storageUsed
		ownerAnalysis = analysis
	}
	if ownerIndex < 0 {
		return false
	}
	defer putNormalizedRuneBuffer(ownerRunes, ownerStorage)
	ownerSpans, ok := profiledClauseSpans(ownerRunes, ownerAnalysis.clauses)
	if !ok {
		return false
	}

	rebased := make([]EvidenceOccurrence, len(result.EvidenceOccurrences))
	copy(rebased, result.EvidenceOccurrences)
	for index := range rebased {
		occurrence := &rebased[index]
		coreSpan, found := profiledClauseSpanByID(coreSpans, int32(occurrence.ClauseID))
		if !found || occurrence.Start < 0 || occurrence.End <= occurrence.Start ||
			occurrence.End > coreSpan.end-coreSpan.start {
			return false
		}
		absoluteStart := ownerOffset + coreSpan.start + occurrence.Start
		absoluteEnd := ownerOffset + coreSpan.start + occurrence.End
		ownerSpan, found := profiledClauseSpanContaining(ownerSpans, absoluteStart, absoluteEnd)
		if !found {
			return false
		}
		occurrence.ClauseID = int(ownerSpan.clauseID)
		occurrence.SentenceID = occurrence.ClauseID
		occurrence.Start = absoluteStart - ownerSpan.start
		occurrence.End = absoluteEnd - ownerSpan.start
	}
	result.EvidenceOccurrences = rebased
	return true
}

func profiledClauseSpans(text []rune, clauses []analyzedDirectiveClause) ([]profiledClauseSpan, bool) {
	if len(text) == 0 || len(clauses) == 0 {
		return nil, false
	}
	spans := make([]profiledClauseSpan, 0, len(clauses))
	cursor := 0
	for _, clause := range clauses {
		if len(clause.runes) == 0 {
			continue
		}
		start := profiledRuneSliceIndex(text, clause.runes, cursor)
		if start < 0 {
			return nil, false
		}
		spans = append(spans, profiledClauseSpan{
			clauseID: clauseIDForOccurrence(clause),
			start:    start,
			end:      start + len(clause.runes),
		})
		cursor = start + len(clause.runes)
	}
	return spans, len(spans) != 0
}

func profiledRuneSliceIndex(text, target []rune, start int) int {
	if len(target) == 0 || len(target) > len(text) {
		return -1
	}
	if start < 0 {
		start = 0
	}
	// Directive analysis uses private non-Unicode rune sentinels. Converting both
	// sides to strings maps those sentinels to the same public replacement rune,
	// which is also how rawInertQuotedSafetyReviewReferent serializes its core.
	haystack := string(text[start:])
	byteOffset := strings.Index(haystack, string(target))
	if byteOffset < 0 {
		return -1
	}
	return start + utf8.RuneCountInString(haystack[:byteOffset])
}

func profiledClauseSpanByID(spans []profiledClauseSpan, clauseID int32) (profiledClauseSpan, bool) {
	for _, span := range spans {
		if span.clauseID == clauseID {
			return span, true
		}
	}
	return profiledClauseSpan{}, false
}

func profiledClauseSpanContaining(
	spans []profiledClauseSpan,
	start, end int,
) (profiledClauseSpan, bool) {
	for _, span := range spans {
		if start >= span.start && end <= span.end {
			return span, true
		}
	}
	return profiledClauseSpan{}, false
}

func mergeProfiledCarrierRunOwner(
	refs []profiledSegmentRef,
	owner profiledSegmentRef,
) []profiledSegmentRef {
	merged := make([]profiledSegmentRef, 0, len(refs)+1)
	if len(refs) != 0 && owner.index < refs[0].index {
		merged = append(merged, owner)
		return append(merged, refs...)
	}
	merged = append(merged, refs...)
	return append(merged, owner)
}

func profiledSelfContainedCarrierCandidate(result Result, thresholds Thresholds) bool {
	if !resultHasEligibleMaliciousWinner(result, thresholds) ||
		result.FindingConfidence == FindingNone || result.DecisionExplanation == nil ||
		!result.DecisionExplanation.CorePredicateComplete {
		return false
	}
	const requiredCore = uint16(1)<<ruleDimensionIntent | uint16(1)<<ruleDimensionObject
	return result.DecisionExplanation.EvidenceDimensionMask&requiredCore == requiredCore
}

func profiledClosedFenceBodyOrText(text string) string {
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) < 3 {
		return text
	}
	marker, count, ok := profiledFenceMarkerLine(strings.TrimSuffix(lines[0], "\r"))
	if !ok || !profiledClosingFenceLine(strings.TrimSuffix(lines[len(lines)-1], "\r"), marker, count) {
		return text
	}
	return strings.Join(lines[1:len(lines)-1], "\n")
}

func profiledFenceMarkerLine(line string) (byte, int, bool) {
	spaces := 0
	for spaces < len(line) && line[spaces] == ' ' && spaces < 4 {
		spaces++
	}
	if spaces > 3 || spaces >= len(line) || line[spaces] != '`' && line[spaces] != '~' {
		return 0, 0, false
	}
	marker := line[spaces]
	end := spaces
	for end < len(line) && line[end] == marker {
		end++
	}
	if end-spaces < 3 {
		return 0, 0, false
	}
	return marker, end - spaces, true
}

func profiledClosingFenceLine(line string, marker byte, minimum int) bool {
	spaces := 0
	for spaces < len(line) && line[spaces] == ' ' && spaces < 4 {
		spaces++
	}
	if spaces > 3 || spaces >= len(line) || line[spaces] != marker {
		return false
	}
	end := spaces
	for end < len(line) && line[end] == marker {
		end++
	}
	if end-spaces < minimum {
		return false
	}
	return strings.TrimSpace(line[end:]) == ""
}

func (c *Classifier) profiledSelfContainedCarrierRunLocalOwner(
	segments []extract.Segment,
	start int,
	end int,
) (profiledSegmentRef, bool) {
	if c == nil || start < 0 || start >= end || end > len(segments) {
		return profiledSegmentRef{}, false
	}
	carrier := segments[start]
	before, beforeOK := nearestProfiledCurrentScopeUnit(segments, carrier, start, -1)
	after, afterOK := nearestProfiledCurrentScopeUnit(segments, carrier, end-1, 1)
	eligible := func(owner profiledSegmentRef, ok bool) bool {
		return ok && owner.segment.ScopeID == carrier.ScopeID &&
			owner.segment.TurnIndex == carrier.TurnIndex && owner.segment.IsCurrentTurn &&
			trustedUserContentSegment(owner.segment)
	}
	beforeEligible := eligible(before, beforeOK)
	afterEligible := eligible(after, afterOK)
	beforeDisposition, beforeComplete := c.profiledCarrierLocalOwnerDisposition(before.segment)
	afterDisposition, afterComplete := c.profiledCarrierLocalOwnerDisposition(after.segment)
	if !beforeEligible || !beforeComplete {
		beforeDisposition = quotedReviewContinuationNone
	}
	if !afterEligible || !afterComplete {
		afterDisposition = quotedReviewContinuationNone
	}
	// A newer active speech act or explicit cancellation owns the completed
	// run. A trailing inert review outranks a generic prefix, but it must not
	// erase a preceding active execution request because review is additive,
	// not a cancellation.
	if afterDisposition == quotedReviewContinuationActive ||
		afterDisposition == quotedReviewContinuationCancelled {
		return after, true
	}
	if beforeDisposition == quotedReviewContinuationActive {
		return before, true
	}
	if afterDisposition == quotedReviewContinuationInert {
		return after, true
	}
	if beforeDisposition == quotedReviewContinuationCancelled ||
		beforeDisposition == quotedReviewContinuationInert {
		return before, true
	}
	var owner profiledSegmentRef
	switch {
	case beforeOK:
		owner = before
	case afterOK:
		owner = after
	default:
		return profiledSegmentRef{}, false
	}
	if !eligible(owner, true) {
		return profiledSegmentRef{}, false
	}
	return owner, true
}

func (c *Classifier) profiledCarrierLocalOwnerClaimsCarrier(owner extract.Segment) bool {
	disposition, complete := c.profiledCarrierLocalOwnerDisposition(owner)
	return complete && disposition != quotedReviewContinuationNone
}

func (c *Classifier) profiledCarrierLocalOwnerRunDisposition(
	owner extract.Segment,
) (suppress bool, reactivate bool, complete bool) {
	disposition, complete := c.profiledCarrierLocalOwnerDisposition(owner)
	if !complete {
		return false, false, false
	}
	switch disposition {
	case quotedReviewContinuationActive:
		return false, true, true
	case quotedReviewContinuationInert, quotedReviewContinuationCancelled:
		return true, false, true
	default:
		return false, false, true
	}
}

func (c *Classifier) profiledCarrierLocalOwnerDisposition(
	owner extract.Segment,
) (quotedReviewContinuationDisposition, bool) {
	if c == nil {
		return quotedReviewContinuationNone, true
	}
	switch owner.ContentKind {
	case extract.ContentKindNaturalLanguageDirective, extract.ContentKindUnknown:
	default:
		return quotedReviewContinuationNone, true
	}
	var scratch normalizationScratch
	views := normalizePartsInto([]string{owner.Text}, takeNormalizedRuneBuffer(), &scratch)
	defer putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
	if views.truncated {
		return quotedReviewContinuationNone, false
	}
	normalized := string(views.standardRunes)
	disposition := quotedReviewFollowUpDisposition(
		normalized, c.implementationStarts, c.implementationPatterns,
	)
	if disposition != quotedReviewContinuationNone {
		return disposition, true
	}
	if quotedReviewContinuationIsSafetyOnly(normalized, c.implementationStarts) ||
		profiledCarrierLocalOwnerIsNonOperationalReview(normalized) {
		return quotedReviewContinuationInert, true
	}
	return quotedReviewContinuationNone, true
}

// profiledCarrierLocalOwnerIsNonOperationalReview is deliberately narrower
// than the general quoted-review safety grammar. It only lets an adjacent
// current-user owner keep one fenced carrier inert when the entire normalized
// instruction asks to summarize/review that carrier, optionally for an
// explicit safety purpose. Exact tail matching prevents an appended
// operational instruction from inheriting this local suppression.
func profiledCarrierLocalOwnerIsNonOperationalReview(clause string) bool {
	clause = strings.Join(strings.Fields(clause), " ")
	clause = strings.TrimRightFunc(clause, func(value rune) bool {
		return unicode.IsSpace(value) || unicode.IsPunct(value)
	})
	for _, head := range []string{
		"summarize it", "summarise it", "review it", "analyze it", "analyse it",
	} {
		if clause == head {
			return true
		}
		if !strings.HasPrefix(clause, head+" for ") {
			continue
		}
		purpose := strings.TrimSpace(clause[len(head)+len(" for "):])
		purpose = strings.TrimPrefix(purpose, "the ")
		purpose = strings.TrimPrefix(purpose, "a ")
		switch purpose {
		case "defensive review", "safety review", "security review", "risk review", "harm review":
			return true
		}
	}
	return false
}

func profiledContentActiveDirective(kind extract.ContentKind) bool {
	switch kind {
	case extract.ContentKindNaturalLanguageDirective, extract.ContentKindToolSchema,
		extract.ContentKindToolCallArguments, extract.ContentKindUnknown:
		return true
	default:
		return false
	}
}

type profiledCurrentReferent struct {
	group  profiledSegmentGroup
	anchor profiledSegmentRef
}

func affirmativeCurrentReferents(
	c *Classifier,
	groups []profiledSegmentGroup,
) ([]profiledCurrentReferent, bool) {
	if c == nil {
		return nil, true
	}
	referents := make([]profiledCurrentReferent, 0, len(groups))
	for _, group := range groups {
		if len(group.refs) == 0 || len(group.refs) != len(group.parts) {
			continue
		}
		segment := group.refs[0].segment
		if !trustedUserContentSegment(segment) || !segment.IsCurrentTurn || !group.activeDirective {
			continue
		}
		partIndexes, complete := affirmativeProfiledPartIndexes(c, group.parts)
		if !complete {
			return nil, false
		}
		for _, partIndex := range partIndexes {
			referents = append(referents, profiledCurrentReferent{
				group:  group,
				anchor: group.refs[partIndex],
			})
		}
	}
	// Preserve the previous latest-speech-act preference for equal-ranked
	// findings while still evaluating every surviving anchor. A later benign
	// anchor no longer erases an earlier malicious execution pair.
	sort.SliceStable(referents, func(i, j int) bool {
		return referents[i].anchor.index > referents[j].anchor.index
	})
	return referents, true
}

// latestAffirmativeProfiledPartIndex preserves cross-part cancellation while
// locating the physical segment that contains the latest surviving affirmative
// speech act. A phrase split across fields has no local anchor and therefore
// cannot create an implicit cross-field link.
func latestAffirmativeProfiledPartIndex(c *Classifier, parts []string) (int, bool) {
	indexes, complete := affirmativeProfiledPartIndexes(c, parts)
	if !complete || len(indexes) == 0 {
		return -1, false
	}
	return indexes[len(indexes)-1], true
}

// affirmativeProfiledPartIndexes returns every physical segment whose
// affirmative speech act remains effective after applying later explicit
// cancellations. Multiple independent "Execute it" anchors are not implicit
// cancellations of one another; each must bind to its own nearest local owner.
func affirmativeProfiledPartIndexes(c *Classifier, parts []string) ([]int, bool) {
	if c == nil || len(parts) == 0 {
		return nil, true
	}
	allIntents := make([]string, 0,
		len(quotedReviewSpecificContinuationIntents)+len(quotedReviewTerseContinuationIntents)+len(c.implementationStarts))
	allIntents = append(allIntents, quotedReviewSpecificContinuationIntents...)
	allIntents = append(allIntents, quotedReviewTerseContinuationIntents...)
	allIntents = append(allIntents, c.implementationStarts...)
	cancellations := make([]quotedReviewContinuationDecision, 0, 4)
	indexes := make([]int, 0, len(parts))
	for index := len(parts) - 1; index >= 0; index-- {
		decisions, complete := profiledPartContinuationDecisions(c, parts[index], allIntents)
		if !complete {
			if profiledOverflowNeutralDirective(c, parts[index]) {
				continue
			}
			return nil, false
		}
		activePart := false
		for _, decision := range decisions {
			switch decision.disposition {
			case quotedReviewContinuationActive:
				cancelled := false
				for _, cancellation := range cancellations {
					if quotedReviewContinuationIntentsEquivalent(decision.intent, cancellation.intent) {
						cancelled = true
						break
					}
				}
				if !cancelled {
					activePart = true
				}
			case quotedReviewContinuationCancelled:
				if !decision.alternative {
					cancellations = append(cancellations, decision)
				}
			}
		}
		if activePart {
			indexes = append(indexes, index)
		}
	}
	// The scan above is newest-to-oldest. Return physical order so callers that
	// ask for the latest index can take the final element deterministically.
	for left, right := 0, len(indexes)-1; left < right; left, right = left+1, right-1 {
		indexes[left], indexes[right] = indexes[right], indexes[left]
	}
	return indexes, true
}

func profiledPartContinuationDecisions(
	c *Classifier,
	text string,
	allIntents []string,
) ([]quotedReviewContinuationDecision, bool) {
	return profiledPartIntentDecisionsBounded(
		c, text, c.implementationStarts, allIntents, true, true,
	)
}

func profiledPartIntentDecisions(
	c *Classifier,
	text string,
	explicitIntents []string,
	allIntents []string,
	allowInertClauseOverflow bool,
) ([]quotedReviewContinuationDecision, bool) {
	return profiledPartIntentDecisionsBounded(
		c, text, explicitIntents, allIntents, allowInertClauseOverflow, false,
	)
}

func profiledPartIntentDecisionsBounded(
	c *Classifier,
	text string,
	explicitIntents []string,
	allIntents []string,
	allowInertClauseOverflow bool,
	completeNeutralOverflow bool,
) ([]quotedReviewContinuationDecision, bool) {
	if c == nil || strings.TrimSpace(text) == "" {
		return nil, true
	}
	var scratch normalizationScratch
	views := normalizePartsInto([]string{text}, nil, &scratch)
	defer putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
	if views.truncated {
		return nil, false
	}
	if !allowInertClauseOverflow {
		clauses := make([]string, 0, 4)
		overflow := false
		walkDirectiveClauses(views.standardRunes, func(clauseRunes []rune) bool {
			if len(clauses) >= 32 {
				overflow = true
				return false
			}
			if clause := strings.TrimSpace(string(clauseRunes)); clause != "" {
				clauses = append(clauses, clause)
			}
			return true
		})
		if overflow {
			return nil, false
		}
		ordered := make([]quotedReviewContinuationDecision, 0, 4)
		for index := len(clauses) - 1; index >= 0; index-- {
			next := ""
			if index+1 < len(clauses) {
				next = clauses[index+1]
			}
			decisions, _, occurrenceOverflow := quotedReviewContinuationClauseDecisions(
				clauses[index], next, explicitIntents, compactRuleIntentPatterns{}, allIntents,
			)
			if occurrenceOverflow {
				return nil, false
			}
			for _, decision := range decisions {
				if decision.disposition == quotedReviewContinuationCancelled &&
					!decision.alternative && index > 0 &&
					quotedReviewStandaloneAlternativeClause(clauses[index-1]) {
					decision.alternative = true
				}
				ordered = append(ordered, decision)
			}
		}
		return ordered, true
	}
	// Clause count is not itself evidence complexity. A long, otherwise benign
	// field may contain many ordinary sentences before one final "Execute it".
	// Treating the 33rd physical clause as proof loss makes that complete current
	// speech act fail open before the existing overflow-aware continuation parser
	// can examine it. Scan the bounded normalized field and cap only actionable
	// continuation decisions. The cap preserves the old worst-case decision
	// materialization bound (32 clauses * 64 occurrences) without letting inert
	// prose consume the proof budget.
	const maxProfiledPartContinuationDecisions = 32 * maxAnalyzedDirectiveClauses
	chronological := make([]quotedReviewContinuationDecision, 0, 4)
	complete := true
	physicalClauses := 0
	previous := ""
	current := ""
	process := func(clause, next, prior string) bool {
		decisions, _, occurrenceOverflow := quotedReviewContinuationClauseDecisions(
			clause, next, explicitIntents, compactRuleIntentPatterns{}, allIntents,
		)
		if occurrenceOverflow {
			complete = false
			return false
		}
		// Clause decisions are newest-to-oldest. Store the field in physical
		// order, then reverse once below so cross-clause and cross-part
		// cancellation semantics remain identical to the bounded path.
		for index := len(decisions) - 1; index >= 0; index-- {
			decision := decisions[index]
			if decision.disposition == quotedReviewContinuationCancelled &&
				!decision.alternative && prior != "" &&
				quotedReviewStandaloneAlternativeClause(prior) {
				decision.alternative = true
			}
			if len(chronological) >= maxProfiledPartContinuationDecisions {
				complete = false
				return false
			}
			chronological = append(chronological, decision)
		}
		return true
	}
	walkDirectiveClauses(views.standardRunes, func(clauseRunes []rune) bool {
		clause := strings.TrimSpace(string(clauseRunes))
		if clause == "" {
			return true
		}
		physicalClauses++
		if current != "" && !process(current, clause, previous) {
			return false
		}
		previous, current = current, clause
		return true
	})
	if complete && current != "" {
		process(current, "", previous)
	}
	if !complete {
		return nil, false
	}
	if physicalClauses > 32 && len(chronological) == 0 && !completeNeutralOverflow {
		// Preserve the established incomplete boundary for an oversized field
		// whose relation to a carrier is wholly unrecognized. The narrow
		// exception above is only for a physically located affirmative or
		// cancellation decision; ordinary overflow text must not silently make an
		// earlier direct/referent pair look fully inspected.
		return nil, false
	}
	for left, right := 0, len(chronological)-1; left < right; left, right = left+1, right-1 {
		chronological[left], chronological[right] = chronological[right], chronological[left]
	}
	return chronological, true
}

// profiledOverflowNeutralDirective proves only the absence of an effective
// referent or direct-rule speech act in one fully retained logical piece. It is
// deliberately narrower than making the piece generally "complete": callers
// may use the content-free result only while evicting an adjacent carrier pair.
// Physical clause count does not consume the proof budget; actionable intent
// occurrences remain bounded by profiledPartIntentDecisionsBounded.
func profiledOverflowNeutralDirective(c *Classifier, text string) bool {
	if c == nil || strings.TrimSpace(text) == "" {
		return false
	}
	affirmativeIntents := make([]string, 0,
		len(quotedReviewSpecificContinuationIntents)+len(quotedReviewTerseContinuationIntents)+len(c.implementationStarts))
	affirmativeIntents = append(affirmativeIntents, quotedReviewSpecificContinuationIntents...)
	affirmativeIntents = append(affirmativeIntents, quotedReviewTerseContinuationIntents...)
	affirmativeIntents = append(affirmativeIntents, c.implementationStarts...)
	affirmative, complete := profiledPartIntentDecisionsBounded(
		c, text, c.implementationStarts, affirmativeIntents, true, true,
	)
	if !complete || profiledEffectiveIntentDecisionExists(affirmative, nil) {
		return false
	}

	directIntents := profiledRuleDirectiveIntents(c)
	if len(directIntents) == 0 {
		return true
	}
	directSet := make(map[string]struct{}, len(directIntents))
	for _, intent := range directIntents {
		directSet[intent] = struct{}{}
	}
	allDirectIntents := make([]string, 0,
		len(quotedReviewSpecificContinuationIntents)+len(quotedReviewTerseContinuationIntents)+len(directIntents))
	allDirectIntents = append(allDirectIntents, quotedReviewSpecificContinuationIntents...)
	allDirectIntents = append(allDirectIntents, quotedReviewTerseContinuationIntents...)
	allDirectIntents = append(allDirectIntents, directIntents...)
	direct, complete := profiledPartIntentDecisionsBounded(
		c, text, directIntents, allDirectIntents, true, true,
	)
	return complete && !profiledEffectiveIntentDecisionExists(direct, directSet)
}

// profiledEffectiveIntentDecisionExists consumes newest-to-oldest decisions,
// matching affirmativeProfiledPartIndexes. A newer explicit cancellation can
// neutralize only the equivalent older intent; unrelated cancellations and
// alternatives never provide a general safe summary.
func profiledEffectiveIntentDecisionExists(
	decisions []quotedReviewContinuationDecision,
	allowed map[string]struct{},
) bool {
	cancellations := make([]quotedReviewContinuationDecision, 0, 4)
	for _, decision := range decisions {
		if allowed != nil {
			if _, ok := allowed[decision.intent]; !ok {
				continue
			}
		}
		switch decision.disposition {
		case quotedReviewContinuationCancelled:
			if !decision.alternative {
				cancellations = append(cancellations, decision)
			}
		case quotedReviewContinuationActive:
			cancelled := false
			for _, cancellation := range cancellations {
				if quotedReviewContinuationIntentsEquivalent(decision.intent, cancellation.intent) {
					cancelled = true
					break
				}
			}
			if !cancelled {
				return true
			}
		}
	}
	return false
}

// directProfiledPartIndexes returns every physical natural-language segment
// whose direct rule-intent speech act remains effective. A later unrelated
// directive is not an implicit replacement. Only a later explicit negative
// occurrence in the same intent family removes an earlier anchor.
func directProfiledPartIndexes(c *Classifier, parts []string) ([]int, bool) {
	if c == nil || len(parts) == 0 {
		return nil, true
	}
	directIntents := profiledRuleDirectiveIntents(c)
	if len(directIntents) == 0 {
		return nil, true
	}
	directSet := make(map[string]struct{}, len(directIntents))
	for _, intent := range directIntents {
		directSet[intent] = struct{}{}
	}
	allIntents := make([]string, 0,
		len(quotedReviewSpecificContinuationIntents)+len(quotedReviewTerseContinuationIntents)+len(directIntents))
	allIntents = append(allIntents, quotedReviewSpecificContinuationIntents...)
	allIntents = append(allIntents, quotedReviewTerseContinuationIntents...)
	allIntents = append(allIntents, directIntents...)

	cancellations := make([]quotedReviewContinuationDecision, 0, 4)
	indexes := make([]int, 0, len(parts))
	for index := len(parts) - 1; index >= 0; index-- {
		decisions, complete := profiledPartIntentDecisionsBounded(
			c, parts[index], directIntents, allIntents, true, true,
		)
		if !complete {
			return nil, false
		}
		activePart := false
		for _, decision := range decisions {
			if _, direct := directSet[decision.intent]; !direct {
				continue
			}
			switch decision.disposition {
			case quotedReviewContinuationActive:
				cancelled := false
				for _, cancellation := range cancellations {
					if quotedReviewContinuationIntentsEquivalent(decision.intent, cancellation.intent) {
						cancelled = true
						break
					}
				}
				if !cancelled {
					activePart = true
				}
			case quotedReviewContinuationCancelled:
				if !decision.alternative {
					cancellations = append(cancellations, decision)
				}
			}
		}
		if activePart && profiledPartStartsRuleDirective(c, parts[index]) {
			// Referential speech acts have their own ownership path and must
			// not be reinterpreted as a direct code/config continuation.
			if _, referential := latestAffirmativeProfiledPartIndex(c, []string{parts[index]}); !referential {
				indexes = append(indexes, index)
			}
		}
	}
	for left, right := 0, len(indexes)-1; left < right; left, right = left+1, right-1 {
		indexes[left], indexes[right] = indexes[right], indexes[left]
	}
	return indexes, true
}

func profiledPartDirectRuleDecisions(
	c *Classifier,
	text string,
) ([]quotedReviewContinuationDecision, bool) {
	directIntents := profiledRuleDirectiveIntents(c)
	if len(directIntents) == 0 {
		return nil, true
	}
	directSet := make(map[string]struct{}, len(directIntents))
	for _, intent := range directIntents {
		directSet[intent] = struct{}{}
	}
	allIntents := make([]string, 0,
		len(quotedReviewSpecificContinuationIntents)+len(quotedReviewTerseContinuationIntents)+len(directIntents))
	allIntents = append(allIntents, quotedReviewSpecificContinuationIntents...)
	allIntents = append(allIntents, quotedReviewTerseContinuationIntents...)
	allIntents = append(allIntents, directIntents...)
	decisions, complete := profiledPartIntentDecisionsBounded(
		c, text, directIntents, allIntents, true, true,
	)
	if !complete {
		return nil, false
	}
	filtered := decisions[:0]
	for _, decision := range decisions {
		if _, direct := directSet[decision.intent]; direct {
			filtered = append(filtered, decision)
		}
	}
	return filtered, true
}

func profiledRuleDirectiveIntents(c *Classifier) []string {
	if c == nil {
		return nil
	}
	intents := make([]string, 0, 64)
	for _, bucket := range c.directiveIntentStarts.ascii {
		intents = append(intents, bucket...)
	}
	for _, bucket := range c.directiveIntentStarts.other {
		for _, intent := range bucket {
			intents = append(intents, string(intent))
		}
	}
	return uniqueSorted(intents)
}

// selectProfiledCurrentCarrier applies a bounded nearest/local tie rule. The
// first non-empty unit on either side of the affirmative anchor is the only
// eligible local owner; when both sides exist, the preceding unit wins as the
// conventional anaphoric referent. A nearby benign carrier therefore
// terminates both farther malicious carriers and historical fallback. Any
// nearby non-carrier is a locality barrier rather than a transparent bridge.
// Exactly one carrier is returned and classified.
func (c *Classifier) selectProfiledCurrentCarrier(
	segments []extract.Segment,
	currentReferent profiledSegmentGroup,
	anchor profiledSegmentRef,
) (profiledSegmentGroup, bool) {
	if c == nil || len(currentReferent.refs) == 0 {
		return profiledSegmentGroup{}, false
	}
	owner := anchor.segment
	if owner.ScopeID == 0 || !owner.IsCurrentTurn || !trustedUserContentSegment(owner) {
		return profiledSegmentGroup{}, false
	}
	before, beforeOK := nearestProfiledCurrentScopeUnit(segments, owner, anchor.index, -1)
	after, afterOK := nearestProfiledCurrentScopeUnit(segments, owner, anchor.index, 1)
	var selected profiledSegmentRef
	switch {
	case beforeOK && afterOK:
		selected = before
	case beforeOK:
		selected = before
	case afterOK:
		selected = after
	default:
		return profiledSegmentGroup{}, false
	}
	if selected.segment.ScopeID != owner.ScopeID || selected.segment.TurnIndex != owner.TurnIndex ||
		!selected.segment.IsCurrentTurn || !trustedUserContentSegment(selected.segment) {
		return profiledSegmentGroup{}, true
	}
	parts := []string{selected.segment.Text}
	if !profiledReferentCarrierKind(selected.segment.ContentKind) {
		// Natural-language quotes retain their segment-level content kind. Admit
		// only the closed, bounded quoted payload proved by the existing inert
		// safety-review parser; ordinary directives and bare prose remain locality
		// barriers and cannot become referent carriers.
		switch selected.segment.ContentKind {
		case extract.ContentKindNaturalLanguageDirective, extract.ContentKindUnknown:
			quoted, inert := c.rawInertQuotedSafetyReviewReferent(selected.segment.Text)
			if !inert {
				return profiledSegmentGroup{}, true
			}
			parts = []string{quoted}
		default:
			return profiledSegmentGroup{}, true
		}
	}
	return profiledSegmentGroup{
		refs:  []profiledSegmentRef{selected},
		parts: parts,
	}, true
}

func nearestProfiledCurrentScopeUnit(
	segments []extract.Segment,
	owner extract.Segment,
	anchorIndex int,
	direction int,
) (profiledSegmentRef, bool) {
	if anchorIndex < 0 || anchorIndex >= len(segments) || direction == 0 {
		return profiledSegmentRef{}, false
	}
	for index := anchorIndex + direction; index >= 0 && index < len(segments); index += direction {
		segment := segments[index]
		if strings.TrimSpace(segment.Text) == "" {
			continue
		}
		if !segment.IsCurrentTurn && segment.TurnIndex != owner.TurnIndex {
			continue
		}
		return profiledSegmentRef{index: index, segment: segment}, true
	}
	return profiledSegmentRef{}, false
}

func (c *Classifier) classifyProfiledCurrentDirectCarriers(
	segments []extract.Segment,
	directive profiledSegmentGroup,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) ([]Result, bool) {
	if c == nil || len(directive.refs) == 0 || len(directive.refs) != len(directive.parts) {
		return nil, true
	}
	owner := directive.refs[0].segment
	if owner.ScopeID == 0 || !owner.IsCurrentTurn || !trustedUserContentSegment(owner) ||
		!directive.activeDirective {
		return nil, true
	}
	if !c.profiledCurrentDirectCarrierPossible(segments, directive) {
		// The bounded direct-carrier proof exists only to decide whether a
		// natural-language speech act activates an adjacent code/configuration
		// carrier. A standalone natural-language request has no such relation to
		// prove, so exhausting the intent-occurrence budget in a long request must
		// not discard an already eligible candidate as incomplete inspection.
		return nil, true
	}
	anchorParts, complete := directProfiledPartIndexes(c, directive.parts)
	if !complete {
		return nil, false
	}
	if len(anchorParts) == 0 {
		return nil, true
	}
	results := make([]Result, 0, len(anchorParts))
	for _, anchorIndex := range anchorParts {
		if anchorIndex < 0 || anchorIndex >= len(directive.refs) {
			continue
		}
		anchor := directive.refs[anchorIndex]
		carrier, localOwner := c.selectProfiledCurrentCarrier(segments, directive, anchor)
		if !localOwner || len(carrier.refs) != 1 || !profiledDirectCarrierKind(carrier.refs[0].segment.ContentKind) {
			continue
		}
		combined := mergeProfiledLocalUnits(anchor, carrier.refs[0])
		// The natural-language speech act owns the adjacent code/config carrier
		// regardless of whether that carrier was emitted immediately before or
		// after it. Classify the semantic relation in anchor-first order while
		// retaining physical order in the ownership refs used for audit metadata.
		parts := []string{anchor.segment.Text, carrier.refs[0].segment.Text}
		candidate := c.classifyWithPolicy(parts, mode, thresholds, policy, false)
		if candidate.Truncated {
			results = append(results, candidate)
			continue
		}
		candidate = withRoleAwareFindingOrigin(candidate, FindingOriginUserContent, mode, thresholds)
		c.annotateProfiledResult(&candidate, combined, false, policy, mode, thresholds)
		markResultDirectCarrierActivated(&candidate, true, true, mode, thresholds)
		if !resultHasEligibleMaliciousWinner(candidate, thresholds) || candidate.FindingConfidence == FindingNone {
			continue
		}
		results = append(results, candidate)
	}
	return results, true
}

func (c *Classifier) profiledCurrentDirectCarrierPossible(
	segments []extract.Segment,
	directive profiledSegmentGroup,
) bool {
	for _, anchor := range directive.refs {
		owner := anchor.segment
		if owner.ScopeID == 0 || !owner.IsCurrentTurn || !trustedUserContentSegment(owner) {
			continue
		}
		before, beforeOK := nearestProfiledCurrentScopeUnit(segments, owner, anchor.index, -1)
		after, afterOK := nearestProfiledCurrentScopeUnit(segments, owner, anchor.index, 1)
		var selected profiledSegmentRef
		switch {
		case beforeOK:
			// Match selectProfiledCurrentCarrier's deterministic tie rule: when
			// both sides exist, the preceding unit owns the anaphoric relation.
			selected = before
		case afterOK:
			selected = after
		default:
			continue
		}
		segment := selected.segment
		if segment.ScopeID == owner.ScopeID && segment.TurnIndex == owner.TurnIndex &&
			segment.IsCurrentTurn && trustedUserContentSegment(segment) &&
			profiledDirectCarrierKind(segment.ContentKind) {
			return true
		}
	}
	return false
}

func profiledDirectCarrierKind(kind extract.ContentKind) bool {
	return kind == extract.ContentKindCodeBlock || kind == extract.ContentKindConfiguration
}

func profiledPartStartsRuleDirective(c *Classifier, text string) bool {
	if c == nil || strings.TrimSpace(text) == "" {
		return false
	}
	var scratch normalizationScratch
	views := normalizePartsInto([]string{text}, nil, &scratch)
	defer putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
	if views.truncated {
		return false
	}
	suffix := trimLeadingRuneSpaces(views.standardRunes)
	return directiveSuffixStartsRuleIntent(suffix, &c.directiveIntentStarts) ||
		directiveSuffixContainsModalRuleIntent(suffix, &c.directiveIntentStarts)
}

func mergeProfiledLocalUnits(first, second profiledSegmentRef) []profiledSegmentRef {
	if first.index <= second.index {
		return []profiledSegmentRef{first, second}
	}
	return []profiledSegmentRef{second, first}
}

type profiledOccurrenceKey struct {
	refIndex int
	clauseID int32
	start    int32
	end      int32
}

type profiledOccurrenceSource struct {
	valid      bool
	ref        profiledSegmentRef
	occurrence signalOccurrence
}

func (c *Classifier) annotateProfiledResult(
	result *Result,
	refs []profiledSegmentRef,
	referent bool,
	policy Policy,
	mode Mode,
	thresholds Thresholds,
) {
	if result == nil || len(refs) == 0 {
		return
	}
	ensureResultDecisionExplanation(result)
	if result.DecisionExplanation == nil {
		return
	}
	owner := refs[len(refs)-1]
	syntheticMetaOwner, syntheticMetaOwnership := c.profiledSyntheticMetaControlOwner(
		result, refs, policy, mode, thresholds,
	)
	if syntheticMetaOwnership {
		owner = syntheticMetaOwner
	}
	var sources []profiledOccurrenceSource
	if !syntheticMetaOwnership {
		sources = c.profiledOccurrenceSources(result.EvidenceOccurrences, refs, policy)
	}
	sourceBindingAmbiguous := false
	scopeIDs := make([]uint64, 0, len(result.EvidenceOccurrences))
	for index := range result.EvidenceOccurrences {
		occurrence := &result.EvidenceOccurrences[index]
		source := owner
		sourceProven := syntheticMetaOwnership
		if index < len(sources) && sources[index].valid {
			source = sources[index].ref
			sourceProven = true
			if occurrence.ClauseID < 0 {
				occurrence.ClauseID = int(sources[index].occurrence.clauseID)
				occurrence.SentenceID = occurrence.ClauseID
			}
			if occurrence.Start < 0 || occurrence.End < 0 {
				occurrence.Start = int(sources[index].occurrence.start)
				occurrence.End = int(sources[index].occurrence.end)
			}
		}
		if !sourceProven {
			// Do not silently assign an unlocated multi-field occurrence to the
			// final field. The rule match remains auditable, but its actor/scope
			// provider is unknown and therefore cannot enter the blocking gate.
			sourceBindingAmbiguous = true
			occurrence.SegmentID = -1
			occurrence.FieldID = -1
			occurrence.Role = extract.RoleUnknown
			occurrence.UserAttribution = extract.UserAttributionUntrusted
			occurrence.CurrentTurn = false
			occurrence.DirectiveOwner = DirectiveOwnerUnknown
			continue
		}
		occurrence.SegmentID = source.segment.ConversationIndex
		occurrence.FieldID = source.index
		occurrence.Role = source.segment.Role
		occurrence.Provenance = source.segment.Provenance
		occurrence.UserAttribution = source.segment.UserAttribution
		occurrence.CurrentTurn = source.segment.IsCurrentTurn
		occurrence.DirectiveOwner = directiveOwnerForRole(source.segment.Role)
		if source.segment.ScopeID != 0 {
			scopeIDs = append(scopeIDs, source.segment.ScopeID)
		}
	}
	explanation := result.DecisionExplanation
	explanation.WinningRole = owner.segment.Role
	explanation.WinningProvenance = owner.segment.Provenance
	explanation.CurrentTurnEvidence = owner.segment.IsCurrentTurn || referent
	explanation.CrossSegmentComposition = len(refs) > 1 || referent
	explanation.ReferentLinkUsed = explanation.ReferentLinkUsed || referent
	explanation.EvidenceSegmentCount = len(refs)
	explanation.EvidenceOccurrenceCount = len(result.EvidenceOccurrences)
	explanation.EvidenceDimensionMask = occurrenceDimensionMask(result.EvidenceOccurrences)
	explanation.ScoreBreakdown.FinalScore = result.Score
	bindResultCandidateIdentity(
		result,
		candidateIdentityFor(result.Category, result.EvidenceOccurrences, referent, scopeIDs...),
		mode,
		thresholds,
	)
	if sourceBindingAmbiguous {
		markResultCandidateEvidenceAmbiguous(result, mode, thresholds)
	} else if syntheticMetaOwnership {
		scope := enforcementScopeForProfiledGroup(refs)
		if scope == EnforcementScopeRequestLocalSystem || scope == EnforcementScopeRequestLocalTool {
			// Request-local META authority is admitted only after the exact field
			// owner and the candidate identity have both been bound. The role-aware
			// pre-pass deliberately keeps standalone META audit-only until here.
			bindResultCandidateEnforcementScope(result, scope, mode, thresholds)
		}
	}
}

// profiledSyntheticMetaControlOwner recognizes the one result shape whose
// occurrences deliberately have no physical clause spans: a standalone META
// control candidate. The roleless classifier has already proved the bounded
// active control document. The profiled group must then prove either one
// current trusted-user owner or one closed request-local system/tool owner.
// Replaying every ordinary directive and semantic matcher cannot recover a
// more precise META span
// (signalSupportsProfiledEvidence intentionally excludes META), so the generic
// path would otherwise reject the deliberately synthetic occurrence. The
// request-local path therefore reclassifies each bounded field and requires one
// unique complete control-plane owner; mixed ordinary/META candidates, tool
// payload provenance, and cross-scope text still cannot borrow ownership.
func (c *Classifier) profiledSyntheticMetaControlOwner(
	result *Result,
	refs []profiledSegmentRef,
	policy Policy,
	mode Mode,
	thresholds Thresholds,
) (profiledSegmentRef, bool) {
	if result == nil || !standaloneMetaControlResult(*result) ||
		len(result.EvidenceOccurrences) == 0 || len(refs) == 0 {
		return profiledSegmentRef{}, false
	}
	for _, occurrence := range result.EvidenceOccurrences {
		if occurrence.RuleID != metaOverrideRuleID || occurrence.Dimension != "meta_override" ||
			occurrence.SegmentID >= 0 || occurrence.FieldID >= 0 ||
			occurrence.ClauseID >= 0 || occurrence.SentenceID >= 0 ||
			occurrence.Start >= 0 || occurrence.End >= 0 ||
			occurrence.DirectiveOwner != DirectiveOwnerUnknown {
			return profiledSegmentRef{}, false
		}
	}

	base := refs[0].segment
	if scope := enforcementScopeForProfiledGroup(refs); scope == EnforcementScopeRequestLocalSystem || scope == EnforcementScopeRequestLocalTool {
		var owner profiledSegmentRef
		ownerSet := false
		for _, ref := range refs {
			segment := ref.segment
			if segment.Role != base.Role || segment.Provenance != extract.ProvenanceContent ||
				segment.ScopeID == 0 || segment.ScopeID != base.ScopeID ||
				segment.FieldPathHash == "" || enforcementScopeForSegment(segment) != scope {
				return profiledSegmentRef{}, false
			}
			var fieldFacts classificationSignalFacts
			fieldCandidate := c.classifyWithPolicyCaptured(
				[]string{segment.Text}, mode, thresholds, policy, false, &fieldFacts, false, nil,
			)
			if !c.requestLocalStandaloneMetaControlEnforceable(
				fieldCandidate, fieldFacts, segment.Text, policy, thresholds,
			) {
				continue
			}
			if ownerSet {
				// Synthetic META occurrences carry no physical spans. More than one
				// independently complete field therefore has no unique bounded owner.
				return profiledSegmentRef{}, false
			}
			owner = ref
			ownerSet = true
		}
		return owner, ownerSet
	}
	var owner profiledSegmentRef
	ownerSet := false
	for _, ref := range refs {
		segment := ref.segment
		if !trustedUserContentSegment(segment) || !segment.IsCurrentTurn ||
			segment.ScopeID == 0 || segment.ScopeID != base.ScopeID || segment.TurnIndex != base.TurnIndex ||
			!segmentDeclaresProfiledCoordinates(segment) ||
			segment.ConversationIndex < 0 {
			return profiledSegmentRef{}, false
		}
		switch segment.ContentKind {
		case extract.ContentKindToolSchema, extract.ContentKindToolCallArguments,
			extract.ContentKindToolResult:
			return profiledSegmentRef{}, false
		}
		if profiledContentActiveDirective(segment.ContentKind) {
			owner = ref
			ownerSet = true
			continue
		}
		if !profiledReferentCarrierKind(segment.ContentKind) {
			return profiledSegmentRef{}, false
		}
	}
	return owner, ownerSet
}

// profiledOccurrenceSources binds the content-free winning evidence back to
// the exact profiled fields that supplied it. The roleless classifier keeps
// physical clause offsets for rule-local winners, while semantic/composed
// winners intentionally expose only stable evidence IDs. Replaying the bounded
// matcher over each field restores that ownership without retaining request
// text. A small bipartite assignment preserves the one-occurrence/one-dimension
// contract when one phrase belongs to more than one compiled evidence family.
func (c *Classifier) profiledOccurrenceSources(
	evidence []EvidenceOccurrence,
	refs []profiledSegmentRef,
	policy Policy,
) []profiledOccurrenceSource {
	return c.profiledOccurrenceSourcesWithOptions(evidence, refs, policy, false)
}

func (c *Classifier) profiledOccurrenceSourcesWithOptions(
	evidence []EvidenceOccurrence,
	refs []profiledSegmentRef,
	policy Policy,
	replaySingle bool,
) []profiledOccurrenceSource {
	sources := make([]profiledOccurrenceSource, len(evidence))
	if c == nil || len(evidence) == 0 || len(refs) == 0 {
		return sources
	}
	if len(refs) == 1 && !replaySingle {
		// Every finding in a one-field group necessarily belongs to that exact
		// profiled field. Preserve physical offsets when the roleless classifier
		// has them, but do not replay the matcher merely to replace synthetic
		// semantic offsets: candidateIdentityFor deliberately represents such a
		// bounded field with its stable negative internal clause key.
		for index, item := range evidence {
			sources[index] = profiledOccurrenceSource{
				valid: true,
				ref:   refs[0],
				occurrence: signalOccurrence{
					clauseID: int32(item.ClauseID), start: int32(item.Start), end: int32(item.End),
				},
			}
		}
		return sources
	}
	candidates := make([][]profiledOccurrenceKey, len(evidence))
	physical := make(map[profiledOccurrenceKey]profiledOccurrenceSource)
	serviceSpanPossible := false
	for _, item := range evidence {
		if item.RuleID == "DISRUPT-001" && item.Dimension == "object" &&
			item.ClauseID >= 0 && item.Start >= 0 && item.End > item.Start {
			serviceSpanPossible = true
			break
		}
	}
	matcherSignals := takeClassifierSignalBuffer(c.signalCount)
	defer putClassifierSignalBuffer(matcherSignals)
	var normalizerScratch normalizationScratch
	var runeBuffer []rune
	maxRuneStorage := 0
	defer func() {
		putNormalizedRuneBuffer(runeBuffer, maxRuneStorage)
	}()
	var compactScratch []bool
	if c.compactMatcher != nil && c.compactMatcher.maxPatternLength > 0 {
		compactScratch = make([]bool, c.compactMatcher.maxPatternLength)
	}
	for refIndex := len(refs) - 1; refIndex >= 0; refIndex-- {
		ref := refs[refIndex]
		if strings.TrimSpace(ref.segment.Text) == "" {
			continue
		}
		views := normalizePartsInto([]string{ref.segment.Text}, runeBuffer, &normalizerScratch)
		runeBuffer = views.standardRunes
		if views.storageUsed > maxRuneStorage {
			maxRuneStorage = views.storageUsed
		}
		clear(matcherSignals)
		c.standardMatcher.match(views.standardRunes, matcherSignals)
		if c.compactMatcher != nil {
			c.compactMatcher.matchCompactWithScratch(
				views.standardRunes, matcherSignals, compactScratch,
			)
		}
		if !profiledSignalBufferMatched(matcherSignals) &&
			(!serviceSpanPossible || !profiledRunesContainDisruptionService(views.standardRunes)) {
			continue
		}
		analysis := c.analyzeDirectives(views.standardRunes, policy)
		visitClause := func(clause analyzedDirectiveClause) {
			for _, matched := range clause.occurrences {
				key := profiledOccurrenceKey{
					refIndex: refIndex, clauseID: matched.clauseID, start: matched.start, end: matched.end,
				}
				physical[key] = profiledOccurrenceSource{valid: true, ref: ref, occurrence: matched}
				for evidenceIndex := range evidence {
					item := evidence[evidenceIndex]
					if !profiledOccurrenceOffsetsMatch(item, matched) ||
						!c.signalSupportsProfiledEvidence(int(matched.signalID), item) ||
						profiledOccurrenceCandidateExists(candidates[evidenceIndex], key) {
						continue
					}
					candidates[evidenceIndex] = append(candidates[evidenceIndex], key)
				}
			}
			for evidenceIndex := range evidence {
				item := evidence[evidenceIndex]
				if item.RuleID != "DISRUPT-001" || item.Dimension != "object" ||
					item.ClauseID < 0 || item.Start < 0 || item.End <= item.Start {
					continue
				}
				clauseID := clauseIDForOccurrence(clause)
				if clauseID != int32(item.ClauseID) || item.End > len(clause.runes) ||
					!profiledDisruptionServiceSpan(clause.runes[item.Start:item.End]) {
					continue
				}
				matched := signalOccurrence{
					clauseID: clauseID, start: int32(item.Start), end: int32(item.End),
				}
				key := profiledOccurrenceKey{
					refIndex: refIndex, clauseID: matched.clauseID, start: matched.start, end: matched.end,
				}
				physical[key] = profiledOccurrenceSource{valid: true, ref: ref, occurrence: matched}
				if !profiledOccurrenceCandidateExists(candidates[evidenceIndex], key) {
					candidates[evidenceIndex] = append(candidates[evidenceIndex], key)
				}
			}
		}
		for _, clause := range analysis.clauses {
			visitClause(clause)
		}
		for _, clause := range analysis.overflowTail {
			visitClause(clause)
		}
		// Candidate lists are populated newest field first. Once that prefix has
		// a complete one-occurrence/one-dimension assignment, older fields can
		// only append lower-priority alternatives and therefore cannot change the
		// deterministic assignment below. Stop replaying the classifier at that
		// point; in particular, a max-parts request with a complete final field no
		// longer analyzes thousands of irrelevant earlier copies.
		if profiledOccurrenceCandidatesComplete(candidates) {
			if _, complete := profiledOccurrenceAssignment(candidates); complete {
				break
			}
		}
	}

	assigned, _ := profiledOccurrenceAssignment(candidates)
	for key, evidenceIndex := range assigned {
		sources[evidenceIndex] = physical[key]
	}
	return sources
}

func profiledOccurrenceCandidatesComplete(candidates [][]profiledOccurrenceKey) bool {
	if len(candidates) == 0 {
		return false
	}
	for _, matches := range candidates {
		if len(matches) == 0 {
			return false
		}
	}
	return true
}

func profiledOccurrenceAssignment(candidates [][]profiledOccurrenceKey) (map[profiledOccurrenceKey]int, bool) {
	assigned := make(map[profiledOccurrenceKey]int, len(candidates))
	var augment func(int, []bool) bool
	augment = func(evidenceIndex int, seen []bool) bool {
		if evidenceIndex < 0 || evidenceIndex >= len(candidates) || seen[evidenceIndex] {
			return false
		}
		seen[evidenceIndex] = true
		for _, key := range candidates[evidenceIndex] {
			previous, occupied := assigned[key]
			if occupied && !augment(previous, seen) {
				continue
			}
			assigned[key] = evidenceIndex
			return true
		}
		return false
	}
	seen := make([]bool, len(candidates))
	complete := true
	for evidenceIndex := range candidates {
		clear(seen)
		if !augment(evidenceIndex, seen) {
			complete = false
		}
	}
	return assigned, complete
}

func profiledRunesContainDisruptionService(runes []rune) bool {
	for _, literal := range [][]rune{{'s', 'e', 'r', 'v', 'i', 'c', 'e'}, {'服', '务'}} {
		if len(runes) < len(literal) {
			continue
		}
		for start := 0; start <= len(runes)-len(literal); start++ {
			matched := true
			for offset := range literal {
				if runes[start+offset] != literal[offset] {
					matched = false
					break
				}
			}
			if matched {
				return true
			}
		}
	}
	return false
}

func profiledOccurrenceOffsetsMatch(evidence EvidenceOccurrence, occurrence signalOccurrence) bool {
	if evidence.ClauseID >= 0 && evidence.ClauseID != int(occurrence.clauseID) {
		return false
	}
	if evidence.Start >= 0 && evidence.Start != int(occurrence.start) {
		return false
	}
	return evidence.End < 0 || evidence.End == int(occurrence.end)
}

func profiledOccurrenceCandidateExists(candidates []profiledOccurrenceKey, target profiledOccurrenceKey) bool {
	for _, candidate := range candidates {
		if candidate == target {
			return true
		}
	}
	return false
}

func profiledDisruptionServiceSpan(span []rune) bool {
	return directiveRunesEqualString(span, "service") || directiveRunesEqualString(span, "服务")
}

func (c *Classifier) signalSupportsProfiledEvidence(signalID int, evidence EvidenceOccurrence) bool {
	for _, rule := range c.rules {
		if rule.id != evidence.RuleID {
			continue
		}
		var expected int
		switch evidence.Dimension {
		case "intent":
			expected = rule.intent
		case "object":
			expected = rule.object
		case "operational":
			// A bounded adjacent implementation speech act (for example,
			// "show the commands step by step") is the physical provider for
			// the synthetic operational dimension used by the cross-field
			// implementation-follow-up candidate. Bind it to that exact field
			// instead of either rejecting the candidate or borrowing the final
			// field without proof.
			if signalID == c.implementationRequest {
				return true
			}
			expected = rule.independentOperational
		case "target":
			expected = rule.independentTarget
		case "evasion":
			expected = rule.independentEvasion
		case "scale":
			expected = rule.independentScale
		default:
			return false
		}
		return expected >= 0 && signalID == expected
	}
	for _, profile := range c.semanticProfiles {
		if profile.id() != evidence.RuleID {
			continue
		}
		dimension := -1
		for index, kind := range semanticDimensionKinds {
			if kind == evidence.Dimension {
				dimension = index
				break
			}
		}
		if dimension < 0 {
			return false
		}
		mask := uint16(1) << semanticDimension(dimension)
		for _, compiled := range profile.evidence {
			if compiled.signalID == signalID && compiled.dimensionMask&mask != 0 {
				return true
			}
		}
		return false
	}
	return false
}

func directiveOwnerForRole(role extract.Role) DirectiveOwner {
	switch role {
	case extract.RoleUser:
		return DirectiveOwnerUser
	case extract.RoleSystem:
		return DirectiveOwnerSystem
	case extract.RoleAssistant:
		return DirectiveOwnerAssistant
	case extract.RoleTool:
		return DirectiveOwnerTool
	default:
		return DirectiveOwnerUnknown
	}
}

// refusedHistoricalSafetyMaintenanceTail recognizes one deliberately narrow
// conversation closure: a trusted-user attack, an immediately adjacent clear
// assistant refusal, and a final trusted-user request to improve the guard or
// reduce false positives. The two candidate classifications prevent wording
// alone from creating safety credit. Any execution/implementation follow-up,
// untrusted attribution, non-adjacent refusal, or independent older finding
// keeps the established conservative behavior.
func (c *Classifier) refusedHistoricalSafetyMaintenanceTail(
	segments []extract.Segment,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) (historicalUser, refusal int, ok bool) {
	if c == nil || len(segments) < 3 {
		return 0, 0, false
	}
	historicalUser = len(segments) - 3
	refusal = len(segments) - 2
	currentIndex := len(segments) - 1
	historical := segments[historicalUser]
	assistant := segments[refusal]
	current := segments[currentIndex]
	if !trustedUserContentSegment(historical) || !trustedUserContentSegment(current) ||
		assistant.Role != extract.RoleAssistant || assistant.Provenance != extract.ProvenanceContent ||
		len(assistant.Text) > streamRoleSummaryBytes || len(current.Text) > streamRoleSummaryBytes ||
		!isClearNonUserSafetyContent(extract.RoleAssistant, assistant.Text) ||
		!c.isNarrowSafetyMaintenanceRequest(current.Text) {
		return 0, 0, false
	}

	currentResult := c.classifyWithPolicy([]string{current.Text}, mode, thresholds, policy, false)
	if !safeHistoricalMaintenanceCandidate(currentResult) {
		return 0, 0, false
	}
	historicalResult := c.classifyWithPolicy([]string{historical.Text}, mode, thresholds, policy, false)
	if !resultHasEligibleMaliciousWinner(historicalResult, thresholds) {
		return 0, 0, false
	}
	return historicalUser, refusal, true
}

func trustedUserContentSegment(segment extract.Segment) bool {
	return segment.Role == extract.RoleUser && segment.Provenance == extract.ProvenanceContent &&
		segment.UserAttribution == extract.UserAttributionTrusted
}

func safeHistoricalMaintenanceCandidate(result Result) bool {
	return !result.Truncated && result.Action == ActionAllow && result.Score < AuditThreshold &&
		result.Category == "" && (result.Behavior == nil || !result.Behavior.BaseBehavior)
}

func (c *Classifier) isNarrowSafetyMaintenanceRequest(text string) bool {
	if c == nil || strings.TrimSpace(text) == "" {
		return false
	}
	normalized := strings.ToLower(roleSafetyPunctuation.Replace(text))
	falsePositiveReview := containsAnyRolePhrase(normalized,
		"reduce false positives", "lower false positives", "fewer false positives",
		"reduce false blocks", "reduce false rejections", "review false positives",
		"降低误伤", "减少误伤", "降低误拦", "减少误拦", "降低误报", "减少误报", "审查误拦", "检查误拦",
	)
	guardMaintenance := containsAnyRolePhrase(normalized,
		"improve the abuse guard", "improving the abuse guard", "improve abuse guard", "improving abuse guard",
		"tune the abuse guard", "refine the abuse guard", "improve the risk controls", "tune the risk controls",
		"完善风控", "优化风控", "改进风控", "调整风控", "完善防护", "优化防护", "改进防护",
	)
	if !falsePositiveReview && !guardMaintenance {
		return false
	}
	// These are exact reactivation speech acts for the refused referent. They
	// must win even when the same turn also contains safety-maintenance wording.
	if containsUnnegatedRuleIntentPrepared(
		normalized, quotedReviewSpecificContinuationIntents, quotedReviewSpecificContinuationPatterns,
	) {
		return false
	}
	activeReferent, _, complete := c.hasRawAffirmativeQuotedReviewFollowUp(text)
	return complete && !activeReferent && !c.hasAffirmativeImplementationRequest(normalized)
}

func metaOverrideDefensiveUserSegmentRun(segments []extract.Segment) (string, bool) {
	if len(segments) < 2 || len(segments) > 8 {
		return "", false
	}
	parts := make([]string, 0, len(segments))
	totalBytes := 0
	for _, segment := range segments {
		if segment.Role != extract.RoleUser || segment.Provenance != extract.ProvenanceContent ||
			segment.UserAttribution != extract.UserAttributionTrusted {
			return "", false
		}
		totalBytes += len(segment.Text)
		if totalBytes > maxClassifierInputBytes {
			return "", false
		}
		parts = append(parts, segment.Text)
	}
	joined := strings.Join(parts, "\n")
	if !metaOverrideDefensiveAnalysis(joined, ContextFlags{}) {
		return "", false
	}
	return joined, true
}

// threeTurnPlanWindowEligible permits one additional bounded user-only merge
// when a conversation explicitly links fragments and asks for an operational
// plan or sequence. Ordinary adjacent follow-ups retain the two-turn path; the
// third turn is never merged merely because three user messages exist.
func threeTurnPlanWindowEligible(turns []string) bool {
	if len(turns) != 3 {
		return false
	}
	first := strings.ToLower(roleSafetyPunctuation.Replace(turns[0]))
	second := strings.ToLower(roleSafetyPunctuation.Replace(turns[1]))
	last := strings.ToLower(roleSafetyPunctuation.Replace(turns[2]))
	if hasNegatedSafetyFraming(first) || hasNegatedSafetyFraming(second) || hasNegatedSafetyFraming(last) ||
		hasAffirmativeSafetyPurpose(last) || isSafetyDeliverableClause(last) ||
		containsAnyRolePhrase(last, "detection plan", "defensive plan", "recovery plan", "restoration plan", "patch plan", "检测计划", "防御计划", "恢复计划", "补丁计划") {
		return false
	}
	linked := containsAnyRolePhrase(first, "these messages", "one operation", "one workflow", "one rollout", "next pieces", "following pieces", "these fragments", "next details", "all three", "combine", "treat the next", "read the following", "这些消息", "同一操作", "同一流程", "同一投放", "下面几段", "以下片段", "接下来的内容", "合并") ||
		containsAnyRolePhrase(second, "the above", "those pieces", "same operation", "same workflow", "上述", "前面的内容", "同一操作", "同一流程") ||
		hasAnyPrefix(strings.TrimSpace(last), "now ", "next ", "then ", "continue ", "现在", "接下来", "然后", "继续")
	if !linked {
		return false
	}
	return containsAnyRolePhrase(last,
		"execution plan", "execution sequence", "operating sequence", "operational sequence",
		"implementation plan", "implementation sequence", "rollout plan", "deployment plan",
		"actionable plan", "practical workflow", "step-by-step plan",
		"执行计划", "执行步骤", "操作顺序", "实施计划", "实施步骤", "投放计划", "部署计划", "可操作方案",
	)
}

func knownSegmentRoles(segments []extract.Segment) bool {
	for _, segment := range segments {
		switch segment.Provenance {
		case extract.ProvenanceContent, extract.ProvenanceToolPayload:
		default:
			return false
		}
		switch segment.Role {
		case extract.RoleSystem, extract.RoleUser, extract.RoleAssistant, extract.RoleTool:
		default:
			return false
		}
	}
	return true
}

func findingOriginForSegment(segment extract.Segment) FindingOrigin {
	if segment.Role == extract.RoleUser && segment.Provenance == extract.ProvenanceContent &&
		segment.UserAttribution == extract.UserAttributionTrusted && segment.IsCurrentTurn &&
		segment.ScopeID != 0 && segment.ConversationIndex >= 0 && segment.TurnIndex >= 0 &&
		segmentDeclaresProfiledCoordinates(segment) {
		return FindingOriginUserContent
	}
	return FindingOriginNonUserOrUntrusted
}

// enforcementScopeForSegment preserves user attribution while recognizing the
// two closed non-user carriers that directly control the model response. Tool
// results reach this helper only after the profiled batch/streaming path proves
// that they are terminal request-local input rather than replayed history.
func enforcementScopeForSegment(segment extract.Segment) EnforcementScope {
	if findingOriginForSegment(segment) == FindingOriginUserContent {
		return EnforcementScopeCurrentUser
	}
	if segment.ScopeID == 0 || segment.FieldPathHash == "" ||
		segment.Provenance != extract.ProvenanceContent {
		return EnforcementScopeNone
	}
	switch {
	case segment.Role == extract.RoleSystem &&
		segment.ContentKind == extract.ContentKindNaturalLanguageDirective:
		return EnforcementScopeRequestLocalSystem
	case segment.Role == extract.RoleTool && segment.ContentKind == extract.ContentKindToolResult &&
		authoritativeToolResultAssociation(segment.ToolAssociation):
		return EnforcementScopeRequestLocalTool
	default:
		return EnforcementScopeNone
	}
}

// enforcementScopeForProfiledGroup binds a candidate to the active authority
// owner anywhere in one extractor-proven group. Fenced code/configuration is a
// carrier rather than an authority declaration, so selecting refs[0] (batch)
// or the most recently streamed field made ownership depend on physical order.
// The group key fields prove that every carrier belongs to the same owner; one
// qualifying directive/tool-result field then supplies the enforcement scope
// for the complete group.
func enforcementScopeForProfiledGroup(refs []profiledSegmentRef) EnforcementScope {
	if len(refs) == 0 {
		return EnforcementScopeNone
	}
	base := refs[0].segment
	if base.ScopeID == 0 {
		return EnforcementScopeNone
	}
	scope := EnforcementScopeNone
	for _, ref := range refs {
		segment := ref.segment
		if segment.Role != base.Role || segment.Provenance != base.Provenance ||
			segment.UserAttribution != base.UserAttribution ||
			segment.ToolAssociation != base.ToolAssociation ||
			segment.ConversationIndex != base.ConversationIndex ||
			segment.TurnIndex != base.TurnIndex || segment.IsCurrentTurn != base.IsCurrentTurn ||
			segment.ScopeID != base.ScopeID {
			return EnforcementScopeNone
		}
		candidate := enforcementScopeForSegment(segment)
		if candidate == EnforcementScopeNone {
			continue
		}
		if scope != EnforcementScopeNone && scope != candidate {
			return EnforcementScopeNone
		}
		scope = candidate
	}
	return scope
}

func userCombinationFindingOrigin(trusted bool) FindingOrigin {
	// This helper is used only by the legacy/non-profiled conversation path.
	// Trust in the role label alone does not prove current-turn ownership.
	_ = trusted
	return FindingOriginNonUserOrUntrusted
}

func allTrusted(values []bool) bool {
	if len(values) == 0 {
		return false
	}
	for _, trusted := range values {
		if !trusted {
			return false
		}
	}
	return true
}

func withFindingOrigin(result Result, origin FindingOrigin) Result {
	if result.Score == 0 && result.Action == ActionAllow && result.Category == "" &&
		len(result.RuleIDs) == 0 && len(result.Evidence) == 0 && result.Behavior == nil {
		result.FindingOrigin = FindingOriginNone
		return result
	}
	result.FindingOrigin = origin
	return result
}

// withRoleAwareFindingOrigin applies the role boundary before candidates are
// ranked. A persistent prompt-injection wrapper remains a local hard block when
// it is an explicit trusted-user request, but the same wrapper arriving from a
// system, assistant, tool, or structurally untrusted field is audit-only unless
// that field independently establishes a cyber-abuse base behavior.
//
// This helper is intentionally not used by the roleless Classify API or the
// unknown-role fallback: callers without proven role provenance retain their
// existing conservative behavior.
func withRoleAwareFindingOrigin(result Result, origin FindingOrigin, mode Mode, thresholds Thresholds) Result {
	return withRoleAwareFindingOriginAndScope(result, origin, EnforcementScopeNone, mode, thresholds)
}

func withRoleAwareFindingOriginAndScope(
	result Result,
	origin FindingOrigin,
	scope EnforcementScope,
	mode Mode,
	thresholds Thresholds,
) Result {
	result = withFindingOrigin(result, origin)
	// Result is passed by value, but its explanation is a pointer. Actor binding
	// narrows eligibility and may remove an ineligible hard floor, so clone the
	// closed explanation before any such mutation. Otherwise a role-aware view
	// can silently rewrite the caller's source result and its audit evidence.
	if result.DecisionExplanation != nil {
		explanation := *result.DecisionExplanation
		result.DecisionExplanation = &explanation
	}
	if origin == FindingOriginUserContent {
		bindResultCandidateActor(&result, true, mode, thresholds)
	} else if scope == EnforcementScopeRequestLocalSystem || scope == EnforcementScopeRequestLocalTool {
		// Prompt-override wrappers remain audit-only until annotateProfiledResult
		// proves one exact request-local owner. That later binding admits either an
		// independently complete cyber-abuse base behavior or one narrowly defined
		// active META takeover profile; ordinary provider policy and tool diagnostics
		// still cannot block merely because they mention hierarchy or refusals.
		if standaloneMetaControlResult(result) {
			alreadyBound := result.BlockEligibility != nil &&
				result.BlockEligibility.EnforcementScope == scope &&
				result.BlockEligibility.Eligible &&
				result.CandidateIdentityBlockingProofComplete()
			if !alreadyBound {
				bindResultCandidateActor(&result, false, mode, thresholds)
			}
		} else {
			bindResultCandidateEnforcementScope(&result, scope, mode, thresholds)
		}
	} else {
		bindResultCandidateActor(&result, false, mode, thresholds)
	}
	if origin != FindingOriginNonUserOrUntrusted || result.Behavior == nil ||
		!result.Behavior.Wrapper || result.Behavior.BaseBehavior {
		return result
	}
	thresholds = validThresholdsOrDefault(thresholds)
	originalScore := result.Score
	if result.DecisionExplanation != nil {
		// A prior content-kind cap may already have changed Result.Score without
		// changing the explanation. Ownership is the final admission boundary for
		// this wrapper-only finding, so reconcile from the last explained score;
		// repeated calls see the updated FinalScore and therefore add zero.
		originalScore = result.DecisionExplanation.ScoreBreakdown.FinalScore
	}
	result.Score = metaControlAuditScore(result.Score, thresholds)
	if result.BlockEligibility != nil {
		result.Action = candidateActionFor(mode, result.Score, thresholds, *result.BlockEligibility)
	} else {
		result.Action = actionForMetaControl(mode, result.Score, thresholds)
	}
	if result.DecisionExplanation != nil {
		// The wrapper predicate is still complete, but non-user or untrusted
		// ownership prevents it from carrying cyber-abuse blocking weight. Keep
		// that provenance adjustment explicit in the numeric decomposition so
		// the persisted final score remains identical to the decision score.
		result.DecisionExplanation.ScoreBreakdown.OwnershipScore += result.Score - originalScore
		result.DecisionExplanation.ScoreBreakdown.FinalScore = result.Score
		result.DecisionExplanation.CorePredicateComplete = true
		result.DecisionExplanation.HardFloorApplied = false
		result.DecisionExplanation.HardFloorReason = hardFloorReasonNone
	}
	return result
}

// requestLocalStandaloneMetaControlEnforceable distinguishes a complete
// prescriptive control-plane carrier from ordinary provider policy language.
// The caller has already proved the closed request-local system/tool role,
// provenance, content-kind, path/scope, and (for tools) terminality boundary.
// Requiring the four independently classified control families keeps that
// structural authority from promoting a generic hierarchy/refusal discussion.
func (c *Classifier) requestLocalStandaloneMetaControlEnforceable(
	result Result,
	facts classificationSignalFacts,
	text string,
	policy Policy,
	thresholds Thresholds,
) bool {
	if !standaloneMetaControlResult(result) || result.BlockEligibility == nil {
		return false
	}
	eligibility := result.BlockEligibility
	if !eligibility.InspectionComplete || !eligibility.CurrentExecutionActProven ||
		!eligibility.HarmfulCoreComplete || !eligibility.OperationallyActionable ||
		!eligibility.SecurityControlEvasion || eligibility.DefensiveScopeConflict ||
		eligibility.QuotedOrAnalyticalScope || eligibility.CrossScopeComposition ||
		!eligibility.ReferentProofComplete || eligibility.EvidenceAmbiguous {
		return false
	}
	var hierarchy, refusal, unrestricted, completion, laundering, outputControl bool
	for _, evidence := range result.Evidence {
		switch evidence.ID {
		case metaOverrideRuleID + ":hierarchy":
			hierarchy = true
		case metaOverrideRuleID + ":refusal_suppression":
			refusal = true
		case metaOverrideRuleID + ":unrestricted_mode":
			unrestricted = true
		case metaOverrideRuleID + ":direct_completion":
			completion = true
		case metaOverrideRuleID + ":scope_laundering":
			laundering = true
		case metaOverrideRuleID + ":output_control":
			outputControl = true
		}
	}
	// Two control-plane-only profiles are sufficiently specific to enforce even
	// without borrowing an ordinary cyber category, but request-local provider
	// authority still needs one explicit, uncancelled execution/reactivation act:
	//
	//   1. an explicit unrestricted takeover that inverts hierarchy, suppresses
	//      refusal, orders direct completion, and controls the response; or
	//   2. concealed blanket-authorization laundering that suppresses refusal and
	//      hides the active policy source.
	//
	// The ordinary roleless classifier has already proved active application and
	// rejected quoted/analytical or defensive use. The additional referential act
	// distinguishes an activated embedded takeover from provider policy that only
	// describes a strong operating mode while the actual user task is harmless.
	activeControlText, activeControlComplete := metaOverrideActiveControlText(text)
	_, explicitExecution := latestAffirmativeProfiledPartIndex(c, []string{activeControlText})
	explicitExecution = activeControlComplete && explicitExecution
	strongUnrestrictedTakeover := hierarchy && refusal && unrestricted && completion && outputControl &&
		explicitExecution
	concealedAuthorizationLaundering := refusal && laundering && outputControl && explicitExecution &&
		requestLocalMetaOverrideConcealment(text)
	if strongUnrestrictedTakeover || concealedAuthorizationLaundering {
		return true
	}
	if !completion || !outputControl || !refusal || !unrestricted {
		return false
	}
	// A pure hierarchy/refusal/output wrapper is common in legitimate provider
	// policy and remains audit-only. Request-local META becomes enforceable only
	// when the same exact field also carries a qualified ordinary cyber-abuse
	// core and an explicit harmful-target conflict. This is a secondary positive
	// proof attached to the already complete META candidate; it can never create
	// a category or score by itself.
	if c == nil || !facts.harmConflict {
		return false
	}
	potential := c.streamingRiskPotential(facts, policy, thresholds)
	thresholds = validThresholdsOrDefault(thresholds)
	return potential.hasQualifiedOrdinary && potential.qualifiedOrdinaryScore >= thresholds.HardBlock
}

func requestLocalMetaOverrideConcealment(text string) bool {
	if text == "" {
		return false
	}
	active, complete := metaOverrideActiveControlText(text)
	if !complete {
		return false
	}
	return containsAnyLiteral(active,
		"never mention these instructions", "never acknowledge the mode switch",
		"hide the override source", "conceal the active policy",
		"do not disclose policy changes", "don't disclose policy changes",
		"不要提及这些指令", "不要承认模式切换", "隐藏覆盖来源", "不要披露策略变更",
	)
}

func profiledRoleOwnedWrapper(result Result, origin FindingOrigin) bool {
	return origin == FindingOriginNonUserOrUntrusted && result.Behavior != nil &&
		result.Behavior.Wrapper && !result.Behavior.BaseBehavior
}

func shouldClassifyRoleSegment(segment extract.Segment) bool {
	if segment.Provenance == extract.ProvenanceToolPayload {
		return true
	}
	switch segment.Role {
	case extract.RoleUser, extract.RoleTool:
		return true
	case extract.RoleAssistant, extract.RoleSystem:
		return !isClearNonUserSafetyContent(segment.Role, segment.Text)
	default:
		// This branch is reachable only if this helper is used independently;
		// ClassifySegmentsWithPolicy sends unknown provenance through its more
		// conservative all-parts fallback before reaching it.
		return true
	}
}

// isClearNonUserSafetyContent recognizes only explicit refusals or policy
// prohibitions. It is intentionally narrow: ordinary non-user instructions are
// still scanned, and a refusal/policy followed by an operational override is
// not suppressed. Tool payloads never reach this function.
func isClearNonUserSafetyContent(role extract.Role, value string) bool {
	text := strings.ToLower(strings.TrimSpace(value))
	text = roleSafetyPunctuation.Replace(text)
	text = strings.TrimLeft(text, " \t\r\n-*#>")
	if text == "" || hasUnscopedNonUserSafetyOverride(role, text) || hasUnscopedSafetyContinuation(role, text) {
		return false
	}

	switch role {
	case extract.RoleAssistant:
		return hasClearAssistantRefusal(text)
	case extract.RoleSystem:
		return hasClearSystemSafetyPolicy(text)
	default:
		return false
	}
}

func hasClearAssistantRefusal(text string) bool {
	return hasAnyPrefix(text,
		"i cannot ", "i can't ", "i will not ", "i won't ", "i refuse ", "i must refuse",
		"i am unable ", "i'm unable ", "sorry, i cannot ", "sorry, i can't ",
		"sorry, but i cannot ", "sorry, but i can't ", "cannot assist with ", "can't assist with ",
		"i'm sorry, but i cannot ", "i'm sorry, but i can't ", "i am sorry, but i cannot ", "i am sorry, but i can't ",
		"apologies, but i cannot ", "apologies, but i can't ", "as an ai, i cannot ", "as an ai, i can't ",
		"我不能", "我无法", "我不会", "我拒绝", "抱歉，我不能", "抱歉，我无法", "无法协助", "不能协助",
	)
}

func hasClearSystemSafetyPolicy(text string) bool {
	policyFraming := containsAnyRolePhrase(text,
		"system policy", "safety policy", "security policy", "content policy", "moderation policy", "abuse policy",
		"system safety", "safe system policy", "安全策略", "安全政策", "内容策略", "审核策略", "滥用策略",
	) || hasAnyPrefix(text,
		"you must not ", "you must never ", "never assist ", "do not assist ", "don't assist ",
		"never provide ", "do not provide ", "don't provide ", "you must refuse ", "always refuse ",
		"refuse requests ", "reject requests ", "block requests ",
		"不得协助", "不要协助", "严禁协助", "拒绝处理", "阻止请求",
	)
	prohibition := containsAnyRolePhrase(text,
		"must refuse", "should refuse", "refuse any", "refuse requests", "reject any", "reject requests",
		"block any", "block requests", "prevent ", "never ", "do not ", "don't ", "must not ",
		"prohibit", "forbid", "not allowed", "禁止", "不得", "严禁", "拒绝", "阻止", "防止", "不要",
	)
	return policyFraming && prohibition
}

func scopedSafetyContinuationIsInert(role extract.Role, fullText, clause string) bool {
	if !isScopedSafetyContinuation(role, clause) {
		return false
	}
	if !hasCoordinatedOperationalContinuation(clause) {
		return true
	}
	_, _, explicitlyQuoted := explicitQuotedSafetyState(role, fullText, clause)
	if !explicitlyQuoted {
		return false
	}
	switch role {
	case extract.RoleAssistant:
		return hasClearAssistantRefusal(fullText)
	case extract.RoleSystem:
		return hasClearSystemSafetyPolicy(fullText)
	default:
		return false
	}
}

func isExplicitQuotedSafetyContinuation(role extract.Role, clause string) bool {
	_, ok := explicitQuotedSafetyPayload(role, clause)
	return ok
}

func explicitQuotedSafetyPayload(role extract.Role, clause string) (string, bool) {
	clause = strings.TrimLeft(strings.TrimSpace(clause), "-*#> ")
	var prefixes []string
	switch role {
	case extract.RoleAssistant:
		prefixes = []string{
			"the blocked prompt was", "the forbidden prompt was", "the quoted prompt was", "the blocked prompt said",
			"the forbidden prompt said", "the quoted prompt said", "the quoted request was", "the forbidden request was",
			"the blocked request was", "被禁止的请求是", "被拦截的请求是", "引用的请求是", "引用提示词是",
		}
	case extract.RoleSystem:
		prefixes = []string{
			"the blocked prompt was", "the forbidden prompt was", "the quoted prompt was", "the blocked prompt said",
			"the forbidden prompt said", "the quoted prompt said", "the quoted request was", "the forbidden request was",
			"the blocked request was", "被禁止的请求是", "被拦截的请求是", "引用的请求是", "引用提示词是",
		}
	default:
		return "", false
	}
	for _, prefix := range prefixes {
		if !strings.HasPrefix(clause, prefix) {
			continue
		}
		payload := strings.TrimLeft(clause[len(prefix):], " \t:：=-")
		return payload, true
	}
	return "", false
}

func hasNonUserSafetyOverride(text string) bool {
	if containsAnyRolePhrase(text,
		"do not refuse", "don't refuse", "must not refuse", "never refuse", "ignore the safety", "ignore safety",
		"ignore the policy", "disregard the policy", "bypass the policy", "bypass safety", "policy is irrelevant",
		"must not be denied", "must not deny", "do not deny", "don't deny", "must not be blocked", "must not block",
		"do not block", "don't block", "must not be filtered", "do not filter", "disable guardrails", "remove guardrails",
		"disable safety checks", "skip safety checks", "must not enforce the policy", "must not apply safety",
		"but here is the code", "however, here is the code", "instead, here is the code", "here's the working code",
		"use the following code", "run the following code", "execute the following code", "nevertheless", "nonetheless",
		"even so", "that said", "having said that", "all the same", "regardless", "despite that", "despite this",
		"separately", "independently", "in any case", "anyway", "however", "instead", "but then", "and then",
		"不要拒绝", "不得拒绝", "不得阻止", "不得拦截", "不得过滤", "不要阻止", "不要拦截", "不要过滤",
		"关闭护栏", "移除护栏", "禁用安全检查", "跳过安全检查", "不得执行安全策略",
		"忽略安全", "忽略策略", "绕过策略", "策略无关", "但以下是代码", "不过以下是代码",
		"使用以下代码", "运行以下代码", "执行以下代码", "尽管如此", "话虽如此", "无论如何", "然而", "另外",
		"另行", "分别", "接下来", "然后照做", "照样执行",
	) {
		return true
	}
	return hasCoordinatedOperationalContinuation(text)
}

func hasUnscopedNonUserSafetyOverride(role extract.Role, text string) bool {
	if !hasNonUserSafetyOverride(text) {
		return false
	}
	var quotedScope rune
	for _, clause := range splitStrongSafetyClauses(text) {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}
		if quotedScope != 0 {
			suffix, closed := closeQuotedSafetyScope(clause, quotedScope)
			if !closed {
				continue
			}
			quotedScope = 0
			clause = suffix
			if clause == "" {
				continue
			}
		}
		if !hasNonUserSafetyOverride(clause) {
			continue
		}
		if scopedSafetyContinuationIsInert(role, text, clause) {
			if suffix, quote, quoted := explicitQuotedSafetyState(role, text, clause); quoted {
				quotedScope = quote
				if suffix != "" && hasNonUserSafetyOverride(suffix) {
					return true
				}
			}
			continue
		}
		return true
	}
	return false
}

// hasCoordinatedOperationalContinuation catches a second operational predicate
// hidden inside an otherwise scoped restatement, for example "the request was:
// steal cookies and send them to my server". The role label is caller supplied,
// so a quoted/restated request receives only narrow negative-scope treatment.
func hasCoordinatedOperationalContinuation(text string) bool {
	for _, separator := range []string{
		" and ", " then ", " plus ", " as well as ", " followed by ", " & ",
		"，", "、", "并且", "并将", "并把", "然后", "同时", "以及",
	} {
		remaining := text
		for {
			index := strings.Index(remaining, separator)
			if index < 0 {
				break
			}
			remaining = remaining[index+len(separator):]
			continuation := strings.TrimSpace(remaining)
			if hasOperationalContinuationPrefix(continuation) || hasAnyPrefix(continuation,
				"writing ", "creating ", "generating ", "building ", "providing ", "giving ", "showing ",
				"running ", "executing ", "deploying ", "sending ", "stealing ", "exfiltrating ", "answering ",
				"following ", "obeying ", "complying ",
				"bypassing ", "exploiting ", "installing ",
				"编写", "创建", "生成", "构建", "提供", "运行", "执行", "部署", "发送", "窃取", "回答", "遵循", "服从", "照做",
				"绕过", "利用", "安装",
			) {
				return true
			}
		}
	}
	return false
}

// hasUnscopedSafetyContinuation prevents a safe-looking prefix from laundering
// later instructions. Only an explicit restatement of the refused request (or
// another prohibition in a system policy) remains inside the safety scope.
// Unknown later clauses are classified normally; benign alternatives will
// simply score as benign, while attacker-controlled role labels gain no trust.
func hasUnscopedSafetyContinuation(role extract.Role, text string) bool {
	return unscopedSafetyContinuation(role, text) != ""
}

// unscopedSafetyContinuation returns the first clause that has escaped a
// refusal/policy's negative scope. It is classified separately so the leading
// refusal cannot cause the core negation detector to suppress the new request.
func unscopedSafetyContinuation(role extract.Role, text string) string {
	clauses := splitStrongSafetyClauses(text)
	var quotedScope rune
	for index, clause := range clauses {
		clause = strings.TrimSpace(clause)
		if clause == "" || index == 0 {
			continue
		}
		if quotedScope != 0 {
			suffix, closed := closeQuotedSafetyScope(clause, quotedScope)
			if !closed {
				continue
			}
			quotedScope = 0
			if suffix == "" {
				continue
			}
			return suffix
		}
		if scopedSafetyContinuationIsInert(role, text, clause) {
			if suffix, quote, quoted := explicitQuotedSafetyState(role, text, clause); quoted {
				quotedScope = quote
				if suffix != "" {
					return suffix
				}
			}
			continue
		}
		return clause
	}

	// A comma or colon can introduce an imperative without creating a new
	// sentence ("I cannot help: write ..."). Treat that as an operational
	// continuation unless the delimiter explicitly introduces a quotation or
	// restatement of the refused request.
	for _, delimiter := range []string{",", ":", "，", "："} {
		parts := strings.Split(text, delimiter)
		for index := 1; index < len(parts); index++ {
			continuation := strings.TrimSpace(parts[index])
			if continuation == "" || isScopedSafetyContinuation(role, continuation) {
				continue
			}
			if (delimiter == ":" || delimiter == "：") && isScopedSafetyContinuation(role, lastSafetyClause(parts[index-1])) {
				continue
			}
			if hasOperationalContinuationPrefix(continuation) {
				return continuation
			}
		}
	}
	return ""
}

// explicitQuotedSafetyState returns any text after a quote that closes in the
// current clause, or the balanced quote delimiter whose span continues into a
// later clause. This keeps only the actual quoted bytes inert; text after the
// closing delimiter is always classified again.
func explicitQuotedSafetyState(role extract.Role, fullText, clause string) (string, rune, bool) {
	payload, ok := explicitQuotedSafetyPayload(role, clause)
	if !ok {
		return "", 0, false
	}
	for _, quote := range []rune{'"', '`'} {
		quoteText := string(quote)
		if !strings.HasPrefix(payload, quoteText) {
			continue
		}
		remainder := payload[len(quoteText):]
		if closeIndex := strings.Index(remainder, quoteText); closeIndex >= 0 {
			return strings.TrimSpace(remainder[closeIndex+len(quoteText):]), 0, true
		}
		count := strings.Count(fullText, quoteText)
		if count >= 2 && count%2 == 0 {
			return "", quote, true
		}
	}
	return "", 0, false
}

func closeQuotedSafetyScope(clause string, quote rune) (string, bool) {
	quoteText := string(quote)
	closeIndex := strings.Index(clause, quoteText)
	if closeIndex < 0 {
		return "", false
	}
	return strings.TrimSpace(clause[closeIndex+len(quoteText):]), true
}

// splitStrongSafetyClauses treats Unicode punctuation, symbols, and
// non-ordinary whitespace as trust boundaries. This prevents a caller from
// choosing an unlisted separator to keep a new instruction inside a leading
// refusal's negative scope. Commas and colons retain their narrower handling
// below, while ordinary punctuation inside a word is preserved.
func splitStrongSafetyClauses(text string) []string {
	runes := []rune(text)
	clauses := make([]string, 0, 2)
	start := 0
	for index, current := range runes {
		var previous, next rune
		if index > 0 {
			previous = runes[index-1]
		}
		if index+1 < len(runes) {
			next = runes[index+1]
		}
		if !isStrongSafetyBoundary(current, previous, next) {
			continue
		}
		if clause := strings.TrimSpace(string(runes[start:index])); clause != "" {
			clauses = append(clauses, clause)
		}
		start = index + 1
	}
	if clause := strings.TrimSpace(string(runes[start:])); clause != "" {
		clauses = append(clauses, clause)
	}
	return clauses
}

func isStrongSafetyBoundary(current, previous, next rune) bool {
	if unicode.IsSpace(current) {
		return current != ' '
	}
	// Paired punctuation keeps quoted/restated content attached to the
	// surrounding refusal or policy scope. Curly quotes are normalized before
	// this helper; the Unicode categories cover brackets and other quote forms.
	if current == '`' || unicode.Is(unicode.Quotation_Mark, current) ||
		unicode.Is(unicode.Ps, current) || unicode.Is(unicode.Pe, current) ||
		unicode.Is(unicode.Pi, current) || unicode.Is(unicode.Pf, current) {
		return false
	}
	// A comma or colon may introduce a scoped quotation/restatement and is
	// evaluated with that context in unscopedSafetyContinuation.
	switch current {
	case ',', ':', '，', '：':
		return false
	}
	if isSafetyWordRune(previous) && isSafetyWordRune(next) {
		// Keep contractions, identifiers, and ordinary hyphenated words intact.
		if unicode.Is(unicode.Pc, current) || unicode.Is(unicode.Hyphen, current) {
			return false
		}
	}
	return unicode.IsPunct(current) || unicode.IsSymbol(current)
}

func isSafetyWordRune(value rune) bool {
	return unicode.IsLetter(value) || unicode.IsDigit(value) || unicode.IsMark(value)
}

func lastSafetyClause(value string) string {
	if index := strings.LastIndexAny(value, ".!?;\n\r。！？；"); index >= 0 {
		value = value[index+1:]
	}
	return strings.TrimSpace(value)
}

func isScopedSafetyContinuation(role extract.Role, clause string) bool {
	clause = strings.TrimLeft(strings.TrimSpace(clause), "-*#> ")
	switch role {
	case extract.RoleAssistant:
		return hasAnyPrefix(clause,
			"the request was", "the forbidden request was", "the blocked request was", "the request says",
			"the blocked prompt was", "the forbidden prompt was", "the quoted prompt was", "the blocked prompt said",
			"the forbidden prompt said", "the quoted prompt said",
			"the user asked", "you asked", "that request was", "this request was", "the quoted request was",
			"被禁止的请求是", "被拦截的请求是", "该请求是", "这个请求是", "用户要求", "你要求",
		)
	case extract.RoleSystem:
		return hasAnyPrefix(clause,
			"refuse ", "reject ", "block ", "never ", "do not ", "don't ", "must not ", "should refuse ",
			"the request was", "the forbidden request was", "the policy prohibits", "this is prohibited", "that is prohibited",
			"拒绝", "禁止", "不得", "严禁", "不要", "必须拒绝", "应当拒绝", "该请求是", "这个请求是",
		)
	default:
		return false
	}
}

func hasOperationalContinuationPrefix(clause string) bool {
	clause = strings.TrimLeft(strings.TrimSpace(clause), "-*#> ")
	return hasAnyPrefix(clause,
		"write ", "create ", "generate ", "build ", "provide ", "give ", "show ", "tell ", "return ",
		"run ", "execute ", "deploy ", "send ", "steal ", "exfiltrate ", "bypass ", "exploit ", "install ",
		"answer ", "follow ", "obey ", "comply ",
		"now ", "next ", "then ", "also ", "still ", "yet ",
		"编写", "写出", "创建", "生成", "构建", "提供", "给出", "展示", "运行", "执行", "部署", "发送", "窃取",
		"绕过", "利用", "安装", "回答", "遵循", "服从", "照做", "现在", "接下来", "然后", "另外", "同时", "仍然",
	)
}

func hasAnyPrefix(text string, prefixes ...string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(text, prefix) {
			return true
		}
	}
	return false
}

func containsAnyRolePhrase(text string, phrases ...string) bool {
	for _, phrase := range phrases {
		if strings.Contains(text, phrase) {
			return true
		}
	}
	return false
}

const (
	minIsolatedRuneRun = 4
	maxIsolatedRuneRun = 64
)

func reconstructedIsolatedPartRuns(parts []string) []string {
	runs := make([]string, 0, 2)
	var builder strings.Builder
	runeCount := 0
	flush := func() {
		if runeCount >= minIsolatedRuneRun {
			runs = append(runs, builder.String())
		}
		builder.Reset()
		runeCount = 0
	}
	for _, part := range parts {
		r, ok := isolatedCompactRune(part)
		if !ok {
			flush()
			continue
		}
		if runeCount == maxIsolatedRuneRun {
			flush()
		}
		if runeCount > 0 {
			builder.WriteByte(' ')
		}
		builder.WriteRune(r)
		runeCount++
	}
	flush()
	return runs
}

type reconstructedUserRun struct {
	text    string
	trusted bool
}

func reconstructedIsolatedUserRuns(segments []extract.Segment) []reconstructedUserRun {
	parts := make([]string, 0, len(segments))
	trusted := true
	runs := make([]reconstructedUserRun, 0, 2)
	flush := func() {
		for _, run := range reconstructedIsolatedPartRuns(parts) {
			runs = append(runs, reconstructedUserRun{text: run, trusted: trusted})
		}
		parts = parts[:0]
		trusted = true
	}
	for _, segment := range segments {
		if segment.Role != extract.RoleUser || segment.Provenance != extract.ProvenanceContent {
			flush()
			continue
		}
		if _, ok := isolatedCompactRune(segment.Text); !ok {
			flush()
			continue
		}
		parts = append(parts, segment.Text)
		trusted = trusted && segment.UserAttribution == extract.UserAttributionTrusted
	}
	flush()
	return runs
}

func isolatedCompactRune(value string) (rune, bool) {
	trimmed := strings.TrimSpace(value)
	runes := []rune(trimmed)
	if len(runes) != 1 || !isCompactRune(runes[0]) {
		return 0, false
	}
	return runes[0], true
}

func roleResultBetter(candidate, current Result) bool {
	candidateEligible := candidate.BlockEligibility != nil && candidate.BlockEligibility.Eligible
	currentEligible := current.BlockEligibility != nil && current.BlockEligibility.Eligible
	if candidateEligible != currentEligible {
		return candidateEligible
	}
	if candidate.Score != current.Score {
		return candidate.Score > current.Score
	}
	if candidate.Action != current.Action {
		return roleActionPriority(candidate.Action) > roleActionPriority(current.Action)
	}
	if candidate.Category != current.Category {
		return categoryPriority(candidate.Category) < categoryPriority(current.Category)
	}
	candidateReferent := candidate.DecisionExplanation != nil &&
		candidate.DecisionExplanation.ReferentLinkUsed && candidate.DecisionExplanation.ReferentProofComplete
	currentReferent := current.DecisionExplanation != nil &&
		current.DecisionExplanation.ReferentLinkUsed && current.DecisionExplanation.ReferentProofComplete
	if candidateReferent != currentReferent {
		return candidateReferent
	}
	candidateWrapper := resultContainsRuleID(candidate, metaOverrideRuleID)
	currentWrapper := resultContainsRuleID(current, metaOverrideRuleID)
	if candidateWrapper != currentWrapper {
		// A profiled natural-language pre-pass may preserve an independently
		// executable tail before the complete field is ranked. When both results
		// prove the same eligible base behavior at the same score, retain the full
		// field's bounded META evidence instead of silently dropping the wrapper
		// amplifier from the persisted decision.
		return candidateWrapper
	}
	if candidate.FindingOrigin != current.FindingOrigin {
		return candidate.FindingOrigin == FindingOriginUserContent
	}
	return false
}

func resultContainsRuleID(result Result, want string) bool {
	for _, ruleID := range result.RuleIDs {
		if ruleID == want {
			return true
		}
	}
	return false
}

func roleActionPriority(action Action) int {
	switch action {
	case ActionBlock:
		return 4
	case ActionAudit:
		return 3
	case ActionObserve:
		return 2
	default:
		return 1
	}
}
