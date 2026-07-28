package classifier

import (
	"sort"
	"strings"
	"unicode"

	"github.com/yujianwudi/cyber-abuse-guard/internal/extract"
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
		result = withFindingOrigin(result, FindingOriginNonUserOrUntrusted)
		attachBehaviorGraph(&result, "untrusted_parts", "")
		return result
	}
	segments := make([]extract.Segment, len(parts))
	for index, part := range parts {
		segments[index] = extract.Segment{Role: extract.Role("untrusted"), Text: part}
	}
	result := c.ClassifySegmentsWithPolicy(segments, mode, thresholds, policy)
	for _, reconstructed := range reconstructedIsolatedPartRuns(parts) {
		candidate := withFindingOrigin(
			c.ClassifyWithPolicy([]string{reconstructed}, mode, thresholds, policy),
			FindingOriginNonUserOrUntrusted,
		)
		if roleResultBetter(candidate, result) {
			result = candidate
		}
	}
	attachBehaviorGraph(&result, "untrusted_parts", "")
	return result
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
		best := withFindingOrigin(c.ClassifyWithPolicy(parts, mode, thresholds, policy), FindingOriginNonUserOrUntrusted)
		truncated = truncated || best.Truncated
		for index, segment := range segments {
			candidate := withFindingOrigin(
				c.ClassifyWithPolicy([]string{segment.Text}, mode, thresholds, policy),
				FindingOriginNonUserOrUntrusted,
			)
			truncated = truncated || candidate.Truncated
			if roleResultBetter(candidate, best) {
				best = candidate
			}
			if index > 0 {
				adjacent := withFindingOrigin(
					c.ClassifyWithPolicy([]string{segments[index-1].Text, segment.Text}, mode, thresholds, policy),
					FindingOriginNonUserOrUntrusted,
				)
				truncated = truncated || adjacent.Truncated
				if roleResultBetter(adjacent, best) {
					best = adjacent
				}
			}
		}
		best.Truncated = best.Truncated || truncated
		attachBehaviorGraph(&best, "unknown_role_fallback", "")
		return best
	}
	closedHistoryUser, closedHistoryRefusal, hasClosedHistory :=
		c.refusedHistoricalSafetyMaintenanceTail(segments, mode, thresholds, policy)

	best := c.ClassifyWithPolicy(nil, mode, thresholds, policy)
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
			c.ClassifyWithPolicy([]string{nonUser, user}, mode, thresholds, policy),
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
					c.ClassifyWithPolicy([]string{continuation}, mode, thresholds, policy),
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
				c.ClassifyWithPolicy(linkedMetaUsers, mode, thresholds, policy),
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
				c.ClassifyWithPolicy([]string{previousUser, segment.Text}, mode, thresholds, policy),
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
					c.ClassifyWithPolicy([]string{previousUser + "\n" + segment.Text}, mode, thresholds, policy),
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
				c.ClassifyWithPolicy([]string{strings.Join(recentUsers, "\n")}, mode, thresholds, policy),
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
			c.ClassifyWithPolicy([]string{reconstructed.text}, mode, thresholds, policy),
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
				c.ClassifyWithPolicy([]string{joined}, mode, thresholds, policy),
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
	attachBehaviorGraph(&best, "role_aware", "")
	return best
}

type profiledSegmentRef struct {
	index   int
	segment extract.Segment
}

type profiledSegmentGroup struct {
	refs            []profiledSegmentRef
	parts           []string
	activeDirective bool
	structuredTool  bool
}

type profiledSegmentGroupKey struct {
	role            extract.Role
	provenance      extract.SegmentProvenance
	attribution     extract.UserAttribution
	turnIndex       int
	currentTurn     bool
	scopeID         uint64
	zeroScopeUnique int
}

func hasProfiledSegmentMetadata(segments []extract.Segment) bool {
	for _, segment := range segments {
		if segmentDeclaresProfiledMetadata(segment) {
			return true
		}
	}
	return false
}

func segmentDeclaresProfiledMetadata(segment extract.Segment) bool {
	// Index values cannot signal presence: zero is a valid first conversation
	// item/turn, while -1 is also emitted by the legacy extractor for unknown
	// coordinates. Structural ownership metadata is the opt-in boundary.
	return segment.ContentKind != extract.ContentKindUnknown || segment.ScopeID != 0 ||
		segment.FieldPathHash != "" || segment.IsCurrentTurn
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
	best := c.ClassifyWithPolicy(nil, mode, thresholds, policy)
	truncated := false
	quotedOrInertSuppressed := false
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
			return c.profiledProofUnavailableResult(mode, thresholds, policy)
		}
		if imperative {
			annotationRefs := refs
			referent := false
			suppressed := false
			if owner, localOwner := c.profiledSelfContainedCarrierRunLocalOwner(
				segments, index, end,
			); localOwner {
				if len(refs) == 1 {
					suppressed = c.profiledCarrierLocalOwnerClaimsCarrier(owner.segment)
				} else {
					var reactivated bool
					suppressed, reactivated, complete =
						c.profiledCarrierLocalOwnerRunDisposition(owner.segment)
					if !complete {
						return c.profiledProofUnavailableResult(mode, thresholds, policy)
					}
					if reactivated {
						annotationRefs = mergeProfiledCarrierRunOwner(refs, owner)
						referent = true
					}
				}
			}
			if suppressed {
				index = end
				continue
			}
			candidate := c.classifyWithPolicy(
				parts, mode, thresholds, policy, false,
			)
			if profiledSelfContainedCarrierCandidate(candidate) {
				if len(refs) > 1 {
					profiledCarrierRunClearOccurrenceOffsets(&candidate)
				}
				candidate = withRoleAwareFindingOrigin(
					candidate, FindingOriginUserContent, mode, thresholds,
				)
				c.annotateProfiledResult(&candidate, annotationRefs, referent, policy)
				truncated = truncated || candidate.Truncated
				if roleResultBetter(candidate, best) {
					best = candidate
				}
			}
		}
		index = end
	}
	groups := buildProfiledSegmentGroups(segments, false)
	for _, group := range groups {
		if len(group.parts) == 0 {
			continue
		}
		candidate := c.classifyWithPolicy(group.parts, mode, thresholds, policy, group.structuredTool)
		origin := findingOriginForSegment(group.refs[0].segment)
		roleOwnedWrapper := profiledRoleOwnedWrapper(candidate, origin)
		if !group.activeDirective && !roleOwnedWrapper &&
			candidate.Score >= validThresholdsOrDefault(thresholds).BalancedBlock {
			// Code/configuration without an active natural-language execution
			// relation is reviewable evidence, but is not a balanced block by
			// itself under the Round 8 content-kind contract.
			candidate.Score = validThresholdsOrDefault(thresholds).BalancedBlock - 1
			candidate.Action = actionFor(mode, candidate.Score, thresholds)
			if candidate.DecisionExplanation != nil {
				candidate.DecisionExplanation.CorePredicateComplete = false
				candidate.DecisionExplanation.HardFloorApplied = false
				candidate.DecisionExplanation.HardFloorReason = ""
			}
			markQuotedOrInertSuppressed(&candidate)
			quotedOrInertSuppressed = true
		}
		candidate = withRoleAwareFindingOrigin(
			candidate, origin, mode, thresholds,
		)
		c.annotateProfiledResult(&candidate, group.refs, false, policy)
		if candidate.DecisionExplanation != nil && candidate.DecisionExplanation.QuotedOrInertSuppressed {
			quotedOrInertSuppressed = true
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
			// The direct code/config association proof is bounded. Do not silently
			// discard an earlier split directive when a later field exhausts that
			// proof budget; return the same neutral incomplete-inspection contract
			// as the streaming path so the host can apply its mode-specific policy.
			return c.profiledProofUnavailableResult(mode, thresholds, policy)
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
	currentReferents, referentProofComplete := affirmativeCurrentReferents(c, groups)
	if !referentProofComplete {
		return c.profiledProofUnavailableResult(mode, thresholds, policy)
	}
	for _, currentReferent := range currentReferents {
		anchor := currentReferent.anchor
		if carrier, localOwner := selectProfiledCurrentCarrier(segments, currentReferent.group, anchor); localOwner {
			if len(carrier.refs) != 0 {
				referent := c.classifyWithPolicy(carrier.parts, mode, thresholds, policy, false)
				truncated = truncated || referent.Truncated
				if !referent.Truncated && referent.Action == ActionBlock &&
					referent.FindingConfidence != FindingNone {
					referent = withRoleAwareFindingOrigin(referent, FindingOriginUserContent, mode, thresholds)
					c.annotateProfiledResult(&referent, carrier.refs, false, policy)
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
		} else if referent, historical, ok := c.nearestProfiledHistoricalReferent(segments, mode, thresholds, policy); ok {
			referent = withRoleAwareFindingOrigin(referent, FindingOriginUserContent, mode, thresholds)
			c.annotateProfiledResult(&referent, historical.refs, false, policy)
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

	best.Truncated = best.Truncated || truncated
	ensureResultDecisionExplanation(&best)
	if quotedOrInertSuppressed {
		markQuotedOrInertSuppressed(&best)
	}
	attachBehaviorGraph(&best, "role_aware_profiled", "")
	return best
}

func (c *Classifier) profiledProofUnavailableResult(
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) Result {
	result := c.classifyWithPolicy(nil, mode, thresholds, policy, false)
	result.Coverage = Coverage{
		State: CoverageUnavailable, Reason: CoverageReasonClassifierWindow,
	}
	result.Truncated = true
	result.FindingConfidence = FindingNone
	result.FindingOrigin = FindingOriginNone
	return result
}

func buildProfiledSegmentGroups(segments []extract.Segment, historicalTrustedUsers bool) []profiledSegmentGroup {
	groups := make([]profiledSegmentGroup, 0, len(segments))
	indexes := make(map[profiledSegmentGroupKey]int, len(segments))
	activeTurnIndex := -1
	for _, segment := range segments {
		if segment.IsCurrentTurn && segment.TurnIndex > activeTurnIndex {
			activeTurnIndex = segment.TurnIndex
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
		} else if !profiledSegmentClassifiable(segment, activeTurnIndex) {
			continue
		}
		effectiveCurrent := profiledEffectiveCurrentTurn(segment, activeTurnIndex)
		segment.IsCurrentTurn = effectiveCurrent
		key := profiledSegmentGroupKey{
			role: segment.Role, provenance: segment.Provenance, attribution: segment.UserAttribution,
			turnIndex: segment.TurnIndex, currentTurn: effectiveCurrent, scopeID: segment.ScopeID,
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
		group.activeDirective = group.activeDirective || profiledContentActiveDirective(segment.ContentKind)
		group.structuredTool = group.structuredTool || segment.Provenance == extract.ProvenanceToolPayload ||
			segment.ContentKind == extract.ContentKindToolCallArguments
	}
	return groups
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
			turnIndex: segment.TurnIndex, currentTurn: false, scopeID: segment.ScopeID,
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
	if segment.IsCurrentTurn || segment.Provenance == extract.ProvenanceToolPayload ||
		!segmentDeclaresProfiledCoordinates(segment) {
		return false
	}
	switch segment.ContentKind {
	case extract.ContentKindToolSchema, extract.ContentKindToolCallArguments:
		return false
	case extract.ContentKindToolResult:
		return segment.Role == extract.RoleTool || segment.Role == extract.RoleUnknown
	case extract.ContentKindCodeBlock, extract.ContentKindQuotedText,
		extract.ContentKindLogOutput, extract.ContentKindConfiguration,
		extract.ContentKindDocumentation, extract.ContentKindSecurityAnalysis:
		return profiledHistoricalEvidenceCarrier(segment)
	case extract.ContentKindNaturalLanguageDirective, extract.ContentKindUnknown:
		if trustedUserContentSegment(segment) {
			return true
		}
		return segment.Role == extract.RoleAssistant
	default:
		return false
	}
}

// profiledHistoricalEvidenceCarrier identifies inert historical material that
// a later explicit user speech act may reactivate. The material remains inert
// on its own; admitting it here both lets "Execute it" bind to the nearest
// quoted/code/log/configuration scope and prevents that bare referent from
// jumping across a newer benign scope to an unrelated older attack. Role is
// not an allow boundary: inert system material can also become active through
// an explicit trusted-user referent. Tool-schema declarations remain isolated.
func profiledHistoricalEvidenceCarrier(segment extract.Segment) bool {
	switch segment.Role {
	case extract.RoleUser:
		return segment.UserAttribution == extract.UserAttributionTrusted
	case extract.RoleSystem, extract.RoleAssistant, extract.RoleTool, extract.RoleUnknown:
		return true
	default:
		return false
	}
}

func (c *Classifier) nearestProfiledHistoricalReferent(
	segments []extract.Segment,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) (Result, profiledSegmentGroup, bool) {
	groups := buildProfiledHistoricalReferentGroups(segments)
	for index := len(groups) - 1; index >= 0; index-- {
		group := groups[index]
		if len(group.parts) == 0 || len(group.refs) == 0 {
			continue
		}
		owner := group.refs[len(group.refs)-1].segment
		if owner.Role == extract.RoleAssistant &&
			isClearNonUserSafetyContent(owner.Role, strings.Join(group.parts, "\n")) {
			continue
		}
		candidate := c.classifyWithPolicy(group.parts, mode, thresholds, policy, false)
		if candidate.Action != ActionBlock {
			// A defensive user review deliberately suppresses the quoted behavior in
			// its own turn. Keep the closed quotation as the historical referent so
			// an explicit later "Execute it" can reactivate that behavior without
			// treating the surrounding safety analysis as active evidence.
			if quoted, inert := c.rawInertQuotedSafetyReviewReferent(strings.Join(group.parts, "\n")); inert {
				candidate = c.classifyWithPolicy([]string{quoted}, mode, thresholds, policy, false)
			}
		}
		if candidate.Truncated || candidate.Action != ActionBlock ||
			candidate.FindingConfidence == FindingNone {
			// The nearest eligible scope owns a bare referent even when it is
			// benign. Do not skip it and bind "Execute it" to an older attack.
			return Result{}, profiledSegmentGroup{}, false
		}
		return candidate, group, true
	}
	return Result{}, profiledSegmentGroup{}, false
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
			return segment.IsCurrentTurn
		}
		// Model-visible text under an unknown/future field remains independently
		// inspectable, but its untrusted attribution prevents subject-state
		// accumulation. Scope IDs still prohibit it from donating dimensions to a
		// separate trusted user field.
		return segment.IsCurrentTurn || segment.TurnIndex < 0
	case extract.RoleSystem:
		return true
	case extract.RoleAssistant:
		return false
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

func profiledSelfContainedCarrierCandidate(result Result) bool {
	if result.Truncated || result.Action != ActionBlock || result.Category == "" ||
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
	return profiledPartIntentDecisions(c, text, c.implementationStarts, allIntents)
}

func profiledPartIntentDecisions(
	c *Classifier,
	text string,
	explicitIntents []string,
	allIntents []string,
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
		decisions, complete := profiledPartIntentDecisions(c, parts[index], directIntents, allIntents)
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
	decisions, complete := profiledPartIntentDecisions(c, text, directIntents, allIntents)
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
func selectProfiledCurrentCarrier(
	segments []extract.Segment,
	currentReferent profiledSegmentGroup,
	anchor profiledSegmentRef,
) (profiledSegmentGroup, bool) {
	if len(currentReferent.refs) == 0 {
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
		!selected.segment.IsCurrentTurn || !trustedUserContentSegment(selected.segment) ||
		!profiledReferentCarrierKind(selected.segment.ContentKind) {
		return profiledSegmentGroup{}, true
	}
	return profiledSegmentGroup{
		refs:  []profiledSegmentRef{selected},
		parts: []string{selected.segment.Text},
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
		carrier, localOwner := selectProfiledCurrentCarrier(segments, directive, anchor)
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
		if candidate.Action != ActionBlock || candidate.FindingConfidence == FindingNone {
			continue
		}
		candidate = withRoleAwareFindingOrigin(candidate, FindingOriginUserContent, mode, thresholds)
		c.annotateProfiledResult(&candidate, combined, false, policy)
		results = append(results, candidate)
	}
	return results, true
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

func (c *Classifier) annotateProfiledResult(result *Result, refs []profiledSegmentRef, referent bool, policy Policy) {
	if result == nil || len(refs) == 0 {
		return
	}
	ensureResultDecisionExplanation(result)
	if result.DecisionExplanation == nil {
		return
	}
	owner := refs[len(refs)-1]
	sources := c.profiledOccurrenceSources(result.EvidenceOccurrences, refs, policy)
	for index := range result.EvidenceOccurrences {
		occurrence := &result.EvidenceOccurrences[index]
		source := owner
		if index < len(sources) && sources[index].valid {
			source = sources[index].ref
			if occurrence.ClauseID < 0 {
				occurrence.ClauseID = int(sources[index].occurrence.clauseID)
				occurrence.SentenceID = occurrence.ClauseID
			}
			if occurrence.Start < 0 || occurrence.End < 0 {
				occurrence.Start = int(sources[index].occurrence.start)
				occurrence.End = int(sources[index].occurrence.end)
			}
		}
		occurrence.SegmentID = source.segment.ConversationIndex
		occurrence.FieldID = source.index
		occurrence.Role = source.segment.Role
		occurrence.Provenance = source.segment.Provenance
		occurrence.UserAttribution = source.segment.UserAttribution
		occurrence.CurrentTurn = source.segment.IsCurrentTurn
		occurrence.DirectiveOwner = directiveOwnerForRole(source.segment.Role)
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
	sources := make([]profiledOccurrenceSource, len(evidence))
	if c == nil || len(evidence) == 0 || len(refs) == 0 {
		return sources
	}
	candidates := make([][]profiledOccurrenceKey, len(evidence))
	physical := make(map[profiledOccurrenceKey]profiledOccurrenceSource)
	for refIndex := len(refs) - 1; refIndex >= 0; refIndex-- {
		ref := refs[refIndex]
		if strings.TrimSpace(ref.segment.Text) == "" {
			continue
		}
		var scratch normalizationScratch
		views := normalizePartsInto([]string{ref.segment.Text}, takeNormalizedRuneBuffer(), &scratch)
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
		putNormalizedRuneBuffer(views.standardRunes, views.storageUsed)
	}

	assigned := make(map[profiledOccurrenceKey]int)
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
	for evidenceIndex := range evidence {
		augment(evidenceIndex, make([]bool, len(evidence)))
	}
	for key, evidenceIndex := range assigned {
		sources[evidenceIndex] = physical[key]
	}
	return sources
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
	if historicalResult.Truncated || historicalResult.Action != ActionBlock {
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
		segment.UserAttribution == extract.UserAttributionTrusted {
		return FindingOriginUserContent
	}
	return FindingOriginNonUserOrUntrusted
}

func userCombinationFindingOrigin(trusted bool) FindingOrigin {
	if trusted {
		return FindingOriginUserContent
	}
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
	result = withFindingOrigin(result, origin)
	if origin != FindingOriginNonUserOrUntrusted || result.Behavior == nil ||
		!result.Behavior.Wrapper || result.Behavior.BaseBehavior {
		return result
	}
	thresholds = validThresholdsOrDefault(thresholds)
	if result.DecisionExplanation != nil {
		explanation := *result.DecisionExplanation
		result.DecisionExplanation = &explanation
	}
	originalScore := result.Score
	if result.DecisionExplanation != nil {
		// A prior content-kind cap may already have changed Result.Score without
		// changing the explanation. Ownership is the final admission boundary for
		// this wrapper-only finding, so reconcile from the last explained score;
		// repeated calls see the updated FinalScore and therefore add zero.
		originalScore = result.DecisionExplanation.ScoreBreakdown.FinalScore
	}
	result.Score = metaControlAuditScore(result.Score, thresholds)
	result.Action = actionForMetaControl(mode, result.Score, thresholds)
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
	if candidate.Score != current.Score {
		return candidate.Score > current.Score
	}
	if candidate.Action != current.Action {
		return roleActionPriority(candidate.Action) > roleActionPriority(current.Action)
	}
	if candidate.Category != current.Category {
		return categoryPriority(candidate.Category) < categoryPriority(current.Category)
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
