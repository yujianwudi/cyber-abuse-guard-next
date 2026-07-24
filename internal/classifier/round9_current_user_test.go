package classifier

import "github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"

const round9TestCurrentUserScopeID uint64 = 90_001

// round9CurrentUserSegments makes the actor assumption explicit in tests that
// exercise malicious blocking rather than role/provenance admission. The
// production roleless API is intentionally untrusted and must remain audit-only.
func round9CurrentUserSegments(parts []string) []extract.Segment {
	segments := make([]extract.Segment, len(parts))
	for index, part := range parts {
		segments[index] = extract.Segment{
			Role:              extract.RoleUser,
			Provenance:        extract.ProvenanceContent,
			UserAttribution:   extract.UserAttributionTrusted,
			ConversationIndex: 0,
			TurnIndex:         0,
			IsCurrentTurn:     true,
			ScopeID:           round9TestCurrentUserScopeID,
			ContentKind:       extract.ContentKindNaturalLanguageDirective,
			FieldPathHash:     "round9-test-current-user",
			Text:              part,
		}
	}
	return segments
}

func round9AnalyzeCurrentUser(c *Classifier, parts []string) Result {
	return round9ClassifyCurrentUserWithPolicy(
		c, parts, ModeBalanced, DefaultThresholds(), DefaultPolicy(),
	)
}

func round9ClassifyCurrentUser(c *Classifier, parts []string, mode Mode, thresholds Thresholds) Result {
	return round9ClassifyCurrentUserWithPolicy(c, parts, mode, thresholds, DefaultPolicy())
}

func round9ClassifyCurrentUserWithPolicy(
	c *Classifier,
	parts []string,
	mode Mode,
	thresholds Thresholds,
	policy Policy,
) Result {
	return c.ClassifySegmentsWithPolicy(
		round9CurrentUserSegments(parts), mode, thresholds, policy,
	)
}
