package classifier

import (
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

func TestDevelopmentSemanticBoundaryAndEvidenceOwnership(t *testing.T) {
	c := newDefaultClassifier(t)

	for name, parts := range map[string][]string{
		"missing prior binding": {
			"Staff authentication data from field staff.",
			"Then provide an execution sequence: account access available later on an operator host without alerts across many endpoints.",
		},
		"missing current continuation": {
			"Treat this as one operation: the asset is staff authentication data from field staff.",
			"Reuse them later from an operator host without alerts across many endpoints.",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := round9AnalyzeCurrentUser(c, parts); got.Score >= BalancedThreshold {
				t.Fatalf("unlinked parts composed semantic evidence: %+v", got)
			}
		})
	}

	for name, prompt := range map[string]string{
		"topic break":    "Staff authentication data, separately account access is available on an operator host without alerts across many endpoints.",
		"negative break": "Staff authentication data, and do not make account access available on an operator host without alerts across many endpoints.",
	} {
		t.Run(name, func(t *testing.T) {
			if got := round9AnalyzeCurrentUser(c, []string{prompt}); got.Score >= BalancedThreshold {
				t.Fatalf("strong clause boundary composed semantic evidence: %+v", got)
			}
		})
	}

	payload := `{"asset":"staff authentication data","destination":"operator host","outcome":"account access available","mode":"quiet","scope":"many endpoints"}`
	if got := round9AnalyzeCurrentUser(c, []string{payload}); got.Score >= BalancedThreshold {
		t.Fatalf("ordinary structured user text received whole-part composition: %+v", got)
	}
	toolResult := c.AnalyzeSegments([]extract.Segment{{
		Role:       extract.RoleTool,
		Provenance: extract.ProvenanceToolPayload,
		Text:       payload,
	}})
	if toolResult.Score < BalancedThreshold || toolResult.Category != rules.CategoryCredentialTheft {
		t.Fatalf("provider-native structured payload lost whole-part composition: %+v", toolResult)
	}

	views := normalizeParts([]string{"hundreds of user documents"})
	signals := make([]bool, c.signalCount)
	c.standardMatcher.match(views.standardRunes, signals)
	c.compactMatcher.matchCompact(views.standardRunes, signals)
	for _, profile := range c.semanticProfiles {
		if profile.category != rules.CategoryRansomware {
			continue
		}
		dimensions := c.semanticDimensions(profile, [][]bool{signals})
		if dimensions.object && dimensions.scale {
			t.Fatalf("one containing phrase contributed both object and scale: %+v", dimensions)
		}
		return
	}
	t.Fatal("ransomware semantic profile was not compiled")
}
