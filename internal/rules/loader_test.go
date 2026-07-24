package rules

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestLoadDefaultValidatesVersionedBilingualUniqueRules(t *testing.T) {
	t.Parallel()

	set, err := LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault() error = %v", err)
	}
	if set.Version == "" {
		t.Fatal("ruleset version is empty")
	}
	if len(set.Rules) < 14 {
		t.Fatalf("got %d rules, want at least 14", len(set.Rules))
	}

	wantCategories := map[Category]bool{
		CategoryCredentialTheft: false,
		CategoryPhishing:        false,
		CategoryMalware:         false,
		CategoryRansomware:      false,
		CategoryExploitation:    false,
		CategoryDisruption:      false,
		CategoryExfiltration:    false,
		CategoryEvasion:         false,
	}
	ids := make(map[string]struct{}, len(set.Rules))
	for _, rule := range set.Rules {
		if _, exists := ids[rule.ID]; exists {
			t.Errorf("duplicate rule ID %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		if _, exists := wantCategories[rule.Category]; !exists {
			t.Errorf("unexpected category %q", rule.Category)
		} else {
			wantCategories[rule.Category] = true
		}
		if len(rule.Intent.ZH) == 0 || len(rule.Intent.EN) == 0 {
			t.Errorf("rule %s lacks bilingual intent terms", rule.ID)
		}
		if len(rule.Object.ZH) == 0 || len(rule.Object.EN) == 0 {
			t.Errorf("rule %s lacks bilingual object terms", rule.ID)
		}
	}
	for category, found := range wantCategories {
		if !found {
			t.Errorf("default rules lack category %q", category)
		}
	}

	wantContexts := []ContextKind{
		ContextDefensive,
		ContextRemediation,
		ContextCTF,
		ContextLab,
		ContextAuthorized,
		ContextStaticAnalysis,
		ContextIncidentResponse,
		ContextHighLevel,
	}
	for _, kind := range wantContexts {
		terms, ok := set.Contexts[kind]
		if !ok {
			t.Errorf("default rules lack context %q", kind)
			continue
		}
		if len(terms.ZH) == 0 || len(terms.EN) == 0 {
			t.Errorf("context %q is not bilingual", kind)
		}
	}
}

func TestDefaultRulesDoNotReuseLiteralAcrossEvidenceGroups(t *testing.T) {
	t.Parallel()
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	for _, rule := range set.Rules {
		groups := map[string]Terms{
			"intent": rule.Intent, "object": rule.Object, "operational": rule.Operational,
			"target": rule.Target, "evasion": rule.Evasion, "scale": rule.Scale,
		}
		owners := make(map[string]string)
		for group, terms := range groups {
			for _, term := range append(append([]string(nil), terms.ZH...), terms.EN...) {
				key := strings.ToLower(strings.TrimSpace(term))
				if previous, exists := owners[key]; exists && previous != group {
					t.Errorf("rule %s reuses literal %q in %s and %s", rule.ID, term, previous, group)
				}
				owners[key] = group
			}
		}
	}
}

func TestRuleSetValidateRejectsDuplicateID(t *testing.T) {
	t.Parallel()
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	set.Rules[1].ID = set.Rules[0].ID
	if err := set.Validate(); err == nil || !strings.Contains(err.Error(), "duplicate rule ID") {
		t.Fatalf("Validate() duplicate error = %v", err)
	}
}

func TestRuleSetValidateRejectsSingleEvidenceRule(t *testing.T) {
	t.Parallel()

	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	set.Rules[0].Object = Terms{}
	if err := set.Validate(); err == nil || !strings.Contains(err.Error(), "object") {
		t.Fatalf("Validate() missing-object error = %v", err)
	}
}

func TestRuleSetValidateRejectsNormalizedCrossGroupReuse(t *testing.T) {
	t.Parallel()
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	set.Rules[0].Object.EN[0] = "ＳＴＥＡＬ"
	if err := set.Validate(); err == nil || !strings.Contains(err.Error(), "reuses normalized literal") {
		t.Fatalf("Validate() normalized-reuse error = %v", err)
	}
}

func TestRuleSetValidateRejectsLeetCrossGroupReuse(t *testing.T) {
	t.Parallel()
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	set.Rules[0].Intent.EN[0] = "st3al"
	set.Rules[0].Object.EN[0] = "steal"
	if err := set.Validate(); err == nil || !strings.Contains(err.Error(), "reuses normalized literal") {
		t.Fatalf("Validate() leet-reuse error = %v", err)
	}
}

func TestRuleSetValidateRejectsCompatibilityCaseCrossGroupReuse(t *testing.T) {
	t.Parallel()
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	set.Rules[0].Intent.EN[0] = "𝐒𝐓𝐄𝐀𝐋"
	set.Rules[0].Object.EN[0] = "steal"
	if err := set.Validate(); err == nil || !strings.Contains(err.Error(), "reuses normalized literal") {
		t.Fatalf("Validate() compatibility-case error = %v", err)
	}
}

func TestRuleSetValidateRejectsHomoglyphCrossGroupReuse(t *testing.T) {
	t.Parallel()
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	set.Rules[0].Intent.EN[0] = "steal"
	set.Rules[0].Object.EN[0] = "stеal" // Cyrillic ie in an otherwise-Latin token.
	if err := set.Validate(); err == nil || !strings.Contains(err.Error(), "reuses normalized literal") {
		t.Fatalf("Validate() homoglyph-reuse error = %v", err)
	}
}

func TestRuleSetValidateRejectsCrossGroupPhraseOverlap(t *testing.T) {
	t.Parallel()
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	set.Rules[0].Intent.EN[0] = "denial-of-service"
	set.Rules[0].Object.EN[0] = "distributed denial-of-service"
	if err := set.Validate(); err == nil || !strings.Contains(err.Error(), "overlaps normalized literal") {
		t.Fatalf("Validate() phrase-overlap error = %v", err)
	}
}

func TestRuleSetValidateRejectsLiteralNormalizingToEmptyEvidence(t *testing.T) {
	t.Parallel()
	set, err := LoadDefault()
	if err != nil {
		t.Fatal(err)
	}
	set.Rules[0].Intent.EN[0] = "\u200b"
	if err := set.Validate(); err == nil || !strings.Contains(err.Error(), "normalizes to empty evidence") {
		t.Fatalf("Validate() empty-normalized-literal error = %v", err)
	}
}

func TestLoadFSRejectsUnknownRegexField(t *testing.T) {
	t.Parallel()

	assets := fstest.MapFS{
		"manifest.yaml": &fstest.MapFile{Data: []byte("version: test-v1\ncontext_file: contexts.yaml\nrule_files: [rules.yaml]\nregex: '(a+)+$'\n")},
	}
	if _, err := LoadFS(assets); err == nil {
		t.Fatal("LoadFS() accepted an unsupported regex field")
	}
}

func TestLoadFSRejectsUnsafeManifestPaths(t *testing.T) {
	t.Parallel()
	for _, name := range []string{`..\evil.yaml`, `dir\evil.yaml`, `dir/evil.yaml`, `/evil.yaml`, `C:\evil.yaml`} {
		name := name
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := LoadFS(fstest.MapFS{}, name); err == nil || !strings.Contains(err.Error(), "unsafe asset name") {
				t.Fatalf("LoadFS(%q) error = %v, want unsafe asset name", name, err)
			}
		})
	}
}
