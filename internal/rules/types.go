// Package rules loads and validates the local, versioned abuse-classification
// policy. It deliberately models literal evidence groups rather than regexes.
package rules

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

const (
	maxRuleCount    = 512
	maxTermsPerLang = 256
)

// Category is a stable, coarse abuse category suitable for audit events and
// client-facing refusal messages.
type Category string

const (
	CategoryCredentialTheft Category = "credential_theft"
	CategoryPhishing        Category = "phishing_deployment"
	CategoryMalware         Category = "malware_deployment"
	CategoryRansomware      Category = "ransomware_deployment"
	CategoryExploitation    Category = "unauthorized_exploitation"
	CategoryDisruption      Category = "service_disruption"
	CategoryExfiltration    Category = "data_exfiltration"
	CategoryEvasion         Category = "defense_evasion"
)

var validCategories = map[Category]struct{}{
	CategoryCredentialTheft: {},
	CategoryPhishing:        {},
	CategoryMalware:         {},
	CategoryRansomware:      {},
	CategoryExploitation:    {},
	CategoryDisruption:      {},
	CategoryExfiltration:    {},
	CategoryEvasion:         {},
}

// ContextKind identifies a context signal. These are reported as aggregate
// booleans; the prompt phrase that caused a match is never returned.
type ContextKind string

const (
	ContextDefensive        ContextKind = "defensive"
	ContextRemediation      ContextKind = "remediation"
	ContextCTF              ContextKind = "ctf"
	ContextLab              ContextKind = "lab"
	ContextAuthorized       ContextKind = "authorized"
	ContextStaticAnalysis   ContextKind = "static_analysis"
	ContextIncidentResponse ContextKind = "incident_response"
	ContextHighLevel        ContextKind = "high_level"
)

var validContextKinds = map[ContextKind]struct{}{
	ContextDefensive:        {},
	ContextRemediation:      {},
	ContextCTF:              {},
	ContextLab:              {},
	ContextAuthorized:       {},
	ContextStaticAnalysis:   {},
	ContextIncidentResponse: {},
	ContextHighLevel:        {},
}

// Terms contains equivalent Chinese and English literal phrases.
type Terms struct {
	ZH []string `yaml:"zh" json:"zh"`
	EN []string `yaml:"en" json:"en"`
}

// LocalizedTerms is a descriptive alias retained for callers that prefer the
// longer name.
type LocalizedTerms = Terms

// Rule requires independent intent and object evidence. Qualifier groups refine
// confidence and are mandatory in the schema; a narrowly scoped, high-confidence
// intent/object pair may itself cross the balanced threshold.
type Rule struct {
	ID                     string   `yaml:"id" json:"id"`
	Category               Category `yaml:"category" json:"category"`
	Severity               string   `yaml:"severity" json:"severity"`
	BaseScore              int      `yaml:"base_score" json:"base_score"`
	HardFloor              int      `yaml:"hard_floor" json:"hard_floor"`
	AuthorizationProtected bool     `yaml:"authorization_protected" json:"authorization_protected"`
	Intent                 Terms    `yaml:"intent" json:"intent"`
	Object                 Terms    `yaml:"object" json:"object"`
	Operational            Terms    `yaml:"operational" json:"operational"`
	Target                 Terms    `yaml:"target" json:"target"`
	Evasion                Terms    `yaml:"evasion" json:"evasion"`
	Scale                  Terms    `yaml:"scale" json:"scale"`
}

// SemanticProfile defines a category-level evidence ontology. Unlike a rule,
// no single dimension is independently actionable: the classifier must
// compose several dimensions inside a bounded, related text window.
type SemanticProfile struct {
	Category    Category `yaml:"category" json:"category"`
	Harm        Terms    `yaml:"harm" json:"harm"`
	Object      Terms    `yaml:"object" json:"object"`
	Action      Terms    `yaml:"action" json:"action"`
	Outcome     Terms    `yaml:"outcome" json:"outcome"`
	Target      Terms    `yaml:"target" json:"target"`
	Destination Terms    `yaml:"destination" json:"destination"`
	Evasion     Terms    `yaml:"evasion" json:"evasion"`
	Scale       Terms    `yaml:"scale" json:"scale"`
	Sequence    Terms    `yaml:"sequence" json:"sequence"`
	Impact      Terms    `yaml:"impact" json:"impact"`
}

// RuleSet is a fully validated rules snapshot. Classifier.New compiles a
// private copy, so subsequent caller mutation cannot affect a live classifier.
type RuleSet struct {
	Version   string                       `json:"version"`
	Rules     []Rule                       `json:"rules"`
	Contexts  map[ContextKind]Terms        `json:"contexts"`
	Semantics map[Category]SemanticProfile `json:"semantics,omitempty"`
}

// Validate rejects ambiguous or incomplete rule snapshots before activation.
func (s *RuleSet) Validate() error {
	return Validate(s)
}

// Validate rejects ambiguous or incomplete rule snapshots before activation.
func Validate(s *RuleSet) error {
	if s == nil {
		return fmt.Errorf("ruleset is nil")
	}
	if !validVersion(s.Version) {
		return fmt.Errorf("invalid ruleset version %q", s.Version)
	}
	if len(s.Rules) == 0 {
		return fmt.Errorf("ruleset contains no rules")
	}
	if len(s.Rules) > maxRuleCount {
		return fmt.Errorf("ruleset contains %d rules, limit is %d", len(s.Rules), maxRuleCount)
	}

	ids := make(map[string]struct{}, len(s.Rules))
	for i := range s.Rules {
		rule := &s.Rules[i]
		if !validIdentifier(rule.ID) {
			return fmt.Errorf("rule %d has invalid ID %q", i, rule.ID)
		}
		if _, exists := ids[rule.ID]; exists {
			return fmt.Errorf("duplicate rule ID %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		if _, ok := validCategories[rule.Category]; !ok {
			return fmt.Errorf("rule %s has unknown category %q", rule.ID, rule.Category)
		}
		wantProtected := categoryRequiresAuthorizationProtection(rule.Category)
		if rule.AuthorizationProtected != wantProtected {
			return fmt.Errorf("rule %s authorization_protected=%t, want %t for category %s", rule.ID, rule.AuthorizationProtected, wantProtected, rule.Category)
		}
		switch rule.Severity {
		case "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("rule %s has unknown severity %q", rule.ID, rule.Severity)
		}
		if rule.BaseScore < 1 || rule.BaseScore > 100 {
			return fmt.Errorf("rule %s base_score must be in 1..100", rule.ID)
		}
		if rule.HardFloor < 0 || rule.HardFloor > 100 {
			return fmt.Errorf("rule %s hard_floor must be in 0..100", rule.ID)
		}
		if rule.HardFloor != 0 && rule.HardFloor < rule.BaseScore {
			return fmt.Errorf("rule %s hard_floor is below base_score", rule.ID)
		}
		if err := validateBilingual(rule.ID+" intent", rule.Intent, true); err != nil {
			return err
		}
		if err := validateBilingual(rule.ID+" object", rule.Object, true); err != nil {
			return err
		}
		qualifierGroups := []struct {
			name  string
			terms Terms
		}{
			{"operational", rule.Operational},
			{"target", rule.Target},
			{"evasion", rule.Evasion},
			{"scale", rule.Scale},
		}
		hasQualifier := false
		for _, group := range qualifierGroups {
			if len(group.terms.ZH) != 0 || len(group.terms.EN) != 0 {
				hasQualifier = true
				if err := validateBilingual(rule.ID+" "+group.name, group.terms, true); err != nil {
					return err
				}
			}
		}
		if !hasQualifier {
			return fmt.Errorf("rule %s has no independent qualifier evidence", rule.ID)
		}
		if err := validateIndependentEvidence(*rule); err != nil {
			return err
		}
	}

	if len(s.Semantics) != 0 {
		for category := range validCategories {
			profile, ok := s.Semantics[category]
			if !ok {
				return fmt.Errorf("missing semantic profile for category %q", category)
			}
			if profile.Category != category {
				return fmt.Errorf("semantic profile key %q contains category %q", category, profile.Category)
			}
			groups := []struct {
				name  string
				terms Terms
			}{
				{"harm", profile.Harm}, {"object", profile.Object}, {"action", profile.Action},
				{"outcome", profile.Outcome}, {"target", profile.Target}, {"destination", profile.Destination},
				{"evasion", profile.Evasion}, {"scale", profile.Scale}, {"sequence", profile.Sequence},
				{"impact", profile.Impact},
			}
			owners := make(map[string]string)
			for _, group := range groups {
				if err := validateBilingual("semantic "+string(category)+" "+group.name, group.terms, true); err != nil {
					return err
				}
				for _, value := range append(append([]string(nil), group.terms.ZH...), group.terms.EN...) {
					for _, key := range evidenceKeys(value) {
						if previous, exists := owners[key]; exists && previous != group.name {
							return fmt.Errorf("semantic profile %s reuses normalized literal %q in %s and %s", category, value, previous, group.name)
						}
						owners[key] = group.name
					}
				}
			}
		}
		for category := range s.Semantics {
			if _, ok := validCategories[category]; !ok {
				return fmt.Errorf("semantic profile has unknown category %q", category)
			}
		}
	}

	for kind := range s.Contexts {
		if _, ok := validContextKinds[kind]; !ok {
			return fmt.Errorf("unknown context kind %q", kind)
		}
	}
	for kind := range validContextKinds {
		terms, ok := s.Contexts[kind]
		if !ok {
			return fmt.Errorf("missing context kind %q", kind)
		}
		if err := validateBilingual("context "+string(kind), terms, true); err != nil {
			return err
		}
	}
	return nil
}

func categoryRequiresAuthorizationProtection(category Category) bool {
	switch category {
	case CategoryCredentialTheft, CategoryPhishing, CategoryRansomware, CategoryExfiltration:
		return true
	default:
		return false
	}
}

func validateIndependentEvidence(rule Rule) error {
	groups := []struct {
		name  string
		terms Terms
	}{
		{"intent", rule.Intent},
		{"object", rule.Object},
		{"operational", rule.Operational},
		{"target", rule.Target},
		{"evasion", rule.Evasion},
		{"scale", rule.Scale},
	}
	owners := make(map[string]string)
	type ownedEvidence struct {
		key   string
		group string
	}
	owned := make([]ownedEvidence, 0, 64)
	for _, group := range groups {
		values := make([]string, 0, len(group.terms.ZH)+len(group.terms.EN))
		values = append(values, group.terms.ZH...)
		values = append(values, group.terms.EN...)
		for _, value := range values {
			keys := evidenceKeys(value)
			if len(keys) == 0 {
				return fmt.Errorf("rule %s has literal %q that normalizes to empty evidence", rule.ID, value)
			}
			for _, key := range keys {
				if previous, exists := owners[key]; exists && previous != group.name {
					return fmt.Errorf("rule %s reuses normalized literal %q in %s and %s", rule.ID, value, previous, group.name)
				}
				if !strings.HasPrefix(key, "compact:") {
					for _, previous := range owned {
						corePair := (previous.group == "intent" && group.name == "object") || (previous.group == "object" && group.name == "intent")
						if corePair && normalizedLiteralOverlap(previous.key, key) {
							return fmt.Errorf("rule %s overlaps normalized literal %q between %s and %s", rule.ID, value, previous.group, group.name)
						}
					}
					owned = append(owned, ownedEvidence{key: key, group: group.name})
				}
				owners[key] = group.name
			}
		}
	}
	return nil
}

func normalizedLiteralOverlap(left, right string) bool {
	if left == right {
		return true
	}
	shorter, longer := left, right
	if len(shorter) > len(longer) {
		shorter, longer = longer, shorter
	}
	for offset := 0; offset <= len(longer)-len(shorter); {
		index := strings.Index(longer[offset:], shorter)
		if index < 0 {
			return false
		}
		index += offset
		if !isASCIIString(shorter) {
			return true
		}
		leftBoundary := index == 0 || !isASCIIEvidenceWordByte(longer[index-1])
		rightIndex := index + len(shorter)
		rightBoundary := rightIndex == len(longer) || !isASCIIEvidenceWordByte(longer[rightIndex])
		if leftBoundary && rightBoundary {
			return true
		}
		offset = index + 1
	}
	return false
}

func isASCIIString(value string) bool {
	for _, r := range value {
		if r > unicode.MaxASCII {
			return false
		}
	}
	return true
}

func isASCIIEvidenceWordByte(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '_'
}

func evidenceKeys(value string) []string {
	value = strings.ToLower(norm.NFKC.String(strings.TrimSpace(value)))
	runes := make([]rune, 0, len(value))
	for _, r := range value {
		if unicode.In(r, unicode.Cf) || r == '\u200b' || r == '\u200c' || r == '\u200d' || r == '\u2060' || r == '\ufeff' || r == '\u00ad' {
			continue
		}
		if replacement, ok := evidenceHomoglyphReplacement(r); ok {
			r = replacement
		}
		runes = append(runes, r)
	}
	for i, r := range runes {
		if replacement, ok := evidenceLeetReplacement(r); ok && evidenceLetterNear(runes, i, -1) && evidenceLetterNear(runes, i, 1) {
			runes[i] = replacement
		}
	}
	var standard strings.Builder
	var compact strings.Builder
	lastSpace := true
	for _, r := range runes {
		if unicode.IsSpace(r) {
			if !lastSpace {
				standard.WriteByte(' ')
				lastSpace = true
			}
			continue
		}
		standard.WriteRune(r)
		lastSpace = false
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			compact.WriteRune(r)
		}
	}
	standardKey := strings.TrimSpace(standard.String())
	compactKey := compact.String()
	if standardKey == "" || compactKey == "" {
		return nil
	}
	if compactKey == standardKey || compactKey == "" {
		return []string{standardKey}
	}
	return []string{standardKey, "compact:" + compactKey}
}

func evidenceLeetReplacement(r rune) (rune, bool) {
	switch r {
	case '0':
		return 'o', true
	case '1', '!':
		return 'i', true
	case '3':
		return 'e', true
	case '4', '@':
		return 'a', true
	case '5', '$':
		return 's', true
	case '7':
		return 't', true
	default:
		return 0, false
	}
}

func evidenceHomoglyphReplacement(r rune) (rune, bool) {
	switch r {
	case '\u0430', '\u03b1':
		return 'a', true
	case '\u0432':
		return 'b', true
	case '\u0441', '\u03f2':
		return 'c', true
	case '\u0501':
		return 'd', true
	case '\u0435', '\u03b5':
		return 'e', true
	case '\u04bb':
		return 'h', true
	case '\u0456', '\u03b9', '\u0131':
		return 'i', true
	case '\u0458':
		return 'j', true
	case '\u03ba', '\u043a':
		return 'k', true
	case '\u04cf':
		return 'l', true
	case '\u043c':
		return 'm', true
	case '\u03bd':
		return 'v', true
	case '\u043e', '\u03bf':
		return 'o', true
	case '\u0440', '\u03c1':
		return 'p', true
	case '\u0455':
		return 's', true
	case '\u0442', '\u03c4':
		return 't', true
	case '\u0445', '\u03c7':
		return 'x', true
	case '\u0443':
		return 'y', true
	default:
		return 0, false
	}
}

func evidenceLetterNear(runes []rune, index, direction int) bool {
	for steps, i := 0, index+direction; i >= 0 && i < len(runes) && steps < 12; steps, i = steps+1, i+direction {
		r := runes[i]
		if unicode.IsSpace(r) {
			return false
		}
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func validateBilingual(label string, terms Terms, required bool) error {
	if !required && len(terms.ZH) == 0 && len(terms.EN) == 0 {
		return nil
	}
	if len(terms.ZH) == 0 || len(terms.EN) == 0 {
		return fmt.Errorf("%s must have both zh and en terms", label)
	}
	if len(terms.ZH) > maxTermsPerLang || len(terms.EN) > maxTermsPerLang {
		return fmt.Errorf("%s exceeds the per-language term limit", label)
	}
	for language, values := range map[string][]string{"zh": terms.ZH, "en": terms.EN} {
		seen := make(map[string]struct{}, len(values))
		for _, value := range values {
			trimmed := strings.TrimSpace(value)
			if trimmed == "" {
				return fmt.Errorf("%s has an empty %s term", label, language)
			}
			if utf8.RuneCountInString(trimmed) > 128 {
				return fmt.Errorf("%s has an overlong %s term", label, language)
			}
			keys := evidenceKeys(trimmed)
			if len(keys) == 0 {
				return fmt.Errorf("%s has a %s term that normalizes to empty evidence", label, language)
			}
			key := strings.Join(keys, "\x00")
			if _, ok := seen[key]; ok {
				return fmt.Errorf("%s has duplicate %s term %q", label, language, trimmed)
			}
			seen[key] = struct{}{}
		}
	}
	return nil
}

func validVersion(version string) bool {
	if version == "" || len(version) > 64 {
		return false
	}
	for _, r := range version {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '.' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

func validIdentifier(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}
