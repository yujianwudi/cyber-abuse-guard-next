package round9corpus

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

const (
	ExpectedMaliciousDecision = "block_malicious_text"
	UnambiguousLabel          = "unambiguous"
)

var MaliciousCategories = []string{
	"credential_theft",
	"phishing_deployment",
	"malware_deployment",
	"ransomware_deployment",
	"unauthorized_exploitation",
	"service_disruption",
	"data_exfiltration",
	"defense_evasion",
	"prompt_injection_evasion",
}

// MaliciousRecord is one externally labelled malicious semantic base request.
// The label is frozen before the candidate is run and is never inferred from
// the candidate's own eligibility output.
type MaliciousRecord struct {
	ID               string `json:"id"`
	Category         string `json:"category"`
	Language         string `json:"language"`
	Prompt           string `json:"prompt"`
	ExpectedDecision string `json:"expected_decision"`
	LabelConfidence  string `json:"label_confidence"`
	AuthoringContext string `json:"authoring_context"`
}

// MaliciousManifest is a closed identity and distribution contract for a
// malicious corpus. It deliberately has no field for candidate output.
type MaliciousManifest struct {
	Name               string                  `json:"name"`
	Version            int                     `json:"version"`
	GeneratedAt        string                  `json:"generated_at"`
	AuthoringContext   string                  `json:"authoring_context"`
	ExpectedDecision   string                  `json:"expected_decision"`
	LabelConfidence    string                  `json:"label_confidence"`
	GenerationBoundary GenerationBoundary      `json:"generation_boundary"`
	Schema             ManifestSchema          `json:"schema"`
	Counts             ManifestCounts          `json:"counts"`
	Files              map[string]FileIdentity `json:"files"`
}

// MaliciousLoadOptions binds the externally frozen corpus contract.
type MaliciousLoadOptions struct {
	Name                string
	AuthoringContext    string
	ExpectedTotal       int
	ExpectedPerCategory int
	ExpectedPerLanguage int
	Independent         bool
}

// LoadedMaliciousCorpus is returned only after the closed manifest, byte
// identity, labels, distribution, and semantic uniqueness checks pass.
type LoadedMaliciousCorpus struct {
	Manifest MaliciousManifest
	Records  []MaliciousRecord
}

// LoadMalicious validates an externally labelled malicious corpus without
// modifying or executing any corpus content.
func LoadMalicious(directory string, options MaliciousLoadOptions) (LoadedMaliciousCorpus, error) {
	if err := validateMaliciousLoadOptions(options); err != nil {
		return LoadedMaliciousCorpus{}, err
	}
	directory = filepath.Clean(directory)
	manifestData, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return LoadedMaliciousCorpus{}, fmt.Errorf("read malicious manifest: %w", err)
	}
	var manifest MaliciousManifest
	if err := decodeStrictJSON(manifestData, &manifest); err != nil {
		return LoadedMaliciousCorpus{}, fmt.Errorf("decode malicious manifest: %w", err)
	}
	if err := validateMaliciousManifest(manifest, options); err != nil {
		return LoadedMaliciousCorpus{}, err
	}
	identity, ok := manifest.Files["cases.jsonl"]
	if !ok || len(manifest.Files) != 1 {
		return LoadedMaliciousCorpus{}, errors.New("malicious manifest files must contain only cases.jsonl")
	}
	caseData, err := os.ReadFile(filepath.Join(directory, "cases.jsonl"))
	if err != nil {
		return LoadedMaliciousCorpus{}, fmt.Errorf("read malicious cases: %w", err)
	}
	if err := verifyIdentity(caseData, identity); err != nil {
		return LoadedMaliciousCorpus{}, fmt.Errorf("malicious cases.jsonl identity: %w", err)
	}
	records, err := decodeMaliciousRecords(caseData, manifest, options)
	if err != nil {
		return LoadedMaliciousCorpus{}, err
	}
	return LoadedMaliciousCorpus{Manifest: manifest, Records: records}, nil
}

func validateMaliciousLoadOptions(options MaliciousLoadOptions) error {
	if options.Name == "" || options.AuthoringContext == "" {
		return errors.New("malicious load options must bind name and authoring context")
	}
	if options.ExpectedTotal <= 0 || options.ExpectedPerCategory <= 0 || options.ExpectedPerLanguage <= 0 {
		return errors.New("malicious load options must bind positive corpus counts")
	}
	if options.ExpectedTotal != len(MaliciousCategories)*options.ExpectedPerCategory ||
		options.ExpectedPerCategory != 2*options.ExpectedPerLanguage {
		return errors.New("malicious load option totals do not match the nine-category bilingual contract")
	}
	return nil
}

func validateMaliciousManifest(manifest MaliciousManifest, options MaliciousLoadOptions) error {
	if manifest.Name != options.Name || manifest.Version != 1 ||
		manifest.AuthoringContext != options.AuthoringContext ||
		manifest.ExpectedDecision != ExpectedMaliciousDecision ||
		manifest.LabelConfidence != UnambiguousLabel {
		return errors.New("malicious manifest identity does not match the frozen load contract")
	}
	if strings.TrimSpace(manifest.GeneratedAt) == "" {
		return errors.New("malicious manifest generated_at is empty")
	}
	wantFields := []string{
		"id", "category", "language", "prompt", "expected_decision",
		"label_confidence", "authoring_context",
	}
	if manifest.Schema.FileFormat != "jsonl" ||
		!equalStrings(manifest.Schema.Fields, wantFields) ||
		!equalStrings(manifest.Schema.LanguageValues, []string{LanguageChinese, LanguageEnglish}) {
		return errors.New("malicious manifest schema drift")
	}
	if manifest.Counts.Total != options.ExpectedTotal || len(manifest.Counts.Languages) != 2 ||
		manifest.Counts.Languages[LanguageChinese] != options.ExpectedTotal/2 ||
		manifest.Counts.Languages[LanguageEnglish] != options.ExpectedTotal/2 {
		return errors.New("malicious manifest language totals drift")
	}
	if len(manifest.Counts.Categories) != len(MaliciousCategories) {
		return errors.New("malicious manifest category set drift")
	}
	for _, category := range MaliciousCategories {
		count, ok := manifest.Counts.Categories[category]
		if !ok || count.Total != options.ExpectedPerCategory ||
			count.ZH != options.ExpectedPerLanguage || count.EN != options.ExpectedPerLanguage {
			return fmt.Errorf("malicious manifest category %s distribution drift", category)
		}
	}
	boundary := manifest.GenerationBoundary
	if options.Independent {
		if !boundary.IndependentlyAuthoredBeforeCandidateExecution || boundary.SourceCodeRead || boundary.RulesRead ||
			boundary.ExistingDevelopmentCorporaRead || boundary.ExistingRestrictedContentRead ||
			boundary.CandidateOutputObserved || boundary.ClassifierOrProjectTestsRun {
			return errors.New("independent malicious authoring boundary is not closed")
		}
	}
	if len(strings.TrimSpace(boundary.SemanticPolicy)) < 24 || len(strings.TrimSpace(boundary.SafetyPolicy)) < 24 {
		return errors.New("malicious manifest authoring policies are incomplete")
	}
	return nil
}

func decodeMaliciousRecords(data []byte, manifest MaliciousManifest, options MaliciousLoadOptions) ([]MaliciousRecord, error) {
	records := make([]MaliciousRecord, 0, options.ExpectedTotal)
	ids := make(map[string]int, options.ExpectedTotal)
	canonical := make(map[string]int, options.ExpectedTotal)
	categoryCounts := make(map[string]CategoryCount, len(MaliciousCategories))
	languageCounts := map[string]int{LanguageChinese: 0, LanguageEnglish: 0}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		lineNumber := len(records) + 1
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			return nil, fmt.Errorf("malicious cases line %d is blank", lineNumber)
		}
		var record MaliciousRecord
		if err := decodeStrictJSON(line, &record); err != nil {
			return nil, fmt.Errorf("malicious cases line %d: %w", lineNumber, err)
		}
		if err := validateMaliciousRecord(record, manifest, ids); err != nil {
			return nil, fmt.Errorf("malicious case %q: %w", record.ID, err)
		}
		key := canonicalSemantic(record.Prompt)
		if previous, duplicate := canonical[key]; duplicate {
			return nil, fmt.Errorf("malicious case %q semantically duplicates line %d", record.ID, previous)
		}
		ids[record.ID] = lineNumber
		canonical[key] = lineNumber
		count := categoryCounts[record.Category]
		count.Total++
		if record.Language == LanguageChinese {
			count.ZH++
		} else {
			count.EN++
		}
		categoryCounts[record.Category] = count
		languageCounts[record.Language]++
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan malicious cases: %w", err)
	}
	if len(records) != options.ExpectedTotal {
		return nil, fmt.Errorf("malicious semantic base requests=%d want %d", len(records), options.ExpectedTotal)
	}
	for _, category := range MaliciousCategories {
		if got, want := categoryCounts[category], manifest.Counts.Categories[category]; got != want {
			return nil, fmt.Errorf("malicious category %s count=%+v want %+v", category, got, want)
		}
	}
	for language, want := range manifest.Counts.Languages {
		if languageCounts[language] != want {
			return nil, fmt.Errorf("malicious language %s count=%d want %d", language, languageCounts[language], want)
		}
	}
	base := make([]BaseRecord, 0, len(records))
	for _, record := range records {
		base = append(base, BaseRecord{ID: record.ID, Category: record.Category, Language: record.Language, Prompt: record.Prompt})
	}
	if err := rejectNearDuplicates(base); err != nil {
		return nil, err
	}
	return records, nil
}

func validateMaliciousRecord(record MaliciousRecord, manifest MaliciousManifest, ids map[string]int) error {
	if !recordIDPattern.MatchString(record.ID) {
		return errors.New("invalid id")
	}
	if previous, duplicate := ids[record.ID]; duplicate {
		return fmt.Errorf("duplicates line %d", previous)
	}
	if _, ok := manifest.Counts.Categories[record.Category]; !ok {
		return errors.New("unknown category")
	}
	if record.Language != LanguageChinese && record.Language != LanguageEnglish {
		return errors.New("unknown language")
	}
	if record.ExpectedDecision != ExpectedMaliciousDecision ||
		record.LabelConfidence != UnambiguousLabel ||
		record.AuthoringContext != manifest.AuthoringContext {
		return errors.New("malicious ground truth or authoring context drift")
	}
	if record.Prompt != strings.TrimSpace(record.Prompt) || len([]rune(record.Prompt)) < 18 {
		return errors.New("prompt is empty, too short, or has surrounding whitespace")
	}
	if strings.IndexFunc(record.Prompt, func(r rune) bool {
		return unicode.IsControl(r) && r != '\n' && r != '\t'
	}) >= 0 {
		return errors.New("prompt contains a control character")
	}
	return nil
}

// ExpectedRuleCategory maps the independent taxonomy to the classifier's
// stable coarse category. Prompt-injection evasion is intentionally reported
// under the classifier's defense-evasion category rather than inventing an
// unversioned audit taxonomy value.
func ExpectedRuleCategory(category string) (rules.Category, error) {
	switch category {
	case "credential_theft":
		return rules.CategoryCredentialTheft, nil
	case "phishing_deployment":
		return rules.CategoryPhishing, nil
	case "malware_deployment":
		return rules.CategoryMalware, nil
	case "ransomware_deployment":
		return rules.CategoryRansomware, nil
	case "unauthorized_exploitation":
		return rules.CategoryExploitation, nil
	case "service_disruption":
		return rules.CategoryDisruption, nil
	case "data_exfiltration":
		return rules.CategoryExfiltration, nil
	case "defense_evasion", "prompt_injection_evasion":
		return rules.CategoryEvasion, nil
	default:
		return "", fmt.Errorf("unknown malicious category %q", category)
	}
}

// SortedMaliciousCategories returns the corpus taxonomy in stable order.
func SortedMaliciousCategories() []string {
	result := append([]string(nil), MaliciousCategories...)
	sort.Strings(result)
	return result
}
