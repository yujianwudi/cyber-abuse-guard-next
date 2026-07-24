package round9corpus

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	ExpectedPairedAuthoringContext = "visible_round9_paired_development_v3"
	PairedMaliciousCorpusName      = "round9-development-paired-malicious-v3"
	PairedLabelAuditFileName       = "LABEL_AUDIT.md"
)

// PairedDifferenceAxes enumerate the externally authored semantic changes
// allowed between a benign development request and its malicious neighbor.
// They are labels only and never inferred from candidate classifier output.
var PairedDifferenceAxes = []string{
	"unauthorized_target",
	"third_party_victim",
	"covert_acquisition",
	"bypass_consent",
	"exfiltration_or_takeover",
	"real_deployment",
	"service_disruption",
	"execute_referent",
}

// PairedMaliciousRecord binds one visible malicious neighbor to a distinct
// frozen benign base request. The prompt remains development data, never an
// independent holdout or source of candidate-derived ground truth.
type PairedMaliciousRecord struct {
	ID               string `json:"id"`
	Family           string `json:"family"`
	BenignBaseID     string `json:"benign_base_id"`
	DifferenceAxis   string `json:"difference_axis"`
	Category         string `json:"category"`
	Language         string `json:"language"`
	Prompt           string `json:"prompt"`
	ExpectedDecision string `json:"expected_decision"`
	LabelConfidence  string `json:"label_confidence"`
	AuthoringContext string `json:"authoring_context"`
}

// PairedManifestCounts keeps family coverage separate from classifier
// taxonomy and semantic-difference coverage.
type PairedManifestCounts struct {
	Total          int                      `json:"total"`
	Languages      map[string]int           `json:"languages"`
	Families       map[string]CategoryCount `json:"families"`
	Categories     map[string]int           `json:"categories"`
	DifferenceAxes map[string]int           `json:"difference_axes"`
}

// PairedMaliciousManifest is the closed, candidate-independent identity of the
// visible paired development corpus.
type PairedMaliciousManifest struct {
	Name               string                  `json:"name"`
	Version            int                     `json:"version"`
	GeneratedAt        string                  `json:"generated_at"`
	AuthoringContext   string                  `json:"authoring_context"`
	ExpectedDecision   string                  `json:"expected_decision"`
	LabelConfidence    string                  `json:"label_confidence"`
	GenerationBoundary GenerationBoundary      `json:"generation_boundary"`
	Schema             ManifestSchema          `json:"schema"`
	Counts             PairedManifestCounts    `json:"counts"`
	Files              map[string]FileIdentity `json:"files"`
	LabelAudit         FileIdentity            `json:"label_audit"`
}

// PairedLoadOptions binds the exact visible paired corpus distribution.
type PairedLoadOptions struct {
	Name                string
	AuthoringContext    string
	ExpectedTotal       int
	ExpectedPerFamily   int
	ExpectedPerLanguage int
}

// LoadedPairedMaliciousCorpus is returned only after the corpus identity,
// benign references, labels, distributions, and uniqueness all validate.
type LoadedPairedMaliciousCorpus struct {
	Manifest PairedMaliciousManifest
	Records  []PairedMaliciousRecord
}

// LoadPairedMalicious validates a visible paired corpus against an already
// frozen benign corpus. Candidate output is never an input to this operation.
func LoadPairedMalicious(directory string, benign []BaseRecord, options PairedLoadOptions) (LoadedPairedMaliciousCorpus, error) {
	if err := validatePairedLoadOptions(options); err != nil {
		return LoadedPairedMaliciousCorpus{}, err
	}
	directory = filepath.Clean(directory)
	manifestData, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return LoadedPairedMaliciousCorpus{}, fmt.Errorf("read paired manifest: %w", err)
	}
	var manifest PairedMaliciousManifest
	if err := decodeStrictJSON(manifestData, &manifest); err != nil {
		return LoadedPairedMaliciousCorpus{}, fmt.Errorf("decode paired manifest: %w", err)
	}
	if err := validatePairedManifest(manifest, options); err != nil {
		return LoadedPairedMaliciousCorpus{}, err
	}
	identity, ok := manifest.Files["cases.jsonl"]
	if !ok || len(manifest.Files) != 1 {
		return LoadedPairedMaliciousCorpus{}, errors.New("paired manifest files must contain only cases.jsonl")
	}
	caseData, err := os.ReadFile(filepath.Join(directory, "cases.jsonl"))
	if err != nil {
		return LoadedPairedMaliciousCorpus{}, fmt.Errorf("read paired cases: %w", err)
	}
	if err := verifyIdentity(caseData, identity); err != nil {
		return LoadedPairedMaliciousCorpus{}, fmt.Errorf("paired cases.jsonl identity: %w", err)
	}
	labelAuditData, err := os.ReadFile(filepath.Join(directory, PairedLabelAuditFileName))
	if err != nil {
		return LoadedPairedMaliciousCorpus{}, fmt.Errorf("read paired label audit: %w", err)
	}
	if err := verifyIdentity(labelAuditData, manifest.LabelAudit); err != nil {
		return LoadedPairedMaliciousCorpus{}, fmt.Errorf("paired label audit identity: %w", err)
	}
	if err := ValidatePairedLabelAudit(labelAuditData, identity.SHA256, options.ExpectedTotal); err != nil {
		return LoadedPairedMaliciousCorpus{}, fmt.Errorf("paired label audit contract: %w", err)
	}
	records, err := decodePairedRecords(caseData, benign, manifest, options)
	if err != nil {
		return LoadedPairedMaliciousCorpus{}, err
	}
	return LoadedPairedMaliciousCorpus{Manifest: manifest, Records: records}, nil
}

func validatePairedLoadOptions(options PairedLoadOptions) error {
	if options.Name == "" || options.AuthoringContext == "" {
		return errors.New("paired load options must bind name and authoring context")
	}
	if options.ExpectedTotal <= 0 || options.ExpectedPerFamily <= 0 || options.ExpectedPerLanguage <= 0 {
		return errors.New("paired load options must bind positive counts")
	}
	if options.ExpectedTotal != len(BaseCategories)*options.ExpectedPerFamily ||
		options.ExpectedPerFamily != 2*options.ExpectedPerLanguage {
		return errors.New("paired load option totals do not match the bilingual family contract")
	}
	return nil
}

func validatePairedManifest(manifest PairedMaliciousManifest, options PairedLoadOptions) error {
	if manifest.Name != options.Name || manifest.Version != 2 ||
		manifest.AuthoringContext != options.AuthoringContext ||
		manifest.ExpectedDecision != ExpectedMaliciousDecision ||
		manifest.LabelConfidence != UnambiguousLabel {
		return errors.New("paired manifest identity does not match the load contract")
	}
	if strings.TrimSpace(manifest.GeneratedAt) == "" {
		return errors.New("paired manifest generated_at is empty")
	}
	wantFields := []string{
		"id", "family", "benign_base_id", "difference_axis", "category", "language", "prompt",
		"expected_decision", "label_confidence", "authoring_context",
	}
	if manifest.Schema.FileFormat != "jsonl" ||
		!equalStrings(manifest.Schema.Fields, wantFields) ||
		!equalStrings(manifest.Schema.LanguageValues, []string{LanguageChinese, LanguageEnglish}) {
		return errors.New("paired manifest schema drift")
	}
	if manifest.Counts.Total != options.ExpectedTotal || len(manifest.Counts.Languages) != 2 ||
		manifest.Counts.Languages[LanguageChinese] != options.ExpectedTotal/2 ||
		manifest.Counts.Languages[LanguageEnglish] != options.ExpectedTotal/2 {
		return errors.New("paired manifest language totals drift")
	}
	if len(manifest.Counts.Families) != len(BaseCategories) {
		return errors.New("paired manifest family set drift")
	}
	for _, family := range BaseCategories {
		count, ok := manifest.Counts.Families[family]
		if !ok || count.Total != options.ExpectedPerFamily || count.ZH != options.ExpectedPerLanguage || count.EN != options.ExpectedPerLanguage {
			return fmt.Errorf("paired manifest family %s distribution drift", family)
		}
	}
	if len(manifest.Counts.Categories) != len(MaliciousCategories) {
		return errors.New("paired manifest must cover every malicious category")
	}
	categoryTotal := 0
	for _, category := range MaliciousCategories {
		count, ok := manifest.Counts.Categories[category]
		if !ok || count <= 0 {
			return fmt.Errorf("paired manifest category %s is not covered", category)
		}
		categoryTotal += count
	}
	if categoryTotal != options.ExpectedTotal {
		return errors.New("paired manifest category totals drift")
	}
	if len(manifest.Counts.DifferenceAxes) != len(PairedDifferenceAxes) {
		return errors.New("paired manifest difference-axis set drift")
	}
	axisTotal := 0
	for _, axis := range PairedDifferenceAxes {
		count, ok := manifest.Counts.DifferenceAxes[axis]
		if !ok || count <= 0 {
			return fmt.Errorf("paired manifest difference axis %s is not covered", axis)
		}
		axisTotal += count
	}
	if axisTotal != options.ExpectedTotal {
		return errors.New("paired manifest difference-axis totals drift")
	}
	boundary := manifest.GenerationBoundary
	if boundary.ExistingRestrictedContentRead || boundary.CandidateOutputObserved ||
		boundary.ClassifierOrProjectTestsRun || !boundary.ExistingDevelopmentCorporaRead {
		return errors.New("paired development authoring boundary is not closed")
	}
	if len(strings.TrimSpace(boundary.SemanticPolicy)) < 24 || len(strings.TrimSpace(boundary.SafetyPolicy)) < 24 {
		return errors.New("paired manifest authoring policies are incomplete")
	}
	return nil
}

// ValidatePairedLabelAudit binds the human pre-execution label review to the
// exact assembled cases bytes. It deliberately checks only bounded review
// metadata; the report may not become an alternate source of prompts or
// classifier-derived labels.
func ValidatePairedLabelAudit(data []byte, casesSHA256 string, expectedTotal int) error {
	if len(data) < 512 || len(data) > 256<<10 {
		return errors.New("label audit size is outside the bounded contract")
	}
	if !utf8.Valid(data) || bytes.IndexByte(data, 0) >= 0 {
		return errors.New("label audit must be valid UTF-8 without NUL bytes")
	}
	if len(casesSHA256) != 64 || strings.ToLower(casesSHA256) != casesSHA256 {
		return errors.New("label audit cases SHA-256 binding is invalid")
	}
	for _, r := range casesSHA256 {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return errors.New("label audit cases SHA-256 binding is not hexadecimal")
		}
	}
	report := string(data)
	required := []string{
		"# Round 9 paired-v3 pre-execution label audit",
		fmt.Sprintf("Draft cases SHA-256: `%s`", casesSHA256),
		fmt.Sprintf("Reviewed records: %d", expectedTotal),
		fmt.Sprintf("Passed records: %d", expectedTotal),
		"Failed records: 0",
		"Candidate output observed: false",
		"Classifier or project tests run: false",
		"Overall verdict: PASS",
	}
	for _, marker := range required {
		if !strings.Contains(report, marker) {
			return fmt.Errorf("label audit is missing required marker %q", marker)
		}
	}
	for _, contradiction := range []string{
		"Candidate output observed: true",
		"Classifier or project tests run: true",
		"Overall verdict: FAIL",
	} {
		if strings.Contains(report, contradiction) {
			return fmt.Errorf("label audit contains contradictory marker %q", contradiction)
		}
	}
	return nil
}

func decodePairedRecords(data []byte, benign []BaseRecord, manifest PairedMaliciousManifest, options PairedLoadOptions) ([]PairedMaliciousRecord, error) {
	benignByID := make(map[string]BaseRecord, len(benign))
	for _, record := range benign {
		if _, duplicate := benignByID[record.ID]; duplicate {
			return nil, fmt.Errorf("duplicate frozen benign id %q", record.ID)
		}
		benignByID[record.ID] = record
	}
	if len(benignByID) == 0 {
		return nil, errors.New("paired corpus requires frozen benign records")
	}

	records := make([]PairedMaliciousRecord, 0, options.ExpectedTotal)
	ids := make(map[string]int, options.ExpectedTotal)
	benignRefs := make(map[string]int, options.ExpectedTotal)
	canonical := make(map[string]int, options.ExpectedTotal)
	familyCounts := make(map[string]CategoryCount, len(BaseCategories))
	languageCounts := map[string]int{LanguageChinese: 0, LanguageEnglish: 0}
	categoryCounts := make(map[string]int, len(MaliciousCategories))
	axisCounts := make(map[string]int, len(PairedDifferenceAxes))

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		lineNumber := len(records) + 1
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			return nil, fmt.Errorf("paired cases line %d is blank", lineNumber)
		}
		var record PairedMaliciousRecord
		if err := decodeStrictJSON(line, &record); err != nil {
			return nil, fmt.Errorf("paired cases line %d: %w", lineNumber, err)
		}
		if err := validatePairedRecord(record, benignByID, manifest, ids, benignRefs); err != nil {
			return nil, fmt.Errorf("paired case %q: %w", record.ID, err)
		}
		key := canonicalSemantic(record.Prompt)
		if previous, duplicate := canonical[key]; duplicate {
			return nil, fmt.Errorf("paired case %q semantically duplicates line %d", record.ID, previous)
		}
		ids[record.ID] = lineNumber
		benignRefs[record.BenignBaseID] = lineNumber
		canonical[key] = lineNumber
		count := familyCounts[record.Family]
		count.Total++
		if record.Language == LanguageChinese {
			count.ZH++
		} else {
			count.EN++
		}
		familyCounts[record.Family] = count
		languageCounts[record.Language]++
		categoryCounts[record.Category]++
		axisCounts[record.DifferenceAxis]++
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan paired cases: %w", err)
	}
	if len(records) != options.ExpectedTotal {
		return nil, fmt.Errorf("paired semantic requests=%d want %d", len(records), options.ExpectedTotal)
	}
	for _, family := range BaseCategories {
		if got, want := familyCounts[family], manifest.Counts.Families[family]; got != want {
			return nil, fmt.Errorf("paired family %s count=%+v want %+v", family, got, want)
		}
	}
	for language, want := range manifest.Counts.Languages {
		if languageCounts[language] != want {
			return nil, fmt.Errorf("paired language %s count=%d want %d", language, languageCounts[language], want)
		}
	}
	for category, want := range manifest.Counts.Categories {
		if categoryCounts[category] != want {
			return nil, fmt.Errorf("paired category %s count=%d want %d", category, categoryCounts[category], want)
		}
	}
	for axis, want := range manifest.Counts.DifferenceAxes {
		if axisCounts[axis] != want {
			return nil, fmt.Errorf("paired difference axis %s count=%d want %d", axis, axisCounts[axis], want)
		}
	}
	base := make([]BaseRecord, 0, len(records))
	for _, record := range records {
		base = append(base, BaseRecord{ID: record.ID, Category: record.Family, Language: record.Language, Prompt: record.Prompt})
	}
	if err := rejectNearDuplicates(base); err != nil {
		return nil, err
	}
	return records, nil
}

func validatePairedRecord(record PairedMaliciousRecord, benignByID map[string]BaseRecord, manifest PairedMaliciousManifest, ids, benignRefs map[string]int) error {
	if !recordIDPattern.MatchString(record.ID) {
		return errors.New("invalid id")
	}
	if previous, duplicate := ids[record.ID]; duplicate {
		return fmt.Errorf("duplicates line %d", previous)
	}
	if previous, duplicate := benignRefs[record.BenignBaseID]; duplicate {
		return fmt.Errorf("benign base id is already paired on line %d", previous)
	}
	if !containsString(BaseCategories, record.Family) {
		return errors.New("unknown family")
	}
	if !containsString(MaliciousCategories, record.Category) {
		return errors.New("unknown malicious category")
	}
	if !containsString(PairedDifferenceAxes, record.DifferenceAxis) {
		return errors.New("unknown difference axis")
	}
	if record.Language != LanguageChinese && record.Language != LanguageEnglish {
		return errors.New("unknown language")
	}
	if record.ExpectedDecision != ExpectedMaliciousDecision || record.LabelConfidence != UnambiguousLabel ||
		record.AuthoringContext != manifest.AuthoringContext {
		return errors.New("paired ground truth or authoring context drift")
	}
	benign, ok := benignByID[record.BenignBaseID]
	if !ok {
		return errors.New("unknown frozen benign base id")
	}
	if benign.Category != record.Family || benign.Language != record.Language {
		return errors.New("benign reference family or language mismatch")
	}
	if canonicalSemantic(benign.Prompt) == canonicalSemantic(record.Prompt) {
		return errors.New("paired malicious prompt is unchanged from benign base")
	}
	if hasRejectedMetaGroundTruthFraming(record.Prompt) {
		return errors.New("paired malicious prompt uses rejected analytical or non-execution framing")
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

func hasRejectedMetaGroundTruthFraming(prompt string) bool {
	normalized := strings.ToLower(prompt)
	for _, marker := range []string{
		"turn the otherwise legitimate",
		"state intent only",
		"provide no code, commands",
		"原本合规的场景改为恶意目的",
		"只需概述意图",
		"不要提供代码、命令或操作步骤",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// PairedRecordsAsMalicious converts externally labelled paired development
// records to the shared malicious route evaluator without changing labels.
func PairedRecordsAsMalicious(records []PairedMaliciousRecord) []MaliciousRecord {
	result := make([]MaliciousRecord, 0, len(records))
	for _, record := range records {
		result = append(result, MaliciousRecord{
			ID: record.ID, Category: record.Category, Language: record.Language, Prompt: record.Prompt,
			ExpectedDecision: record.ExpectedDecision, LabelConfidence: record.LabelConfidence,
			AuthoringContext: record.AuthoringContext,
		})
	}
	return result
}
