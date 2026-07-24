// Package round9corpus contains the strict, test-only contracts used by the
// Round 9 development and independently frozen corpora. It deliberately keeps
// semantic base requests separate from protocol/carrier route executions.
package round9corpus

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

const (
	ExpectedBenignDisposition = "allow_or_audit"
	LanguageChinese           = "zh"
	LanguageEnglish           = "en"
)

var (
	BaseCategories = []string{
		"ordinary_coding_refactor",
		"os_operations",
		"oauth_token_api_key_lifecycle",
		"enterprise_credential_lifecycle",
		"siem_edr_ids_log_analysis",
		"sigma_yara_ioc_detection",
		"malware_static_analysis",
		"forensics_incident_response",
		"security_education_quote_translation",
		"ctf_isolated_lab",
		"load_capacity_chaos_recovery",
		"enterprise_remote_management_agent",
		"inert_carriers_history",
		"long_context_risk_vocabulary",
		"mixed_zh_en_colloquial",
	}

	recordIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{5,127}$`)
)

// FileIdentity freezes one corpus file before candidate execution.
type FileIdentity struct {
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// CategoryCount records semantic sample distribution, never route execution
// counts.
type CategoryCount struct {
	Total int `json:"total"`
	ZH    int `json:"zh"`
	EN    int `json:"en"`
}

// ManifestCounts is the closed distribution contract shared by Round 9 base
// request corpora.
type ManifestCounts struct {
	Total      int                      `json:"total"`
	Languages  map[string]int           `json:"languages"`
	Categories map[string]CategoryCount `json:"categories"`
}

// GenerationBoundary is intentionally bounded metadata. It proves the
// authoring declaration without embedding prompts or arbitrary fields.
type GenerationBoundary struct {
	IndependentlyAuthoredBeforeCandidateExecution bool   `json:"independently_authored_before_candidate_execution"`
	SourceCodeRead                                bool   `json:"source_code_read"`
	RulesRead                                     bool   `json:"rules_read"`
	ExistingDevelopmentCorporaRead                bool   `json:"existing_development_corpora_read"`
	ExistingRestrictedContentRead                 bool   `json:"existing_holdout_evaluation_private_retired_content_read"`
	CandidateOutputObserved                       bool   `json:"candidate_output_observed"`
	ClassifierOrProjectTestsRun                   bool   `json:"classifier_or_project_tests_run"`
	SemanticPolicy                                string `json:"semantic_policy"`
	SafetyPolicy                                  string `json:"safety_policy"`
}

// ManifestSchema documents the exact JSONL fields and language enum.
type ManifestSchema struct {
	FileFormat     string   `json:"file_format"`
	Fields         []string `json:"fields"`
	LanguageValues []string `json:"language_values"`
}

// Manifest is the closed Round 9 semantic-base corpus descriptor.
type Manifest struct {
	Name                string                  `json:"name"`
	Version             int                     `json:"version"`
	GeneratedAt         string                  `json:"generated_at"`
	AuthoringContext    string                  `json:"authoring_context"`
	ExpectedDisposition string                  `json:"expected_disposition"`
	GenerationBoundary  GenerationBoundary      `json:"generation_boundary"`
	Schema              ManifestSchema          `json:"schema"`
	Counts              ManifestCounts          `json:"counts"`
	Files               map[string]FileIdentity `json:"files"`
}

// BaseRecord is one semantically unique request. Protocol, stream, wrapper,
// role, and carrier variants are generated later and never counted here.
type BaseRecord struct {
	ID                  string `json:"id"`
	Category            string `json:"category"`
	Language            string `json:"language"`
	Prompt              string `json:"prompt"`
	ExpectedDisposition string `json:"expected_disposition"`
	AuthoringContext    string `json:"authoring_context"`
}

// LoadOptions binds the expected frozen identity and distribution.
type LoadOptions struct {
	Name                string
	AuthoringContext    string
	ExpectedDisposition string
	ExpectedTotal       int
	ExpectedPerCategory int
	ExpectedPerLanguage int
	Independent         bool
}

// LoadedCorpus is returned only after byte identity, schema, distribution,
// and semantic uniqueness checks all pass.
type LoadedCorpus struct {
	Manifest Manifest
	Records  []BaseRecord
}

// Load validates manifest.json and cases.jsonl without modifying either file.
func Load(directory string, options LoadOptions) (LoadedCorpus, error) {
	if err := validateLoadOptions(options); err != nil {
		return LoadedCorpus{}, err
	}
	directory = filepath.Clean(directory)
	manifestData, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return LoadedCorpus{}, fmt.Errorf("read manifest: %w", err)
	}
	var manifest Manifest
	if err := decodeStrictJSON(manifestData, &manifest); err != nil {
		return LoadedCorpus{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := validateManifest(manifest, options); err != nil {
		return LoadedCorpus{}, err
	}
	identity, ok := manifest.Files["cases.jsonl"]
	if !ok || len(manifest.Files) != 1 {
		return LoadedCorpus{}, errors.New("manifest files must contain only cases.jsonl")
	}
	casePath := filepath.Join(directory, "cases.jsonl")
	caseData, err := os.ReadFile(casePath)
	if err != nil {
		return LoadedCorpus{}, fmt.Errorf("read cases: %w", err)
	}
	if err := verifyIdentity(caseData, identity); err != nil {
		return LoadedCorpus{}, fmt.Errorf("cases.jsonl identity: %w", err)
	}
	records, err := decodeRecords(caseData, manifest, options)
	if err != nil {
		return LoadedCorpus{}, err
	}
	return LoadedCorpus{Manifest: manifest, Records: records}, nil
}

func validateLoadOptions(options LoadOptions) error {
	if options.Name == "" || options.AuthoringContext == "" || options.ExpectedDisposition == "" {
		return errors.New("load options must bind name, authoring context, and disposition")
	}
	if options.ExpectedTotal <= 0 || options.ExpectedPerCategory <= 0 || options.ExpectedPerLanguage <= 0 {
		return errors.New("load options must bind positive corpus counts")
	}
	if options.ExpectedTotal != len(BaseCategories)*options.ExpectedPerCategory ||
		options.ExpectedPerCategory != 2*options.ExpectedPerLanguage {
		return errors.New("load option totals do not match the 15-category bilingual contract")
	}
	return nil
}

func validateManifest(manifest Manifest, options LoadOptions) error {
	if manifest.Name != options.Name || manifest.Version != 1 || manifest.AuthoringContext != options.AuthoringContext ||
		manifest.ExpectedDisposition != options.ExpectedDisposition {
		return errors.New("manifest identity does not match the frozen load contract")
	}
	if strings.TrimSpace(manifest.GeneratedAt) == "" {
		return errors.New("manifest generated_at is empty")
	}
	if manifest.Schema.FileFormat != "jsonl" ||
		!equalStrings(manifest.Schema.Fields, []string{"id", "category", "language", "prompt", "expected_disposition", "authoring_context"}) ||
		!equalStrings(manifest.Schema.LanguageValues, []string{LanguageChinese, LanguageEnglish}) {
		return errors.New("manifest schema drift")
	}
	if manifest.Counts.Total != options.ExpectedTotal || len(manifest.Counts.Languages) != 2 ||
		manifest.Counts.Languages[LanguageChinese] != options.ExpectedTotal/2 ||
		manifest.Counts.Languages[LanguageEnglish] != options.ExpectedTotal/2 {
		return errors.New("manifest language totals drift")
	}
	if len(manifest.Counts.Categories) != len(BaseCategories) {
		return errors.New("manifest category set drift")
	}
	for _, category := range BaseCategories {
		count, ok := manifest.Counts.Categories[category]
		if !ok || count.Total != options.ExpectedPerCategory || count.ZH != options.ExpectedPerLanguage || count.EN != options.ExpectedPerLanguage {
			return fmt.Errorf("manifest category %s distribution drift", category)
		}
	}
	boundary := manifest.GenerationBoundary
	if options.Independent {
		if !boundary.IndependentlyAuthoredBeforeCandidateExecution || boundary.SourceCodeRead || boundary.RulesRead ||
			boundary.ExistingDevelopmentCorporaRead || boundary.ExistingRestrictedContentRead || boundary.CandidateOutputObserved ||
			boundary.ClassifierOrProjectTestsRun {
			return errors.New("independent authoring boundary is not closed")
		}
	}
	if len(strings.TrimSpace(boundary.SemanticPolicy)) < 24 || len(strings.TrimSpace(boundary.SafetyPolicy)) < 24 {
		return errors.New("manifest authoring policies are incomplete")
	}
	return nil
}

func verifyIdentity(data []byte, identity FileIdentity) error {
	if identity.Bytes < 0 || int64(len(data)) != identity.Bytes {
		return fmt.Errorf("bytes=%d want %d", len(data), identity.Bytes)
	}
	if len(identity.SHA256) != sha256.Size*2 || strings.ToLower(identity.SHA256) != identity.SHA256 {
		return errors.New("sha256 must be lowercase hexadecimal")
	}
	if _, err := hex.DecodeString(identity.SHA256); err != nil {
		return errors.New("sha256 is not hexadecimal")
	}
	actual := sha256.Sum256(data)
	if hex.EncodeToString(actual[:]) != identity.SHA256 {
		return fmt.Errorf("sha256=%s want %s", hex.EncodeToString(actual[:]), identity.SHA256)
	}
	return nil
}

func decodeRecords(data []byte, manifest Manifest, options LoadOptions) ([]BaseRecord, error) {
	records := make([]BaseRecord, 0, options.ExpectedTotal)
	ids := make(map[string]int, options.ExpectedTotal)
	canonical := make(map[string]int, options.ExpectedTotal)
	categoryCounts := make(map[string]CategoryCount, len(BaseCategories))
	languageCounts := map[string]int{LanguageChinese: 0, LanguageEnglish: 0}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	for scanner.Scan() {
		lineNumber := len(records) + 1
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			return nil, fmt.Errorf("cases line %d is blank", lineNumber)
		}
		var record BaseRecord
		if err := decodeStrictJSON(line, &record); err != nil {
			return nil, fmt.Errorf("cases line %d: %w", lineNumber, err)
		}
		if err := validateRecord(record, manifest, options, ids); err != nil {
			return nil, fmt.Errorf("case %q: %w", record.ID, err)
		}
		key := canonicalSemantic(record.Prompt)
		if previous, duplicate := canonical[key]; duplicate {
			return nil, fmt.Errorf("case %q semantically duplicates line %d", record.ID, previous)
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
		return nil, fmt.Errorf("scan cases: %w", err)
	}
	if len(records) != options.ExpectedTotal {
		return nil, fmt.Errorf("semantic base requests=%d want %d", len(records), options.ExpectedTotal)
	}
	for _, category := range BaseCategories {
		got := categoryCounts[category]
		want := manifest.Counts.Categories[category]
		if got != want {
			return nil, fmt.Errorf("category %s count=%+v want %+v", category, got, want)
		}
	}
	for language, want := range manifest.Counts.Languages {
		if languageCounts[language] != want {
			return nil, fmt.Errorf("language %s count=%d want %d", language, languageCounts[language], want)
		}
	}
	if err := rejectNearDuplicates(records); err != nil {
		return nil, err
	}
	return records, nil
}

func validateRecord(record BaseRecord, manifest Manifest, options LoadOptions, ids map[string]int) error {
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
	if record.ExpectedDisposition != options.ExpectedDisposition || record.AuthoringContext != options.AuthoringContext {
		return errors.New("ground truth or authoring context drift")
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

func rejectNearDuplicates(records []BaseRecord) error {
	canonical := make([]string, len(records))
	shingles := make([]map[string]struct{}, len(records))
	for index, record := range records {
		canonical[index] = canonicalSemantic(record.Prompt)
		shingles[index] = semanticShingles(canonical[index])
	}
	for left := range records {
		for right := left + 1; right < len(records); right++ {
			if records[left].Language != records[right].Language {
				continue
			}
			similarity := jaccard(shingles[left], shingles[right])
			if similarity >= 0.90 {
				return fmt.Errorf("cases %q and %q are unmarked near-duplicates (%.3f)", records[left].ID, records[right].ID, similarity)
			}
		}
	}
	return nil
}

func canonicalSemantic(value string) string {
	var builder strings.Builder
	spacePending := false
	for _, r := range strings.ToLower(strings.TrimSpace(value)) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) {
			if spacePending && builder.Len() > 0 {
				builder.WriteByte(' ')
			}
			builder.WriteRune(r)
			spacePending = false
			continue
		}
		spacePending = true
	}
	return strings.TrimSpace(builder.String())
}

func semanticShingles(value string) map[string]struct{} {
	words := strings.Fields(value)
	if len(words) >= 6 {
		return stringShingles(words, 3)
	}
	runes := []rune(strings.ReplaceAll(value, " ", ""))
	items := make([]string, len(runes))
	for index, r := range runes {
		items[index] = string(r)
	}
	return stringShingles(items, 5)
}

func stringShingles(items []string, size int) map[string]struct{} {
	result := make(map[string]struct{})
	if len(items) < size {
		if len(items) > 0 {
			result[strings.Join(items, "\x00")] = struct{}{}
		}
		return result
	}
	for index := 0; index+size <= len(items); index++ {
		result[strings.Join(items[index:index+size], "\x00")] = struct{}{}
	}
	return result
}

func jaccard(left, right map[string]struct{}) float64 {
	if len(left) == 0 || len(right) == 0 {
		return 0
	}
	intersection := 0
	for item := range left {
		if _, ok := right[item]; ok {
			intersection++
		}
	}
	return float64(intersection) / float64(len(left)+len(right)-intersection)
}

func decodeStrictJSON(data []byte, destination any) error {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := consumeJSONValue(decoder, "$", 0); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder, path string, depth int) error {
	if depth > 32 {
		return fmt.Errorf("JSON nesting exceeds limit at %s", path)
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key at %s is not a string", path)
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate key %q at %s", key, path)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder, path+"/"+key, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("invalid object close at %s", path)
		}
	case '[':
		for index := 0; decoder.More(); index++ {
			if err := consumeJSONValue(decoder, fmt.Sprintf("%s/%d", path, index), depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("invalid array close at %s", path)
		}
	default:
		return fmt.Errorf("unexpected delimiter %q at %s", delimiter, path)
	}
	return nil
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

// SortedCategoryCounts returns a stable copy useful for JSON reports.
func SortedCategoryCounts(counts map[string]int) []struct {
	Category string `json:"category"`
	Count    int    `json:"count"`
} {
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]struct {
		Category string `json:"category"`
		Count    int    `json:"count"`
	}, 0, len(keys))
	for _, key := range keys {
		result = append(result, struct {
			Category string `json:"category"`
			Count    int    `json:"count"`
		}{Category: key, Count: counts[key]})
	}
	return result
}
