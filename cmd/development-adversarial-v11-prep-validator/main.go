package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

const developmentDatasetID = "development-adversarial-v11-prep"

var fixtureIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{5,95}$`)

type manifest struct {
	SchemaVersion         int      `json:"schema_version"`
	Dataset               string   `json:"dataset"`
	DevelopmentOnly       bool     `json:"development_only"`
	FutureHoldoutEligible bool     `json:"future_holdout_eligible"`
	Notice                string   `json:"notice"`
	Cases                 string   `json:"cases"`
	RequiredProtocols     []string `json:"required_protocols"`
	RequiredLanguages     []string `json:"required_languages"`
	RequiredCarriers      []string `json:"required_carriers"`
	RequiredTags          []string `json:"required_tags"`
}

type fixtureLimits struct {
	MaxScanBytes int `json:"max_scan_bytes,omitempty"`
	MaxJSONDepth int `json:"max_json_depth,omitempty"`
	MaxTextParts int `json:"max_text_parts,omitempty"`
}

func (limits fixtureLimits) production() extract.Limits {
	return extract.Limits{
		MaxScanBytes: limits.MaxScanBytes,
		MaxJSONDepth: limits.MaxJSONDepth,
		MaxTextParts: limits.MaxTextParts,
	}
}

type fixtureRecord struct {
	ID                string          `json:"id"`
	Dataset           string          `json:"dataset"`
	Label             string          `json:"label"`
	Taxonomy          string          `json:"taxonomy"`
	Language          string          `json:"language"`
	Protocol          string          `json:"protocol"`
	Carrier           string          `json:"carrier"`
	PairID            string          `json:"pair_id,omitempty"`
	Tags              []string        `json:"tags"`
	Purpose           string          `json:"purpose"`
	ExpectedSemantics []string        `json:"expected_semantics"`
	ExpectedRoleAware *bool           `json:"expected_role_aware"`
	ExpectedTruncated *bool           `json:"expected_truncated"`
	Limits            fixtureLimits   `json:"limits,omitempty"`
	Input             json.RawMessage `json:"input"`
}

type validationMetrics struct {
	Total     int
	Block     int
	Allow     int
	Audit     int
	Boundary  int
	RoleAware int
	Untrusted int
	Truncated int
	Taxonomy  map[string]int
	Protocol  map[string]int
	Language  map[string]int
	Carrier   map[string]int
	Tags      map[string]int
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	metrics, err := validateDevelopmentCorpus(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("development adversarial corpus PASS: total=%d block=%d allow=%d audit=%d boundary=%d role_aware=%d untrusted=%d truncated=%d\n",
		metrics.Total, metrics.Block, metrics.Allow, metrics.Audit, metrics.Boundary, metrics.RoleAware, metrics.Untrusted, metrics.Truncated)
}

func validateDevelopmentCorpus(root string) (validationMetrics, error) {
	directory := filepath.Join(root, "testdata", developmentDatasetID)
	manifestData, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return validationMetrics{}, fmt.Errorf("read development manifest: %w", err)
	}
	var descriptor manifest
	if err := decodeStrictJSON(manifestData, &descriptor); err != nil {
		return validationMetrics{}, fmt.Errorf("decode development manifest: %w", err)
	}
	if err := validateManifest(descriptor); err != nil {
		return validationMetrics{}, err
	}
	casePath := filepath.Clean(filepath.Join(directory, descriptor.Cases))
	if !pathWithin(directory, casePath) {
		return validationMetrics{}, errors.New("development case file escapes its dataset directory")
	}
	file, err := os.Open(casePath)
	if err != nil {
		return validationMetrics{}, fmt.Errorf("open development cases: %w", err)
	}
	defer file.Close()

	set, err := rules.LoadDefault()
	if err != nil {
		return validationMetrics{}, fmt.Errorf("load production rules: %w", err)
	}
	engine, err := classifier.New(set)
	if err != nil {
		return validationMetrics{}, fmt.Errorf("compile production classifier: %w", err)
	}

	metrics := validationMetrics{
		Taxonomy: map[string]int{}, Protocol: map[string]int{}, Language: map[string]int{},
		Carrier: map[string]int{}, Tags: map[string]int{},
	}
	ids := map[string]struct{}{}
	pairs := map[string][]fixtureRecord{}
	canonical := make([]string, 0, 64)
	records := make([]fixtureRecord, 0, 64)
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			return validationMetrics{}, fmt.Errorf("development cases line %d is blank", lineNumber)
		}
		var record fixtureRecord
		if err := decodeStrictJSON(line, &record); err != nil {
			return validationMetrics{}, fmt.Errorf("development cases line %d: %w", lineNumber, err)
		}
		if err := validateRecordSchema(record, ids); err != nil {
			return validationMetrics{}, fmt.Errorf("development case %q: %w", record.ID, err)
		}
		ids[record.ID] = struct{}{}
		if record.PairID != "" {
			pairs[record.PairID] = append(pairs[record.PairID], record)
		}

		profile, err := developmentRequestProfile(record.Protocol)
		if err != nil {
			return validationMetrics{}, fmt.Errorf("development case %q: %w", record.ID, err)
		}
		extracted, err := extract.ExtractProfiledRequest(
			record.Input,
			http.Header{"Content-Type": []string{"application/json"}},
			profile,
			record.Limits.production(),
		)
		if err != nil || extracted.ParseError != "" {
			return validationMetrics{}, fmt.Errorf("development case %q production extraction failed", record.ID)
		}
		if extracted.RoleAware != *record.ExpectedRoleAware {
			return validationMetrics{}, fmt.Errorf("development case %q role-aware=%t want %t", record.ID, extracted.RoleAware, *record.ExpectedRoleAware)
		}
		if extracted.Truncated != *record.ExpectedTruncated {
			return validationMetrics{}, fmt.Errorf("development case %q truncated=%t want %t", record.ID, extracted.Truncated, *record.ExpectedTruncated)
		}
		semanticText := extractedSemanticText(extracted)
		if record.Label != "boundary" {
			for _, expected := range record.ExpectedSemantics {
				if !strings.Contains(strings.ToLower(semanticText), strings.ToLower(expected)) {
					return validationMetrics{}, fmt.Errorf("development case %q did not recover expected semantic marker", record.ID)
				}
			}
		}
		if err := validateBoundaryFixture(record); err != nil {
			return validationMetrics{}, err
		}
		if record.Label != "boundary" {
			result := classifyExtracted(engine, extracted)
			if string(result.Action) != record.Label {
				return validationMetrics{}, fmt.Errorf("development case %q action=%s want %s", record.ID, result.Action, record.Label)
			}
			if record.Label == "block" && string(result.Category) != record.Taxonomy {
				return validationMetrics{}, fmt.Errorf("development case %q taxonomy=%s want %s", record.ID, result.Category, record.Taxonomy)
			}
			if record.Label != "block" && result.Action == classifier.ActionBlock {
				return validationMetrics{}, fmt.Errorf("development case %q unexpectedly blocked", record.ID)
			}
		}

		metrics.Total++
		metrics.Taxonomy[record.Taxonomy]++
		metrics.Protocol[record.Protocol]++
		metrics.Language[record.Language]++
		metrics.Carrier[record.Carrier]++
		for _, tag := range record.Tags {
			metrics.Tags[tag]++
		}
		switch record.Label {
		case "block":
			metrics.Block++
		case "allow":
			metrics.Allow++
		case "audit":
			metrics.Audit++
		case "boundary":
			metrics.Boundary++
		}
		if extracted.RoleAware {
			metrics.RoleAware++
		} else {
			metrics.Untrusted++
		}
		if extracted.Truncated {
			metrics.Truncated++
		}
		canonical = append(canonical, canonicalSemantic(semanticText))
		records = append(records, record)
	}
	if err := scanner.Err(); err != nil {
		return validationMetrics{}, fmt.Errorf("scan development cases: %w", err)
	}
	if err := validateCorpusAggregates(descriptor, records, canonical, pairs, metrics); err != nil {
		return validationMetrics{}, err
	}
	return metrics, nil
}

func developmentRequestProfile(protocol string) (extract.RequestProfile, error) {
	switch protocol {
	case "openai_chat":
		return extract.RequestProfile{Source: extract.SourceProfileOpenAI}, nil
	case "openai_responses":
		return extract.RequestProfile{Source: extract.SourceProfileOpenAIResponse}, nil
	case "anthropic_messages":
		return extract.RequestProfile{Source: extract.SourceProfileClaude}, nil
	case "gemini":
		return extract.RequestProfile{Source: extract.SourceProfileGemini}, nil
	default:
		return extract.RequestProfile{}, fmt.Errorf("unsupported production protocol %q", protocol)
	}
}

func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err == io.EOF {
		return nil
	} else if err != nil {
		return err
	}
	return errors.New("multiple JSON values")
}

func validateManifest(value manifest) error {
	if value.SchemaVersion != 2 || value.Dataset != developmentDatasetID || !value.DevelopmentOnly || value.FutureHoldoutEligible {
		return errors.New("development manifest identity or holdout prohibition is invalid")
	}
	if value.Cases == "" || !strings.Contains(strings.ToLower(value.Notice), "never") || !strings.Contains(strings.ToLower(value.Notice), "holdout") {
		return errors.New("development manifest must explicitly prohibit future holdout reuse")
	}
	for label, values := range map[string][]string{
		"protocols": value.RequiredProtocols, "languages": value.RequiredLanguages,
		"carriers": value.RequiredCarriers, "tags": value.RequiredTags,
	} {
		if len(values) == 0 {
			return fmt.Errorf("development manifest required_%s is empty", label)
		}
		seen := map[string]struct{}{}
		for _, item := range values {
			if item == "" {
				return fmt.Errorf("development manifest required_%s contains an empty value", label)
			}
			if _, duplicate := seen[item]; duplicate {
				return fmt.Errorf("development manifest required_%s duplicates %q", label, item)
			}
			seen[item] = struct{}{}
		}
	}
	return nil
}

func validateRecordSchema(record fixtureRecord, ids map[string]struct{}) error {
	if !fixtureIDPattern.MatchString(record.ID) {
		return errors.New("invalid ID")
	}
	if _, duplicate := ids[record.ID]; duplicate {
		return errors.New("duplicate ID")
	}
	if record.Dataset != developmentDatasetID {
		return errors.New("record is not marked with the development-only dataset identity")
	}
	if _, ok := map[string]struct{}{"allow": {}, "audit": {}, "block": {}, "boundary": {}}[record.Label]; !ok {
		return errors.New("invalid label")
	}
	validTaxonomy := map[string]struct{}{"benign": {}}
	for _, category := range []rules.Category{
		rules.CategoryCredentialTheft, rules.CategoryPhishing, rules.CategoryMalware, rules.CategoryRansomware,
		rules.CategoryExploitation, rules.CategoryDisruption, rules.CategoryExfiltration, rules.CategoryEvasion,
	} {
		validTaxonomy[string(category)] = struct{}{}
	}
	if _, ok := validTaxonomy[record.Taxonomy]; !ok {
		return errors.New("invalid taxonomy enum")
	}
	if record.Label == "block" && record.Taxonomy == "benign" {
		return errors.New("blocked decision is missing a cyber taxonomy")
	}
	if record.Label != "block" && record.Taxonomy != "benign" {
		return errors.New("non-block decision must use benign taxonomy")
	}
	if record.Language != "en" && record.Language != "zh-CN" && record.Language != "mixed" {
		return errors.New("invalid language enum")
	}
	if record.Protocol == "" || record.Carrier == "" || len(record.Purpose) < 12 || len(record.ExpectedSemantics) == 0 || record.ExpectedRoleAware == nil || record.ExpectedTruncated == nil {
		return errors.New("required metadata is missing")
	}
	if len(record.Tags) == 0 {
		return errors.New("tags are empty")
	}
	seenTags := map[string]struct{}{}
	for _, tag := range record.Tags {
		if tag == "" {
			return errors.New("empty tag")
		}
		if _, duplicate := seenTags[tag]; duplicate {
			return errors.New("duplicate tag")
		}
		seenTags[tag] = struct{}{}
	}
	input := bytes.TrimSpace(record.Input)
	if len(input) < 2 || input[0] != '{' || input[len(input)-1] != '}' || !json.Valid(input) {
		return errors.New("input must be one valid production-style JSON object")
	}
	return nil
}

func classifyExtracted(engine *classifier.Classifier, extracted extract.Result) classifier.Result {
	if extracted.RoleAware {
		return engine.ClassifySegmentsWithPolicy(extracted.Segments, classifier.ModeBalanced, classifier.DefaultThresholds(), classifier.DefaultPolicy())
	}
	return engine.ClassifyUntrustedPartsWithPolicy(extracted.Parts, classifier.ModeBalanced, classifier.DefaultThresholds(), classifier.DefaultPolicy())
}

func extractedSemanticText(result extract.Result) string {
	values := make([]string, 0, len(result.Parts)+len(result.Segments))
	values = append(values, result.Parts...)
	for _, segment := range result.Segments {
		values = append(values, segment.Text)
	}
	return strings.Join(values, "\n")
}

func validateBoundaryFixture(record fixtureRecord) error {
	hasTag := func(want string) bool {
		for _, tag := range record.Tags {
			if tag == want {
				return true
			}
		}
		return false
	}
	if hasTag("boundary_max_parts") && (record.Limits.MaxTextParts == 0 || !*record.ExpectedTruncated) {
		return fmt.Errorf("development case %q does not exercise the max-parts boundary", record.ID)
	}
	if hasTag("boundary_scan_budget") {
		headroom := record.Limits.MaxScanBytes - len(record.Input)
		if record.Limits.MaxScanBytes == 0 || headroom < 0 || headroom > 64 || *record.ExpectedTruncated {
			return fmt.Errorf("development case %q is not within 64 bytes of the scan budget", record.ID)
		}
	}
	if hasTag("legacy_window_alias") && (record.Limits.MaxScanBytes == 0 || len(record.Input) <= record.Limits.MaxScanBytes || *record.ExpectedTruncated || !*record.ExpectedRoleAware) {
		return fmt.Errorf("development case %q does not verify full coverage across the legacy window alias", record.ID)
	}
	return nil
}

func validateCorpusAggregates(descriptor manifest, records []fixtureRecord, canonical []string, pairs map[string][]fixtureRecord, metrics validationMetrics) error {
	if len(records) < 32 || metrics.Block < 8 || metrics.Allow < 8 || metrics.Audit < 8 || metrics.Boundary < 3 {
		return errors.New("development corpus classification balance is invalid")
	}
	allowedProtocols := stringSet(descriptor.RequiredProtocols)
	allowedLanguages := stringSet(descriptor.RequiredLanguages)
	allowedCarriers := stringSet(descriptor.RequiredCarriers)
	for _, record := range records {
		if _, ok := allowedProtocols[record.Protocol]; !ok {
			return fmt.Errorf("development case %q has unexpected protocol %q", record.ID, record.Protocol)
		}
		if _, ok := allowedLanguages[record.Language]; !ok {
			return fmt.Errorf("development case %q has unexpected language %q", record.ID, record.Language)
		}
		if _, ok := allowedCarriers[record.Carrier]; !ok {
			return fmt.Errorf("development case %q has unexpected carrier %q", record.ID, record.Carrier)
		}
	}
	for _, taxonomy := range []string{
		string(rules.CategoryCredentialTheft), string(rules.CategoryPhishing), string(rules.CategoryMalware), string(rules.CategoryRansomware),
		string(rules.CategoryExploitation), string(rules.CategoryDisruption), string(rules.CategoryExfiltration), string(rules.CategoryEvasion),
	} {
		count := 0
		for _, record := range records {
			if record.Label == "block" && record.Taxonomy == taxonomy {
				count++
			}
		}
		if count < 1 {
			return fmt.Errorf("development corpus taxonomy %s has %d blocked cases, want at least 1 current-user case", taxonomy, count)
		}
	}
	for label, required := range map[string][]string{
		"protocol": descriptor.RequiredProtocols, "language": descriptor.RequiredLanguages,
		"carrier": descriptor.RequiredCarriers, "tag": descriptor.RequiredTags,
	} {
		actual := map[string]int{}
		switch label {
		case "protocol":
			actual = metrics.Protocol
		case "language":
			actual = metrics.Language
		case "carrier":
			actual = metrics.Carrier
		case "tag":
			actual = metrics.Tags
		}
		for _, item := range required {
			if actual[item] == 0 {
				return fmt.Errorf("development corpus required %s %q is uncovered", label, item)
			}
		}
	}
	if metrics.RoleAware == 0 || metrics.Untrusted == 0 {
		return errors.New("development corpus must cover role-aware and untrusted extraction")
	}
	for pairID, members := range pairs {
		if len(members) != 2 || members[0].Label == members[1].Label {
			return fmt.Errorf("development contrast pair %q must contain exactly two different labels", pairID)
		}
	}
	for left := range canonical {
		if records[left].Label == "boundary" {
			continue
		}
		if canonical[left] == "" {
			return fmt.Errorf("development case %q canonical semantic text is empty", records[left].ID)
		}
		for right := left + 1; right < len(canonical); right++ {
			if records[right].Label == "boundary" {
				continue
			}
			if canonical[left] == canonical[right] {
				return fmt.Errorf("development cases %q and %q are semantic duplicates", records[left].ID, records[right].ID)
			}
			similarity := shingleSimilarity(canonical[left], canonical[right])
			if similarity < 0.92 {
				continue
			}
			intentionalContrast := records[left].PairID != "" && records[left].PairID == records[right].PairID && records[left].Label != records[right].Label
			if !intentionalContrast {
				return fmt.Errorf("development cases %q and %q are unmarked near-duplicates (%.3f)", records[left].ID, records[right].ID, similarity)
			}
		}
	}
	return nil
}

func stringSet(values []string) map[string]struct{} {
	result := make(map[string]struct{}, len(values))
	for _, value := range values {
		result[value] = struct{}{}
	}
	return result
}

func canonicalSemantic(value string) string {
	var builder strings.Builder
	space := true
	for _, r := range strings.ToLower(value) {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			builder.WriteRune(r)
			space = false
		} else if !space {
			builder.WriteByte(' ')
			space = true
		}
	}
	return strings.TrimSpace(builder.String())
}

func shingleSimilarity(left, right string) float64 {
	leftSet := wordShingles(left, 3)
	rightSet := wordShingles(right, 3)
	if len(leftSet) == 0 || len(rightSet) == 0 {
		return 0
	}
	intersection := 0
	for item := range leftSet {
		if _, ok := rightSet[item]; ok {
			intersection++
		}
	}
	union := len(leftSet) + len(rightSet) - intersection
	return float64(intersection) / float64(union)
}

func wordShingles(value string, size int) map[string]struct{} {
	words := strings.Fields(value)
	result := map[string]struct{}{}
	if len(words) < size {
		if len(words) != 0 {
			result[strings.Join(words, " ")] = struct{}{}
		}
		return result
	}
	for index := 0; index+size <= len(words); index++ {
		result[strings.Join(words[index:index+size], " ")] = struct{}{}
	}
	return result
}

func pathWithin(parent, child string) bool {
	relative, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}
