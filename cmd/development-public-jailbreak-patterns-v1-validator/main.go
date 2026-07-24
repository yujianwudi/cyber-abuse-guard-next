package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/extract"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

const developmentDatasetID = "development-public-jailbreak-patterns-v1"

var (
	caseIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{5,95}$`)
	urlPattern    = regexp.MustCompile(`(?i)\b(?:https?|ftp)://`)
	ipv4Pattern   = regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`)

	canonicalDevelopmentFiles = []string{
		"README.md",
		"cases.jsonl",
		"manifest.json",
	}
	canonicalDevelopmentFamilies = []string{
		"hierarchy",
		"refusal_suppression",
		"unrestricted_mode",
		"direct_completion",
		"scope_laundering",
		"output_control",
		"secret_disclosure",
		"negative_authorization",
		"benchmark_coercion",
		"persistent_instruction_injection",
		"persona_takeover",
		"agentic_execution_escalation",
	}
	canonicalDevelopmentProtocols = []string{
		"openai_chat",
		"openai_responses",
		"anthropic_messages",
		"gemini",
		"generic_future",
	}
	canonicalDevelopmentCarriers = []string{
		"openai_chat_plain",
		"openai_chat_content_parts",
		"openai_chat_tool_arguments",
		"openai_chat_multi_turn",
		"openai_responses_instructions",
		"openai_responses_input",
		"openai_responses_function_call",
		"anthropic_messages_plain",
		"anthropic_tool_use",
		"gemini_contents_plain",
		"gemini_function_call",
		"tool_output",
		"nested_tool_json",
		"unknown_future_envelope",
	}
	canonicalDevelopmentTransforms = []string{
		"plain",
		"nfkc",
		"zero_width",
		"homoglyph",
		"leet",
		"punctuation_split",
		"parts_split",
		"json_unicode",
		"html_entity",
		"percent_encoding",
		"base64",
		"nested_json",
		"bilingual",
		"adjacent_turns",
		"mixed_roles",
		"semantic_alias",
		"override_concealment",
		"filter_boundary_split",
		"html_comment_modules",
	}
	canonicalDevelopmentSourceContexts = []string{
		"request_body",
		"local_model_instructions",
		"managed_agents",
		"skill_mcp",
		"remote_template_cache",
	}
)

type manifest struct {
	SchemaVersion                        int      `json:"schema_version"`
	Dataset                              string   `json:"dataset"`
	DevelopmentOnly                      bool     `json:"development_only"`
	FutureHoldoutEligible                bool     `json:"future_holdout_eligible"`
	DerivedFromPublicAdversarialTaxonomy bool     `json:"derived_from_public_adversarial_taxonomy"`
	ContainsLivePayloads                 bool     `json:"contains_live_payloads"`
	Notice                               string   `json:"notice"`
	Cases                                string   `json:"cases"`
	RequiredFamilies                     []string `json:"required_families"`
	RequiredProtocols                    []string `json:"required_protocols"`
	RequiredCarriers                     []string `json:"required_carriers"`
	RequiredTransforms                   []string `json:"required_transforms"`
	RequiredSourceContexts               []string `json:"required_source_contexts"`
}

type fixtureRecord struct {
	ID                string          `json:"id"`
	Dataset           string          `json:"dataset"`
	Family            string          `json:"family"`
	Label             string          `json:"label"`
	Protocol          string          `json:"protocol"`
	Carrier           string          `json:"carrier"`
	Transform         string          `json:"transform"`
	SourceContext     string          `json:"source_context,omitempty"`
	PairID            string          `json:"pair_id"`
	Purpose           string          `json:"purpose"`
	HarmlessCanary    bool            `json:"harmless_canary"`
	ExpectedEvidence  []string        `json:"expected_evidence,omitempty"`
	ExpectedRoleAware *bool           `json:"expected_role_aware"`
	Input             json.RawMessage `json:"input"`
}

type validationMetrics struct {
	Total          int
	Allow          int
	Audit          int
	RoleAware      int
	Untrusted      int
	Families       map[string]int
	Protocols      map[string]int
	Carriers       map[string]int
	Transforms     map[string]int
	SourceContexts map[string]int
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	metrics, err := validateDevelopmentCorpus(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("development public jailbreak patterns PASS: total=%d allow=%d audit=%d role_aware=%d untrusted=%d\n",
		metrics.Total, metrics.Allow, metrics.Audit, metrics.RoleAware, metrics.Untrusted)
}

func validateDevelopmentCorpus(root string) (validationMetrics, error) {
	directory := filepath.Join(root, "testdata", developmentDatasetID)
	if err := validateCorpusDirectory(directory); err != nil {
		return validationMetrics{}, err
	}
	corpusFiles := make(map[string][]byte, len(canonicalDevelopmentFiles))
	for _, name := range canonicalDevelopmentFiles {
		data, err := os.ReadFile(filepath.Join(directory, name))
		if err != nil {
			return validationMetrics{}, fmt.Errorf("read development corpus file %s: %w", name, err)
		}
		if err := validateCorpusSafety(data); err != nil {
			return validationMetrics{}, fmt.Errorf("development corpus file %s: %w", name, err)
		}
		corpusFiles[name] = data
	}
	manifestData := corpusFiles["manifest.json"]
	if err := validateDecodedJSONSafety(manifestData); err != nil {
		return validationMetrics{}, fmt.Errorf("development manifest decoded content: %w", err)
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
	rawCases := corpusFiles[descriptor.Cases]

	set, err := rules.LoadDefault()
	if err != nil {
		return validationMetrics{}, fmt.Errorf("load production rules: %w", err)
	}
	engine, err := classifier.New(set)
	if err != nil {
		return validationMetrics{}, fmt.Errorf("compile production classifier: %w", err)
	}

	metrics := validationMetrics{
		Families: map[string]int{}, Protocols: map[string]int{},
		Carriers: map[string]int{}, Transforms: map[string]int{},
		SourceContexts: map[string]int{},
	}
	ids := map[string]struct{}{}
	pairs := map[string][]fixtureRecord{}
	scanner := bufio.NewScanner(bytes.NewReader(rawCases))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
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
		if err := validateRecord(record, ids, descriptor); err != nil {
			return validationMetrics{}, fmt.Errorf("development case %q: %w", record.ID, err)
		}
		if err := validateDecodedJSONSafety(line); err != nil {
			return validationMetrics{}, fmt.Errorf("development case %q decoded record: %w", record.ID, err)
		}
		ids[record.ID] = struct{}{}
		pairs[record.PairID] = append(pairs[record.PairID], record)

		extracted, err := extract.ExtractText(record.Input, extract.Limits{})
		if err != nil || !extracted.IsComplete() {
			return validationMetrics{}, fmt.Errorf("development case %q production extraction is incomplete", record.ID)
		}
		if extracted.RoleAware != *record.ExpectedRoleAware {
			return validationMetrics{}, fmt.Errorf("development case %q role-aware=%t want %t", record.ID, extracted.RoleAware, *record.ExpectedRoleAware)
		}
		if err := validateCorpusSafety([]byte(extractedSemanticText(extracted))); err != nil {
			return validationMetrics{}, fmt.Errorf("development case %q recovered semantics: %w", record.ID, err)
		}
		result := classifyExtracted(engine, extracted)
		if string(result.Action) != record.Label {
			return validationMetrics{}, fmt.Errorf("development case %q action=%s want %s", record.ID, result.Action, record.Label)
		}
		if result.Category != "" || result.Behavior != nil && result.Behavior.BaseBehavior {
			return validationMetrics{}, fmt.Errorf("development case %q unexpectedly produced cyber-abuse taxonomy %q", record.ID, result.Category)
		}
		if record.Label == "audit" && (result.Behavior == nil || !result.Behavior.Wrapper) {
			return validationMetrics{}, fmt.Errorf("development case %q did not retain a control-plane wrapper", record.ID)
		}
		for _, expected := range record.ExpectedEvidence {
			if !hasEvidence(result.Evidence, expected) {
				return validationMetrics{}, fmt.Errorf("development case %q missing fixed evidence %q", record.ID, expected)
			}
		}

		metrics.Total++
		metrics.Families[record.Family]++
		metrics.Protocols[record.Protocol]++
		metrics.Carriers[record.Carrier]++
		metrics.Transforms[record.Transform]++
		metrics.SourceContexts[effectiveSourceContext(record)]++
		if record.Label == "allow" {
			metrics.Allow++
		} else {
			metrics.Audit++
		}
		if extracted.RoleAware {
			metrics.RoleAware++
		} else {
			metrics.Untrusted++
		}
	}
	if err := scanner.Err(); err != nil {
		return validationMetrics{}, fmt.Errorf("scan development cases: %w", err)
	}
	if err := validateAggregates(descriptor, pairs, metrics); err != nil {
		return validationMetrics{}, err
	}
	return metrics, nil
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
	if value.SchemaVersion != 1 || value.Dataset != developmentDatasetID ||
		!value.DevelopmentOnly || value.FutureHoldoutEligible ||
		!value.DerivedFromPublicAdversarialTaxonomy || value.ContainsLivePayloads {
		return errors.New("development manifest identity, provenance, payload, or holdout flags are invalid")
	}
	notice := strings.ToLower(value.Notice)
	if value.Cases != "cases.jsonl" || !strings.Contains(notice, "never") || !strings.Contains(notice, "holdout") || !strings.Contains(notice, "development") {
		return errors.New("development manifest must explicitly prohibit future holdout reuse")
	}
	for _, check := range []struct {
		label     string
		actual    []string
		canonical []string
	}{
		{label: "required_families", actual: value.RequiredFamilies, canonical: canonicalDevelopmentFamilies},
		{label: "required_protocols", actual: value.RequiredProtocols, canonical: canonicalDevelopmentProtocols},
		{label: "required_carriers", actual: value.RequiredCarriers, canonical: canonicalDevelopmentCarriers},
		{label: "required_transforms", actual: value.RequiredTransforms, canonical: canonicalDevelopmentTransforms},
		{label: "required_source_contexts", actual: value.RequiredSourceContexts, canonical: canonicalDevelopmentSourceContexts},
	} {
		if err := validateExactEnums(check.label, check.actual, check.canonical); err != nil {
			return err
		}
	}
	return nil
}

func validateCorpusDirectory(directory string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect development corpus directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("development corpus path must be a real directory")
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("list development corpus directory: %w", err)
	}
	expected := enumSet(canonicalDevelopmentFiles)
	if len(entries) != len(expected) {
		return errors.New("development corpus directory must contain exactly the approved files")
	}
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if _, approved := expected[entry.Name()]; !approved {
			return errors.New("development corpus directory contains an unapproved file")
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("development corpus files must not be symbolic links")
		}
		entryInfo, err := entry.Info()
		if err != nil {
			return fmt.Errorf("inspect development corpus file: %w", err)
		}
		if !entryInfo.Mode().IsRegular() {
			return errors.New("development corpus entries must be regular files")
		}
		seen[entry.Name()] = struct{}{}
	}
	for name := range expected {
		if _, present := seen[name]; !present {
			return errors.New("development corpus directory is missing an approved file")
		}
	}
	return nil
}

func validateExactEnums(label string, actual, canonical []string) error {
	if err := validateUniqueEnums(label, actual); err != nil {
		return err
	}
	actualSet := enumSet(actual)
	canonicalSet := enumSet(canonical)
	if len(actualSet) != len(canonicalSet) {
		return fmt.Errorf("development manifest %s must match the canonical exact set", label)
	}
	for value := range canonicalSet {
		if _, present := actualSet[value]; !present {
			return fmt.Errorf("development manifest %s must match the canonical exact set", label)
		}
	}
	return nil
}

func enumSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func validateUniqueEnums(label string, values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("development manifest %s is empty", label)
	}
	seen := map[string]struct{}{}
	for _, value := range values {
		if value == "" {
			return fmt.Errorf("development manifest %s contains an empty value", label)
		}
		if _, duplicate := seen[value]; duplicate {
			return fmt.Errorf("development manifest %s duplicates %q", label, value)
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validateRecord(record fixtureRecord, ids map[string]struct{}, descriptor manifest) error {
	if !caseIDPattern.MatchString(record.ID) {
		return errors.New("invalid ID")
	}
	if _, duplicate := ids[record.ID]; duplicate {
		return errors.New("duplicate ID")
	}
	if record.Dataset != developmentDatasetID || record.Family == "" || record.Protocol == "" || record.Carrier == "" || record.Transform == "" || record.PairID == "" {
		return errors.New("required development identity metadata is missing")
	}
	for _, check := range []struct {
		label     string
		value     string
		manifest  []string
		canonical []string
	}{
		{label: "family", value: record.Family, manifest: descriptor.RequiredFamilies, canonical: canonicalDevelopmentFamilies},
		{label: "protocol", value: record.Protocol, manifest: descriptor.RequiredProtocols, canonical: canonicalDevelopmentProtocols},
		{label: "carrier", value: record.Carrier, manifest: descriptor.RequiredCarriers, canonical: canonicalDevelopmentCarriers},
		{label: "transform", value: record.Transform, manifest: descriptor.RequiredTransforms, canonical: canonicalDevelopmentTransforms},
		{label: "source context", value: effectiveSourceContext(record), manifest: descriptor.RequiredSourceContexts, canonical: canonicalDevelopmentSourceContexts},
	} {
		if !enumContains(check.manifest, check.value) || !enumContains(check.canonical, check.value) {
			return fmt.Errorf("development case %s is outside the approved manifest and canonical sets", check.label)
		}
	}
	if record.Label != "allow" && record.Label != "audit" {
		return errors.New("only allow/audit harmless development fixtures are permitted")
	}
	if !record.HarmlessCanary || len(record.Purpose) < 16 || record.ExpectedRoleAware == nil {
		return errors.New("harmless canary metadata is missing")
	}
	input := bytes.TrimSpace(record.Input)
	if len(input) < 2 || input[0] != '{' || input[len(input)-1] != '}' || !json.Valid(input) {
		return errors.New("input must be one valid production-style JSON object")
	}
	if !containsApprovedCanary(string(input)) {
		return errors.New("input does not contain an approved harmless canary task")
	}
	for _, evidence := range record.ExpectedEvidence {
		if !strings.HasPrefix(evidence, "META-OVERRIDE-001:") || !safeIdentifier(evidence) {
			return errors.New("expected evidence is not a fixed meta-override identifier")
		}
	}
	wantFamilyEvidence := "META-OVERRIDE-001:" + record.Family
	if record.Label == "audit" {
		found := false
		for _, evidence := range record.ExpectedEvidence {
			found = found || evidence == wantFamilyEvidence
		}
		if !found {
			return errors.New("audit fixture does not require its declared fixed family evidence")
		}
	} else if len(record.ExpectedEvidence) != 0 {
		return errors.New("allow fixture must not require control-plane evidence")
	}
	return nil
}

func enumContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func effectiveSourceContext(record fixtureRecord) string {
	if record.SourceContext == "" {
		return "request_body"
	}
	return record.SourceContext
}

func validateCorpusSafety(raw []byte) error {
	return validateSafetyText(string(raw))
}

func validateSafetyText(value string) error {
	lower := strings.ToLower(value)
	for _, forbidden := range []string{
		"jia-ethan", "codex-keysmith", "mdx-tom", "gpt-5.6-instruct", "yynxxxxx",
		"codex-x", "codex-5.5-codex-instruct", "codex-5.5-codex-instruct-5.5", "github.com/",
		"f699b9bd2cb59eb0d54e69139c68f7808d869b6d",
		"5f469e43ef66f540cadb475039fd9ed469aef654",
		"7d0e0064d54f860d4bf12b557fd9f8c489043a35",
		"ed0b6dc37d1994e93788d92f7af63f58bf0b9e2d",
		"real victim", "real target", "真实目标", "真实受害", "password", "credential",
		"malware", "ransomware", "phishing", "keylogger", "exploit", "exfiltrat",
		"reverse shell", "powershell -", "curl ", "wget ", "api key", "token=",
	} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("development corpus contains forbidden live/reference material marker %q", forbidden)
		}
	}
	if urlPattern.MatchString(value) || ipv4Pattern.MatchString(value) {
		return errors.New("development corpus contains a URL or IPv4-like target")
	}
	return nil
}

func validateDecodedJSONSafety(raw json.RawMessage) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return err
	}
	return walkDecodedSafety(value)
}

func walkDecodedSafety(value any) error {
	switch typed := value.(type) {
	case string:
		return validateSafetyText(typed)
	case []any:
		for _, item := range typed {
			if err := walkDecodedSafety(item); err != nil {
				return err
			}
		}
	case map[string]any:
		for key, item := range typed {
			if err := validateSafetyText(key); err != nil {
				return err
			}
			if err := walkDecodedSafety(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func containsApprovedCanary(value string) bool {
	lower := strings.ToLower(value)
	for _, canary := range []string{"canary", "football scores", "public weather report", "harmless strings", "足球比分", "公开天气报告", "无害字符串"} {
		if strings.Contains(lower, canary) {
			return true
		}
	}
	return false
}

func validateAggregates(descriptor manifest, pairs map[string][]fixtureRecord, metrics validationMetrics) error {
	if metrics.Total < len(descriptor.RequiredFamilies)*2 || metrics.Allow == 0 || metrics.Audit == 0 || metrics.RoleAware == 0 || metrics.Untrusted == 0 {
		return errors.New("development corpus balance or provenance coverage is invalid")
	}
	for _, family := range descriptor.RequiredFamilies {
		if metrics.Families[family] < 2 {
			return fmt.Errorf("development family %q has %d cases, want at least 2", family, metrics.Families[family])
		}
	}
	for label, required := range map[string][]string{
		"protocol": descriptor.RequiredProtocols, "carrier": descriptor.RequiredCarriers,
		"transform": descriptor.RequiredTransforms, "source context": descriptor.RequiredSourceContexts,
	} {
		actual := metrics.Protocols
		if label == "carrier" {
			actual = metrics.Carriers
		} else if label == "transform" {
			actual = metrics.Transforms
		} else if label == "source context" {
			actual = metrics.SourceContexts
		}
		for _, value := range required {
			if actual[value] == 0 {
				return fmt.Errorf("development corpus required %s %q is uncovered", label, value)
			}
		}
	}
	for pairID, members := range pairs {
		if len(members) != 2 || members[0].Family != members[1].Family || members[0].Label == members[1].Label {
			return fmt.Errorf("development pair %q must contain one allow and one audit case for the same family", pairID)
		}
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
	values := append([]string(nil), result.Parts...)
	for _, segment := range result.Segments {
		values = append(values, segment.Text)
	}
	return strings.Join(values, "\n")
}

func hasEvidence(values []classifier.Evidence, want string) bool {
	for _, value := range values {
		if value.ID == want && value.Kind == "meta_override" {
			return true
		}
	}
	return false
}

func safeIdentifier(value string) bool {
	for _, r := range value {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == ':' {
			continue
		}
		return false
	}
	return true
}

func pathWithin(parent, child string) bool {
	relative, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}
