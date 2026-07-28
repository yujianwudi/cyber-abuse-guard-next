package rules

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"path"
	"strings"

	defaultdata "github.com/yujianwudi/cyber-abuse-guard/rules"
	"gopkg.in/yaml.v3"
)

const defaultManifest = "manifest.yaml"

const (
	maxRuleAssetBytes = 512 << 10
	maxRuleFiles      = 64
)

type manifestDocument struct {
	Version      string   `yaml:"version"`
	ContextFile  string   `yaml:"context_file"`
	SemanticFile string   `yaml:"semantic_file"`
	RuleFiles    []string `yaml:"rule_files"`
}

type rulesDocument struct {
	Version string `yaml:"version"`
	Rules   []Rule `yaml:"rules"`
}

type contextEntry struct {
	Kind  ContextKind `yaml:"kind"`
	Terms Terms       `yaml:"terms"`
}

type contextsDocument struct {
	Version  string         `yaml:"version"`
	Contexts []contextEntry `yaml:"contexts"`
}

type semanticsDocument struct {
	Version  string            `yaml:"version"`
	Profiles []SemanticProfile `yaml:"profiles"`
}

// LoadDefault parses and validates a fresh snapshot from the YAML assets
// compiled into the binary.
func LoadDefault() (*RuleSet, error) {
	return LoadFS(defaultdata.FS, defaultManifest)
}

// LoadFS loads a rule manifest and all files it names. An optional manifest
// name supports tests and future data-directory overrides without weakening
// path validation.
func LoadFS(source fs.FS, manifestNames ...string) (*RuleSet, error) {
	if source == nil {
		return nil, fmt.Errorf("rule filesystem is nil")
	}
	manifestName := defaultManifest
	if len(manifestNames) > 1 {
		return nil, fmt.Errorf("expected at most one manifest name")
	}
	if len(manifestNames) == 1 {
		manifestName = manifestNames[0]
	}
	if err := validateAssetName(manifestName); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}

	var manifest manifestDocument
	if err := decodeStrictFile(source, manifestName, &manifest); err != nil {
		return nil, err
	}
	if !validVersion(manifest.Version) {
		return nil, fmt.Errorf("manifest has invalid version %q", manifest.Version)
	}
	if manifest.ContextFile == "" || len(manifest.RuleFiles) == 0 {
		return nil, fmt.Errorf("manifest must name a context file and at least one rule file")
	}
	if len(manifest.RuleFiles) > maxRuleFiles {
		return nil, fmt.Errorf("manifest names %d rule files, limit is %d", len(manifest.RuleFiles), maxRuleFiles)
	}
	if err := validateAssetName(manifest.ContextFile); err != nil {
		return nil, fmt.Errorf("context file: %w", err)
	}

	var contexts contextsDocument
	if err := decodeStrictFile(source, manifest.ContextFile, &contexts); err != nil {
		return nil, err
	}
	if contexts.Version != manifest.Version {
		return nil, fmt.Errorf("context version %q does not match manifest %q", contexts.Version, manifest.Version)
	}
	contextMap := make(map[ContextKind]Terms, len(contexts.Contexts))
	for _, entry := range contexts.Contexts {
		if _, exists := contextMap[entry.Kind]; exists {
			return nil, fmt.Errorf("duplicate context kind %q", entry.Kind)
		}
		contextMap[entry.Kind] = canonicalTerms(entry.Terms)
	}

	set := &RuleSet{Version: manifest.Version, Contexts: contextMap}
	seenFiles := map[string]struct{}{manifestName: {}, manifest.ContextFile: {}}
	if manifest.SemanticFile != "" {
		if err := validateAssetName(manifest.SemanticFile); err != nil {
			return nil, fmt.Errorf("semantic file: %w", err)
		}
		if _, exists := seenFiles[manifest.SemanticFile]; exists {
			return nil, fmt.Errorf("duplicate asset %q in manifest", manifest.SemanticFile)
		}
		seenFiles[manifest.SemanticFile] = struct{}{}
		var document semanticsDocument
		if err := decodeStrictFile(source, manifest.SemanticFile, &document); err != nil {
			return nil, err
		}
		if document.Version != manifest.Version {
			return nil, fmt.Errorf("semantic file %s version %q does not match manifest %q", manifest.SemanticFile, document.Version, manifest.Version)
		}
		set.Semantics = make(map[Category]SemanticProfile, len(document.Profiles))
		for _, profile := range document.Profiles {
			canonicalizeSemanticProfile(&profile)
			if _, exists := set.Semantics[profile.Category]; exists {
				return nil, fmt.Errorf("duplicate semantic profile category %q", profile.Category)
			}
			set.Semantics[profile.Category] = profile
		}
	}
	for _, name := range manifest.RuleFiles {
		if err := validateAssetName(name); err != nil {
			return nil, fmt.Errorf("rule file: %w", err)
		}
		if _, exists := seenFiles[name]; exists {
			return nil, fmt.Errorf("duplicate asset %q in manifest", name)
		}
		seenFiles[name] = struct{}{}
		var document rulesDocument
		if err := decodeStrictFile(source, name, &document); err != nil {
			return nil, err
		}
		if document.Version != manifest.Version {
			return nil, fmt.Errorf("rule file %s version %q does not match manifest %q", name, document.Version, manifest.Version)
		}
		for i := range document.Rules {
			canonicalizeRule(&document.Rules[i])
		}
		set.Rules = append(set.Rules, document.Rules...)
	}
	if err := set.Validate(); err != nil {
		return nil, fmt.Errorf("validate ruleset: %w", err)
	}
	return set, nil
}

func canonicalizeSemanticProfile(profile *SemanticProfile) {
	profile.Harm = canonicalTerms(profile.Harm)
	profile.Object = canonicalTerms(profile.Object)
	profile.Action = canonicalTerms(profile.Action)
	profile.Outcome = canonicalTerms(profile.Outcome)
	profile.Target = canonicalTerms(profile.Target)
	profile.Destination = canonicalTerms(profile.Destination)
	profile.Evasion = canonicalTerms(profile.Evasion)
	profile.Scale = canonicalTerms(profile.Scale)
	profile.Sequence = canonicalTerms(profile.Sequence)
	profile.Impact = canonicalTerms(profile.Impact)
}

func decodeStrictFile(source fs.FS, name string, target any) error {
	file, err := source.Open(name)
	if err != nil {
		return fmt.Errorf("open rule asset %s: %w", name, err)
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, maxRuleAssetBytes+1))
	if err != nil {
		return fmt.Errorf("read rule asset %s: %w", name, err)
	}
	if len(b) > maxRuleAssetBytes {
		return fmt.Errorf("rule asset %s exceeds %d bytes", name, maxRuleAssetBytes)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	decoder.KnownFields(true)
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("parse rule asset %s: %w", name, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("parse rule asset %s: multiple YAML documents are not allowed", name)
		}
		return fmt.Errorf("parse rule asset %s: %w", name, err)
	}
	return nil
}

func validateAssetName(name string) error {
	if name == "" || strings.ContainsAny(name, `/\\:`) || name != path.Base(name) || path.Clean(name) != name || !strings.HasSuffix(name, ".yaml") {
		return fmt.Errorf("unsafe asset name %q", name)
	}
	return nil
}

func canonicalizeRule(rule *Rule) {
	rule.ID = strings.TrimSpace(rule.ID)
	rule.Severity = strings.ToLower(strings.TrimSpace(rule.Severity))
	rule.Intent = canonicalTerms(rule.Intent)
	rule.Object = canonicalTerms(rule.Object)
	rule.Operational = canonicalTerms(rule.Operational)
	rule.Target = canonicalTerms(rule.Target)
	rule.Evasion = canonicalTerms(rule.Evasion)
	rule.Scale = canonicalTerms(rule.Scale)
}

func canonicalTerms(terms Terms) Terms {
	terms.ZH = trimTerms(terms.ZH)
	terms.EN = trimTerms(terms.EN)
	return terms
}

func trimTerms(values []string) []string {
	trimmed := make([]string, len(values))
	for i, value := range values {
		trimmed[i] = strings.TrimSpace(value)
	}
	return trimmed
}
