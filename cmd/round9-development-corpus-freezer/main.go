package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/round9corpus"
)

const (
	developmentCorpusName = "round9-development-benign-v1"
	developmentContext    = "visible_round9_development"
)

func main() {
	root := flag.String("root", ".", "repository root")
	generatedAt := flag.String("generated-at", "", "predeclared RFC3339 corpus freeze time")
	flag.Parse()
	if err := freeze(*root, *generatedAt); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func freeze(root, generatedAt string) error {
	if _, err := time.Parse(time.RFC3339, generatedAt); err != nil {
		return fmt.Errorf("--generated-at must be RFC3339: %w", err)
	}
	root = filepath.Clean(root)
	directory := filepath.Join(root, "testdata", developmentCorpusName)
	fragments := filepath.Join(directory, "fragments")
	casesData, counts, err := assembleFragments(fragments)
	if err != nil {
		return err
	}
	caseSum := sha256.Sum256(casesData)
	manifest := round9corpus.Manifest{
		Name: developmentCorpusName, Version: 1, GeneratedAt: generatedAt,
		AuthoringContext: developmentContext, ExpectedDisposition: round9corpus.ExpectedBenignDisposition,
		GenerationBoundary: round9corpus.GenerationBoundary{
			IndependentlyAuthoredBeforeCandidateExecution: false,
			SourceCodeRead: true, RulesRead: true, ExistingDevelopmentCorporaRead: true,
			ExistingRestrictedContentRead: false, CandidateOutputObserved: false,
			ClassifierOrProjectTestsRun: true,
			SemanticPolicy:              "each visible development record is independently meaningful; wrapper changes, mechanical translations, templates, and slot substitutions are excluded",
			SafetyPolicy:                "benign coding, operations, lifecycle, defensive, analytical, educational, isolated-lab, recovery, and enterprise-management requests only",
		},
		Schema: round9corpus.ManifestSchema{
			FileFormat:     "jsonl",
			Fields:         []string{"id", "category", "language", "prompt", "expected_disposition", "authoring_context"},
			LanguageValues: []string{round9corpus.LanguageChinese, round9corpus.LanguageEnglish},
		},
		Counts: counts,
		Files: map[string]round9corpus.FileIdentity{
			"cases.jsonl": {Bytes: int64(len(casesData)), SHA256: hex.EncodeToString(caseSum[:])},
		},
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestData = append(manifestData, '\n')
	readmeData := []byte(fmt.Sprintf(
		"# Round 9 Visible Development Benign Corpus v1\n\n"+
			"This directory contains 1,200 semantically unique visible development base\n"+
			"requests across 15 categories. Each category contains 40 Chinese and 40\n"+
			"English requests. Protocol, stream, mode, wrapper, role, and carrier variants\n"+
			"are route executions and are not additional semantic samples.\n\n"+
			"The corpus is visible development evidence, not an independent holdout. It was\n"+
			"frozen before the final candidate-bound independent evaluations. Candidate\n"+
			"output must not be used to delete records, rewrite prompts, or change expected\n"+
			"dispositions.\n\n"+
			"`cases.jsonl`:\n\n"+
			"- Bytes: `%d`\n"+
			"- SHA-256: `%s`\n\n"+
			"Every record expects `allow_or_audit`. Any local malicious-text or hard-policy\n"+
			"block is a corpus failure and must remain visible in the generated report.\n",
		len(casesData), hex.EncodeToString(caseSum[:]),
	))

	if err := validateFrozenBytes(root, manifestData, casesData); err != nil {
		return err
	}
	return installExclusive(directory, map[string][]byte{
		"cases.jsonl": casesData, "manifest.json": manifestData, "README.md": readmeData,
	})
}

func assembleFragments(directory string) ([]byte, round9corpus.ManifestCounts, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, round9corpus.ManifestCounts{}, fmt.Errorf("read fragments: %w", err)
	}
	wantFiles := make(map[string]string, len(round9corpus.BaseCategories))
	for _, category := range round9corpus.BaseCategories {
		wantFiles[category+".jsonl"] = category
	}
	seenFiles := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, round9corpus.ManifestCounts{}, fmt.Errorf("unexpected fragment directory %q", entry.Name())
		}
		if _, ok := wantFiles[entry.Name()]; !ok {
			return nil, round9corpus.ManifestCounts{}, fmt.Errorf("unexpected fragment file %q", entry.Name())
		}
		seenFiles[entry.Name()] = struct{}{}
	}
	if len(seenFiles) != len(wantFiles) {
		missing := make([]string, 0)
		for name := range wantFiles {
			if _, ok := seenFiles[name]; !ok {
				missing = append(missing, name)
			}
		}
		sort.Strings(missing)
		return nil, round9corpus.ManifestCounts{}, fmt.Errorf("missing fragments: %s", strings.Join(missing, ", "))
	}

	counts := round9corpus.ManifestCounts{
		Total:      1200,
		Languages:  map[string]int{round9corpus.LanguageChinese: 600, round9corpus.LanguageEnglish: 600},
		Categories: make(map[string]round9corpus.CategoryCount, len(round9corpus.BaseCategories)),
	}
	var output bytes.Buffer
	ids := make(map[string]struct{}, 1200)
	for _, category := range round9corpus.BaseCategories {
		path := filepath.Join(directory, category+".jsonl")
		file, err := os.Open(path)
		if err != nil {
			return nil, round9corpus.ManifestCounts{}, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		categoryCount := round9corpus.CategoryCount{}
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				_ = file.Close()
				return nil, round9corpus.ManifestCounts{}, fmt.Errorf("fragment %s contains a blank line", category)
			}
			var record round9corpus.BaseRecord
			decoder := json.NewDecoder(bytes.NewReader(line))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&record); err != nil {
				_ = file.Close()
				return nil, round9corpus.ManifestCounts{}, fmt.Errorf("fragment %s: %w", category, err)
			}
			var trailing any
			if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				_ = file.Close()
				if err == nil {
					return nil, round9corpus.ManifestCounts{}, fmt.Errorf("fragment %s contains multiple JSON values", category)
				}
				return nil, round9corpus.ManifestCounts{}, fmt.Errorf("fragment %s trailing JSON: %w", category, err)
			}
			if record.Category != category || record.ExpectedDisposition != round9corpus.ExpectedBenignDisposition || record.AuthoringContext != developmentContext {
				_ = file.Close()
				return nil, round9corpus.ManifestCounts{}, fmt.Errorf("fragment %s has category or ground-truth drift", category)
			}
			if record.Language != round9corpus.LanguageChinese && record.Language != round9corpus.LanguageEnglish {
				_ = file.Close()
				return nil, round9corpus.ManifestCounts{}, fmt.Errorf("fragment %s has invalid language", category)
			}
			if _, duplicate := ids[record.ID]; duplicate {
				_ = file.Close()
				return nil, round9corpus.ManifestCounts{}, fmt.Errorf("duplicate id %q", record.ID)
			}
			ids[record.ID] = struct{}{}
			categoryCount.Total++
			if record.Language == round9corpus.LanguageChinese {
				categoryCount.ZH++
			} else {
				categoryCount.EN++
			}
			output.Write(line)
			output.WriteByte('\n')
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			return nil, round9corpus.ManifestCounts{}, err
		}
		if err := file.Close(); err != nil {
			return nil, round9corpus.ManifestCounts{}, err
		}
		if categoryCount != (round9corpus.CategoryCount{Total: 80, ZH: 40, EN: 40}) {
			return nil, round9corpus.ManifestCounts{}, fmt.Errorf("fragment %s count=%+v want total=80 zh=40 en=40", category, categoryCount)
		}
		counts.Categories[category] = categoryCount
	}
	return output.Bytes(), counts, nil
}

func validateFrozenBytes(root string, manifestData, casesData []byte) error {
	parent := filepath.Join(filepath.Clean(root), "testdata")
	temporary, err := os.MkdirTemp(parent, ".round9-development-freeze-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temporary)
	if err := os.WriteFile(filepath.Join(temporary, "manifest.json"), manifestData, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(temporary, "cases.jsonl"), casesData, 0o600); err != nil {
		return err
	}
	_, err = round9corpus.Load(temporary, round9corpus.LoadOptions{
		Name: developmentCorpusName, AuthoringContext: developmentContext,
		ExpectedDisposition: round9corpus.ExpectedBenignDisposition,
		ExpectedTotal:       1200, ExpectedPerCategory: 80, ExpectedPerLanguage: 40,
	})
	if err != nil {
		return fmt.Errorf("validate assembled development corpus: %w", err)
	}
	return nil
}

func installExclusive(directory string, files map[string][]byte) error {
	created := make([]string, 0, len(files))
	rollback := true
	defer func() {
		if rollback {
			for _, path := range created {
				_ = os.Remove(path)
			}
		}
	}()
	for _, name := range []string{"cases.jsonl", "manifest.json", "README.md"} {
		data, ok := files[name]
		if !ok {
			return errors.New("internal freeze output is incomplete")
		}
		path := filepath.Join(directory, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return fmt.Errorf("create %s: %w", name, err)
		}
		if _, err := file.Write(data); err != nil {
			_ = file.Close()
			return fmt.Errorf("write %s: %w", name, err)
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return fmt.Errorf("sync %s: %w", name, err)
		}
		if err := file.Close(); err != nil {
			return fmt.Errorf("close %s: %w", name, err)
		}
		created = append(created, path)
	}
	rollback = false
	return nil
}
