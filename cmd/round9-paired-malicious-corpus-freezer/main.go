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

const recordsPerFamily = 8

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
	benign, err := round9corpus.Load(filepath.Join(root, "testdata", "round9-development-benign-v1"), round9corpus.LoadOptions{
		Name: "round9-development-benign-v1", AuthoringContext: "visible_round9_development",
		ExpectedDisposition: round9corpus.ExpectedBenignDisposition,
		ExpectedTotal:       1200, ExpectedPerCategory: 80, ExpectedPerLanguage: 40,
	})
	if err != nil {
		return fmt.Errorf("load frozen development benign corpus: %w", err)
	}
	directory := filepath.Join(root, "testdata", round9corpus.PairedMaliciousCorpusName)
	casesData, counts, err := assembleFragments(filepath.Join(directory, "fragments"))
	if err != nil {
		return err
	}
	caseSum := sha256.Sum256(casesData)
	caseDigest := hex.EncodeToString(caseSum[:])
	labelAuditData, err := os.ReadFile(filepath.Join(directory, round9corpus.PairedLabelAuditFileName))
	if err != nil {
		return fmt.Errorf("read paired pre-execution label audit: %w", err)
	}
	if err := round9corpus.ValidatePairedLabelAudit(labelAuditData, caseDigest, counts.Total); err != nil {
		return fmt.Errorf("validate paired pre-execution label audit: %w", err)
	}
	labelAuditSum := sha256.Sum256(labelAuditData)
	manifest := round9corpus.PairedMaliciousManifest{
		Name: round9corpus.PairedMaliciousCorpusName, Version: 2, GeneratedAt: generatedAt,
		AuthoringContext: round9corpus.ExpectedPairedAuthoringContext,
		ExpectedDecision: round9corpus.ExpectedMaliciousDecision,
		LabelConfidence:  round9corpus.UnambiguousLabel,
		GenerationBoundary: round9corpus.GenerationBoundary{
			IndependentlyAuthoredBeforeCandidateExecution: false,
			SourceCodeRead: false, RulesRead: false, ExistingDevelopmentCorporaRead: true,
			ExistingRestrictedContentRead: false, CandidateOutputObserved: false,
			ClassifierOrProjectTestsRun: false,
			SemanticPolicy:              "each record is an independently authored malicious neighbor bound to one distinct frozen benign request; labels are fixed before candidate evaluation",
			SafetyPolicy:                "high-level malicious intent descriptions only; no executable code commands payloads real targets operational procedures or third-party repository execution",
		},
		Schema: round9corpus.ManifestSchema{FileFormat: "jsonl", Fields: []string{
			"id", "family", "benign_base_id", "difference_axis", "category", "language", "prompt",
			"expected_decision", "label_confidence", "authoring_context",
		}, LanguageValues: []string{round9corpus.LanguageChinese, round9corpus.LanguageEnglish}},
		Counts: counts,
		Files: map[string]round9corpus.FileIdentity{
			"cases.jsonl": {Bytes: int64(len(casesData)), SHA256: caseDigest},
		},
		LabelAudit: round9corpus.FileIdentity{Bytes: int64(len(labelAuditData)), SHA256: hex.EncodeToString(labelAuditSum[:])},
	}
	manifestData, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	manifestData = append(manifestData, '\n')
	readmeData := []byte(fmt.Sprintf(
		"# Round 9 Visible Paired-Malicious Development Corpus v3\n\n"+
			"This directory contains 120 externally labelled, high-level malicious\n"+
			"neighbors: eight for each of the 15 frozen benign development families.\n"+
			"Every record binds a distinct benign base ID, the semantic difference axis,\n"+
			"language, and expected malicious taxonomy before candidate evaluation.\n\n"+
			"This is visible development evidence, not an independent holdout. It contains\n"+
			"no executable payloads, commands, real targets, or operational procedures.\n\n"+
			"`cases.jsonl`:\n\n- Bytes: `%d`\n- SHA-256: `%s`\n\n"+
			"`%s`:\n\n- Bytes: `%d`\n- SHA-256: `%s`\n",
		len(casesData), caseDigest, round9corpus.PairedLabelAuditFileName,
		len(labelAuditData), hex.EncodeToString(labelAuditSum[:]),
	))
	if err := validateFrozenBytes(root, benign.Records, manifestData, casesData, labelAuditData); err != nil {
		return err
	}
	return installExclusive(directory, map[string][]byte{
		"cases.jsonl": casesData, "manifest.json": manifestData, "README.md": readmeData,
	})
}

func assembleFragments(directory string) ([]byte, round9corpus.PairedManifestCounts, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, round9corpus.PairedManifestCounts{}, fmt.Errorf("read paired fragments: %w", err)
	}
	wantFiles := make(map[string]string, len(round9corpus.BaseCategories))
	for _, family := range round9corpus.BaseCategories {
		wantFiles[family+".jsonl"] = family
	}
	seenFiles := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			return nil, round9corpus.PairedManifestCounts{}, fmt.Errorf("unexpected paired fragment directory %q", entry.Name())
		}
		if _, ok := wantFiles[entry.Name()]; !ok {
			return nil, round9corpus.PairedManifestCounts{}, fmt.Errorf("unexpected paired fragment file %q", entry.Name())
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
		return nil, round9corpus.PairedManifestCounts{}, fmt.Errorf("missing paired fragments: %s", strings.Join(missing, ", "))
	}

	counts := round9corpus.PairedManifestCounts{
		Total: len(round9corpus.BaseCategories) * recordsPerFamily,
		Languages: map[string]int{
			round9corpus.LanguageChinese: len(round9corpus.BaseCategories) * recordsPerFamily / 2,
			round9corpus.LanguageEnglish: len(round9corpus.BaseCategories) * recordsPerFamily / 2,
		},
		Families:       make(map[string]round9corpus.CategoryCount, len(round9corpus.BaseCategories)),
		Categories:     make(map[string]int, len(round9corpus.MaliciousCategories)),
		DifferenceAxes: make(map[string]int, len(round9corpus.PairedDifferenceAxes)),
	}
	var output bytes.Buffer
	for _, family := range round9corpus.BaseCategories {
		path := filepath.Join(directory, family+".jsonl")
		file, err := os.Open(path)
		if err != nil {
			return nil, round9corpus.PairedManifestCounts{}, err
		}
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64<<10), 1<<20)
		familyCount := round9corpus.CategoryCount{}
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				_ = file.Close()
				return nil, round9corpus.PairedManifestCounts{}, fmt.Errorf("paired fragment %s contains a blank line", family)
			}
			var record round9corpus.PairedMaliciousRecord
			decoder := json.NewDecoder(bytes.NewReader(line))
			decoder.DisallowUnknownFields()
			if err := decoder.Decode(&record); err != nil {
				_ = file.Close()
				return nil, round9corpus.PairedManifestCounts{}, fmt.Errorf("paired fragment %s: %w", family, err)
			}
			var trailing any
			if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
				_ = file.Close()
				if err == nil {
					return nil, round9corpus.PairedManifestCounts{}, fmt.Errorf("paired fragment %s contains multiple JSON values", family)
				}
				return nil, round9corpus.PairedManifestCounts{}, fmt.Errorf("paired fragment %s trailing JSON: %w", family, err)
			}
			if record.Family != family || record.ExpectedDecision != round9corpus.ExpectedMaliciousDecision ||
				record.LabelConfidence != round9corpus.UnambiguousLabel ||
				record.AuthoringContext != round9corpus.ExpectedPairedAuthoringContext {
				_ = file.Close()
				return nil, round9corpus.PairedManifestCounts{}, fmt.Errorf("paired fragment %s has family or ground-truth drift", family)
			}
			familyCount.Total++
			if record.Language == round9corpus.LanguageChinese {
				familyCount.ZH++
			} else if record.Language == round9corpus.LanguageEnglish {
				familyCount.EN++
			} else {
				_ = file.Close()
				return nil, round9corpus.PairedManifestCounts{}, fmt.Errorf("paired fragment %s has invalid language", family)
			}
			counts.Categories[record.Category]++
			counts.DifferenceAxes[record.DifferenceAxis]++
			output.Write(line)
			output.WriteByte('\n')
		}
		if err := scanner.Err(); err != nil {
			_ = file.Close()
			return nil, round9corpus.PairedManifestCounts{}, err
		}
		if err := file.Close(); err != nil {
			return nil, round9corpus.PairedManifestCounts{}, err
		}
		if familyCount != (round9corpus.CategoryCount{Total: recordsPerFamily, ZH: recordsPerFamily / 2, EN: recordsPerFamily / 2}) {
			return nil, round9corpus.PairedManifestCounts{}, fmt.Errorf("paired fragment %s count=%+v", family, familyCount)
		}
		counts.Families[family] = familyCount
	}
	return output.Bytes(), counts, nil
}

func validateFrozenBytes(root string, benign []round9corpus.BaseRecord, manifestData, casesData, labelAuditData []byte) error {
	temporary, err := os.MkdirTemp(filepath.Join(filepath.Clean(root), "testdata"), ".round9-paired-freeze-")
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
	if err := os.WriteFile(filepath.Join(temporary, round9corpus.PairedLabelAuditFileName), labelAuditData, 0o600); err != nil {
		return err
	}
	_, err = round9corpus.LoadPairedMalicious(temporary, benign, round9corpus.PairedLoadOptions{
		Name: round9corpus.PairedMaliciousCorpusName, AuthoringContext: round9corpus.ExpectedPairedAuthoringContext,
		ExpectedTotal:     len(round9corpus.BaseCategories) * recordsPerFamily,
		ExpectedPerFamily: recordsPerFamily, ExpectedPerLanguage: recordsPerFamily / 2,
	})
	if err != nil {
		return fmt.Errorf("validate assembled paired corpus: %w", err)
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
			return errors.New("internal paired freeze output is incomplete")
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
