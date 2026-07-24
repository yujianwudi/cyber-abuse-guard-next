package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/round9corpus"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

type candidateIdentity struct {
	PolicyVersion string `json:"policy_version"`
	PolicySHA256  string `json:"policy_sha256"`
	Ruleset       string `json:"ruleset"`
}

type report struct {
	Schema               string                            `json:"schema"`
	Corpus               string                            `json:"corpus"`
	CorpusManifest       round9corpus.FileIdentity         `json:"corpus_manifest"`
	CorpusCases          round9corpus.FileIdentity         `json:"corpus_cases"`
	CorpusLabelAudit     round9corpus.FileIdentity         `json:"corpus_label_audit"`
	BenignCorpusManifest round9corpus.FileIdentity         `json:"benign_corpus_manifest"`
	BenignCorpusCases    round9corpus.FileIdentity         `json:"benign_corpus_cases"`
	Candidate            candidateIdentity                 `json:"candidate"`
	Runtime              string                            `json:"runtime"`
	Platform             string                            `json:"platform"`
	PairCounts           round9corpus.PairedManifestCounts `json:"pair_counts"`
	Metrics              round9corpus.MaliciousMetrics     `json:"metrics"`
	RecallPercent        float64                           `json:"recall_percent"`
	Wilson95LowerPercent float64                           `json:"wilson_95_lower_percent"`
	Wilson95UpperPercent float64                           `json:"wilson_95_upper_percent"`
	ClaimBoundary        string                            `json:"claim_boundary"`
}

func main() {
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	result, err := run(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println(string(encoded))
	if result.Metrics.SemanticBlocked != result.Metrics.UniqueSemanticSamples {
		os.Exit(2)
	}
}

func run(root string) (report, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return report{}, fmt.Errorf("Round 9 paired corpus evaluation requires linux/amd64, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	root = filepath.Clean(root)
	activeRules, err := rules.LoadDefault()
	if err != nil {
		return report{}, fmt.Errorf("load active ruleset identity: %w", err)
	}
	benignDirectory := filepath.Join(root, "testdata", "round9-development-benign-v1")
	benign, err := round9corpus.Load(benignDirectory, round9corpus.LoadOptions{
		Name: "round9-development-benign-v1", AuthoringContext: "visible_round9_development",
		ExpectedDisposition: round9corpus.ExpectedBenignDisposition,
		ExpectedTotal:       1200, ExpectedPerCategory: 80, ExpectedPerLanguage: 40,
	})
	if err != nil {
		return report{}, fmt.Errorf("load frozen benign corpus: %w", err)
	}
	pairedDirectory := filepath.Join(root, "testdata", round9corpus.PairedMaliciousCorpusName)
	paired, err := round9corpus.LoadPairedMalicious(pairedDirectory, benign.Records, round9corpus.PairedLoadOptions{
		Name: round9corpus.PairedMaliciousCorpusName, AuthoringContext: round9corpus.ExpectedPairedAuthoringContext,
		ExpectedTotal: 120, ExpectedPerFamily: 8, ExpectedPerLanguage: 4,
	})
	if err != nil {
		return report{}, fmt.Errorf("load frozen paired corpus: %w", err)
	}
	malicious := round9corpus.PairedRecordsAsMalicious(paired.Records)
	routes, err := round9corpus.BuildMaliciousRoutes(malicious)
	if err != nil {
		return report{}, err
	}
	metrics, err := round9corpus.EvaluateMaliciousRoutes(malicious, routes)
	if err != nil {
		return report{}, err
	}
	pairedManifest, err := fileIdentity(filepath.Join(pairedDirectory, "manifest.json"))
	if err != nil {
		return report{}, err
	}
	pairedCases, err := fileIdentity(filepath.Join(pairedDirectory, "cases.jsonl"))
	if err != nil {
		return report{}, err
	}
	pairedLabelAudit, err := fileIdentity(filepath.Join(pairedDirectory, round9corpus.PairedLabelAuditFileName))
	if err != nil {
		return report{}, err
	}
	benignManifest, err := fileIdentity(filepath.Join(benignDirectory, "manifest.json"))
	if err != nil {
		return report{}, err
	}
	benignCases, err := fileIdentity(filepath.Join(benignDirectory, "cases.jsonl"))
	if err != nil {
		return report{}, err
	}
	lower, upper := round9corpus.WilsonInterval95(metrics.SemanticBlocked, metrics.UniqueSemanticSamples)
	return report{
		Schema: "round9-development-paired-malicious-report/v3", Corpus: round9corpus.PairedMaliciousCorpusName,
		CorpusManifest: pairedManifest, CorpusCases: pairedCases, CorpusLabelAudit: pairedLabelAudit,
		BenignCorpusManifest: benignManifest, BenignCorpusCases: benignCases,
		Candidate: candidateIdentity{
			PolicyVersion: classifier.ClassifierPolicyVersion,
			PolicySHA256:  classifier.ClassifierPolicySHA256,
			Ruleset:       activeRules.Version,
		},
		Runtime: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		PairCounts: paired.Manifest.Counts, Metrics: metrics,
		RecallPercent:        percentage(metrics.SemanticBlocked, metrics.UniqueSemanticSamples),
		Wilson95LowerPercent: lower * 100, Wilson95UpperPercent: upper * 100,
		ClaimBoundary: "Visible paired development evidence only; it is not an independent holdout, production validation, or proof of population recall.",
	}, nil
}

func fileIdentity(path string) (round9corpus.FileIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return round9corpus.FileIdentity{}, err
	}
	sum := sha256.Sum256(data)
	return round9corpus.FileIdentity{Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}, nil
}

func percentage(events, total int) float64 {
	if total <= 0 {
		return 0
	}
	return float64(events) * 100 / float64(total)
}
