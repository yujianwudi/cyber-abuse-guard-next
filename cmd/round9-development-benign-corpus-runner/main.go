package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/classifier"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/round9corpus"
	"github.com/yujianwudi/cyber-abuse-guard-next/internal/rules"
)

const developmentCorpusName = "round9-development-benign-v1"

type runtimeIdentity struct {
	ClassifierPolicyVersion string `json:"classifier_policy_version"`
	ClassifierPolicySHA256  string `json:"classifier_policy_sha256"`
	RulesetVersion          string `json:"ruleset_version"`
}

type report struct {
	Schema                       string                    `json:"schema"`
	Corpus                       string                    `json:"corpus"`
	CorpusManifestBytes          int64                     `json:"corpus_manifest_bytes"`
	CorpusManifestSHA256         string                    `json:"corpus_manifest_sha256"`
	CorpusCasesBytes             int64                     `json:"corpus_cases_bytes"`
	CorpusCasesSHA256            string                    `json:"corpus_cases_sha256"`
	RuntimeIdentity              runtimeIdentity           `json:"runtime_identity"`
	Runtime                      string                    `json:"runtime"`
	Platform                     string                    `json:"platform"`
	Metrics                      round9corpus.RouteMetrics `json:"metrics"`
	ObservedBenignSemanticBlocks int                       `json:"observed_benign_semantic_blocks"`
	ObservedBenignRouteBlocks    int                       `json:"observed_benign_route_blocks"`
	Wilson95UpperPercent         float64                   `json:"wilson_95_upper_percent"`
	ClaimBoundary                string                    `json:"claim_boundary"`
}

func main() {
	root := flag.String("root", ".", "repository root containing the visible development corpus")
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
	if result.ObservedBenignSemanticBlocks != 0 || result.ObservedBenignRouteBlocks != 0 {
		os.Exit(2)
	}
}

func run(root string) (report, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return report{}, fmt.Errorf("Round 9 development corpus evaluation requires linux/amd64, got %s/%s", runtime.GOOS, runtime.GOARCH)
	}
	activeRules, err := rules.LoadDefault()
	if err != nil {
		return report{}, fmt.Errorf("load active ruleset identity: %w", err)
	}
	directory := filepath.Join(filepath.Clean(root), "testdata", developmentCorpusName)
	loaded, err := round9corpus.Load(directory, round9corpus.LoadOptions{
		Name:                developmentCorpusName,
		AuthoringContext:    "visible_round9_development",
		ExpectedDisposition: round9corpus.ExpectedBenignDisposition,
		ExpectedTotal:       1200,
		ExpectedPerCategory: 80,
		ExpectedPerLanguage: 40,
	})
	if err != nil {
		return report{}, err
	}
	routes, err := round9corpus.BuildBenignRoutes(loaded.Records)
	if err != nil {
		return report{}, err
	}
	metrics, err := round9corpus.EvaluateBenignRoutes(loaded.Records, routes)
	if err != nil {
		return report{}, err
	}
	manifestIdentity, err := fileIdentity(filepath.Join(directory, "manifest.json"))
	if err != nil {
		return report{}, err
	}
	casesIdentity, err := fileIdentity(filepath.Join(directory, "cases.jsonl"))
	if err != nil {
		return report{}, err
	}
	return report{
		Schema: "round9-development-benign-corpus-report/v1", Corpus: developmentCorpusName,
		CorpusManifestBytes: manifestIdentity.Bytes, CorpusManifestSHA256: manifestIdentity.SHA256,
		CorpusCasesBytes: casesIdentity.Bytes, CorpusCasesSHA256: casesIdentity.SHA256,
		RuntimeIdentity: runtimeIdentity{
			ClassifierPolicyVersion: classifier.ClassifierPolicyVersion,
			ClassifierPolicySHA256:  classifier.ClassifierPolicySHA256,
			RulesetVersion:          activeRules.Version,
		},
		Runtime: runtime.Version(), Platform: runtime.GOOS + "/" + runtime.GOARCH,
		Metrics:                      metrics,
		ObservedBenignSemanticBlocks: metrics.BlockedSemanticSamples,
		ObservedBenignRouteBlocks:    metrics.BlockedExecutions,
		Wilson95UpperPercent:         wilsonUpper95(metrics.BlockedSemanticSamples, metrics.UniqueSemanticSamples) * 100,
		ClaimBoundary:                "Visible development evidence only; it is candidate-owned, is not independent evidence, and cannot authorize release.",
	}, nil
}

type identity struct {
	Bytes  int64
	SHA256 string
}

func fileIdentity(path string) (identity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return identity{}, err
	}
	sum := sha256.Sum256(data)
	return identity{Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}, nil
}

func wilsonUpper95(events, total int) float64 {
	if total <= 0 || events < 0 || events > total {
		return 1
	}
	const z = 1.959963984540054
	n := float64(total)
	p := float64(events) / n
	z2 := z * z
	center := p + z2/(2*n)
	margin := z * math.Sqrt(p*(1-p)/n+z2/(4*n*n))
	upper := (center + margin) / (1 + z2/n)
	if upper < 0 {
		return 0
	}
	if upper > 1 {
		return 1
	}
	return upper
}
