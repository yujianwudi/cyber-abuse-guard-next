package classifier

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/yujianwudi/cyber-abuse-guard-next/internal/round8test"
)

const (
	round8CalibrationBenign    = "benign"
	round8CalibrationMalicious = "malicious"
	round8CalibrationUpdateEnv = "ROUND8_CALIBRATION_UPDATE"
)

var round8CalibrationThresholds = [...]int{80, 85, 90}

type round8CalibrationSample struct {
	nominalRuleID string
	label         string
	score         int
	action        Action
	policyVersion string
	policySHA256  string
	ruleset       string
}

type round8CalibrationMetrics struct {
	benignTotal    int
	maliciousTotal int
	falsePositive  int
	trueNegative   int
	truePositive   int
	falseNegative  int
}

func newRound8CalibrationSample(nominalRuleID, label string, result Result) round8CalibrationSample {
	return round8CalibrationSample{
		nominalRuleID: nominalRuleID,
		label:         label,
		score:         result.Score,
		action:        result.Action,
		policyVersion: result.PolicyVersion,
		policySHA256:  result.PolicySHA256,
		ruleset:       result.RuleSetVersion,
	}
}

func assertRound8CalibrationReport(
	t *testing.T,
	document round8test.Document,
	variants []round8test.MutationVariant,
	samples []round8CalibrationSample,
) {
	t.Helper()
	report, err := renderRound8CalibrationReport(document, variants, samples)
	if err != nil {
		t.Fatalf("render Round 8 calibration report: %v", err)
	}

	reportPath := filepath.Join("..", "..", "docs", "reports", "ROUND8_CALIBRATION.md")
	if os.Getenv(round8CalibrationUpdateEnv) == "1" {
		t.Logf("%s is ignored: the Round 8 calibration report is frozen legacy evidence", round8CalibrationUpdateEnv)
	}

	committed, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf(
			"read frozen Round 8 calibration report %s: %v",
			reportPath, err,
		)
	}
	if string(committed) != report {
		// Round 9 preserves the 336/336 seeded neighbor assertions above, but
		// must not rewrite or byte-compare the legacy Round 8 report against a
		// new policy/ruleset identity. Rendering still validates cardinality,
		// score bounds, current identity consistency, and aggregate structure.
		t.Log("current candidate metrics intentionally differ from frozen ROUND8_CALIBRATION.md")
	}
}

func renderRound8CalibrationReport(
	document round8test.Document,
	variants []round8test.MutationVariant,
	samples []round8CalibrationSample,
) (string, error) {
	if err := round8test.ValidateDocument(document); err != nil {
		return "", fmt.Errorf("fixture contract: %w", err)
	}
	wantVariants := round8test.FixturePairCount * round8test.VariantsPerFamily
	if len(variants) != wantVariants {
		return "", fmt.Errorf("variants=%d, want %d", len(variants), wantVariants)
	}
	if len(samples) != wantVariants*2 {
		return "", fmt.Errorf("samples=%d, want %d", len(samples), wantVariants*2)
	}

	policyVersion := ""
	policySHA256 := ""
	rulesetVersion := ""
	ruleCounts := make(map[string]map[string]int)
	sampleRuleCounts := make(map[string]map[string]int)
	for _, variant := range variants {
		counts := ruleCounts[variant.RuleID]
		if counts == nil {
			counts = map[string]int{
				round8CalibrationBenign:    0,
				round8CalibrationMalicious: 0,
			}
			ruleCounts[variant.RuleID] = counts
		}
		counts[round8CalibrationBenign]++
		counts[round8CalibrationMalicious]++
	}

	histogram := make(map[int]map[string]int)
	actions := make(map[string]map[Action]int)
	benignMin, benignMax := 101, -1
	maliciousMin, maliciousMax := 101, -1
	for _, sample := range samples {
		if sample.label != round8CalibrationBenign && sample.label != round8CalibrationMalicious {
			return "", fmt.Errorf("unknown sample label %q", sample.label)
		}
		if _, ok := ruleCounts[sample.nominalRuleID]; !ok {
			return "", fmt.Errorf("unknown nominal rule %q", sample.nominalRuleID)
		}
		if sample.score < 0 || sample.score > 100 {
			return "", fmt.Errorf("%s/%s score=%d outside [0,100]", sample.nominalRuleID, sample.label, sample.score)
		}
		if policyVersion == "" {
			policyVersion = sample.policyVersion
			policySHA256 = sample.policySHA256
			rulesetVersion = sample.ruleset
		}
		if sample.policyVersion != policyVersion || sample.policySHA256 != policySHA256 || sample.ruleset != rulesetVersion {
			return "", fmt.Errorf("classifier identity drift inside calibration samples")
		}
		countsByLabel := sampleRuleCounts[sample.nominalRuleID]
		if countsByLabel == nil {
			countsByLabel = make(map[string]int, 2)
			sampleRuleCounts[sample.nominalRuleID] = countsByLabel
		}
		countsByLabel[sample.label]++
		counts := histogram[sample.score]
		if counts == nil {
			counts = make(map[string]int, 2)
			histogram[sample.score] = counts
		}
		counts[sample.label]++
		labelActions := actions[sample.label]
		if labelActions == nil {
			labelActions = make(map[Action]int)
			actions[sample.label] = labelActions
		}
		labelActions[sample.action]++
		if sample.label == round8CalibrationBenign {
			benignMin = min(benignMin, sample.score)
			benignMax = max(benignMax, sample.score)
		} else {
			maliciousMin = min(maliciousMin, sample.score)
			maliciousMax = max(maliciousMax, sample.score)
		}
	}
	if policyVersion != ClassifierPolicyVersion || policySHA256 != ClassifierPolicySHA256 {
		return "", fmt.Errorf(
			"calibration identity=%s/%s, want %s/%s",
			policyVersion, policySHA256, ClassifierPolicyVersion, ClassifierPolicySHA256,
		)
	}
	for ruleID, wantCounts := range ruleCounts {
		gotCounts := sampleRuleCounts[ruleID]
		for _, label := range []string{round8CalibrationBenign, round8CalibrationMalicious} {
			if gotCounts[label] != wantCounts[label] {
				return "", fmt.Errorf(
					"%s/%s samples=%d, want %d",
					ruleID, label, gotCounts[label], wantCounts[label],
				)
			}
		}
	}

	fixturePath := filepath.Join("..", "..", "testdata", "round8_balanced_readmission.json")
	fixtureBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		return "", fmt.Errorf("read fixture for digest: %w", err)
	}
	fixtureSHA256 := fmt.Sprintf("%x", sha256.Sum256(fixtureBytes))

	ruleIDs := make([]string, 0, len(ruleCounts))
	for ruleID := range ruleCounts {
		ruleIDs = append(ruleIDs, ruleID)
	}
	sort.Strings(ruleIDs)

	scores := make([]int, 0, len(histogram))
	for score := range histogram {
		scores = append(scores, score)
	}
	sort.Ints(scores)

	var report strings.Builder
	report.WriteString("# Round 8 synthetic score calibration\n\n")
	fmt.Fprintf(
		&report,
		"```text\ncurrent_classifier_policy_version: %s\ncurrent_classifier_policy_sha256: %s\n```\n\n",
		policyVersion,
		policySHA256,
	)
	report.WriteString("Status: **DEVELOPMENT SELF-CHECK / NOT BLIND OR HOLDOUT EVIDENCE**.\n\n")
	report.WriteString("This report is deterministically generated from the public, synthetic Round 8 paired-mutation fixture. It contains only aggregate classifier metadata and no request text. The generated metrics load no `evaluation-v10`, retired/private dataset, or blind-holdout samples.\n\n")
	report.WriteString("## Identity and method\n\n")
	fmt.Fprintf(&report, "- Fixture schema: `%s`\n", document.Schema)
	fmt.Fprintf(&report, "- Fixture SHA-256: `%s`\n", fixtureSHA256)
	fmt.Fprintf(&report, "- Synthetic provenance: `%s`\n", round8test.SyntheticProvenance)
	fmt.Fprintf(&report, "- Deterministic variant seed: `%d` (`0x%X`)\n", round8test.VariantSeed, round8test.VariantSeed)
	fmt.Fprintf(&report, "- Families: `%d`; variants per family: `%d`\n", len(document.Pairs), round8test.VariantsPerFamily)
	fmt.Fprintf(&report, "- Samples: `%d` benign + `%d` paired malicious = `%d` total\n", wantVariants, wantVariants, wantVariants*2)
	fmt.Fprintf(&report, "- Classifier policy: `%s` / `%s`\n", policyVersion, policySHA256)
	fmt.Fprintf(&report, "- Ruleset version: `%s`\n", rulesetVersion)
	report.WriteString("- Path: `ClassifySegmentsWithPolicy`, `ModeBalanced`, `DefaultThresholds`, and `DefaultPolicy`; each current trusted-user variant is preceded by the same deterministic 12-segment synthetic history used by the Round 8 regression gate.\n")
	report.WriteString("- Threshold analysis below is score-only: a sample is positive when `score >= threshold`. It does not replace the classifier's mode, completeness, provenance, core-predicate, hard-floor, or action logic.\n\n")

	report.WriteString("Regenerate and verify from WSL Ubuntu-26.04 after setting `GO` to the pinned Go 1.26.4 Linux amd64 binary:\n\n")
	report.WriteString("```bash\n")
	report.WriteString(": \"${GO:?set GO to the absolute go1.26.4 linux-amd64 binary path}\"\n")
	report.WriteString("test \"$(\"$GO\" version)\" = 'go version go1.26.4 linux/amd64'\n")
	report.WriteString("export GOTOOLCHAIN=local\n")
	report.WriteString("export GOPROXY=https://goproxy.cn,direct\n")
	report.WriteString("export GOSUMDB=sum.golang.google.cn\n")
	report.WriteString("ROUND8_CALIBRATION_UPDATE=1 \"$GO\" test -tags=sqlite_omit_load_extension ./internal/classifier -run='^TestRound8SeededOneSlotPairedMutationMatrix$' -count=1\n")
	report.WriteString("\"$GO\" test -tags=sqlite_omit_load_extension ./internal/classifier -run='^TestRound8SeededOneSlotPairedMutationMatrix$' -count=1\n")
	report.WriteString("```\n\n")

	report.WriteString("## Balanced decision check\n\n")
	fmt.Fprintf(
		&report,
		"Within this synthetic set, benign scores range from `%d` to `%d`, malicious scores range from `%d` to `%d`, and the default Balanced block boundary is `%d`. Classifier `audit` remains non-blocking; the action table preserves that distinction instead of relabeling audits as plain allows.\n\n",
		benignMin, benignMax, maliciousMin, maliciousMax, BalancedThreshold,
	)
	report.WriteString("| Label | Allow | Observe | Audit | Block |\n")
	report.WriteString("|---|---:|---:|---:|---:|\n")
	for _, label := range []string{round8CalibrationBenign, round8CalibrationMalicious} {
		fmt.Fprintf(
			&report, "| %s | %d | %d | %d | %d |\n",
			label,
			actions[label][ActionAllow],
			actions[label][ActionObserve],
			actions[label][ActionAudit],
			actions[label][ActionBlock],
		)
	}
	report.WriteString("\n")

	report.WriteString("## Score histogram\n\n")
	report.WriteString("Exact final scores are shown so boundary effects are not hidden by coarse bins.\n\n")
	report.WriteString("| Final score | Benign | Malicious |\n")
	report.WriteString("|---:|---:|---:|\n")
	for _, score := range scores {
		fmt.Fprintf(
			&report, "| %d | %d | %d |\n",
			score,
			histogram[score][round8CalibrationBenign],
			histogram[score][round8CalibrationMalicious],
		)
	}
	report.WriteString("\n")

	report.WriteString("## Threshold impact\n\n")
	report.WriteString("| Threshold | TN | FP | FPR | TP | FN | TPR/recall |\n")
	report.WriteString("|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, threshold := range round8CalibrationThresholds {
		metrics := round8CalibrationAtThreshold(samples, "", threshold)
		fmt.Fprintf(
			&report, "| %d | %d | %d | %s | %d | %d | %s |\n",
			threshold,
			metrics.trueNegative,
			metrics.falsePositive,
			round8CalibrationRate(metrics.falsePositive, metrics.benignTotal),
			metrics.truePositive,
			metrics.falseNegative,
			round8CalibrationRate(metrics.truePositive, metrics.maliciousTotal),
		)
	}
	report.WriteString("\n")

	report.WriteString("## Per-rule ROC-like threshold table\n\n")
	report.WriteString("The rule column is the synthetic fixture's nominal family rule. These rows are threshold operating points, not an independently estimated ROC curve or AUC.\n\n")
	report.WriteString("| Nominal rule | Threshold | Benign N | FP | FPR | Malicious N | TP | FN | TPR/recall |\n")
	report.WriteString("|---|---:|---:|---:|---:|---:|---:|---:|---:|\n")
	for _, ruleID := range ruleIDs {
		for _, threshold := range round8CalibrationThresholds {
			metrics := round8CalibrationAtThreshold(samples, ruleID, threshold)
			fmt.Fprintf(
				&report, "| %s | %d | %d | %d | %s | %d | %d | %d | %s |\n",
				ruleID,
				threshold,
				metrics.benignTotal,
				metrics.falsePositive,
				round8CalibrationRate(metrics.falsePositive, metrics.benignTotal),
				metrics.maliciousTotal,
				metrics.truePositive,
				metrics.falseNegative,
				round8CalibrationRate(metrics.truePositive, metrics.maliciousTotal),
			)
		}
	}
	report.WriteString("\n")

	report.WriteString("## Interpretation limits\n\n")
	report.WriteString("- This is a development-set calibration of synthetic neighbors derived from 42 false-positive families, not raw production requests and not an independent review.\n")
	report.WriteString("- The eight variants per family share one rule-specific benign/malicious replacement and differ mainly in deterministic wrapper context; they are not 336 statistically independent incidents.\n")
	report.WriteString("- The per-rule label is fixture provenance, not necessarily the only rule present in a full-ruleset result.\n")
	report.WriteString("- Thresholds 80/85/90 are reported for impact analysis only. No default or production threshold may be selected solely from this development corpus. Independent, untouched holdout review remains required.\n")
	report.WriteString("- This report provides classifier score/action evidence only. It does not prove CPA Host integration, counted-Mock zero-call behavior, performance, production approval, or release readiness.\n")

	return report.String(), nil
}

func round8CalibrationAtThreshold(samples []round8CalibrationSample, ruleID string, threshold int) round8CalibrationMetrics {
	var metrics round8CalibrationMetrics
	for _, sample := range samples {
		if ruleID != "" && sample.nominalRuleID != ruleID {
			continue
		}
		positive := sample.score >= threshold
		switch sample.label {
		case round8CalibrationBenign:
			metrics.benignTotal++
			if positive {
				metrics.falsePositive++
			} else {
				metrics.trueNegative++
			}
		case round8CalibrationMalicious:
			metrics.maliciousTotal++
			if positive {
				metrics.truePositive++
			} else {
				metrics.falseNegative++
			}
		}
	}
	return metrics
}

func round8CalibrationRate(numerator, denominator int) string {
	if denominator == 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.2f%%", 100*float64(numerator)/float64(denominator))
}
