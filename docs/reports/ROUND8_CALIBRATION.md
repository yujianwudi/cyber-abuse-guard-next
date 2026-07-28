# Round 8 synthetic score calibration

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: f9529ada85dee7e35267c70da54aa74e266e88b4ed2703924f352c2cb0cb4333
```

Status: **DEVELOPMENT SELF-CHECK / NOT BLIND OR HOLDOUT EVIDENCE**.

This report is deterministically generated from the public, synthetic Round 8 paired-mutation fixture. It contains only aggregate classifier metadata and no request text. The generated metrics load no `evaluation-v10`, retired/private dataset, or blind-holdout samples.

## Identity and method

- Fixture schema: `round8-balanced-readmission/v1`
- Fixture SHA-256: `bc1e7e852562f05547cd9718075ecd34c161adaa3ac0677d53c9340149fdd1bc`
- Synthetic provenance: `synthetic_from_production_fp_family`
- Deterministic variant seed: `1128351496` (`0x43414708`)
- Families: `42`; variants per family: `8`
- Samples: `336` benign + `336` paired malicious = `672` total
- Classifier policy: `classifier-policy-v7` / `ea8c4dcfacacc6478f86fd2ca5de96d667ae98f2fc6ff0c83d8e6092e9f6a82d`
- Ruleset version: `1.0.9`
- Path: `ClassifySegmentsWithPolicy`, `ModeBalanced`, `DefaultThresholds`, and `DefaultPolicy`; each current trusted-user variant is preceded by the same deterministic 12-segment synthetic history used by the Round 8 regression gate.
- Threshold analysis below is score-only: a sample is positive when `score >= threshold`. It does not replace the classifier's mode, completeness, provenance, core-predicate, hard-floor, or action logic.

Regenerate and verify from WSL Ubuntu-26.04 after setting `GO` to the pinned Go 1.26.4 Linux amd64 binary:

```bash
: "${GO:?set GO to the absolute go1.26.4 linux-amd64 binary path}"
test "$("$GO" version)" = 'go version go1.26.4 linux/amd64'
export GOTOOLCHAIN=local
export GOPROXY=https://goproxy.cn,direct
export GOSUMDB=sum.golang.google.cn
ROUND8_CALIBRATION_UPDATE=1 "$GO" test -tags=sqlite_omit_load_extension ./internal/classifier -run='^TestRound8SeededOneSlotPairedMutationMatrix$' -count=1
"$GO" test -tags=sqlite_omit_load_extension ./internal/classifier -run='^TestRound8SeededOneSlotPairedMutationMatrix$' -count=1
```

## Balanced decision check

Within this synthetic set, benign scores range from `0` to `57`, malicious scores range from `100` to `100`, and the default Balanced block boundary is `60`. Classifier `audit` remains non-blocking; the action table preserves that distinction instead of relabeling audits as plain allows.

| Label | Allow | Observe | Audit | Block |
|---|---:|---:|---:|---:|
| benign | 216 | 0 | 120 | 0 |
| malicious | 0 | 0 | 0 | 336 |

## Score histogram

Exact final scores are shown so boundary effects are not hidden by coarse bins.

| Final score | Benign | Malicious |
|---:|---:|---:|
| 0 | 208 | 0 |
| 9 | 8 | 0 |
| 37 | 112 | 0 |
| 57 | 8 | 0 |
| 100 | 0 | 336 |

## Threshold impact

| Threshold | TN | FP | FPR | TP | FN | TPR/recall |
|---:|---:|---:|---:|---:|---:|---:|
| 80 | 336 | 0 | 0.00% | 336 | 0 | 100.00% |
| 85 | 336 | 0 | 0.00% | 336 | 0 | 100.00% |
| 90 | 336 | 0 | 0.00% | 336 | 0 | 100.00% |

## Per-rule ROC-like threshold table

The rule column is the synthetic fixture's nominal family rule. These rows are threshold operating points, not an independently estimated ROC curve or AUC.

| Nominal rule | Threshold | Benign N | FP | FPR | Malicious N | TP | FN | TPR/recall |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| CRED-001 | 80 | 80 | 0 | 0.00% | 80 | 80 | 0 | 100.00% |
| CRED-001 | 85 | 80 | 0 | 0.00% | 80 | 80 | 0 | 100.00% |
| CRED-001 | 90 | 80 | 0 | 0.00% | 80 | 80 | 0 | 100.00% |
| CRED-002 | 80 | 80 | 0 | 0.00% | 80 | 80 | 0 | 100.00% |
| CRED-002 | 85 | 80 | 0 | 0.00% | 80 | 80 | 0 | 100.00% |
| CRED-002 | 90 | 80 | 0 | 0.00% | 80 | 80 | 0 | 100.00% |
| DISRUPT-001 | 80 | 32 | 0 | 0.00% | 32 | 32 | 0 | 100.00% |
| DISRUPT-001 | 85 | 32 | 0 | 0.00% | 32 | 32 | 0 | 100.00% |
| DISRUPT-001 | 90 | 32 | 0 | 0.00% | 32 | 32 | 0 | 100.00% |
| EVADE-002 | 80 | 128 | 0 | 0.00% | 128 | 128 | 0 | 100.00% |
| EVADE-002 | 85 | 128 | 0 | 0.00% | 128 | 128 | 0 | 100.00% |
| EVADE-002 | 90 | 128 | 0 | 0.00% | 128 | 128 | 0 | 100.00% |
| MAL-002 | 80 | 16 | 0 | 0.00% | 16 | 16 | 0 | 100.00% |
| MAL-002 | 85 | 16 | 0 | 0.00% | 16 | 16 | 0 | 100.00% |
| MAL-002 | 90 | 16 | 0 | 0.00% | 16 | 16 | 0 | 100.00% |

## Interpretation limits

- This is a development-set calibration of synthetic neighbors derived from 42 false-positive families, not raw production requests and not an independent review.
- The eight variants per family share one rule-specific benign/malicious replacement and differ mainly in deterministic wrapper context; they are not 336 statistically independent incidents.
- The per-rule label is fixture provenance, not necessarily the only rule present in a full-ruleset result.
- Thresholds 80/85/90 are reported for impact analysis only. No default or production threshold may be selected solely from this development corpus. Independent, untouched holdout review remains required.
- This report provides classifier score/action evidence only. It does not prove CPA Host integration, counted-Mock zero-call behavior, performance, production approval, or release readiness.
