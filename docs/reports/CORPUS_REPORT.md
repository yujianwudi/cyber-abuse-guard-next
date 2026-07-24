# Historical Project Regression Corpus Report — v0.1.2 candidate

Status: **FROZEN HISTORICAL DEVELOPMENT EVIDENCE ONLY**. This report is not a
current v0.15 test result, release decision, or release-document hash input.

## Scope

The files below are maintained in the same repository as the rules and are a
regression signal, not an independent blind benchmark:

- `testdata/corpus/benign-security.jsonl`: 142 legitimate requests;
- `testdata/corpus/malicious-operational.jsonl`: 154 explicit operational-abuse
  requests.

They cover Chinese and English, ordinary programming, defense/remediation,
CTF/lab/authorization, negation, multi-turn prompts, light obfuscation, and
natural paraphrases. Because developers can see them, a PASS cannot substitute
for the separately authored release evaluation.

## Historical v0.1.1 baseline

Ruleset 1.0.1 previously measured:

| Measure | Historical result |
|---|---:|
| Balanced benign false positives | 0 / 142 (0.00%) |
| Malicious operational recall | 154 / 154 (100.00%) |
| Exact category recall | 154 / 154 (100.00%) |

Those values are historical context only. They are not v0.1.2 results and not
proof of real-world accuracy.

## v0.1.2 final regression run

Ruleset: `1.0.7`

```bash
make corpus-regression
```

| Measure | Requirement | Final result |
|---|---:|---|
| Balanced benign false-positive rate | `< 5%` | **PASS — 0 / 142 (0.00%)** |
| Malicious operational recall | `> 90%` | **PASS — 154 / 154 (100.00%)** |
| Exact category recall | informational | **154 / 154 (100.00%)** |
| Natural-paraphrase exact recall | informational | **18 / 18 (100.00%)** |
| Chinese and English coverage | required | **PASS** |
| Development Round 4 malicious blocking | informational | **64 / 64** |
| Development Round 4 legitimate false positives | informational | **0 / 64** |

```text
candidate_run_utc: 2026-07-12
release_commit_and_tag: NOT CREATED — RELEASE BLOCKED
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
benign_file_sha256: f7d4152fd372819797ac853b5f5ccb21724d8f6c78c574600736ab657457e040
malicious_file_sha256: 27f1328943ef344b0c77e5875a8cf24e4ab01681e7335ed0fd4ca3d97a976ba6
command_exit_status: 0
release_log_sha256: no formal tagged release log — release blocked
overall_regression_gate: PASS (candidate preflight)
```

The project corpus and Round 4 suite pass, but both are developer-visible and
cannot approve a release. v1-v8 are retired or consumed failures; v9 is a
consumed methodology-invalid failure; methodologically valid v10 is a consumed
formal failure (FP 28/320, blocked 49/320, exact 33/320). The v0.1.2 release is
blocked. No generation may be rerun or used for row-specific tuning; a future
attempt requires a new implementation and a new independently authored unseen
set.
