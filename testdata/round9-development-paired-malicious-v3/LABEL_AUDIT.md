# Round 9 paired-v3 pre-execution label audit

## Verdict

This independent, pre-execution, label-only cross-audit re-read and re-evaluated every one of the 120 current paired-malicious fragment records against its referenced development-benign record. All 120 records passed the required structural, referential, semantic-label, difference-axis, malicious-intent, and high-level safety checks.

Draft cases SHA-256: `2a30da8d4872029d9b070a7b8bd8fb72a132994a21975f64b49cd56ecf4b2b3d`

Reviewed records: 120

Passed records: 120

Failed records: 0

Candidate output observed: false

Classifier or project tests run: false

Overall verdict: PASS

## Scope and blind-audit boundary

The only corpus content read for this audit was:

- `testdata/round9-development-benign-v1/cases.jsonl`
- `testdata/round9-development-paired-malicious-v3/fragments/*.jsonl`

No source, rule, classifier, manifest, generated or candidate `cases` output, independent corpus, freezer, runner, Go test, project test, or network resource was read or executed. Candidate output was not observed. `LABEL_AUDIT_REJECTED_DRAFT1.md` was not used as an audit input and was not modified or deleted. The benign cases and paired-v3 fragments were not modified.

## Draft digest method

The digest was calculated from the current fragments in this exact family order, retaining the line order within each fragment:

1. `ordinary_coding_refactor`
2. `os_operations`
3. `oauth_token_api_key_lifecycle`
4. `enterprise_credential_lifecycle`
5. `siem_edr_ids_log_analysis`
6. `sigma_yara_ioc_detection`
7. `malware_static_analysis`
8. `forensics_incident_response`
9. `security_education_quote_translation`
10. `ctf_isolated_lab`
11. `load_capacity_chaos_recovery`
12. `enterprise_remote_management_agent`
13. `inert_carriers_history`
14. `long_context_risk_vocabulary`
15. `mixed_zh_en_colloquial`

Each source line was trimmed at both ends and followed by exactly one LF. SHA-256 was then calculated over the final UTF-8 bytes without a BOM.

## Checks performed

| Check | Result |
|---|---:|
| Fragment families present in the required order | 15/15 |
| Records per family | 8 each |
| Total records | 120 |
| Records with the exact required field set | 120/120 |
| Records with all required fields populated | 120/120 |
| Unique `id` values | 120/120 |
| Unique `benign_base_id` values | 120/120 |
| Existing benign references | 120/120 |
| Benign family alignment | 120/120 |
| Benign language alignment | 120/120 |
| `expected_decision = block_malicious_text` | 120/120 |
| `label_confidence = unambiguous` | 120/120 |
| `authoring_context = visible_round9_paired_development_v3` | 120/120 |
| Category matches the explicit malicious behavior | 120/120 |
| Declared `difference_axis` is substantively present | 120/120 |
| Current request is active, realistic, executable, and unambiguously malicious | 120/120 |
| Non-`execute_referent` records with a literal quoted malicious payload | 0/105 |
| `execute_referent` records with an actual quoted payload | 15/15 |
| `execute_referent` records with explicit immediate execution/application language | 15/15 |
| `real_deployment` records with an explicit live/production/real environment | 15/15 |
| `real_deployment` records with a non-consenting or unaware victim | 15/15 |
| Records that are merely analysis, detection, quotation, education, authorized defense, or meta-labeling | 0/120 |
| High-level safety text without executable code, commands, real targets, credentials, procedural steps, or directly reusable abuse detail | 120/120 |

The audit compared each malicious prompt with its referenced benign prompt. References exist one-to-one, stay within the same subject family, and preserve the declared language. The malicious side consistently changes the user request into a present-tense or imperative abuse request rather than merely mentioning risky vocabulary or describing a defensive scenario.

## Distribution summary

### By family

| Family | Records |
|---|---:|
| `ordinary_coding_refactor` | 8 |
| `os_operations` | 8 |
| `oauth_token_api_key_lifecycle` | 8 |
| `enterprise_credential_lifecycle` | 8 |
| `siem_edr_ids_log_analysis` | 8 |
| `sigma_yara_ioc_detection` | 8 |
| `malware_static_analysis` | 8 |
| `forensics_incident_response` | 8 |
| `security_education_quote_translation` | 8 |
| `ctf_isolated_lab` | 8 |
| `load_capacity_chaos_recovery` | 8 |
| `enterprise_remote_management_agent` | 8 |
| `inert_carriers_history` | 8 |
| `long_context_risk_vocabulary` | 8 |
| `mixed_zh_en_colloquial` | 8 |

### By category

| Category | Records |
|---|---:|
| `credential_theft` | 16 |
| `data_exfiltration` | 16 |
| `defense_evasion` | 16 |
| `malware_deployment` | 8 |
| `phishing_deployment` | 16 |
| `prompt_injection_evasion` | 16 |
| `ransomware_deployment` | 8 |
| `service_disruption` | 8 |
| `unauthorized_exploitation` | 16 |

### By difference axis

| Difference axis | Records |
|---|---:|
| `bypass_consent` | 15 |
| `covert_acquisition` | 15 |
| `execute_referent` | 15 |
| `exfiltration_or_takeover` | 15 |
| `real_deployment` | 15 |
| `service_disruption` | 15 |
| `third_party_victim` | 15 |
| `unauthorized_target` | 15 |

### By language

| Language | Records |
|---|---:|
| `en` | 60 |
| `zh` | 60 |
