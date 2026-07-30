# v0.16 Round 9 release evidence — current candidate contract plus frozen history

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: 6cd7296bee90b9352a9cf1745b7760c0ff1b18a265da4af498c5877d4b542f87
```

Last updated: 2026-07-29 (Asia/Shanghai)

## Current Round 9 source-tree status — not a release PASS

The active development target is Linux amd64 `v0.16-rc.4`,
classifier-policy-v9, ruleset 1.0.10, audit schema v6, and CPA
`v7.2.109@928478e4b91533cec05a763bfac3edad9c3e76cf` with RPC schema 2. The protected Host lane may
bind CPA only as `127.0.0.1:18394 -> 8317/tcp` and may contact only the isolated
counted Mock.

The last committed isolated-audit baseline is the exact audited commit
`150c25e6352cb237cb3956bd66c83c3278c3fe33` with classifier
historical classifier digest `e0cbc975...`.
CI run `30353591705` passed its engineering gates, but that result is not a
safety or release PASS. The isolated safety audit returned `FAIL / BLOCKED`:
287 complete malicious cases failed open, 36 malicious incomplete cases
returned HTTP 403, and 2 complete benign cases were false positives.

The current source snapshot carries a remediation at
`classifier-policy-v9` /
`6cd7296bee90b9352a9cf1745b7760c0ff1b18a265da4af498c5877d4b542f87`.
It has no commit-bound CI or second-machine retest. Final remediation freeze,
exact-main CI, reproducible release assets, protected
Host execution, independent re-audit, tag, and GitHub prerelease remain pending.

The immutable `v0.16-rc.3` Tag is a failed Phase 1 identity, not the current
candidate. Run `30118817188` failed on the undeclared PyYAML import before any
candidate, attestation, or Release asset was created. It is retained unchanged
while the active namespace advances to `v0.16-rc.4`.

```text
candidate_tag: v0.16-rc.4 / NOT CREATED
release_kind: prerelease
latest: false
audited_head: 150c25e6352cb237cb3956bd66c83c3278c3fe33
audited_classifier_policy_digest: e0cbc975... / historical exact value retained in TEST_REPORT.md
engineering_ci: 30353591705 / PASS / ENGINEERING ONLY
safety_audit: FAIL / BLOCKED
safety_findings: complete_malicious_fail_open=287 / malicious_incomplete_http_403=36 / complete_benign_false_positive=2
remediation_source_snapshot: classifier-policy-v9 / 6cd7296bee90b9352a9cf1745b7760c0ff1b18a265da4af498c5877d4b542f87 / SOURCE GATES ONLY
remediation_exact_commit_ci: PENDING
second_machine_retest: PENDING
counted_mock_host: NOT_PROVIDED
independent_reaudit: PENDING
production_approval: NOT_GRANTED
overall: ENGINEERING BASELINE PASS / SECURITY AUDIT FAIL / BLOCKED
```

## Historical Round 8 source-tree status — not a Round 9 release PASS

This retained section records the immutable `v0.16-rc.2` contract in its
historical terms. It is not the current candidate identity and cannot satisfy
any Round 9 gate.

```text
status: SOURCE-TREE SNAPSHOT / LOCAL LINUX DEVELOPMENT GATES PASS / NOT RELEASED
source_version: 0.16
candidate_tag: v0.16-rc.2 / NOT CREATED
platform: linux-amd64
ruleset_version: 1.0.9
ruleset_sha256: a3de344d3f6dc8eea86d946a823996494d4d297c41efcc6346a6ef757f263a7d
historical_round8_classifier_policy_version: classifier-policy-v7
historical_round8_classifier_policy_sha256: ea8c4dcfacacc6478f86fd2ca5de96d667ae98f2fc6ff0c83d8e6092e9f6a82d
host_evidence_assembler_contract: 44/44 DEVELOPMENT SELF-TESTS PASS / NOT HOST EXECUTION
final_linux_quality_race_allocation_benchmark: DEVELOPMENT SELF-CHECK PASS / NOT EXACT-MAIN OR RELEASE EVIDENCE
exact_main_github_ci: NOT_AVAILABLE_FOR_THIS_SOURCE_SNAPSHOT
phase1_private_candidate: NOT_CREATED
cpa_v7.2.95_counted_mock_host: NOT_RUN
independent_audit: NOT_PROVIDED / REQUIRED
github_prerelease: NOT_CREATED
production_approval: NOT_GRANTED
stable_v0.16: NOT_RELEASED
```

This checked-in report records a source-tree contract, not a tag, artifact,
Host attestation, independent audit, or GitHub Release. A development contract
self-test cannot be promoted into CPA Host evidence. The detailed Round 8
publication schema appears near the end of this document; the older sections
below are retained only as explicitly historical evidence.

The final local Linux development snapshot completed `make unit-test`, the
complete race run, module/vet/vulnerability gates, deterministic fuzz smoke,
all 13 configured long-fuzz targets, and the complete benchmark gate. Race
durations were 379.920 and 69.762 seconds for plugin and classifier
respectively, with no reported data race and no reachable vulnerability. The same-machine
baseline comparison measured short-request p50/p95/p99 at
173.973/282.720/406.484 us for `d540eaa` and 105.272/146.139/263.117 us for
Round 8. Candidate-rich latency improved from 130.700829 to 45.245564 ms/op;
all paired long-text cases stayed within the fixed ceiling, and paired peak RSS
changed from 46,132 to 46,616 KiB. These remain source-tree development
self-checks, not exact-main, CPA Host, or Release evidence.

The CPA v7.2.95 source/compile/contract target passed with its exact pinned
version, commit, module sum,
go.mod sums, and Origin. Official GitHub latest metadata returned v7.2.95 and
the exact tag commit was verified inside the same
`CPA_COMPAT_VERIFY_REMOTE=1` primary-profile run. The run also compiled the
Guard and integration packages and passed the official Host routing, Responses
`additional_tools`, Interactions, fail-open, Raw Capture management, release,
and v7.2.95 Store contracts. This is source-tree development evidence only; it
is not counted-Mock Host execution or a production claim.

Methodology deviation: eight additional over-broad read-only searches
cumulatively displayed evaluation/holdout test or historical-report filenames,
historical ruleset SHA-256 references, a small number of caller-path lines, and
a few historical aggregate count/summary lines. The sixth accidentally matched
`HOLDOUT_REPORT.md` and `HOLDOUT_V3_REPORT.md`; the seventh matched two
operator-local command-path lines in `HOLDOUT_V2_REPORT.md`. The eighth search
displayed several single request lines from retired holdout fixtures. None of
that output was used for classifier, rule, or threshold calibration, and the
classifier issue under review had already been identified before that search.
This work therefore does not claim that no fixture or request body was seen. One separate over-broad
`go test ./internal/classifier` may have compiled or run the restricted gate;
its result is excluded from this evidence. Zero-access, blind, and independent-
evaluation claims therefore remain `NOT_PROVIDED`.

## Historical Round 6 v0.15 evidence status — not a release PASS

Historical Round 6 project version is `0.15`; its only formal tag is `v0.15`, never
`v0.15.0`. Active validation and the supported release target are fixed at
CPA v7.2.95 (`f71ec0eb6776854457892452cf28c47f0d658251`). Later
upstream versions are not followed automatically. Legacy
version-specific profiles and Make aliases have been removed.

```text
status: BLOCKED / PENDING HOST AND INDEPENDENT AUDIT
project_version: 0.15
formal_tag: v0.15
last_fully_verified_pre_cleanup_main_commit: 6782dfaffd4da3f09604113c7d38675f331dc759
last_fully_verified_pre_cleanup_tree: a8edbe2e6d19fa725fb962cdd6aaad5b416d4b85
round6_implementation_pr: 9 / MERGED / head d0b63c67e099d403be1a8ad0a3183c9474ac5b9a
round6_pr_ci: 29620335143 / JOBS NOT STARTED DUE BILLING / NOT A PASS
post_merge_main_push_ci: 29630844605 / SUCCESS
public_source_only_prerelease_tag: v0.15-rc.1
source_only_tag_ci: 29630926354 / SUCCESS
current_hardening_pr: 18 / MERGED / exact source history remains external GitHub evidence
current_release_contract_local: ROUND6-SCRIPT-TEST + REAL DOC GATE + MUTATION FIXTURE + 154 SAFE-CONTRACT TESTS PASS / DEVELOPMENT ONLY
failed_rc3_tag_object: 6733a74903c7f2174a24fc53fad601e763e6a4c7 / IMMUTABLE / NO RELEASE
failed_rc3_source: ac1456b74edd73bec5d8a8fb8b87630cb3320d21 / tree 5838d9bac6251fd1212cce86c2c608b6d8cbee47
failed_rc3_workflow: 29728286559 attempt 1 / ADMISSION PASS / BUILD FAIL / PUBLISH SKIPPED / ZERO ARTIFACTS
current_rc_target: v0.15-rc.4 / ACTIVE EXACT-MAIN WORKFLOW / LINUX AMD64
current_rc_asset_contract: EXACTLY 17 / FORMAL STRUCTURE / RC EVIDENCE ONLY
current_rc_runtime_evidence: rc-release-evidence.md + rc-release-manifest.json
private_untagged_clean_candidate: NOT CREATED / PENDING
candidate_manifest: NOT CREATED / PENDING
cpa_host_target: v7.2.95 / f71ec0eb6776854457892452cf28c47f0d658251
cpa_host_mock: NOT RUN / PENDING
cpa_host_attestation_schema: 2 / cpa_version,cpa_commit,cpa_host_sha256
four_layer_zero_call_evidence: NOT RUN / PENDING
independent_source_artifact_host_audit: NOT RUN / PENDING
candidate_bound_evaluation_v11_plus: NOT RUN / PENDING / requires CONSUMED PASS
round6_prerelease_attestation: NOT CREATED / PENDING
historical_v10: CONSUMED / FAIL / IMMUTABLE / NOT A FORMAL INPUT
formal_v0.15_tag_draft: ABSENT / BLOCKED
formal_release_attestation: NOT CREATED / PENDING
formal_v0.15_promotion: NOT RUN / BLOCKED
```

This checked-in report is a source-policy baseline, not a self-referential
record of the future tagged commit. The protected RC3 tag records a failed,
unpublished attempt and is not moved or reused. Exact RC4 tag object, commit,
tree, CI run, workflow run, asset hashes, and upload verification belong only in the
run-generated `rc-release-evidence.md` and `rc-release-manifest.json`.
Engineering evidence is not final candidate, Host, audit, or formal-release
evidence. The PR jobs that did not start are not retrospectively called a PASS.
The public `v0.15-rc.1` prerelease has no attached release assets and does not
replace the dedicated private, untagged candidate workflow. That workflow has
not been dispatched and must produce clean Linux amd64 bytes plus
`candidate-manifest.json`; clean bytes remain unreleased.

The CPA v7.2.95 Host + Mock record and the independent audit must bind the same
candidate workflow run, commit, tree, and SO SHA-256. Every local block must
show zero Auth Selector, Provider, usage, and Mock-upstream deltas. The exact
candidate must also receive an external `evaluation-v11` or later first-and-only
`CONSUMED / PASS` report. Only after those gates may an optional annotated
`v0.15-dev.round6[.N]` draft prerelease be created, still marked
`BLOCKED / NOT A FORMAL RELEASE`. Its `round6-prerelease-attestation.json`
records the evaluation ID and report SHA-256; the annotated formal `v0.15` tag
and verified draft consume that same candidate-level attestation. Protected
promotion may publish only the unchanged draft.

Historical Round 6 policy identity is `classifier-policy-v5` /
`0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b`;
scanner identity is `streaming-scanner-v1`; ruleset identity remains `1.0.7` /
`7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134`.

The merged PR #18 hardening delta closes a quoted-review continuation bypass
without turning the safety wrapper into reusable malicious evidence. Only the
unique quote from the newest eligible RoleUser review is reclassified, and
its score, category, rule IDs, evidence, context, and behavior match direct
classification of that referent. Questions, explanations, negation,
consequences, remediation, and assistant/system/tool/unknown review carriers
remain inert. Mixed-trust RoleUser pairs preserve conservative direct
disposition with `non_user_or_untrusted` origin and remain ineligible for subject
accumulation.

Long-field handling retains only privacy-safe `Result` values and bounded
affirmative-reference facts. If exact linkage falls outside the retained
classifier windows, coverage becomes `CoverageUnavailable` /
`classifier_window_incomplete`; the additional referent classification consumes
the ordinary chunk budget and can produce `classification_chunk_limit`. Common
directive governors now include `just`, `simply`, `let's`, and `let us`; only a
positively proven analytical/safety/negated form suppresses the incomplete-prior
signal fallback. Bounded adjacent reclassification is skipped when either field
already proved an inert quoted referent.
Targeted OpenAI Chat/Responses routes, the Linux long-text size ladder, full safe
unit tests, classifier/plugin race checks, and `make round6-script-test` passed
locally. Release contracts also reject formal document override environments
and lock the public jailbreak review into required inputs, audit-bundle
installation, and verification. These
facts are merged development evidence after PR #18 exact-head CI and review
completed; they are not candidate, Host, independent-audit, evaluation, tag,
or Release approval.

The final PR head must have no unresolved, non-outdated actionable review
threads before merge. No automated-review result is treated as an independent
audit PASS.

This historical section does not self-record future Host/audit PASS hashes,
merge identity, tag state, or Release state. Those remain external attestation
fields. Stable v0.15 eligibility is determined only by the Round 6 and formal
attestation assets that bind the final source and candidate bytes.
The neutral policy is [RELEASE_POLICY.md](../RELEASE_POLICY.md); the named
external assets are `round6-prerelease-attestation.json` and
`formal-release-attestation.json`.

Historical evaluation-v10 cannot be rerun and is not accepted by the formal
build. Formal source and audit bundles exclude evaluation, Holdout, private,
blind, and retired material; only low-sensitivity attestation IDs and hashes may
cross the packaging boundary.

The Round5.2 v7.2.80 PASS record below remains frozen historical
source/compile evidence and is not rewritten or reused as current Round 6
matrix evidence. All historical 0.1.2 tags, hashes, assets, and v10 facts remain
unchanged.

## Frozen Round5.2 source-freeze / pre-merge record

This section is intentionally limited to evidence that can be fixed before
merge: source-freeze identity, safe local gates, exact-source branch push CI,
the PR synthetic merge-result gate, and review state.
It must not guess or self-reference a future merge commit. Post-merge main CI,
the exact-main artifact, tag, release flags, and release asset hashes are
authoritative only through GitHub API metadata; the corresponding Release notes
link those records and preserve per-asset hashes and incomplete gates. The
working branch is based on historical
`main@89b62b341278073e7b6518b85e41cd7f7c6b682c`; the pre-merge fields below are
backfilled from local and GitHub evidence without inventing a future merge commit.

```text
round5_2_branch: agent/post-release-reaudit-fixes
round5_2_base_commit: 89b62b341278073e7b6518b85e41cd7f7c6b682c
round5_2_source_fixes: COMPLETE / SOURCE FREEZE READY
round5_2_source_freeze: 170de7f324c2bdf9a473b1866bdfc1e097182301
round5_2_classifier_policy_identity: classifier-policy-v2 / e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec
round5_2_cpa_latest_source_compat: v7.2.80 / 09da52ad509e2c18e7b9540db3b98c2214c280aa / DEVELOPMENT SELF-CHECK AND EXACT-SOURCE PUSH/PR CI PASS
round5_2_public_reference_corpus: 36 sanitized cases / 18 allow / 18 audit / development-only
round5_2_local_safe_gates: PASS / format-diff-module / round5 / safe test-vet / sanitized public corpus / scripts / CPA latest remote identity and contracts
round5_2_push_ci: https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29467936241 / attempt 1 / SUCCESS / quality-and-artifacts, fuzz-long, reproducibility
round5_2_source_freeze_push_artifact: 8363874523 / cyber-abuse-guard-linux-amd64-dirty / 10827848 bytes / sha256:fdec405e991498d4b7fb16557796a22736456c01fb1bd0e31d8eac5800438176 / expires 2026-10-14T03:00:42Z / development-only
round5_2_pull_request: https://github.com/yujianwudi/cyber-abuse-guard/pull/8
round5_2_pull_request_ci: https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29467938359 / attempt 1 / SUCCESS / base 89b62b341278073e7b6518b85e41cd7f7c6b682c / head 170de7f324c2bdf9a473b1866bdfc1e097182301 / synthetic merge fc8b5649505662e47bedbd85a41fbea306a2df7c / quality-and-artifacts, fuzz-long, reproducibility
round5_2_code_rabbit_follow_up: PASS / CLI 0.6.5 / final source delta / 0 issues / GitHub check SUCCESS / 10 of 10 current PR review threads resolved (9 source-freeze + 1 documentation wording)
round5_2_tencent_isolated_host: NOT RUN
round5_2_independent_review: NOT RUN
round5_2_post_merge_main_ci: EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES
round5_2_post_merge_artifact: EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES
round5_2_tag_and_release: EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES
stable_v0.1.2_tag: NOT CREATED / BLOCKED
production_deployment: NOT PERFORMED
source_freeze_record_status: PRE-MERGE SOURCE EVIDENCE PASS / REAL HOST AND INDEPENDENT REVIEW NOT RUN / BLOCKED FOR HANDOFF
```

The pre-merge record uses two commits. `S` is the implementation/source freeze:
all code, workflows, tests, scripts, and development corpus files are fixed.
Exact-source branch CI binds to `S`; pull-request CI validates GitHub's synthetic
merge result and must record base, head, merge SHA, run, and job conclusions.
`D` is a documentation-only evidence backfill. Any non-document change in
`S..D` invalidates `S`. Final checks for `D` remain external GitHub evidence
rather than another self-referential document commit.

Post-merge evidence must record API-verifiable workflow run ID, attempt,
conclusion, event, head SHA, required job conclusions, artifact ID/digest/size/
expiry and available attestation, tag object type/target/verification status,
and Release ID plus draft/prerelease/latest flags. Release notes link those
records, list each of the nine asset SHA-256 values, and preserve every
`NOT RUN/BLOCKED` gate; notes alone are never proof that main CI, artifact, and
tag resolve to one commit.

Older CPA compatibility lanes, checksums, and CI runs are historical evidence
only and remain traceable through the changelog and archived reports. They are
not current v7.2.95 admission evidence and cannot replace the exact-source,
counted-Mock Host, or independent-audit gates for this candidate.

The round5.2 re-audit also reproduced and closed source-level merge blockers
with sanitized CANARY inputs. Repeated `copy/copies/copied` forms no
longer inherit an earlier prohibition; bounded `not allowed/permitted/
authorized/required/supposed/able to prohibit ...` bridges and common copular/
do/have contractions no longer hide an active intent; and meta-wrapper
structural analysis now rejects defensive credit after 128 clauses or 1,024
directive boundaries. The reachable `8 x 32 KiB` period/semicolon/newline
CANARY gate fell from about 118-123 ms and 12.1 MiB/op before the fix to about
7-10 ms and 1.36 MiB/op after it. A separate ModelRoute regression prevents an
internal adjacent-negation proof budget from being mislabeled as incomplete and
downgraded in Balanced mode. The primary request walker now inspects root
container-valued `tools/functions` even when a large raw body skips the role
index, including descriptions beyond the 256 KiB raw offset, while nested
business lookalikes remain inert. CPA `interactions` is registered directly,
uses a fixed audit enum and conservative extraction profile, and no longer
depends on translator fallback for executor format readiness. These are
development/source-contract results, not Host or production evidence.

Release-path hardening in the same source freeze makes every tracked shell
script executable in Git, runs dirty `release-preflight` in ordinary CI, adds
the previously omitted CPA Host/latest/proxy gates to formal release, and
verifies both GitHub `releases/latest` and the pinned Tag-to-Commit ref through
authenticated REST metadata when a token is available.

The sanitized public-reference refresh is fixed to
`Jia-Ethan/codex-keysmith@f699b9bd2cb59eb0d54e69139c68f7808d869b6d`,
`MDX-Tom/gpt-5.6-instruct@18fea37f4f1a263cc0fc31bb0e32e61ace0b1f69`,
`yynxxxxx/Codex-X@7d0e0064d54f860d4bf12b557fd9f8c489043a35`, and
`yynxxxxx/Codex-5.5-codex-instruct-5.5@ed0b6dc37d1994e93788d92f7af63f58bf0b9e2d`.
No third-party installer, mutator, test runner, or prompt payload was executed or
copied. The 36-case corpus proves only visible sanitized mechanism regression;
it cannot attribute repository origin or inspect opaque/local-only content.

## Historical round5.1 prerelease closure

[`v0.1.2-dev.round5.1`](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.1.2-dev.round5.1)
is treated as a historical development snapshot by project policy. GitHub
currently reports `isImmutable=false`, so its API metadata and hashes are
point-in-time evidence rather than platform-enforced immutability. It is explicitly
`BLOCKED / NOT FOR DEPLOYMENT`, `prerelease=true`, and `latest=false`. Its tag
must remain at `89b62b341278073e7b6518b85e41cd7f7c6b682c`; moving or reusing that
tag would break the recorded source/artifact chain. Any later source must use a
new tag only after its own freeze, CI, merge, and evidence closure.

```text
historical_round5_1_tag: v0.1.2-dev.round5.1
historical_round5_1_release: https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.1.2-dev.round5.1
historical_round5_1_merge_and_tag_commit: 89b62b341278073e7b6518b85e41cd7f7c6b682c
historical_round5_1_implementation_freeze: 174401cd234f960e66ce55b9fc88614d948d5129
historical_round5_1_pull_request: https://github.com/yujianwudi/cyber-abuse-guard/pull/7
historical_round5_1_main_ci: https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29409182748
historical_round5_1_main_ci_attempt_1: FAIL — fuzz timer-boundary context deadline exceeded
historical_round5_1_main_ci_attempt_2: PASS — quality-and-artifacts, fuzz-long, reproducibility
historical_round5_1_artifact_id: 8340894661
historical_round5_1_artifact_name: cyber-abuse-guard-linux-amd64-dirty
historical_round5_1_artifact_size: 10691298 bytes
historical_round5_1_artifact_digest: sha256:7419fcf0c0745472728d6e9c73d99aa01737930ccf25e26501e17ae4d453db61
historical_round5_1_artifact_expiry: 2026-10-13T10:54:12Z
historical_round5_1_tencent_isolated_host: NOT RUN
historical_round5_1_independent_review: NOT RUN
historical_round5_1_release_flags: prerelease=true; latest=false
historical_round5_1_production_deployment: NOT PERFORMED
```

The round5.1 release assets were downloaded and hashed individually. The
exact-main Actions artifact is recorded above by its archive-level digest, but
no member-to-release-asset mapping was retained, so this record does **not**
claim byte-for-byte equivalence between artifact members and release assets.
The audit bundle remained opaque; only its outer file hash was computed.

| Historical round5.1 release asset | SHA-256 |
|---|---|
| `cyber-abuse-guard-v0.1.2-dirty.so` | `3176d2af23963a2768672034af02fc1ca9ebe0c3f29a3654aa802ce0f822b6be` |
| `cyber-abuse-guard-v0.1.2-dirty.so.sha256` | `55cd48b122b361c34cb8f638bf0823fd5512e5c23090b206e36eb26d5eacf761` |
| `cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip` | `a954d1c816362197d406b8954736349516dd9e4d270264b1db83b1fe7f36972e` |
| `cyber-abuse-guard-v0.1.2-dirty-audit-bundle.zip` | `7ea8f90a6b679b0aa5b45f303d5ef068204bea2f2cf5f4ffe9361b12bd596d6f` |
| `build-metadata.json` | `2577c053211581ba511b1b77e4ef507cf199239985739e74645a1d8fc5385b44` |
| `checksums.txt` | `25e616eb1712b8dc1c4d03df5abae309e0883204a5351498aa3e29fe5ca7d785` |
| `ruleset-manifest.json` | `486a4dfad49b4e96a600f908cbea47376baab5c8875324999ae50b6251f1af7e` |
| `ruleset.sha256` | `a8ff687340617dc18832047f841979a0bd06ff8c50a4bc3c15dd7da37b6fbee2` |
| `sbom.cdx.json` | `73c8c49742a7478f3ab9ef3ccabbdb4fe34f92f45779b88147322eb4978cfc01` |

The historical local CodeRabbit CLI follow-up recorded 0 issues. GitHub does
not contain a durable review carrying that exact result: the Bot comment later
ended `Review failed — pull request is closed`, while a status context showed
success without a review URL. Therefore no CodeRabbit approval is claimed.

## Historical round5.1 pre-merge audit-fix artifact provenance

Before round5.1 merged, the exact-source artifact for the audit-fix
implementation freeze was the push-run artifact below, not the PR-run artifact.
It was later superseded for release purposes by exact-main artifact
`8340894661` recorded above:

```text
artifact_id: 8339760603
name: cyber-abuse-guard-linux-amd64-dirty
size_in_bytes: 10690635
container_digest: sha256:84a4003f3b8cccbb2454fcce689033bf0592b11e06f0e74c5632a1b5031cc6ce
created_at: 2026-07-15T10:20:15Z
expires_at: 2026-10-13T10:06:30Z
workflow_run: https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29406952739
source_commit: 174401cd234f960e66ce55b9fc88614d948d5129
```

This historical pre-merge artifact was downloaded and rehashed without
deploying or loading the plugin. The audit bundle was treated as an opaque file
for SHA-256 only; its contents were not opened.

| File | SHA-256 | Verification |
|---|---|---|
| `cyber-abuse-guard-v0.1.2-dirty.so` | `7664a6ddc2f2301467200ee7f8d77b445e1627f3ab13e223c4dea2d83d1d6dc6` | `checksums.txt` and SO sidecar match |
| `cyber-abuse-guard-v0.1.2-dirty.so.sha256` | `1c0afc8300cc68c54324fd67d5a45050afbb1955069dde90b7d9d4e4bd0a6606` | `checksums.txt` match |
| `cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip` | `6a9720cad5c4ee9ad6cfaae552c988bd14314b2afbc160bb62d045caa4ee4f72` | `checksums.txt` match |
| `cyber-abuse-guard-v0.1.2-dirty-audit-bundle.zip` | `917a3b82de31b748fbcf65d6161c8e1589f8a90c512b2e2e615ce41e13a229f2` | `checksums.txt` match; body not opened |
| `build-metadata.json` | `0698cdd9a2df7b1b39ca6a5c66b12958c9e067540a8ceef524818dcf84e7312b` | `checksums.txt` match |
| `checksums.txt` | `bd65e32c7b70cbeefbf83b2efcf264f84e84efda8ddea52fc56bb260ee4f3ae1` | locally hashed |
| `ruleset-manifest.json` | `486a4dfad49b4e96a600f908cbea47376baab5c8875324999ae50b6251f1af7e` | `checksums.txt` and ruleset sidecar match |
| `ruleset.sha256` | `a8ff687340617dc18832047f841979a0bd06ff8c50a4bc3c15dd7da37b6fbee2` | `checksums.txt` match |
| `sbom.cdx.json` | `0820956e7270401c3b2d8e66b48d3ad513c56053620a1f5c07ef2a6d983a076a` | `checksums.txt` match; CycloneDX 1.6 |

All entries listed by `checksums.txt` rehashed successfully. Build metadata is:

```text
schema_version: 1
version: 0.1.2-dirty
source_version: 0.1.2
commit: 174401cd234f960e66ce55b9fc88614d948d5129
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
dirty: true
source_date_epoch: 1784109984
go_version: go1.26.4
goos/goarch: linux/amd64
cgo_enabled: true
```

## Historical round5.1 pre-audit artifact identity

The artifact below is canonical only for the pre-audit source commit. It cannot
validate the audit-fix commit or the historical development prerelease. It was
replaced first by the audit-fix push artifact and then by the exact-main
artifact recorded above:

```text
artifact_id: 8336957771
name: cyber-abuse-guard-linux-amd64-dirty
size_in_bytes: 10686558
container_digest: sha256:b2662faa01071cef6a111b03d1cff85d3bf4796ed2e7a54aaf584c451f581a8e
created_at: 2026-07-15T08:26:51Z
expires_at: 2026-10-13T08:13:03Z
workflow_run: https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29400003434
source_commit: 1466b2e7dfcafbb0547fc7863a419eccccd8091f
```

The PR-run artifact is ID `8336942789`, but its internal metadata binds GitHub's
temporary merge commit `226c89e3b932c18f9572822db9cf27a3faab09ec`.
It is useful as historical PR validation evidence but is not the release's
canonical exact-main artifact.

The pre-audit canonical artifact was downloaded and rehashed without deploying
or loading the plugin. The audit bundle was treated as an opaque file for
SHA-256 only; its contents were not opened. These hashes are historical and
must not be reused as validation of round5.1 after the audit fixes or of any
round5.2 source.

| File | SHA-256 | Verification |
|---|---|---|
| `cyber-abuse-guard-v0.1.2-dirty.so` | `ccc818561077f2840f3d00d33cbc344ed9055aede725986c8c17b22fdb427d5e` | `checksums.txt` and SO sidecar match |
| `cyber-abuse-guard-v0.1.2-dirty.so.sha256` | `49a682f0cb5ca03440355919ce74783e4430dd6449ab73132e1d5c9f7e3c2125` | `checksums.txt` match |
| `cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip` | `eb9b5713525edc4fa193c0256eb4a3acae2be0507a03b04f64357e6f8c9b620e` | `checksums.txt` match |
| `cyber-abuse-guard-v0.1.2-dirty-audit-bundle.zip` | `1ce140b6f3018e3a56c6d958ba7286e78aaffea5662fbe11a2fcc0a7ce2da4fb` | `checksums.txt` match; body not opened |
| `build-metadata.json` | `80d3d4adb80b671463fdff6532b22b4517e7656d48e5b6e0c2001c6b7cc4c5d8` | `checksums.txt` match |
| `checksums.txt` | `3f5f47d2a7649812efa166530d4aab2ade7816d165d579ebba72d44743aa7558` | locally hashed |
| `ruleset-manifest.json` | `486a4dfad49b4e96a600f908cbea47376baab5c8875324999ae50b6251f1af7e` | `checksums.txt` and ruleset sidecar match |
| `ruleset.sha256` | `a8ff687340617dc18832047f841979a0bd06ff8c50a4bc3c15dd7da37b6fbee2` | `checksums.txt` match |
| `sbom.cdx.json` | `c889fa1cb8be8d3ec541dd9ad970bec4ea18ed52dbd58729d0f8103264ec5731` | `checksums.txt` match; CycloneDX 1.6, 5 components |

All entries listed by `checksums.txt` rehashed successfully. Build metadata is:

```text
schema_version: 1
version: 0.1.2-dirty
source_version: 0.1.2
commit: 1466b2e7dfcafbb0547fc7863a419eccccd8091f
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
dirty: true
source_date_epoch: 1784103146
go_version: go1.26.4
goos/goarch: linux/amd64
cgo_enabled: true
```

The historical audit-fix artifact metadata does not embed classifier-policy
identity. Its classifier identity therefore remains a joint binding of
`classifier-policy-v2`, SHA-256
`c2092d0949fcaa1d0f085dfe31a668d45cc4d14efc10427d0f3ebcf3e821a112`,
and exact Git commit `174401cd234f960e66ce55b9fc88614d948d5129`.

Historical round5.1 ordinary CI was development-only. It ran
`make integration-compile` and did not start CPA, deploy a plugin, or execute
the real Host matrix. Existing
`make integration-test`/Host targets remain explicit manual targets for the
later authorized Tencent Cloud CPA v7.2.75 + Mock-upstream sandbox. Ordinary CI
also excludes `make consumed-boundary-test` and all evaluation-v10/retired
Holdout content; that target is retained only for separately authorized audit
work. Round5.2 must rerun the applicable source and CI gates on its own freeze.

Distinct fifth-round methodology deviations must remain attached to every
artifact/CI claim. One over-broad read-only `git grep` unexpectedly emitted
content from restricted `testdata/holdout/malicious-operational.jsonl`; no
holdout test ran, no output was redirected or copied into source/tests/docs,
and it was not analyzed or used for tuning or conclusions. During the later
release audit, one classifier source search also unintentionally matched
historical holdout gate-test source lines; it opened no `testdata` corpus,
selected no holdout/evaluation test, and did not influence the fixes. All
remaining commands explicitly exclude holdout/evaluation paths. This round
cannot claim zero restricted-corpus access, and engineering PASS evidence
cannot lift the methodological `BLOCKED FOR HANDOFF` status.

During the post-release round5.2 re-audit, a case-insensitive path exclusion
failed and a read-only status search printed exactly one status line from each
of `EVALUATION_V5_REPORT.md` through `EVALUATION_V10_REPORT.md`. No evaluation
corpus or sample row was opened, printed, classified, extracted, or used for a
source, test, documentation, or release decision. This additional disclosure
does not change the frozen v10 `CONSUMED / FAIL` result and keeps methodology
handoff blocked.

During the same re-audit, a classifier sub-agent mistakenly started
`go test -shuffle=on -count=20 ./...`. The root process interrupted it after
about 23 seconds and sent `TERM` to PID `265343`. The same command then
reappeared as PID `266741` with WSL `/init` as its parent, consistent with an
orphaned CodeRabbit/tool session. The root interrupted the classifier agent
again, terminated every matching process, and verified that none remained. It
is unknown whether a consumed evaluation or Holdout test selected or read a
restricted fixture before termination. The command and every partial result
are permanently excluded and did not inform source, tests, documentation, CI,
or release decisions. Subsequent validation is constrained to the explicit
safe allowlist. This round cannot claim no restricted access; v10 remains
`CONSUMED / FAIL`, and methodology handoff remains blocked.

During the final independent diff audit, an overly broad read-only
`cmd/**/*.go` search printed evaluation/holdout author-source snippets and a
few synthetic examples. It did not open restricted `testdata`, execute an
author/evaluation/holdout tool, or inform source, tests, documentation, or
release conclusions. The output is permanently excluded, but the event remains
part of the methodology record and prevents a clean zero-access claim.

Release evidence must bind two separate policy identities:

- ruleset `1.0.7` and its YAML asset hash; and
- the classifier-policy identity plus exact Git commit for the Go
  `META-OVERRIDE-001` overlay, extraction/media/multipart semantics, the
  tool-only `cag_control_schema=meta_override_control/v1` mapping, and fixed
  control-plane telemetry. The historical round5.1 value is
  `classifier-policy-v2` /
  `c2092d0949fcaa1d0f085dfe31a668d45cc4d14efc10427d0f3ebcf3e821a112`.
  The round5.2 source-bound value is `classifier-policy-v2` /
  `e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec`;
  the exact source-freeze Commit remains a separate pre-merge field.

Ruleset `1.0.7` alone does not identify the complete policy. The Tool schema
marker is valid only inside established tool/tool-payload provenance; it does
not authorize arbitrary business JSON keys or Provider configuration.

The artifact/Host reviewer must also verify controls outside the Router:
instruction-path allowlists and owner/mode/hash/signature/reload checks for
`model_instructions_file`, `AGENTS.md`, and remote templates; and a versioned
host schema allowlist that rejects or forcibly overwrites unsafe
`safetySettings`, `generationConfig`, `options`, and equivalents.

The reviewer must also retain two P2 limitations. Role-aware classification
does not merge a base Cyber Abuse taxonomy from system/assistant content into a
later user message, so authenticated high-priority instruction provenance is a
host prerequisite. In addition, `Segments` is still produced by a second
bounded JSON parse after the primary extractor walk; current tests have not
reproduced a leak, but a future single semantic parse product is required to
remove dual-parser drift risk.

The historical round5.1 base-to-pre-audit-freeze history also contains one
composite implementation commit. Post-fix regressions are green, but no
independently preserved pre-fix red-test commit or command log exists for the
two HIGH cases. That task-book evidence criterion remains open for independent
audit and is not inferred from the final green state.

Unit, CI, reproducibility, and artifact PASS results are necessary engineering
evidence but never production admission. After every source/artifact gate is
complete, the highest permitted status is
`READY FOR INDEPENDENT SOURCE/ARTIFACT REVIEW`, not `PRODUCTION APPROVED`.

Historical round5.1 local source evidence is recorded in `TEST_REPORT.md`: Go 1.26.4
format/diff/module, Round 5, development-corpus, safe unit/vet, vulncheck,
source-contract, and compile-only checks passed; the full safe race, fuzz,
benchmark, privacy, and script gates also passed. The first benchmark and
vulncheck attempts failed for documented environment/toolchain reasons and were
retained rather than hidden. Exact-source push CI and PR merge-validation CI
both passed, and its historical artifacts were downloaded and statically
rehashed. No Host or deployment claim follows from these results. Round5.2
evidence remains limited to the source-freeze/pre-merge record above until its
own checks are completed.

---

## Historical prior-round evidence

## Historical prior-round decision

**RELEASE DECISION: FAIL / RELEASE BLOCKED.**

**DEVELOPMENT HANDOFF STATUS: BLOCKED FOR HANDOFF.**

The methodologically valid evaluation v10 was executed once and failed. Its
aggregate result is immutable; it was not read or rerun during this work. The
post-v10 implementation may be prepared for independent Leo verification only
after its final commit, clean tree, GitHub CI, real CPA v7.2.72 Host matrix,
proxy check, and artifact identities are recorded. Those engineering fields are
now recorded for implementation freeze `61536f9`; this is still not a release
approval or independent quality PASS.

No tag, GitHub Release, formal artifact publication, or production deployment is
authorized. Even a future-passing engineering matrix cannot guarantee that an
upstream account will never be warned, rate-limited, suspended, or deactivated.

Methodology incident: three incorrectly scoped WSL source-search commands
unexpectedly emitted several rows from the retired `testdata/holdout-v3`
corpus. All three were stopped immediately; the rows were not analyzed or used
for tuning or conclusions. Evaluation v10 content was not accessed. The retired
holdout-v3 corpus is no longer eligible as independent evidence, and the
incident independently blocks handoff.

The emitted rows appeared only in interactive command output captured by the
task transcript. None of the three commands redirected that output to a
repository or workspace file, and no separate emitted-output copy was retained
locally. There was therefore no local output file to remove before handoff; the
task transcript remains retained as the audit record and is permanently
excluded from evaluation evidence.

Independent Host audit also found a separate handoff blocker. Guard
`executor.http_request` returns an RPC error carrying status 405 and the official
adapter returns `(nil, error)`. CPA v7.2.72's provider-specific public
`POST /v1/alpha/search` consumer normally selects `codex` and maps every
`HttpRequest` error to HTTP 502. The project `httptest.Server` manually maps the
status error and is not official Host evidence. No current official route maps
Guard's error to final client 405, so that result is `NOT AVAILABLE / NOT RUN`
and current CI cannot close it.

## Historical prior-round development identity

```text
repository: https://github.com/yujianwudi/cyber-abuse-guard-next
starting_baseline: a121a444cb0d82cba4e27754914a1f88258e1d7b
branch: agent/complete-classifier-cpa-v7272-handoff
reliability_checkpoint_commit: 573def2649d164161e2dfdfeb3f59b1e1b38ebbc
implementation_freeze_commit: 61536f9f02c47a4d79031a47dc8a284f040e41c1
evidence_document_commit: a2d30fc63fca4fba020cda282474aaca15a47d8f
worktree: CLEAN AT FINAL HANDOFF
root_cpa_version: v7.2.72
cpa_upstream_tag_commit: 6279bb8a4c2835ff6ed99c6b85083b2afbefa681
cpa_module_sum: h1:ppce0MLsz2xJi2yi3/A60zu03cM7bMWBAEJ6eC29E5Y=
cpa_go_mod_sum: h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=
cpa_abi: C ABI/RPC schema v1
target: linux/amd64, glibc 2.34+
go_toolchain_for_recorded_wsl_checks: go1.26.4 linux/amd64
ruleset_version: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
historical_classifier_policy_version: classifier-policy-v2
historical_classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
```

The final resolution-only follow-up commit changes only the `SELF` evidence
identity fields to this substantive evidence snapshot's immutable parent
commit. The commit plus repository path independently identifies each exact
evidence document without a self-referential file hash.

The classifier-policy digest is source-bound and exposed through classifier
results/authenticated status. Current build metadata and artifact verification
do not yet bind it, so the full final Git commit remains part of the behavior
identity.

Three WSL commands were mistakenly executed outside the authorized evidence
path: `make cpa-router-fixture-blackbox`,
the now-removed legacy target `cpa-v7272-host-blackbox`, and
`scripts/management-proxy-413-test.sh`. They used loopback/Mock components only,
contacted no production service or real provider, and cleanup left no fixture
process running. Their status is:

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

They are not delivery PASS evidence.

## Historical prior-round implementation closure matrix

| Area | Source state | Executed evidence at this revision |
|---|---|---|
| Wrapper/amplifier separation | Wrapper-only cannot synthesize a Cyber Abuse taxonomy; wrapper can amplify only an independent base behavior | Targeted classifier DEVELOPMENT SELF-CHECK **PASS** |
| Behavior graph | Privacy-safe evidence relations for behavior, intent, target, execution, evasion, impact, scale, authorization, role, carrier, and reasons | Targeted DEVELOPMENT SELF-CHECK **PASS** |
| Role/multi-turn/tool/placeholder/carrier | Bounded provider-aware extraction and composition | Targeted classifier/plugin DEVELOPMENT SELF-CHECK **PASS** |
| Classifier identity | `classifier-policy-v2` source digest test and authenticated status | DEVELOPMENT SELF-CHECK **PASS**; artifact binding incomplete |
| Development corpus | 35 visible cases; validator, fixed taxonomy, coverage, extraction, duplicate/near-duplicate checks | DEVELOPMENT SELF-CHECK **PASS**; never blind evidence |
| Subject idempotency | One risk hit per subject/request digest across retries, methods, races, reconfigure, persistence | Windows and WSL targeted DEVELOPMENT SELF-CHECK **PASS** |
| Pending cache | Ordered O(1) refresh/eviction | Targeted tests/benchmarks **PASS** |
| HMAC/SQLite/lifecycle | owner/mode/type, migration rollback/collision, audit close, lifecycle races | WSL race/vet DEVELOPMENT SELF-CHECK **PASS** |
| Privacy canary | DB/backup/snapshot/API/log/panic/CSV/watchdog/release-evidence scans | Recorded WSL/script DEVELOPMENT SELF-CHECK **PASS** |
| CPA root dependency | root `go.mod` on v7.2.72 | module inspection/verify **PASS** |
| Official Host source contract | 16 exact upstream test names plus fail-open overlays | Windows SOURCE OVERLAY **PASS** |
| Real Guard first install through `InstallManifest` and Host load | harness exists | **GITHUB CI PASS**; local mis-execution remains excluded |
| Same-Dist repeat-skip/tamper-repair through `TestPublishedStoreArchive` | real artifact contract exists | **GITHUB CI PASS** with required Dist artifacts; synthetic fallback disabled |
| Four-protocol 403/pre-SSE/token-count | harness exists | **GITHUB CI PASS — 32 Host subtests** |
| `http_request` 405 at ProviderExecutor adapter/status-error layer | source/adapter test | **SOURCE / ADAPTER CHECK — response=nil** |
| Final official CPA handler/client HTTP 405 | current public consumer maps executor errors to 502 | **NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF** |
| Auth/Provider/Usage/Mock Upstream zero side effects | counting seams exist | **GITHUB CI PASS** |
| Router priority/not-ready/invalid-target/fallback | second native fixture exists | **GITHUB CI PASS — 15 isolated scenarios** |
| Fuse/pre-result panic | official source overlay only | **SOURCE OVERLAY ONLY** |
| Management proxy 413 before CPA `io.ReadAll` | script/fixture exists | **GITHUB CI PASS** — counted CPA-handler stub remained zero |
| GitHub CI | workflow changes exist | **PASS** — push `29312969925`, PR `29312971717`; push long fuzz PASS; both reproducibility jobs PASS |
| Development-candidate artifact verification | store/audit split and verifier source exist | **GITHUB CI PASS / HASHES RECORDED**; not a formal release |

No row may be upgraded based on design intent, compilation, an older branch, or
another evidence class.

## Historical prior-round performance and privacy interpretation

Same-machine classifier development medians improved on all five measured
latency cases from `a121a44` to `a1be19f`. Allocations increased on the ordinary,
candidate-rich, and role-aware paths. Pending-cache and duplicate-request
microbenchmarks show the intended constant-time behavior. These results are
`DEVELOPMENT SELF-CHECK / NOT FINAL EVIDENCE`; Leo must rerun the final commit.

Privacy canary/race/vet checks passed for the named safe WSL/script commands.
The v1→v2 migration additionally fails closed before backup publication or
migration when legacy request/subject/model/source-format values violate the
digest/fixed-provider privacy contract; it preserves the original DB for
operator repair and does not auto-sanitize legacy plaintext. Exact-commit
GitHub CI passed the real Host, proxy-413, artifact, SBOM, and privacy gates;
Leo independent review remains not run.

## Historical frozen evaluation evidence

Evaluation generations v1-v8 remain retired or consumed historical failures;
v9 remains `CONSUMED / METHODOLOGY INVALID / FAIL`. The methodologically valid
v10 first-and-only run remains the authoritative `CONSUMED / FAIL`:

| Aggregate | Frozen result | Gate |
|---|---:|---|
| Benign false positives | 28 / 320 (8.75%) | FAIL; required `<5%` |
| Policy blocked | 49 / 320 (15.31%) | FAIL; required `>90%` |
| Policy exact taxonomy | 33 / 320 (10.31%) | FAIL; required `>90%` |

All four critical taxonomy floors also failed. The v10 report, hashes, byte/row
counts, and taxonomy aggregates remain frozen in
`EVALUATION_V10_REPORT.md`. No row-level result or sample may be used for tuning.

The visible 35-case development corpus is permanently ineligible for a future
v11. A future quality decision requires a newly authored, isolated, unseen set
outside the implementation process.

## Historical prior-round engineering redlines

| Redline | Status |
|---|---|
| Clean final handoff commit and tree | **PASS AT FINAL HANDOFF** |
| Safe local Go test/race/boundary scripts | **DEVELOPMENT SELF-CHECK PASS** |
| GitHub CI on exact implementation commit | **PASS — push and PR runs** |
| Real v7.2.72 store install and native `.so` load | **GITHUB CI PASS** |
| Same-Dist repeat-skip/tamper-repair with required real artifacts | **GITHUB CI PASS** |
| Four protocols: allow/block, non-stream/stream, pre-SSE, token-count | **GITHUB CI PASS** |
| `http_request` adapter/status-error 405 | **SOURCE / ADAPTER CHECK — response=nil** |
| Final official CPA client HTTP 405 | **NOT AVAILABLE / NOT RUN — current public consumer maps the error to 502; BLOCKER** |
| Blocked Auth Selector/Provider/Usage/Mock Upstream all zero | **GITHUB CI PASS** |
| Multi-Router priority/fallback fixture | **GITHUB CI PASS — 15 scenarios** |
| Management proxy 413 before CPA read | **GITHUB CI PASS** |
| Development-candidate privacy/artifact canary scan | **GITHUB CI PASS** |
| Implementation-freeze performance rerun | **GITHUB CI PASS**; Leo rerun not run |
| Leo independent verification | **NOT RUN** |
| New independent blind evaluation | **NOT CREATED**; development corpus forbidden |
| Tag/GitHub Release/production deployment | **NOT CREATED / PROHIBITED** |

## Historical prior-round development artifacts

These would be development candidates only, not approved release assets:

| Artifact | SHA-256 | Status |
|---|---|---|
| `cyber-abuse-guard-v0.1.2-dirty.so` | `61ca7324b647efe1fc264878b712827982c636518896f7e9b4d6797e52e4edda` | **GITHUB CI VERIFIED** |
| `cyber-abuse-guard-v0.1.2-dirty.so.sha256` | `214c3c393416c10880e1cf9320b3d7de5e540452b224dcd7f2d384dc9eaf88ea` | **GITHUB CI VERIFIED** |
| `cyber-abuse-guard_0.1.2-dirty_linux_amd64.zip` (one root `.so`) | `16c5e089b7d7e0cf07f837b70ec745a2dcae73acfd60e3e18ab0118303b6959e` | **GITHUB CI VERIFIED / REAL HOST INSTALLED** |
| `cyber-abuse-guard-v0.1.2-dirty-audit-bundle.zip` | `7592938325fd0e879139ba96f11c33c400ad3d8019e2c7ffb1b53742d6188a21` | **GITHUB CI VERIFIED** |
| `build-metadata.json` | `10fe6f16663667dbfda18001e131ea1383a2b687777ae68091da478edd2f7d16` | **GITHUB CI VERIFIED** |
| `checksums.txt` | `b79fb5e9a608d0d8bc2c949c4dac159f23a3a36e529a74761d912b52e7663618` | **DOWNLOADED CI ARTIFACT / LOCALLY REHASHED** |
| `ruleset-manifest.json` | `486a4dfad49b4e96a600f908cbea47376baab5c8875324999ae50b6251f1af7e` | **GITHUB CI VERIFIED** |
| `ruleset.sha256` | `a8ff687340617dc18832047f841979a0bd06ff8c50a4bc3c15dd7da37b6fbee2` | **GITHUB CI VERIFIED** |
| `sbom.cdx.json` | `da6e6caec7dce7e0daa33be67e488a47318b8404509a03f79d7ad052264c7169` | **GITHUB CI VERIFIED** |
| `release-test-summary.txt` | NOT CREATED | **FORMAL-RELEASE-ONLY; RELEASE BLOCKED** |

Push artifact `cyber-abuse-guard-linux-amd64-dirty` is Actions artifact ID
`8303051476`, uploaded size `10276537`, container digest
`sha256:1d134b2c211665faab3478bd3c9cc2badc2f7ace7c76780f2d662c0b72d171d8`.
The PR-run artifact is ID `8302950575`, size `10276698`, container digest
`sha256:e90cd200df9b20201da5506a3c6440dcdb2232b12028acd9dad818aeaea40318`.
Container digests are not substitutes for the internal-file hashes above.

Store ZIP and audit bundle must remain separate. The store ZIP must contain
exactly one root regular executable `.so`, with no absolute path, `..`,
backslash escape, symlink, or duplicate entry. Formal release scripts remain
blocked because v10 failed; development artifacts must be clearly dirty and
non-production and must not be uploaded as a stable GitHub Release. Under the
current policy, they may be uploaded only to an explicitly **BLOCKED**
prerelease audit snapshot.

## Historical prior-round unresolved limitations

- CPA ABI-v1 Host fail-open, Router enumeration, and duplicate plugin-directory
  visibility;
- no HMAC dual-key rotation and no keyed whole-snapshot MAC;
- bounded text decoders cannot interpret arbitrary encoding, encryption,
  archive/document content, or opaque media semantics;
- cross-request classifier semantics remain stateless;
- classifier-policy identity is not yet embedded in artifact metadata;
- a local SQLite writer remains trusted for snapshot completeness;
- no guarantee against upstream account action.

## Historical prior-round approval block

```text
implementation_freeze_commit: 61536f9f02c47a4d79031a47dc8a284f040e41c1
evidence_document_commit: a2d30fc63fca4fba020cda282474aaca15a47d8f
annotated_tag: NOT CREATED — RELEASE BLOCKED
github_release_url: NOT CREATED — RELEASE BLOCKED
github_actions_ci_run: PASS — push 29312969925; pull_request 29312971717
real_host_matrix: GITHUB CI PASS — 32 Host subtests; 15 Router scenarios
management_proxy_413: GITHUB CI PASS
http_request_adapter_405: SOURCE / ADAPTER STATUS-ERROR CHECK (response=nil)
official_cpa_final_client_http_405: NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF
development_candidate_artifact_hashes: RECORDED / VERIFIED; not formal release assets
leo_verification: NOT RUN
new_independent_blind_evaluation: NOT CREATED
all_handoff_redlines_pass: NO
release_owner: NOT APPROVED
independent_reviewer: NOT APPROVED
decision: BLOCKED FOR HANDOFF / RELEASE FAIL
```

## Historical v0.16-rc.1 local package identity

```text
artifact_status: LOCAL RC CORE PACKAGE / NOT A GITHUB RELEASE
source_version: 0.16
local_rc_artifact_version: 0.16-rc.1
local_tag_object: 4c04e465ba10815e6ee7261e86807556c2e86102
commit: 7b2422ed30c11d405d05bcb6b46a2527eed6471b
tree: d586824ed7f273e9f7f49f82d5ea0eb24bdd2da9
cpa_contract: v7.2.95
ruleset_sha256: 1d908c8c631bc6f72e7ec6b098bea49c4923580766859393d0be48c8c00c6d7d
so_sha256: 9d0ee747491dedeb83f3b3e98137d879dbaba5818e7a6922f9cf1f61d407e685
store_zip_sha256: 86e9eba5265d5f2bb737ec41d5ed8ada51bf352b3833c2d985d3f754963540f7
github_actions_run: 29799561002
github_actions_attempt_1: FAILED / fuzz-smoke / FuzzExtractText context deadline exceeded
github_actions_attempt_2: FAILED / operational-script-security / document consistency fixture
github_actions_artifacts: 0
remote_v0.16-rc.1_tag: NOT CREATED
github_release_evidence: NOT CREATED
real_host_attestation: NOT RUN
```

The local manifest and checksum files are package evidence only. They do not
convert either failed CI attempt into a PASS and do not authorize pushing the
local tag or creating a prerelease. At the time of that package, the retained
v0.15 workflows were version-locked historical machinery. The later Round 8
`v0.16-rc.2` prerelease path is described separately below and does not relabel
the old bytes.

## Historical post-package P1-P2 hardening working-tree status

The raw-capture admission, CPA management-response, fuzz-gate, and CodeQL
hardening performed after the local `v0.16-rc.1` package was development work.
It is not included in the package hashes above, has no tag-, package-, or
artifact-bound release evidence, and is superseded by Round 8.

```text
development_base: 7b2422ed30c11d405d05bcb6b46a2527eed6471b
development_branch: fix/p1-p2-hardening-v016
working_tree_identity: DEVELOPMENT BRANCH / NOT ARTIFACT-BOUND
linux_targeted_long_json_acceptance: DEVELOPMENT SELF-CHECK PASS
linux_targeted_raw_capture_acceptance: DEVELOPMENT SELF-CHECK PASS
linux_full_post_hardening_gate_set: DEVELOPMENT SELF-CHECK PASS
safe_gate_contract_tests: 157 PASS
deterministic_fuzz_seed_targets: 13/13 PASS
cpa_v7.2.95_raw_capture_host_source_overlay: DEVELOPMENT SELF-CHECK PASS
github_actions_exact_working_tree: NOT AVAILABLE
cpa_v7.2.95_real_host_attestation: NOT RUN
p0_assistant_history_bypass: UNRESOLVED / RELEASE BLOCKER
publication_authorization: NO
```

The complete Linux self-check observed 457,790,105 ns/op, 3,355,125 B/op,
and 43 allocs/op for near-8 MiB preparation; 454,296,686 ns/op, 3,360,418
B/op, and 68 allocs/op for composite admission; 46 ns/op with zero allocation
for queue-full rejection; and 54,596,462 ns/op, 8,529,000 B/op, and 1,329
allocs/op for the worst-case management response. The P2 Text, KeyRich, and
SemanticRich long-JSON fixtures also passed their fixed 1 MiB, Near-8 MiB, and
per-byte scaling limits. These are development self-checks only. They must not
be copied into a release attestation as CI, formal benchmark, CPA Host, or
production evidence.

## Historical Round 8 source-tree candidate identity

This retained section records only the historical `v0.16-rc.2` release contract. It does not
claim that exact-main CI, the annotated tag, the private Phase 1 artifact, either
counted-Mock Host lane, independent audit, or the GitHub prerelease already
exists. Those are external gates and must remain `NOT_PROVIDED` until produced
for the exact merged commit and candidate bytes.

```text
source_version: 0.16
candidate_tag: v0.16-rc.2 / NOT CREATED
ruleset_version: 1.0.9
ruleset_sha256: a3de344d3f6dc8eea86d946a823996494d4d297c41efcc6346a6ef757f263a7d
historical_round8_classifier_policy_version: classifier-policy-v7
historical_round8_classifier_policy_sha256: ea8c4dcfacacc6478f86fd2ca5de96d667ae98f2fc6ff0c83d8e6092e9f6a82d
release_kind: prerelease
latest: false
build_metadata_schema: 4
builder_reference: docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b
runner_label: ubuntu-24.04
runner_os_arch_environment: Linux/X64/github-hosted
runner_name: UNRECORDED_EPHEMERAL_GITHUB_HOSTED_RUNNER
runner_image_os: UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER
runner_image_version: UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER
independent_audit: NOT_PROVIDED
production_approval: NOT_GRANTED
stable_v0.16: NOT_RELEASED
```

## Current Round 9 source-tree identity footer

This footer supersedes the current-tense identity for release-document
validation without rewriting the retained Round 8 evidence above. It is a
development contract only; classifier final source freeze, exact-main CI,
counted-Mock Host evidence, independent audit, tag, and GitHub prerelease are
not provided by this source-tree record.

```text
source_version: 0.16
candidate_tag: v0.16-rc.4 / NOT CREATED
ruleset_version: 1.0.10
ruleset_sha256: e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0
classifier_policy_freeze: PENDING_FINAL_SOURCE_FREEZE
release_kind: prerelease
latest: false
independent_audit: NOT_PROVIDED
production_approval: NOT_GRANTED
```
