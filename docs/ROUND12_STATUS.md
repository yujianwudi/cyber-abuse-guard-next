# Round 12 frozen status and evidence boundary

```text
current_classifier_policy_version: classifier-policy-v19
current_classifier_policy_sha256: b9ee45401a50ae5c6fafa80d219e8f47e726bdfe15b5fc7838a96edd095460a1
```

This page is the frozen Round 12 status record for
[the Round 12 task book](ROUND12_PRODUCTION_HARDENING_TASK_BOOK.md). Historical
Round 6 through Round 11 documents remain evidence for their named source and
CPA identities; they do not override this overlay or transfer a PASS to the
Round 12 working tree. Every PASS below is explicitly scoped to CPA v7.2.124
or a named pre-v7.2.124 historical identity; none transfers to Round 13,
CPA v7.2.125, or `v1.0.0-rc.1`.

<!-- round12-status:start -->
```text
round12_status: CPA_V7.2.124_LOCAL_SOURCE_COMPILE_PASS / INDEPENDENT_API_IDENTITY_PASS / REMOTE_MAKE_GATE_NETWORK_FAILED / EXACT_CANDIDATE_GATES_PENDING / ACCEPTANCE_INCOMPLETE / NO_RELEASE
round12_baseline_main: 21267e742b624b29a75bd3683fd6914f76c764b5
round12_baseline_tree: 6272ac0ba818d39b89481db1f8e360e9b262fde6
round12_cpa_target: v7.2.124 / 197f520426374e514218ed155933ac546c98d345
round12_go_platform: go1.26.4 / linux-amd64
round12_local_cpa_source_compile: CPA_V7.2.124_PASS / GO1.26.4 / LINUX_AMD64 / FULL_LOCAL_MATRIX / PROFILES_PRIMARY / REMOTE_TAG_CHECK_SKIPPED / REMOTE_LATEST_CHECK_SKIPPED
round12_remote_latest_release_api: CPA_V7.2.124_PASS / v7.2.124 / INDEPENDENT_API_VERIFICATION
round12_remote_tag_ref_api: CPA_V7.2.124_PASS / 197f520426374e514218ed155933ac546c98d345 / COMMIT_VERIFIED / INDEPENDENT_API_VERIFICATION
round12_remote_combined_make_gate: NETWORK_FAILED / GITHUB_GIT_CURL_52 / NOT_CODE_FAILURE
round12_native_host_so: NOT_RUN / LOCAL_DEPLOYMENT_PROHIBITED
round12_classifier_policy: HISTORICAL_ROUND12 / classifier-policy-v12 / 2e9d02371c2ff18d6f5efe7765db45517471603ea9d772c73664bf92c7625a5b
round12_source_policy: APPROVED_EXACT_PINS / 9b98eb1c31a148a1f4327cba270bea627ff97e775139df002b820cb24cfde225
round12_audit_runner_bundle: 6c9bcece412f3164845f831856b39fc23e80b0939ae64e3adae2f41e00c017a4
round12_audit_contract: 0b518e0ca12011dc9fe2064740ed799adf5faaf0da8f474512b0ba6557360680
round12_audit_run_source: cd42cff19d6f01c60f42e382b329c9682f7cb5a995b6213a3fa7094c7966fe73
round12_audit_machine_schema: 063d70925671b54a0726778df4f8224471c1705d8ac39a9ee8bb44340d824060
round12_local_audit_tool_tests: CPA_V7.2.124_PASS / LINUX / 148_OF_148
round12_second_machine_bind_preflight: HISTORICAL_PRE_CPA124_PASS / NORMAL_BIND_RUNC_START / RPRIVATE / HOSTCONFIG_TMPFS_CLOSED / MOUNTS_TMPFS_OMITTED / NOT_FINAL_CANDIDATE
round12_local_safe_gate: CPA_V7.2.124_PASS / 211_TESTS / 91_RETIRED_SKIPS / 3_ENTRYPOINTS / 38_TARGETS / 47_SCRIPTS
round12_local_go_unit: HISTORICAL_PRE_CPA124 / GO1.26.4_LINUX / REVALIDATION_REQUIRED
round12_local_go_race: HISTORICAL_PRE_CPA124 / GO1.26.4_LINUX_AMD64 / REVALIDATION_REQUIRED / EXACT_CI_REQUIRED
round12_local_coderabbit: INITIAL_REVIEW_12_ISSUES / 6_MAJOR_6_MINOR / ALL_REMEDIATED / EXACT_COMMIT_FOLLOWUP_PENDING
round12_host_performance_contract: CPA_V7.2.124_PASS / SIX_SOURCE_TOOL_CLOSURE / WARM_CADENCE_3601_TO_3602 / REQUEST_OUTCOME_CONSERVATION
round12_candidate_manifest_gate: CPA_V7.2.124_PASS / CLEAN_EXACT_EIGHT_FILE_CI_SEAL / TRACKED_AND_UNTRACKED_CLEAN
round12_baseline_engineering_ci: HISTORICAL_PRE_CPA124_PASS / V7.2.116_EXACT_MAIN_ONLY / NOT_TRANSFERABLE
round12_superseded_pr_head: 9782eaf9da37d466ffc0b644b052d3c842f7f1ca
round12_superseded_pr_head_engineering_ci: CPA_V7.2.124_PASS / CI_31016759352 / POLICY_31016760807 / CODEQL_31016759262
round12_superseded_pr_head_second_machine: FAIL_CLOSED / ERROR_32a64d93ec0f3ed9 / NO_MACHINE_EVIDENCE
round12_prior_remediated_pr_head: 30b613e82a1be97938dbfe974b98d4cb76a359a0
round12_prior_remediated_merge_ref: 2be72ccd7f431344b4f6bb18811fa08949105121
round12_prior_remediated_engineering_ci: CPA_V7.2.124_PASS / CI_31031462761 / POLICY_31031462702 / CODEQL_31031462510
round12_prior_remediated_second_machine: FAIL_CLOSED / ERROR_2f0ba84bbf89fe0c / DIRTY_CANDIDATE_READINESS_MISMATCH / NO_MACHINE_EVIDENCE
round12_current_remediation: MDX_V45_CLASSIFIER / HOST_PERFORMANCE_FALSE_PASS_CLOSURE / CI_CANDIDATE_BINDING / CLEAN_EXACT_MERGE_CANDIDATE_REQUIRED
round12_sbom_repro_remediation: EXACT_IDENTITY_NORMALIZATION / TWO_INDEPENDENT_BLOBLESS_SPARSE_CLONES / LOCAL_CONTRACT_PASS / EXACT_CI_PENDING
round12_second_machine_envfile_smoke: CPA_V7.2.124_PASS / PROC_FD_DOCKER_CLI / SUCCESS_AND_EXPECTED_FAILURE / JOURNAL_FIELD_MENTIONS_0 / RESIDUALS_0 / NOT_FINAL_CANDIDATE
round12_working_candidate_engineering_ci: NOT_RUN / PENDING_EXACT_HEAD
round12_input_second_machine_report: HISTORICAL_V7.2.116_DIAGNOSTIC_ONLY / NOT_FINAL_CANDIDATE / NOT_INDEPENDENT_ATTESTATION
round12_final_candidate_second_machine: NOT_RUN / PENDING_EXACT_HEAD_EXECUTION
round12_historical_v7_2_116_final_candidate_second_machine: FAIL_CLOSED_SOURCE_DRIFT_ON_E624EEA / MDX_V45_REVIEWED / NO_MACHINE_EVIDENCE
round12_protected_host: NOT_PROVIDED
round12_independent_attestation: NOT_PROVIDED
round12_production_approved: NOT_PROVIDED
round12_release_ready: NOT_PROVIDED
round12_tag_and_release: NOT_CREATED / NOT_AUTHORIZED
legacy_v0.15_availability: UNAVAILABLE
legacy_v0.15_support: SUSPENDED
```
<!-- round12-status:end -->

## What has passed

The results below predate the v7.2.124 pin unless a line explicitly names the
new target. They remain useful historical development evidence but do not
transfer to the new source identity. The v7.2.124 update has independently
revalidated the complete local CPA source/compile compatibility matrix, the
three module closures, the integration compile-only path, and 148/148 Linux
current-audit-tool tests; full root unit, race, exact-commit CI, native Host,
and second-machine gates remain open.

- the complete safe package, classifier, and counted-Mock unit lanes passed
  under the exact Go 1.26.4 Linux toolchain;
- format, diff, module verification, vet, fuzz seed, repository-secret,
  workflow, ShellCheck, script-contract, corpus, and release-document gates
  passed;
- the Safe Gate mutation suite passed 211 tests with 91 explicitly retired
  workflow cases skipped, and its live contract closed three entrypoints,
  38 Make targets, and 47 scripts;
- the CycloneDX main-component contract passed versioned/unversioned byte
  identity, candidate/RC/formal/dirty-development identity, full commit/tree
  property binding, malformed-graph rejection, and a synthetic independent
  `blob:none` sparse-clone test in which the excluded restricted blob remained
  absent before and after checkout;
- the current CPA audit harness passed 148/148 Linux tests, including the
  concatenated-ZIP rejection, stopped-image Mock source verification,
  private-parent mode drift, symlink/ancestor/evidence/subdirectory replacement,
  normal-path Docker handoff, closed Source/Destination/RW/rprivate bind and
  `/tmp` tmpfs contracts, extra-volume rejection, clean-candidate readiness,
  mode-0600 Mock `--env-file` lifecycle on Docker success/failure, and
  credential-free Docker argv, Host A/B tool-identity closure over
  `acquire.py`, `audit_contract.py`, the Host schema/source, `run.py`, and
  `validate.py`, 3,601-3,602-row warm-lane cadence enforcement, request-outcome
  conservation, clean eight-file CI candidate binding, explicit descriptor
  guards under optimized Python, and a finite counted-Mock idle timeout, with
  11 reviewed source pins and 19 semantic
  cases bound by the approved policy above; MDX latest HEAD is `77e7a649…`, the
  current v45 single-member archive has newly reviewed blob/raw/text identities,
  and the selected safety-evaluation document is byte-identical;
  this diagnostic harness does not claim same-UID bootstrap or daemon-handoff
  isolation;
- a uniquely named, network-none second-machine Docker preflight successfully
  started the pinned Python image with the normal bind source. Inspect returned
  the exact source, `RW=false`, and `Propagation=rprivate`; it returned the
  hardened `/tmp` in `HostConfig.Tmpfs` but omitted tmpfs from `.Mounts`. This
  closes the runc/inspect shape used by the remediation but is not a final
  candidate harness PASS;
- a separate real-Docker second-machine smoke proved that `sudo docker run`
  can read the mode-0600 Mock env file through the runner-PID proc-fd path. Both
  the successful container start and expected Docker failure removed their
  files and labelled containers; the unit journal contained zero Mock
  credential-field mentions. This closes the CLI handoff shape only, not the
  final candidate harness;
- subject-snapshot replacement is transactionally capacity bounded without
  retaining a second full encoded snapshot or deleting audit evidence; explicit
  event deletion, Raw Capture purge, and subject deletion remeasure without
  evicting rows outside the requested maintenance scope.

These are working-tree development results, not remediated-candidate CI or
second-machine evidence. After the local CodeRabbit remediation, the exact Go
1.26.4 Linux race lane completed in 977.8 seconds with exit code 0 and no data
race, panic, or timeout. It remains
development evidence only; the new candidate must still pass the required
GitHub lane on its exact commit.

Exact baseline `main@21267e742b624b29a75bd3683fd6914f76c764b5` passed the five
required GitHub engineering contexts through CI run `30880739397`, Policy and
Corpus Gate run `30880739368`, and CodeQL run `30880739360`. These results are
bound only to that exact baseline commit. They do not validate later working
tree or pull-request bytes and are not a protected Host, independent audit,
release, or production PASS.

Superseded PR head `9782eaf9da37d466ffc0b644b052d3c842f7f1ca` also passed its
GitHub engineering checks: CI `31016759352`, Policy and Corpus Gate
`31016760807`, and CodeQL `31016759262`. Linux artifact `8936474093` contained
an SO with SHA-256
`4fdd0914328b63f585187b970a0dc8f4501c3f6dece7819cd414d4fb3179a4ad`.
Those green checks remain bound to that superseded head and do not validate the
current remediation.

The corresponding second-machine run is an immutable fail-closed record:

```text
candidate_head: 9782eaf9da37d466ffc0b644b052d3c842f7f1ca
result: FAIL_CLOSED / NOT_PASS
error_id: 32a64d93ec0f3ed9
machine_evidence_emitted: false
third_party_code_executions: 0
private_corpus_text_removed: true
root_cause: Docker/runc rejected a proc-fd magic link as a bind-mount source
retained_evidence_root: /opt/cag-audit-rt12-9782eaf-20260805-1615
```

The `30b613e` runner kept all local evidence writes descriptor-bound, used a
fully identity-checked normal path for Docker bind sources, revalidated the path
and exact inspect mount contract immediately after start, and reached CPA
readiness on real Docker/runc. Its exact merge-ref input was
`2be72ccd7f431344b4f6bb18811fa08949105121`; artifact ZIP digest
`7392a1dbd502f6c19922050077e319ce006130347ecc9f1012fd5e40e6e91da4`
and SO SHA-256
`199a7617b1ae37237768b252a2c5bd2ffb292dfcef7ec84a8c9a7bd4d095b0e8`
were independently rechecked. That run is also an immutable fail-closed record:

```text
candidate_head: 30b613e82a1be97938dbfe974b98d4cb76a359a0
merge_ref: 2be72ccd7f431344b4f6bb18811fa08949105121
result: FAIL_CLOSED / NOT_PASS
error_id: 2f0ba84bbf89fe0c
machine_evidence_emitted: false
third_party_code_executions: 0
private_corpus_text_removed: true
labelled_docker_resources_removed: true
business_container_snapshot_unchanged: true
root_cause: CI development SO reported dirty=true while readiness requires a clean candidate
retained_evidence_root: /opt/cag-audit-rt12-30b613e-20260805-1830
```

This run also proved that generated Mock credentials were present in
`sudo docker run` argv and the persistent system journal. The current
remediation keeps the clean readiness requirement, changes the existing CI lane
to produce and reproduce an exact-merge `dirty=false` audit candidate, and
fails closed unless `dist/` is exactly eight fixed v0.16 base files. It seals
those files into a ninth `audit-candidate-manifest.json` marked
`UNRELEASED / SECOND-MACHINE AUDIT CANDIDATE / NOT RELEASE`, with the workflow
event/run, commit/tree, `dirty=false`, version, SHA-256, and byte counts. The
consumer job rechecks the exact nine-file set and every digest before
two-clean-clone reproduction. Mock credentials pass only through an
identity-checked, immediately removed mode-0600 `--env-file`. A new exact HEAD,
artifact, and new-path second-machine run are required; neither fail-closed
record is relabelled as PASS.

The supplied second-machine report is retained as an owner-run input diagnostic:

```text
report_sha256: fcc0558904d17ed735ef131dc2ef01170d5e211fcf95d0686df1af244b25083a
summary_sha256: 446b56b2d91ccafb3c21d04a339f8772febaf68478e8721027cd92e0b8216554
evidence_level: SECOND_MACHINE_DIAGNOSTIC / NOT_INDEPENDENT_ATTESTATION
transport_executions: 1320
```

The 1,320 count is a transport-execution count, not 1,320 independent semantic
samples. That report is not the required RT12-05/06 run against the final
candidate commit/tree/SO. The remediated final-candidate second-machine run is
still pending and no `SECOND-MACHINE DIAGNOSTIC PASS` is claimed for Round 12.

## What remains open

- The remediated candidate must obtain its own five required GitHub checks.
- Exact Go 1.26.4 race, CPA compatibility, build, reproducibility, and bounded
  CI fuzz results must come from that candidate's GitHub jobs; local functional
  development evidence does not replace them.
- RT12-05/06 must run against the remediated final candidate on CPA
  `v7.2.124@197f520426374e514218ed155933ac546c98d345` and close the functional,
  security, side-effect, identity, database, and performance evidence schema.
- Protected-Host evidence and independent attestation remain `NOT_PROVIDED`.
  An owner-run diagnostic is not independent evidence.
- Production approval and release readiness remain `NOT_PROVIDED`. Round 12 may
  merge a gated pull request to `main`; it must not create a tag, RC, plugin
  asset, or GitHub Release.

## Legacy v0.15 availability

The previously documented repository `yujianwudi/cyber-abuse-guard` and its
`v0.15` Release both returned GitHub API `404` on 2026-08-04. The historical
identities remain audit records, but the original bytes and digests are not
currently reachable from their documented URLs. Availability is therefore
`UNAVAILABLE` and security support is `SUSPENDED` until a verifiable read-only
repository or signed immutable archive is restored. Historical prose is not a
download, rollback, or support guarantee.

## 中文口径

精确基线 `main@21267e742b624b29a75bd3683fd6914f76c764b5` 的五项 GitHub 工程门禁
已经通过，但结果只绑定该精确提交，不能转移到后续工作树或 PR。旧 PR 候选
`9782eaf` 的 CI、Policy Gate 和 CodeQL 也曾通过，但二号机正式 harness 因 runc
拒绝 proc-fd bind source 而 fail closed：没有生成 `machine-evidence.json`，没有执行
第三方仓库代码，私有 corpus 正文已经删除。当前 normal-path handoff 修复已完成本地
148/148 Linux 审计工具回归；313.5 秒 unit 和 977.8 秒 Go 1.26.4 race 属于
v7.2.124 固定前的历史开发证据，不能转移；新的精确
HEAD 门禁和二号机执行仍为
`PENDING_NEW_HEAD_EXECUTION`。已有的 1,320 次传输执行报告只属于所有者运行
的输入诊断，不是独立证明。受保护 Host、独立证明、生产批准与 Release Ready 均为
`NOT_PROVIDED`。本轮不创建 tag、RC 或 GitHub Release。

旧仓库及 `v0.15` Release 当前均为 GitHub API `404`，因此其可用性为
`UNAVAILABLE`、安全支持为 `SUSPENDED`；历史记录不等于仍可下载、可回滚或受支持。

The read-only GitHub governance observation supporting the repository-facing
claims is recorded in
[the Round 12 GitHub governance snapshot](reports/ROUND12_GITHUB_GOVERNANCE_SNAPSHOT.md).
