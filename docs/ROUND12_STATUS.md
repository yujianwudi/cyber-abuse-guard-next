# Round 12 active status and evidence boundary

This page is the short, current status overlay for
[the Round 12 task book](ROUND12_PRODUCTION_HARDENING_TASK_BOOK.md). Historical
Round 6 through Round 11 documents remain evidence for their named source and
CPA identities; they do not override this overlay or transfer a PASS to the
Round 12 working tree.

<!-- round12-status:start -->
```text
round12_status: REMEDIATION_IMPLEMENTED / REVALIDATION_PENDING / ACCEPTANCE_INCOMPLETE / NO_RELEASE
round12_baseline_main: 21267e742b624b29a75bd3683fd6914f76c764b5
round12_baseline_tree: 6272ac0ba818d39b89481db1f8e360e9b262fde6
round12_cpa_target: v7.2.116 / a88197f845c979132c8978ea223c6af05cc81536
round12_go_platform: go1.26.4 / linux-amd64
round12_classifier_policy: classifier-policy-v11 / f1b4665c751306a1a30c96a58ddb84714541e6e476c66db8ad436480e4c98f55
round12_source_policy: APPROVED_EXACT_PINS / d457374f193db13fd43422104f760997c935de057ae3add7a0faf56a5260ad89
round12_audit_runner_bundle: c043a0f81523a6edbed357319fc8b8141f776e92071c287b2d360d0693ce3394
round12_audit_run_source: 9a8ff1f708a3a27b93c9d856993dc8aa5a85fa26d84a6c6ae788053d88caa740
round12_local_audit_tool_tests: PASS / LINUX / 68_OF_68
round12_local_safe_gate: PASS / 209_TESTS / 91_RETIRED_SKIPS / 3_ENTRYPOINTS / 38_TARGETS / 47_SCRIPTS
round12_local_go_unit: PASS / GO1.26.4_LINUX_DEVELOPMENT_EVIDENCE_ONLY
round12_local_go_race: INCOMPLETE_SESSION_INTERRUPTION / NOT_PASS / EXACT_CI_REQUIRED
round12_baseline_engineering_ci: PASS / EXACT_MAIN_ONLY
round12_superseded_pr_head: 9782eaf9da37d466ffc0b644b052d3c842f7f1ca
round12_superseded_pr_head_engineering_ci: PASS / CI_31016759352 / POLICY_31016760807 / CODEQL_31016759262
round12_superseded_pr_head_second_machine: FAIL_CLOSED / ERROR_32a64d93ec0f3ed9 / NO_MACHINE_EVIDENCE
round12_working_candidate_engineering_ci: PENDING_REMEDIATED_HEAD
round12_input_second_machine_report: DIAGNOSTIC_ONLY / NOT_FINAL_CANDIDATE / NOT_INDEPENDENT_ATTESTATION
round12_final_candidate_second_machine: PENDING_REMEDIATED_HEAD_EXECUTION
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

The Round 12 implementation has passed its pre-final Linux development checks:

- the complete safe package, classifier, and counted-Mock unit lanes passed
  under the exact Go 1.26.4 Linux toolchain;
- format, diff, module verification, vet, fuzz seed, repository-secret,
  workflow, ShellCheck, script-contract, corpus, and release-document gates
  passed;
- the Safe Gate mutation suite passed 209 tests with 91 explicitly retired
  workflow cases skipped, and its live contract closed three entrypoints,
  38 Make targets, and 47 scripts;
- the current CPA audit harness passed 68/68 Linux tests, including the
  concatenated-ZIP rejection, stopped-image Mock source verification,
  private-parent mode drift, symlink/ancestor/evidence/subdirectory replacement,
  normal-path Docker handoff, closed Source/Destination/RW/rprivate bind and
  `/tmp` tmpfs contracts, and extra-volume rejection, with 11 reviewed source
  pins and 19 semantic cases bound by the approved policy
  above; MDX latest HEAD is `7588d25d…` and its selected blobs are unchanged;
  this diagnostic harness does not claim same-UID bootstrap or daemon-handoff
  isolation;
- subject-snapshot replacement is transactionally capacity bounded without
  retaining a second full encoded snapshot or deleting audit evidence; explicit
  event deletion, Raw Capture purge, and subject deletion remeasure without
  evicting rows outside the requested maintenance scope.

These are working-tree development results, not remediated-candidate CI or
second-machine evidence. The local race attempt was interrupted by the tool
session and is explicitly `NOT_PASS`; it must complete in the required GitHub
lane.

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

The current runner keeps all local evidence writes descriptor-bound but uses a
fully identity-checked normal path for Docker bind sources, then revalidates the
path and exact inspect mount contract immediately after start. This is a local
remediation, not proof that the second-machine failure is closed; a new exact
HEAD, artifact, and real Docker/runc run are required.

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
  `v7.2.116@a88197f845c979132c8978ea223c6af05cc81536` and close the functional,
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
第三方仓库代码，私有 corpus 正文已经删除。当前 normal-path handoff 修复仅完成本地
68/68 Linux 回归，新的精确 HEAD 门禁和二号机执行仍为
`PENDING_REMEDIATED_HEAD_EXECUTION`。已有的 1,320 次传输执行报告只属于所有者运行
的输入诊断，不是独立证明。受保护 Host、独立证明、生产批准与 Release Ready 均为
`NOT_PROVIDED`。本轮不创建 tag、RC 或 GitHub Release。

旧仓库及 `v0.15` Release 当前均为 GitHub API `404`，因此其可用性为
`UNAVAILABLE`、安全支持为 `SUSPENDED`；历史记录不等于仍可下载、可回滚或受支持。

The read-only GitHub governance observation supporting the repository-facing
claims is recorded in
[the Round 12 GitHub governance snapshot](reports/ROUND12_GITHUB_GOVERNANCE_SNAPSHOT.md).
