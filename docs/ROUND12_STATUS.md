# Round 12 active status and evidence boundary

This page is the short, current status overlay for
[the Round 12 task book](ROUND12_PRODUCTION_HARDENING_TASK_BOOK.md). Historical
Round 6 through Round 11 documents remain evidence for their named source and
CPA identities; they do not override this overlay or transfer a PASS to the
Round 12 working tree.

<!-- round12-status:start -->
```text
round12_status: IMPLEMENTATION_IN_PROGRESS / ACCEPTANCE_INCOMPLETE / NO_RELEASE
round12_baseline_main: 21267e742b624b29a75bd3683fd6914f76c764b5
round12_baseline_tree: 6272ac0ba818d39b89481db1f8e360e9b262fde6
round12_cpa_target: v7.2.116 / a88197f845c979132c8978ea223c6af05cc81536
round12_go_platform: go1.26.4 / linux-amd64
round12_classifier_policy: classifier-policy-v11 / f1b4665c751306a1a30c96a58ddb84714541e6e476c66db8ad436480e4c98f55
round12_source_policy: APPROVED_EXACT_PINS / 14da58806760262908240593c176c8bdf1f2216df7f23de71bd172e8e6b48d97
round12_audit_runner_bundle: fb886a238acab50d2c90c3768e5ffd54a6318a15c80fbdc0b065098824b391fb
round12_audit_run_source: 665ffba5e1a454973c39f62c68fa0186bf5aa956e48e5f4db00a1518f7083f6d
round12_local_audit_tool_tests: PASS / LINUX / 62_OF_62
round12_local_safe_gate: PASS / 209_TESTS / 91_RETIRED_SKIPS / 3_ENTRYPOINTS / 38_TARGETS / 47_SCRIPTS
round12_local_go_unit: PASS / GO1.26.4_LINUX_DEVELOPMENT_EVIDENCE_ONLY
round12_local_go_race: INCOMPLETE_SESSION_INTERRUPTION / NOT_PASS / EXACT_CI_REQUIRED
round12_baseline_engineering_ci: PASS / EXACT_MAIN_ONLY
round12_working_candidate_engineering_ci: PENDING_FINAL_CANDIDATE
round12_input_second_machine_report: DIAGNOSTIC_ONLY / NOT_FINAL_CANDIDATE / NOT_INDEPENDENT_ATTESTATION
round12_final_candidate_second_machine: PENDING_FINAL_CANDIDATE_EXECUTION
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
- the current CPA audit harness passed 62/62 Linux tests, including the
  concatenated-ZIP rejection, stopped-image Mock source verification, and
  private-parent and post-bind evidence-directory identity regressions, with 11
  reviewed source pins and 19 semantic cases bound by the approved policy
  above; this diagnostic harness does not claim same-UID bootstrap isolation;
- subject-snapshot replacement is transactionally capacity bounded without
  retaining a second full encoded snapshot or deleting audit evidence; explicit
  event deletion, Raw Capture purge, and subject deletion remeasure without
  evicting rows outside the requested maintenance scope.

These are working-tree development results, not final-candidate CI or
second-machine evidence. The local race attempt was interrupted by the tool
session and is explicitly `NOT_PASS`; it must complete in the required GitHub
lane.

Exact baseline `main@21267e742b624b29a75bd3683fd6914f76c764b5` passed the five
required GitHub engineering contexts through CI run `30880739397`, Policy and
Corpus Gate run `30880739368`, and CodeQL run `30880739360`. These results are
bound only to that exact baseline commit. They do not validate later working
tree or pull-request bytes and are not a protected Host, independent audit,
release, or production PASS.

The supplied second-machine report is retained as an owner-run input diagnostic:

```text
report_sha256: fcc0558904d17ed735ef131dc2ef01170d5e211fcf95d0686df1af244b25083a
summary_sha256: 446b56b2d91ccafb3c21d04a339f8772febaf68478e8721027cd92e0b8216554
evidence_level: SECOND_MACHINE_DIAGNOSTIC / NOT_INDEPENDENT_ATTESTATION
transport_executions: 1320
```

The 1,320 count is a transport-execution count, not 1,320 independent semantic
samples. That report is not the required RT12-05/06 run against the final
candidate commit/tree/SO. The final-candidate second-machine run is still
pending and no `SECOND-MACHINE DIAGNOSTIC PASS` is claimed for Round 12.

## What remains open

- The final candidate must obtain its own five required GitHub checks.
- Exact Go 1.26.4 race, CPA compatibility, build, reproducibility, and bounded
  CI fuzz results must come from that candidate's GitHub jobs; local functional
  development evidence does not replace them.
- RT12-05/06 must run against the final candidate on CPA
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
已经通过，但结果只绑定该精确提交，不能转移到后续工作树或 PR。已有的 1,320 次
传输执行报告只属于所有者运行的输入诊断，不是独立证明，也不是针对第十二轮最终候选
commit/tree/SO 的 RT12-05/06 结果。最终候选二号机执行仍为
`PENDING_FINAL_CANDIDATE_EXECUTION`；受保护 Host、独立证明、生产批准与 Release
Ready 均为 `NOT_PROVIDED`。本轮不创建 tag、RC 或 GitHub Release。

旧仓库及 `v0.15` Release 当前均为 GitHub API `404`，因此其可用性为
`UNAVAILABLE`、安全支持为 `SUSPENDED`；历史记录不等于仍可下载、可回滚或受支持。

The read-only GitHub governance observation supporting the repository-facing
claims is recorded in
[the Round 12 GitHub governance snapshot](reports/ROUND12_GITHUB_GOVERNANCE_SNAPSHOT.md).
