# 独立审计交接说明 — CPA Cyber Abuse Guard v0.16 Round 9 候选

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: e7a00b02d7e0e4ca837204cfed476b4f371f599facbf546e342362370111ec14
```

## 2026-07-29 当前审计与修复门禁

最近一次已提交并接受隔离审计的基线是：

```text
audited_head: 150c25e6352cb237cb3956bd66c83c3278c3fe33
audited_classifier_policy_digest: e0cbc975c126a12649a1b8e309e4e2a95efc64e46346467771ecae61b3e14971
audited_cpa: v7.2.104 / c9417c8ae9b16fabc0386ca35d36f13bf8b1d678
engineering_ci: 30353591705 / PASS
security_audit: FAIL / BLOCKED
complete_malicious_fail_open: 287
malicious_incomplete_http_403: 36
complete_benign_false_positive: 2
```

CI `30353591705` 只证明上述精确 HEAD 的工程构建与测试门禁通过，不能覆盖隔离
审计的安全失败。该审计观察到 287 个 coverage complete 的恶意样本放行、36 个
恶意 incomplete 样本返回 HTTP 403，以及 2 个 coverage complete 的正常样本误拦；
因此该基线不得发布、部署或恢复生产 Balanced。

当前候选修复的源码身份是 `classifier-policy-v9` /
`e7a00b02d7e0e4ca837204cfed476b4f371f599facbf546e342362370111ec14`。
它不是新的已审计候选：提交绑定 CI 和二号机隔离重验均为
`PENDING`。在三类失败全部由绑定同一精确提交的新证据关闭前，当前结论保持：

```text
ENGINEERING BASELINE PASS / SECURITY AUDIT FAIL /
CURRENT POLICY IDENTITY RECORDED / LOCAL LINUX SOURCE GATES PASS /
CPA V7.2.104 SOURCE_COMPILE CONTRACT PASS /
EXACT-COMMIT CI AND SECOND-MACHINE RETEST PENDING /
BLOCKED
```

## Historical snapshot — 2026-07-25 Round 9 handoff gate

以下“当前”“本轮”只描述 2026-07-25 的旧工作树与当时尚未提供的门禁状态，不能
覆盖上方 2026-07-29 的隔离审计 `FAIL / BLOCKED`，也不能被重标为当前 PASS。

当前源码版本为 `0.16`，开发目标为 Linux amd64 非 latest 预发行
`v0.16-rc.4`、`classifier-policy-v9`、ruleset `1.0.10`、audit schema v6，
以及唯一 CPA 合同
`v7.2.104@c9417c8ae9b16fabc0386ca35d36f13bf8b1d678`。受保护 Host 作业不做
source checkout，只把候选与 Phase 1 的不可变身份交给预装的 root-owned broker；
该 broker 才能访问外置加密独立语料、评估器、密钥、固定镜像和受保护 Git 账本。
CPA 只允许 `127.0.0.1:18394 -> 8317/tcp` 的隔离 counted-Mock 绑定；不得接触
真实 Provider、真实账号池、生产数据库或生产流量。

当前机器合同为 `round9-external-evaluation/v3`、
`round9-external-evaluator-aggregate/v3`、
`round9-external-evaluation-ledger-event/v3`、
`round9-protected-git-ledger-proof/v1`、
`round9-external-counted-mock/v1` 和 `round9-external-cpa-sandbox/v2`。
可发布结果必须机械绑定 Audit→Balanced→Strict、模式状态、SQLite v6
`quick_check`/WAL/受控重启、panic/lifecycle、usage queue 与默认关闭 Raw Capture；
任何必需观察缺失都不能生成 `PASS`。

独立审计的机械验证合同现已单独实现为
`round9-independent-audit-evidence/v1`、
`round9-independent-audit-ledger-event/v1` 和
`round9-independent-audit-ledger-proof/v1`。它只验证签名 aggregate、精确 19
资产 bytes/SHA-256/provenance、独立 signer/run/challenge 和不可更新/删除的 Git
账本，不读取受限正文。当前没有提供由独立审计方签发的证据包、公钥信任配置或受保护
账本事件，所以机械门禁结果仍为 `NOT_PROVIDED`，不是 `PASS`。

Round 9 将 malicious-text 阻断资格绑定到具体 candidate/clause/scope/
ownership/referent chain。评分与 hard floor 只能在候选通过
`CandidateBlockEligibility` 后运行；Balanced 与 Strict 共用这条 malicious-text
门禁，Strict 的 incomplete 处置使用独立 decision kind，不能伪造恶意分类、winner
或主体累计。正常防御、分析、检测、迁移、轮换、恢复、取证、引用、教育、代码、
日志和测试夹具在资格无法证明时必须 allow + audit。

当前工作树仍是开发候选。可见开发语料的活动身份是
`round9-public-adversarial-v13`（481448 bytes，SHA-256
`91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6`）；
它不是独立 holdout，也不执行第三方仓库代码。v12 以 485221 bytes /
`eb72fd7b88c052c6af98c97636c18aba96f499597741bcba262dda59de3c2387`
原样保留为上一份有效冻结历史，v11/v10/v9 继续保留为更早有效历史。精确公布的 v8 以 105299 bytes /
`5def53300bad07c65717ed8f8a32d2da49952528275df77ea55703713f9e330f`
作为 immutable-invalid 历史保留；105298-byte / `2f953da4…` 的原位修正 v8
作为 rejected rebind 单独保留。v7 仍是更早有效冻结历史，v6 仍是较早的
frozen-invalid review-digest 历史。
当前可见开发自检在性能修复后的工作树身份下记录为：正常语料 0/1200
semantic、0/7200 route blocks（166 audit、7034 allow，stream/nonstream 各
3600）；paired-malicious v3 为 120/120 semantic blocks、960/960 route passes
（stream/nonstream 各 480）。对应报告分别是
`dist/round9-worklogs/development-benign-post-perf-20260724.json`（2515 bytes，
SHA-256 `607b751defeebd9681170a558528aa1a4827c1c176bce2886a1929b59193af01`）和
`dist/round9-worklogs/paired-malicious-post-perf-20260724.json`（7150 bytes，
SHA-256 `ba9733503985195204c0bc1eef95f936951ab8947c67ce4d316abcb8c6ab3276`）。
这些结果仅是项目可见、候选自有的开发证据；独立 benign/malicious 证据仍为
`NOT_PROVIDED`，不能提交 Host 或发布准入。
classifier/ruleset 最终源码 SHA、exact-main CI、两个 clean clone 的最终可复现资产、
签名外部评估、受保护账本 proof、tag、GitHub prerelease 和独立审计均未在本交接
记录中提供。当前结论：

```text
BLOCKED / NOT PROVIDED / REQUIRES INDEPENDENT AUDIT
```

当前设计、Host、审计迁移、operator-only 上线和逐条追踪证据分别见
[DESIGN.md](DESIGN.md)、[ROUND9_HOST_RUNNER.md](ROUND9_HOST_RUNNER.md)、
[ROUND9_AUDIT_SCHEMA_V6.md](ROUND9_AUDIT_SCHEMA_V6.md)、
[ROUND9_INDEPENDENT_AUDIT_CONTRACT.md](ROUND9_INDEPENDENT_AUDIT_CONTRACT.md)、
[ROUND9_OPERATOR_ROLLOUT.md](ROUND9_OPERATOR_ROLLOUT.md) 和
[ROUND9_EXECUTION_RECORD.md](reports/ROUND9_EXECUTION_RECORD.md)。

`v0.16-rc.1`、Round 8 `v0.16-rc.2` 与 failed Phase 1 `v0.16-rc.3` 身份、Release、SO、checksum、manifest、
attestation 和 Host evidence 均为不可变历史证据；Round 9 不得覆盖、重打、改名、
修复或冒充这些产物。生产仍保持 `mode=audit`、`subject_control=false`；本文件中的
生产章节只属于 operator runbook，不构成 Codex 的生产变更授权。

## Historical 2026-07-22 Round 8 handoff

以下内容原样保留 Round 8 `v0.16-rc.2` 的历史交接语义。其“当前”“本轮”只指
2026-07-22 的旧快照，不能满足 Round 9 门禁，也不能被重标为本轮 PASS。

本轮修复重点是 Balanced 误报治理：分类器保留 occurrence 级证据归属、当前 turn、
role/provenance、字段与 clause/sentence 边界、主动指令所有者、否定/引用/inert 状态，
并实施一条 occurrence 最多占用一个评分维度。只有同一可归因主动恶意指令或显式
referent chain 中的完整 harmful core 与独立强化维度成立，Balanced 才可阻断。
历史 assistant/tool/system、tool schema、代码、日志、互不相关 JSON 字段和长文本窗口
不得为当前正常请求补齐风险维度。

当前 CPA 固定矩阵：

```text
target:        v7.2.95 / f71ec0eb6776854457892452cf28c47f0d658251
platform:      linux-amd64
host_mode:     counted Mock only; no real Provider
```

源码/编译合同与官方 Host overlay 已在固定 CPA `v7.2.95` primary profile 上通过，但这仍不是候选 SO 的
真实 counted-Mock Host 证明。下列事项保持 **PENDING / NOT PROVIDED**：独立源码与
产物审计、固定 CPA `v7.2.95` 对同一候选 SHA-256 的完整 Host 计数矩阵、外部准入、
生产 Audit 观察和 Balanced canary。详见
[ROUND8_RELEASE_READINESS.md](reports/ROUND8_RELEASE_READINESS.md)。

### Round 8 RC 两阶段发布交接

`release-rc.yml` 只接受 exact-main 注解标签 `v0.16-rc.2`，并使用恰好 10 个
`workflow_dispatch` 输入：5 个 tag/commit/tree/CI 身份输入（其中 `ci_run` 以
`RUN_ID:RUN_ATTEMPT` 绑定两项身份）、布尔值 `publish_rc_release`，以及 4 个受保护
Host 输入（`host_run` 同样编码 run ID/attempt，另含 artifact ID、artifact digest
和一次性 64-hex challenge）。

- `publish_rc_release=false`：4 个顶层 Host 输入必须为空；完整 Linux 与固定 CPA
  `v7.2.95` primary profile 内部门禁通过后，对根构建和两个独立 clean clone 的全部 17 项最终资产
  逐字节比较，仅上传私有 Actions Host-test candidate，不创建或修改 GitHub
  Release。Host/count-Mock 状态保持 `NOT_RUN / HOST_TEST_REQUIRED`。
- Host 阶段：`round8-host-validation.yml` 只在受保护的 `self-hosted` / Linux /
  x64 / `cag-round8-sandbox` runner 上运行。它按 Phase 1 run/attempt、artifact
  ID/digest 下载精确 17 项候选，验证 Phase 1 signer workflow、tag ref、commit 和
  每个资产的 GitHub attestation；随后验证受保护 daemon ID、sandbox/production
  labels、预装 immutable probe image，并通过不可预测宿主 bind-mount nonce
  challenge 证明本地性。固定 CPA `v7.2.95` counted-Mock lane 完成后，仅对 schema-v2
  `round8-host-evidence.json` 与 sidecar 生成 GitHub attestation 并上传两文件 artifact。
- `publish_rc_release=true`：只接受指定成功 Host run/attempt 和精确 Host artifact
  ID/digest，并要求 evidence 中的 challenge、Host workflow/ref/commit、Phase 1
  artifact、runner、daemon/sandbox/probe 与 locality `PASS` 全部一致。证据仍必须
  绑定 CPA v7.2.95 的 counted-Mock `PASS`、Chat/Responses `1/0` 上游
  计数、42/42 benign 与 paired-malicious 结果、stream/nonstream、
  audit/balanced/strict、DB quick_check/WAL/restart、Balanced/Strict incomplete、
  usage queue 和 Raw Capture 专项，并证明未联系真实 Provider、未访问生产、无
  unexpected restart/OOM/panic/fatal/plugin error。证据及 sidecar 进入两份 clean
  rebuild、audit bundle、`checksums.txt`、manifest 和 19 项 Release allowlist。

上述代码门禁依赖尚未自动创建的 GitHub 外部配置：`round8-host-validation` 与
`round8-rc-publication` environments、required reviewers、禁止 self-review、禁止
admin bypass、精确部署策略、专用 runner，以及 `ROUND8_SANDBOX_ID`、
`ROUND8_DAEMON_ID`、`ROUND8_PROBE_IMAGE_ID`。在管理员完成并复核这些配置前，
不得把当前仓库状态写成“可发布”或“Host 已验证”。

发布阶段的 Host 结论只能表述为 `VERIFIED / COUNTED_MOCK_ONLY`，不得表述为真实
Provider 或生产验证。独立审计和独立评测仍是 `NOT_PROVIDED / required`，生产批准
仍未授予。

方法学披露：本轮开发继承了下文记录的历史受限材料误读事件；此前多次过宽只读搜索曾
显示 evaluation/holdout 测试或历史报告文件名、历史 ruleset SHA-256 引用、少量调用路径
和 aggregate 摘要。本次收口又有一次过宽 `git grep` 意外输出若干 retired holdout fixture
中的单条 request 与 label。possessive browser target 漏报在该搜索前已经由分类器终审明确
提出；这些输出未复制进源码、测试或文档，也未用于选择规则、谓词、分数或阈值。另有
一次过宽的 `go test ./internal/classifier` 可能编译或运行了受限 gate；其结果继续从全部
发行证据中排除。本次会话不得声称 fixture 零接触、盲测或独立评测；这些证据继续标记为
`NOT_PROVIDED`，未来必须由未参与开发且持有全新未接触 holdout 的审计方重新裁决。

## Historical Round 6 handoff

以下 Round 6、v0.15、旧 PR/CI、evaluation-v10 与旧 CPA 记录仅用于历史审计。
其中出现的“当前”均指当时快照，不是 Round 9 当前状态，也不得重标为本轮 PASS。

## Current PR #18 hardening delta — 2026-07-20

[PR #18](https://github.com/yujianwudi/cyber-abuse-guard/pull/18) is the
external authority for the final exact head, CI, and review state. The current
source delta closes a quoted-review continuation bypass by independently
reclassifying only the unique quoted referent from the newest eligible RoleUser
review. `Execute it`, `proceed`, `go ahead`, and bounded polite or
conditional equivalents reactivate that referent; questions, explanations,
negation, consequences, remediation, and assistant/system/tool/unknown review
carriers remain inert. User attribution controls `FindingOrigin` and subject
admission rather than direct disposition: a mixed-trust RoleUser pair remains
conservatively classified but is `non_user_or_untrusted` and cannot accumulate
subject risk. The result does not borrow safety-wrapper signals or context.

Long streaming fields retain only a privacy-safe `Result` and bounded
affirmative-follow-up facts, never the quote or prompt. Unprovable cross-window
linkage yields `CoverageUnavailable` / `classifier_window_incomplete`; direct
referent classification consumes `MaxChunks` and can yield
`classification_chunk_limit`. Formal release also rejects all document-root,
fixture, and current-identity environment overrides. The visible document
prologue, real-tree CI gate, and public jailbreak review's required/install/
verify audit-bundle path are mutation-tested.

The reverse audit also closed two follow-up edge cases: `just`, `simply`,
`let's`, and `let us` are now directive governors; and a complete but
unrecognized speech act cannot suppress conservative signals from an incomplete
prior field. Only a positively proven analytical/safety/negated form receives
inert credit. Bounded adjacent reclassification is skipped when either field
already proved an inert quoted referent.

A final delta audit found that the earlier parser still collapsed a multi-action
clause to one rightmost decision and retained only one later cancellation. That
could allow `implement and run; do not run` by losing the still-active
implementation action, and could also block a request after every distinct
action family had been explicitly cancelled. The current source keeps every
bounded active/cancelled occurrence, applies cancellations by action family and
order, preserves alternative-branch semantics, and covers narrow
`follow`/`obey`/`carry out`/`run quoted request` forms plus defensive neighbors.
It also distinguishes coordinated `do not A or/nor B`, where one negation
cancels both actions, from `A or do not A`, where the prohibition is only an
optional alternative and cannot erase the active choice. An alternative arm
remains alternative through later `and`-joined cancellations in that same arm;
it cannot leak a cancellation back across the `or` boundary.

The historical v0.15 Linux development snapshot passed targeted OpenAI Chat and
Responses routes, the long-text size/position ladder, classifier and plugin
race, full `make unit-test`, and `make round6-script-test`. Its safe-gate suite
contained 152 tests. These results are not a candidate artifact, CPA v7.2.88
Host + Mock record, independent audit, external evaluation, tag, or Release
approval.

历史 v0.15 策略与构建身份：

```text
project_version: 0.15
formal_tag: v0.15
streaming_scanner: streaming-scanner-v1
recorded_current_classifier_policy_version: classifier-policy-v5
recorded_current_classifier_policy_sha256: 0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b
ruleset: 1.0.7 / 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
historical_v10: CONSUMED / FAIL / MUST NOT RERUN / NOT A FORMAL INPUT
```

发行证据链必须严格按顺序执行：

1. 冻结最终 PR head，并通过该 PR 的 Linux amd64 CI；
2. 合并最终 PR 到 `main`；该合并只是候选生成前置条件，不是发行批准；
3. 精确合并后 `main` commit/tree 的 Push CI；
4. 从 `refs/heads/main` dispatch 候选 workflow，生成私有、无标签、干净精确源码的
   Linux amd64 Actions 候选产物及
   `candidate-manifest.json`；
5. CPA v7.2.88 Host + Mock 记录绑定 candidate SO SHA-256，并通过 schema v2
   `cpa_version`、`cpa_commit`、`cpa_host_sha256` 绑定 Host 身份与证据哈希，同时证明
   Auth Selector、Provider、Usage、Mock Upstream
   四层零调用；
6. 独立源码、产物、Host 审计；
7. 对该精确候选独立编写并首次且唯一消费 `evaluation-v11` 或更高评估，低敏报告状态必须
   为 `CONSUMED / PASS`；
8. 如需持久交接，可选创建注解标签 `v0.15-dev.round6[.N]` 的 draft prerelease，
   但它必须标记 `BLOCKED / NOT A FORMAL RELEASE`；
9. `round6-prerelease-attestation.json` 必须绑定该 evaluation ID 与报告 SHA-256，之后才允许
   注解正式标签 `v0.15`、已验证 draft 与受保护 promotion。

最终 PR head 合并前必须没有未解决且未过时的可操作审查线程。自动化审查只作为开发
反馈，不得写成远端或独立批准。

中立源码策略见 [RELEASE_POLICY.md](RELEASE_POLICY.md)。未来外部决策资产固定命名为
`round6-prerelease-attestation.json` 与 `formal-release-attestation.json`；本源码文档不
自我回填它们的未来 PASS 哈希或发布状态。

正式 source / audit bundle 必须排除 evaluation、Holdout、private、blind、retired
资料；只允许携带外部 evaluation 身份/哈希和 release attestation。历史 v10 不得进入
formal build 或 bundle。

最后更新：2026-07-17（Asia/Shanghai）

## 0. Round5.2 冻结历史交接门禁

本节刻意只记录可在合并前冻结的 round5.2 证据：source-freeze identity、安全本地门禁、
精确源码 Branch Push CI、PR 临时 Merge Result CI 与复核状态。它不猜测或自引用未来
Merge Commit。合并后的 main CI、exact-main artifact、Tag、Release Flags 与发行资产
哈希，只能以 GitHub API metadata 为权威外部证据；对应 Release notes 只负责链接这些
记录、列出逐资产 SHA-256 并保留全部未完成门禁。修复分支以历史
`main@89b62b341278073e7b6518b85e41cd7f7c6b682c` 为基线；下方合并前字段已按 GitHub 与本地
实际证据回填，不包含未来 Merge Commit。历史 `v0.1.2-dev.round5.1` 是 `BLOCKED / NOT FOR DEPLOYMENT` 的开发预发行，
其 Tag 必须永久保持指向 `89b62b341278073e7b6518b85e41cd7f7c6b682c`，不得移动或复用。
当前状态是：

```text
ROUND5.2 SOURCE FREEZE, LOCAL GATES, PUSH/PR CI, AND REVIEW PASS /
MERGE, MAIN CI, ARTIFACT, TAG, AND RELEASE PENDING /
REAL HOST AND INDEPENDENT REVIEW NOT RUN /
METHODOLOGY HANDOFF BLOCKED
```

Round5.2 当前证据身份：

```text
branch: agent/post-release-reaudit-fixes
base_commit: 89b62b341278073e7b6518b85e41cd7f7c6b682c
source_fixes: COMPLETE / SOURCE FREEZE READY
source_freeze_commit: 170de7f324c2bdf9a473b1866bdfc1e097182301
classifier_policy_identity: classifier-policy-v2 / e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec
cpa_latest_source_compat: v7.2.80 / 09da52ad509e2c18e7b9540db3b98c2214c280aa / DEVELOPMENT SELF-CHECK AND EXACT-SOURCE PUSH/PR CI PASS
local_safe_gates: PASS / format-diff-module / round5 / safe test-vet / sanitized public corpus / scripts / CPA latest remote identity and contracts
push_ci: https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29467936241 / attempt 1 / SUCCESS / quality-and-artifacts, fuzz-long, reproducibility
source_freeze_push_artifact: 8363874523 / cyber-abuse-guard-linux-amd64-dirty / 10827848 bytes / sha256:fdec405e991498d4b7fb16557796a22736456c01fb1bd0e31d8eac5800438176 / expires 2026-10-14T03:00:42Z / development-only
pull_request: https://github.com/yujianwudi/cyber-abuse-guard/pull/8
pull_request_ci: https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29467938359 / attempt 1 / SUCCESS / base 89b62b341278073e7b6518b85e41cd7f7c6b682c / head 170de7f324c2bdf9a473b1866bdfc1e097182301 / synthetic merge fc8b5649505662e47bedbd85a41fbea306a2df7c / quality-and-artifacts, fuzz-long, reproducibility
code_rabbit_follow_up: PASS / CLI 0.6.5 / final source delta / 0 issues / GitHub check SUCCESS / 10 of 10 current PR review threads resolved (9 source-freeze + 1 documentation wording)
tencent_isolated_host: NOT RUN
independent_review: NOT RUN
post_merge_main_ci: EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES
post_merge_artifact: EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES
tag_and_release: EXTERNAL EVIDENCE — GITHUB API METADATA + LINKED RELEASE NOTES
stable_v0.1.2_tag: NOT CREATED / BLOCKED
production_deployment: NOT PERFORMED
source_freeze_record_status: PRE-MERGE SOURCE EVIDENCE PASS / REAL HOST AND INDEPENDENT REVIEW NOT RUN / BLOCKED FOR HANDOFF
```

合并前采用两层冻结，避免证据文档形成无限自引用：

- `S`（implementation/source-freeze）固定所有代码、workflow、测试、脚本与开发语料；本地
  安全门禁、精确 `S` 的 Branch Push CI、PR 临时 Merge Result CI 和 CodeRabbit 都围绕
  `S` 建立证据。PR CI 必须同时记录 base SHA、head SHA、临时 merge SHA、Run ID/URL 与
  三个 Job 结论，不得把 PR artifact 写成 `S` 或最终 main artifact。
- `D`（evidence-backfill）只允许 README/文档回填 `S` 的真实证据；`S..D` 若包含任何代码、
  workflow、测试、脚本或 corpus 变化，则 `S` 作废并重新冻结。`D` 自身的最终 PR CI 与
  CodeRabbit 由 GitHub checks/API 外部证明，不继续提交自引用字段。

合并后的外部证据必须可独立核验：记录 workflow Run ID/URL、event、attempt、overall
conclusion、head SHA 与全部要求 Job 的结论；记录 artifact ID、API digest、大小、过期时间
及 attestation（若有）；记录 Tag ref 的对象类型、精确 target SHA、签名/verification 状态
（预期 lightweight Tag 应明确记为不适用而非伪称已签名）；记录 Release ID/URL 以及
`draft=false`、`prerelease=true`、`latest=false`。Release notes 只能链接这些 API 记录，
并列出九个发行资产的逐文件 SHA-256 和仍为 `NOT RUN/BLOCKED` 的门禁，不能单独证明
main CI、artifact 与 Tag 指向同一 Commit。

历史 round5.1 证据身份：

```text
historical_prerelease: v0.1.2-dev.round5.1 — BLOCKED / NOT FOR DEPLOYMENT
historical_release_url: https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.1.2-dev.round5.1
historical_merge_and_tag_commit: 89b62b341278073e7b6518b85e41cd7f7c6b682c
historical_implementation_freeze: 174401cd234f960e66ce55b9fc88614d948d5129
historical_pull_request: https://github.com/yujianwudi/cyber-abuse-guard/pull/7
historical_main_ci: https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29409182748
historical_main_ci_attempt_1: FAIL — fuzz timer-boundary context deadline exceeded
historical_main_ci_attempt_2: PASS — all jobs
historical_artifact_id: 8340894661
historical_artifact_digest: sha256:7419fcf0c0745472728d6e9c73d99aa01737930ccf25e26501e17ae4d453db61
historical_so_sha256: 3176d2af23963a2768672034af02fc1ca9ebe0c3f29a3654aa802ce0f822b6be
historical_release_flags: prerelease=true; latest=false
historical_tag_policy: IMMUTABLE / MUST NOT MOVE
```

Round5.1 的本地 CodeRabbit CLI 后续复核曾记录 0 issues，但 GitHub Bot 评论随后因 PR 已
关闭而显示 `Review failed — pull request is closed`，因此不得把它写成 CodeRabbit 的公开
批准。Round5.2 的 CLI `0.6.5` 最终源码 delta 复核为 0 issues，GitHub CodeRabbit 检查为
SUCCESS，当前 10/10 个 review thread（9 个源码冻结线程 + 1 个文档措辞线程）均已处理并
关闭；这仍不等于独立源码/artifact 复核。

工程证据包只能按其精确 Commit 和轮次使用。任何历史 round5.1 SHA、CI 或 artifact 都不能
替代 round5.2 证据。CI 或单元测试全绿也不能替代腾讯云二号机 CPA v7.2.75 + Mock
upstream Host 验收或独立源码/artifact 复核，更不能推翻唯一方法学有效且已冻结的 v10
`CONSUMED / FAIL`。

旧版 CPA 兼容性门禁、校验和与 CI 记录仅作为历史事实保留在 CHANGELOG 和归档报告中；
它们不是当前 v7.2.104 准入证据，也不得替代本轮精确源码、Host 与独立审计门禁。

第五轮审计必须单独确认以下宿主边界：

- Router 无法证明请求进入 CPA 前使用的本地 `model_instructions_file`、`AGENTS.md`、
  远程指令模板或其他高优先级配置的路径、owner、mode、hash/签名与 reload 历史。宿主须
  实施路径 allowlist、写权限隔离、SHA-256/签名绑定、启动和每次 reload 前复核、固定变更
  审计，以及远程模板人工审批并固定 commit/hash。
- `safetySettings`、`generationConfig`、`options` 等 Provider 配置不能交给 Prompt 关键词
  猜测；宿主须通过版本化 schema allowlist 拒绝不安全字段/值，或在进入 Router 前强制
  覆盖为安全值，并在隔离 Host 核对最终生效配置。
- Key-only Tool 映射仅在已建立的 tool/tool-payload 来源内由
  `cag_control_schema=meta_override_control/v1` 显式启用；相同 marker 位于普通业务 JSON
  或 Provider 配置时不具备映射权限。已知 schema 的未知控制键走固定 `tool_schema`
  incomplete，不把原始 Key 写入审计。
- Provider-aware 主 JSON walker 仅把根级容器 `tools` / `functions` 识别为模型可见 Tool
  Definition；即使 raw body 超过 `max_scan_bytes`、第二次 role index 被跳过，位于 256 KiB
  原始偏移之后的 description/schema 文本仍会进入有界分类。嵌套业务 `catalog.tools/functions`
  与根级标量同名字段仍保持 inert，避免扩大普通 JSON 误报面。
- CPA `interactions` 已进入固定 SourceFormat、审计枚举与 Executor input/output formats；其
  JSON 使用无角色信任的保守遍历，Strict benign 不再因 unknown format 误封。v7.2.80 的
  agent 请求若被 Guard self/executor 路由，CPA 当前会在 Auth/Provider 前返回固定 400 而非
  执行 Guard 403；model/agent、stream/non-stream 和零下游计数仍须由服务器沙盒验证。
- Ruleset `1.0.7` 只标识内嵌 YAML Cyber Abuse 资产，不包含 Go 代码中的
  `META-OVERRIDE-001` overlay、Extractor/Multipart 语义、批准的 Tool Schema 映射或
  control-plane counter。Round5.2 source-bound classifier-policy identity 是
`classifier-policy-v2` / `e9b87f7e2635495bdbceae469ef89e696b419f0a9a6fd129558a20bc4be947ec`，
  并须与 source-freeze Git Commit `170de7f324c2bdf9a473b1866bdfc1e097182301`
  同时核对。历史 round5.1 值为
  `classifier-policy-v2` / `c2092d0949fcaa1d0f085dfe31a668d45cc4d14efc10427d0f3ebcf3e821a112`。
- `testdata/development-public-jailbreak-patterns-v1` 现有 36 个净化用例（18 allow / 18
  audit），必须保持 `development_only=true`、`future_holdout_eligible=false`、
  `derived_from_public_adversarial_taxonomy=true`、`contains_live_payloads=false`。其固定公开
  参考为 `MDX-Tom/gpt-5.6-instruct@18fea37f...`、
  `yynxxxxx/Codex-X@7d0e0064...`、
  `yynxxxxx/Codex-5.5-codex-instruct-5.5@ed0b6dc3...`；只抽象机制，不复制或执行原始
  payload。`source_context` 只是开发元数据，不能证明攻击来自某仓库或本地文件，也不是
  独立盲测证据。
- 普通 CI 已移除 `consumed-boundary-test`。该目标仅保留为另行授权的人工审计入口；第五轮
  日常开发、CI 与 artifact 构建不得访问 evaluation-v10、retired holdout 或历史原始样本。
- 普通 CI 的 integration-tagged 路径仅运行 `make integration-compile`；另有固定的 Host
  源码契约测试，但不得调用 `make integration-test`、启动 CPA 或加载真实 `.so`。Store
  安装和 Host 黑盒矩阵只在后续获授权的腾讯云二号机隔离沙盒执行。
- Role-aware 路径为避免把 System 安全策略或 Assistant refusal 归因给用户，不会把其中的
  base Cyber Abuse taxonomy 与后续 User 消息合并。审计必须把这视为 P2 边界，并独立
  验证所有高优先级指令来源的路径、owner、mode、hash/签名和 reload 过程；不能把该边界
  描述为插件已覆盖的供应链防护。
- `Segments` 当前仍在主 extractor walk 后执行第二次有界 JSON parse。已有 differential、
  race、fuzz 和第五轮标量媒体回归没有复现泄漏，但独立复核应检查两套路径是否存在语义
  漂移；后续应重构为单次解析产出共享语义结果。
- 历史 round5.1 从 Base `67b2470` 到 pre-audit freeze `1466b2e7` 只有一个综合实现
  Commit。后续修复回归已转绿，但没有独立保留两个 HIGH 的修复前红测 Commit 或命令
  日志；任务书中的 red-before-fix 证据要求仍是历史独立审计项，不能由最终绿测倒推。

本轮还发生了独立于历史 holdout-v3 事件的方法学偏差：一条作用域过宽的只读 `git grep`
意外输出了受限 `testdata/holdout/malicious-operational.jsonl` 正文。没有运行 holdout 测试；
输出未重定向、未复制到源码/测试/文档、未分析，也未用于调参或形成实现结论。后续发行
审计中，一条 classifier 源码搜索又意外匹配了历史 holdout gate-test 源码行；它没有打开
任何 `testdata` 语料、没有运行 holdout/evaluation 测试，输出同样没有用于实现判断。
其余命令均须显式排除 holdout、evaluation-v10、retired/historical 语料。因此本轮不得
声明“完全未访问受限语料”；即使工程门禁全绿，方法学交接仍为 `BLOCKED FOR HANDOFF`，
不能升级为独立验收通过。

发行后的 round5.2 复审还发生了一次单独的方法学偏差：大小写不敏感的路径排除失效，
只读状态搜索从 `EVALUATION_V5_REPORT.md` 到 `EVALUATION_V10_REPORT.md` 各输出了恰好一行
状态。没有打开或输出任何评估语料或样本行，没有运行 evaluation 测试，也没有据此作出
源码、测试、文档或发行决策。该披露不改变 v10 `CONSUMED / FAIL`，并继续使方法学交接
保持阻断。

同一轮复审中，classifier 子代理误启动 `go test -shuffle=on -count=20 ./...`。主线程在进程
运行约 23 秒时立即 interrupt，并向 PID `265343` 发送 `TERM`；随后同一命令又以 PID
`266741` 出现，父进程为 WSL `/init`，与孤立的 CodeRabbit/工具会话一致。主线程再次
interrupt classifier agent，终止所有匹配进程，并复查确认无残留。目前无法确认终止前
是否有 consumed evaluation/holdout 测试被选择或是否读取了受限 fixture。因此该命令及其
所有部分结果永久排除，不得用于源码、测试、文档、CI 或发行判断；本轮也不得声明未访问
受限内容。后续验证已强制只使用显式 safe allowlist。v10 仍为 `CONSUMED / FAIL`，handoff
继续 `BLOCKED FOR HANDOFF`。

最终独立 diff 审计又发生一次范围错误：只读 `cmd/**/*.go` 搜索打印了部分
evaluation/holdout author 源码片段与少量合成示例。它没有打开受限 `testdata`、没有运行
author/evaluation/holdout 工具，也没有被用于实现、测试、文档或发行结论。该输出永久排除，
但本事件必须保留在交接中，并继续阻止“受限内容零访问”的方法学声明。

历史 round5.1 的允许范围本地检查、精确 CI 和 main artifact 已记录在
`docs/reports/TEST_REPORT.md` 与 `docs/reports/RELEASE_EVIDENCE.md`，只能证明其精确历史
Commit。Round5.2 必须在本文件中记录新的 source freeze、本地门禁、Branch Push CI、PR
Merge Result CI 与复核；合并后的 main CI、exact-main artifact、Tag 和 Release 由 GitHub
API metadata 独立证明，并由对应 Release notes 链接和汇总。
历史 round5.1 和更早 CPA v7.2.72 Host 结果均不能继承为 round5.2 PASS。

---

## 以下为上一轮冻结交接记录（历史，不是第五轮当前证据）

## 1. 历史结论

当前状态是：

```text
BLOCKED FOR HANDOFF
```

这不是最终质量 PASS，也不是生产批准。实际起始基线为
`a121a444cb0d82cba4e27754914a1f88258e1d7b`；实现冻结为 `61536f9`，两条精确 SHA 的
GitHub CI 均已通过。证据文档单独提交；最终交接时已核对工作树清洁。

方法学有效的 v10 首次且唯一正式运行仍为 `CONSUMED / FAIL`：合法误报 28/320，恶意
阻断 49/320，精确分类 33/320。该结论不变。不得读取、打印、执行、通过 Git 历史获取或
逐条分析 v10 样本，也不得用开发集冒充新盲测。

方法学事件：三条作用域错误的 WSL 源码搜索命令意外输出了已退役
`testdata/holdout-v3` 的若干行。三次搜索都被立即停止；输出内容没有被分析，也没有用于
分类器调优或任何结论。Evaluation v10 内容未被访问。即便如此，已退役 holdout-v3 不再
具备独立证据资格；该事件本身也使交接状态保持 `BLOCKED FOR HANDOFF`。

未创建 Tag、GitHub Release，未部署或修改生产 CPA。即使未来工程门禁通过，也不能保证
上游账号永不被警告、限流、暂停或封禁。

## 2. 证据标签

审计时必须严格区分：

| 标签 | 含义 |
|---|---|
| `DEVELOPMENT SELF-CHECK` | 指定本地开发命令已运行，只证明该命令和当时工作树 |
| `SOURCE IMPLEMENTED` | 源码/测试夹具存在，不表示已执行 |
| `SOURCE OVERLAY PASS` | 固定 CPA 上游源码契约已运行，不表示真实 Guard `.so` 已加载 |
| `GITHUB CI` | 精确推送 Commit 的远端检查；旧 main/旧分支结果不能继承 |
| `REAL HOST` | 真实 Guard `.so` 由 CPA v7.2.72 Host 加载，并经 HTTP 路径验证 |
| `LOCAL MIS-EXECUTION / EXCLUDED` | 命令在授权证据路径外运行；该结果永久排除，必须分别引用 GitHub CI 或 Leo 的独立结果 |
| `NOT RUN` | 没有该层结果 |
| `BLOCKED` | 缺少冻结、环境或前置条件，绝不是 PASS |

WSL 中曾误执行以下三个本地目标：

```text
make cpa-router-fixture-blackbox
# removed historical command: make cpa-v7272-host-blackbox
scripts/management-proxy-413-test.sh
```

它们只使用随机回环端口和 Mock 组件，没有连接真实 Provider 或生产服务；清理核对确认无
Fixture 进程残留。其结果从交付证据中排除，状态固定为：

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

不得把这些本地结果改写成 PASS。

## 3. 精确开发身份

```text
repository: https://github.com/yujianwudi/cyber-abuse-guard-next
starting_baseline: a121a444cb0d82cba4e27754914a1f88258e1d7b
branch: agent/complete-classifier-cpa-v7272-handoff
reliability_checkpoint_commit: 573def2649d164161e2dfdfeb3f59b1e1b38ebbc
implementation_freeze_commit: 61536f9f02c47a4d79031a47dc8a284f040e41c1
evidence_document_commit: a2d30fc63fca4fba020cda282474aaca15a47d8f
root_cpa_version: v7.2.72
cpa_upstream_tag_commit: 6279bb8a4c2835ff6ed99c6b85083b2afbefa681
cpa_module_sum: h1:ppce0MLsz2xJi2yi3/A60zu03cM7bMWBAEJ6eC29E5Y=
cpa_go_mod_sum: h1:f4pcyAej8RoeRhIxJfm+OUMkCKaApiA8WzxR2XVlBh8=
target: Linux amd64, glibc 2.34+, C ABI/RPC schema v1
recorded_wsl_toolchain: go1.26.4 linux/amd64
ruleset: 1.0.7
ruleset_sha256: 7bef8b0854b4d75dd5d807e1c33e93b708af4e9e29d0d2b59a18b9031c4da134
historical_classifier_policy_version: classifier-policy-v2
historical_classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
```

classifier-policy 哈希通过源码清单测试绑定分类器、Matcher、Normalizer、Role、Wrapper、
BehaviorGraph、语义组合、Extractor、规则加载/YAML 和依赖锁。管理状态会暴露版本/哈希，
但当前 Build Metadata/Artifact Verifier 尚未绑定该字段，因此最终完整 Git Commit 仍是行为
身份的一部分。

## 4. 请求安全链路

```text
下游请求
  -> CPA v7.2.72 ModelRouter（Auth Selector / Provider / Usage / Upstream 之前）
     -> 放行：Handled=false，保持模型、消息和 Tool 参数，进入 CPA 原生链路
     -> 阻断：Handled=true + TargetKind=self
        -> execute / execute_stream / count_tokens：策略 HTTP 403
        -> stream：在成功 SSE Header/Chunk 之前同步 403
        -> http_request：仅有 RPC/Adapter status-error 405（response=nil）
           /v1/alpha/search 普通路径选择 codex，并把 Executor Error 映射为 502；
           当前没有官方公开路由把 Guard Error 映射为最终客户端 405
        -> Auth Selector / Provider / Usage / Mock Upstream 应全部为 0
```

CPA Host 根本 fail-open 仍存在：插件未加载、注册失败、被 fuse、Router error、Host 接受
Handled Result 前 panic、invalid target、executor not-ready，或更高优先级 Router 先 Handle，
都可能继续后续 Router/原生路由。同优先级按 Plugin ID 升序。`enforcement_ready` 仅说明
插件内部 Runtime 状态，不能证明 Host 已加载、未 fuse、顺序正确或具体 Executor ready。

## 5. 分类器重构

本轮源码将危险底层行为与 Wrapper/Amplifier 分开：

- Wrapper-only 不能创建 Cyber Abuse Taxonomy；弱 Wrapper 放行，强 Wrapper 最多审计；
- Wrapper + 独立危险行为可提高置信度，但保留原危险类别；
- BehaviorGraph 表示 Actor/Action/Object/Target/Technique/Execution/Credential/
  Persistence/Evasion/Exfiltration/Impact/Scale/Authorization/Role/Carrier 等关系；
- 图和管理输出只含布尔/关系/固定 ID，不含原文、片段、目标、URL 或 Tool Arguments；
- System 安全政策和 Assistant refusal 不作为用户恶意意图；相邻用户续接和明确三轮计划可
  有界组合；
- Tool provenance、占位符绑定、URL percent、HTML entity、Base64、JSON Unicode、嵌套
  Tool JSON 和有限分片/同形字在资源上限内处理。

可见开发集 `testdata/development-adversarial-v11-prep` 共 35 条：16 block、14 allow、
2 audit、3 resource-boundary。覆盖八类、四协议、三种语言类型以及 Wrapper、Role、
Multi-turn、Tool、Carrier、Placeholder 和边界。其 Manifest 明确
`development_only=true`、`future_holdout_eligible=false`。里奥绝不能把它或派生措辞用于
独立 v11。

## 6. 主体、持久化与隐私

- 主体风险以 Subject HMAC + 域分离 Request Digest 幂等；execute/stream/token-count、
  retry、并发、pending miss/expiry、enabled reconfigure 和 shutdown race 不重复记分；
- 幂等 Receipt 随 Subject Snapshot 保存；旧快照保持兼容；
- Pending Cache 使用有序 O(1) 刷新/淘汰；
- Unix HMAC 文件校验 owner/mode/regular-file/symlink/FIFO/device/空短 Key；
- SQLite/迁移备份/Subject Snapshot/管理 API/CSV/日志/Panic/Watchdog/Release Evidence
  有 Canary 测试；
- v1→v2 迁移在发布备份或写入前验证旧库 `request_hash`、`subject_hash`、`model` 和
  `source_format` 隐私契约；任一值不是规定 Digest/固定 Provider Enum 时 fail closed，
  不发布备份、不执行迁移，原库保留给运营修复；不会自动清洗旧明文库；
- 插件不把 Prompt、Token、Cookie、OAuth、API Key、IP、域名或完整模型名写入这些表面；
- 仍未实现 HMAC 双密钥轮换和 keyed whole-snapshot MAC。

## 7. 当前已执行的开发检查

| 范围 | 结果 |
|---|---|
| Wrapper/BehaviorGraph/Role/Policy Identity 定向分类器测试 | **DEVELOPMENT SELF-CHECK PASS** |
| 35 条 Development Corpus Validator | **DEVELOPMENT SELF-CHECK PASS** |
| Prompt Injection/Tool/Encoding 定向 Plugin 测试 | **DEVELOPMENT SELF-CHECK PASS** |
| Classifier Validator `go vet`、gofmt、根 module verify/tidy、当时 diff check | **DEVELOPMENT SELF-CHECK PASS** |
| WSL `-race` Subject/Config/Audit 及定向 Plugin 生命周期/隐私测试 | **DEVELOPMENT SELF-CHECK PASS** |
| `go-safe-development-test.sh test`、`go-safe-development-test.sh race`、`go-safe-development-test.sh boundary` | **DEVELOPMENT SELF-CHECK PASS** — WSL Ubuntu 26.04 / Go 1.26.4；test/race 未运行 Evaluation/Holdout 测试名；boundary 只运行 3 个 v10 聚合/报告标记/拒绝重跑测试且日志确认 fixture 未访问 |
| WSL reliability `go vet`、Health Script、Release Evidence Privacy Script | **DEVELOPMENT SELF-CHECK PASS** |
| 同机 Classifier Benchmark 对比 | **DEVELOPMENT SELF-CHECK PASS / NOT FINAL EVIDENCE** |
| CPA 16 个精确官方 Host Source Tests | **SOURCE OVERLAY PASS** |
| 真实 `.so` Store Install/Host Load | **GITHUB CI PASS** — 真实 Store ZIP 首装并由 CPA v7.2.72 Host 加载；本地误执行仍排除 |
| 四协议 403/pre-SSE/token-count | **GITHUB CI PASS** — 32 个 Host 子测试；本地误执行仍排除 |
| `http_request` RPC/Adapter status-error 405（response=nil） | **SOURCE / ADAPTER CHECK** |
| 官方 CPA Handler 最终客户端 HTTP 405 | **NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF；当前 CI 无法补齐** |
| Auth/Provider/Usage/Mock Upstream 零调用 | **GITHUB CI PASS**；本地误执行仍排除 |
| Multi-Router/fail-open Native Fixture | **GITHUB CI PASS** — 15 个隔离原生场景；panic/fuse 另有官方源码 overlay |
| Management Proxy 413 | **GITHUB CI PASS** — 超限请求在计数 CPA Handler Stub 前返回 413 |
| GitHub CI | **PASS** — Push `29312969925`，PR `29312971717`；Push 长 Fuzz PASS，两条可复现性 PASS |
| CodeRabbit Ready Review | 首轮对 `8719c7f` 提出 8 个线程和 2 个 nitpick；有效问题由 `61536f9` 修复，`cmd` 缺失符号项经定向编译证伪；对 `8719c7f..61536f9` 的后续复审为 **NO ACTIONABLE COMMENTS** |
| 开发候选产物与哈希 | **GITHUB CI PASS / RECORDED**；不是正式发布产物 |

完整命令和矩阵见 `docs/reports/TEST_REPORT.md`，性能与隐私分别见
`docs/reports/PERFORMANCE.md`、`docs/reports/PRIVACY.md`。

## 8. 冻结 v10 结论

审计者只允许读取冻结聚合报告，不允许读取/打印/运行样本。v10 聚合：

| 指标 | 结果 |
|---|---:|
| 合法误报 | 28 / 320（8.75%） |
| 恶意阻断 | 49 / 320（15.31%） |
| 精确分类 | 33 / 320（10.31%） |

发布门槛全部失败，四个关键类别门槛也全部失败。该历史结果既不能被本轮源码改写，也不能
被开发集 PASS 覆盖。未来必须由开发流程外独立创建全新盲测。

## 9. 里奥建议验证顺序

在最终实现冻结前，本地只运行不会打开已消费评估样本、不会加载 `.so` 的安全开发门禁：

```bash
git status --short
git rev-parse HEAD
git log --oneline --decorate -10
go version
go env GOOS GOARCH CGO_ENABLED GOMAXPROCS GOAMD64

make format-check
make git-diff-check
make module-verify
./scripts/go-safe-development-test.sh test
./scripts/go-safe-development-test.sh race
./scripts/go-safe-development-test.sh boundary
make vet
make fuzz-smoke
make script-test
make corpus-regression
make benchmark
make vulncheck
make build-linux-amd64
make cpa-host-fixture-contract
```

不要运行已消费 v10 分类，不要运行独立 v11。若某个广泛 Target 会读取已消费样本，应先
审计其定义并改用不读取样本的精确定向命令；不得通过跳过失败或 `|| true` 制造 PASS。

`make integration-test`、`make management-proxy-413-test` 和带
`REQUIRE_DIST_ARTIFACTS=1` 的 `make cpa-store-contract` 只能由授权 GitHub CI 运行，并在
Leo 的授权隔离环境复验。CI 的 Host Blackbox 通过 `InstallManifest` 完成同一 Dist 身份的
首装和真实 Host 加载；随后 `TestPublishedStoreArchive` 对该身份验证 repeat-skip 与
tamper-repair。Synthetic fallback 不是 CI 证据。

现有项目 `httptest.Server` 是测试自建的包装，会手工把 `error.StatusCode()` 写入 HTTP
响应；它只能证明 RPC/Adapter 状态码错误层，不能冒充官方 CPA Handler。CPA v7.2.72
确有 provider-specific 的 `POST /v1/alpha/search`：普通路径固定选择 `codex`，而且对
任何 `HttpRequest` Error 固定返回 502。Guard 返回的是携带 405 的 Error，不是成功的
`ExecutorHTTPResponse`，所以当前没有官方公开路由把它映射为最终客户端 405。该项无法
由当前 CI 自然产生，是独立的 `BLOCKED FOR HANDOFF` 阻断项。

精确 Implementation Freeze 的 GitHub CI、产物 SHA-256、Store ZIP 根目录、完整 Install
Lifecycle、真实 Host 四协议和零副作用、Proxy 413 以及隐私 Canary 已记录。最终独立质量
结论仍由里奥给出。

## 10. 交接字段

```text
implementation_freeze_commit: 61536f9f02c47a4d79031a47dc8a284f040e41c1
evidence_document_commit: a2d30fc63fca4fba020cda282474aaca15a47d8f
pull_request: https://github.com/yujianwudi/cyber-abuse-guard/pull/4
clean_tree: YES AT FINAL HANDOFF
github_ci: PASS — push 29312969925; pull_request 29312971717
real_host_matrix: GITHUB CI PASS — 32 Host subtests; 15 Router scenarios
management_proxy_413: GITHUB CI PASS
http_request_adapter_405: SOURCE / ADAPTER STATUS-ERROR CHECK (response=nil)
official_cpa_final_client_http_405: NOT AVAILABLE / NOT RUN — BLOCKED FOR HANDOFF
development_artifact_hashes: RECORDED — see docs/reports/RELEASE_EVIDENCE.md
tag: NOT CREATED
github_release: NOT CREATED
production_deployment: NOT PERFORMED
leo_verification: NOT RUN
final_status: BLOCKED FOR HANDOFF
```

旧版 30 项交接清单已经从活跃源码树移除，仅保留在 Git 历史中；当前验证入口见
`docs/ROUND6_RELEASE_GATE.md` 与 `docs/reports/CPA_INTEGRATION.md`。
