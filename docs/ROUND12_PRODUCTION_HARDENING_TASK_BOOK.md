# Cyber-Abuse-Guard Next 第十二轮生产误报、审计证据与仓库治理任务书

```text
current_classifier_policy_version: classifier-policy-v12
current_classifier_policy_sha256: 795dbcf90f94bdebdc1c66abbeeb6c9d92cb82e84b56b602832f89014cd7593c
```

状态：**批准实施 / 未完成验收 / 禁止发布**
工作分支：`codex/round12-production-hardening`
合并目标：`main`
平台范围：**仅 Linux amd64**
CPA 固定目标：**CLIProxyAPI v7.2.116**
发布范围：**源码、测试、审计工具与证据；不创建 tag 或插件 Release**

## 1. 权威基线

本轮从以下干净基线开始：

```text
repository: yujianwudi/cyber-abuse-guard-next
baseline_branch: main
baseline_commit: 21267e742b624b29a75bd3683fd6914f76c764b5
baseline_tree: 6272ac0ba818d39b89481db1f8e360e9b262fde6
cpa_version: v7.2.116
cpa_commit: a88197f845c979132c8978ea223c6af05cc81536
cpa_module_sum: h1:dGGI/CeEQTyKkFNeeqMoIyK/mWx5hVaQlZLDiHPoBTU=
go_toolchain: go1.26.4
platform: linux/amd64
```

基线精确提交的 GitHub CI、Policy and Corpus Gate 与 CodeQL 已成功。任何后续
提交必须取得自己的精确提交结果，不能继承或重标基线 PASS。

本轮输入的二号机报告为：

```text
report_sha256: fcc0558904d17ed735ef131dc2ef01170d5e211fcf95d0686df1af244b25083a
summary_sha256: 446b56b2d91ccafb3c21d04a339f8772febaf68478e8721027cd92e0b8216554
evidence_level: SECOND_MACHINE_DIAGNOSTIC / NOT_INDEPENDENT_ATTESTATION
```

该报告的 1,320 次传输执行内部对账成立，但不能当作 1,320 个独立语义样本，
也不能自动成为 protected Host、独立审计、Release 或生产 PASS。

## 2. 本轮目标

1. 将 `audit.max_db_mb` 从“周期清理目标”收紧为可测量的运行时容量合同；
2. 修复五个已确认的长文本防御性引用误报，同时保持真实激活阻断；
3. 补齐仓库原生指代激活，不再依赖单个复合凭据窃取尾句证明全部召回；
4. 固化一套当前 CPA 的五仓库隔离诊断工具和闭合机器证据 schema；
5. 修正管理请求上限、重复认证头、第三方许可和活动状态文档的漂移；
6. 在 GitHub Linux 门禁与二号机 CPA v7.2.116 隔离审计均通过后，以 PR 合并
   到 `main`；不创建插件发行版。

## 3. 安全不变量

1. 第三方破限仓库、ZIP、脚本和文本仅作为惰性数据读取；不得执行其代码、
   安装器、hook、宏、二进制或依赖。
2. 正常请求、授权安全测试、逆向材料、翻译、引用、拒绝和防御审计不能因高风险
   词汇密度单独被阻断。
3. 只有“完整有害核心 + 当前执行行为 + 明确作用域/未授权语义”才能形成
   `block_malicious_text`。coverage failure 不得伪造恶意召回。
4. Audit、Balanced、Strict 的策略分别验收；Strict incomplete fail-close 不计入
   semantic true positive。
5. Raw Capture 默认关闭；开启时仅保存最终阻断请求、强制脱敏、TTL 有界、容量
   有界，并只通过 CPA 已认证管理接口读取。
6. 所有证据必须绑定 CAG commit/tree/SO SHA、CPA tag/commit/image/binary identity、
   runner source SHA 和语料 commit/tree/blob/文本 SHA。
7. 测试不得接触真实 Provider、生产账号池、生产数据库或真实客户请求。
8. 仅验证 Linux amd64；不增加 Windows/macOS 运行门禁。
9. 不绕过分支保护强推；不创建 tag、RC 或 GitHub Release。

## 4. 非目标与后续轮次

- 不为追求原文阻断率而扩大关键词表、调高全局分数或降低阈值；
- 不把所有 reverse-shell、keygen、anti-detection 或逆向材料粗暴标为恶意；
- 不把本轮二号机诊断重标为独立审计；
- 不在本轮大爆炸重写 classifier/extractor；
- 不在本轮删除历史 corpus 或 v0.16-rc.2 rollback capsule。历史数据先设计
  内容寻址存储与迁移合同，后续单独执行；
- 不恢复自动 Release/RC workflow；
- 不宣称生产 Balanced 已获批准。

## 5. 工作包与验收标准

### RT12-01：任务书、身份与状态词冻结（P0）

交付：本任务书、基线身份、审计报告摘要、范围、非目标、验收、回滚与证据状态词。

验收：任务书先于行为实现提交；后续只追加实际结果，不改写基线历史。

### RT12-02：审计数据库容量硬合同（P1）

实现：

- 在每个有界写批次后检查 SQLite live pages；超过 `MaxBytes` 时立即执行有界
  清理，而不是等待默认一小时 ticker；
- 优先删除最旧 Raw Capture，再删除最旧普通事件；
- 无法恢复到上限时拒绝后续敏感 capture/审计写入并公开 degraded 状态，但不改变
  请求分类决定；
- 状态与统计增加 `current_live_bytes`、`configured_max_bytes`、`over_limit` 和容量
  清理/拒绝计数；
- 容量查询或清理失败必须有低基数错误，不回显路径、请求或 secret。

验收：

- 不显式调用 `Cleanup()`，连续写入事件和最大允许 Raw Capture 后，数据库 live
  pages 不超过“配置上限 + 一个明确计算的有界批次”；
- 写入、重启、WAL、TTL、禁用 capture purge 和 schema 6 迁移回归全过；
- `quick_check=ok`，无 panic、死锁或队列计数漂移；
- 性能回退在现行 SQLite/Raw Capture 门槛内。

回滚：容量门禁实现可按单一提交回退；schema 不升级，不产生不可逆迁移。

### RT12-03：管理边界和 Subject 头冲突（P2）

实现：

- 选择并固定唯一管理合同：request body 1 MiB、RPC envelope 2 MiB；代码、文档、
  Nginx 示例和测试使用字面量合同，不再让测试引用实现常量自证；
- 对大小写不同但语义相同的 `Authorization`/`X-API-Key` map key 做确定性汇总；
- 多个竞争的非空认证值不得由 Go map 遍历顺序决定 Subject；应返回稳定的冲突
  状态，不把请求随机分配到不同 cooldown/manual-block 桶；
- 单请求分类和 before-auth 阻断保持不变。

验收：1 MiB/2 MiB 精确边界正负例、重复头排列与大小写置换、race 和生命周期
fingerprint 回归全过。

### RT12-04：防御性引用误报和原生激活（P1）

实现：

- 为 Codex-X 两份 unrestricted 文本以及 NERV `README.md`、`docs/README.md`、
  `docs/README_CN.md` 建立内容 hash 固定的 paired fixtures；
- 最外层当前用户完整、终止明确的 quoted/defensive owner 优先于内部长载荷重复，
  但第二引用、未闭合引用、跨 scope、后续执行或 proof budget exhaustion 不能获得
  抑制；
- 加入“安装并激活以上 skill”“按上面的默认流程执行”“执行它”等仓库原生指代；
- 将复合激活拆成 credential theft、persistence/C2、ransomware、phishing、exploit、
  exfiltration 和 evasion 单一意图；
- 单独复核 Keysmith `unknown-server-zh` 的未授权目标真值；dual-use 邻近样本保持
  allow/audit 分层。

验收：

- 五个已知防御性语义样本在 Balanced/Strict 均为 complete non-block；
- 对应明确激活在 Balanced/Strict 均为 complete `block_malicious_text`；
- Audit 记录语义类别但不阻断；
- Chat/Responses、batch/stream、system/tool/current-user、front/middle/back parity
  mismatch 为 0；
- normal critical controls 0 block；当前 paired malicious 120/120 保持阻断；
- 不以 incomplete block 计入召回。

### RT12-05：当前 CPA 五仓库诊断工具（P1）

实现：

- 在 `tools/current-cpa-audit/` 固化只读 GitHub 文本采集、隔离 CPA runner、schema
  validator 和测试；
- 语料采集只允许固定 HTTPS GitHub host、allowlisted 文本路径和单 Markdown ZIP；
  拒绝 symlink、LFS pointer、NUL、非 UTF-8、超限 blob、多条 ZIP、路径穿越和
  未知压缩项；
- 每例包含 `expected_action_by_mode`、标签理由、授权/所有权/current-action、
  reviewer、template SHA、source commit/tree/blob/text SHA；
- 分开报告 `unique_semantic_cases`、`unique_content_hashes` 和
  `transport_executions`；传输排列不得放大统计置信度；
- 保存测试前/后仓库 HEAD、时间、ETag/API body SHA；
- 保存 CAG SO、本轮 source commit/tree、CPA binary SHA、image ID/RepoDigest、官方
  asset SHA、runner SHA、配置 hash；
- 每个 block 验证 HTTP 403、协议错误 schema/content-type、Mock/Auth/Provider/
  Usage delta 0、配对审计事件和 request hash；
- 每个 allow 验证 HTTP 200、Mock delta 1、usage 和 stream termination；
- 机器证据包含 `quick_check`、WAL checkpoint、restart/OOM/panic、容器 capability、
  网络/端口、前后业务容器快照和 cleanup 结果；
- 容器先 graceful stop/checkpoint，再按本轮精确 label 删除。

验收：

- schema 正例通过；缺 ground truth、身份、post-head、quick_check、错误响应合同或
  出现额外字段均 fail closed；
- 固定 seed，模式/样本顺序随机化，至少三次冷启动结果一致；
- 第三方代码执行计数恒为 0；基础设施错误为 0。

### RT12-06：CPA v7.2.116 特殊路径与性能（P1）

二号机和/或 Linux Host integration 必须覆盖：

- Audit/Balanced/Strict；Chat、Responses、适用的 Interactions；batch/stream；
- Home OAuth 401 同一逻辑请求最多刷新重试一次，started stream 不重放；
- Alpha Search 两条 alias；
- management missing/wrong key 401；
- malformed、oversize、unknown schema、multipart、opaque media、incomplete；
- interceptor priority、duplicate SO、RPC error、panic fuse；
- Raw Capture enable/query/dedupe/disable/purge、schema 6、restart、WAL checkpoint；
- CPA-only 与 CPA+CAG A/B，c=1/4/8/16，CPU/RSS/队列深度、p50/p95/p99。

最低性能验收：

```text
ordinary_p95_ms <= 10
five_repository_activation_p95_ms <= 250
public_p95_ms <= 150
public_p99_ms <= 300
fixed_workload_p99_regression_percent <= 10
host_throughput_vs_cpa_only >= 0.90
audit_queue_peak_ratio < 0.80
warm_rss_growth_60m_mib <= 64
unexpected_http_or_infra_errors = 0
restart_oom_panic = 0
```

若二号机存在持续高 CPU 干扰，性能只能记为 `DIAGNOSTIC / NOT_BASELINE`，不得
用宽松阈值覆盖或伪造 PASS；功能、安全和副作用门禁仍必须完成。

### RT12-07：文档、许可与 GitHub 治理（P1）

实现：

- 将失联的旧 `v0.15` 标为 `UNAVAILABLE / SUPPORT SUSPENDED`，直到旧仓库或签名
  归档可验证；
- 当前文档记录 exact-main engineering CI PASS 与二号机 diagnostic，继续保留
  independent/protected/production `NOT_PROVIDED`；
- 为当前公开 corpus 的第三方完整字节补齐 copyright、MIT notice、repo/commit/path；
  对无明确许可证来源只保留 hash/元数据和去武器化合成 fixture；
- 增加 Dependabot（GitHub Actions、根 Go module、CPA contract modules）；
- 固定 `Dockerfile.test` 基础镜像 digest；
- development/policy artifacts 明确保留期；
- 开启仓库级 Action SHA enforcement/allowlist，关闭 workflow token 审批 PR；
- 公共仓库的持久 self-hosted runner 在二号机验证完成后注销并停机。后续使用
  私有验证仓库或一次性 runner；
- 单维护者条件下不伪造独立审批。若没有第二维护者，继续披露审批/独立性缺口，
  不设置会锁死仓库的虚假一人审批门禁。

验收：文档链接和 live API 状态一致；active workflow 仍只有三条；Actions/runner/
branch protection API 结果保存；仓库 secrets 和 open security alerts 为 0。

### RT12-08：最终审计、PR 与 main 合并（P0）

流程：

1. 所有实现位于本工作分支；
2. 运行定向测试、完整 Linux CI、Policy Gate、CodeQL；
3. 对最终 candidate commit/tree/SO 在二号机执行 RT12-05/06；
4. 对最终 `main...HEAD` 做只读差异审计，修复可复现 critical/major；
5. 创建 PR，等待五项 required checks 全部成功；
6. 仅当二号机功能、安全、副作用门禁通过且没有未解决 P0/P1 时合并；
7. 合并后验证 `origin/main`、精确 main CI、分支、runner 和工作树状态。

失败条件：

- 任一正常 critical case 被拦；
- 任一明确激活未阻断；
- incomplete 被错误计为 semantic TP；
- Mock/Auth/Provider/Usage 出现阻断后副作用；
- SQLite corruption、容量失控、panic、OOM、restart 或业务容器漂移；
- CPA/runner/corpus 身份不闭合；
- required check 失败或证据 schema 不闭合。

任一失败均停止合并；不得以跳过测试、管理员旁路或修改报告措辞关闭门禁。

## 6. 最终状态定义

- `ENGINEERING PASS`：精确提交五项 GitHub 必需检查成功；
- `SECOND-MACHINE DIAGNOSTIC PASS`：RT12 机器证据闭合、功能/副作用通过，但仍非
  独立证明；
- `INDEPENDENT ATTESTATION`：本轮不提供；
- `PRODUCTION APPROVED`：本轮不提供；
- `RELEASE READY`：本轮不提供。

本轮成功终点是：**源码和审计工具通过门禁并合并到远端 `main`，不发布插件。**
