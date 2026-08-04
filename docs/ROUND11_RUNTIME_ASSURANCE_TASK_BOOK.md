# Cyber-Abuse-Guard Next 第十一轮运行时可信度完善任务书

```text
current_classifier_policy_version: classifier-policy-v11
current_classifier_policy_sha256: f1b4665c751306a1a30c96a58ddb84714541e6e476c66db8ad436480e4c98f55
```

状态：**实现已完成 / 本地与 GitHub 收口中**
工作分支：`codex/round11-runtime-assurance`  
合并目标：`main`  
平台范围：**仅 Linux amd64**  
CPA 固定目标：**CLIProxyAPI v7.2.113**  
发布范围：**源码、测试与审计证据；不创建插件 Release 或 tag**

## 1. 权威基线与任务目标

本轮从以下干净、已通过远端必需检查的基线开始：

```text
repository: yujianwudi/cyber-abuse-guard-next
baseline_commit: aaa71d9924bef935196790976c838968408dcdeb
baseline_branch: main
cpa_version: v7.2.113
cpa_commit: bc71c77f5cc42f3fbe1bf040cf14d4f166894835
cpa_module_sum: h1:Aj3J7zI5VxyKpsHbG6+ChVpeW4QGkcJ+ZwWWnWmuChA=
go_toolchain: go1.26.4
platform: linux/amd64
```

基线提交的 GitHub CI、CodeQL、Policy and Corpus Gate 均为成功；这些结果只证明
`aaa71d9`，不能自动重标为本轮最终提交的证据。

本轮不重新调高风险分数、不降低阻断阈值，也不通过扩大关键词表来掩盖检测缺口。
目标是补齐“真实候选 `.so`、CPA Host 管理链、审计载体和证据身份”之间的可信闭环，
同时保留正常请求零误伤和已有性能门禁。

## 2. 审计发现与优先级

### P0-1：Raw Capture Host 合同仍断言旧 schema

证据：

- `internal/plugin/management.go` 的实际响应合同为
  `raw_capture_response_schema_version = 4`；
- `internal/plugin/raw_capture_management_test.go` 已验证 schema 4；
- `integration/cpalatestcontract/raw_capture_management_host_contract_test.go`
  的 CPA Host 覆盖层仍构造并断言 schema 2；
- 该覆盖层使用管理插件 test double，不能单独证明候选 `.so` 返回的真实 schema 4
  响应经过 CPA v7.2.113 Host 后仍满足认证、8 MiB 和字段语义。

风险：上游 Host HTML 转义或响应大小行为发生漂移时，旧覆盖层仍可能绿色；当前 CI
也可能在真实插件 schema 4 管理链缺失的情况下给出过强的兼容性印象。

### P0-2：Host evidence CLI 可接受无执行身份的 schema 1

证据：

- `scripts/round9_host_evidence.py` 的离线 `assemble` 路径在没有 execution binding
  时生成 `schema_version = 1`；
- `validate_final_evidence` 会根据输入版本选择性跳过 execution binding；
- CLI 对该路径仍打印 `PASS`；
- 正式 `round9_host_evidence_contract.py` 已要求 probe schema 2，形成两个入口的
  信任强度不一致。

风险：本地拼装结果可能被误读为 GitHub attested Host evidence，缺少 workflow、
runner、sandbox、challenge 和 Phase 1 artifact 身份绑定。

### P1-1：当前 Linux Host `.so` 黑盒未覆盖 Raw Capture 完整生命周期

现有 `TestCPAPluginHostBlocksBeforeUpstream` 会加载真实 Linux `.so` 并验证阻断、
Provider/Usage 隔离与管理状态，但没有在同一 Host 进程中机械验证：

- 默认关闭和启用后的 only-blocked 语义；
- Management Key 认证；
- schema 4、Base64 规范字段和 `Cache-Control: no-store`；
- 合成 secret 的脱敏及不回显；
- 相同阻断请求的 TTL 预览去重；
- live reconfigure disable 后的 preview purge；
- SQLite schema 6、`quick_check=ok` 与 WAL checkpoint。

### P1-2：活动文档仍把已删除 workflow 写成可执行入口

`.github/workflows/` 当前仅允许 `ci.yml`、`codeql.yml` 和 `policy-gate.yml`，但
`docs/ROUND9_HOST_RUNNER.md` 仍以现在时描述已经删除的
`.github/workflows/round9-host-validation.yml` 与 `round9-release-rc.yml`。
详细设计可以作为历史审计记录保留，但不得被当前文档索引表达成可运行门禁。

### P2-1：正常用户与性能只需防回退，不在无证据时改策略

当前可见开发语料门禁记录 1,200 个正常语义样本、7,200 条序列化路由零阻断，
Round 10 也已有 system/tool/assistant 历史载体、request-local authority、长文本和
并发性能覆盖。本轮若没有可复现的新误报，不改 classifier 分数或 eligibility；只把
这些既有门禁纳入最终回归，避免运行时/审计改动造成间接回退。

## 3. 安全不变量

1. 第三方破限仓库、归档和文本只作为惰性防御样本；不执行其代码、安装器、hook、
   二进制或依赖。
2. 正常请求、引用、翻译、防御审计、历史 assistant/tool 内容，不因出现高风险词汇
   单独被阻断。
3. 只有完整且有资格的恶意语义 winner 可以形成 `block_malicious_text`；coverage
   failure 不得伪造恶意类别。
4. Raw Capture 默认关闭；开启时仅保存最终阻止上游的请求、强制脱敏、大小有界、
   TTL 有界，并只通过 CPA 已认证管理接口读取。
5. 测试只使用合成 request、临时数据库、loopback 和 counted/mock provider；不得
   接触真实 Provider、生产账号、生产数据库或客户原文。
6. 所有“PASS”必须绑定实际执行入口和候选身份。缺失、跳过、环境不满足或只做静态
   审查时分别记录为 `FAIL`、`NOT RUN`、`BLOCKED` 或 `STATIC ONLY`。
7. 只验证 Linux amd64；不增加 Windows/macOS 运行矩阵。
8. 不创建 GitHub Release、tag 或插件发行资产。

## 4. 非目标

- 不升级或改变 CPA v7.2.113 固定身份；
- 不部署二号机、生产 CPA 或真实用户流量；
- 不重新执行或重标历史独立语料、Holdout、evaluation-v10；
- 不扩大公开恶意 payload 内容或把客户原文写入测试；
- 不进行无基线支撑的 classifier 调参；
- 不恢复已经删除的 release、RC 或 self-hosted Host workflow；
- 不绕过 `main` 分支保护直接强推。

## 5. 工作包

### RT11-01：冻结任务书和审计边界（P0）

交付：

- 本任务书；
- 基线 commit、CPA、Go、平台和 classifier 身份；
- P0/P1/P2、非目标、验收、回滚和证据状态词。

验收：任务书先于实现提交；后续实现记录只追加实际完成状态，不改写基线事实。

### RT11-02：Host evidence schema 2 单入口（P0）

实现：

- 正式 Host evidence 只允许 schema 2；
- `execution` 必须存在并通过 closed-key validation；
- 删除或封闭会生成 schema 1 最终证据的 CLI `assemble` 入口；
- `run` 保持 Linux、显式 `--execute`、workflow/challenge/runner/sandbox/Phase 1
  artifact 绑定；
- schema 1、缺失 execution、额外字段、错误 ref/SHA、错误 artifact digest 必须失败；
- Round 8 历史实现保持只读，不被重标为 Round 11 结果。

验收：

- `scripts/round9-host-evidence-test.py` 全过；
- 新增负例证明 schema 1 无法通过 final validator；
- parser 不再公开无身份拼装命令；
- 输出文案不能把 unattested 开发结果称为 Host PASS。

### RT11-03：CPA v7.2.113 Raw Capture schema 4 源合同（P0）

实现：

- CPA Host overlay 改为完整 schema 4 最小响应；
- 固定并断言 audit schema 6、decision/explanation semantics、canonical Base64、
  compatibility aliases、redaction metadata、`no-store` 和 8 MiB Host-visible budget；
- 保留单个最大 preview 可容纳、两个最大 preview 必须由插件层截断的边界证明；
- 文档明确该 overlay 是上游 Host transport source contract，不冒充真实 `.so`
  runtime evidence。

验收：`integration/cpalatestcontract` 的目标测试在 CPA 固定 module identity 下通过。

### RT11-04：真实 Linux `.so` Raw Capture Host 黑盒（P1）

在现有网络隔离的 CPA Host integration 中增加：

1. 启动配置使用临时持久目录并显式开启 only-blocked Raw Capture；
2. 未认证、错误 Management Key 和客户端 API key 查询均为 401；
3. 正常请求不生成 capture；
4. 含合成 secret 的恶意请求在 Provider、Usage、Mock upstream 前 403；
5. 认证查询返回 schema 4、audit schema 6、`no-store`、规范 Base64；
6. 完整 management HTTP body、schema 4 字段与兼容别名、decision/explanation、
   redaction metadata、持久化 capture 行和配对 audit 行均不包含合成 secret；preview
   已脱敏；
7. 相同请求重复阻断时 audit 事件保留、preview 在 TTL 内去重；
8. live reconfigure 关闭 capture 后，管理页为 disabled/empty；直接查询临时
   `events.db` 证明 preview 行为 0，而本轮两个 block audit 事件仍保留；
9. 临时 `events.db` 执行 `PRAGMA quick_check` 为 `ok`，schema 为 6，并在 CPA 仍持有
   数据库时以非独占方式确认 WAL journal 可读；
10. 全程 upstream/provider/usage 计数保持现有不变量。

验收：`make integration-test` 在 Linux amd64 加载本轮候选 `.so` 并通过；测试退出后
无残留 CPA 进程、监听器或临时审计载体。

### RT11-05：活动 workflow 与文档真实性（P1）

实现：

- 把 Round 9 Host runner 文档明确标为历史、不可执行设计；
- 文档索引不再把已删除 workflow 表达成当前操作入口；
- release document consistency gate 增加机械断言：当前仓库只有三份允许的 workflow，
  已删除 Host/RC workflow 只能出现在显式历史语境；
- README、README_CN、workflow index、repository governance 保持同一事实边界。

验收：正例通过；把历史标记改回“当前可执行”或加入未审 workflow 的 fixture 必须失败。

### RT11-06：零误伤与性能防回退（P2）

不改变 classifier policy identity，除非发现并修复真实分类语义变更。必须重新运行：

- 1,200 semantic / 7,200 route 正常开发语料，阻断数为 0；
- 120 semantic / 960 route paired malicious 开发语料，语义阻断为 120；
- system/tool/assistant historical 与 request-local authority 定向回归；
- Round 10 bounded concurrency performance；
- Raw Capture preparation、queue 和 management response 性能验收；
- race、fuzz smoke 和 fixed policy identity gate。

本轮运行结果只绑定最终候选 commit。历史性能数字保持原始 commit 标识。

### RT11-07：本地 CodeRabbit、GitHub PR 与合并（P1）

流程：

1. 在功能分支完成实现和 Linux 验证；
2. 先运行本地 CodeRabbit 对 `main...HEAD` 差异审查；
3. 若本地 CodeRabbit 失败或不可用，记录精确原因并使用 GitHub PR 的 CodeRabbit；
4. 修复所有可复现的 critical/major 问题；
5. 推送 `codex/round11-runtime-assurance`，创建非 draft PR 到 `main`；
6. 等待 `quality-and-artifacts`、`fuzz-long`、`reproducibility`、
   `Analyze Go on Linux`、`round9-policy-and-corpus` 全绿；
7. 解决全部未过期 review conversation，再通过受保护 PR 合并；
8. 确认 `origin/main` 指向合并提交、本地 `main` 同步且工作树干净。

不得使用 force push 覆盖 `main`，不得用管理员直推替代 PR 检查。

## 6. Linux 验收矩阵

| 范围 | 必需结果 |
|---|---|
| 格式/差异 | `gofmt`、`git diff --check` 通过 |
| 模块 | root、cpalatestcontract、pluginstorecontract、round9countedmock 均 `mod verify` / `tidy -diff` |
| 单元 | root safe unit suite 通过 |
| 竞态 | Go race suite 通过 |
| Host evidence | schema 2 only；schema 1/无 execution 负例失败 |
| CPA source | v7.2.113 exact tag/commit/module sum/source/API/SDK contract 通过 |
| CPA Host | 真实候选 `.so` 加载、注册、阻断、Raw Capture schema 4 生命周期通过 |
| 审计存储 | schema 6、`quick_check=ok`、WAL journal 可读、disable purge 通过 |
| 正常语料 | 1,200 semantic 与 7,200 routes 零阻断 |
| 恶意开发语料 | 120 semantic 与 960 routes 全通过固定预期 |
| 性能 | Round 10 与 Raw Capture 固定门限不回退 |
| 安全扫描 | repository secret scan、govulncheck、CodeQL 通过 |
| GitHub | 所有 required checks 绑定 PR head 并成功 |

本机缺失可信 module `Origin`、网络中断、Go proxy 漂移或 CPU 资源不足时，不把未完成的
本地项目写为 PASS；由 GitHub Linux lane 重新验证，并保留本地失败原因。

## 7. 回滚与证据规则

- 实现只在功能分支进行；合并前可安全放弃分支，不改 `main` 历史。
- 合并后如需回滚，使用新的 revert PR；不移动 tag、不改历史 Release、不 force push。
- Raw Capture schema 4 和 audit schema 6 均为已存在的数据合同；本轮不得降级数据库或
  删除迁移备份。
- 测试数据库只位于测试临时目录；清理仅删除本轮创建的临时文件。
- `aaa71d9` 的绿色检查、本轮本地检查、PR 检查和最终 main 检查分别记录，互不替代。
- CodeRabbit 是开发审查，不替代独立服务器沙盒审计或生产批准。

## 8. 实施记录

| 工作包 | 状态 | 证据 |
|---|---|---|
| RT11-01 | DONE | 本任务书已创建于功能分支 |
| RT11-02 | LOCAL PASSED / FINAL PENDING | final validator 仅接受 schema 2 与完整 `execution` binding，且 binding execution ID 必须匹配 runner lane；公开 `assemble` CLI 已删除；本地 validate/run 输出不再声称 Host PASS 或已完成 attestation，最终接受仍绑定 PR head 与外部证明 |
| RT11-03 | LOCAL PASSED / FINAL PENDING | CPA v7.2.113 Raw Capture source overlay 已升级到 schema 4 / audit schema 6，并使用 CPA `htmlsanitize.JSONBody` 校验字段语义、Base64 与 8 MiB Host 可见预算；最终接受仍绑定 PR head 与必需检查 |
| RT11-04 | PRE-REVIEW LOCAL PASSED / POST-REVIEW INTERRUPTED / FINAL PENDING | 审查前 Linux amd64 真实候选 `.so` 完成完整生命周期；CodeRabbit 修复后重跑在完整矩阵中途被 WSL 终止，未产生终态，不能继承为当前 PASS。最终接受绑定 PR head 的 `quality-and-artifacts` Host 黑盒 |
| RT11-05 | LOCAL PASSED / FINAL PENDING | 已删除 workflow 的文档被明确降为历史不可执行设计；当前工作流限为三项；历史链接必须位于历史段，正例与降级/错位负例均通过；最终接受仍绑定 PR head 与必需检查 |
| RT11-06 | LOCAL PARTIAL PASS / FINAL PENDING | 完整正常 runner 为 0/1,200 semantic、0/7,200 routes；paired runner 为 120/120 semantic blocks、960/960 routes，均无 failure，Raw Capture 与 Round 10 性能门限通过。精确最终工作树的完整 core/race/fuzz 未取得终态，由 PR 必需检查完成最终接受 |
| RT11-07 | LOCAL REVIEW FIXES APPLIED / GITHUB PENDING | 本地 CodeRabbit 共返回 7、2、2 项 issues，均已验证并修复；后续清零复审受本地额度限制，转由 GitHub PR CodeRabbit、五项必需检查及受保护合并完成；不创建 Release/tag |

### 当前本地证据边界

- `aaa71d9924bef935196790976c838968408dcdeb` 是本轮起始 `main` 基线；其 CI
  `30697468074`、CodeQL `30697468078`、Policy and Corpus Gate
  `30697468079` 成功，但不替代本轮候选检查。
- 审查前工作树的真实 CPA v7.2.113 `.so` Host Raw Capture 生命周期通过；CodeRabbit
  修复后的精确工作树重跑在完整 Host 矩阵中途被 WSL 终止且没有终态文件，因此当前
  只记 **INTERRUPTED / NOT PASS**，由 PR head 的 `quality-and-artifacts` 重跑。
- 当前工作树的 Host evidence 57 项合同、文档一致性正/负例、repository secret scan
  与 Bash 语法通过。此前相关 Python 合同、integration Linux compile、`govulncheck`
  （可达漏洞 0）与补充 actionlint v1.7.7 结果均早于最后一轮审查修复，不冒充最终
  PR-head 结果。
- 固定 Go 1.26.4、Linux amd64、离线 module 模式下，完整正常开发 runner 实测
  1,200 semantic / 7,200 routes 且阻断均为 0；完整 paired-malicious runner 实测
  120/120 semantic blocks、960/960 routes、failure 为 0。两份临时机器报告分别为
  2,516 bytes / SHA-256 `18198d0009dc6267170edac68c6465f64080666586ab4577819a211ec7517abb`
  与 7,151 bytes / SHA-256
  `b54578f24300d3b0e8ba27b333e334b27c52fd71e42eb1cc81ea0974bdd0e82c`；它们是本地
  dirty-worktree 开发证据，不是独立语料或发布证明。
- 完整 `scripts/cpa-latest-compat.sh` 本地为 **BLOCKED**：固定 CPA module 的可信
  `Origin` 不在 warm cache，且 WSL 在 60 秒内无法从 Go proxy/GitHub 刷新。没有降低
  `Origin` 校验；该项必须由 GitHub Linux lane 重新执行。
- 固定 actionlint v1.7.12 与 ShellCheck 本地未完成，分别记为 **NOT RUN**；由 GitHub
  Linux CI 执行。补充的 actionlint v1.7.7 结果不冒充固定版本门禁。
- 本地 CodeRabbit 三轮有效审查依次返回 7、2、2 项 issues，均已机械修复并运行相关
  回归；后续清零复审被服务以 `rate_limit` 拒绝，并提示约 17 分钟等待或需分配
  seat/API key。因此不声称本地 0 issues，继续使用 GitHub PR 侧 CodeRabbit。
- 本地测试只使用临时数据、loopback 与 counted/mock provider；未连接二号机、真实
  Provider 或生产环境，也未执行第三方破限仓库代码。
