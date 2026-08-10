# Cyber-Abuse-Guard Next 第十三轮 CPA v7.2.125 与 v1.0.0-rc.1 任务书

## Supplemental archive 状态分层

Supplemental Codex archive 的源码合同在显式输入、policy、schema、validator、
negative tests、固定分母和 Safe Gate pins 全部落地后，可标记为
`IMPLEMENTED / CLOSED`。真实二号机 supplemental runtime audit 是独立门禁；
在精确候选执行成功前必须保持 `NOT_RUN / NO_PASS_CLAIM`。本任务书后文若仅写
`NOT_RUN`，均指 runtime audit，不否定已经闭合的源码合同。

状态：**已批准实施 / 验收未完成 / 禁止提前合并或发布**
工作分支：`agent/cpa-v7.2.125-v1-rc1`
合并目标：`main`
平台范围：**仅 Linux amd64**
CPA 固定目标：**CLIProxyAPI v7.2.125**
候选发行：**`v1.0.0-rc.1` GitHub prerelease，`latest=false`**

## 1. 权威身份

```text
repository: yujianwudi/cyber-abuse-guard-next
baseline_main_commit: 11199dde1da5741ecec009be17b8a55294e39421
baseline_main_tree: resolve_at_gate_time

cpa_module_path: github.com/router-for-me/CLIProxyAPI/v7
cpa_version: v7.2.125
cpa_commit: 2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e
cpa_module_sum: h1:jz3yxTI7mp+ej2kI1T4OPs+QhIgP6Mmu5BGvipjQWRg=
cpa_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
cpa_plugin_abi: 1
cpa_rpc_schema: 2

cpa_linux_amd64_asset: CLIProxyAPI_7.2.125_linux_amd64.tar.gz
cpa_linux_amd64_asset_bytes: 20853030
cpa_linux_amd64_asset_sha256: 4e940b7dc5bdf867b5c58ca30f1b368fae6dc2e041e8a351d5c2c07f3f610233
cpa_checksums_sha256: fde093eb31bb4b8896d26e354c14ea9960bc3d0f3168f83766f2990b282aaeb2
cpa_linux_binary_sha256: 656cde7bfd966dbcaaa9d9260dd1de75716c0b9dead66d91ceb2d8d55f6d623a
cpa_linux_binary_reported_identity: 7.2.125 / 2e6b1d83 / 2026-08-08T21:13:51Z

source_version: 1.0.0
rc_artifact_version: 1.0.0-rc.1
rc_tag: v1.0.0-rc.1
```

任何 CPA v7.2.124 或更早版本的 CI、二号机、五仓、性能或 Host
结果都只能保留为历史证据，不得重标为 v7.2.125 结果。开发分支、PR
merge ref、最终 `main` 和 tag 的 commit/tree/SO 必须分别闭合身份链。

## 2. 本轮目标

1. 把全部活动 CPA 合同从 v7.2.124 升级到 v7.2.125，同时保留 ABI 1、RPC schema 2 的显式断言。
2. 验证 v7.2.125 的 no-copy/in-place 大载荷路径不会改变 CAG 已检查的请求载体、审计载体或请求生命周期指纹。
3. 补齐官方 Codex Responses 流式 `response.failed` 行为，并证明 CAG 前置拦截不会产生 Provider、Auth、Executor、Usage 或 SSE 副作用。
4. 修复热重配的事务边界：失败重配不得暗改现行 Subject 状态、请求缓存或候选 SQLite。
5. 继续以正常用户零误伤优先：不得因安全审查、引用、翻译、防御性说明、授权测试或工具 schema 中出现高风险词汇而屏蔽请求。
6. 完成 Linux CI、CodeRabbit，以及 PR synthetic merge artifact 的五仓与
   `Codex全破` 二号机 pre-merge 隔离诊断；只有全部适用门禁闭合后才由 PR
   作者通过受保护 squash merge 合并 `main`，该阶段禁止 portable `pack`。
7. 等待精确合并后 `main` `push` 的五项 required checks，下载新的唯一九文件
   artifact，以新 `RUN_ID` 全量重跑同一二号机矩阵，再从该 post-main
   release-admitted candidate 原样封装、验证并发布 `v1.0.0-rc.1` 预发行版；
   发布阶段不得重新编译已审计 SO。

## 3. 上游 v7.2.125 变化边界

v7.2.124 到 v7.2.125 共七个上游提交，必须覆盖以下高风险面：

- `internal/util/gjson.go` 与 `internal/util/nocopy_invariant_test.go`：GJSON 结果可直接引用输入字节；引用存活期间不得写入底层载体。
- `internal/translator/antigravity/gemini/*`：大载荷减少整包复制，并增加可失败的 payload-reuse 守卫。
- `internal/client/codex/optimize-multi-agent-v2/optimize_multi_agent_v2.go`：公开官方 Codex 客户端识别函数。
- `sdk/api/handlers/openai_responses_stream_error.go` 和 Responses handler：官方 Codex 客户端的终止流事件改为 `response.failed`。
- `sdk/cliproxy/session/identity.go`：会话身份变化必须通过上游测试，但不得被误述为 CAG 自有能力。
- Claude thinking replay 新增逻辑属于 Host 回归范围；CAG 不修改、接管或宣称该能力。

## 4. 安全不变量

1. 第三方破限仓库和 ZIP 仅作为惰性文本数据读取；禁止执行其中的脚本、二进制、Java/Gradle、hook、MCP 配置、安装器或依赖。
2. 测试只连接隔离 counted Mock；不得联系真实 Provider、生产账户池、生产数据库或真实客户请求。
3. `Audit` 只记录不拦截；`Balanced` 和 `Strict` 分开验收。Strict 的 incomplete fail-close 不计入语义召回。
4. 正常、防御、授权、翻译、引用、拒绝执行与审计请求不得因词汇密度单独被屏蔽。
5. 只有完整有害核心、当前执行动作、明确未授权作用域共同成立时，才计入 `block_malicious_text` 真阳性。
6. Raw Capture 默认关闭；开启后仍必须 block-only、脱敏、截断、TTL/容量有界，并仅能通过 CPA 已认证管理面读取。
7. 热重配必须是可观察的全有或全无操作；被拒重配不能改变现行策略、Subject 条目/计数、请求生命周期缓存或磁盘 schema/内容。
8. CAG 在拦截返回前完成检查；后续 Host no-copy/in-place 修改不得回写或污染 CAG 保存的载体。
9. 所有 block 必须证明 Mock/Auth/Provider/Executor/Usage/SSE delta 为零；所有 allow 必须证明唯一一次预期 Mock 调用和正确流终止。
10. 不绕过分支保护、required checks、签名或对话解决要求。

## 5. 非目标

- 不增加 Windows 或 macOS 测试、构建或发布资产。
- 不执行、安装或重新分发第三方破限仓库代码。
- 不把安全产品讨论、逆向分析、恶意样本引用或授权红队文本粗暴标为恶意。
- 不删除历史 v0.16/RC、Round 6 至 Round 12、旧 CPA 或 rollback capsule 证据。
- 不将二号机所有者运行结果包装为独立第三方证明。
- 不接触二号机业务容器、业务配置、业务凭据、业务日志正文或真实上游。
- 不创建稳定版 `v1.0.0`；本轮仅允许 `v1.0.0-rc.1` prerelease。

## 6. 工作包与验收标准

### R13-01：任务书、身份与状态冻结（P0）

交付：本任务书、`ROUND13_STATUS.md`、CPA 官方资产与 Go 模块身份记录。

验收：

- 任务书先于本轮源码修复创建；
- tag、commit、module sum、GoMod sum、资产 SHA、内含二进制 SHA、自报版本全部一致；
- 文档明确区分 v7.2.124 历史结果与 v7.2.125 待执行结果。

### R13-02：CPA v7.2.125 源码/API/ABI/RPC 兼容（P0）

活动文件至少包括：

- 根 `go.mod`/`go.sum`；
- `integration/cpalatestcontract` 与 `integration/pluginstorecontract`；
- `scripts/cpa-latest-compat.sh`、健康门、当前 CPA 审计 harness/schema；
- CI、README、当前状态与集成报告。

验收：

- 三个活动 Go module 都精确固定 `github.com/router-for-me/CLIProxyAPI/v7 v7.2.125`；
- 本地 module cache 的 Origin 必须是 tag `v7.2.125` 和提交 `2e6b1d83…`；
- ABI 1、schema 2、plugin store 安装、注册、reconfigure、shutdown、Host fail-open/fail-closed 合同全部通过；
- 上游 pluginhost、Responses handler、Multi-Agent v2、no-copy invariant 与大载荷测试按显式名称存在并执行；
- `CPA_COMPAT_REQUIRE_LATEST=1` 时远端最新正式 tag 必须仍为 v7.2.125，否则 fail closed。

### R13-03：no-copy 载体所有权与 Responses 流错误（P0）

实现和测试要求：

- 证明 CAG 解码的 request body、fingerprint、审计摘要和 block-only raw capture 不引用可被 Host 后续原地修改的字节；
- 使用大载荷、容量复用、同底层数组改写和并发回归验证，无 data race、无载体串请求污染；
- Multi-Agent v2 的工具描述仍是 inert schema，当前用户文本仍是唯一语义动作来源；
- allowed 官方 Codex HTTP/SSE 在上游失败时输出合法 `response.failed`；非 Codex 保持上游 legacy error 合同；
- CAG 前置 block 返回 HTTP 403，不能先发送 SSE header/data，也不能增加 Auth、Provider、Executor、Usage 或 counted-Mock 计数。

### R13-04：热重配事务化（P0）

已确认问题：

- 当前实现会先原地 `Subject.Reconfigure`，后执行可能失败的 raw-capture drain/purge；后续失败会保留旧 runtime 指针，却已改变旧 Subject 参数或驱逐条目。
- 当前实现可能先打开/迁移候选 SQLite，之后才因 Subject 可保留性拒绝配置。
- 成功重配未清空 request-lifecycle cache，after-auth 可能把旧策略下的 before-auth 结果当作新策略命中。

修复合同：

- Subject 迁移使用独立候选或等价的 prepare/commit，不得原地修改当前 controller；
- 在任何候选数据库可见副作用之前完成全部会拒绝配置的纯内存预检；
- 失败路径关闭候选资源并保持旧 runtime、Subject 快照/计数、request cache 和数据库前后镜像不变；
- 成功 swap 同时清理 pending、request-lifecycle 和 startup privacy challenge cache；
- in-flight 请求要么完整使用旧 generation，要么在 after-auth 重新按新 generation 检查，不能绕过新策略；
- 测试注入 subject capacity、audit open、flush、purge、migration、close 失败，并运行 race。

### R13-05：正常用户零误伤与恶意召回（P1）

补充确认的分片边界要求：同一可信当前用户逻辑消息内的危险词不得通过词内换行、
同 FieldID 流式 chunk 或相邻 provider 自然语言 content block 拆分绕过；重建必须受
片段数、总 rune、单片段长度、字符脚本、scope、role、turn、provenance 和累计重放工作
上界约束，不得跨独立消息、角色、作用域、来源或标点句拼接。拆分与未拆分请求的
action/category/eligibility 必须一致，并保留正常相邻块零误拦负例。

开发门禁：

```text
development_benign_unique_semantic_samples >= 1200
development_benign_blocked_semantic_samples = 0
development_benign_blocked_route_executions = 0
paired_malicious_unique_semantic_samples >= 120
paired_malicious_balanced_semantic_recall = 100%
paired_malicious_strict_semantic_recall = 100%
chat_responses_stream_batch_carrier_parity_mismatch = 0
```

二号机两阶段候选门禁；pre-merge synthetic merge 完整诊断和 post-main
release admission 必须分别从各自 artifact 全量满足，结果不可转移：

```text
normal_defensive_authorized_semantic_false_positives = 0
five_repository_expected_malicious_balanced_blocks = 100%
five_repository_expected_malicious_strict_blocks = 100%
audit_mode_malicious_blocks = 0
audit_mode_malicious_detections = 100%
incomplete_counted_as_semantic_true_positive = 0
unexpected_http_or_infrastructure_errors = 0
third_party_code_executions = 0
```

固定五仓：

1. `Jia-Ethan/codex-keysmith`
2. `yynxxxxx/Codex-5.5-codex-instruct-5.5`
3. `yynxxxxx/Codex-X`
4. `MDX-Tom/gpt-5.6-instruct`
5. `lingbol088-spec/5.6-JAILBREAK-NERV-codex-instruct-5.6`

补充 ZIP：`Codex全破.zip`，输入 SHA-256
`23000a55f3922c9c2daf04e27d4bdf49d5f95109dd76ba25fa0b3f834c67ed1c`。
该 ZIP 必须经显式 `--supplemental-archive` 输入；source hash、case count、
误报分母、恶意召回分母、结果和清理状态均须单独报告，不能混入五仓召回
分母。该参数不能因 draft code 出现就视为准入；在 parser/schema/validator/
negative tests/pins 一起正式落地并完成真实运行前，只能标记 `NOT_RUN`，不得
声称 PASS。

### R13-06：性能与资源（P1）

Linux 固定工作负载验收：

```text
ordinary_plugin_overhead_p95_ms <= 10
five_repository_activation_p95_ms <= 250
public_adversarial_p95_ms <= 150
public_adversarial_p99_ms <= 300
fixed_workload_p99_regression_percent <= 10
host_throughput_vs_cpa_only >= 0.90
audit_queue_peak_ratio < 0.80
warm_rss_growth_60m_mib <= 64
large_payload_full_copy_regression = 0
restart_oom_panic = 0
unexpected_http_or_infrastructure_errors = 0
```

`ordinary_plugin_overhead_p95_ms` 必须来自同一 workload、concurrency、
repetition 的 CPA-only/CPA+CAG 配对原始数据。当前 Host lane 是配对时间窗而非
逐请求同步配对，因此保守定义为每个 concurrency 的
`max(0, CPA+CAG aggregate p95 - CPA-only aggregate p50)`，最终取四个
concurrency 的最大值；禁止把 CPA+CAG 绝对 p95 改名冒充插件 overhead。

`large_payload_full_copy_regression` 的可证测量边界收紧为 Host process RSS
resident-amplification proxy：每臂、每 repetition 固定 4 MiB canonical wire
payload、16 requests、c=4，记录请求前 5 个 VmRSS 样本和请求期间 20 ms VmRSS
序列。若 CPA+CAG 相对自身 baseline 的 peak RSS growth 比 CPA-only 对应值多出
至少一个完整 payload，则该 repetition 计 1，所有 repetition 求和必须为 0。
该值不是 allocator trace，也不是精确 copy/allocation 次数；报告不得作此声称。
每个 RSS 观察必须同时绑定 Docker init PID、`/proc/<pid>/stat` starttime、单调
elapsed marker 和三位毫秒 UTC `observed_at`；wall/elapsed 误差最多 5 ms，非 final
间隔至少 10 ms、任何间隔最多 30 ms，并覆盖 baseline 与 request 两端。原始成功
latency 的 `sum / concurrency` 及最大 latency 必须能装入 request wall interval。
缺任一 arm、payload/请求数漂移、稀疏 RSS、PID/starttime 漂移、时间戳形状漂移、
不可能的 latency work 或派生值不守恒均 fail closed。

Host A/B 还必须输出 closed、无明文 Host path 的结构化 bind projection。common bind
要求完整投影相同；arm-specific config/runtime bind 至少要求 destination/access shape、
filesystem type、device/`st_dev`、mount source/root/options hashes 及 critical flags
等价，禁止以 ext4 对 NFS/FUSE。两臂本地 source/resolved hash、inode 和 file content
可以不同；plugin bind 继续单独要求 CPA-only 缺席、CPA+CAG 唯一只读。最终 evidence
必须同时发布完整 common/per-arm projection 及可重算 hash，缺字段、额外字段或伪造
hash 均 fail closed。

若二号机存在不可控 CPU/网络干扰，性能结论只能标记
`DIAGNOSTIC / NOT_BASELINE`，不得放宽阈值伪造 PASS；功能、安全、副作用与
误报门禁仍必须通过。

### R13-07：v1.0.0-rc.1 版本与发行合同（P0）

活动发行身份统一为：

```text
buildinfo source version: 1.0.0
Makefile default VERSION: 1.0.0
RC tag: v1.0.0-rc.1
artifact version: 1.0.0-rc.1
```

要求：

- 发布公共函数从旧“两段版本”迁移到严格三段 SemVer，不改变历史 v0.16 fixture；
- CI audit candidate 的二进制/Store ZIP/metadata/ruleset/SBOM 使用 `1.0.0`；
  RC 原样复用这些文件和 `cyber-abuse-guard-v1.0.0.so`，候选 checksum 以
  `audit-candidate-checksums.txt` 保留，不得生成或改名 standalone
  `cyber-abuse-guard-v1.0.0-rc.1.so`。为满足 CPA v7.2.125 Store 精确选择，
  仅从审计 SO 字节确定性派生 `cyber-abuse-guard_1.0.0-rc.1_linux_amd64.zip`，
  内部恰好一个根 `cyber-abuse-guard.so`，并生成 CPA-facing `checksums.txt`；
- RC tag 必须指向精确合并后 `main`，且由真实、获授权、持有对应私钥的
  signer 创建为 GitHub 可验证的 signed annotated tag；unsigned annotated
  tag、lightweight tag、Release 自动代建 tag 或冒充维护者身份的签名均不准入；
- Linux `.so`、Store ZIP、源码归档、checksums、build metadata、ruleset manifest、SBOM、审计摘要和 provenance/attestation 都绑定同一 commit/tree；发布
  provenance 还必须绑定 CI artifact ID/digest/size 和二号机 staging
  Release/asset ID/digest/size；
- PR `pull_request` artifact 只用于 pre-merge synthetic-merge 完整诊断，禁止
  `pack`、禁止 staging Release、禁止作为 release admission；
- squash merge 会产生新的 `main` commit；`.so` 嵌入 commit，因此即使 tree
  不变，commit、SO bytes、hash 和 artifact identity 也会改变。必须等待精确
  `main` `push` 的五项 required checks，再下载该 push run 的九文件 artifact，
  使用新的 `RUN_ID` 和 evidence root 全量重跑；任何 PR 阶段 SO、报告或 PASS
  均不可转移；
- CI reproducibility lane 分别证明其精确候选可复现；RC seal job 只下载并复核
  通过 post-main 二号机 release admission 的同一九文件 `push`/`main` artifact，
  原样发布，不进行第三次构建；
- Release 必须 `prerelease=true`、`make_latest=false`，不存在同名旧 Release/tag；
- Release 说明明确“候选版、二号机所有者审计、非独立证明、非稳定生产批准”。

### R13-08：Linux、CodeRabbit、GitHub 与二号机门禁（P0）

顺序：

1. 定向单测和完整 Linux unit/race/vet/fuzz/script/corpus/compat/reproducibility；
2. 完成实现后运行本地 CodeRabbit `--base main`，修复有效 critical/major/minor 并复审到 0 issues；
3. 创建签名候选提交和 PR；
4. 等待 PR head 的五个 required contexts 全绿：`quality-and-artifacts`、
   `fuzz-long`、`reproducibility`、`Analyze Go on Linux`、
   `round9-policy-and-corpus`；
5. 下载精确 PR synthetic merge artifact，把九个候选文件直接放在
   `/srv/artifacts/candidate`，把官方 CPA v7.2.125 tar 只放在
   `/srv/artifacts/upstream`，并以新的语义 `RUN_ID` 使用
   `/srv/cag-audit/evidence-$RUN_ID`；manifest 必须分别闭合 PR head 与
   synthetic merge commit/tree；
6. 在二号机使用官方 CPA v7.2.125 和 isolated counted Mock 完成 pre-merge
   五仓、内建 ZIP、特殊路径、功能、安全、副作用、性能和清理诊断。该阶段
   即使全通过也只允许记录 `PREMERGE_DIAGNOSTIC_PASS`，禁止执行 portable
   `pack`，禁止 staging/tag/release；
7. 独立提供的 Codex 全破 ZIP 必须通过显式 `--supplemental-archive` 输入，
   其 source hash、case count、误报分母、恶意召回分母、结果和清理状态必须
   与固定五仓 11-source/19-case 分母分开。在参数及闭合 schema/validator/
   negative tests/pins 正式落地并完成真实运行前，当前状态只能是 `NOT_RUN`，
   不得把五仓或内建单 ZIP 结果重标为该 supplemental archive 的 PASS；本轮
   若把该独立 ZIP 列为准入输入，则在上述代码与实跑闭环前合并/发布继续阻断；
8. 只有 PR required checks、pre-merge 完整诊断、所有适用 supplemental gate、
   CodeRabbit/P0/P1 和 PR 对话均闭合时，才允许 PR 作者通过 GitHub squash
   merge；不得使用 merge commit、rebase、管理员绕过或 force push；
9. squash 后读取新的 protected-`main` commit/tree，等待该精确 `push` 的五项
   required checks 全绿，下载新的九文件 main artifact，并用新的 `RUN_ID`、
   新的 `/srv/cag-audit/evidence-$RUN_ID` 全量重跑与 pre-merge 相同的二号机
   功能、安全、五仓/ZIP、性能、副作用和清理矩阵。只有 manifest
   `event=push`、`head_branch=main` 且 `head_sha=commit=protected main` 的本轮
   fresh PASS 才可执行 portable `pack`；
10. post-main portable report 与 draft staging Release/asset 闭合后，由真实
    signer 在该精确 main commit 上创建 GitHub 验证为 valid 的 signed
    annotated `v1.0.0-rc.1` tag；轻量或未签 tag 立即停止。最后从该 tag 手动
    dispatch 固定 RC workflow，复核资产后只发布 non-latest prerelease。

二号机清理只允许删除本轮精确 task label/root、临时容器、网络和惰性语料；
禁止 `docker system prune`，禁止删除业务镜像、容器、卷、配置、数据库、凭据或旧审计证据。

## 7. 失败与停止条件

以下任一条件立即停止合并/发布：

- 正常、防御或授权语义出现一次误拦；
- 明确恶意激活在 Balanced 或 Strict 漏拦；
- block 后出现任何上游、Auth、Provider、Executor、Usage 或 SSE 副作用；
- no-copy 载体被污染、串请求、出现 race 或大载荷复制回退；
- 被拒重配改变当前 Subject、请求缓存、配置或 SQLite；
- CPA、CAG、语料、runner、CI artifact、commit/tree/SO 身份不闭合；
- 尝试把 pre-merge artifact、SO、证据或 PASS 转移到 post-main，或从
  `pull_request`/非 `main` artifact 执行 portable `pack`；
- supplemental archive 参数、独立分母、schema/validator/tests 尚未落地却
  声称 Codex 全破 ZIP PASS；
- required check 失败、CodeRabbit 仍有有效问题或 PR 对话未解决；
- 二号机出现 OOM、panic、非预期 restart、业务快照漂移或清理残留；
- tag/commit 不能满足签名要求，或 signer 身份/私钥所有权不真实明确；
- Release 资产集合、checksum、SBOM、provenance 或复现性不闭合。

## 8. 回滚方案

- 合并前：仅回退本轮独立提交；不得 reset 或覆盖进入本轮前的 75 文件工作树。
- 运行时：保留旧 CAG `.so`、配置和 audit DB 的已验证备份；切换新插件前记录哈希，失败时恢复旧 `.so` 与配置并验证 CPA 健康。
- 数据库：任何迁移前必须生成并验证备份；被拒重配不能依赖“事后恢复”来掩盖候选副作用。
- GitHub：不改写 `main`，不 force push；RC 失败则保留不可变失败证据并使用新的 RC 序号，不移动已发布 tag。
- 二号机：graceful stop、SQLite flush/checkpoint、按本轮 label 删除资源，再确认业务容器快照不变。

## 9. 最终状态定义

- `ENGINEERING PASS`：精确候选的 Linux 与五项 GitHub required checks 成功。
- `PREMERGE DIAGNOSTIC PASS`：PR synthetic merge artifact 的完整二号机诊断
  成功；仅授权 squash merge，不是 release admission，禁止 `pack`。
- `POSTMAIN SECOND-MACHINE OWNER RELEASE ADMISSION PASS`：精确 protected-main
  `push` artifact 在新的完整二号机运行中闭合功能、安全、副作用、误报、
  身份、性能和清理，并生成 portable report；仍非独立证明。
- `RC RELEASED`：精确合并 `main` 上的签名 tag 和完整 prerelease 资产已验证。
- `INDEPENDENT ATTESTATION`：本轮不提供。
- `STABLE PRODUCTION APPROVED`：本轮不提供；`v1.0.0-rc.1` 不是稳定版。
