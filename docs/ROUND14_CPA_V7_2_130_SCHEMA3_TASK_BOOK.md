# Cyber-Abuse-Guard Next 第十四轮 CPA v7.2.137 / RPC schema 3 活动任务书

状态：**ACTIVE / DIRTY-WORKTREE / LOCAL GATES IN PROGRESS / CI NOT_RUN / SECOND-MACHINE NOT_RUN / NO_MERGE / RC PUBLICATION GATED**

工作分支：`agent/cpa-v7.2.130-v1-rc1`

基线 HEAD：`c4408af041e4b3c0d58406ccca816b8d8585840b`

平台范围：**仅 Linux amd64**

CPA 固定目标：**CLIProxyAPI v7.2.137，C ABI 1，RPC schema 3**

上游正式发布日期：**2026-08-19**

本轮首先完成 v7.2.137/schema 3 兼容与准入；只有全部适用验收通过后，才按
[`ROUND14_EXECUTION_AND_RC1_ACCEPTANCE.md`](ROUND14_EXECUTION_AND_RC1_ACCEPTANCE.md)
进入固定 `v1.0.0-rc.1` 发布门。Round 13
v7.2.125/schema 2 的任务书、报告、CI、二号机、五仓、ZIP、性能和 Host 证据只对其
原始身份有效；不得复制、改名、重标或转移为本轮 PASS。

## 1. 权威身份冻结

```text
repository: yujianwudi/cyber-abuse-guard-next
branch: agent/cpa-v7.2.130-v1-rc1
baseline_head: c4408af041e4b3c0d58406ccca816b8d8585840b

cpa_module_path: github.com/router-for-me/CLIProxyAPI/v7
cpa_version: v7.2.137
cpa_commit: 85d2faddd17e6f4f8675a84ee28b131f702e8eaa
cpa_module_sum: h1:CYYByMn7/NwnsCJEMiLI2F8kIJMTb5jRrLaIK6H0c0w=
cpa_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
cpa_plugin_c_abi: 1
cpa_rpc_schema: 3

cpa_linux_amd64_asset: CLIProxyAPI_7.2.137_linux_amd64.tar.gz
cpa_linux_amd64_asset_bytes: 21072175
cpa_linux_amd64_asset_sha256: ae68c776e124dbc8c8c5b86c501fc6906efa180cc5e35383adb26d05c2c91401
cpa_linux_binary_bytes: 63738088
cpa_linux_binary_sha256: aac02193aee085542f2452e02606a0ab0e3c3c65ace6216bd39bc48e733c37fa
cpa_checksums_sha256: 9ae7dee90cd717a373acb58fad0163264891d5a76b27fb15d4c88bd10467012e
cpa_release_type: formal
cpa_release_date: 2026-08-19
```

Go module origin、tag commit、官方 checksums、资产大小/哈希、内含二进制大小/哈希
必须在 Linux 门禁和二号机门禁分别复核。开发工作树、PR head、synthetic merge、
最终合并 commit/tree、SO 和 artifact 必须各自绑定，不得因源码树相近而转移结果。

## 2. 本轮目标

1. 将全部活动 CPA 合同精确升级到 v7.2.137，并显式固定 C ABI 1、RPC schema 3。
2. 验证 schema 3 的流式边界：header-init 仍携带 `OriginalRequest` 和
   `RequestBody`，payload chunk 省略二者；CAG 不注册 response stream interceptor，
   不依赖或改写 payload chunk。
3. 验证请求拦截与生命周期合同继续适用于既有受保护路由，block 在 Auth、Router、
   Provider、Executor、Usage 和 SSE 副作用前完成。
4. 记录并验证 CPA v7.2.137 新增的 `/v1/realtime*` 独立处理链边界。该链绕过
   `RequestInterceptor`、`ModelRouter` 和 request lifecycle，当前 CAG 对其不可见。
5. 修复并锁定 audit oracle：允许 category-free 的 `META-OVERRIDE-001` classifier
   audit 例外；拒绝 transport disposition 携带伪造 classifier winner。
6. 以本轮新产物完成 Linux、CI、二号机五仓与 ZIP、误报、性能，以及 Host
   300 秒准入和 3600 秒稳定性门禁。

## 3. 已知上游边界与保护声明

### 3.1 schema 3 stream 合同

- `StreamChunkHeaderInitIndex` 的 header-init 仍必须包含完整
  `OriginalRequest`/`RequestBody`，用于 Host 建立流上下文。
- 后续 payload chunk 必须省略 `OriginalRequest`/`RequestBody`，只携带当前响应块和
  chunk 元数据；测试必须拒绝把省略误报为请求丢失。
- CAG 的保护点是 request before/after-auth 与 terminal lifecycle；CAG 必须明确
  报告 `response_stream_interceptor=false`，不得加入成功响应或 stream chunk 改写链。
- schema 3 的带宽优化不是 CAG 的安全能力；不得声称 CAG 审查了每个响应 chunk。

### 3.2 `/v1/realtime*` 明确不受保护

CPA v7.2.137 的 `/v1/realtime*` 使用独立处理链，当前绕过
`RequestInterceptor`、`ModelRouter` 和 request lifecycle。因此：

- 本轮把该路由族固定标为 **OUT_OF_SCOPE / UNPROTECTED / CAG_NOT_VISIBLE**；
- 不得用普通 chat/responses 路由的 PASS 宣称 realtime 覆盖，也不得宣称“全流量覆盖”；
- 二号机 Host 准入必须主动探测并记录 realtime 路由的实际行为、可达性、认证边界、
  CAG/Router/lifecycle 调用计数均为零的事实；动态探针固定为
  `probe_mode=UNAUTHENTICATED`、`credential_kind=NONE`、
  `termination=AUTH_REJECTED`，并逐路记录六项 `cag_counter_delta=0`；不得向真实
  Provider 建连；
- 静态源码拓扑结论单独标为 `SOURCE_TOPOLOGY_UNPROTECTED`。未认证动态探针仅证明
  认证边界，必须标为 `AUTH_BOUNDARY_ONLY`；它不证明认证后的 handler/provider 链，
  不得冒充完整动态旁路证据；
- 若部署方要求 realtime 受保护，必须在 CPA 提供可拦截链或另行禁用/前置隔离后开启
  新任务；本轮不以静默 allow、伪造 audit 或路由改写掩盖缺口。

## 4. 安全与证据不变量

1. 第三方五仓和 ZIP 只作为惰性文本数据读取；禁止执行脚本、二进制、安装器、hook、
   Java/Gradle、MCP 配置或依赖。
2. 所有动态请求仅连接隔离 counted Mock；禁止真实 Provider、生产账户池、生产数据库
   和真实客户请求。
3. `Audit` 只记录不拦截；`Balanced`、`Strict` 分开验收。正常、防御、引用、翻译、
   拒绝、授权测试和工具 schema 不得因关键词密度被屏蔽。
4. block 必须证明 Mock/Auth/Router/Provider/Executor/Usage/SSE delta 全为零；allow
   只能产生唯一预期调用。
5. category 与 classifier winner 是独立字段。category-free classifier audit 仅允许
   `winning_rule_id=META-OVERRIDE-001`；transport/incomplete/scan-limit 等独立 disposition
   不得携带 classifier winner。
6. 所有证据绑定 v7.2.137、schema 3、精确 commit/tree/SO/artifact；缺失、陈旧、混合
   或不可重算数据 fail closed。
7. 二号机只清理本轮精确 task label/root、临时容器、网络和惰性语料；禁止
   `docker system prune`，禁止碰业务镜像、容器、卷、配置、数据库、凭据或旧证据。

## 5. 非目标

- 不增加 Windows 或 macOS 构建、测试、二号机或发布资产。
- 不实现、代理或宣称 `/v1/realtime*` 的 CAG 保护；它保持明确未保护边界。
- 不注册 response interceptor 或 stream interceptor，不改写成功响应流。
- 不执行、安装、重新分发或信任第三方破限仓库/ZIP 中的代码。
- 不删除、修改、迁移或借用 Round 13 v7.2.125/schema 2 历史证据。
- 不把二号机所有者运行包装为独立第三方证明或稳定生产批准。
- 不创建 stable Release；在全部适用验收闭合前，不创建 tag、GitHub Release、
  prerelease 或执行 release seal。验收闭合后只允许由受审 `release-rc.yml`
  创建固定 `v1.0.0-rc.1` prerelease，且 `make_latest=false`。

## 6. 工作包与验收标准

### R14-01：身份、任务书和状态冻结（P0）

交付：本任务书与 `ROUND14_STATUS.md`。

验收：

- 上述 tag、commit、module sums、C ABI/schema、资产和二进制身份逐字一致；
- Round 13 保持只读历史，本轮证据从 `NOT_RUN`/`PENDING` 起步；
- 文档和脚本不包含任何把 v7.2.125 PASS 转移到 v7.2.137 的措辞。

### R14-02：v7.2.137 / schema 3 源码兼容（P0）

验收：

- 根模块、`integration/cpalatestcontract`、`integration/pluginstorecontract` 精确固定
`github.com/router-for-me/CLIProxyAPI/v7 v7.2.137` 及给定 sums；
- 编译合同固定 ABI 1、schema 3、request before/after、completion method 和 outcome；
- header-init 保留 `OriginalRequest`/`RequestBody`，payload chunk 省略二者；
- 插件注册明确 `response_interceptor=false`、`response_stream_interceptor=false`；
- Store 安装、注册、reconfigure、shutdown、Host fail-open/fail-closed 与 schema 3
  overlay 全部通过；远端验证固定 tag，不以漂移的 latest 取代目标。

### R14-03：受保护路由与 realtime 隔离合同（P0）

验收：

- chat、responses 及仓库当前声明受保护的路由逐一证明 request interceptor 和
  lifecycle 调用、block 零副作用、allow 唯一 Mock 调用；
- `/v1/realtime` 及所有已知 `/v1/realtime*` 变体列入专门 negative coverage；
- Host probe 记录路由、HTTP/upgrade 结果、无凭据探针模式、认证拒绝终止、逐路六项
  零增量、目标地址与 Mock 边界；真实上游调用必须为零；动态结论仅限未认证边界，
  源码拓扑结论与动态结论必须分层展示；
- machine evidence、portable report 和准入摘要都输出
  `realtime_protection=unprotected`，缺失或声称 protected 必须 fail closed；
- 任何用户可见总结必须限定为“已列举受保护路由”，禁止“全流量覆盖”。

### R14-04：oracle category/winner 修复（P0）

验收：

- category-free `META-OVERRIDE-001` classifier audit 在 batch/stream 和适用协议通过；
- category-free 的其它 classifier winner 被拒绝；
- transport disposition 携带任意 classifier winner 被拒绝；
- malicious classifier event 仍要求适用 category 与稳定 winner，paired Audit
  expected/actual winner 不得漂移；
- schema、validator、runner projection、negative tests、固定分母和报告共同闭合，
  不通过放宽 schema 或吞掉 winner 达成兼容。

### R14-05：Linux-only 本地与 CI 门禁（P0）

本地 dirty-worktree 只产生开发证据；候选准入必须由精确 artifact 重跑：

```text
go unit/vet/race/fuzz: PASS required
schema3 cpalatest/pluginstore contracts: PASS required
audit-contract and runner tests: PASS required
safe-gate/script/corpus/benchmark/performance: PASS required
govulncheck: 0 applicable findings required
secret scan/actionlint/shellcheck: PASS required
artifact identity/reproducibility: PASS required
```

PR 和最终候选所适用的 required checks 必须全部绿色；名称以当时受保护分支配置为准，
逐项记录 URL、run ID、event、head SHA、artifact ID/digest/size。没有 GitHub 运行就保持
`NOT_RUN`，本地结果不能代替 CI。

### R14-06：五仓、ZIP、误报与副作用（P0）

固定五仓：

1. `Jia-Ethan/codex-keysmith`
2. `yynxxxxx/Codex-5.5-codex-instruct-5.5`
3. `yynxxxxx/Codex-X`
4. `MDX-Tom/gpt-5.6-instruct`
5. `lingbol088-spec/5.6-JAILBREAK-NERV-codex-instruct-5.6`

补充 ZIP：`Codex全破.zip`，输入 SHA-256
`23000a55f3922c9c2daf04e27d4bdf49d5f95109dd76ba25fa0b3f834c67ed1c`。
必须通过显式 supplemental 输入，单独报告 source hash、case count、正常误报分母、
恶意召回分母、结果和清理状态，不得混入五仓分母。

准入：正常/防御/授权语义误拦为 0；Balanced/Strict 的 expected malicious 均 100%
命中；Audit 恶意 detection 为 100% 且 block 为 0；incomplete 不计语义真阳性；
unexpected HTTP/infrastructure error、第三方代码执行和 block 后副作用均为 0。

### R14-07：性能门禁（P1）

使用与 Round 13 定义等价但**重新执行**的 Linux 固定 workload 和 CPA-only/CPA+CAG
配对原始数据，不得导入旧数值：

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

报告必须保留 workload、concurrency、repetition、payload、计数、原始 latency/RSS、
容器 init PID/starttime 和可重算派生值。环境受扰时只能标为
`DIAGNOSTIC / NOT_BASELINE`，不能放宽阈值或借用 v7.2.125 性能数据。

### R14-08：二号机精确候选与 Host 准入（P0）

二号机必须使用官方 v7.2.137 Linux amd64 资产、本轮精确 Linux SO/Store ZIP、隔离
counted Mock 和新 `RUN_ID`/evidence root。按顺序执行：

1. 复核 Host 资产、二进制、schema 3、SO、config、artifact 与 evidence manifest；
2. 完成功能、安全、受保护路由、realtime 未保护 negative coverage、五仓、supplemental
   ZIP、误报、副作用、性能和资源清理；
3. **Host 300 秒准入门**：连续 300 秒健康，期间 `/keeper/healthz` 为 healthy、根路由
   200、未授权 `/v1/models` 为 401，restart/OOM/panic 为 0，Mock/插件/Router/lifecycle
   计数与预期一致；
4. **Host 3600 秒稳定性门**：在同一不可变候选上连续 3600 秒，固定频率采样健康、
   PID/starttime、restart、RSS/queue/error 指标并执行代表性受保护流量；结束后重新验证
   realtime 未保护声明、五仓/ZIP 摘要、数据库完整性和清理；
5. 任一时间窗中断、身份漂移、采样缺口、真实上游调用、非预期 restart/OOM/panic、
   误拦、漏拦或副作用均不得补记 PASS，须生成新 RUN_ID 从头执行。

300 秒 PASS 不能代替 3600 秒 PASS；两者都必须记录开始/结束 UTC、单调时钟、采样数、
候选身份与原始 evidence 路径。本轮 Host admission 只说明该精确候选在声明的受保护
路由上通过，不改变 realtime 的 `OUT_OF_SCOPE / UNPROTECTED` 状态。

## 7. 回滚与成对约束

运行时二进制与插件必须作为不可拆分对回滚：

- **v7.2.137 Host 只能搭配为 C ABI 1 / RPC schema 3 构建并验证的本轮 SO。**
- **旧 Host 必须恢复与该旧 Host 的 ABI/RPC schema 精确匹配、此前验证过的旧 SO；
禁止旧 Host 搭配 schema 3 SO，也禁止 v7.2.137 Host 搭配旧 schema 2 SO。**
- 切换前备份并校验 Host 二进制/镜像、SO、配置、Store metadata、SQLite/audit DB；
  回滚后复核精确哈希、schema、`/keeper/healthz`、根 200、未授权 models 401、PID/restart
  和 counted Mock，不以“进程启动”代替兼容验证。
- 合并前只回退本轮独立提交，不 reset/覆盖进入本轮前的脏工作树；GitHub 不 force
  push、不移动历史 tag。二号机只删除本轮资源，保留不可变失败证据。

## 8. 停止条件

以下任一项立即停止合并/部署准入：身份或 schema 不闭合；正常语义误拦；Balanced/
Strict 漏拦；block 后出现副作用；category/winner oracle 接受伪造组合；realtime 被误报
为受保护；五仓或 ZIP 分母混合；本轮证据引用 Round 13；Linux/CI/Host 任一适用门失败；
300 秒或 3600 秒窗口不完整；候选/Host/SO 漂移；OOM、panic、restart、真实 Provider
访问或清理越界。

## 9. 本轮完成定义

- `LOCAL TARGETED PASS`：仅表示列出的 dirty-worktree 定向命令通过，不是候选准入。
- `LINUX CI PASS`：精确候选的适用 Linux checks 与 artifact/reproducibility 闭合。
- `SECOND-MACHINE OWNER ADMISSION PASS`：同一本轮候选完成五仓/ZIP、误报、性能、
  realtime 未保护记录，以及 Host 300 秒和 3600 秒门；仍非独立第三方证明。
- `MERGE READY`：前述适用门、CodeRabbit/P0/P1 和对话闭合，可按分支保护合并。
- `RC_RELEASED`：全部适用验收、受保护 main、签名 annotated tag、immutable
  Release 和受审 `release-rc.yml` 发布均闭合；该状态不代表 stable 或生产批准。
