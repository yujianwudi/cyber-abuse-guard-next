# Cyber-Abuse-Guard Next 第十五轮完整任务书

## CPA v7.2.142、主动 Quiesce、二号机回归与 RC3 发布

状态：`ACTIVE / IMPLEMENTATION_PENDING`

最后更新：2026-08-26（Asia/Shanghai）

## 1. 权威身份与决策

```text
source_version: 1.0.0
candidate_release: v1.0.0-rc.3
platform: linux-amd64 only
go_toolchain: go1.26.6
cpa_version: v7.2.142
cpa_commit: 1f53b2eb03b9e963bac647e5566ca2b304239116
cpa_module_sum: h1:30twcgoSCSjBtc4tgZBKPC4sQpsEWwgu4d9r7tIDpQQ=
cpa_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
cpa_linux_amd64_asset: CLIProxyAPI_7.2.142_linux_amd64.tar.gz
cpa_linux_amd64_asset_bytes: 21193314
cpa_linux_amd64_asset_sha256: a7cccc8f94b07660303c1874fb6bedae6d573a0f3c4c0b17ad8cf7885dd7a051
cpa_checksums_bytes: 1094
cpa_checksums_sha256: 2a04364707aa7e8922c7ee35ad3b90437659c08fa4dbaa962f02b274993a0a6c
cpa_c_abi: 1
cpa_rpc_schema: 3
second_machine: 42.193.150.215 / ubuntu / authorized isolated sandbox
```

仓库已经存在并保护两个 GitHub-verified signed annotated tag：
`v1.0.0-rc.1` 和 `v1.0.0-rc.2`。二者均不可更新、删除或复用；RC1/RC2
没有可转移到本轮候选的发行 PASS。因此，本轮唯一合法候选为
`v1.0.0-rc.3`。用户最初要求的 RC1 名称因不可变 tag 冲突不能再次创建；不得绕过
tag ruleset、移动 tag、伪造 Release 或另指提交。

## 2. 审计基线

当前仓库基线为 protected `main@d861ed326c2ba0b042f9206f823bff055ada210b`，
1043 个跟踪文件、390 个 Go 源文件、4 个仓库 YAML workflow。远端分支仅
`main`；branch protection 要求严格最新分支、GitHub Actions app 绑定的
`quality-and-artifacts`、`fuzz-long`、`reproducibility`、
`Analyze Go on Linux`、`round9-policy-and-corpus`，并启用签名、管理员执行、
会话解决，禁止强推和删除。

GitHub Actions API 还会返回两个平台动态记录：

```text
dynamic/dependabot/dependabot-updates
dynamic/dependabot/update-graph
```

它们不是仓库 YAML，继续使用精确平台 allowlist；任何其他 active path
必须失败关闭。

二号机 SSH 与 sudo 可用、Linux x86_64、根分区约 40 GiB/剩余 31 GiB。当前没有
运行中的 CPA 或 Docker 容器；旧 `/opt/cpa-v7272-test` 已不存在，仅观察到三个指向
已删除旧路径的陈旧 Python 辅助进程。本轮不得把该状态当作已有测试环境或历史 PASS，
必须创建新的、命名隔离且可清理的 v7.2.142 沙盒。

## 3. 已确认风险与工作项

### P0-1：CPA v7.2.142 exact identity

将所有活动依赖、构建、CI、Host、审计、回执、文档和发行合同从 v7.2.137 精确升级到
v7.2.142。Round 14 及更早的 137/125/124 记录只保留在明确的 historical/frozen
区块，禁止机械全局替换。

验收：

1. root、`integration/cpalatestcontract`、`integration/pluginstorecontract`
   三个 Go module 都固定 v7.2.142 与上述 module/go.mod sum；
2. exact tag、commit、官方 checksums、Linux 插件版归档、归档内二进制字节数与 SHA-256
   均由自动合同验证；
3. `pluginabi.ABIVersion == 1`、`SchemaVersion == 3`、schema-3 stream header/payload
   语义不漂移；
4. `_no-plugin` 资产不得用于 CAG Host 准入或发布。

### P0-2：`plugin.quiesce` 主动生命周期

CPA v7.2.142 在 hot reload 注册替换插件前调用 `plugin.quiesce`，失败替换时会重新
`plugin.register` 旧实例执行回滚。当前 CAG 返回 `unknown_method`，CPA 虽能降级，
但无法证明主动静默、in-flight drain、审计持久化和回滚恢复。

实现要求：

1. 单独实现可逆 `quiesce` 状态，不得复用不可逆 `shutdown`；
2. quiesce 发布当前模式的终端策略，停止接纳新的普通 RPC 工作，并等待已进入
   `opMu` 读侧的请求完成；
3. 对已接受审计项执行有界 Flush/Quiesce，但不关闭 SQLite、不删除 runtime、
   不丢失主体控制或 Raw Capture 状态；
4. quiesce 幂等；并发 quiesce/reconfigure/shutdown 无死锁、panic 或数据竞争；
5. CPA 回滚调用 `plugin.register` 成功后恢复旧实例服务，且只有成功注册才清除
   quiesce；失败注册保留静默状态；
6. shutdown 在 quiesce 前后均不可逆并执行完整持久化关闭；
7. quiesce 期间 Balanced/Strict 继续按快照策略成功返回直接终止响应，
   Observe/Audit/Off 明确 pass-through，不能返回会让 CPA fail-open 的裸 RPC 错误；
8. management status 仅暴露低基数生命周期状态/计数，不含请求原文、路径或 Secret。

验收测试至少覆盖：正常 quiesce、重复 quiesce、quiesce 后 register 回滚、无效 register、
shutdown、in-flight request、audit queue drain、Raw Capture、subject persistence、
并发 race、oversized RPC、panic recovery 与真实 v142 Host hot reload/rollback。

### P0-3：发行合同与版本不可变性

把活动发行合同升级到 `v1.0.0-rc.3`。RC1/RC2 只保留不可变失败/未发布历史，禁止修改。

验收：

1. RC3 仅能由 GitHub-verified signed annotated tag 派发；
2. tag 必须指向 exact protected main squash commit；
3. exact-main CI、CodeQL、Policy/Corpus run 和每个 required job 已成功；
4. 唯一 live 九文件候选 artifact 被 ID/digest/size/run/attempt 绑定；
5. RC workflow 不重编译审计 SO，只封装 exact candidate bytes；
6. Release 为 immutable、non-draft、prerelease、not latest；
7. 失败 tag 不移动，下一次失败必须使用新的 RC 号。

### P0-4：治理凭证与可审计失败

当前 RC1/RC2 admission 多次在聚合 Bash step 内静默失败，专用
`CAG_RELEASE_GOVERNANCE_TOKEN` 的权限/字段漂移不能被安全定位。

实现要求：

1. 把 admission 拆成有名称的只读治理阶段，或使用不含敏感值的稳定错误代码；
2. Administration/Actions/Contents 只读凭证仅调用治理端点，普通 repository/run/artifact
   读取继续使用 job-scoped `GITHUB_TOKEN`；
3. 日志只能输出端点类别、HTTP 状态和固定断言代码，绝不输出 token/header/body 中的
   敏感值；
4. 缺少 Secret、403、字段缺失、策略不匹配均明确 fail-closed；
5. 添加 fixture/unit 合同覆盖 fine-grained PAT 可见字段、缺字段、403、空响应和
   GitHub API schema 漂移；
6. 不得使用管理员 bypass、广权限经典 PAT 或在源码/对话/Release 中保存 token。

### P1-1：请求安全、正常用户误报与原文审查

保持“正常用户零误伤优先”：关键词、仓库名、防御性研究、合规、事件响应、授权测试和
本项目自身维护请求不得仅凭表面词汇阻断。Balanced 覆盖不完整继续 allow+audit；
Strict 才按既定合同 fail-closed。

验收：

1. 正常/防御/合规/本项目维护集合 eligible blocks = 0，误报率 = 0%；
2. block-only Raw Capture 默认关闭；开启时仅保存被拦截请求的有界、脱敏、截断预览；
3. CSAM 仍为 text-only，不打开/保存真实媒体；举报、热线、预防与研究内容零误报；
4. 审计失败不改变分类决策，但 readiness 明确降级；
5. Secret、Authorization、Cookie、Provider/OAuth 身份不得进入日志、报告或 Release。

### P1-2：五仓、Codex ZIP 与性能回归

受控输入包括五个公开破限仓库的最新默认分支，以及用户提供的 `Codex全破.zip`。
仓库只读获取、固定 commit/tree/path/bytes/hash，从不执行第三方代码。ZIP 只做有界、
防 Zip Slip/符号链接/压缩炸弹的文本提取；不将公开语料当独立 Holdout。

验收：

1. 五仓与 ZIP 每个来源独立计数、可复现，`third_party_code_executions = 0`；
2. 已标注恶意样本在 Balanced/Strict 达到任务书固定召回门，不用仓库名直接提权；
3. 独立正常请求集合 eligible false positives = 0；
4. 性能以 CPA no-plugin、CPA+CAG observe、balanced、strict 分离测量；
5. 普通请求 p95/p99、恶意集合 p95/p99、RSS、审计队列、并发 1/4/16、300 秒 soak
   均有机器可读结果；不得以单次微基准代替 Host 性能；
6. 不降低既有 Round 10/14 阈值，若环境噪声导致失败必须保留失败并重跑同一候选，
   不能改阈值追绿。

### P1-3：二号机全新隔离沙盒

沙盒根建议 `/opt/cag-round15-v72142`，资源名称必须携带 execution ID。禁止复用或覆盖
生产配置、凭据、会话、数据库、日志和旧证据。

准入：

1. 从 GitHub exact candidate artifact 与官方 v142 asset 获取字节；
2. SHA-256、ELF、GLIBC、C ABI/RPC schema、tag/commit/tree 全闭合；
3. 使用 internal-only Docker network 或等价无公网入站隔离，零 Host 端口发布；
4. counted mock 是唯一上游，所有 Auth/Provider/Usage/Executor/Mock/SSE 副作用有计数；
5. 测试后卸载临时 runner/容器/网络/目录；仅保留无请求原文的有界报告和校验和；
6. 二号机上观察到的三个陈旧 Python 进程在确认不属于当前任务/生产后定向终止，
   不执行宽泛 kill/prune。

### P2：仓库治理和历史分层

1. 活动文档只有 Round 15 入口；Round 14 及之前明确 historical/superseded；
2. GitHub repository workflow 仍恰好四个，平台 dynamic path 使用闭集 allowlist；
3. PR 合并后本地/远端仅 `main`；签名 tag 保留；
4. README/README_CN、SECURITY、CHANGELOG、发行策略、审计交接与 operator guide 同步；
5. 不删除仍被合同/回滚/语料身份引用的 fixture；无用临时下载、clone、构建目录在任务完成后定向清理。

## 4. 执行顺序

1. 固定 v142 source/module/asset/binary 身份与上游差异；
2. 更新 Go modules 和 exact-source contracts；
3. 实现可逆 quiesce 与单元/race/Host 合同；
4. 更新审计、文档、回执、发布与治理诊断；
5. 本地 Linux 全量验证与 CodeRabbit 修复循环；
6. 签名 PR，等待 exact-head 全绿；
7. 二号机从 exact PR/main candidate artifact 运行全新隔离审计；
8. 只有二号机所有适用门通过才 squash merge；若测试发生在合并前，合并后必须重新绑定
   exact-main artifact，不能转移旧 commit PASS；
9. 等待 exact-main required checks 全绿；
10. 清理所有非 main 分支；创建并验证 signed annotated RC3 tag；
11. 从 tag 派发唯一 RC workflow并核验 immutable prerelease。

## 5. 总验收门

只有同时满足以下条件才可声明本轮完成：

- CPA v7.2.142 / commit / module sum / asset / binary / ABI / schema 身份全闭合；
- `plugin.quiesce` 可逆生命周期及 rollback 真实 Host 测试通过；
- Go format/module/unit/vet/race/fuzz/benchmark、safe-gate、文档变异、RC 合同、
  secret scan、govulncheck、CodeQL 全通过；
- CodeRabbit 无未解决 actionable issue；
- 二号机五仓/ZIP/正常请求/副作用/性能/soak/清理全部适用门通过；
- exact-head 和 exact-main required checks 全绿；
- 合并采用 protected-main squash，无管理员 bypass；远端/本地仅 main；
- RC3 tag 和 commit 均 GitHub verified/valid；
- RC3 Release immutable、prerelease、not latest，Linux资产、checksum、manifest、SBOM、
  provenance/attestation 全部互相闭合；
- Release 和报告明确不是稳定生产批准，也不伪造独立审计或二号机 PASS。

任何 P0、身份、签名、治理、Host、误报、性能、隐私或清理门失败，都必须停止发行并
保留失败证据；不得通过改名、移动 tag、删除失败 run、降低阈值或手工上传资产绕过。
