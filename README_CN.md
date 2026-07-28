# CPA Cyber Abuse Guard

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: e0cbc975c126a12649a1b8e309e4e2a95efc64e46346467771ecae61b3e14971
```

> **RC 身份说明：** `v0.16-rc.3` 是不可移动的 Phase 1 失败 Tag，没有候选产物或
> Release。当前目标是尚未占用的 `v0.16-rc.4`；在独立证据齐备前，公共发布继续硬阻断。

> **仓库沿革：** 这是采用全新 Git 历史的后续项目。旧 tag、分支、Release
> 和历史资产继续只读保留在
> [`yujianwudi/cyber-abuse-guard`](https://github.com/yujianwudi/cyber-abuse-guard)，
> 本仓库不会重新创建或冒充这些历史产物。

> **当前开发状态：** 第九轮正在以候选/子句/scope/referent 绑定的阻断资格
> 重新设计 Balanced，并准备 Linux amd64 `v0.16-rc.4` 预发行链。固定源码/编译目标仅为 CPA
> `v7.2.104`，并仅使用 RPC schema 2。源码变更本身不会创建标签、Release
> 或稳定版 `v0.16`。无 checkout 的受保护 CPA 外部评估、受保护账本证明、exact-main CI
> 和独立审计仍是必需门禁；尚未获得生产批准，也不得据此自动重新开启生产 Balanced。

[![Historical CI](https://img.shields.io/badge/historical_CI-v0.15-blue)](https://github.com/yujianwudi/cyber-abuse-guard/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.26.4-00ADD8?logo=go&logoColor=white)](go.mod)
[![Platform](https://img.shields.io/badge/platform-Linux%20amd64-lightgrey)](docs/ROUND6_LIMITATIONS.md)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Historical RC](https://img.shields.io/badge/historical_RC-v0.15--rc.4-orange)](docs/ROUND6_RELEASE_GATE.md)
[![Historical stable](https://img.shields.io/badge/historical_stable-v0.15-published-success)](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.15)

**面向 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI)（CPA）的本地、确定性、路由前 Cyber Abuse 请求风控插件。**

[English](README.md) | 简体中文

> [!WARNING]
> [`v0.15`](https://github.com/yujianwudi/cyber-abuse-guard/releases/tag/v0.15)
> 已于 2026-07-20 手工发布为 latest stable，共十项资产。Release Notes 明确披露：
> GitHub Actions 因 Billing 未运行，资产由所有者在报告生产沙盒通过后手工构建。
> 该 Release 没有附带独立 Host、审计或评测 attestation。下文保留的 Round 6
> 与 `v0.15-rc.*` 内容是发布前工程历史，不代表当前 v0.16 发布状态。

CPA 加载并注册插件后，Guard 通过 schema 2 的 before-auth RequestInterceptor，在账号认证调度、Provider 执行、用量记账、SSE 建立和上游请求之前检查受支持的模型请求。命中时直接返回 HTTP 403；旧的本地 Executor 仅作为纵深防御保留。请求内容只在进程内判断，不发送给公网分类器。

## 当前 v0.16 开发状态

| 项目 | 状态 |
|---|---|
| 源码版本 / RC 目标 | `0.16` / 仅 `v0.16-rc.4` 预发行；精确 tag、commit、tree 和产物 hash 必须由未来 clean release run 生成 |
| 历史候选 | `v0.16-rc.1`、不可变的第八轮 `v0.16-rc.2`，以及 Phase 1 失败且不可移动的 `v0.16-rc.3` 仅保留为历史证据，不得覆盖、改名或复用 |
| GitHub 发布 | `v0.16-rc.3` 仅有 annotated Tag，没有 Release 或 Actions artifact；当前尚无 `v0.16-rc.4` Tag 或 Release。`round9-release-rc.yml` 只能生成私有 17 资产候选，公共预发行写入保持硬阻断 |
| 冻结的 v7.2.103 exact-main 基线 | `1a64639c0bac7a157d8201c1593bd68cf6e7fe11`；CI `30327322793`、Round 9 gate `30327322810`、CodeQL `30327322801` 在 v7.2.104 发布前均通过。它只属于 v7.2.103 开发与 Host 加载证据；当前 v7.2.104 仍待重新验证 |
| CPA 源码/编译目标 | `v7.2.104`（`c9417c8ae9b16fabc0386ca35d36f13bf8b1d678`） |
| 受保护 CPA 外部评估 | **NOT RUN / PROTECTED SANDBOX REQUIRED**；无 checkout 的 root-owned broker 必须把 CPA 精确绑定到 `127.0.0.1:18394 -> 8317/tcp`，并生成签名 external-evaluation v3 与账本证明 |
| 外部证据合同 | evaluator aggregate v3、ledger event v3、受保护 Git ledger proof v1、机械派生 external counted-Mock v1、CPA sandbox descriptor v2 |
| 公开对抗语料 | 当前为 `round9-public-adversarial-v13` / 481,448 bytes / SHA-256 `91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6`；199 个 GitHub Release 资产只记录元数据与摘要，未下载、未打开二进制资产；v12/v11/v10/v9 作为有效冻结历史保留，精确公布的 v8 作为 immutable-invalid 历史保留，误将修正摘要原位绑定到 v8 的 105,298-byte 快照作为 rejected rebind 保留，v7 与 v6 继续作为历史；仅为可见开发回归，不是独立 holdout，也不执行第三方仓库代码 |
| 独立审计 | 用户提供的外部 `f37a25dd` 报告称 CPA v7.2.95 多语言检查通过，并发现防御性事件响应请求误拦。该文件不是仓库绑定 attestation；当前源码仍需绑定最终 commit 重新审计 |
| 生产批准 | **NOT GRANTED**；不存在稳定版 `v0.16`，也不能自动重新准入 Balanced |
| v0.16 工作流 | `round9-gate.yml`、无 checkout 的 `round9-host-validation.yml`、`round9-release-rc.yml` 是当前第九轮链；第八轮与 v0.15 流程只读保留为历史证据 |
| 静态分析治理 | `.github/workflows/codeql.yml` 在经过审查的稀疏源码边界内，以最小权限在 Ubuntu 上分析 Go；CodeQL 结果不能授权发布 |
| 验证平台 | 仅 Linux amd64；产物引用的数字型 GLIBC ABI 版本必须 `<= 2.34` |
| 不在范围 | Windows、macOS、musl/Alpine、真实 Provider、生产部署/验证 |
| CPA 固定目标 | 仅 v7.2.104；仅 Linux amd64 counted Mock；Audit→Balanced→Strict 与数据库/重启/panic/usage/Raw Capture 运行时检查尚未执行 |
| 外部 CPA 评估 / 当前源码独立审计 | 外部评估仍为 `NOT_RUN`；仓库外的 `f37a25dd` 报告不能替代当前源码精确重审，生产批准未授予 |
| Scanner identity | `streaming-scanner-v1` |
| Classifier policy | 当前源码快照为 `classifier-policy-v9` / `e0cbc975c126a12649a1b8e309e4e2a95efc64e46346467771ecae61b3e14971`；Host 与发行绑定仍待完成 |
| 内嵌 YAML ruleset | 当前 main 快照为 `1.0.10` / `e609669853036090ff4d09379a84a4c0209d1f39120db910a6a38575678749b0`；最终候选绑定仍待完成 |
| 审计 schema | v6；decision kind 与 explanation variant 为闭集，v5→v6 强制创建迁移前备份，状态页披露敏感备份清单，raw capture 默认仍关闭 |

### 最新源码修复

- 当前兼容目标已升级到官方最新 CPA `v7.2.104` / `c9417c8ae9b16fabc0386ca35d36f13bf8b1d678`。Linux CI 会执行完整上游 Host 测试和公开插件 ABI/API 测试，校验该固定版本仍是 GitHub `releases/latest`，并通过真实 CPA Host 路径加载构建出的候选 `.so`；历史第六/八轮及 v0.15/v0.16-rc.2 证据仍保留原始 CPA v7.2.95 身份。
- 普通模型请求的生产主链已迁移到 RPC schema 2 的 RequestInterceptor 与 request lifecycle。before-auth 会完成分类，恶意 batch/stream 会在 Auth、Provider、Usage、Executor、Mock upstream 和 SSE 之前直接 403；生命周期缓存只保留 `RequestID` 与覆盖规范化 SourceFormat、body、大小写归一的 header 名、保持原值及顺序的 header values、stream 的进程随机密钥、RequestID 域分离 HMAC-SHA256 指纹，相同输入的 after-auth 只计算指纹并跳过重复分类/审计/风险副作用，任一安全相关输入变化都会重新分类。before-auth 若发生可放行的运行时故障则不写入“已检查”缓存，after-auth 仍会重试。完成回调清理有界、带 TTL 的 ID/指纹状态。CPA v7.2.104 的两条 Alpha Search 路由不调用该拦截链，因此 CAG 额外注册一个仅处理 `codex-alpha-search` 的窄 ModelRouter：安全搜索继续走 Codex，本地判恶意时在 Codex 认证和上游之前失败关闭；受 CPA 当前 handler 限制，该路径返回 503 而不是插件原生 403。
- 已补齐 `prompt`、`induce`、`receive`、`solicit` 及其时态，防止训练 telemetry 遮蔽真实凭据索取；四角色批处理/流式回归都要求完整钓鱼阻断。重复入侵告警降噪、监控维护和退役规则审计保持放行，只有明确用于隐藏恶意软件、未授权访问等敌意目的时才按规避阻断。
- 精确支持“仅做防御性事件响应训练/分析、解释风险、提供检测与修复建议、明确不要执行”的单一闭合引用审查。
- 该修复只扩展有限英文引导语，不会把泛化的“防御、训练、事件响应”关键词当作放行条件；第二引用、超预算、跨字段/跨 scope、缺少终止边界和后续执行指令仍不能获得抑制。
- 已补批处理、内容类型拆分、整段/二分/逐字节流式，以及 Balanced/Strict × OpenAI Chat/Responses/Claude/Gemini 模拟路由回归；仍不等同于最终 `.so` 或 CPA Host 证据。
- provider-native tool result 只有在请求内完整事务被证明后才具有 request-local 权限。Gemini 整组只能是全显式 ID 匹配，或全无 ID 且按 name+ordinal 完整匹配；混合、缺项、错 owner、非终端和孤立结果均无权。只有 `previous_response_id` 的 Responses continuation 仍无权，因为插件无法验证 Host 的 pending call、已消费状态与防重放状态。
- 去武器化 NERV 回归已覆盖凭证/会话窃取、持久化/C2/规避、勒索、钓鱼、隐蔽键盘记录、未授权利用和入侵后外传，并覆盖四 Provider 约 7 KiB 前/中/后 system 与终端 tool 路由；仓库名、授权运维、检测工程和闭合防御分析近邻保持不阻断。当前仍只是源码回归，精确 main 的五仓 counted-Mock 复测尚未提供。

## 历史 v0.15 发布记录

| 项目 | 历史事实 |
|---|---|
| Stable Release | `v0.15` 于 2026-07-20 手工发布，非 draft、非 prerelease、标记为 latest |
| 资产 | 十项手工构建的发行资产 |
| 验证声明 | 生产沙盒 PASS 仅为所有者在 Release Notes 中的报告，未附独立 Host 证据 |
| 独立证据 | 没有 `formal-release-attestation.json` 或 `round6-prerelease-attestation.json` 资产 |
| 源码身份 | classifier `v5`、ruleset `1.0.7`、audit schema v3 |

历史 v10 评测仍为 `CONSUMED / FAIL`，不得重跑或用于调参。内部工程门禁通过不能覆盖该方法学结论，也不能授权生产封控。

## Round 6 做了什么

- 移除生产路径中的 `body[:max_scan_bytes]`；受支持的 JSON 会遍历完整
  CPA 可见结构。
- 将旧 `max_scan_bytes` 迁移为 classifier 保留窗口的兼容别名，不再表示
  “只检查前 256 KiB”。
- 新增有界 `max_total_text_bytes` 与
  `max_classification_chunks`，把累计覆盖量和峰值保留内存分开控制。
- 将 JSON 字符串、multipart 文本、role、provenance 和逻辑字段边界流式送入
  有界 classifier session。
- 在提交分类文本前事务式处理媒体、metadata、tool schema 与 role；未知或歧义
  role 不能冒充可信 user。
- 支持跨窗口匹配和有界 role-aware 组合，同时不保留完整 prompt。
- 审计 schema v3 新增 `decision`、`coverage`、
  `incomplete_reason`、`scanner`，并增加固定低基数 counters。
- envelope 或文本 coverage 一旦 incomplete，会清空所有 partial category、
  score、rule、evidence 和 behavior。

本轮没有启用“incomplete 下 verified local hard finding”窄例外。兼容 counter
仍保留，但预期始终为 0。

## 检查与处置契约

Envelope 完整性和文本 coverage 分开记录：

- `complete`：完整验证可见结构，并检查全部模型可见解码文本；
- `budget_exhausted`：达到累计文本或分类工作预算；
- `unavailable`：malformed、未知 schema/encoding、role 歧义或 RPC 边界导致
  无法证明完整覆盖。

| 模式 | 完整且有害的请求 | Incomplete inspection |
|---|---|---|
| `off` | 放行 | 放行 |
| `observe` | 仅观测 | 放行 + observe |
| `audit` | 仅审计 | 放行 + audit |
| `balanced` | 达到阈值时本地阻断 | 放行 + audit |
| `strict` | 达到 strict 阈值时本地阻断 | 本地阻断 + audit |

安全启动默认值为 `mode: observe` 和 `subject_control.enabled: false`。
Observe 只更新有界 counters：不阻断、不累计主体风险、不持久化逐请求 SQLite
event，也不会为审计关联而扫描完整请求 Body 计算哈希。

Incomplete 请求不进入 subject risk。半截 prefix 不能在 `balanced` 下产生策略阻断。
恶意文本阻断必须具备一个闭集请求权限证明：当前可信用户的 `current_user` ownership，
或对独立完整有害候选的结构化 `request_local_system` / `request_local_tool` 权限。
只有 `current_user` finding 可以累计滚动主体风险；request-local system/tool 阻断绝不
归因给已认证用户。未知/未来字段、assistant 历史、tool schema 与非终端 tool result
只保留可检查、可审计状态，不能直接阻断。只有后续当前用户通过完整、有界的
referent 证明重新激活历史载荷，并再次通过同一候选 eligibility gate，载荷才可进入
阻断判定。
嵌套 history/content 数组、provider content 数组中的标量成员，以及 Responses 未知或
非字符串 `type` 仍会接受扫描，但不能获得可信 user attribution；精确 Responses `type`
是传输层判别字段，不作为模型可见 prompt 文本。

启用 audit 后，来自非用户或不可信 wrapper 流量、完整且无 Cyber Abuse category 的
wrapper-only finding 默认只更新有界 `audited` 与 `control_plane_meta_override` counters，不写逐请求 SQLite event，也不计算
request/subject 关联哈希。只有需要逐请求关联时才设置 `audit.persist_wrapper_only: true`。
可信用户 wrapper finding、Cyber Abuse 基础行为、阻断、incomplete inspection 与
opaque-media 处置仍保留完整审计路径。

来自四个公开破限项目的仓库中性回归覆盖 Chat/Responses 的 system、developer、
assistant、tool、function/custom description、tool-call/output，以及 CPA v7.2.104
Codex Desktop 的 `additional_tools`。测试不加入仓库名签名，不复制完整第三方提示词，
并同时验证 1,397–17,166 解码字节长模板、16 KiB 边界、普通双用途安全请求与同身份干净后续请求。

## 默认有效上限

| 控制项 | 默认值 / 边界 |
|---|---|
| 运行模式 | `observe` |
| Subject control | 默认关闭，需显式启用 |
| CPA 可见 RPC envelope | 8 MiB |
| Classifier 保留窗口 | 旧别名默认 256 KiB；合法范围 16 KiB–1 MiB |
| 模型可见文本累计量 | 8 MiB |
| 逻辑文本字段 | 512 |
| 分类工作量 | 自动计算，最小 2048 chunks |
| JSON depth | 32 |
| 派生解码 | 最多 2 层、8 个 variants、128 KiB encoded source、64 KiB 累计保留 decoded text |

`text_bytes_scanned_total` 是累计量，可以大于 `max_scan_bytes`。峰值文本保留量
由有效窗口和固定 classifier state 控制。

如果密集 encoded 文本的派生 decoded view 超过 128 KiB encoded-source 上限，
检查仍会标记为 incomplete。这是明确保留的边界：长 plain text 可以流式扫描，但实现
不会对超限派生视图声称完整 coverage。

压缩后的 shadow planner 只保留封闭语义代表、短 marker 和有界 span metadata，
不再复制调用方可控的长 key 或长语义值。剩余分配仍会随 JSON token/node 与逻辑字段
数量增长，但受显式硬上限控制。alloc、RSS 与并发结果只以最终 Linux CI 和沙盒证据为准。

旧 `ExtractText` API 为源码兼容继续保留，并维持物化 `Parts` 的旧分段语义。
生产 Router 使用 streaming request API，不物化完整 prompt。

相关文档：

- [Streaming scanner 设计](docs/ROUND6_STREAMING_SCANNER_DESIGN.md)
- [配置迁移](docs/ROUND6_CONFIG_MIGRATION.md)
- [已知限制](docs/ROUND6_LIMITATIONS.md)
- [CI、候选构建与发行门禁](docs/ROUND6_RELEASE_GATE.md)
- [文档与工作流索引](docs/README.md)
- [开发交接](docs/ROUND6_DEVELOPMENT_HANDOFF.md)

## 支持的请求面

请求路径覆盖 OpenAI Chat、OpenAI Responses、Interactions、Anthropic Claude、
Google Gemini、OpenAI image/video profile、有界 `multipart/form-data`、
tool definition/payload、metadata 排除和 opaque media 分类。

图片、音频、视频和文档内容保持 opaque，不会解码、远程抓取或发送到其他服务。
Opaque media 的 `allow` 表示“未检查”，不表示“安全”。

确定性策略覆盖 credential theft、phishing、malware、ransomware、exploitation、
data exfiltration、service disruption 和 defense evasion。它不是通用内容审核器，
也不能替代上游 Provider 策略。

## 安全与隐私边界

- 默认情况下 Guard 不持久化原始 prompt、tool payload、Authorization header、
  明文凭证、上传代码或 Provider 账号身份。下文显式开启的
  `audit.raw_capture.enabled` 是唯一例外，并且只保存最终阻止上游路由的请求
  （`block`，包括 subject cooldown）的脱敏、有界预览。
- 这只是 Guard 本地边界，不是端到端 Host 保证。CPA 可能临时 spool 非 multipart
  请求体，并可能在 Host HTTP 错误日志中持久化原始 body；见
  [决策输出与隐私](docs/RULES.md#decision-output-and-privacy)。
- 常规审计、metrics 和 management status 只暴露固定字段、counter 与 identity，
  不暴露 prompt 片段或 offset；只有通过认证的 `/raw-captures` 路由可在启用后返回审查预览。
- 永不抓取媒体 URL，也不执行请求携带的代码。
- Round 6 未连接真实 Provider 或账号池，未读取生产请求和生产审计数据。
- 未执行四个公开对抗仓库，也未重放其原始 payload。
- CPA 在插件未加载、Router fuse/error、更高优先级 Router、invalid target 或
  Host 不认可 Executor ready 等情况下仍可能 fail-open，因此真实 Host 验证不可省略。

Round 6 的受限数据事实披露见
[开发交接](docs/ROUND6_DEVELOPMENT_HANDOFF.md)。文档不会在发生过宽源码搜索和机械
build-tag 修改的前提下声称“完全零触及”，但没有使用受限 corpus payload 或生产数据
进行实现、调参或得出结论。

## 仅拦截请求原文审查记录

`audit.raw_capture` 是供运维复核误拦的敏感功能。它**默认关闭**，依赖普通 audit
存储，并被强制限定为阻断处置（`block` 或 subject `cooldown`）；放行、observe
和仅 audit 的请求都不会记录。队列容量会在哈希、脱敏前预留；SHA-256 仍覆盖完整
原始请求，而脱敏只扫描有界的 `max_bytes + 64 KiB` 前缀/重叠窗口，随后在合法
UTF-8 边界截断。默认每条最多 8 KiB，TTL 为 72 小时。脱敏不是完整 DLP 保证，
因此 SQLite 数据目录和 CPA Management Key 都必须按生产密钥级别保护。

schema v6 迁移备份是精确回滚快照，可能保留敏感请求预览。关闭 Raw Capture
只清理活动数据库，不会删除这些备份。认证后的 `/status` 会披露不含路径的备份
数量、最早时间和敏感数据警告；删除必须使用独立的
`POST /migration-backups/purge` 路由，并提交两项精确确认。详见
[Raw Capture](docs/RAW_CAPTURE.md#migration-backup-inventory-and-explicit-cleanup)。

显式开启：

```yaml
audit:
  enabled: true
  raw_capture:
    enabled: true
    only_blocked: true
    redact_secrets: true
    max_bytes: 8192
    ttl_hours: 72
```

`only_blocked: false` 或 `redact_secrets: false` 会被配置校验拒绝。通过 CPA 已认证的
管理接口查询，可使用 `event_id`、`request_hash` 和/或 `limit`（默认 20，最大 100）：

```bash
curl -H "X-Management-Key: $CPA_MANAGEMENT_KEY" \
  "http://127.0.0.1:8317/v0/management/plugins/cyber-abuse-guard/raw-captures?limit=20"
```

CPA v7.2.104 会对旧字段 `raw_preview` 做 HTML 转义。该字段仅为旧客户端兼容而
保留，并已明确弃用；新客户端应使用规范字段 `raw_preview_b64`。Base64 只是传输
编码，不是加密或额外脱敏，解码后仍是敏感的用户原文。解码结果只能作为纯文本
渲染，禁止传给 `innerHTML`、HTML 模板或其他可执行/可解释内容的渲染器。

管理响应对完整的 CPA Host 可见 JSON body 实行固定 8 MiB 总预算。`limit=100`
仍是合法请求，但接口可能返回更少记录；应检查 `response_truncated`、
`returned_count` 和精确的 `cpa_host_response_bytes`。

在 audit 仍启用且实时关闭转换成功时，只有完成 capture 表清空和 WAL checkpoint 后，
接口才返回空列表。如果跨重启直接关闭整个 audit 子系统，旧数据库不会被自动打开或清理。
响应字段和敏感数据处理要求见[运维说明](docs/RAW_CAPTURE.md)。

## 历史 v0.15 发布前验证记录

下表和后续流程描述的是 v0.15 手工稳定版发布前审查过的 admission 设计，保留用于
审计历史；它们不是当前可用的 v0.16 工作流。

| 门禁 | 当前状态 |
|---|---|
| Round 6 实现 PR | [PR #9](https://github.com/yujianwudi/cyber-abuse-guard/pull/9) 已合并；其 PR runner 因已记录的 GitHub Billing 限制没有启动，因此不声称 PR CI PASS |
| 清理前最后一个完整验证的 `main` Push CI | [29630844605](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630844605) 对 `6782dfa` / tree `a8edbe2` **SUCCESS** |
| RC4 精确 main CI | 必须是精确 tagged `main` commit 的 `ci.yml` push SUCCESS，并绑定 run ID 与精确 run attempt；发布前重复验证 |
| 源码预发行 `v0.15-rc.1` 标签 CI | [29630926354](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29630926354) 对 `6782dfa` / tree `a8edbe2` **SUCCESS** |
| 私有无标签干净候选 Actions 产物 | **NOT CREATED / PENDING**；必须绑定最终 commit/tree 并生成 `candidate-manifest.json` |
| CPA v7.2.95 Host + Mock upstream | **NOT RUN / PENDING** |
| 独立源码、产物和 Host 审计 | **NOT RUN / PENDING** |
| 与候选绑定的外部 evaluation-v11 或更高 | **NOT RUN / PENDING**；必须是该精确候选首次且唯一的 `CONSUMED / PASS` |
| 注解标签 `v0.15-dev.round6[.N]` 预发行 | 可选；Host、独立审计、候选级评估通过前阻断，且永远不是正式发行 |
| 公开源码预发行 `v0.15-rc.1` | 已存在但没有附加资产；不是私有候选、Host 证据或正式发行 |
| 历史带资产预发行 `v0.15-rc.2` | **PUBLIC / PRERELEASE / SANDBOX ONLY**；通过直接所有者覆盖发布十项 Linux amd64 资产并跳过测试 |
| 受保护的 `v0.15-rc.3` 尝试 | **FAILED / UNPUBLISHED / ZERO ASSETS**；工作流 [29728286559](https://github.com/yujianwudi/cyber-abuse-guard/actions/runs/29728286559) 通过 admission 后在打包前失败，publish 被跳过且没有创建 Release |
| 正式结构 `v0.15-rc.4` 预发行 | 精确 17 项 Linux amd64 资产；完整内部门禁与可复现构建必须通过，真实 Host、独立审计/评测、正式发布与生产授权仍缺失 |
| 注解标签 `v0.15` | 已于 2026-07-20 手工发布为 stable；未使用受保护 draft/promotion 链 |
| 受保护地发布未变化 draft | 实际 v0.15 发布未使用该流程 |

Windows 和 macOS 有意不出现在本轮矩阵中。缺少它们不是 Linux-only 任务的失败，
也不得被描述成已有测试覆盖。

安全 Round 6 入口见
[ROUND6_RELEASE_GATE.md](docs/ROUND6_RELEASE_GATE.md)。不要用宽泛
`go test ./...` 或 `go vet ./...` 替换 allowlist 门禁，以免编译或打开已消费的
evaluation 包。

在手工发布之前，审查流程要求外部门禁通过前不得创建 `v0.15`。该指令现在仅是历史
记录；已发布的 v0.15 资产仍不得用作 v0.16 证据。已消费 v10 保持不可重跑。

## 产物契约

历史 v0.15 发布前证据链原计划拆分如下：

1. 冻结最终 PR head、通过 PR CI、合并到 `main`，并让合并后精确 main commit/tree
   的 Push CI 通过。合并只是 candidate 前置条件，不是部署或发行批准。
2. 从 `main` 手动 dispatch 私有、**无标签**的 GitHub Actions 运行，从干净精确源码生成 Linux amd64
   候选字节；该 Actions artifact 不是 GitHub Release，且会过期。
3. CPA v7.2.95 Host + Mock 记录、独立审计，以及与候选
   绑定的外部 `evaluation-v11` 或更高 `CONSUMED / PASS` 报告，必须绑定同一候选身份。
   Host 身份和证据哈希通过 attestation schema v2 的 `cpa_version`、
   `cpa_commit`、`cpa_host_sha256` 字段传递。
4. 如需持久开发交接，上述门禁通过后，可使用既有注解标签
   `v0.15-dev.round6`（或数字后缀）创建 draft prerelease；它仍是
   `BLOCKED / NOT A FORMAL RELEASE`。
5. 只有该候选级外部评估 attestation 才能准入注解正式标签 `v0.15`。正式工作流
   重建并逐字节比对 Host 已测候选，生成
   `formal-release-attestation.json` 并创建 draft 正式 Release；另一个受保护 promotion
   步骤才发布这份未变化的 draft。

私有候选包含 `cyber-abuse-guard-v0.15.so`、sidecar、
`cyber-abuse-guard_0.15_linux_amd64.zip`、metadata、checksums、ruleset identity、
SBOM 与 `candidate-manifest.json`。Store ZIP 根目录恰好一个 `.so`。Audit bundle 与
source archive 只属于后续正式发行路径。候选字节即使干净，也仍未发布且不授权部署。
正式 source / audit bundle 必须排除 evaluation、Holdout、private、blind、retired
资料，只携带允许公开的低敏 attestation 身份与哈希。

源码树刻意不自我回填未来 Host/审计 PASS 哈希、Merge 身份或 Release 状态。稳定版
v0.15 是否具备资格，只能由外部 Round 6 / formal attestation 资产判定；这些资产必须绑定
最终源码、候选工作流运行、候选字节、Host 记录、独立审计与发行评估。

实际 2026-07-20 的 v0.15 发布没有完成上述受保护链；所有者报告的沙盒结果与手工构建
披露只存在于 GitHub Release Notes，本仓库不会把它升级成独立证据。

第八轮预发行目标固定为 CPA v7.2.95 / `f71ec0eb6776854457892452cf28c47f0d658251`。
后续上游版本不会自动改变受支持或可准入发行的目标；更早观察仅作为
不可执行历史记录保留，不属于当前发行或 Host 证据。

历史 evaluation-v10 始终为 `CONSUMED / FAIL`，不得重跑，也不得作为 formal build 输入。

中立源码策略见 [RELEASE_POLICY.md](docs/RELEASE_POLICY.md)。外部决策记录为
`round6-prerelease-attestation.json` 与 `formal-release-attestation.json`；源码树不会预先
把它们写成未来 PASS。

## 仓库结构

| 路径 | 用途 |
|---|---|
| `cmd/cyber-abuse-guard/` | 原生插件入口和 CPA ABI bridge |
| `internal/classifier/` | 确定性策略和 streaming classifier |
| `internal/extract/` | 事务式请求遍历、流式文本回放、解码、role、multipart 与媒体处理 |
| `internal/plugin/` | Router、Executor、disposition、management、health 与 reconfigure |
| `internal/audit/` | 隐私最小化 SQLite event、schema migration、retention 与 subject state |
| `integration/` | CPA 源码/编译与 Host 契约模块 |
| `scripts/` | 安全门禁、Linux 构建、打包、验证和可复现工具 |
| [`docs/README.md`](docs/README.md) | 架构、运维、策略、当前发行交接与历史报告的文档索引 |

历史 Round 5.2 证据仍保留在
[AUDIT_HANDOFF.md](docs/AUDIT_HANDOFF.md)、
[TEST_REPORT.md](docs/reports/TEST_REPORT.md) 和
[RELEASE_EVIDENCE.md](docs/reports/RELEASE_EVIDENCE.md)，但不能验证 Round 6 候选。

## 安全问题报告

请遵循 [SECURITY.md](SECURITY.md)。Issue 中不得包含真实凭证、私有 prompt、
OAuth 材料、生产请求内容或账号标识。

## 许可证

[MIT](LICENSE)
