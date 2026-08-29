# Cyber-Abuse-Guard Next 第十七轮完善任务书与验收标准

> 状态：执行中（2026-08-29）。本文件是 v7.2.145 新兼容轮次的活动任务书。
> 旧 Round 16 / CPA v7.2.144 的活动正文已由本轮覆盖；其中冻结的历史段、回执和结果
> 保持原身份，不得转移为本轮证据。现有 `round16_*` 字段名仅因解析器兼容而保留。

## 1. 目标与边界

本轮目标是将 Cyber-Abuse-Guard Next 的 Linux amd64 CPA 插件兼容目标升级到
CLIProxyAPI v7.2.145，完成全项目安全/隐私/误报/性能审计，修复审计发现的问题，
在全新隔离的二号机环境执行精确候选验证，随后通过受保护流程合并 `main`，清理
非 `main` 分支，并创建正式 prerelease `v1.0.0-rc.3`。

本轮不读取、保存、生成或执行真实 CSAM、露骨材料、真实用户请求、Provider/OAuth
凭据或不受信任的第三方破限仓库代码。CSAM 仍只覆盖合成、非露骨的文本意图回归；
媒体本体识别不在本轮范围。二号机只使用隔离 CPA、Mock upstream、临时数据库和
临时网络。为验证插件 ABI/Host 兼容性，允许在无凭据、无真实 Provider、固定校验和
且有界的 Linux 沙盒内执行官方 CPA v7.2.145 自带测试；这类“受信依赖测试执行”与
五个破限仓库的惰性文本审查严格区分，不能计入 third_party_code_executions。

## 2. 已知审计基线（必须先记录）

| 项目 | 当前基线 | 风险/处理 |
|---|---|---|
| 工作树 | `audit/cpa-v7.2.145-rc3`，含上一轮 metadata-only 合成语料契约 | 作为本轮候选起点，禁止混用旧候选 |
| 旧 PR | #31（v7.2.144）required checks 已通过但未合并 | 不把旧 PR 结果转移为本轮 PASS |
| 保护分支 | `main` 启用 strict required checks：quality-and-artifacts、fuzz-long、reproducibility、Analyze Go on Linux、round9-policy-and-corpus | 必须走 PR/squash merge，不使用 admin bypass |
| 远端分支 | 存在旧 CPA142/144 审计分支及失败 Dependabot 分支 | 新 main 全绿后按治理策略删除，仅保留 `main` |
| 当前发布 | 无 v1.0.0-rc.3 Release；rc.1/rc.2 为不可变历史标签 | 本轮重新生成候选资产和证据 |
| Realtime | `/v1/realtime*` 当前绕过 CAG RequestInterceptor/生命周期 | 继续明确标为 OUT_OF_SCOPE/UNPROTECTED，不得扩大覆盖声明 |
| 本地平台 | Windows/386 无法提供 cgo/SQLite/race 证据 | Linux amd64 CI/二号机为权威验证环境 |

## 3. CPA v7.2.145 固定身份

| 字段 | 固定值 |
|---|---|
| tag / commit | `v7.2.145` / `d9cea8904b14fbbebb77ef26e98ef08f6b48a724` |
| Go module | `github.com/router-for-me/CLIProxyAPI/v7 v7.2.145` |
| module sum | `h1:5AG1q4MhRK+IU5oP5PPvm04AJYvEkj60br85jiBan5o=` |
| go.mod sum | `h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=` |
| C ABI / RPC schema | `1 / 4` |
| Linux amd64 archive | `CLIProxyAPI_7.2.145_linux_amd64.tar.gz` |
| archive bytes / SHA-256 | `21226153` / `ffb59d406af9b849ec9174154d96642a1d3ccb315f8687c56ac55202816e9b37` |
| checksums bytes / SHA-256 | `1094` / `df71c910a0ceb83f67ada7c193a1b2d87f1bae955929d4a1d18fb4cf7f4b9d7c` |
| contained binary bytes / SHA-256 | `64207528` / `576a0555e5180c48a5cdf51ee92047a6ab78c363dfe612ea75925ba7f1ae1713` |

v7.2.145 的 SDK ABI/schema 源合同与 v7.2.144 相同；本轮仍必须重新编译和验证，
不能因为接口未变而复用旧 `.so`。上游行为变化（home 端口解析、管理 auth 规范化、
Gemini tool array `items` 补全、scheduler successor 保持、HTTPS proxy ALPN）必须
分别执行回归，且不得改变 CAG 的阻断副作用和隐私边界。

## 4. P0：身份、供应链与兼容性

1. 根模块及两个 integration module 精确固定 v7.2.145，`go mod verify`、
   `go mod tidy -diff` 和完整 module provenance 通过。
2. `scripts/cpa-latest-compat.sh`、CI、发布脚本和 active 文档只接受上表 tag、
   commit、sums、资产 bytes/SHA；旧 v7.2.144 只能出现在明确历史正文。
3. C ABI 1、RPC schema 4、header-init/body chunk 分流、注册/quiesce/reconfigure/
   shutdown 生命周期合同全部重新验证；不得注册未实现的 response/WebSocket observer。
4. v7.2.145 的 CPA Host、Store、Interactions、request logging、rewritten tool
   schema 和 native `.so` 加载测试必须绑定同一候选身份。
5. 官方资产下载必须校验 Git tag、Release API digest、checksums 行、归档内容、ELF
   架构/GLIBC 和二进制 SHA；不执行不受信任仓库代码。CPA 兼容脚本必须固定
   Linux/amd64、清理 Git 路由环境，并对每个外部 Go 命令和整条兼容 lane 设置硬上限
    （默认单命令 5 分钟，允许范围 1 秒–10 分钟；完整 cpalatest 命令单独 10 分钟；
    整 lane 25 分钟；上限分别为 10/45 分钟）。RC 发布验证中的 Store 回归也必须
    使用 `GOTOOLCHAIN=local`、只读 module 模式和 5 分钟硬超时。
    脚本同时强制 `GOENV=off` 与 `GOPROXY=https://proxy.golang.org,direct`，避免调用方
    `go env -w` 或环境变量重定向模块/工具链解析。

## 5. P1：安全、误报、隐私与性能

### 5.1 请求与破限载体

- 继续覆盖五个公开破限仓库及补充 `Codex全破.zip` 的最新只读提交；只提取有界
  文本/元数据，不执行代码，不保存正文，最终清理所有临时目录。官方 CPA 测试是
  独立的固定依赖验证，不属于这五个仓库的代码执行。
- 覆盖 system/assistant/tool/history、伪造 AGENTS/技能/MCP、分段拼接、HTML 注释、
  URL/Unicode/percent/base64 载体和 Responses 工具 schema 重写边界。
- 恶意候选必须在 Auth/Provider/Executor/Usage/Mock 前阻断；普通、防御、研究和授权
  请求必须到达 Mock，且不因单个关键词或仓库名被拦截。

### 5.2 CSAM 文本边界

- 仅使用合成、非露骨、无真实人物/年龄/地点/链接/媒体/Base64 的文本占位样本。
- 15 个高风险意图样本：Balanced/Strict 阻断率 100%，Audit 检出率 100% 且不阻断。
- 21 个保护性 benign 样本：三种模式放行率 100%，CSAM winner/label 为 0，误拦为 0。
- 新增 metadata-only `testdata/csam-text-synthetic-v1` 只作为开发边界回归，不能冒充
  独立盲测或二号机 CSAM 证据；manifest 不得含原文、媒体或可逆编码。

### 5.3 审计隐私与副作用

- 默认只记录有界决策元数据、哈希和低基数计数；Raw Capture 必须显式开启、脱敏、有界、
  TTL 生效，CSAM 私有文本永不持久化。
- 结构化不完整或未知格式的 block 同样只写元数据事件，不进入 Raw Capture；这避免
  未被完整审查的原文因 Strict 处置而落盘。完整 `opaque_media` block 也不落盘，
  因为媒体本体未被 CAG 解码审查。
- block 后 Provider/Auth/Router/Executor/Usage/SSE/Mock delta 必须全为 0；allow 只产生
  唯一预期调用；存储失败不得改变分类结果。
- 所有审计证据绑定精确 commit/tree/SO/CPA 身份，缺失、过期或混合身份一律 fail-closed。
- before/after 生命周期缓存必须对 request ID、源格式、有效客户端请求模型、流标记、
  headers 和 body 做域分离指纹。有效模型优先取 CPA 的 `RequestedModel`（客户端意图），
  仅在该字段为空时回退到 `Model`；CPA 认证后填充/改写的选定 `Model`、`ToFormat`，以及
  不被 CAG 分类器或审计投影消费的 best-effort `metadata`，均明确排除，避免正常
  after-auth 回调重复分类。任一纳入字段无法在有界预算内编码时禁用缓存并重新分类，
  不得把不可验证的回调当作已审查。该排除边界必须由“选定模型改写/metadata 变化仍命中、
  客户端 RequestedModel 变化失效”的回归测试锁定。
- `CallOversized` 与普通 RPC 入口必须共享 `plugin.quiesce` 生命周期门禁；热替换排空后，
  oversized model/interceptor/executor 回调不得再次触碰退役 runtime，也不得写入重复的
  incomplete-inspection 事件。注册/重配置仍是唯一恢复路径，并须有回归测试覆盖所有模式。
- 生命周期检查必须在 `opMu` 读锁内再次确认 quiesce 状态，覆盖回调通过快速入口检查后
  排队等待写锁的 TOCTOU 窗口；被排空的回调只能返回 quiesced 处置，不得进入退役 runtime。
- 启用主体风险持久化时，`plugin.quiesce` 只有在最终快照写入成功且未处于
  `writes_blocked/degraded` 状态时才可报告成功；快照失败必须保持 quiesced 并返回错误，
  防止 CPA 退休实例时静默丢失风险状态。

### 5.4 性能与稳定性

- Linux amd64 并发 1/4/16、large payload、300 秒 soak、3600 秒 warm-RSS、队列和 SQLite
  durability 全部完成；对比 v7.2.144 基线时记录 p50/p95/p99、RSS、错误率和副作用。
- 不得以“进程启动”替代健康检查；必须检查 root、`/v1/models` 未授权 401、CPA/Mock/SQLite、
  restart=0、OOM=false、网络隔离和清理收据。

## 6. P2：治理、文档与发布

1. 新增/更新 Round17 活动状态、CPA 集成、测试报告、发布证据和 README；所有历史 Round
   14/15/16 正文保持不可变并显式标注不可转移。
2. active workflow 保持四个且只允许受审计的 YAML；任何 workflow hash/权限/触发器漂移先
   修合同再继续，不能用跳过或 waiver 绕过门禁。
3. 精确候选 PR 的 required checks 全绿后 squash merge 到 `main`；重新等待新 main 的全部
   checks，不把 PR synthetic merge 结果转移为 main 证据。
4. 只在新 main 与二号机 v3 staging admission 均 PASS 后删除远端/本地非 main 分支，保留
   不可变历史 tag。
5. 由授权维护者在合并后的精确 main 提交上预先推送一次 GitHub-verified signed
   annotated tag `v1.0.0-rc.3`（不可移动、不可删除）；受治理的 release workflow
   只从该 tag 做只读绑定、验签和发布，发布为 prerelease、非 latest。资产、checksums、
   SBOM、provenance 和签名身份必须闭合；若 tag 不存在或验证不通过，发布保持阻断。
   首次 dispatch 前还必须确认同名 Release（包括 draft）不存在；发布流程发生部分
   写入后不得删除或改写不可变 Release/tag，需按新的 RC 编号重新走完整门禁。

## 7. 验收总表

| 门禁 | PASS 条件 | 禁止替代物 |
|---|---|---|
| 源码/模块 | v7.2.145 精确身份、三模块 verify/tidy、Linux 编译通过 | 本地 Windows 编译或旧模块缓存 |
| 单测/静态 | unit/vet/race、fuzz、CodeQL、Safe Gate、secret scan 全绿 | `continue-on-error`、retired skip 冒充 PASS |
| 语料 | 五仓+ZIP 最新身份、0 第三方执行、清理完成；CSAM 15/15 与 benign 21/21 | 旧轮次报告、开发可见集冒充盲测 |
| Host | 精确候选 `.so` + CPA v7.2.145，健康、请求/阻断/热替换/回滚/Usage/隔离全绿 | synthetic fallback、仅进程启动 |
| 性能 | 300/3600 soak、paired cells、RSS/队列/SQLite 指标在阈值内 | 未完成采集、单次手工请求 |
| 合并 | 受保护 PR squash 到新 main，新 main required checks 全绿 | admin bypass、旧 PR 状态转移 |
| 分支 | 本地和远端只剩 `main`（历史 tag 保留） | 删除前未确认 merge/引用 |
| 发布 | signed annotated `v1.0.0-rc.3`、prerelease/non-latest、资产哈希/证明一致 | 手工上传、unsigned/lightweight tag、旧候选资产 |

## 8. 失败处理

任何网络中断、资产 hash 不一致、CPA schema/ABI 漂移、CI 取消、二号机报告缺失/过期、
性能采集超时、清理不完整或发现真实/露骨材料，均保持 `BLOCKED/PENDING`，保存不含
正文的错误 ID、stderr 摘要和哈希，修复后从同一精确候选重新开始。不得把部分 PASS
改写成整体 PASS，也不得为了发布放宽误报、副作用或隐私门槛。

## 9. 本地自检回执更新

当前仓库自检回执为 `316/316 PASS / ZERO_SKIPS`。回执子进程使用显式的
loader/credential-free 环境白名单（仅保留 `PATH`、locale、`PYTHONDONTWRITEBYTECODE`
和固定 `GOTOOLCHAIN`），以避免宿主的动态加载、Shell 启动、代理或凭据变量改变审计
结果。该回执仍是未签名的开发自检，不能替代精确提交的 GitHub CI、二号机或独立证明。

## 10. 本轮审计修订记录（2026-08-29）

- 修复 CPA v7.2.145 before/after 生命周期指纹误把认证后选定 `Model` 和
  best-effort `metadata` 当成决策输入的问题。当前实现使用有效客户端模型
  （`RequestedModel`，为空时才回退 `Model`），并对选定模型改写、metadata-only
  变化、客户端模型变化分别有回归覆盖；对应的 after-auth 重复分类故障不得再以旧
  CI 结果掩盖。
- 加强 RC workflow 的 required-job 校验：每个 required context 必须恰好出现一次，且
  唯一 job 必须 `completed/success`；同名失败 job 不得被成功副本掩盖。RC Store 回归
  另外绑定 `GOTOOLCHAIN=local`、只读 module 模式和 5 分钟超时。
- 加强 CPA 远端 tag 供应链查询：禁用 Git 全局/系统配置、URL 重写、交互式凭据 helper
  和终端提示；远端 identity 仍只接受本任务书第 3 节的 v7.2.145 固定值。
- CPA v7.2.145 Host 源码当前会记录 `plugin.quiesce` 失败但继续替换流程；CAG 仍必须
  在持久化快照失败时保持 quiesced 并返回错误，二号机报告必须明确记录该上游语义，
  不得宣称 Host 已因该错误自动回滚。若实际准入需要“失败即不替换”的强保证，必须先
  取得带该修复的 CPA 版本或由部署编排层提供门禁；本 RC 不以文档推断替代运行证据。
- 生命周期 `RequestID` 现在限制为最多 256 个 UTF-8 字节且拒绝控制字符；超限或非法
  ID 不得进入缓存，完成回调同样拒绝该值，以防 Host 输入放大生命周期内存。Raw Capture
  脱敏键覆盖通用 `token`、`id_token`、`oauth_token`、`credential(s)` 和 `private_key`
  变体，并由回归测试验证不泄露这些值。
- Raw Capture 补偿校验现在要求新连接看到的行集与删除前快照严格相等；额外行（包括
  空快照时出现的任何行）会使补偿失败并保持写入熔断，不能被成功前缀匹配掩盖。
