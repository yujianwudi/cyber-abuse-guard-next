# Cyber-Abuse-Guard Next

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: 1580f71d77cbb4bf58d3a734ae3a3994dfe2472478ed5f2dc1f18c86fa004b2d
```

[English](README.md) | 简体中文

## 项目身份

```text
current_source_version: 1.0.0
current_rc_tag: v1.0.0-rc.1
current_cpa_target: v7.2.137 / 85d2faddd17e6f4f8675a84ee28b131f702e8eaa
current_cpa_contract: C_ABI_1 / RPC_SCHEMA_3
current_cpa_module_sum: h1:CYYByMn7/NwnsCJEMiLI2F8kIJMTb5jRrLaIK6H0c0w=
current_cpa_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
current_platform: linux-amd64
current_audit_sqlite_schema: 7
current_csam_text_policy: csam-text-policy-v1 / c338d97927489237c5413574489febbaa0468154ba61e8012fd1ecfcfc5a120f
current_second_machine_release_admission_schema: cyber-abuse-guard.second-machine-release-admission.v3
current_active_workflows: 4 / ci.yml / codeql.yml / policy-gate.yml / release-rc.yml
current_status: MAIN_MERGED / ENGINEERING_CI_PASS / SECOND_MACHINE_CANCELLED / RC_BLOCKED
```

Cyber-Abuse-Guard Next（CAG）是面向
[CLIProxyAPI（CPA）](https://github.com/router-for-me/CLIProxyAPI) 的本地、确定性、
路由前请求风控与审计插件。项目目标是降低网络滥用风险，同时保护普通编码、
防御性安全、事件响应、合规和授权运维请求不被关键词误伤。当前唯一维护分支是
`main`，唯一兼容目标是 CPA `v7.2.137` / RPC schema 3。

当前源码已经合并到 `main`，合并后的 Linux CI 也已通过。`v1.0.0-rc.1` 尚未发布：
发行合同要求独立的二号机准入报告，而本轮二号机测试已由操作者取消。不能用旧候选、
本地回执或历史 PASS 替代该证据。

## 请求处理链路

```text
CPA schema-3 请求
      |
      v
before-auth RequestInterceptor
      |
      +--> 有界解析、role/provenance 归一化
      |          |
      |          v
      |    流式分类会话
      |          |
      |          +--> policy winner / coverage / explanation
      |          +--> 有界审计事件与计数器
      |
      +--> allow / observe / audit / balanced block / strict block
      |
      v
CPA 认证 -> Provider/Router -> Usage/SSE/上游
```

主要 Go 包按信任边界划分：

- `internal/extract`：解析 JSON、multipart 和流式字段，保留逻辑字段、角色和来源；
- `internal/classifier`：有界流式规范化、语义匹配、winner 排序和策略身份校验；
- `internal/csamtext`：仅文本 CSAM 策略和良性保护性输出回归，不读取真实媒体；
- `internal/plugin`：CPA 回调、处置、生命周期、审计持久化、管理状态和失败关闭；
- `internal/audit`：SQLite schema 7、保留策略、readiness 和 Raw Capture 控制；
- `internal/subject`：有界主体标识与风险状态，不代替 Provider/OAuth 决策；
- `rules`：嵌入式策略清单；`cmd/`：插件入口与开发期校验器。

## 模式与误伤控制

安全启动默认值是 `mode: observe`、主体控制关闭：

| 模式 | 完整且有害请求 | 覆盖不完整 |
|---|---|---|
| `off` | 放行 | 放行 |
| `observe` | 仅观测 | 放行 + observe |
| `audit` | 仅审计 | 放行 + audit |
| `balanced` | 达到审查阈值才阻断 | 放行 + audit |
| `strict` | 达到 strict 阈值才阻断 | 失败关闭 + audit |

普通请求、防御性分析、授权运维都是一等回归输入。单个风险词、仓库名或安全术语
不会自动触发阻断；必须满足有界语义、所有权和来源合同。模糊、跨字段或覆盖不完整
的证据不能被无关 carrier 提权，这是降低误伤的核心边界。

## 审计、隐私与 CSAM

审计事件只保存有界决策元数据、coverage、explanation 和低基数计数器，默认不保存
完整请求原文。Raw Capture 需要显式开启，并受权限、脱敏、保留期和容量控制；存储
失败不会改变分类结果。

CSAM 检测只处理文本策略。预防指南、热线/平台通知、举报说明和安全研究引用均有
良性回归；仓库测试不需要真实媒体、Provider 凭据、OAuth 会话，也不执行第三方代码。

## CPA 与 Host 兼容性

当前固定目标为 CPA `v7.2.137@85d2faddd17e6f4f8675a84ee28b131f702e8eaa`、C ABI 1、
RPC schema 3。schema 3 仅在 header-init 保留 `OriginalRequest` / `RequestBody`，
payload chunk 不重复携带；插件不注册 successful-response 或 stream-chunk interceptor。

Host 性能采集仅支持 Linux。Docker Engine API 使用有界 v1.44 读取；队列采样在每个
测量 cell 复用一条私有 HTTP/1.1 管理连接，拒绝公网目标、服务端主动关闭、畸形/超大/
非严格 JSON，并在异常时失败关闭。100ms cadence、样本数、deadline 和阈值不变。

受保护 evaluator 必须使用 internal-only Docker 网络，不向 Host 发布 CPA 或 counted-Mock 端口，
并记录 `host_ip=internal-only, host_port=0, container_port=8317`。Host 只能访问经 Docker
inspect 验证、彼此不同的两个 RFC1918 bridge IPv4；任何 Host binding、额外容器或非内部网络均不准入。

## Linux amd64 构建

需要 Go 1.26.6、Linux amd64 工具链、CPA v7.2.137，以及支持 C ABI 1 / RPC schema 3 的 CPA loader。

```bash
git clone https://github.com/yujianwudi/cyber-abuse-guard-next.git
cd cyber-abuse-guard-next
make round6-format-check round6-module-verify
make unit-test
make build-linux-amd64
```

产物为 `dist/cyber-abuse-guard-v1.0.0.so`。安装前必须确认 CPA 管理状态和 ABI/schema，
不能把其他 CPA 版本编译的 `.so` 混用。

## 验证命令

仓库 Linux 审计工具当前固定为 `315/315`、zero skips；GitHub CI 还执行 Go unit/vet/race、
有界 fuzz、策略/语料、依赖漏洞、Linux Host `.so` 加载和 reproducibility。仓库回执是可追溯
记录，不是独立证明。

```bash
python3 -I -B -m unittest discover -s tools/current-cpa-audit/tests -p 'test_*.py'
bash scripts/release-doc-consistency.sh
python3 -B scripts/round6_safe_gate_contract.py --root .
make repository-secret-scan
```

五仓和 supplemental ZIP 测试按身份绑定、分母隔离且不执行第三方代码。二号机测试取消后，
它不能关闭 RC 发行门禁。

## 仓库布局与归档原则

| 路径 | 用途 | 生命周期 |
|---|---|---|
| `cmd/` | 插件入口和校验器 | 当前维护 |
| `internal/` | 运行时、分类器、审计和 CPA 集成 | 当前维护 |
| `rules/` | 嵌入式策略清单 | 当前维护 |
| `tools/current-cpa-audit/` | Linux 审计、Host 和 admission 合同 | 当前维护 |
| `testdata/` | 有版本、带摘要的回归夹具 | 被测试/证据引用时保留 |
| `docs/` | 架构、治理、状态和证据 | 当前文档 + 明确历史标记 |
| `docs/archive/` | 退役 workflow 与历史说明 | 只读归档，不是执行入口 |
| `.github/workflows/` | 四条受审 workflow YAML | 仅索引中的文件有效 |

旧测试夹具只要仍证明身份、回滚边界或证据不可转移，就不是无用文件；未经版本化不能
随意移动。退役 workflow 已放在 `docs/archive/workflows/`，归档索引是唯一地图。生成的
报告、凭据、请求原文和本地 `_cag_*` 辅助文件不应进入 Git。

## 关键文档

- [第十四轮任务书](docs/ROUND14_CPA_V7_2_130_SCHEMA3_TASK_BOOK.md)
- [第十四轮执行与 RC 验收](docs/ROUND14_EXECUTION_AND_RC1_ACCEPTANCE.md)
- [第十四轮状态](docs/ROUND14_STATUS.md)
- [发行策略](docs/RELEASE_POLICY.md)
- [仓库治理](docs/REPOSITORY_GOVERNANCE.md)
- [安全策略](SECURITY.md)
- [归档索引](docs/archive/README.md)

Release workflow 失败关闭，只有所有适用验收门禁通过后才能发布。旧 PASS、本地回执和
历史 CPA 结果均不能替代新的精确候选和所需准入证据。

<!-- 下方第十二轮状态仅保留为 CPA v7.2.124 历史证据 -->
<!-- 历史证据位于 docs/ROUND12_STATUS.md，不代表当前发行状态。 -->
