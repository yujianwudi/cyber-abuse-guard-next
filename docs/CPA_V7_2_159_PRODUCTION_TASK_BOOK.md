# CPA v7.2.159 生产化完善任务书

状态：执行中（发布阻断项未全部关闭）  
适用分支：`compat/cpa-v7.2.159`，合并目标：`main`  
活动兼容边界：CLIProxyAPI `v7.2.159@ac02da6c05e18f465aa7e3ed5b0a65a2f060917d`，C ABI 1，RPC schema 6，Linux amd64。

## 1. 审计结论

本轮审计确认活动 CPA 159 的模块、schema-6 Host 合同、Raw Capture 字节计数和审计工具身份已统一；`tools/current-cpa-audit` 的 362 项 Python 测试通过（38 项按环境/外部证据跳过）。审计还发现并纳入本任务的回归：

- Round 13 历史发布合同的 SHA-256 必须保持不可变，CPA 159 的变更只能出现在活动 Round 16 overlay。
- 文档一致性 fixture 的 Round 16 active pins 必须显式更新；Round 6 的历史 hash 常量仍保持冻结，不能静默覆盖。
- Round 9 报告解析必须接受 Linux/Windows checkout 的 CRLF，同时仍严格验证历史 v10 身份；不能把当前 classifier-policy-v20 冒充 Round 9 证据。
- 0400 备份权限是 Linux 安全合同；Windows 不具备等价 POSIX 语义，相关测试仅在 Linux runner 验收。
- `/v1/realtime*` 不经过 CAG 回调，发布说明必须继续标为 OUT_OF_SCOPE/UNPROTECTED，并要求外部鉴权、限流和隔离。

## 2. 实施范围与优先级

### P0：发布阻断

1. 在 Linux amd64 runner 上重新核验 CPA 159 官方归档、内置 binary、module/go.sum、ABI/schema 和 SHA-256。
2. 运行真实 CPA schema-6 Host/Store `.so` 加载与生命周期合同；禁止用 synthetic/mock 结果替代。
3. 生成绑定候选 commit/tree 的第二机器 admission 报告，并在发布前检查有效期、同一候选和清理证明。
4. 仅当所有 required checks 通过、PR 合并到 `main`、候选源码 clean 且证据未过期时创建正式发行版 `v1.0.0`；失败必须 fail closed。

### P1：合同与安全边界

1. 恢复 Round 13 冻结 hash，活动变更通过 Round 16 mapping 显式覆盖。
2. 保持 CPA v7.2.159/schema 6 的 request lifecycle、Raw Capture 和 fail-open 合同一致。
3. 将 Round 9 历史报告身份与当前 classifier-policy-v20 隔离；任何候选身份、规则集或 schema 漂移都必须拒绝。
4. 继续禁止执行外部 ZIP/安装器；第三方压缩包仅做静态 hash、路径和脚本审查。

### P2：可维护性

1. 保持活动文档只声明 v7.2.159，旧 CPA 仅作为冻结历史证据。
2. CI 只保留当前所需 workflow 和显式 required checks；历史脚本只能作为回归合同，不得成为活动版本来源。
3. 分支清理在 PR 合并后执行，仅保留远端 `main`；不得删除 `main` 或未合并的审计证据。

## 3. 不在本任务范围内

- 不声称 CAG 覆盖 `/v1/realtime*`；该路径仍需 CPA 外部网关策略保护。
- 不在 Windows 上宣称 Go、CGO、Linux Host 或 `.so` 集成通过。
- 不把四个破限仓库、外部 ZIP 或模型输出当作可信安装输入；测试只验证隔离、计数和拒绝合同。

## 4. 变更验收顺序

先修复 P1 合同回归，再执行本文件的验收清单；任何 P0 未关闭都不得打 stable tag、创建 Release 或删除当前兼容分支。
