# Cyber-Abuse-Guard Next 第十七轮 CPA v7.2.145 完善任务书（兼容路径保留）

状态：`ACTIVE / IMPLEMENTATION AND ADMISSION PENDING`

## 1. 权威身份

```text
source_version: 1.0.0
candidate_release: v1.0.0-rc.3
platform: linux-amd64 only
go_toolchain: go1.26.6
cpa_version: v7.2.145
cpa_commit: d9cea8904b14fbbebb77ef26e98ef08f6b48a724
cpa_module_sum: h1:5AG1q4MhRK+IU5oP5PPvm04AJYvEkj60br85jiBan5o=
cpa_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
cpa_linux_amd64_asset_bytes: 21226153
cpa_linux_amd64_asset_sha256: ffb59d406af9b849ec9174154d96642a1d3ccb315f8687c56ac55202816e9b37
cpa_linux_amd64_binary_bytes: 64207528
cpa_linux_amd64_binary_sha256: 576a0555e5180c48a5cdf51ee92047a6ab78c363dfe612ea75925ba7f1ae1713
cpa_checksums_sha256: df71c910a0ceb83f67ada7c193a1b2d87f1bae955929d4a1d18fb4cf7f4b9d7c
cpa_c_abi: 1
cpa_rpc_schema: 4
```

已有 `v1.0.0-rc.1` 和 `v1.0.0-rc.2` 为不可变历史 tag，不能移动、删除或复用。
因此本轮合法候选仍是 `v1.0.0-rc.3`，不得通过管理员绕过或手工资产上传改变这一事实。

## 2. 目标与范围

1. 全面审计当前项目的源码、配置、生命周期、CI、发行和证据闭包。
2. 将所有活动依赖和兼容合同精确升级到 CPA v7.2.145，历史证据保持冻结。
3. 复验 `plugin.quiesce`、成功热替换、失败替换回滚、请求副作用和管理状态。
4. 维持正常用户零误伤优先：普通编码、防御分析、合规、授权测试必须放行。
5. 使用只读、惰性、非执行语料处理五个公开仓库与补充 ZIP；不执行第三方代码。
6. 完成 Linux 性能、race、fuzz、SQLite、Raw Capture 隐私和清理验证。
7. 全部门禁通过后 squash merge 到 `main`，删除非 main 分支，并由受治理 workflow
   创建不可变 prerelease `v1.0.0-rc.3`。

## 3. P0 工作项

- 三个 Go module 精确固定 v7.2.145 及模块校验和。
- CPA source/pluginhost/Store/Interactions/Realtime 合同重新编译并测试。
- v7.2.145 官方 Linux 资产和二进制逐字节校验。
- CAG 注册、quiesce、reconfigure rollback、shutdown 和 in-flight drain 回归。
- 二号机使用全新隔离目录；禁止复用旧服务、数据库、Provider/OAuth 或生产配置。
- 普通请求必须到达 counted Mock；恶意请求必须在 Mock/Auth/Provider 前阻断。
- CI、CodeQL、Policy/Corpus、fuzz、reproducibility 均不得跳过或降级。

## 4. P1/P2 工作项

- 五仓库与补充 ZIP 的最新 HEAD 只读身份获取、标签复核和有界执行矩阵。
- Balanced 正常语料误报为零；保护性 CSAM 文本、引用分析和审计请求不得误拦。
- 并发 1/4/16 性能、300 秒 soak、队列、RSS、SQLite durability 和无残留清理。
- README、SECURITY、LIMITATIONS、发行证据和任务状态只声明精确候选已验证结果。
- 清理仓库分支和无用工作流只能在新 main 全绿后执行。

## 5. 验收标准

### 代码与合同

- 根模块及两个 integration module 均为 v7.2.145，`go mod verify` / `go mod tidy -diff` 通过。
- C ABI 1、RPC schema 4、官方资产大小和所有 SHA-256 与上方身份完全一致。
- schema 4 的 `websocket.response_event` 能力边界明确：CAG 不注册该上游观察器，
  不把响应观察误称为请求前阻断或 `/v1/realtime*` 覆盖。
- quiesce 单测及 race 子集通过；成功 hot reload 与失败 rollback 都保持服务可用。
- 配置漂移 rollback 被拒绝；shutdown 后不能恢复；审计 flush 有界且不丢已接受事件。

### 安全与误报

- 正常开发/防御/合规/授权请求：Balanced 阻断数 0。
- 合成高风险请求：Balanced/Strict 按预期阻断且上游副作用为 0。
- 五仓库和补充 ZIP：第三方代码执行数 0；所有语料在 finally 中清理。
- Raw Capture 仅 blocked、显式开启、脱敏、有界、TTL 生效，不记录 CSAM 私有证据。

### 工程与发布

- 本地 Linux 门禁、GitHub required checks 和精确 PR candidate 全部通过。
- 二号机报告绑定精确 commit/tree/SO/CPA binary，清理后无容器、服务或网络残留。
- PR squash merge；新 main CI 全绿；远端和本地仅保留 `main`。
- 只允许创建未被占用且符合 ruleset 的 `v1.0.0-rc.3`；发布为 prerelease、非 latest，
  资产、checksums、SBOM、provenance 和签名身份全部相符。

任何缺失、过期、混合身份、网络故障、CI 取消、无 Provider 请求或旧候选 PASS 都不能
转移为本轮通过结论。
