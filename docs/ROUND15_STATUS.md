# Round 15 status — CPA v7.2.142 / RC3

更新时间：2026-08-27

## 当前边界

- CPA：`v7.2.142`
- upstream commit：`1f53b2eb03b9e963bac647e5566ca2b304239116`
- C ABI / RPC：`1 / 3`
- Linux amd64 官方资产 SHA-256：`a7cccc8f94b07660303c1874fb6bedae6d573a0f3c4c0b17ad8cf7885dd7a051`
- 候选发行版：`v1.0.0-rc.3`（`v1.0.0-rc.1`、`v1.0.0-rc.2` 已存在且不可复用）

## 已完成

1. 根模块及两个隔离 integration module 已固定 CPA v7.2.142。
2. 已实现 `plugin.quiesce` 生命周期：可逆静默、in-flight 等待、审计队列有界 flush、精确配置恢复、漂移拒绝、shutdown 后不可恢复。
3. 已增加 quiesce 单元测试及 race 测试覆盖。
4. 已写入本轮任务书与验收标准：
   [ROUND15_CPA_V7_2_142_RC3_TASK_BOOK.md](ROUND15_CPA_V7_2_142_RC3_TASK_BOOK.md)

## 验证状态

已通过（Linux 工具链约束下）：

```text
go test -tags=sqlite_omit_load_extension ./internal/plugin -run '^TestQuiesce|^TestShutdownAfterQuiesce' -count=1
go test -tags=sqlite_omit_load_extension -race ./internal/plugin -run '^TestQuiesce|^TestShutdownAfterQuiesce' -count=1
go test -tags=sqlite_omit_load_extension ./internal/... ./cmd/... -run '^$'
```

Windows 原生环境不作为 Linux/CGO 验收依据。二号机 v142 隔离沙盒、完整 CPA host black-box、五个公开仓库及 `Codex全破.zip` 测试尚未在本状态文件中宣称通过。

## 未完成门禁

- 活动文档、脚本和 release contract 尚有 v7.2.137/RC2 历史与活动边界混用，需要逐项复核并只更新活动字段。
- 需要在全新二号机沙盒完成 CPA v7.2.142 load/register/quiesce/reload/rollback/shutdown、误报、性能和残留清理证据。
- 需要完成本地或 GitHub CodeRabbit 审查，并以 PR 状态为准。
- 以上门禁通过后，才允许创建签名提交、PR、squash merge 到 `main`，删除非 main 分支，并发布 `v1.0.0-rc.3`。

## 发布纪律

不得移动或删除既有签名 tag，不得使用暴露的 PAT，不得伪造二号机 PASS，不得手工绕过治理工作流。若治理 token 或 CI 权限失败，应修复门禁并保留失败证据。
