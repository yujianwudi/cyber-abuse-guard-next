# CPA v7.2.159 验收标准

以下命令应在 Linux amd64 CI/Host 上执行。Windows 本地结果只能作为静态检查，不能替代标记为 Linux-required 的项目。

## A. 源码与历史合同

- `git diff --check` 通过，工作树 clean。
- `python -m unittest discover -s tools/current-cpa-audit/tests -p 'test_*.py'`：全绿；允许仅记录环境型 skip。
- `python -m unittest discover -s scripts -p '*_test.py'`：Linux 全绿；Round 13 常量与 Round 6 wrapper 不得被 CPA 159 改写。
- `python -B scripts/round6_safe_gate_contract.py --root .`：PASS。
- `bash scripts/release-doc-consistency.sh` 与 `bash scripts/release-rc-contract-test.sh`：PASS。

## B. CPA/Go/Linux

- `go test ./sdk/pluginabi ./sdk/pluginapi`：PASS。
- `go test ./...`、`go vet ./...`、race/fuzz smoke：PASS；使用仓库固定的 Go 1.26.6。
- `make cpa-latest-compat` 必须绑定 v7.2.159 commit、module sum、go.mod sum；远端 latest 检查若不可用必须明确记录，不得伪造 PASS。
- `make integration-test round6-cpa-store-contract`：Linux Host 加载真实 `.so`，验证 schema 6 协商、请求终止、生命周期完成、Store 归档和 Raw Capture 管理响应。

## C. 资产与第二机器

- CPA 官方 Linux amd64 归档、内置 binary、checksums 文件和 CAG `.so` 均有 SHA-256，且报告绑定同一 commit/tree。
- 第二机器 admission 报告 schema、候选、运行 ID、Host 证据和清理记录全部通过；报告未过期，不能用 maintainer 文本替代。
- `/v1/realtime*` 的未覆盖边界在报告和 Release notes 中明确可见。

## D. GitHub 发布与治理

- PR 合并到 `main`，required checks 完整通过；保护规则要求的 verified signature 不得绕过。
- 合并后枚举远端分支，仅保留 `main`；删除操作记录分支名和响应，不能删除 `main`。
- stable Release 只能从已合并、已验收的 `main` commit 创建，tag 为 `v1.0.0`，资产、SBOM、checksums、provenance 和源码归档绑定同一 commit/tree。
- 若任一 required check、签名、Linux Host 或第二机器证据缺失，验收结论必须为 BLOCKED，而不是“发布成功”。
