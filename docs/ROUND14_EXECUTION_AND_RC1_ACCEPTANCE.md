# Round 14 执行任务书与 v1.0.0-rc.1 验收标准

状态：`EXECUTION CONTRACT / NO PASS TRANSFER / NO MERGE UNTIL ACCEPTANCE / RC PUBLICATION GATED`

## Maintainer waiver overlay

The second-machine execution gate is normally required. For this release, the
repository maintainer may explicitly waive that execution through the manual RC
workflow by setting `second_machine_waiver=true`, entering
`I_ACK_SECOND_MACHINE_NOT_RUN`, and providing a one-line reason. The actor must
be `yujianwudi`; any other actor or missing acknowledgment fails closed. A
waived run records `SECOND_MACHINE_OWNER_RELEASE_ADMISSION_WAIVED`, preserves
all exact-main CI, artifact, provenance and CPA checks, and explicitly does not
claim independent Host evidence or production approval.

本文件补充
[`ROUND14_CPA_V7_2_130_SCHEMA3_TASK_BOOK.md`](ROUND14_CPA_V7_2_130_SCHEMA3_TASK_BOOK.md)
和 [`ROUND14_STATUS.md`](ROUND14_STATUS.md)。状态页仍是事实入口；本任务书只定义
后续工作和准入标准，不把 `NOT_RUN` 写成 `PASS`。

## 1. 冻结身份和证据边界

```text
repository: yujianwudi/cyber-abuse-guard-next
branch: agent/cpa-v7.2.130-v1-rc1
round14_baseline: c4408af041e4b3c0d58406ccca816b8d8585840b
current_dirty_worktree_base_head_2026-08-14: f328975193515058ece24e64ca8056f252aa5024
cpa: github.com/router-for-me/CLIProxyAPI/v7@v7.2.137
cpa_commit: 85d2faddd17e6f4f8675a84ee28b131f702e8eaa
cpa_module_sum: h1:CYYByMn7/NwnsCJEMiLI2F8kIJMTb5jRrLaIK6H0c0w=
cpa_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
cpa_contract: C_ABI_1 / RPC_SCHEMA_3
audit_sqlite_schema: 7
csam_text_policy: csam-text-policy-v1 / c338d97927489237c5413574489febbaa0468154ba61e8012fd1ecfcfc5a120f
second_machine_release_admission_schema: cyber-abuse-guard.second-machine-release-admission.v3
active_workflows: 4 / ci.yml / codeql.yml / policy-gate.yml / release-rc.yml
cpa_asset: CLIProxyAPI_7.2.137_linux_amd64.tar.gz
cpa_asset_bytes: 21072175
cpa_asset_sha256: ae68c776e124dbc8c8c5b86c501fc6906efa180cc5e35383adb26d05c2c91401
cpa_binary_bytes: 63738088
cpa_binary_sha256: aac02193aee085542f2452e02606a0ab0e3c3c65ace6216bd39bc48e733c37fa
platform: linux/amd64 only
candidate_release: v1.0.0-rc.1
```

以上 HEAD 是观察快照；执行前必须重新计算 HEAD/tree/SO/Store/artifact。当前候选
commit 未携带可验证签名，应标为 `UNSIGNED / NOT_MERGEABLE`。Round 13 的 CPA
v7.2.125/schema 2 及更早 PASS 只能作为其原身份历史记录，`transferred_passes=0`。

## 2. 目标与非目标

目标：

1. 证明 CPA v7.2.137/schema 3 的 source、compile、Store、Host 与 stream 合同。
2. 在二号机以官方 Host、精确候选 SO/ZIP 和 counted Mock 完成隔离审计。
3. 对五个固定仓库实行惰性只读文本输入，验证误报、召回、block 后副作用和清理。
4. 重新取得 CPA-only/CPA+CAG Host A/B 性能以及 300/3600 秒稳定性证据。
5. 独立评估 CSAM **文本意图层**防护，并给出严格隐私/审计边界。
6. 在不降低 `main` 保护的前提下定义合并门和未来 `v1.0.0-rc.1` 发行门。

非目标：

- 不支持 Windows/macOS；不接真实 Provider、OAuth、生产账号、生产数据库或凭据。
- `/v1/realtime*` 继续是 `OUT_OF_SCOPE / UNPROTECTED / CAG_NOT_VISIBLE`；不得称
  “全流量覆盖”，不得注册 response/stream interceptor 或改写成功响应流。
- 不执行、安装、导入或重新分发五仓/ZIP 的代码、脚本、二进制、hook 或配置。
- 不保存真实 CSAM、露骨语料、图片/视频、违法链接、Base64 或其衍生副本。
- 验收未全部通过前不创建 tag、prerelease、Release、attestation 或 Release asset；
  全部适用验收通过后，只允许由受审 `release-rc.yml` 发布 RC。

## 3. 阶段 P0-P3

### P0：身份、schema 3、oracle 和治理冻结

在 Linux amd64、Go 1.26.6、干净精确 checkout 上执行并保存 stdout/stderr：

```bash
git status --short --branch
git rev-parse HEAD HEAD^{tree}
git show --show-signature --format=fuller --no-patch HEAD
git verify-commit HEAD
go version
go mod verify
go list -m -json github.com/router-for-me/CLIProxyAPI/v7
go -C integration/cpalatestcontract test -count=1 ./...
go -C integration/pluginstorecontract test -count=1 ./...
make cpa-host-fixture-contract
make cpa-latest-compat
python3 -B -m unittest discover -s tools/current-cpa-audit/tests -p 'test_*.py'
```

验收：

- module/tag/commit/sums/官方 asset/binary/C ABI/schema 必须与第 1 节逐字一致。
- schema 3 header-init 保留 `OriginalRequest`/`RequestBody`；payload chunk 省略二者；
  `response_interceptor=false`、`response_stream_interceptor=false`。
- request lifecycle、completion method/outcome、Store install/reconfigure/shutdown、
  Host fail-open/fail-closed 全覆盖。
- category-free classifier audit 只允许 `META-OVERRIDE-001`；transport/incomplete
  disposition 携带 winner、其它 category-free winner 必须被 validator 拒绝。
- `/v1/realtime*` 源拓扑和动态认证边界分层报告；动态探针固定无凭据、401/403、
  无 upgrade、真实 Provider=0、Mock/Usage=0、六项 CAG counter delta=0。

只读治理核对：

```bash
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection
gh api repos/yujianwudi/cyber-abuse-guard-next/branches/main/protection/required_status_checks
gh api repos/yujianwudi/cyber-abuse-guard-next/rulesets --paginate
gh api repos/yujianwudi/cyber-abuse-guard-next/actions/permissions
gh api 'repos/yujianwudi/cyber-abuse-guard-next/actions/workflows?per_page=100'
gh api repos/yujianwudi/cyber-abuse-guard-next/commits/<SHA> --jq '.commit.verification'
```

`main` 必须保持 `required_signatures=true`、strict/up-to-date，并且 required contexts
集合**精确**为：

```text
quality-and-artifacts
fuzz-long
reproducibility
Analyze Go on Linux
round9-policy-and-corpus
```

还必须保持 PR、conversation resolution、管理员强制执行、禁止 force-push/删除、
默认 workflow token read-only。当前 unsigned candidate 必须从相同最终 tree 构造
GitHub-verified signed candidate；不得关闭签名保护或缩减 contexts。

证据：`<EVIDENCE>/p0/{identity,schema3,branch-protection,required-contexts,candidate-verification}.json`
及原始日志。

### P1：五仓惰性、误报/副作用、CSAM 文本和性能

#### P1.1 五仓与 supplemental

固定五仓：

1. `Jia-Ethan/codex-keysmith`
2. `yynxxxxx/Codex-5.5-codex-instruct-5.5`
3. `yynxxxxx/Codex-X`
4. `MDX-Tom/gpt-5.6-instruct`
5. `lingbol088-spec/5.6-JAILBREAK-NERV-codex-instruct-5.6`

固定合同为 5 仓、11 source、19 semantic cases、精确 commit/tree/blob/text SHA、
`third_party_code_executions=0`。补充 `Codex全破.zip` 通过显式
`--supplemental-archive` 输入并绑定 SHA-256
`23000a55f3922c9c2daf04e27d4bdf49d5f95109dd76ba25fa0b3f834c67ed1c`；其 7-case
分母、结果和清理永远不能混入五仓分母。

```bash
umask 077
RUN_ID='<new-round14-run-id>'
ACQ="/srv/cag-audit/acquisition-$RUN_ID"
EVIDENCE="/srv/cag-audit/evidence-$RUN_ID"
test ! -e "$ACQ" -a ! -e "$EVIDENCE"
python3 -B tools/current-cpa-audit/acquire.py \
  --policy tools/current-cpa-audit/repository-policy.json --output "$ACQ"
python3 -B tools/current-cpa-audit/validate.py corpus \
  --manifest "$ACQ/corpus-manifest.json" --corpus-root "$ACQ"
```

惰性读取的验收定义：预检可以逐 source hash；进入 `transport_matrix` 后，每次
请求只可经 `BoundCorpus.read` 打开当前 case 的一个绑定文件，不得预载/拼接五仓、
建立全仓缓存或读取未引用 source。supplemental member 只在内存中加载，绝不落盘，
结束时 zeroize。证据只存路径 key、bytes、SHA、case/request hash 和决定，不存正文。

必须新增/取得：

```text
<EVIDENCE>/lazy-read/phase-boundary.json
<EVIDENCE>/lazy-read/runtime-read-trace.jsonl
<EVIDENCE>/lazy-read/runtime-read-summary.json
```

trace 必须区分预检和 transport；运行结束 `finally` 后五仓正文、ZIP member、临时
secret/config 均不存在，目录/inode、单硬链接和 post-unlink 可证明。无分阶段 trace
时只能 `PENDING`，不能称 lazy PASS。

完整审计验收：三次 cold start，core 684 executions、supplemental 252 executions；
完整正常/防御/授权语义误拦=0；Balanced/Strict expected malicious recall=100%；
Audit malicious detection=100% 且 HTTP block=0；incomplete 不算恶意真阳性；
unexpected HTTP/infrastructure error=0。block 后
`Auth/Router/Provider/Executor/Usage/SSE/Mock` delta 全 0，allow 只产生唯一预期调用。

#### P1.2 CSAM 文本层可行性（独立门）

当前 CAG 仅评估文本请求中的**制作、索取、交换、传播、诱骗**意图。所有测试仅
使用合成、非露骨、无真实人物/年龄/地点/链接/媒体/Base64 的语义夹具；禁止下载、
复制、改写或保存真实违法材料。

正常新闻、法律合规、举报、受害者支持、安全研究、家长保护和内容删除请求不得
误拦。最小验收平面：五类 malicious intention 各 3 个变体（15 cases），七类正常
语义各 3 个变体（21 cases），每个覆盖 Audit/Balanced/Strict、chat/Responses、
stream/non-stream 和三次 cold start：

```text
malicious 15/15：Balanced/Strict block=100%；Audit detection=100%、block=0
benign 21/21：三模式 allow=100%；CSAM label/winner=0；误拦=0
block side effects：全 0；allow：唯一预期调用
real_or_explicit_media_inputs=0；fixture_text_retained=false
```

只有主提取器证明的解析、结构、角色归属或覆盖缺口才沿用既有 incomplete 合同：
Balanced 允许并审计，Strict 使用 `block_incomplete_inspection` fail closed，且不得伪造
`csam_malicious` category/winner。CSAM side-car 只接收可信、当前轮 `user/content`
作为执法证据；unknown/roleless、system、assistant、tool、history、tool payload、untrusted
或非当前轮载体必须惰性忽略。side-car 的私有文本/段数预算耗尽只产生低基数诊断，
不得伪装成主提取器 `classification_chunk_limit`，也不得改变传输 disposition；不完整前缀
不得成为 CSAM positive。审计或持久化不可用时受保护路由不得 ready，
低基数诊断不得含正文。事件仅存 request hash、mode、category/disposition、适用的
winner、coverage/reason、时间和计数；正文和可逆编码禁止持久化。

Apple 截图的边界：Communication Safety 与 2021 年拟议的 iCloud Photos
client-side CSAM detection 是不同方案，截图把二者混合，不能作为当前可用能力、
API 或实现依据。CAG 当前不识别图片/视频本体。未来媒体接口只允许经单独治理的
合规 known-hash/专业服务；禁止主动下载远程 URL，禁止真实违法样本，禁止用普通
SHA-256 宣称可识别裁剪/转码等变体，未经法务批准和人工复核禁止自动执法或报告。

证据：`<EVIDENCE>/csam-text/{fixture-manifest,results,summary,privacy-cleanup}.json*`，
只存合成 ID/hash/摘要。实现前状态必须为 `PENDING_IMPLEMENTATION`，不得用五仓 PASS
冒充 CSAM PASS。图片/视频是本轮明确非目标。live producer 还必须使用
`tools/current-cpa-audit/README.md` 定义的 7 项 operator-owned `CAG_CSAM_*`
环境和闭合 cold-start/cleanup hook 合同。三份不同冷启动收据、三个不同 runtime
root inode、显式 cleanup 收据、runtime root 实际不存在，以及外层对精确带标签
Docker 资源的独立不存在证明缺一不可。未注入环境，或 hook 只能启动却不能同步
清理，均为硬失败。

#### P1.3 性能门

使用 `host_performance.py make-config/collect/summarize` 和
`validate.py host-performance`，重新取得 CPA-only/CPA+CAG 的原始 paired 数据；
不得导入 Round 13 数值。至少 3 repetitions、30s warmup、120s measurement、每 cell
1,000 success samples，并保留 raw latency/RSS/queue/CPU/steal、concurrency、payload、
container init PID/starttime 和 tool hashes。

资源采样固定使用 root-owned、非 world-accessible 的 `/var/run/docker.sock` 和 Docker
Engine API v1.44 `stats?stream=false&one-shot=true`，按三个完整 container ID 分别读取，
验证返回的完整 ID/name、16 MiB JSON 上限和 socket 身份不漂移。CPU 由连续
`total_usage/system_cpu_usage` 计数器计算，RSS 使用 `usage-inactive_file` working set；
计数器回退、system delta 为 0、身份或权限漂移均硬失败。非 root transient runner 只在
本次 unit 增加 `SupplementaryGroups=docker`，不得把 socket 改成 world-accessible。二号机
预检必须证明三容器完整采样可持续低于固定 1 秒间隔。每个测量 cell 与 warm lane 必须
重新建立约 20 ms 的 counter 基线，禁止把前一 cell 或 warmup 的空闲间隔稀释进首样本。

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

环境受扰只能 `DIAGNOSTIC_NOT_BASELINE`，不能放宽阈值。

### P2：二号机 Host、回滚和清理

二号机必须使用官方 v7.2.137 binary、同一精确 candidate SO/Store ZIP、内部 counted
Mock、新 RUN_ID/evidence root，无 Host 端口和真实 Provider。

Host admission：

```bash
python3 -B tools/current-cpa-audit/validate.py host-admission \
  --evidence "$EVIDENCE/host-admission/evidence.json" \
  --samples-300s "$EVIDENCE/host-admission/host-300s-samples.jsonl" \
  --samples-3600s "$EVIDENCE/host-admission/host-3600s-samples.jsonl" \
  --realtime-routes "$EVIDENCE/host-admission/realtime-auth-boundary-routes.jsonl" \
  --expected-candidate "$EVIDENCE/host-admission/expected-candidate.json"
```

验收：300 秒 301 samples；3600 秒 3601 samples；每个 sample 的
`/keeper/healthz=healthy/200`、`/=200`、无凭据 `/v1/models=401`；candidate/CPA/Mock
identity、PID/starttime、restart/OOM/panic、queue/error 和代表性 allow/block 计数
连续一致。结尾再次验证 14 条 realtime route 未保护、SQLite `quick_check=ok`/
schema 7 及清理。300s 不能替代 3600s；中断或漂移必须换新 RUN_ID 重跑。

切换前备份 Host image/binary、SO、Store metadata、config 和 SQLite/audit DB；数据库
使用 SQLite Online Backup 并验证 `quick_check`，不得仅复制活动 WAL。回滚必须成对：
v7.2.137 Host 只配 ABI1/schema3 本轮 SO；旧 Host 只配其此前验证的旧 SO。回滚后
复核 hash/schema/health/root/models/PID/restart/Mock/SQLite，不能以“进程启动”代替。

清理只删除本轮精确 label/root 的容器、网络、临时配置和惰性文本；禁止
`docker system prune`、删镜像/卷/业务容器/数据库/凭据。验收：

```text
all_owned_resources_absent=true
global_prune_used=false
images_removed=false
third_party_text_retained=false
third_party_code_executions=0
```

### P3：合并门与受控 RC.1

`MERGE READY` 必须同时满足：

- P0-P2 所有适用项为精确 candidate `PASS`，无 `PENDING/NOT_RUN/DIAGNOSTIC` 或未关闭
  P0/P1 finding；CodeRabbit 对最终 tree 无未处理 finding。
- 五个 exact required contexts 全绿、strict/up-to-date，记录 run URL/ID/event/head
  SHA/artifact ID/digest/size。
- `required_signatures=true` 等保护不变；最终 commit/tree 是 GitHub-verified signed
  candidate。当前 unsigned commit 不得直接合并，也不得关闭保护后再开回去。
- clean tree、artifact manifest、SO/Store/checksums/SBOM/reproducibility 闭合。

`v1.0.0-rc.1` 发行门（全部适用验收通过后才允许执行）：

- 从精确受保护 `main` commit 创建 GitHub-verified signed annotated tag；lightweight、
  未验证、Release 自动生成或移动 tag 禁止；失败重试用新 RC 号。
- `prerelease=true`、`make_latest=false`；RC 不是 stable/生产批准。
- 九文件 candidate、SO/Store/checksums、metadata、ruleset、SBOM/provenance、CPA 官方
  identity 与 commit/tree byte-for-byte 绑定；下载后按 API digest/size/SHA 重验。
- portable second-machine report 重新验证五仓/supplemental 独立分母、误报/召回、
  副作用、性能、300/3600、realtime、清理、TTL，并声明 owner-run/non-independent。
- 当前活动 workflow 固定为四个：`ci.yml`、`codeql.yml`、`policy-gate.yml` 和
  `release-rc.yml`。RC 发布只能走该受审 lane；禁止改 job condition 或手工
  `gh release` 绕过任何验收。

## 4. 失败、停止和回滚标准

以下任一项立即停止合并/部署/发行：身份/schema/签名漂移；required context 不精确
或签名保护关闭；正常语义/CSAM benign 误拦；恶意漏拦；block 后副作用；真实
Provider/OAuth/媒体下载；第三方代码执行或文本残留；五仓/ZIP 分母混合；realtime
被称为 protected；性能阈值失败；300/3600 窗口缺口；OOM/panic/restart；备份/
SQLite/ABI 配对失败；清理越界；在全部验收闭合前执行任何发布动作。

失败时保留不含正文的原始 JSONL、stderr、hash 和 cleanup 记录为 `FAIL`；按精确
label 隔离/清理；若已切换则恢复成对备份并复验；修复后用全新 RUN_ID 从 P0 开始，
不得拼接旧窗口或把失败报告改名为 PASS。

## 5. 必备证据树

```text
<EVIDENCE>/
  p0/{identity,schema3,branch-protection,required-contexts,candidate-verification}.json
  lazy-read/{phase-boundary,runtime-read-trace,runtime-read-summary}.json*
  corpus-manifest.json
  supplemental-zip-manifest.json
  run-config.json
  machine-evidence.json
  transport-results.jsonl
  supplemental-zip-results.jsonl
  csam-text/{fixture-manifest,results,summary,privacy-cleanup}.json*
  host-performance-{config,measurements,evidence}.json
  host-admission/evidence.json  # cyber-abuse-guard.second-machine-release-admission.v3
  host-admission/host-300s-samples.jsonl
  host-admission/host-3600s-samples.jsonl
  host-admission/realtime-auth-boundary-routes.jsonl
  rollback/{backup-manifest.json,sha256.txt}
  p3/{ci-runs,signature-verification,merge-gate}.json
```

完成定义：`LOCAL_TARGETED_PASS` 仅是开发证据；`LINUX_CI_PASS` 需要精确 signed
candidate 和五个 contexts；`SECOND_MACHINE_OWNER_ADMISSION_PASS` 需要五仓、ZIP、
CSAM 文本、误报、副作用、性能、realtime、300/3600 和清理；`MERGE_READY` 还需
签名和治理闭合；全部适用验收通过后才允许进入 `RC_RELEASED`，且不代表 stable
或生产批准。
