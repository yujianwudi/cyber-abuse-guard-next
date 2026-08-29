# Round 17 status overlay — CPA v7.2.145 / RPC schema 4

> The `round16_*` field names are retained for parser compatibility; this
> active block now binds the Round 17 v7.2.145 candidate. The old v7.2.144
> values remain only in frozen historical documents and are not transferable.

<!-- round16-status:start -->
```text
round16_cpa_target: v7.2.145 / d9cea8904b14fbbebb77ef26e98ef08f6b48a724 / C_ABI_1 / RPC_SCHEMA_4
round16_cpa_module_sum: h1:5AG1q4MhRK+IU5oP5PPvm04AJYvEkj60br85jiBan5o=
round16_cpa_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
round16_cpa_linux_asset: CLIProxyAPI_7.2.145_linux_amd64.tar.gz / 21226153_BYTES / SHA256_ffb59d406af9b849ec9174154d96642a1d3ccb315f8687c56ac55202816e9b37
round16_cpa_checksums_sha256: df71c910a0ceb83f67ada7c193a1b2d87f1bae955929d4a1d18fb4cf7f4b9d7c
round16_cpa_linux_binary: 64207528_BYTES / SHA256_576a0555e5180c48a5cdf51ee92047a6ab78c363dfe612ea75925ba7f1ae1713
round16_candidate_release: v1.0.0-rc.3 / RC1_AND_RC2_IMMUTABLE_DO_NOT_REUSE
round16_second_machine_release_admission: NOT_RUN / REAL_OWNER_RUN_MANDATORY / RELEASE_BLOCKED
round16_second_machine_release_admission_schema: cyber-abuse-guard.second-machine-release-admission.v3
round16_release_gate: REQUIRED_CHECKS_AND_REAL_SECOND_MACHINE_ADMISSION / NO_WAIVER / RELEASE_RC_WORKFLOW_ONLY
round16_audit_sqlite_schema: 7 / ACTIVE_CONTRACT
round16_csam_text_policy: csam-text-policy-v1 / f8e79b5773d578ef2feefba316c273a2da2fdfbe2eed35b48470b01063944680
round16_active_workflows: 4 / ci.yml / codeql.yml / policy-gate.yml / release-rc.yml
round16_platform_dynamic_workflows: ALLOWLIST_ONLY / dynamic/dependabot/dependabot-updates / dynamic/dependabot/update-graph / ZERO_OTHER_ACTIVE_PATHS
round16_audit_runner_bundle_sha256: d727b92a597ae7b8abf868904535910b04597a8a3ca0b346471af549481d30d6
round16_audit_contract_sha256: 3b601c004a4996f90777ed989d9642cafb237db4dcf000b461a6f86047439c77
round16_audit_run_source_sha256: 44ea0e8519db3dd936de76db56a3f758d8046ff85e49562a254e0cf2ae27dc16
round16_audit_machine_schema_sha256: 428d55f9b0f0fc42441ae0366031b4177d3e8d802e98c3dee4f813b660aa4658
round16_audit_tool_tests: PASS / LINUX / 316_OF_316
round16_audit_tool_skips: 0
round16_audit_test_sources_sha256: d538d6e39f35f9de57c75da5303531fd8de2a516619e0a050b45c25447bc9132
round16_audit_test_ids_sha256: 0ae17691c4961cbb30a05c36577176af9a9d684351784f22b3f57c647216ae86
round16_audit_unit_receipt_sha256: 7ea244f6b8794e10b657ef217e919a7a5b856216a42d19f47a6eb3a05581b032
round16_audit_unit_started_at: 2026-08-29T17:46:25.438Z
round16_audit_unit_finished_at: 2026-08-29T17:47:01.929Z
round16_audit_unit_elapsed_ms: 36491
round16_audit_unit_command: /usr/bin/python3.14 -I -B -m unittest discover -s tools/current-cpa-audit/tests -p test_*.py
```
<!-- round16-status:end -->

当前仅能声明活动工具闭包 Linux 自检通过。精确候选 GitHub CI、真实二号机 CPA
v7.2.145 请求/热更新/回滚、五仓库与补充 ZIP、性能/soak、main 合并和发行仍待完成。
真实二号机准入是强制门禁，缺少与精确候选绑定且未过期的 v3 报告时不得发布。旧 CPA
v7.2.142 或旧候选结果不向本轮转移。当前候选还包含 oversized RPC 在
`plugin.quiesce` 期间的生命周期回归修复；该修复必须随新的精确候选重新通过 CI、Host
和二号机验证，不能沿用旧候选的 Host 结论。
