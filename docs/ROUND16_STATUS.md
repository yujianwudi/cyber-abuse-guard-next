# Round 16 status — CPA v7.2.144 / RPC schema 4

<!-- round16-status:start -->
```text
round16_cpa_target: v7.2.144 / d36b776c790a4d58027fd4fb434800fb5334bceb / C_ABI_1 / RPC_SCHEMA_4
round16_cpa_module_sum: h1:ZNLmwkaMZ+4KbR8BqLHUUDdDzWsQKpXZQbLYesh4ttk=
round16_cpa_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
round16_cpa_linux_asset: CLIProxyAPI_7.2.144_linux_amd64.tar.gz / 21223927_BYTES / SHA256_02be1ad96791f1d2b7e6574bb0f68a3d75622e42cba07fecd012e575ba4b2a96
round16_cpa_checksums_sha256: 1cd243af209cc8f7dac36b3785f9ff2d06a81518f409611a3c674ce2190a4331
round16_cpa_linux_binary: 64203432_BYTES / SHA256_eef73e578f5d272173aadcdf52137390363cd7e4bf0da8651d4c0acd3c0c4f09
round16_candidate_release: v1.0.0-rc.3 / RC1_AND_RC2_IMMUTABLE_DO_NOT_REUSE
round16_second_machine_release_admission: NOT_RUN / REAL_OWNER_RUN_MANDATORY / RELEASE_BLOCKED
round16_second_machine_release_admission_schema: cyber-abuse-guard.second-machine-release-admission.v3
round16_release_gate: REQUIRED_CHECKS_AND_REAL_SECOND_MACHINE_ADMISSION / NO_WAIVER / RELEASE_RC_WORKFLOW_ONLY
round16_audit_sqlite_schema: 7 / ACTIVE_CONTRACT
round16_csam_text_policy: csam-text-policy-v1 / 85437c9e1bd94603f2a837bd66ede6a102b844143e3e869e768901ce9b56276e
round16_active_workflows: 4 / ci.yml / codeql.yml / policy-gate.yml / release-rc.yml
round16_platform_dynamic_workflows: ALLOWLIST_ONLY / dynamic/dependabot/dependabot-updates / dynamic/dependabot/update-graph / ZERO_OTHER_ACTIVE_PATHS
round16_audit_runner_bundle_sha256: 902d7a7eca08b0abf0b260120fcb1aeea7c71e6ff70e684a4853e1ab5d1070d2
round16_audit_contract_sha256: 6e63b60327ef1262925693cb88a0142ec7aa3e6387b9637076e6af073387253f
round16_audit_run_source_sha256: f421c571783c2f58c3b09adc214d57c727b4b30e0d45ea7569100e80fd535fc5
round16_audit_machine_schema_sha256: 0890c7f21218d2baa94a024e1bb4fecc316564411d1b50837752d2fa469b3ad7
round16_audit_tool_tests: PASS / LINUX / 315_OF_315
round16_audit_tool_skips: 0
round16_audit_test_sources_sha256: 4e6c502d33c52c3907e7f150a40ec74c9b565652f6a5d951dea11c8b650477ab
round16_audit_test_ids_sha256: 54d9dd02e597487c54e9264724410f446fdaf6fbf1711a935ce918379b3f5f3f
round16_audit_unit_receipt_sha256: 502805a468c842c32c066ce4f830ede0d5fba84eed7610ab577806ea85905b1b
round16_audit_unit_started_at: 2026-08-28T15:46:46.542Z
round16_audit_unit_finished_at: 2026-08-28T15:47:23.262Z
round16_audit_unit_elapsed_ms: 36720
round16_audit_unit_command: /usr/bin/python3.14 -I -B -m unittest discover -s tools/current-cpa-audit/tests -p test_*.py
```
<!-- round16-status:end -->

当前仅能声明活动工具闭包 Linux 自检通过。精确候选 GitHub CI、真实二号机 CPA
v7.2.144 请求/热更新/回滚、五仓库与补充 ZIP、性能/soak、main 合并和发行仍待完成。
真实二号机准入是强制门禁，缺少与精确候选绑定且未过期的 v3 报告时不得发布。旧 CPA
v7.2.142 或旧候选结果不向本轮转移。
