# Round 13 active status and evidence boundary

This page is the current overlay for
[the Round 13 task book](ROUND13_CPA_V7_2_125_V1_RC1_TASK_BOOK.md). Earlier
Round documents and CPA results remain historical evidence for their exact
identities and do not transfer a PASS to this round.

<!-- round13-status:start -->
```text
round13_status: LOCAL_SOURCE_ENGINEERING_PASS / CPA_V7.2.125_CONTRACT_PASS / EXACT_HEAD_CI_NATIVE_HOST_SECOND_MACHINE_PENDING / NO_MERGE / NO_RELEASE
round13_baseline_main: 11199dde1da5741ecec009be17b8a55294e39421
round13_cpa_target: v7.2.125 / 2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e
round13_cpa_module: github.com/router-for-me/CLIProxyAPI/v7@v7.2.125
round13_cpa_module_sum: h1:jz3yxTI7mp+ej2kI1T4OPs+QhIgP6Mmu5BGvipjQWRg=
round13_cpa_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
round13_cpa_linux_asset_sha256: 4e940b7dc5bdf867b5c58ca30f1b368fae6dc2e041e8a351d5c2c07f3f610233
round13_cpa_linux_binary_sha256: 656cde7bfd966dbcaaa9d9260dd1de75716c0b9dead66d91ceb2d8d55f6d623a
round13_cpa_plugin_abi_rpc_schema: 1 / 2
round13_source_version: 1.0.0
round13_rc_tag: v1.0.0-rc.1
round13_classifier_policy: classifier-policy-v15 / 12f120fb06bc695b827bc4057380cd02b6f4410bd0e3186848bf93bdc06bd7c9
round13_confirmed_p1_hot_reconfigure_atomicity: IMPLEMENTED / COMPLETE_LINUX_UNIT_AND_RACE_PASS
round13_confirmed_p1_request_lifecycle_generation: IMPLEMENTED / COMPLETE_LINUX_UNIT_AND_RACE_PASS
round13_candidate_database_preflight: IMPLEMENTED / SUBJECT_FEASIBILITY_FIRST / HOT_DATA_DIR_IMMUTABLE / COMPLETE_LINUX_UNIT_AND_RACE_PASS
round13_no_copy_contract: SOURCE_CONTRACT_PASS / SOURCE_TEST_ADDED_AND_EXECUTED / NATIVE_HOST_PENDING
round13_response_failed_contract: SOURCE_CONTRACT_PASS / NATIVE_HOST_TEST_ADDED / NATIVE_HOST_PENDING
round13_codex_originator_contract: SOURCE_CONTRACT_PASS / NATIVE_HOST_TEST_ADDED / NATIVE_HOST_PENDING
round13_claude_replay_contract: SOURCE_CONTRACT_PASS / NATIVE_HOST_TEST_ADDED / NATIVE_HOST_PENDING
round13_cpa_contract_and_audit_harness: PASS / THREE_MODULES / 184_PYTHON_TESTS
round13_fragment_boundary_bypass: IMPLEMENTED / COMPLETE_LINUX_UNIT_RACE_FUZZ_AND_CORPUS_PASS
round13_release_admission_contract: IMPLEMENTED / STAGED_REPORT_AND_CI_ARTIFACT_FIXTURES_PASS / LIVE_GITHUB_ADMISSION_NOT_RUN
round13_rc_binary_byte_identity: IMPLEMENTED / AUDITED_V1.0.0_SO_REUSE / NO_RC_RECOMPILE_OR_RENAME / LIVE_SEAL_NOT_RUN
round13_cpa_store_rc_install: IMPLEMENTED / RC_ARCHIVE_EXACT / ROOT_UNVERSIONED_SO / PAYLOAD_BYTE_IDENTICAL / CPA_V7.2.125_OVERLAY_PASS / LIVE_RELEASE_NOT_RUN
round13_local_linux_tests: SOURCE_MATRIX_PASS / UNIT_353.40S / RACE_1153.73S / VET_FUZZ_CORPUS_CONTRACT_AND_PERFORMANCE_PASS / NATIVE_HOST_NOT_RUN
round13_local_round10_performance: SOURCE_ONLY_PASS / ORDINARY_P95_2.395298MS / FIVE_REPOSITORY_SURROGATE_P95_134.449820MS / PUBLIC_P95_P99_9.161171_9.392444MS / ZERO_FAILURE_PANIC
round13_coderabbit: LOCAL_FINDINGS_REMEDIATED / FINAL_LOCAL_REVIEW_NETWORK_FAILED_WEBSOCKET_CLOSED / GITHUB_CODERABBIT_PENDING
round13_pr_required_checks: NOT_RUN
round13_second_machine_v7_2_125: NOT_RUN
round13_five_repository_audit: NOT_RUN
round13_codex_archive_audit: NOT_RUN
round13_main_merge: NOT_DONE
round13_tag_and_release: NOT_CREATED
round13_independent_attestation: NOT_PROVIDED
round13_stable_production_approved: NOT_PROVIDED
```
<!-- round13-status:end -->

## Verified before implementation

- GitHub release `v7.2.125` is a non-prerelease release at commit
  `2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e`.
- The Go module declares the `/v7` module path and resolves to the same tag and
  commit with the module sums recorded above.
- The official Linux amd64 archive matches both GitHub's asset digest and the
  published `checksums.txt`; its binary reports `7.2.125 / 2e6b1d83`.
- CPA plugin ABI 1 and RPC schema 2 are unchanged.
- v7.2.125 adds no-copy/in-place large-payload work and Codex Responses
  `response.failed`; these require new non-transferable regression evidence.
- The working tree inherited 75 modified files aimed at v7.2.124. They are
  preserved and must be deliberately advanced; no reset or global historical
  replacement is allowed.
- Read-only audit confirmed that failed hot reconfiguration can currently
  mutate the active Subject controller before a later raw-capture failure, and
  that successful reconfiguration does not clear the request-lifecycle cache.

## Open gates

The pinned v7.2.125 source/API/ABI/RPC contracts, complete Linux source unit and
race lanes, vet, bounded fuzz, public corpus, release contracts, Safe Gate,
ShellCheck, secret scan, and in-process performance gates pass. Exact-head
reproducibility and GitHub required checks, the clean native CPA Host, the
second-machine false-positive/recall/side-effect/performance run, final
CodeRabbit review, merge, signed tag, and prerelease gates remain open. Local
in-process surrogate performance is not exact-candidate Host or production
performance, and no release-readiness or stable-production PASS is claimed.
