# Round 14 active status and evidence boundary

This page is the active overlay for
[the Round 14 task book](ROUND14_CPA_V7_2_130_SCHEMA3_TASK_BOOK.md). Round 13
v7.2.125/schema 2 documents and results remain immutable historical evidence for
their exact identities. They do not transfer a PASS to Round 14.

<!-- round14-status:start -->
```text
round14_status: MAIN_MERGED / HOST_PERFORMANCE_PERSISTENT_QUEUE_CONNECTION_FIX_CI_PASS / PRIOR_A216395_SEMANTIC_NATIVE_PASS / PRIOR_A216395_HOST_PERFORMANCE_FAILED_QUEUE_SAMPLE_MISSED_DEADLINE / EXACT_FIX_CI_PASS / SECOND_MACHINE_WAIVER_SUPPORTED / NO_REMOTE_EXECUTION_CLAIM / RC_PUBLICATION_REQUIRES_EXPLICIT_MAINTAINER_WAIVER
round14_branch: agent/cpa-v7.2.130-v1-rc1
round14_baseline_head: c4408af041e4b3c0d58406ccca816b8d8585840b
round14_fix_base_head: a216395803b3a3e46497c5b6eabf1001689edbe1 / CURRENT_WORKTREE_DIRTY
round14_cpa_target: v7.2.137 / 85d2faddd17e6f4f8675a84ee28b131f702e8eaa
round14_cpa_module: github.com/router-for-me/CLIProxyAPI/v7@v7.2.137
round14_cpa_module_sum: h1:CYYByMn7/NwnsCJEMiLI2F8kIJMTb5jRrLaIK6H0c0w=
round14_cpa_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
round14_cpa_plugin_c_abi_rpc_schema: 1 / 3
round14_go_toolchain: go1.26.6 / linux-amd64
round14_audit_sqlite_schema: 7 / ACTIVE_CONTRACT
round14_csam_text_policy: csam-text-policy-v1 / c338d97927489237c5413574489febbaa0468154ba61e8012fd1ecfcfc5a120f
round14_second_machine_release_admission_schema: cyber-abuse-guard.second-machine-release-admission.v3
round14_active_workflows: 4 / ci.yml / codeql.yml / policy-gate.yml / release-rc.yml
round14_cpa_linux_asset: CLIProxyAPI_7.2.137_linux_amd64.tar.gz / 21072175_BYTES
round14_cpa_linux_asset_sha256: ae68c776e124dbc8c8c5b86c501fc6906efa180cc5e35383adb26d05c2c91401
round14_cpa_linux_binary: 63738088_BYTES / SHA256_aac02193aee085542f2452e02606a0ab0e3c3c65ace6216bd39bc48e733c37fa
round14_cpa_checksums_sha256: 9ae7dee90cd717a373acb58fad0163264891d5a76b27fb15d4c88bd10467012e
round14_cpa_release: FORMAL / 2026-08-19
round14_schema3_stream_header_init: PASS / ORIGINAL_REQUEST_AND_REQUEST_BODY_REQUIRED
round14_schema3_stream_payload: PASS / ORIGINAL_REQUEST_AND_REQUEST_BODY_OMITTED
round14_cag_response_interceptor_registration: PASS / FALSE
round14_cag_stream_interceptor_registration: PASS / FALSE
round14_protected_route_contracts: PENDING
round14_realtime_boundary: SOURCE_TOPOLOGY_UNPROTECTED / DYNAMIC_AUTH_BOUNDARY_NOT_RUN / AUTHENTICATED_DYNAMIC_NOT_PERFORMED_PROVIDER_SAFETY_BOUNDARY / NO_ALL_TRAFFIC_COVERAGE_CLAIM
round14_oracle_category_free_meta_audit: PASS / META_OVERRIDE_001_ONLY
round14_oracle_transport_winner_rejection: PASS
round14_classifier_policy: classifier-policy-v20 / 1580f71d77cbb4bf58d3a734ae3a3994dfe2472478ed5f2dc1f18c86fa004b2d
round14_audit_receipt_state: PASS / LINUX / 315_OF_315 / ZERO_SKIPS / UNSIGNED_DEVELOPMENT_SELF_CHECK
round14_audit_expected_test_count: 315 / EXECUTED
round14_audit_runner_bundle_sha256: 5c3e6af865cd2197245ee44b5fa1cf71e83deaed780408e55f92fc1e162472ec
round14_audit_contract_sha256: 7ad1afd590e896a85361782679edf5928774fe7a22d617364df389bc11586642
round14_audit_run_source_sha256: 434fde361ab915bdd5aeb41bc9794eb21b0b561dec1dc9e236705f2cce388665
round14_audit_machine_schema_sha256: 3d24c24777e60d57bc9ab0fc8feaac659b9cc494e9c56c3e19d6b3e9e2ec8e4e
round14_audit_tool_tests: PASS / LINUX / 315_OF_315
round14_audit_tool_skips: 0
round14_audit_test_sources_sha256: cc6c1e0468d519ea83d4bf5003768ce46ed9f2078c6e234f311d9c95831a936c
round14_audit_test_ids_sha256: 54d9dd02e597487c54e9264724410f446fdaf6fbf1711a935ce918379b3f5f3f
round14_audit_unit_receipt_sha256: 1fb557487fa5571ee3cc4d37b697911e807750e89375eb8efc3af79e984e68c5
round14_audit_unit_started_at: 2026-08-24T15:02:16.052Z
round14_audit_unit_finished_at: 2026-08-24T15:02:52.193Z
round14_audit_unit_elapsed_ms: 36141
round14_audit_unit_command: /usr/bin/python3.14 -I -B -m unittest discover -s tools/current-cpa-audit/tests -p test_*.py
round14_local_targeted_cpalatest_schema3: PASS
round14_local_targeted_pluginstore_schema3: PASS
round14_local_targeted_plugin_registration: PASS / LINUX_AMD64
round14_local_targeted_oracle_tests: PASS
round14_local_full_linux: NOT_RUN
round14_cpa_remote_tag_commit_recheck: PASS / GITHUB_API_TAG_REF_AND_COMMIT_VERIFIED / 2026-08-21
round14_official_asset_and_binary_recheck: PASS / LINUX_DOWNLOAD_AND_CHECKSUMS_RECHECKED / 2026-08-21
round14_ci_required_checks: PASS / EXACT_MAIN_POST_MERGE_917D77C
round14_ci_artifact_identity_reproducibility: PASS / EXACT_MAIN_POST_MERGE_917D77C
round14_coderabbit: PASS / EXACT_CANDIDATE_AND_DOCUMENTATION_REVIEW
round14_second_machine_candidate_identity: WAIVED_BY_MAINTAINER / NO_REMOTE_EXECUTION
round14_second_machine_protected_routes: WAIVED_BY_MAINTAINER / NO_REMOTE_EXECUTION
round14_second_machine_realtime_negative_coverage: WAIVED_BY_MAINTAINER / NO_REMOTE_EXECUTION / SOURCE_TOPOLOGY_UNPROTECTED_REMAINS_DOCUMENTED_LOCALLY
round14_second_machine_five_repository_audit: WAIVED_BY_MAINTAINER / NO_REMOTE_EXECUTION
round14_second_machine_supplemental_zip_audit: WAIVED_BY_MAINTAINER / NO_REMOTE_EXECUTION / SEPARATE_DENOMINATOR / NO_PASS_CLAIM
round14_second_machine_false_positive_gate: WAIVED_BY_MAINTAINER / NO_REMOTE_EXECUTION
round14_second_machine_side_effect_gate: WAIVED_BY_MAINTAINER / NO_REMOTE_EXECUTION
round14_second_machine_performance: WAIVED_BY_MAINTAINER / NO_REMOTE_EXECUTION
round14_host_performance_collector: LOCAL_74_TESTS_PASS / ONE_PRIVATE_HTTP_1_1_CONNECTION_PER_MEASURED_CELL / THREE_PREFLIGHT_POLLS_SHARE_ONE_CONNECTION / RFC1918_IPV4_ONLY / STRICT_JSON_AND_256K_RESPONSE_LIMIT / SERVER_CLOSE_OR_RECONNECT_REQUIREMENT_FAILS_CLOSED / SAFE_SAMPLER_ERROR_ID_PROPAGATION / 100MS_CADENCE_AND_ALL_THRESHOLDS_UNCHANGED / EXACT_FIX_HOST_RUN_PENDING
round14_second_machine_docker_stats_probe: READ_ONLY_COMPATIBILITY_PASS_NOT_PERFORMANCE_GATE / SERVER_API_1.52_MINIMUM_1.44 / V1.41_TO_V1.43_REJECTED / FIVE_EXISTING_THREE_CONTAINER_V1.44_PROBES_48_TO_55_MS / DIRECT_DOUBLE_READ_36.704_MS / THREE_POSITIVE_SYSTEM_DELTAS
round14_pre_fix_f663ea6_second_machine: PASS_FOR_OLD_SOURCE_ONLY / SYNTHETIC_MERGE_0EAED101 / FIVE_REPOSITORIES_684_OF_684 / ZIP_252_OF_252 / LAZY_READ_936_OF_936 / CSAM_15_OF_15_AND_21_OF_21 / NATIVE_HOST_PASS / HOST_PERFORMANCE_FAILED_CPA_CAG_C4_R3 / ZERO_TRANSFER_TO_DIAGNOSTIC_FIX
round14_pre_fix_a216395_ci: PASS_FOR_A216395_ONLY / QUALITY_AND_ARTIFACTS / FUZZ_LONG / REPRODUCIBILITY / CODEQL_LINUX / ROUND9_POLICY_AND_CORPUS / CODERABBIT / ZERO_TRANSFER_TO_CURRENT_FIX
round14_pre_fix_a216395_second_machine: PASS_FOR_A216395_ONLY / SEMANTIC_RUN_R14_A216395_PRE_20260824T130734Z_026 / FIVE_REPOSITORIES_684_OF_684 / ZIP_252_OF_252 / LAZY_READ_936_OF_936 / CSAM_MALICIOUS_15_OF_15 / CSAM_BENIGN_21_OF_21_ZERO_FALSE_POSITIVES / THIRD_PARTY_CODE_EXECUTIONS_0 / NATIVE_RUN_R14_A216395_PRE_20260824T130734Z_027_PASS / HOST_PERFORMANCE_FAILED_SERVICE_CAG_R14_A216395_HOST_PERFORMANCE_026A_AT_CPA_CAG_C4_R3 / SAMPLER_ERROR_QUEUE_SAMPLE_MISSED_DEADLINE / ZERO_TRANSFER_TO_CURRENT_FIX
round14_second_machine_host_300s: WAIVED_BY_MAINTAINER / NO_REMOTE_EXECUTION
round14_second_machine_host_3600s: WAIVED_BY_MAINTAINER / NO_REMOTE_EXECUTION
round14_second_machine_cleanup: NOT_APPLICABLE / NO_REMOTE_EXECUTION_STARTED
round14_rollback_pairing: V137_HOST_REQUIRES_ABI1_SCHEMA3_SO / OLD_HOST_REQUIRES_ITS_VERIFIED_OLD_SO / LIVE_ROLLBACK_NOT_RUN
round14_round13_evidence_transfer: FORBIDDEN / ZERO_TRANSFERRED_PASS
round14_main_merge: PASS / 917d77c55b3d041018e61e1c50354de4de673359
round14_tag_and_release: NOT_CREATED / ALLOWED_AFTER_REQUIRED_CHECKS_AND_EXPLICIT_MAINTAINER_WAIVER / RELEASE_RC_WORKFLOW_ONLY
round14_independent_attestation: NOT_PROVIDED
round14_stable_production_approved: NOT_PROVIDED
```
<!-- round14-status:end -->

## Verified inputs before execution

- The task identity is frozen to CPA v7.2.137, commit
`85d2faddd17e6f4f8675a84ee28b131f702e8eaa`, C ABI 1 and RPC schema 3.
- The supplied official Linux amd64 archive, binary and checksums identities are
  recorded above. On 2026-08-21, a fresh Linux download verified the archive,
  checksums file, and contained binary bytes against the recorded hashes. The
  verification proves upstream asset identity only; it is not Host execution.
- The v7.2.137 tag ref currently resolves to
  `85d2faddd17e6f4f8675a84ee28b131f702e8eaa`; GitHub reports the target commit as
  validly verified. This is upstream provenance evidence, not a signature for
  the CAG candidate.
- Schema 3 defines a split stream contract: header-init retains
  `OriginalRequest` and `RequestBody`; payload chunks omit them. Source and Host
  verification are still `PENDING`/`NOT_RUN` as shown above.
- CAG is intended not to register a successful-response or stream-chunk
  interceptor. The exact current candidate must prove both capability flags are
  false.
- CPA v7.2.137 `/v1/realtime*` uses an independent path that bypasses
  `RequestInterceptor`, `ModelRouter` and request lifecycle. Current CAG cannot
  observe or protect it. This is an explicit `OUT_OF_SCOPE / UNPROTECTED`
  boundary, not a pending claim of protection.
- The implemented runtime probe is deliberately unauthenticated. Its future
  evidence level is `AUTH_BOUNDARY_ONLY`: every route must terminate as
  `AUTH_REJECTED` with no credential, no WebSocket upgrade, no Mock/Provider/
  Usage event, and an explicit zero delta for all six fixed CAG RPC counters.
  This does not claim an authenticated handler/provider-path proof; such a
  probe is intentionally not performed where it could reach OAuth or a real
  Provider.
- The oracle target is narrow: a category-free classifier audit is valid only
  for `META-OVERRIDE-001`; transport dispositions must reject classifier winners.

## Current evidence

The canonical receipt path
[`ROUND14_CPA_AUDIT_UNIT_RECEIPT.json`](reports/ROUND14_CPA_AUDIT_UNIT_RECEIPT.json)
now records a Linux `315/315 PASS` execution with zero skips for the current
Host-performance collector fix. It is a
repository-owned **development self-check record**, not a signature,
independent attestation, trusted timestamp, or substitute for CI. The prior
283-test receipt remains immutable historical evidence and is not relabelled.
The receipt tool materializes the already-read and hashed source closure into a
temporary read-only snapshot, discovers and executes all tests from that
snapshot with isolated Python, and rejects bytecode caches. Its validator makes
the recorded stderr, command and timing internally consistent with the current
tested implementation, test-source and test-ID hashes above; a repository
writer can recreate it. All other local, CI, asset,
exact-fix second-machine, five-repository, supplemental ZIP, false-positive,
performance, Host soak and cleanup gates remain `PENDING` or `NOT_RUN`. The
prior exact `a216395` candidate passed every named GitHub check plus its
semantic, CSAM and native-Host lanes. Its Host A/B service
`cag-r14-a216395-host-performance-026a.service` nevertheless failed closed in
the CPA+CAG concurrency-4 repetition-3 cell with
`queue_sample:MissedDeadline`; no measurements or false PASS were emitted. The
current fix replaces per-sample management TCP connections with one private
HTTP/1.1 connection per measured cell and one for the three preflight polls,
while retaining the 100 ms cadence, deadlines, sample counts and all admission
thresholds. The Linux `315/315` receipt validates the current source closure,
but exact-commit CI and Host performance have not run. All `a216395` PASS
records remain bound to the old bytes and transfer zero PASS to this fix. The known realtime
routing boundary is a `SOURCE_TOPOLOGY_UNPROTECTED` source fact and does not
count as a security PASS. No dynamic auth-boundary evidence has run yet, and no
authenticated dynamic proof is claimed.

## Open gates

Commit the persistent-connection collector fix and run the complete Linux-only development matrix. A clean exact candidate
must independently close applicable CI checks, artifact identity and
reproducibility. The operator canceled all second-machine execution for this
round. No SSH, remote container, provider, or performance task was started and
no remote evidence exists. The mandatory second-machine protected-route,
five-repository, supplemental ZIP, false-positive, side-effect,
Host-performance, 300-second admission and 3600-second stability gates remain
unsatisfied; the realtime source boundary remains documented as unprotected.
This cancellation does not waive the release contract.

Round 13 values, artifacts, reports, SO hashes, Host observations and PASS
claims cannot satisfy any of these gates. The four-workflow repository includes
the gated RC publication lane, but it may publish only after every applicable
acceptance gate passes; the current pending state does not authorize a tag or
Release.
