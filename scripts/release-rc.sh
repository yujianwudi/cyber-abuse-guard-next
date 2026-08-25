#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"

readonly rc_source_version='1.0.0'
readonly rc_binary_version='1.0.0'
readonly rc_artifact_version='1.0.0-rc.1'
readonly rc_tag='v1.0.0-rc.1'
readonly rc_cpa_version='v7.2.137'
readonly rc_cpa_commit='85d2faddd17e6f4f8675a84ee28b131f702e8eaa'
readonly rc_cpa_c_abi='1'
readonly rc_cpa_rpc_schema='3'
readonly rc_repository='yujianwudi/cyber-abuse-guard-next'
readonly rc_workflow='.github/workflows/release-rc.yml'
readonly rc_candidate_name='cyber-abuse-guard-linux-amd64-audit-candidate'
readonly rc_second_report='second-machine-release-admission.json'
readonly rc_second_schema='cyber-abuse-guard.second-machine-release-admission.v3'
readonly rc_second_status='SECOND_MACHINE_OWNER_RELEASE_ADMISSION_PASS'
readonly rc_second_waiver_schema='cyber-abuse-guard.second-machine-release-admission-waiver.v1'
readonly rc_second_waiver_status='SECOND_MACHINE_OWNER_RELEASE_ADMISSION_WAIVED'
readonly rc_attestation_action='actions/attest-build-provenance@0f67c3f4856b2e3261c31976d6725780e5e4c373'
readonly rc_attestation_asset='release-attestation.intoto.jsonl'
readonly rc_tag_signer_policy='github-verification-verified-valid-annotated-tag-and-commit'

so="cyber-abuse-guard-v${rc_binary_version}.so"
audit_store_zip="cyber-abuse-guard_${rc_binary_version}_linux_amd64.zip"
cpa_store_zip="cyber-abuse-guard_${rc_artifact_version}_linux_amd64.zip"
audit_checksums="audit-candidate-checksums.txt"
source_archive="cyber-abuse-guard-v${rc_artifact_version}-source.tar.gz"
candidate_input_assets=(
  "$so"
  "$so.sha256"
  "$audit_store_zip"
  audit-candidate-manifest.json
  build-metadata.json
  checksums.txt
  ruleset-manifest.json
  ruleset.sha256
  sbom.cdx.json
)
candidate_release_assets=(
  "$so"
  "$so.sha256"
  "$audit_store_zip"
  audit-candidate-manifest.json
  build-metadata.json
  "$audit_checksums"
  ruleset-manifest.json
  ruleset.sha256
  sbom.cdx.json
)
core_assets=(
  "${candidate_release_assets[@]}"
  "$cpa_store_zip"
  checksums.txt
  "$rc_second_report"
  "$source_archive"
  "$source_archive.sha256"
)
provenance_subject_assets=(
  "${core_assets[@]}"
  release-evidence.md
)
manifest_assets=(
  "${provenance_subject_assets[@]}"
  release-provenance.json
)
checksummed_assets=(
  "${manifest_assets[@]}"
  release-manifest.json
)
base_assets=(
  "${checksummed_assets[@]}"
  release-checksums.txt
)
usage() {
  cat >&2 <<'EOF'
usage: release-rc.sh seal-candidate CANDIDATE_DIRECTORY SECOND_MACHINE_REPORT
       release-rc.sh verify
       release-rc.sh attach-attestation BUNDLE_PATH

This fixed v1.0.0-rc.1 entry point seals the exact CI-audited v1.0.0 bytes.
It never recompiles or renames the standalone audited Linux amd64 shared object.
It deterministically derives only the CPA-compatible RC ZIP container.
EOF
  exit 2
}

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

require_regular_file() {
  local path="$1"
  [[ -f "$path" && ! -L "$path" ]] || \
    release_die "RC artifact must be a regular non-symlink file: $path"
}

require_positive() {
  local name="$1"
  local value="${!name:-}"
  [[ "$value" =~ ^[1-9][0-9]*$ ]] || \
    release_die "$name must be a positive decimal identity"
}

require_digest() {
  local name="$1"
  local value="${!name:-}"
  [[ "$value" =~ ^sha256:[0-9a-f]{64}$ ]] || \
    release_die "$name must be a lowercase sha256: digest"
}

init_rc_identity() {
  release_require_commands git sed awk sha256sum sort head jq find grep cmp tar unzip file readelf python3 stat install mktemp rm date chmod mv mkdir diff
  release_init
  release_assert_tag
  release_assert_rc_build

  [[ "$RELEASE_SOURCE_VERSION" == "$rc_source_version" ]] || \
    release_die "RC source version must be exactly $rc_source_version"
  [[ "$RELEASE_ARTIFACT_VERSION" == "$rc_artifact_version" ]] || \
    release_die "RC Release identity must be exactly $rc_artifact_version"
  [[ "$RELEASE_RC_TAG" == "$rc_tag" ]] || \
    release_die "RC tag must be exactly $rc_tag"
  [[ "${RC_CPA_VERSION:-}" == "$rc_cpa_version" ]] || \
    release_die "RC CPA version must be exactly $rc_cpa_version"
  [[ "${RC_CPA_COMMIT:-}" == "$rc_cpa_commit" ]] || \
    release_die "RC CPA commit must be exactly $rc_cpa_commit"
  [[ "${RC_CPA_C_ABI:-}" == "$rc_cpa_c_abi" ]] || \
    release_die "RC CPA C ABI must be exactly $rc_cpa_c_abi"
  [[ "${RC_CPA_RPC_SCHEMA:-}" == "$rc_cpa_rpc_schema" ]] || \
    release_die "RC CPA RPC schema must be exactly $rc_cpa_rpc_schema"
  [[ "${RC_SECOND_MACHINE_SCHEMA:-}" == "$rc_second_schema" ]] || \
    release_die "RC second-machine admission schema must be exactly $rc_second_schema"
  [[ "${RC_TAG_VERIFICATION_STATUS:-}" == VERIFIED_SIGNED_ANNOTATED_TAG ]] || \
    release_die "RC sealing requires the verified signed annotated tag admission"
  [[ "${RC_TAG_SIGNER_POLICY:-}" == "$rc_tag_signer_policy" ]] || \
    release_die "RC sealing requires the fixed GitHub tag signer policy"
  [[ "${RC_TAG_OBJECT_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || \
    release_die "RC sealing requires the annotated tag object SHA"
  [[ "$(git -C "$RELEASE_ROOT" rev-parse "$rc_tag^{tag}")" == "$RC_TAG_OBJECT_SHA" ]] || \
    release_die "admitted annotated tag object differs from the checked-out tag"
  [[ "${RC_ADMISSION_STATUS:-}" == EXACT_PROTECTED_MAIN_CHECKS_PASS ]] || \
    release_die "RC sealing requires the exact protected-main admission result"
  if [[ "${RC_SECOND_MACHINE_STATUS:-}" != "$rc_second_status" &&
        "${RC_SECOND_MACHINE_STATUS:-}" != "$rc_second_waiver_status" ]]; then
    release_die "RC sealing requires a validated second-machine admission or an explicit maintainer waiver"
  fi
  [[ "${RC_SECOND_MACHINE_REPORT_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || \
    release_die "RC sealing requires the downloaded second-machine report SHA-256"
  [[ "${RC_SECOND_MACHINE_SO_SHA256:-}" =~ ^[0-9a-f]{64}$ ]] || \
    release_die "RC sealing requires the report-derived audited SO SHA-256"
  [[ "${RC_SECOND_MACHINE_EXPIRES_AT:-}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || \
    release_die "RC sealing requires the report-derived fixed expiration"
  if [[ "${RC_SECOND_MACHINE_STATUS:-}" == "$rc_second_waiver_status" ]]; then
    require_positive RC_SECOND_MACHINE_REPORT_SIZE
  fi

  require_positive RC_CANDIDATE_ARTIFACT_ID
  require_positive RC_CANDIDATE_ARTIFACT_SIZE
  require_digest RC_CANDIDATE_ARTIFACT_DIGEST
  if [[ "${RC_SECOND_MACHINE_STATUS:-}" == "$rc_second_status" ]]; then
    require_positive RC_SECOND_MACHINE_RELEASE_ID
    require_positive RC_SECOND_MACHINE_ASSET_ID
    require_positive RC_SECOND_MACHINE_ASSET_SIZE
    require_digest RC_SECOND_MACHINE_ASSET_DIGEST
    [[ "$RC_SECOND_MACHINE_ASSET_DIGEST" == "sha256:$RC_SECOND_MACHINE_REPORT_SHA256" ]] || \
      release_die "second-machine API digest differs from the downloaded report SHA-256"
  else
    [[ "${RC_SECOND_MACHINE_RELEASE_ID:-}" == 0 &&
       "${RC_SECOND_MACHINE_ASSET_ID:-}" == 0 &&
       "${RC_SECOND_MACHINE_ASSET_SIZE:-}" == 0 &&
       -z "${RC_SECOND_MACHINE_ASSET_DIGEST:-}" ]] ||
      release_die "waived second-machine admission must use zero remote IDs and no remote asset digest"
  fi

  local run_id
  for run_id in "${RC_CI_RUN_ID:-}" "${RC_CODEQL_RUN_ID:-}" "${RC_POLICY_RUN_ID:-}"; do
    [[ "$run_id" =~ ^[1-9][0-9]*$ ]] || \
      release_die "RC sealing requires numeric exact-main workflow run IDs"
  done
  local run_attempt
  for run_attempt in "${RC_CI_RUN_ATTEMPT:-}" "${RC_CODEQL_RUN_ATTEMPT:-}" \
    "${RC_POLICY_RUN_ATTEMPT:-}"; do
    [[ "$run_attempt" =~ ^[1-9][0-9]*$ ]] || \
      release_die "RC sealing requires numeric exact-main workflow run attempts"
  done

  [[ "${GITHUB_ACTIONS:-false}" == true ]] || \
    release_die "RC assets may only be sealed by GitHub Actions"
  [[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] || \
    release_die "RC assets require the dedicated manual workflow"
  [[ "${GITHUB_REPOSITORY:-}" == "$rc_repository" ]] || \
    release_die "RC assets require the canonical repository"
  [[ "${GITHUB_REF:-}" == "refs/tags/$rc_tag" ]] || \
    release_die "RC workflow must be dispatched from the exact tag ref"
  [[ "${GITHUB_SHA:-}" == "$RELEASE_GIT_COMMIT" ]] || \
    release_die "RC workflow SHA differs from the checked-out commit"
  [[ "${GITHUB_WORKFLOW_SHA:-}" == "$RELEASE_GIT_COMMIT" ]] || \
    release_die "RC workflow source SHA differs from the checked-out commit"
  [[ "${GITHUB_WORKFLOW_REF:-}" == \
    "${rc_repository}/${rc_workflow}@refs/tags/${rc_tag}" ]] || \
    release_die "RC workflow ref is not bound to the tagged workflow"
  [[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ ]] || \
    release_die "RC workflow run ID is missing"
  [[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]*$ ]] || \
    release_die "RC workflow run attempt is missing"
}

resolve_dist() {
  dist="${DIST_DIR:-$root/dist}"
  if [[ -e "$dist" && ( ! -d "$dist" || -L "$dist" ) ]]; then
    release_die "DIST_DIR must be a real directory"
  fi
  mkdir -p "$dist"
  dist="$(cd "$dist" && pwd -P)"
}

assert_exact_dist_assets() {
  local require_attestation="$1"
  local -a expected_assets=("${base_assets[@]}")
  if [[ "$require_attestation" == 1 ]]; then
    expected_assets+=("$rc_attestation_asset")
  fi
  local expected actual name
  expected="$(printf '%s\n' "${expected_assets[@]}" | LC_ALL=C sort)"
  actual="$(find "$dist" -mindepth 1 -maxdepth 1 -printf '%f\n' | LC_ALL=C sort)"
  [[ "$actual" == "$expected" ]] || {
    release_error "RC dist does not match the exact reviewed asset allowlist"
    diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
    exit 1
  }
  for name in "${expected_assets[@]}"; do
    require_regular_file "$dist/$name"
  done
}

validate_portable_and_candidate() {
  local report="$1"
  local candidate_directory="$2"
  if [[ "${RC_SECOND_MACHINE_STATUS:-}" == "$rc_second_waiver_status" ]]; then
    jq -e \
      --arg schema "$rc_second_waiver_schema" \
      --arg status "$rc_second_waiver_status" \
      --arg repository "$rc_repository" \
      --arg commit "$RELEASE_GIT_COMMIT" \
      --arg tree "$RELEASE_GIT_TREE" \
      --arg cpa_tag "$rc_cpa_version" \
      --arg cpa_commit "$rc_cpa_commit" \
      --argjson cpa_abi "$rc_cpa_c_abi" \
      --argjson cpa_rpc_schema "$rc_cpa_rpc_schema" \
      '.schema == $schema and .status == $status and .executed == false and
       .repository == $repository and .source.commit == $commit and
       .source.tree == $tree and .cpa.tag == $cpa_tag and
       .cpa.commit == $cpa_commit and .cpa.c_abi == $cpa_abi and
       .cpa.rpc_schema == $cpa_rpc_schema and
       .waiver.authorized_by == "yujianwudi" and
       .waiver.acknowledgment == "I_ACK_SECOND_MACHINE_NOT_RUN"' \
      "$report" >/dev/null || release_die "maintainer waiver report identity is invalid"
    [[ "$(hash_file "$report")" == "$RC_SECOND_MACHINE_REPORT_SHA256" ]] ||
      release_die "waiver report bytes differ from the admitted SHA-256"
    [[ "$(stat -c %s "$report")" == "$RC_SECOND_MACHINE_REPORT_SIZE" ]] ||
      release_die "waiver report size differs from the admitted size"
    return 0
  fi
  python3 -B "$root/tools/current-cpa-audit/second_machine_release_admission.py" validate \
    --report "$report" \
    --expected-repository "$rc_repository" \
    --expected-commit "$RELEASE_GIT_COMMIT" \
    --expected-tree "$RELEASE_GIT_TREE" \
    --expected-candidate-run-id "$RC_CI_RUN_ID" \
    --expected-candidate-run-attempt "$RC_CI_RUN_ATTEMPT" \
    --expected-candidate-artifact-id "$RC_CANDIDATE_ARTIFACT_ID" \
    --expected-candidate-artifact-digest "$RC_CANDIDATE_ARTIFACT_DIGEST" \
    --expected-candidate-artifact-size "$RC_CANDIDATE_ARTIFACT_SIZE" \
    --candidate-directory "$candidate_directory" >/dev/null || return $?
  [[ "$(hash_file "$report")" == "$RC_SECOND_MACHINE_REPORT_SHA256" ]] || \
    release_die "portable report bytes differ from the GitHub-admitted SHA-256"
  [[ "$(stat -c %s "$report")" == "$RC_SECOND_MACHINE_ASSET_SIZE" ]] || \
    release_die "portable report bytes differ from the GitHub-admitted size"
  jq -e \
    --arg schema "$rc_second_schema" \
    --arg status "$RC_SECOND_MACHINE_STATUS" \
    --arg expires "$RC_SECOND_MACHINE_EXPIRES_AT" \
    --arg cpa_tag "$rc_cpa_version" \
    --arg cpa_commit "$rc_cpa_commit" \
    --argjson cpa_abi "$rc_cpa_c_abi" \
    --argjson cpa_rpc_schema "$rc_cpa_rpc_schema" \
    '.schema == $schema and .status == $status and .expires_at == $expires and
     .cpa.tag == $cpa_tag and .cpa.commit == $cpa_commit and
     .cpa.c_abi == $cpa_abi and .cpa.rpc_schema == $cpa_rpc_schema' \
    "$report" >/dev/null || \
    release_die "portable report schema, status, expiration, or CPA identity drifted"
}

create_source_archive() {
  release_require_commands git tar grep mktemp chmod mv rm
  local temporary listing archive_prefix
  local -a archive_pathspecs
  archive_prefix="cyber-abuse-guard-v${rc_artifact_version}/"
  temporary="$(mktemp "$dist/.source-release.XXXXXX")"
  archive_pathspecs=(
    .
    ':(exclude,glob).round9-local-sandbox/**'
    ':(exclude,glob,icase)cmd/**/*evaluation*'
    ':(exclude,glob,icase)cmd/**/*holdout*'
    ':(exclude,glob,icase)cmd/**/*consumed*'
    ':(exclude,glob,icase)cmd/**/*private*'
    ':(exclude,glob,icase)cmd/**/*blind*'
    ':(exclude,glob,icase)cmd/**/*retired*'
    ':(exclude,glob,icase)docs/**/*evaluation*'
    ':(exclude,glob,icase)docs/**/*holdout*'
    ':(exclude,glob,icase)docs/**/*consumed*'
    ':(exclude,glob,icase)docs/**/*private*'
    ':(exclude,glob,icase)docs/**/*blind*'
    ':(exclude,glob,icase)docs/**/*retired*'
    ':(exclude,glob,icase)internal/classifier/**/*evaluation*'
    ':(exclude,glob,icase)internal/classifier/**/*holdout*'
    ':(exclude,glob,icase)internal/classifier/**/*consumed*'
    ':(exclude,glob,icase)internal/classifier/**/*private*'
    ':(exclude,glob,icase)internal/classifier/**/*blind*'
    ':(exclude,glob,icase)internal/classifier/**/*retired*'
    ':(exclude,glob,icase)testdata/**/*evaluation*'
    ':(exclude,glob,icase)testdata/**/*holdout*'
    ':(exclude,glob,icase)testdata/**/*consumed*'
    ':(exclude,glob,icase)testdata/**/*private*'
    ':(exclude,glob,icase)testdata/**/*blind*'
    ':(exclude,glob,icase)testdata/**/*retired*'
  )
  if ! git -C "$root" archive --format=tar.gz \
    --prefix="$archive_prefix" --output="$temporary" \
    "$RELEASE_GIT_COMMIT" -- "${archive_pathspecs[@]}"; then
    rm -f -- "$temporary"
    release_die "failed to create the exact RC source archive"
  fi
  listing="$(tar -tzf "$temporary")"
  [[ -n "$listing" ]] || release_die "RC source archive is empty"
  if grep -Ev "^${archive_prefix}" <<<"$listing" | grep -q .; then
    release_die "RC source archive contains an entry outside its fixed prefix"
  fi
  if grep -Eiq '(^|/)(\.git($|/)|dist($|/)|build($|/)|[^/]*\.(db|sqlite|sqlite3|key|pem|p12|pfx|jks|keystore|log)($|[-.])|\.env($|[./])|id_(ed25519|ed25519_servers|rsa|dsa|ecdsa)(\.pub)?($|/)|[^/]*\.ppk($|/))' <<<"$listing"; then
    release_die "RC source archive contains a forbidden repository, build, database, secret, or log path"
  fi
  if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<"$listing"; then
    release_die "RC source archive contains restricted evaluation material"
  fi
  if tar -tvzf "$temporary" | grep -Eq '^l'; then
    release_die "RC source archive contains a symbolic link"
  fi
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$dist/$source_archive"
  (cd "$dist" && sha256sum "$source_archive" >"$source_archive.sha256")
}

create_cpa_store_assets() {
  python3 -B "$root/scripts/release_rc_cpa_store.py" create \
    --source "$dist/$so" \
    --output "$dist/$cpa_store_zip"
  (cd "$dist" && sha256sum "$so" "$audit_store_zip" "$cpa_store_zip" >checksums.txt)
}

write_release_evidence() {
  local evidence="$dist/release-evidence.md"
  local temporary release_time name
  temporary="$(mktemp "$dist/.release-evidence.XXXXXX")"
  release_time="$(date -u -d "@$RELEASE_SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
  {
    printf '# Cyber Abuse Guard %s RC release evidence\n\n' "$rc_tag"
    printf -- '- Status: `PRERELEASE / LINUX AMD64 ONLY / NOT FORMAL / NOT STABLE PRODUCTION APPROVAL`\n'
    printf -- '- Annotated tag: `%s`\n' "$rc_tag"
    printf -- '- Signed annotated tag verification: `%s`\n' "$RC_TAG_VERIFICATION_STATUS"
    printf -- '- Tag signer policy: `%s`\n' "$rc_tag_signer_policy"
    printf -- '- Annotated tag object: `%s`\n' "$RC_TAG_OBJECT_SHA"
    printf -- '- Commit: `%s`\n' "$RELEASE_GIT_COMMIT"
    printf -- '- Tree: `%s`\n' "$RELEASE_GIT_TREE"
    printf -- '- Source version: `%s`; audited binary version: `%s`; Release artifact version: `%s`\n' \
      "$rc_source_version" "$rc_binary_version" "$rc_artifact_version"
    printf -- '- Audited binary name/SHA-256: `%s` / `%s`\n' "$so" "$RC_SECOND_MACHINE_SO_SHA256"
    printf -- '- Source date (UTC): `%s`\n' "$release_time"
    printf -- '- CPA compatibility target: `%s` (`%s`), C ABI `%s`, RPC schema `%s`\n' \
      "$rc_cpa_version" "$rc_cpa_commit" "$rc_cpa_c_abi" "$rc_cpa_rpc_schema"
    printf -- '- Portable second-machine admission schema: `%s`\n' "$rc_second_schema"
    printf -- '- Exact-main CI run/attempt: `%s` / `%s`\n' "$RC_CI_RUN_ID" "$RC_CI_RUN_ATTEMPT"
    printf -- '- Exact-main CodeQL run/attempt: `%s` / `%s`\n' "$RC_CODEQL_RUN_ID" "$RC_CODEQL_RUN_ATTEMPT"
    printf -- '- Exact-main policy run/attempt: `%s` / `%s`\n' "$RC_POLICY_RUN_ID" "$RC_POLICY_RUN_ATTEMPT"
    printf -- '- CI audit-candidate artifact ID/digest/size: `%s` / `%s` / `%s`\n' \
      "$RC_CANDIDATE_ARTIFACT_ID" "$RC_CANDIDATE_ARTIFACT_DIGEST" "$RC_CANDIDATE_ARTIFACT_SIZE"
    printf -- '- Second-machine owner admission: `%s`\n' "$RC_SECOND_MACHINE_STATUS"
    printf -- '- Second-machine staging Release/asset IDs: `%s` / `%s`\n' \
      "$RC_SECOND_MACHINE_RELEASE_ID" "$RC_SECOND_MACHINE_ASSET_ID"
    printf -- '- Second-machine asset API digest/size: `%s` / `%s`\n' \
      "$RC_SECOND_MACHINE_ASSET_DIGEST" "$RC_SECOND_MACHINE_ASSET_SIZE"
    printf -- '- Second-machine report SHA-256/expires: `%s` / `%s`\n' \
      "$RC_SECOND_MACHINE_REPORT_SHA256" "$RC_SECOND_MACHINE_EXPIRES_AT"
    printf -- '- Report-derived CPA tag/commit/binary SHA-256: `%s` / `%s` / `%s`\n' \
      "$(jq -r '.cpa.tag' "$dist/$rc_second_report")" \
      "$(jq -r '.cpa.commit' "$dist/$rc_second_report")" \
      "$(jq -r '.cpa.binary_sha256' "$dist/$rc_second_report")"
    printf -- '- Report-derived corpus repositories/sources/semantic cases: `%s` / `%s` / `%s`\n' \
      "$(jq -r '.corpus.repository_count' "$dist/$rc_second_report")" \
      "$(jq -r '.corpus.source_count' "$dist/$rc_second_report")" \
      "$(jq -r '.corpus.unique_semantic_cases' "$dist/$rc_second_report")"
    printf -- '- Report-derived false positives/malicious recall/side-effect violations: `%s` / `%s%%` / `%s`\n' \
      "$(jq -r '.summary.false_positives' "$dist/$rc_second_report")" \
      "$(jq -r '.summary.malicious_recall_percent' "$dist/$rc_second_report")" \
      "$(jq -r '.summary.side_effect_violations' "$dist/$rc_second_report")"
    printf -- '- Report-derived performance/cleanup/third-party execution: `%s/%s gates` / `%s` / `%s`\n' \
      "$(jq -r '.summary.performance_gates_passed' "$dist/$rc_second_report")" \
      "$(jq -r '.summary.performance_gate_count' "$dist/$rc_second_report")" \
      "$(jq -r '.summary.cleanup_pass' "$dist/$rc_second_report")" \
      "$(jq -r '.summary.third_party_code_executions' "$dist/$rc_second_report")"
    printf -- '- Workflow run/attempt: `%s` / `%s`\n\n' "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"
    printf 'The RC workflow downloaded the unique live nine-file candidate artifact from the exact protected-main CI run. '
    printf 'The standalone `%s`, audited candidate Store ZIP, build metadata, ruleset files, SBOM, candidate checksums, and candidate manifest are reused byte-for-byte. ' "$so"
    printf 'The CPA-facing `%s` is a deterministic derived container with one root `cyber-abuse-guard.so` entry whose payload is byte-identical to the audited standalone SO; `checksums.txt` is generated for CPA and the candidate checksum anchor remains `%s`. ' "$cpa_store_zip" "$audit_checksums"
    if [[ "$RC_SECOND_MACHINE_STATUS" == "$rc_second_waiver_status" ]]; then
      printf 'The second-machine requirement was explicitly waived by the repository maintainer. No second-machine execution or independent Host admission is claimed. The waiver is not an independent audit or independent proof.\n\n'
    else
      printf 'The canonical second-machine report was downloaded from the fixed-name asset of an exact-commit draft Release, rehashed, checked for expiry, and validated by the exact tagged code. '
      printf 'It is owner-run corroboration and release admission, not an independent audit or independent proof.\n\n'
    fi
    printf '## Core artifact SHA-256\n\n| Asset | SHA-256 |\n|---|---|\n'
    for name in "${core_assets[@]}"; do
      printf '| `%s` | `%s` |\n' "$name" "$(hash_file "$dist/$name")"
    done
  } >"$temporary"
  release_assert_no_sensitive_env_values "$temporary" \
    CPA_MANAGEMENT_KEY CYBER_ABUSE_GUARD_HMAC_KEY CYBER_ABUSE_GUARD_HMAC_KEY_FILE \
    GITHUB_TOKEN GH_TOKEN GOVERNANCE_TOKEN CAG_RELEASE_GOVERNANCE_TOKEN \
    OPENAI_API_KEY ANTHROPIC_API_KEY GOOGLE_API_KEY \
    AZURE_OPENAI_API_KEY AWS_SECRET_ACCESS_KEY DATABASE_URL
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$evidence"
}

write_release_provenance() {
  local temporary subjects name
  temporary="$(mktemp "$dist/.release-provenance.XXXXXX")"
  subjects='[]'
  for name in "${provenance_subject_assets[@]}"; do
    subjects="$(jq -c --argjson subjects "$subjects" --arg name "$name" \
      --arg sha256 "$(hash_file "$dist/$name")" \
      '$subjects + [{name: $name, digest: {sha256: $sha256}}]' <<<null)"
  done
  jq -n -S \
    --arg tag "$rc_tag" \
    --arg release_version "$rc_artifact_version" \
    --arg source_version "$rc_source_version" \
    --arg binary_version "$rc_binary_version" \
    --arg repository "$rc_repository" \
    --arg commit "$RELEASE_GIT_COMMIT" \
    --arg tree "$RELEASE_GIT_TREE" \
    --arg tag_object "$RC_TAG_OBJECT_SHA" \
    --arg workflow "$rc_workflow" \
    --arg workflow_ref "$GITHUB_WORKFLOW_REF" \
    --argjson run_id "$GITHUB_RUN_ID" \
    --argjson run_attempt "$GITHUB_RUN_ATTEMPT" \
    --argjson ci_run_id "$RC_CI_RUN_ID" \
    --argjson ci_run_attempt "$RC_CI_RUN_ATTEMPT" \
    --argjson codeql_run_id "$RC_CODEQL_RUN_ID" \
    --argjson codeql_run_attempt "$RC_CODEQL_RUN_ATTEMPT" \
    --argjson policy_run_id "$RC_POLICY_RUN_ID" \
    --argjson policy_run_attempt "$RC_POLICY_RUN_ATTEMPT" \
    --arg candidate_name "$rc_candidate_name" \
    --argjson candidate_id "$RC_CANDIDATE_ARTIFACT_ID" \
    --arg candidate_digest "$RC_CANDIDATE_ARTIFACT_DIGEST" \
    --argjson candidate_size "$RC_CANDIDATE_ARTIFACT_SIZE" \
    --arg second_status "$RC_SECOND_MACHINE_STATUS" \
    --argjson second_release_id "$RC_SECOND_MACHINE_RELEASE_ID" \
    --argjson second_asset_id "$RC_SECOND_MACHINE_ASSET_ID" \
    --arg second_asset_digest "$RC_SECOND_MACHINE_ASSET_DIGEST" \
    --argjson second_asset_size "$RC_SECOND_MACHINE_ASSET_SIZE" \
    --arg second_expires_at "$RC_SECOND_MACHINE_EXPIRES_AT" \
    --arg second_report_sha256 "$RC_SECOND_MACHINE_REPORT_SHA256" \
    --arg second_so_sha256 "$RC_SECOND_MACHINE_SO_SHA256" \
    --arg second_schema "$rc_second_schema" \
    --arg cpa_version "$rc_cpa_version" \
    --arg cpa_commit "$rc_cpa_commit" \
    --argjson cpa_abi "$rc_cpa_c_abi" \
    --argjson cpa_rpc_schema "$rc_cpa_rpc_schema" \
    --arg cpa_store_zip "$cpa_store_zip" \
    --arg audited_so "$so" \
    --arg attestation_action "$rc_attestation_action" \
    --argjson subjects "$subjects" \
    '{
      schema_version: 3,
      statement: "audited candidate byte-reuse record; signed GitHub attestation is separate",
      tag: $tag,
      release_artifact_version: $release_version,
      source_version: $source_version,
      binary_version: $binary_version,
      source: {repository: $repository, commit: $commit, tree: $tree, tag_object: $tag_object},
      builder: {workflow: $workflow, workflow_ref: $workflow_ref, run_id: $run_id, run_attempt: $run_attempt, attestation_action: $attestation_action},
      protected_main_workflow_runs: {
        ci: {id: $ci_run_id, attempt: $ci_run_attempt},
        codeql: {id: $codeql_run_id, attempt: $codeql_run_attempt},
        policy: {id: $policy_run_id, attempt: $policy_run_attempt}
      },
      audited_candidate: {
        name: $candidate_name, id: $candidate_id, digest: $candidate_digest,
        size: $candidate_size, original_bytes_reused: true,
        so: {name: "cyber-abuse-guard-v1.0.0.so", sha256: $second_so_sha256}
      },
      derived_artifacts: [{
        name: $cpa_store_zip, relationship: "cpa-plugin-store-container",
        derived_from: {name: $audited_so, sha256: $second_so_sha256},
        archive_entry: "cyber-abuse-guard.so", payload_sha256: $second_so_sha256,
        recompiled: false, standalone_renamed: false
      }],
      second_machine_owner_admission: {
        schema: $second_schema,
        status: $second_status, release_id: $second_release_id, asset_id: $second_asset_id,
        asset_digest: $second_asset_digest, asset_size: $second_asset_size,
        report_name: "second-machine-release-admission.json", report_sha256: $second_report_sha256,
        expires_at: $second_expires_at, independent_proof: false
      },
      host_compatibility: {
        version: $cpa_version, commit: $cpa_commit,
        c_abi: $cpa_abi, rpc_schema: $cpa_rpc_schema
      },
      subjects: $subjects
    }' >"$temporary"
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$dist/release-provenance.json"
}

write_release_manifest() {
  local temporary assets name
  temporary="$(mktemp "$dist/.release-manifest.XXXXXX")"
  assets='[]'
  for name in "${manifest_assets[@]}"; do
    assets="$(jq -c --argjson assets "$assets" --arg name "$name" \
      --arg sha256 "$(hash_file "$dist/$name")" \
      '$assets + [{name: $name, sha256: $sha256}]' <<<null)"
  done
  jq -n -S \
    --arg tag "$rc_tag" \
    --arg source_version "$rc_source_version" \
    --arg binary_version "$rc_binary_version" \
    --arg artifact_version "$rc_artifact_version" \
    --arg repository "$rc_repository" \
    --arg commit "$RELEASE_GIT_COMMIT" \
    --arg tree "$RELEASE_GIT_TREE" \
    --arg tag_object "$RC_TAG_OBJECT_SHA" \
    --arg cpa_version "$rc_cpa_version" \
    --arg cpa_commit "$rc_cpa_commit" \
    --argjson cpa_abi "$rc_cpa_c_abi" \
    --argjson cpa_rpc_schema "$rc_cpa_rpc_schema" \
    --arg cpa_store_zip "$cpa_store_zip" \
    --arg audit_store_zip "$audit_store_zip" \
    --arg audit_checksums "$audit_checksums" \
    --argjson ci_run_id "$RC_CI_RUN_ID" \
    --argjson ci_run_attempt "$RC_CI_RUN_ATTEMPT" \
    --argjson codeql_run_id "$RC_CODEQL_RUN_ID" \
    --argjson codeql_run_attempt "$RC_CODEQL_RUN_ATTEMPT" \
    --argjson policy_run_id "$RC_POLICY_RUN_ID" \
    --argjson policy_run_attempt "$RC_POLICY_RUN_ATTEMPT" \
    --arg candidate_name "$rc_candidate_name" \
    --argjson candidate_id "$RC_CANDIDATE_ARTIFACT_ID" \
    --arg candidate_digest "$RC_CANDIDATE_ARTIFACT_DIGEST" \
    --argjson candidate_size "$RC_CANDIDATE_ARTIFACT_SIZE" \
    --arg second_status "$RC_SECOND_MACHINE_STATUS" \
    --argjson second_release_id "$RC_SECOND_MACHINE_RELEASE_ID" \
    --argjson second_asset_id "$RC_SECOND_MACHINE_ASSET_ID" \
    --arg second_asset_digest "$RC_SECOND_MACHINE_ASSET_DIGEST" \
    --argjson second_asset_size "$RC_SECOND_MACHINE_ASSET_SIZE" \
    --arg second_expires_at "$RC_SECOND_MACHINE_EXPIRES_AT" \
    --arg second_report_sha256 "$RC_SECOND_MACHINE_REPORT_SHA256" \
    --arg second_so_sha256 "$RC_SECOND_MACHINE_SO_SHA256" \
    --arg second_schema "$rc_second_schema" \
    --arg attestation_asset "$rc_attestation_asset" \
    --arg attestation_action "$rc_attestation_action" \
    --argjson assets "$assets" \
    '{
      schema_version: 3,
      status: "RC_PRERELEASE",
      tag: $tag,
      source_version: $source_version,
      binary_version: $binary_version,
      release_artifact_version: $artifact_version,
      platforms: ["linux/amd64"],
      source: {repository: $repository, commit: $commit, tree: $tree, tag_object: $tag_object, dirty: false},
      binary: {name: "cyber-abuse-guard-v1.0.0.so", sha256: $second_so_sha256, recompiled_for_rc: false, renamed_for_rc: false},
      cpa_plugin_store: {
        release_version: $artifact_version, archive: $cpa_store_zip,
        archive_entry: "cyber-abuse-guard.so", payload_sha256: $second_so_sha256,
        derived_from: {name: "cyber-abuse-guard-v1.0.0.so", sha256: $second_so_sha256},
        audited_candidate_archive: $audit_store_zip,
        audited_candidate_checksums: $audit_checksums,
        recompiled: false, standalone_rc_named_so_published: false
      },
      host_compatibility: {
        version: $cpa_version, commit: $cpa_commit,
        c_abi: $cpa_abi, rpc_schema: $cpa_rpc_schema,
        version_policy: "fixed-no-latest-follow"
      },
      admission: {
        status: "EXACT_PROTECTED_MAIN_CHECKS_PASS",
        workflow_runs: {
          ci: {id: $ci_run_id, attempt: $ci_run_attempt},
          codeql: {id: $codeql_run_id, attempt: $codeql_run_attempt},
          policy: {id: $policy_run_id, attempt: $policy_run_attempt}
        },
        audited_candidate: {name: $candidate_name, id: $candidate_id, digest: $candidate_digest, size: $candidate_size, original_bytes_reused: true},
        second_machine_owner_admission: {
          schema: $second_schema,
          status: $second_status, release_id: $second_release_id, asset_id: $second_asset_id,
          asset_digest: $second_asset_digest, asset_size: $second_asset_size,
          report_sha256: $second_report_sha256, expires_at: $second_expires_at,
          independent_proof: false
        }
      },
      publication: {draft_first: true, prerelease: true, latest: false, stable: false, production_approval: false},
      assets: $assets,
      attestation: {required: true, asset: $attestation_asset, action: $attestation_action, note: "generated after this manifest to avoid recursive self-inclusion"}
    }' >"$temporary"
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$dist/release-manifest.json"
}

write_release_checksums() {
  local temporary
  temporary="$(mktemp "$dist/.release-checksums.XXXXXX")"
  (cd "$dist" && sha256sum "${checksummed_assets[@]}" >"$temporary")
  chmod 0644 "$temporary"
  mv -f -- "$temporary" "$dist/release-checksums.txt"
}

verify_json_subjects() {
  local json_file="$1"
  shift
  local -a expected=("$@")
  local name sha256
  [[ "$(jq -r '.subjects | length' "$json_file")" == "${#expected[@]}" ]] || \
    release_die "release provenance subject count changed"
  for name in "${expected[@]}"; do
    sha256="$(hash_file "$dist/$name")"
    jq -e --arg name "$name" --arg sha256 "$sha256" \
      '([.subjects[] | select(.name == $name and .digest.sha256 == $sha256)] | length) == 1' \
      "$json_file" >/dev/null || release_die "release provenance does not bind $name"
  done
}

verify_manifest_assets() {
  local name sha256
  [[ "$(jq -r '.assets | length' "$dist/release-manifest.json")" == "${#manifest_assets[@]}" ]] || \
    release_die "release manifest asset count changed"
  for name in "${manifest_assets[@]}"; do
    sha256="$(hash_file "$dist/$name")"
    jq -e --arg name "$name" --arg sha256 "$sha256" \
      '([.assets[] | select(.name == $name and .sha256 == $sha256)] | length) == 1' \
      "$dist/release-manifest.json" >/dev/null || release_die "release manifest does not bind $name"
  done
}

validate_dist_candidate() (
  local stage name
  stage="$(mktemp -d)"
  trap 'rm -rf -- "$stage"' EXIT
  for name in "${candidate_input_assets[@]}"; do
    if [[ "$name" == checksums.txt ]]; then
      install -m 0644 "$dist/$audit_checksums" "$stage/checksums.txt"
    else
      install -m 0644 "$dist/$name" "$stage/$name"
    fi
  done
  validate_portable_and_candidate "$dist/$rc_second_report" "$stage"
)

verify_assets() {
  local require_attestation="$1"
  [[ "$require_attestation" =~ ^[01]$ ]] || \
    release_die "REQUIRE_ATTESTATION must be exactly 0 or 1"
  resolve_dist
  assert_exact_dist_assets "$require_attestation"
  validate_dist_candidate

  (
    cd "$dist"
    sha256sum -c "$so.sha256"
    sha256sum -c "$source_archive.sha256"
    sha256sum -c ruleset.sha256
    sha256sum -c "$audit_checksums"
    sha256sum -c checksums.txt
    sha256sum -c release-checksums.txt
  )
  local expected_checksums actual_checksums
  expected_checksums="$(printf '%s\n' "${checksummed_assets[@]}" | LC_ALL=C sort)"
  actual_checksums="$(awk '{print $2}' "$dist/release-checksums.txt" | LC_ALL=C sort)"
  [[ "$actual_checksums" == "$expected_checksums" ]] || \
    release_die "release-checksums.txt does not cover the exact pre-attestation RC set"
  local expected_cpa_checksums actual_cpa_checksums
  expected_cpa_checksums="$(printf '%s\n' "$so" "$audit_store_zip" "$cpa_store_zip" | LC_ALL=C sort)"
  actual_cpa_checksums="$(awk '{print $2}' "$dist/checksums.txt" | LC_ALL=C sort)"
  [[ "$actual_cpa_checksums" == "$expected_cpa_checksums" ]] || \
    release_die "checksums.txt does not cover the exact CPA-facing release assets"
  [[ "$(hash_file "$dist/$so")" == "$RC_SECOND_MACHINE_SO_SHA256" ]] || \
    release_die "released SO differs from the report-derived audited SO"
  [[ ! -e "$dist/cyber-abuse-guard-v${rc_artifact_version}.so" ]] || \
    release_die "RC seal illegally renamed or recompiled the audited SO"

  local file_output elf_header audit_store_listing cpa_store_listing source_listing
  file_output="$(file "$dist/$so")"
  grep -Fq 'ELF 64-bit' <<<"$file_output"
  grep -Fq 'shared object' <<<"$file_output"
  grep -Fq 'x86-64' <<<"$file_output"
  elf_header="$(readelf -h "$dist/$so")"
  grep -Eq 'Class:[[:space:]]+ELF64' <<<"$elf_header"
  grep -Eq 'Type:[[:space:]]+DYN' <<<"$elf_header"
  grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' <<<"$elf_header"
  audit_store_listing="$(unzip -Z1 "$dist/$audit_store_zip")"
  [[ "$audit_store_listing" == "$so" ]] || \
    release_die "audited Store ZIP must contain exactly the root v1.0.0 SO"
  unzip -p "$dist/$audit_store_zip" "$so" | cmp -s - "$dist/$so" || \
    release_die "audited Store ZIP SO differs from the standalone bytes"
  cpa_store_listing="$(unzip -Z1 "$dist/$cpa_store_zip")"
  [[ "$cpa_store_listing" == cyber-abuse-guard.so ]] || \
    release_die "CPA RC Store ZIP must contain exactly one root unversioned SO"
  unzip -p "$dist/$cpa_store_zip" cyber-abuse-guard.so | cmp -s - "$dist/$so" || \
    release_die "CPA RC Store ZIP payload differs from the audited standalone SO"

  jq -e --arg version "$rc_binary_version" --arg commit "$RELEASE_GIT_COMMIT" --arg tree "$RELEASE_GIT_TREE" '
    .schema_version == 4 and .version == $version and .source_version == $version and
    .commit == $commit and .tree == $tree and .dirty == false and
    .goos == "linux" and .goarch == "amd64" and .cgo_enabled == true
  ' "$dist/build-metadata.json" >/dev/null || \
    release_die "reused build metadata does not bind the audited v1.0.0 Linux amd64 bytes"
  jq -e --arg version "$rc_binary_version" --arg sha256 "$RELEASE_RULESET_SHA256" \
    '.plugin_version == $version and .ruleset_sha256 == $sha256' \
    "$dist/ruleset-manifest.json" >/dev/null || \
    release_die "reused ruleset manifest does not bind the audited binary/ruleset"

  grep -Fq -- "- Annotated tag: \`$rc_tag\`" "$dist/release-evidence.md"
  grep -Fq -- "- Audited binary name/SHA-256: \`$so\` / \`$RC_SECOND_MACHINE_SO_SHA256\`" "$dist/release-evidence.md"
  grep -Fq -- "- CI audit-candidate artifact ID/digest/size: \`$RC_CANDIDATE_ARTIFACT_ID\` / \`$RC_CANDIDATE_ARTIFACT_DIGEST\` / \`$RC_CANDIDATE_ARTIFACT_SIZE\`" "$dist/release-evidence.md"
  grep -Fq -- "- Second-machine staging Release/asset IDs: \`$RC_SECOND_MACHINE_RELEASE_ID\` / \`$RC_SECOND_MACHINE_ASSET_ID\`" "$dist/release-evidence.md"
  grep -Fq -- 'not an independent audit or independent proof' "$dist/release-evidence.md"

  jq -e \
    --arg tag "$rc_tag" --arg version "$rc_artifact_version" \
    --arg binary_version "$rc_binary_version" --arg commit "$RELEASE_GIT_COMMIT" \
    --arg tree "$RELEASE_GIT_TREE" --argjson candidate_id "$RC_CANDIDATE_ARTIFACT_ID" \
    --arg candidate_digest "$RC_CANDIDATE_ARTIFACT_DIGEST" \
    --argjson second_release_id "$RC_SECOND_MACHINE_RELEASE_ID" \
    --argjson second_asset_id "$RC_SECOND_MACHINE_ASSET_ID" \
    --arg second_digest "$RC_SECOND_MACHINE_ASSET_DIGEST" \
    --arg second_schema "$rc_second_schema" \
    --arg cpa_version "$rc_cpa_version" --arg cpa_commit "$rc_cpa_commit" \
    --argjson cpa_abi "$rc_cpa_c_abi" --argjson cpa_rpc_schema "$rc_cpa_rpc_schema" \
    --arg so_sha "$RC_SECOND_MACHINE_SO_SHA256" \
    '.schema_version == 3 and .tag == $tag and .release_artifact_version == $version and
     .binary_version == $binary_version and .source.commit == $commit and .source.tree == $tree and
     .host_compatibility == {version: $cpa_version, commit: $cpa_commit,
       c_abi: $cpa_abi, rpc_schema: $cpa_rpc_schema} and
     .audited_candidate.id == $candidate_id and .audited_candidate.digest == $candidate_digest and
     .audited_candidate.original_bytes_reused == true and
     .second_machine_owner_admission.schema == $second_schema and
     .second_machine_owner_admission.release_id == $second_release_id and
     .second_machine_owner_admission.asset_id == $second_asset_id and
     .second_machine_owner_admission.asset_digest == $second_digest and
     .second_machine_owner_admission.independent_proof == false and
     .derived_artifacts == [{name: "cyber-abuse-guard_1.0.0-rc.1_linux_amd64.zip",
       relationship: "cpa-plugin-store-container",
       derived_from: {name: "cyber-abuse-guard-v1.0.0.so", sha256: $so_sha},
       archive_entry: "cyber-abuse-guard.so", payload_sha256: $so_sha,
       recompiled: false, standalone_renamed: false}]' \
    "$dist/release-provenance.json" >/dev/null || release_die "release provenance identity mismatch"
  verify_json_subjects "$dist/release-provenance.json" "${provenance_subject_assets[@]}"

  jq -e \
    --arg tag "$rc_tag" --arg version "$rc_artifact_version" \
    --arg binary_version "$rc_binary_version" --arg so "$so" \
    --arg so_sha "$RC_SECOND_MACHINE_SO_SHA256" \
    --argjson candidate_id "$RC_CANDIDATE_ARTIFACT_ID" \
    --arg candidate_digest "$RC_CANDIDATE_ARTIFACT_DIGEST" \
    --argjson second_release_id "$RC_SECOND_MACHINE_RELEASE_ID" \
    --argjson second_asset_id "$RC_SECOND_MACHINE_ASSET_ID" \
    --arg second_digest "$RC_SECOND_MACHINE_ASSET_DIGEST" \
    --arg second_schema "$rc_second_schema" \
    --arg cpa_version "$rc_cpa_version" --arg cpa_commit "$rc_cpa_commit" \
    --argjson cpa_abi "$rc_cpa_c_abi" --argjson cpa_rpc_schema "$rc_cpa_rpc_schema" \
    --arg attestation "$rc_attestation_asset" '
    .schema_version == 3 and .status == "RC_PRERELEASE" and .tag == $tag and
    .binary_version == $binary_version and .release_artifact_version == $version and
    .binary == {name: $so, sha256: $so_sha, recompiled_for_rc: false, renamed_for_rc: false} and
    .host_compatibility == {version: $cpa_version, commit: $cpa_commit,
      c_abi: $cpa_abi, rpc_schema: $cpa_rpc_schema,
      version_policy: "fixed-no-latest-follow"} and
    .cpa_plugin_store == {
      release_version: $version, archive: "cyber-abuse-guard_1.0.0-rc.1_linux_amd64.zip",
      archive_entry: "cyber-abuse-guard.so", payload_sha256: $so_sha,
      derived_from: {name: $so, sha256: $so_sha},
      audited_candidate_archive: "cyber-abuse-guard_1.0.0_linux_amd64.zip",
      audited_candidate_checksums: "audit-candidate-checksums.txt",
      recompiled: false, standalone_rc_named_so_published: false
    } and
    .admission.audited_candidate.id == $candidate_id and
    .admission.audited_candidate.digest == $candidate_digest and
    .admission.audited_candidate.original_bytes_reused == true and
    .admission.second_machine_owner_admission.schema == $second_schema and
    .admission.second_machine_owner_admission.release_id == $second_release_id and
    .admission.second_machine_owner_admission.asset_id == $second_asset_id and
    .admission.second_machine_owner_admission.asset_digest == $second_digest and
    .admission.second_machine_owner_admission.independent_proof == false and
    .publication == {draft_first: true, prerelease: true, latest: false, stable: false, production_approval: false} and
    .attestation.required == true and .attestation.asset == $attestation
  ' "$dist/release-manifest.json" >/dev/null || release_die "release manifest identity mismatch"
  verify_manifest_assets
  python3 -B "$root/scripts/release_rc_cpa_store.py" verify-release --directory "$dist"
  (cd "$root/integration/pluginstorecontract" && \
    DIST_DIR="$dist" go test ./... -run '^TestPublishedRCStoreArchive$' -count=1)

  source_listing="$(tar -tzf "$dist/$source_archive")"
  grep -Fxq "cyber-abuse-guard-v${rc_artifact_version}/.github/workflows/release-rc.yml" \
    <<<"$source_listing" || release_die "source archive is missing the RC workflow"
  grep -Fxq "cyber-abuse-guard-v${rc_artifact_version}/scripts/release-rc.sh" \
    <<<"$source_listing" || release_die "source archive is missing the RC entry point"
  if grep -Ev "^cyber-abuse-guard-v${rc_artifact_version}/" <<<"$source_listing" | grep -q .; then
    release_die "source archive contains an entry outside its fixed prefix"
  fi
  if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<"$source_listing"; then
    release_die "source archive contains restricted evaluation material"
  fi
  if tar -tvzf "$dist/$source_archive" | grep -Eq '^l'; then
    release_die "source archive contains a symbolic link"
  fi

  if [[ "$require_attestation" == 1 ]]; then
    [[ "$(stat -c %s "$dist/$rc_attestation_asset")" -gt 0 ]] || \
      release_die "signed attestation bundle is empty"
    jq -s -e 'length > 0 and all(.[]; type == "object")' \
      "$dist/$rc_attestation_asset" >/dev/null || \
      release_die "signed attestation bundle is not valid JSONL"
  fi
  release_assert_source_unchanged
}

seal_candidate() {
  local candidate_directory="$1"
  local second_report_path="$2"
  resolve_dist
  if find "$dist" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
    release_die "RC seal requires an empty DIST_DIR"
  fi
  candidate_directory="$(cd "$candidate_directory" && pwd -P)"
  require_regular_file "$second_report_path"
  validate_portable_and_candidate "$second_report_path" "$candidate_directory"

  local name
  for name in "${candidate_input_assets[@]}"; do
    if [[ "$name" == checksums.txt ]]; then
      install -m 0644 "$candidate_directory/$name" "$dist/$audit_checksums"
    else
      install -m 0644 "$candidate_directory/$name" "$dist/$name"
    fi
  done
  install -m 0644 "$second_report_path" "$dist/$rc_second_report"
  create_cpa_store_assets
  create_source_archive
  write_release_evidence
  write_release_provenance
  write_release_manifest
  write_release_checksums
  verify_assets 0
  release_assert_source_unchanged
  printf 'RC assets sealed from the exact audited candidate bytes: %s\n' "$dist"
}

attach_attestation() {
  local bundle_path="$1"
  resolve_dist
  assert_exact_dist_assets 0
  require_regular_file "$bundle_path"
  [[ "$(stat -c %s "$bundle_path")" -gt 0 ]] || release_die "GitHub attestation bundle is empty"
  [[ "$(stat -c %s "$bundle_path")" -le 33554432 ]] || release_die "GitHub attestation bundle exceeds 32 MiB"
  jq -s -e 'length > 0 and all(.[]; type == "object")' "$bundle_path" >/dev/null || \
    release_die "GitHub attestation bundle is not valid JSONL"
  install -m 0644 "$bundle_path" "$dist/$rc_attestation_asset"
  release_assert_no_sensitive_env_values "$dist/$rc_attestation_asset" \
    CPA_MANAGEMENT_KEY CYBER_ABUSE_GUARD_HMAC_KEY CYBER_ABUSE_GUARD_HMAC_KEY_FILE \
    GITHUB_TOKEN GH_TOKEN GOVERNANCE_TOKEN CAG_RELEASE_GOVERNANCE_TOKEN \
    OPENAI_API_KEY ANTHROPIC_API_KEY GOOGLE_API_KEY \
    AZURE_OPENAI_API_KEY AWS_SECRET_ACCESS_KEY DATABASE_URL
  verify_assets 1
  printf 'signed RC attestation bundle attached: %s\n' "$dist/$rc_attestation_asset"
}

command_name="${1:-}"
case "$command_name" in
  seal-candidate)
    (($# == 3)) || usage
    init_rc_identity
    seal_candidate "$2" "$3"
    ;;
  verify)
    (($# == 1)) || usage
    init_rc_identity
    verify_assets "${REQUIRE_ATTESTATION:-1}"
    ;;
  attach-attestation)
    (($# == 2)) || usage
    init_rc_identity
    attach_attestation "$2"
    ;;
  *)
    usage
    ;;
esac
