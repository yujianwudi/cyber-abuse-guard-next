#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands make git jq sha256sum awk mktemp mv rm chmod

[[ "${GITHUB_ACTIONS:-false}" == true ]] || \
  release_die "Round6 clean candidates may only be produced by GitHub Actions"
[[ "${GITHUB_EVENT_NAME:-}" == workflow_dispatch ]] || \
  release_die "Round6 clean candidates require the dedicated manual workflow"
[[ "${GITHUB_REPOSITORY:-}" == yujianwudi/cyber-abuse-guard ]] || \
  release_die "Round6 clean candidates require the canonical repository"
[[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ ]] || \
  release_die "Round6 clean candidates require a numeric GitHub run ID"
[[ "${GITHUB_RUN_ATTEMPT:-}" =~ ^[1-9][0-9]*$ ]] || \
  release_die "Round6 clean candidates require a numeric run attempt"
[[ "${GITHUB_REF:-}" == refs/heads/main ]] || \
  release_die "Round6 clean candidates require the exact main ref"
[[ "${GITHUB_WORKFLOW_REF:-}" == \
  "${GITHUB_REPOSITORY}/.github/workflows/candidate.yml@${GITHUB_REF}" ]] || \
  release_die "Round6 clean candidates require the pinned candidate workflow ref"

release_init
release_assert_tag
release_assert_candidate_build
[[ "${GITHUB_SHA:-}" == "$RELEASE_GIT_COMMIT" ]] || \
  release_die "GitHub push SHA does not match the candidate commit"
[[ "${RELEASE_CANDIDATE_WORKFLOW_SHA:-}" == "$RELEASE_GIT_COMMIT" ]] || \
  release_die "candidate workflow source SHA does not match the candidate commit"

make -C "$root" -j1 round6-development-artifacts round6-cpa-store-contract artifact-hash

dist="${DIST_DIR:-$root/dist}"
so="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"
store_zip="cyber-abuse-guard_${RELEASE_ARTIFACT_VERSION}_linux_amd64.zip"
for artifact in \
  "$so" "$so.sha256" "$store_zip" build-metadata.json checksums.txt \
  ruleset-manifest.json ruleset.sha256 sbom.cdx.json; do
  [[ -f "$dist/$artifact" && ! -L "$dist/$artifact" ]] || \
    release_die "candidate artifact must be a regular non-symlink file: $dist/$artifact"
done

jq -e \
  --arg version "$RELEASE_SOURCE_VERSION" \
  --arg commit "$RELEASE_GIT_COMMIT" \
  --arg tree "$RELEASE_GIT_TREE" \
  '.version == $version and .source_version == $version and
   .commit == $commit and .tree == $tree and .dirty == false' \
  "$dist/build-metadata.json" >/dev/null || \
  release_die "candidate build metadata does not describe the clean exact source"

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

manifest="$dist/candidate-manifest.json"
temporary="$(mktemp "$dist/.candidate-manifest.XXXXXX")"
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT

jq -n \
  --arg version "$RELEASE_SOURCE_VERSION" \
  --arg commit "$RELEASE_GIT_COMMIT" \
  --arg tree "$RELEASE_GIT_TREE" \
  --argjson source_date_epoch "$RELEASE_SOURCE_DATE_EPOCH" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg workflow_ref "$GITHUB_WORKFLOW_REF" \
  --arg workflow_sha "$RELEASE_CANDIDATE_WORKFLOW_SHA" \
  --arg event "$GITHUB_EVENT_NAME" \
  --arg ref "$GITHUB_REF" \
  --argjson run_id "$GITHUB_RUN_ID" \
  --argjson run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg so "$so" \
  --arg so_sha256 "$(hash_file "$dist/$so")" \
  --arg store_zip "$store_zip" \
  --arg store_zip_sha256 "$(hash_file "$dist/$store_zip")" \
  --arg build_metadata_sha256 "$(hash_file "$dist/build-metadata.json")" \
  --arg ruleset_manifest_sha256 "$(hash_file "$dist/ruleset-manifest.json")" \
  --arg sbom_sha256 "$(hash_file "$dist/sbom.cdx.json")" \
  '{
    schema_version: 1,
    status: "UNRELEASED / HOST AND INDEPENDENT AUDIT REQUIRED",
    version: $version,
    commit: $commit,
    tree: $tree,
    source_date_epoch: $source_date_epoch,
    github: {
      repository: $repository,
      workflow_ref: $workflow_ref,
      workflow_sha: $workflow_sha,
      event: $event,
      ref: $ref,
      run_id: $run_id,
      run_attempt: $run_attempt
    },
    artifacts: {
      so: {name: $so, sha256: $so_sha256},
      store_zip: {name: $store_zip, sha256: $store_zip_sha256},
      build_metadata_sha256: $build_metadata_sha256,
      ruleset_manifest_sha256: $ruleset_manifest_sha256,
      sbom_sha256: $sbom_sha256
    }
  }' >"$temporary"

release_assert_no_sensitive_env_values "$temporary" \
  CPA_MANAGEMENT_KEY \
  CYBER_ABUSE_GUARD_HMAC_KEY \
  CYBER_ABUSE_GUARD_HMAC_KEY_FILE \
  GITHUB_TOKEN \
  GH_TOKEN \
  OPENAI_API_KEY \
  ANTHROPIC_API_KEY \
  GOOGLE_API_KEY \
  AZURE_OPENAI_API_KEY \
  AWS_SECRET_ACCESS_KEY \
  DATABASE_URL

chmod 0644 "$temporary"
mv -f -- "$temporary" "$manifest"
temporary=""
trap - EXIT
release_assert_source_unchanged
printf 'Round6 clean candidate manifest: %s\n' "$manifest"
