#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands git sha256sum awk date mktemp chmod mv rm mkdir basename jq make cp
release_init
release_assert_tag
release_assert_formal_build

dist="${DIST_DIR:-$root/dist}"
so="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"
store_zip="cyber-abuse-guard_${RELEASE_ARTIFACT_VERSION}_linux_amd64.zip"
bundle_zip="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}-audit-bundle.zip"
source_name="cyber-abuse-guard-v${RELEASE_SOURCE_VERSION}-source.tar.gz"
tag="v$RELEASE_SOURCE_VERSION"

required=(
  "$so"
  "$so.sha256"
  "$store_zip"
  "$bundle_zip"
  "checksums.txt"
  "build-metadata.json"
  "ruleset-manifest.json"
  "ruleset.sha256"
  "sbom.cdx.json"
  "release-test-summary.txt"
  "release-test-summary.txt.sha256"
  "$source_name"
  "$source_name.sha256"
)
for name in "${required[@]}"; do
  [[ -f "$dist/$name" && ! -L "$dist/$name" ]] || \
    release_die "final evidence input must be a regular non-symlink file: $dist/$name"
done
(cd "$dist" && sha256sum -c checksums.txt && sha256sum -c "$so.sha256" && \
  sha256sum -c ruleset.sha256 && sha256sum -c release-test-summary.txt.sha256 && \
  sha256sum -c "$source_name.sha256")

hash_file() {
  sha256sum "$1" | awk '{print $1}'
}

temporary=""
attestation_snapshot_dir=""
cleanup() {
  if [[ -n "$temporary" ]]; then
    rm -f -- "$temporary"
  fi
  if [[ -n "$attestation_snapshot_dir" ]]; then
    rm -rf -- "$attestation_snapshot_dir"
  fi
}
trap cleanup EXIT

external_attestation_input="${RELEASE_EXTERNAL_ATTESTATION:-}"
[[ -n "$external_attestation_input" ]] || \
  release_die "RELEASE_EXTERNAL_ATTESTATION is required for final evidence"
external_attestation_checksum="${external_attestation_input}.sha256"
[[ -f "$external_attestation_input" && ! -L "$external_attestation_input" ]] || \
  release_die "external release attestation input must be a regular non-symlink file"
[[ -f "$external_attestation_checksum" && ! -L "$external_attestation_checksum" ]] || \
  release_die "external release attestation checksum input must be a regular non-symlink file"
[[ "$(basename -- "$external_attestation_input")" == round6-prerelease-attestation.json ]] || \
  release_die "external release attestation input has an unexpected filename"
[[ "$(basename -- "$external_attestation_checksum")" == round6-prerelease-attestation.json.sha256 ]] || \
  release_die "external release attestation checksum input has an unexpected filename"

attestation_snapshot_dir="$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/cag-attestation-snapshot.XXXXXX")"
chmod 0700 "$attestation_snapshot_dir"
cp --no-dereference -- "$external_attestation_input" \
  "$attestation_snapshot_dir/round6-prerelease-attestation.json"
cp --no-dereference -- "$external_attestation_checksum" \
  "$attestation_snapshot_dir/round6-prerelease-attestation.json.sha256"
external_attestation="$attestation_snapshot_dir/round6-prerelease-attestation.json"
[[ -f "$external_attestation" && ! -L "$external_attestation" ]] || \
  release_die "external release attestation snapshot must be a regular non-symlink file"
[[ -f "${external_attestation}.sha256" && ! -L "${external_attestation}.sha256" ]] || \
  release_die "external release attestation checksum snapshot must be a regular non-symlink file"
chmod 0400 "$external_attestation" "${external_attestation}.sha256"

RELEASE_EXTERNAL_ATTESTATION="$external_attestation" \
  make -C "$root" external-release-attestation >/dev/null
external_attestation_sha256="$(hash_file "$external_attestation")"
candidate_tag="$(jq -r '.tag' "$external_attestation")"
candidate_run_id="$(jq -r '.candidate_run_id' "$external_attestation")"
evaluation_id="$(jq -r '.evidence.independent_evaluation_id' "$external_attestation")"
evaluation_status="$(jq -r '.evidence.independent_evaluation_status' "$external_attestation")"
evaluation_sha256="$(jq -r '.evidence.independent_evaluation_sha256' "$external_attestation")"
audit_sha256="$(jq -r '.evidence.independent_audit_sha256' "$external_attestation")"
cpa_version="$(jq -r '.evidence.cpa_version' "$external_attestation")"
cpa_commit="$(jq -r '.evidence.cpa_commit' "$external_attestation")"
host_evidence_sha256="$(jq -r '.evidence.cpa_host_sha256' "$external_attestation")"

tag_object="$(git -C "$root" rev-parse "refs/tags/$tag^{tag}")"
tag_target="$(git -C "$root" rev-list -n 1 "$tag")"
[[ "$tag_target" == "$RELEASE_GIT_COMMIT" ]] || release_die "release tag target changed"
release_time="$(date -u -d "@$RELEASE_SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"

repository="${GITHUB_REPOSITORY:-}"
run_id="${GITHUB_RUN_ID:-}"
release_url="not-recorded-local-build"
actions_url="not-recorded-local-build"
if [[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  release_url="https://github.com/$repository/releases/tag/$tag"
  if [[ "$run_id" =~ ^[0-9]+$ ]]; then
    actions_url="https://github.com/$repository/actions/runs/$run_id"
  fi
fi

evidence="$dist/release-evidence-final.md"
temporary="$(mktemp "$dist/.release-evidence-final.XXXXXX")"

{
  printf '# CPA Cyber Abuse Guard v%s final release evidence\n\n' "$RELEASE_SOURCE_VERSION"
  printf 'This standalone provenance record was generated only after the complete formal gate command returned zero. '
  printf 'The immutable command log is bound below by SHA-256. Neither reproducible ZIP contains this run-specific file.\n\n'
  printf '## Release identity\n\n'
  printf -- '- Commit: `%s`\n' "$RELEASE_GIT_COMMIT"
  printf -- '- Annotated tag: `%s`\n' "$tag"
  printf -- '- Tag object: `%s`\n' "$tag_object"
  printf -- '- Tag target: `%s`\n' "$tag_target"
  printf -- '- Source date (UTC): `%s`\n' "$release_time"
  printf -- '- Ruleset: `%s`\n' "$RELEASE_RULESET_VERSION"
  printf -- '- Rules snapshot SHA-256: `%s`\n' "$RELEASE_RULESET_SHA256"
  printf -- '- Source tree: `clean`\n\n'

  printf '## Verified artifacts\n\n'
  printf '| Artifact | SHA-256 |\n|---|---|\n'
  for name in "$so" "$so.sha256" "$store_zip" "$bundle_zip" checksums.txt build-metadata.json \
    ruleset-manifest.json ruleset.sha256 sbom.cdx.json release-test-summary.txt \
    release-test-summary.txt.sha256 "$source_name" "$source_name.sha256"; do
    printf '| `%s` | `%s` |\n' "$name" "$(hash_file "$dist/$name")"
  done
  printf '\n## External candidate admission\n\n'
  printf -- '- Candidate tag: `%s`\n' "$candidate_tag"
  printf -- '- Candidate workflow run: `%s`\n' "$candidate_run_id"
  printf -- '- Round6 prerelease attestation SHA-256: `%s`\n' "$external_attestation_sha256"
  printf -- '- CPA Host identity: `%s` (`%s`)\n' "$cpa_version" "$cpa_commit"
  printf -- '- CPA Host evidence SHA-256: `%s`\n' "$host_evidence_sha256"
  printf -- '- Independent audit SHA-256: `%s`\n' "$audit_sha256"
  printf -- '- Independent consumed evaluation: `%s` (`%s`)\n' "$evaluation_id" "$evaluation_status"
  printf -- '- Independent evaluation report SHA-256: `%s`\n\n' "$evaluation_sha256"

  printf '## Gate result\n\n'
  printf 'Result: **PASS**. The bound log covers format, diff, module, unit, race, vet, fuzz, operational scripts, regression corpus, '
  printf 'the candidate-bound external Host/audit/evaluation attestation, performance, CPA integration, vulnerability scan, SBOM, packaging, strict verification, '
  printf 'verification fault injection, and two-clean-clone reproducibility.\n\n'
  printf -- '- Release test log SHA-256: `%s`\n' "$(hash_file "$dist/release-test-summary.txt")"
  printf -- '- GitHub Actions run: %s\n' "$actions_url"
  printf -- '- GitHub Release: %s\n\n' "$release_url"

  printf '## Accepted limitations\n\n'
  printf -- '- CPA ABI v1 retains host-level Router fail-open boundaries and exposes no complete router-order or plugin-directory inventory.\n'
  printf -- '- HMAC dual-key rotation is design-only in v0.15.\n'
  printf -- '- Persisted subject-state completeness is protected by filesystem trust, not a keyed whole-snapshot MAC.\n'
  printf -- '- Unknown, novel, or encrypted encodings can evade semantic detection.\n'
  printf -- '- The plugin reduces risk; it cannot guarantee that an upstream account will never be warned, suspended, or deactivated.\n'
} >"$temporary"

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
mv -f -- "$temporary" "$evidence"
temporary=""
(cd "$dist" && sha256sum "$(basename "$evidence")" >"$(basename "$evidence").sha256")
release_assert_source_unchanged
printf 'final release evidence generated: %s\n' "$evidence"
