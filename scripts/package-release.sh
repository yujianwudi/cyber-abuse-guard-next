#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
go_bin="${GO:-go}"
release_require_commands "$go_bin" install zip sha256sum mktemp find touch sort mkdir rm git sed awk cmp
release_init
release_assert_tag
release_assert_formal_build

dist="${DIST_DIR:-$root/dist}"
so="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"
store_zip="cyber-abuse-guard_${RELEASE_ARTIFACT_VERSION}_linux_amd64.zip"
bundle_zip="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}-audit-bundle.zip"
source_date_epoch="$RELEASE_SOURCE_DATE_EPOCH"
bundle_stage=""
export TZ=UTC

cleanup() {
  if [[ -n "$bundle_stage" && -d "$bundle_stage" ]]; then
    rm -rf -- "$bundle_stage"
  fi
}
trap cleanup EXIT

for required_file in \
  "$dist/$so" \
  "$dist/$so.sha256" \
  "$dist/build-metadata.json" \
  "$dist/ruleset-manifest.json" \
  "$dist/ruleset.sha256" \
  "$dist/sbom.cdx.json" \
  "$root/README.md" \
  "$root/README_CN.md" \
  "$root/LICENSE" \
  "$root/SECURITY.md" \
  "$root/CHANGELOG.md" \
  "$root/THIRD_PARTY_NOTICES.md" \
  "$root/config.example.yaml" \
  "$root/docs/DESIGN.md" \
  "$root/docs/AUDIT_HANDOFF.md" \
  "$root/docs/RAW_CAPTURE.md" \
  "$root/docs/THREAT_MODEL.md" \
  "$root/docs/INSTALL_DOCKER.md" \
  "$root/docs/LIMITATIONS.md" \
  "$root/docs/README.md" \
  "$root/docs/archive/v0.1.2/NEXT_VERSION.md" \
  "$root/docs/RELEASE_POLICY.md" \
  "$root/docs/ROUND6_CONFIG_MIGRATION.md" \
  "$root/docs/ROUND6_DEVELOPMENT_HANDOFF.md" \
  "$root/docs/ROUND6_LIMITATIONS.md" \
  "$root/docs/ROUND6_RELEASE_GATE.md" \
  "$root/docs/ROUND6_STREAMING_SCANNER_DESIGN.md" \
  "$root/docs/RULES.md" \
  "$root/docs/reports/TEST_REPORT.md" \
  "$root/docs/reports/PERFORMANCE.md" \
  "$root/docs/reports/CORPUS_REPORT.md" \
  "$root/docs/reports/CPA_INTEGRATION.md" \
  "$root/docs/reports/PHASE0_CPA_CONTRACT.md" \
  "$root/docs/reports/PROMPT_INJECTION_REVIEW.md" \
  "$root/docs/reports/PRIVACY.md" \
  "$root/docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md" \
  "$root/docs/reports/RELEASE_EVIDENCE.md" \
  "$root/scripts/check-production-health.sh" \
  "$root/scripts/generate-hmac-key.sh"; do
  if [[ ! -f "$required_file" || -L "$required_file" ]]; then
    release_die "required release input must be a regular non-symlink file: $required_file"
  fi
done
(cd "$dist" && sha256sum -c "$so.sha256" && sha256sum -c ruleset.sha256)

bundle_stage="$(mktemp -d)"
mkdir -p "$bundle_stage/plugins/linux/amd64" "$bundle_stage/docs/archive/v0.1.2" \
  "$bundle_stage/docs/reports" "$bundle_stage/scripts"
find "$bundle_stage" -type d -exec chmod 0755 {} +

install -m 0755 "$dist/$so" "$bundle_stage/plugins/linux/amd64/$so"
install -m 0644 "$dist/$so.sha256" "$bundle_stage/plugins/linux/amd64/$so.sha256"
install -m 0644 "$root/README.md" "$root/README_CN.md" "$root/LICENSE" \
  "$root/SECURITY.md" \
  "$root/CHANGELOG.md" "$root/THIRD_PARTY_NOTICES.md" \
  "$root/config.example.yaml" "$bundle_stage/"
install -m 0644 "$root/docs/AUDIT_HANDOFF.md" "$root/docs/RAW_CAPTURE.md" \
  "$root/docs/DESIGN.md" "$root/docs/THREAT_MODEL.md" \
  "$root/docs/INSTALL_DOCKER.md" "$root/docs/LIMITATIONS.md" \
  "$root/docs/README.md" "$root/docs/RELEASE_POLICY.md" \
  "$root/docs/ROUND6_CONFIG_MIGRATION.md" \
  "$root/docs/ROUND6_DEVELOPMENT_HANDOFF.md" \
  "$root/docs/ROUND6_LIMITATIONS.md" "$root/docs/ROUND6_RELEASE_GATE.md" \
  "$root/docs/ROUND6_STREAMING_SCANNER_DESIGN.md" \
  "$root/docs/RULES.md" "$bundle_stage/docs/"
install -m 0644 "$root/docs/archive/v0.1.2/NEXT_VERSION.md" \
  "$bundle_stage/docs/archive/v0.1.2/"
install -m 0644 "$root/docs/reports/TEST_REPORT.md" \
  "$root/docs/reports/PERFORMANCE.md" "$root/docs/reports/CORPUS_REPORT.md" \
  "$root/docs/reports/CPA_INTEGRATION.md" \
  "$root/docs/reports/PHASE0_CPA_CONTRACT.md" \
  "$root/docs/reports/PROMPT_INJECTION_REVIEW.md" \
  "$root/docs/reports/PRIVACY.md" \
  "$root/docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md" \
  "$root/docs/reports/RELEASE_EVIDENCE.md" \
  "$bundle_stage/docs/reports/"
install -m 0755 "$root/scripts/check-production-health.sh" \
  "$root/scripts/generate-hmac-key.sh" "$bundle_stage/scripts/"
install -m 0644 "$dist/build-metadata.json" "$dist/ruleset-manifest.json" \
  "$dist/ruleset.sha256" "$dist/sbom.cdx.json" "$bundle_stage/"

find "$bundle_stage" -exec touch -h -d "@$source_date_epoch" {} +
rm -f "$dist/$bundle_zip"
(cd "$bundle_stage" && find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | zip -X -q "$dist/$bundle_zip" -@)
PLUGIN_BINARY="$dist/$so" STORE_ARCHIVE="$dist/$store_zip" \
  SOURCE_DATE_EPOCH="$source_date_epoch" "$root/scripts/create-store-archive.sh"

(cd "$dist" && sha256sum \
  "$so" "$so.sha256" "$store_zip" "$bundle_zip" build-metadata.json ruleset-manifest.json \
  ruleset.sha256 sbom.cdx.json \
  >checksums.txt)
DIST_DIR="$dist" "$root/scripts/verify-release.sh"
DIST_DIR="$dist" "$go_bin" -C "$root/integration/pluginstorecontract" test \
  -run '^TestPublishedStoreArchive$' -count=1 -v
release_assert_source_unchanged
