#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# Check dependencies before release-common performs any external work. A
# missing verifier is a hard failure, never a warning followed by success.
for required in file sha256sum readelf nm unzip zip grep cmp mktemp sort uniq diff \
  stat objdump sed tail awk head git date rm mkdir tr cat strings find; do
  if ! command -v "$required" >/dev/null 2>&1; then
    printf 'required verification command not found: %s\n' "$required" >&2
    exit 127
  fi
done

# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
go_bin="${GO:-go}"
cyclonedx="${CYCLONEDX_GOMOD:-cyclonedx-gomod}"
if ! command -v "$go_bin" >/dev/null 2>&1; then
  printf 'required verification command not found: %s\n' "$go_bin" >&2
  exit 127
fi
if ! command -v "$cyclonedx" >/dev/null 2>&1; then
  printf 'required verification command not found: %s\n' "$cyclonedx" >&2
  exit 127
fi
release_init
release_assert_tag
release_assert_formal_build

dist="${DIST_DIR:-$root/dist}"
so="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"
store_zip="cyber-abuse-guard_${RELEASE_ARTIFACT_VERSION}_linux_amd64.zip"
bundle_zip="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}-audit-bundle.zip"

cd "$dist"
for required_file in "$so" "$so.sha256" "$store_zip" "$bundle_zip" checksums.txt \
  build-metadata.json ruleset-manifest.json ruleset.sha256 sbom.cdx.json; do
  if [[ ! -f "$required_file" || -L "$required_file" ]]; then
    printf 'required release artifact must be a regular non-symlink file: %s\n' "$dist/$required_file" >&2
    exit 1
  fi
done

sha256sum -c "$so.sha256"
sha256sum -c ruleset.sha256
sha256sum -c checksums.txt

expected_checksum_files="$(printf '%s\n' \
  "$so" "$so.sha256" "$store_zip" "$bundle_zip" build-metadata.json ruleset-manifest.json \
  ruleset.sha256 sbom.cdx.json | \
  LC_ALL=C sort)"
actual_checksum_files="$(awk '{print $2}' checksums.txt | LC_ALL=C sort)"
if [[ "$actual_checksum_files" != "$expected_checksum_files" ]]; then
  echo "checksums.txt does not cover exactly the published release files" >&2
  diff -u <(printf '%s\n' "$expected_checksum_files") \
    <(printf '%s\n' "$actual_checksum_files") >&2 || true
  exit 1
fi

file_output="$(file "$so")"
grep -Fq 'ELF 64-bit' <<<"$file_output"
grep -Fq 'shared object' <<<"$file_output"
grep -Fq 'x86-64' <<<"$file_output"

elf_header="$(readelf -h "$so")"
grep -Eq 'Class:[[:space:]]+ELF64' <<<"$elf_header"
grep -Eq 'Type:[[:space:]]+DYN' <<<"$elf_header"
grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64' <<<"$elf_header"

exported_symbols="$(nm -D --defined-only "$so" | awk '{print $3}')"
for symbol in cliproxy_plugin_init cliproxyPluginCall cliproxyPluginFree cliproxyPluginShutdown; do
  if ! grep -Fxq "$symbol" <<<"$exported_symbols"; then
    printf 'required CPA ABI symbol missing: %s\n' "$symbol" >&2
    exit 1
  fi
done

# Keep the published cgo plug-in loadable on the documented glibc baseline.
max_glibc="$(objdump -T "$so" | grep -oE 'GLIBC_[0-9]+(\.[0-9]+)*' | \
  sed 's/^GLIBC_//' | LC_ALL=C sort -Vu | tail -1)"
if [[ -z "$max_glibc" || "$(printf '%s\n' "$max_glibc" '2.34' | sort -V | tail -1)" != 2.34 ]]; then
  printf 'release requires unsupported glibc %s; maximum allowed is 2.34\n' "$max_glibc" >&2
  exit 1
fi

go_version="$($go_bin env GOVERSION)"
if [[ "$go_version" != go1.26.6 ]]; then
  printf 'release verification requires Go go1.26.6, got %s\n' "$go_version" >&2
  exit 1
fi
go_build_info="$($go_bin version -m "$so")"
for setting in \
  'github.com/yujianwudi/cyber-abuse-guard-next/cmd/cyber-abuse-guard' \
  '-buildmode=c-shared' \
  '-tags=sqlite_omit_load_extension' \
  '-trimpath=true' \
  'CGO_ENABLED=1' \
  'GOARCH=amd64' \
  'GOOS=linux'; do
  if ! grep -Fq -- "$setting" <<<"$go_build_info"; then
    printf 'Go build setting is missing or mismatched: %s\n' "$setting" >&2
    exit 1
  fi
done

# -X values do not appear in `go version -m` for c-shared binaries. Exact
# string presence proves the strong per-release identities survived linking;
# management/integration tests validate that the runtime exposes the same data.
binary_strings="$(strings "$so")"
for identity in "$RELEASE_ARTIFACT_VERSION" "$RELEASE_GIT_COMMIT" \
  "$RELEASE_RULESET_VERSION" "$RELEASE_RULESET_SHA256" \
  "$RELEASE_CLASSIFIER_POLICY_VERSION" "$RELEASE_CLASSIFIER_POLICY_SHA256" \
  "$RELEASE_STREAMING_SCANNER"; do
  if ! grep -Fq -- "$identity" <<<"$binary_strings"; then
    printf 'compiled release identity is missing: %s\n' "$identity" >&2
    exit 1
  fi
done

metadata_dir="$(mktemp -d)"
store_verify_dir="$(mktemp -d)"
bundle_verify_dir="$(mktemp -d)"
cleanup() {
  rm -rf -- "$metadata_dir" "$store_verify_dir" "$bundle_verify_dir"
}
trap cleanup EXIT
OUTPUT_DIR="$metadata_dir" GO="$go_bin" "$root/scripts/release-ruleset-manifest.sh" >/dev/null
OUTPUT_DIR="$metadata_dir" GO="$go_bin" "$root/scripts/release-build-metadata.sh" >/dev/null
cmp -s ruleset-manifest.json "$metadata_dir/ruleset-manifest.json" || {
  echo "ruleset-manifest.json does not match the source rules" >&2
  exit 1
}
cmp -s ruleset.sha256 "$metadata_dir/ruleset.sha256" || {
  echo "ruleset.sha256 does not match the source rules manifest" >&2
  exit 1
}
cmp -s build-metadata.json "$metadata_dir/build-metadata.json" || {
  echo "build-metadata.json does not match the source and toolchain" >&2
  exit 1
}

OUTPUT_DIR="$metadata_dir" GO="$go_bin" CYCLONEDX_GOMOD="$cyclonedx" \
  CYCLONEDX_GOMOD_VERSION="${CYCLONEDX_GOMOD_VERSION:-v1.9.0}" \
  "$root/scripts/release-sbom.sh" >/dev/null
cmp -s sbom.cdx.json "$metadata_dir/sbom.cdx.json" || {
  echo "sbom.cdx.json does not match the pinned tool and module graph" >&2
  exit 1
}

fixed_timestamp="$(date -u -d "@$RELEASE_SOURCE_DATE_EPOCH" '+%Y-%m-%dT%H:%M:%SZ')"
grep -Fq '"bomFormat": "CycloneDX"' sbom.cdx.json
grep -Fq '"specVersion": "1.6"' sbom.cdx.json
grep -Fq "\"timestamp\": \"$fixed_timestamp\"" sbom.cdx.json

store_listing="$(unzip -Z1 "$store_zip")"
if [[ "$store_listing" != "$so" ]]; then
  printf 'CPA store ZIP must contain exactly one root dynamic library named %s; got:\n%s\n' \
    "$so" "$store_listing" >&2
  exit 1
fi
if unzip -Z -l "$store_zip" | awk '$1 ~ /^l/ { found = 1 } END { exit !found }'; then
  echo "CPA store ZIP contains a symbolic-link entry" >&2
  exit 1
fi
(umask 000; unzip -q "$store_zip" -d "$store_verify_dir")
[[ -f "$store_verify_dir/$so" && ! -L "$store_verify_dir/$so" ]] || {
  printf 'CPA store ZIP target must extract as a regular non-symlink file: %s\n' "$so" >&2
  exit 1
}
cmp -s "$so" "$store_verify_dir/$so" || {
  echo "CPA store ZIP dynamic library differs from the standalone artifact" >&2
  exit 1
}
store_mode="$(stat -c '%a' "$store_verify_dir/$so")"
if [[ "$store_mode" != 755 ]]; then
  printf 'CPA store ZIP dynamic library mode mismatch: got %s, want 755\n' "$store_mode" >&2
  exit 1
fi

bundle_listing="$(unzip -Z1 "$bundle_zip")"
if unzip -Z -l "$bundle_zip" | awk '$1 ~ /^l/ { found = 1 } END { exit !found }'; then
  echo "audit bundle contains a symbolic-link entry" >&2
  exit 1
fi
expected_bundle_listing="$(cat <<EOF
CHANGELOG.md
LICENSE
README.md
README_CN.md
SECURITY.md
THIRD_PARTY_NOTICES.md
build-metadata.json
config.example.yaml
docs/
docs/AUDIT_HANDOFF.md
docs/DESIGN.md
docs/INSTALL_DOCKER.md
docs/LIMITATIONS.md
docs/RAW_CAPTURE.md
docs/README.md
docs/RELEASE_POLICY.md
docs/ROUND6_CONFIG_MIGRATION.md
docs/ROUND6_DEVELOPMENT_HANDOFF.md
docs/ROUND6_LIMITATIONS.md
docs/ROUND6_RELEASE_GATE.md
docs/ROUND6_STREAMING_SCANNER_DESIGN.md
docs/RULES.md
docs/THREAT_MODEL.md
docs/archive/
docs/archive/v0.1.2/
docs/archive/v0.1.2/NEXT_VERSION.md
docs/reports/
docs/reports/CORPUS_REPORT.md
docs/reports/CPA_INTEGRATION.md
docs/reports/PERFORMANCE.md
docs/reports/PHASE0_CPA_CONTRACT.md
docs/reports/PROMPT_INJECTION_REVIEW.md
docs/reports/PRIVACY.md
docs/reports/PUBLIC_JAILBREAK_REPOSITORY_REVIEW.md
docs/reports/RELEASE_EVIDENCE.md
docs/reports/TEST_REPORT.md
plugins/
plugins/linux/
plugins/linux/amd64/
plugins/linux/amd64/$so
plugins/linux/amd64/$so.sha256
ruleset-manifest.json
ruleset.sha256
sbom.cdx.json
scripts/
scripts/check-production-health.sh
scripts/generate-hmac-key.sh
EOF
)"

duplicates="$(printf '%s\n' "$bundle_listing" | LC_ALL=C sort | uniq -d)"
if [[ -n "$duplicates" ]]; then
  echo "audit bundle contains duplicate entries:" >&2
  printf '%s\n' "$duplicates" >&2
  exit 1
fi
actual_sorted="$(printf '%s\n' "$bundle_listing" | LC_ALL=C sort)"
expected_sorted="$(printf '%s\n' "$expected_bundle_listing" | LC_ALL=C sort)"
if [[ "$actual_sorted" != "$expected_sorted" ]]; then
  echo "audit bundle content differs from the strict allowlist" >&2
  diff -u <(printf '%s\n' "$expected_sorted") <(printf '%s\n' "$actual_sorted") >&2 || true
  exit 1
fi
forbidden_listing="$(grep -Fvx 'scripts/generate-hmac-key.sh' <<<"$bundle_listing")"
if grep -Eiq '(^|/)(\.git|.*\.db($|[-.])|.*secret.*|.*hmac.*|.*\.key|.*\.pem|\.env.*|.*\.log)($|/)' <<<"$forbidden_listing"; then
  echo "audit bundle contains a forbidden repository, database, or secret-like path" >&2
  exit 1
fi
if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<"$bundle_listing"; then
  echo "audit bundle contains evaluation, holdout, consumed, private, blind, or retired material" >&2
  exit 1
fi

(umask 000; unzip -q "$bundle_zip" -d "$bundle_verify_dir")
(cd "$bundle_verify_dir/plugins/linux/amd64" && sha256sum -c "$so.sha256")
cmp -s "$so" "$bundle_verify_dir/plugins/linux/amd64/$so"
for release_file in build-metadata.json ruleset-manifest.json ruleset.sha256 sbom.cdx.json; do
  cmp -s "$release_file" "$bundle_verify_dir/$release_file" || {
    printf 'audit-bundle copy differs from standalone artifact: %s\n' "$release_file" >&2
    exit 1
  }
done

# Bind every source-derived release file to the exact checked-out source. The
# strict name allowlist alone cannot detect an allowlisted README, config,
# report, or operational script whose content was replaced and re-hashed.
source_derived_files=(
  CHANGELOG.md
  LICENSE
  README.md
  README_CN.md
  SECURITY.md
  THIRD_PARTY_NOTICES.md
  config.example.yaml
)
while IFS= read -r relative; do
  source_derived_files+=("docs/$relative")
done < <(find "$bundle_verify_dir/docs" -type f -printf '%P\n' | LC_ALL=C sort)
while IFS= read -r relative; do
  source_derived_files+=("scripts/$relative")
done < <(find "$bundle_verify_dir/scripts" -type f -printf '%P\n' | LC_ALL=C sort)

for release_file in "${source_derived_files[@]}"; do
  source_file="$root/$release_file"
  packaged_file="$bundle_verify_dir/$release_file"
  [[ -f "$source_file" && ! -L "$source_file" ]] || {
    printf 'source-bound release input must be a regular non-symlink file: %s\n' \
      "$source_file" >&2
    exit 1
  }
  cmp -s "$source_file" "$packaged_file" || {
    printf 'audit-bundle source-derived content differs from checked-out source: %s\n' \
      "$release_file" >&2
    exit 1
  }
done

while IFS= read -r entry; do
  if [[ -L "$bundle_verify_dir/$entry" ]]; then
    printf 'audit-bundle entry must not be a symbolic link: %s\n' "$entry" >&2
    exit 1
  fi
  if [[ "$entry" == */ ]]; then
    expected_mode=755
    test -d "$bundle_verify_dir/$entry"
  elif [[ "$entry" == "plugins/linux/amd64/$so" || "$entry" == scripts/*.sh ]]; then
    expected_mode=755
    test -f "$bundle_verify_dir/$entry"
  else
    expected_mode=644
    test -f "$bundle_verify_dir/$entry"
  fi
  actual_mode="$(stat -c '%a' "$bundle_verify_dir/$entry")"
  if [[ "$actual_mode" != "$expected_mode" ]]; then
    printf 'audit-bundle mode mismatch for %s: got %s, want %s\n' \
      "$entry" "$actual_mode" "$expected_mode" >&2
    exit 1
  fi
done <<<"$bundle_listing"

release_assert_source_unchanged
printf 'release verification passed: store=%s/%s audit_bundle=%s/%s\n' \
  "$dist" "$store_zip" "$dist" "$bundle_zip"
