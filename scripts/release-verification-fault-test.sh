#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands cp mkdir mktemp rm sha256sum zip unzip find chmod env cat git sed awk sort ln
release_init

dist="${DIST_DIR:-$root/dist}"
verify="$root/scripts/verify-release.sh"
real_cyclonedx="$(command -v "${CYCLONEDX_GOMOD:-cyclonedx-gomod}")"
so="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}.so"
store_zip="cyber-abuse-guard_${RELEASE_ARTIFACT_VERSION}_linux_amd64.zip"
bundle_zip="cyber-abuse-guard-v${RELEASE_ARTIFACT_VERSION}-audit-bundle.zip"
work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT

if ! DIST_DIR="$dist" "$verify" >"$work/baseline.log" 2>&1; then
  echo "baseline release verification must pass before fault injection" >&2
  cat "$work/baseline.log" >&2
  exit 1
fi

run_must_fail() {
  local name="$1"
  shift
  if "$@" >"$work/$name.log" 2>&1; then
    printf 'fault injection unexpectedly passed: %s\n' "$name" >&2
    cat "$work/$name.log" >&2
    exit 1
  fi
  printf 'fault injection rejected as expected: %s\n' "$name"
}

copy_case() {
  local name="$1"
  mkdir -p "$work/$name"
  cp -a "$dist/." "$work/$name/"
}

write_checksums() {
  local directory="$1"
  (
    cd "$directory"
    sha256sum "$so" "$so.sha256" "$store_zip" "$bundle_zip" \
      build-metadata.json ruleset-manifest.json ruleset.sha256 sbom.cdx.json \
      >checksums.txt
  )
}

repack_bundle() {
  local name="$1"
  local case_dir="$work/$name"
  rm -f "$case_dir/$bundle_zip"
  (
    cd "$case_dir/repack"
    find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | \
      zip -X -q "$case_dir/$bundle_zip" -@
  )
  write_checksums "$case_dir"
}

# A PATH with no verification commands must fail before any positive result.
mkdir -p "$work/empty-path"
run_must_fail missing-command env PATH="$work/empty-path" /bin/bash "$verify"

# A substring such as v11.9.0 must never satisfy the pinned v1.9.0 tool
# identity check.
cat >"$work/cyclonedx-wrong-version" <<EOF
#!/usr/bin/env bash
if [[ "\${1:-}" == version ]]; then
  printf 'Version:\tv11.9.0\n'
  exit 0
fi
exec "$real_cyclonedx" "\$@"
EOF
chmod 0755 "$work/cyclonedx-wrong-version"
run_must_fail sbom-tool-version-substring env \
  CYCLONEDX_GOMOD="$work/cyclonedx-wrong-version" DIST_DIR="$dist" "$verify"

copy_case hash-mismatch
printf 'tamper' >>"$work/hash-mismatch/$so"
run_must_fail hash-mismatch env DIST_DIR="$work/hash-mismatch" "$verify"

copy_case architecture-mismatch
printf 'not an ELF shared object\n' >"$work/architecture-mismatch/$so"
(
  cd "$work/architecture-mismatch"
  sha256sum "$so" >"$so.sha256"
)
write_checksums "$work/architecture-mismatch"
run_must_fail architecture-mismatch env DIST_DIR="$work/architecture-mismatch" "$verify"

# CPA store ZIP faults are isolated from the full audit bundle faults.
copy_case store-unexpected-root-entry
printf 'forbidden\n' >"$work/store-unexpected-root-entry/unexpected.txt"
(
  cd "$work/store-unexpected-root-entry"
  zip -q "$store_zip" unexpected.txt
  rm -f unexpected.txt
)
write_checksums "$work/store-unexpected-root-entry"
run_must_fail store-unexpected-root-entry env \
  DIST_DIR="$work/store-unexpected-root-entry" "$verify"

copy_case store-nested-target
mkdir -p "$work/store-nested-target/repack/plugins/linux/amd64"
cp "$work/store-nested-target/$so" \
  "$work/store-nested-target/repack/plugins/linux/amd64/$so"
chmod 0755 "$work/store-nested-target/repack/plugins/linux/amd64/$so"
rm -f "$work/store-nested-target/$store_zip"
(
  cd "$work/store-nested-target/repack"
  zip -X -q "$work/store-nested-target/$store_zip" "plugins/linux/amd64/$so"
)
write_checksums "$work/store-nested-target"
run_must_fail store-nested-target env DIST_DIR="$work/store-nested-target" "$verify"

copy_case store-extra-dynamic-library
cp "$work/store-extra-dynamic-library/$so" \
  "$work/store-extra-dynamic-library/cyber-abuse-guard-extra.so"
(
  cd "$work/store-extra-dynamic-library"
  zip -q "$store_zip" cyber-abuse-guard-extra.so
  rm -f cyber-abuse-guard-extra.so
)
write_checksums "$work/store-extra-dynamic-library"
run_must_fail store-extra-dynamic-library env \
  DIST_DIR="$work/store-extra-dynamic-library" "$verify"

copy_case store-missing-target
printf 'not the target\n' >"$work/store-missing-target/unexpected.txt"
rm -f "$work/store-missing-target/$store_zip"
(
  cd "$work/store-missing-target"
  zip -X -q "$store_zip" unexpected.txt
  rm -f unexpected.txt
)
write_checksums "$work/store-missing-target"
run_must_fail store-missing-target env DIST_DIR="$work/store-missing-target" "$verify"

copy_case store-mode-mismatch
mkdir -p "$work/store-mode-mismatch/repack"
cp "$work/store-mode-mismatch/$so" "$work/store-mode-mismatch/repack/$so"
chmod 0644 "$work/store-mode-mismatch/repack/$so"
rm -f "$work/store-mode-mismatch/$store_zip"
(
  cd "$work/store-mode-mismatch/repack"
  zip -X -q "$work/store-mode-mismatch/$store_zip" "$so"
)
write_checksums "$work/store-mode-mismatch"
run_must_fail store-mode-mismatch env DIST_DIR="$work/store-mode-mismatch" "$verify"

copy_case store-symlink-entry
mkdir -p "$work/store-symlink-entry/repack"
ln -s "$work/store-symlink-entry/$so" "$work/store-symlink-entry/repack/$so"
rm -f "$work/store-symlink-entry/$store_zip"
(
  cd "$work/store-symlink-entry/repack"
  zip -X -y -q "$work/store-symlink-entry/$store_zip" "$so"
)
write_checksums "$work/store-symlink-entry"
run_must_fail store-symlink-entry env DIST_DIR="$work/store-symlink-entry" "$verify"

copy_case bundle-allowlist-mismatch
printf 'forbidden\n' >"$work/bundle-allowlist-mismatch/unexpected.txt"
(
  cd "$work/bundle-allowlist-mismatch"
  zip -q "$bundle_zip" unexpected.txt
  rm -f unexpected.txt
)
write_checksums "$work/bundle-allowlist-mismatch"
run_must_fail bundle-allowlist-mismatch env \
  DIST_DIR="$work/bundle-allowlist-mismatch" "$verify"

copy_case bundle-readme-content-mismatch
mkdir -p "$work/bundle-readme-content-mismatch/repack"
unzip -q "$work/bundle-readme-content-mismatch/$bundle_zip" \
  -d "$work/bundle-readme-content-mismatch/repack"
printf '\nTampered release documentation.\n' \
  >>"$work/bundle-readme-content-mismatch/repack/README.md"
chmod 0644 "$work/bundle-readme-content-mismatch/repack/README.md"
repack_bundle bundle-readme-content-mismatch
run_must_fail bundle-readme-content-mismatch env \
  DIST_DIR="$work/bundle-readme-content-mismatch" "$verify"

copy_case bundle-script-content-mismatch
mkdir -p "$work/bundle-script-content-mismatch/repack"
unzip -q "$work/bundle-script-content-mismatch/$bundle_zip" \
  -d "$work/bundle-script-content-mismatch/repack"
printf '\n# Tampered operational script.\n' \
  >>"$work/bundle-script-content-mismatch/repack/scripts/check-production-health.sh"
chmod 0755 "$work/bundle-script-content-mismatch/repack/scripts/check-production-health.sh"
repack_bundle bundle-script-content-mismatch
run_must_fail bundle-script-content-mismatch env \
  DIST_DIR="$work/bundle-script-content-mismatch" "$verify"

for missing_case in \
  'bundle-missing-audit-handoff:docs/AUDIT_HANDOFF.md' \
  'bundle-missing-phase0-contract:docs/reports/PHASE0_CPA_CONTRACT.md' \
  'bundle-missing-prompt-injection-review:docs/reports/PROMPT_INJECTION_REVIEW.md'; do
  name="${missing_case%%:*}"
  path="${missing_case#*:}"
  copy_case "$name"
  (
    cd "$work/$name"
    zip -q -d "$bundle_zip" "$path"
  )
  write_checksums "$work/$name"
  run_must_fail "$name" env DIST_DIR="$work/$name" "$verify"
done

copy_case bundle-forbidden-evaluation
mkdir -p "$work/bundle-forbidden-evaluation/repack"
unzip -q "$work/bundle-forbidden-evaluation/$bundle_zip" \
  -d "$work/bundle-forbidden-evaluation/repack"
printf '# Synthetic forbidden evaluation placeholder\n' \
  >"$work/bundle-forbidden-evaluation/repack/docs/reports/EVALUATION_V99_REPORT.md"
chmod 0644 "$work/bundle-forbidden-evaluation/repack/docs/reports/EVALUATION_V99_REPORT.md"
repack_bundle bundle-forbidden-evaluation
run_must_fail bundle-forbidden-evaluation env \
  DIST_DIR="$work/bundle-forbidden-evaluation" "$verify"

copy_case bundle-mode-mismatch
mkdir -p "$work/bundle-mode-mismatch/repack"
unzip -q "$work/bundle-mode-mismatch/$bundle_zip" \
  -d "$work/bundle-mode-mismatch/repack"
chmod 0644 "$work/bundle-mode-mismatch/repack/scripts/check-production-health.sh"
repack_bundle bundle-mode-mismatch
run_must_fail bundle-mode-mismatch env DIST_DIR="$work/bundle-mode-mismatch" "$verify"

copy_case bundle-symlink-entry
mkdir -p "$work/bundle-symlink-entry/repack"
unzip -q "$work/bundle-symlink-entry/$bundle_zip" \
  -d "$work/bundle-symlink-entry/repack"
rm -f "$work/bundle-symlink-entry/repack/README.md"
ln -s README_CN.md "$work/bundle-symlink-entry/repack/README.md"
rm -f "$work/bundle-symlink-entry/$bundle_zip"
(
  cd "$work/bundle-symlink-entry/repack"
  find . -mindepth 1 -printf '%P\n' | LC_ALL=C sort | \
    zip -X -y -q "$work/bundle-symlink-entry/$bundle_zip" -@
)
write_checksums "$work/bundle-symlink-entry"
run_must_fail bundle-symlink-entry env DIST_DIR="$work/bundle-symlink-entry" "$verify"

copy_case ruleset-mismatch
printf ' ' >>"$work/ruleset-mismatch/ruleset-manifest.json"
(
  cd "$work/ruleset-mismatch"
  sha256sum ruleset-manifest.json >ruleset.sha256
)
write_checksums "$work/ruleset-mismatch"
run_must_fail ruleset-mismatch env DIST_DIR="$work/ruleset-mismatch" "$verify"

copy_case sbom-mismatch
printf ' ' >>"$work/sbom-mismatch/sbom.cdx.json"
write_checksums "$work/sbom-mismatch"
run_must_fail sbom-mismatch env DIST_DIR="$work/sbom-mismatch" "$verify"

copy_case version-mismatch
run_must_fail version-mismatch env VERSION=9.9.9 DIST_DIR="$work/version-mismatch" "$verify"

echo "all release verification fault injections were rejected"
