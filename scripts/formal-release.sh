#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands make tee install sha256sum mktemp rm mkdir
release_init
release_assert_tag
release_assert_formal_build
make -C "$root" external-release-attestation
for override in \
  RELEASE_DOC_ROOT \
  RELEASE_DOC_FIXTURE_MODE \
  CURRENT_RELEASE_VERSION \
  CURRENT_RULESET_SHA256 \
  CURRENT_CLASSIFIER_POLICY_VERSION \
  CURRENT_CLASSIFIER_POLICY_SHA256; do
  if [[ -n "${!override+x}" ]]; then
    release_die "formal release forbids release document override environment: $override"
  fi
done
"$root/scripts/release-doc-consistency.sh"

dist="${DIST_DIR:-$root/dist}"
mkdir -p "$dist"
summary="$(mktemp)"
cleanup() {
  rm -f -- "$summary"
}
trap cleanup EXIT

set +e
make -j1 -C "$root" release verify-release verification-fault-test round6-reproducibility-test 2>&1 | tee "$summary"
pipeline_status=("${PIPESTATUS[@]}")
gate_status=${pipeline_status[0]}
tee_status=${pipeline_status[1]}
set -e
if [[ "$gate_status" -ne 0 ]]; then
  printf 'formal release gates failed with exit status %d\n' "$gate_status" >&2
  exit "$gate_status"
fi
if [[ "$tee_status" -ne 0 ]]; then
  printf 'formal release log capture failed with exit status %d\n' "$tee_status" >&2
  exit "$tee_status"
fi

install -m 0644 "$summary" "$dist/release-test-summary.txt"
(cd "$dist" && sha256sum release-test-summary.txt >release-test-summary.txt.sha256)
DIST_DIR="$dist" "$root/scripts/package-source-release.sh"
make -C "$root" artifact-hash clean-tree-check
DIST_DIR="$dist" "$root/scripts/generate-release-evidence.sh"
(cd "$dist" && sha256sum -c release-test-summary.txt.sha256 && \
  sha256sum -c release-evidence-final.md.sha256 && \
  sha256sum -c "cyber-abuse-guard-v${RELEASE_SOURCE_VERSION}-source.tar.gz.sha256")
make -C "$root" clean-tree-check
printf 'formal release completed from %s at %s\n' "$RELEASE_GIT_COMMIT" "$dist"
