#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
go_bin="${GO:-go}"
cyclonedx="${CYCLONEDX_GOMOD:-cyclonedx-gomod}"
release_require_commands "$go_bin" "$cyclonedx" git mktemp rm cmp sha256sum awk mkdir zip unzip jq

if [[ "${ALLOW_DIRTY_BUILD:-0}" != 0 ]]; then
  release_die "round6-reproducibility-test requires a clean committed source tree"
fi
[[ -z "$(git -C "$root" status --porcelain --untracked-files=normal)" ]] || \
  release_die "round6-reproducibility-test requires a clean committed source tree"
reproducibility_mode="${ROUND6_REPRODUCIBILITY_MODE:-release}"
case "$reproducibility_mode" in
  development)
    [[ "${RELEASE_CANDIDATE_BUILD:-0}" == 0 ]] || \
      release_die "development reproducibility mode cannot enable candidate builds"
    ALLOW_DIRTY_BUILD=1
    ;;
  release) ;;
  *) release_die "ROUND6_REPRODUCIBILITY_MODE must be release or development" ;;
esac
# The root may be the CI partial/sparse checkout. release_init remains clean and
# verifies that every skip-worktree path belongs to the explicit restricted-data
# exclusion set; arbitrary sparse omissions still fail closed.
ROUND6_SAFE_SPARSE_BUILD=1
release_init
if [[ "$reproducibility_mode" == development && "$RELEASE_BUILD_KIND" != development ]]; then
  release_die "development reproducibility mode did not select a development build"
fi

work="$(mktemp -d)"
clone_a="$work/source-a"
clone_b="$work/source-b"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT

round6_sparse_clone() {
  local destination="$1"
  local fetch_target
  local unsafe_index_entries status path
  local upload_pack='git -c uploadpack.allowFilter=true -c uploadpack.allowAnySHA1InWant=true upload-pack'
  local -a promisor_markers

  mkdir -m 0700 -- "$destination"
  git -C "$destination" init --quiet
  git -C "$destination" remote add origin "$root"
  git -C "$destination" config remote.origin.uploadpack "$upload_pack"
  fetch_target="$RELEASE_GIT_COMMIT"
  if [[ "$RELEASE_BUILD_KIND" == formal ]]; then
    fetch_target="+refs/tags/v$RELEASE_SOURCE_VERSION:refs/tags/v$RELEASE_SOURCE_VERSION"
  fi
  git -C "$destination" fetch --quiet --filter=blob:none --no-tags origin "$fetch_target"
  [[ "$(git -C "$destination" rev-parse 'FETCH_HEAD^{commit}')" == "$RELEASE_GIT_COMMIT" ]] || \
    release_die "Round6 reproducibility clone fetched the wrong commit"
  if [[ "$RELEASE_BUILD_KIND" == formal ]]; then
    [[ "$(git -C "$destination" tag --list)" == "v$RELEASE_SOURCE_VERSION" ]] || \
      release_die "Round6 formal reproducibility clone must contain only the exact release tag"
    [[ "$(git -C "$destination" cat-file -t "refs/tags/v$RELEASE_SOURCE_VERSION")" == tag ]] || \
      release_die "Round6 formal reproducibility clone requires the annotated release tag"
  fi
  [[ -d "$destination/.git" && ! -L "$destination/.git" ]] || \
    release_die "Round6 reproducibility clone must use an independent Git directory"
  [[ "$(git -C "$destination" rev-parse --git-common-dir)" == .git ]] || \
    release_die "Round6 reproducibility clone must not use a linked common Git directory"
  [[ ! -e "$destination/.git/objects/info/alternates" ]] || \
    release_die "Round6 reproducibility clone must not share a local object database"
  [[ "$(git -C "$destination" config --get remote.origin.promisor)" == true ]] || \
    release_die "Round6 reproducibility clone must keep a promisor origin"
  [[ "$(git -C "$destination" config --get remote.origin.partialclonefilter)" == blob:none ]] || \
    release_die "Round6 reproducibility clone must enforce the blob:none filter"
  [[ "$(git -C "$destination" config --get remote.origin.uploadpack)" == "$upload_pack" ]] || \
    release_die "Round6 reproducibility clone must keep the filtering upload-pack contract"
  shopt -s nullglob
  promisor_markers=("$destination"/.git/objects/pack/*.promisor)
  shopt -u nullglob
  ((${#promisor_markers[@]} > 0)) || \
    release_die "Round6 reproducibility clone did not retain a promisor pack marker"

  git -C "$destination" sparse-checkout set --no-cone \
    '/*' '!/.round9-local-sandbox/**' \
    '!/cmd/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/cmd/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' '!/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/cmd/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/cmd/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/cmd/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/docs/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]_[Rr][Ee][Pp][Oo][Rr][Tt].[Mm][Dd]' \
    '!/docs/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/docs/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/docs/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/docs/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/internal/classifier/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/internal/classifier/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' \
    '!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/internal/classifier/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/internal/classifier/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/internal/classifier/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*' \
    '!/testdata/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*' '!/testdata/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*' \
    '!/testdata/round9-independent-benign-v1/**' '!/testdata/round9-independent-malicious-v1/**' \
    '!/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*' '!/testdata/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*' '!/testdata/**/*[Bb][Ll][Ii][Nn][Dd]*' '!/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
  git -C "$destination" checkout --quiet --detach "$RELEASE_GIT_COMMIT"

  unsafe_index_entries="$(git -C "$destination" ls-files -v | \
    awk 'substr($0, 1, 1) == "S" || substr($0, 1, 1) ~ /[a-z]/')"
  while IFS= read -r entry; do
    [[ -n "$entry" ]] || continue
    status="${entry:0:1}"
    path="${entry:2}"
    if [[ "$status" != S ]] || ! release_round6_safe_sparse_path "$path"; then
      release_die "Round6 reproducibility clone contains an unapproved index flag or excluded path"
    fi
  done <<<"$unsafe_index_entries"
}

round6_sparse_clone "$clone_a"
round6_sparse_clone "$clone_b"

go_path="$(command -v "$go_bin")"
cyclonedx_path="$(command -v "$cyclonedx")"
clone_dirty_build=1
clone_candidate_build=0
artifact_version="${RELEASE_SOURCE_VERSION}-dirty"
case "$RELEASE_BUILD_KIND" in
  candidate)
    release_assert_candidate_build
    clone_dirty_build=0
    clone_candidate_build=1
    artifact_version="$RELEASE_SOURCE_VERSION"
    ;;
  formal)
    release_assert_tag
    release_assert_formal_build
    clone_dirty_build=0
    artifact_version="$RELEASE_SOURCE_VERSION"
    ;;
  development) ;;
  *) release_die "unsupported Round6 reproducibility build kind: $RELEASE_BUILD_KIND" ;;
esac
so="cyber-abuse-guard-v${artifact_version}.so"
store_zip="cyber-abuse-guard_${artifact_version}_linux_amd64.zip"
bundle_zip="cyber-abuse-guard-v${artifact_version}-audit-bundle.zip"

for name in a b; do
  clone="$work/source-$name"
  [[ "$(git -C "$clone" rev-parse HEAD)" == "$RELEASE_GIT_COMMIT" ]]
  [[ "$(git -C "$clone" rev-parse 'HEAD^{tree}')" == "$RELEASE_GIT_TREE" ]]
  [[ -z "$(git -C "$clone" status --porcelain)" ]]
  common_env=(
    GO="$go_path"
    VERSION="$RELEASE_SOURCE_VERSION"
    SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH"
    ALLOW_DIRTY_BUILD="$clone_dirty_build"
    RELEASE_CANDIDATE_BUILD="$clone_candidate_build"
    RELEASE_CANDIDATE_EXPECTED_COMMIT="$RELEASE_GIT_COMMIT"
    RELEASE_CANDIDATE_EXPECTED_TREE="$RELEASE_GIT_TREE"
    ROUND6_SAFE_SPARSE_BUILD=1
    CYCLONEDX_GOMOD="$cyclonedx_path"
    CYCLONEDX_GOMOD_VERSION="${CYCLONEDX_GOMOD_VERSION:-v1.9.0}"
  )
  env "${common_env[@]}" GOCACHE="$work/go-build-cache-$name" \
    "$clone/scripts/build-linux-amd64.sh"
  env "${common_env[@]}" "$clone/scripts/release-sbom.sh"
  if [[ "$RELEASE_BUILD_KIND" == formal ]]; then
    env "${common_env[@]}" "$clone/scripts/package-release.sh"
  else
    PLUGIN_BINARY="$clone/dist/$so" \
      STORE_ARCHIVE="$clone/dist/$store_zip" \
      SOURCE_DATE_EPOCH="$RELEASE_SOURCE_DATE_EPOCH" \
      "$clone/scripts/create-store-archive.sh"
  fi
  if [[ "$RELEASE_BUILD_KIND" != formal ]]; then
    (
      cd "$clone/dist"
      sha256sum \
        "$so" \
        "$so.sha256" \
        "$store_zip" \
        build-metadata.json \
        ruleset-manifest.json \
        ruleset.sha256 \
        sbom.cdx.json >checksums.txt
      sha256sum -c checksums.txt
    )
  fi
  [[ "$(git -C "$clone" rev-parse HEAD)" == "$RELEASE_GIT_COMMIT" ]] ||
    release_die "Round6 reproducibility source $name changed HEAD during the build"
  [[ "$(git -C "$clone" rev-parse 'HEAD^{tree}')" == "$RELEASE_GIT_TREE" ]] ||
    release_die "Round6 reproducibility source $name changed its Git tree during the build"
  [[ -z "$(git -C "$clone" status --porcelain)" ]] ||
    release_die "Round6 reproducibility source $name became dirty during the build"
  jq -e \
    --arg commit "$RELEASE_GIT_COMMIT" \
    --arg tree "$RELEASE_GIT_TREE" \
    '.commit == $commit and .tree == $tree' \
    "$clone/dist/build-metadata.json" >/dev/null ||
    release_die "Round6 reproducibility source $name emitted mismatched build metadata"
done

compare_paths() {
  local description="$1"
  local left="$2"
  local right="$3"
  if ! cmp -s "$left" "$right"; then
    printf 'Round6 reproducibility failure: %s differ\n' "$description" >&2
    sha256sum "$left" "$right" >&2
    exit 1
  fi
  printf 'reproducible %s: ' "$description"
  sha256sum "$left" | awk '{print $1}'
}

compare_artifact() {
  local description="$1"
  local relative="$2"
  compare_paths "$description" "$clone_a/dist/$relative" "$clone_b/dist/$relative"
}

compare_artifact "shared object" "$so"
compare_artifact "shared-object checksum" "$so.sha256"
compare_artifact "CPA Store ZIP" "$store_zip"
compare_artifact "build metadata" build-metadata.json
compare_artifact "SBOM" sbom.cdx.json
compare_artifact "checksums manifest" checksums.txt
compare_artifact "ruleset manifest" ruleset-manifest.json
compare_artifact "ruleset checksum" ruleset.sha256
if [[ "$RELEASE_BUILD_KIND" == formal ]]; then
  compare_artifact "audit bundle" "$bundle_zip"
fi

if [[ "$RELEASE_BUILD_KIND" == candidate || "$RELEASE_BUILD_KIND" == formal ]]; then
  root_dist="${DIST_DIR:-$root/dist}"
  for relative in "$so" "$so.sha256" "$store_zip" build-metadata.json sbom.cdx.json \
    checksums.txt ruleset-manifest.json ruleset.sha256; do
    [[ -f "$root_dist/$relative" && ! -L "$root_dist/$relative" ]] || \
      release_die "$RELEASE_BUILD_KIND reproducibility requires the root artifact: $root_dist/$relative"
    compare_paths "root $RELEASE_BUILD_KIND $relative" "$root_dist/$relative" "$clone_a/dist/$relative"
  done
  if [[ "$RELEASE_BUILD_KIND" == formal ]]; then
    [[ -f "$root_dist/$bundle_zip" && ! -L "$root_dist/$bundle_zip" ]] || \
      release_die "formal reproducibility requires the root artifact: $root_dist/$bundle_zip"
    compare_paths "root formal $bundle_zip" "$root_dist/$bundle_zip" "$clone_a/dist/$bundle_zip"
  fi
fi

release_assert_source_unchanged
if [[ "$RELEASE_BUILD_KIND" == candidate ]]; then
  echo "Round6 clean candidate reproducibility passed and matches root/dist"
elif [[ "$RELEASE_BUILD_KIND" == formal ]]; then
  echo "Round6 safe formal reproducibility passed and matches root/dist"
else
  echo "Round6 safe development reproducibility passed in two independent blobless sparse clones"
fi
