#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
go_bin="${GO:-go}"
release_require_commands "$go_bin" git sed awk sha256sum sort mkdir mktemp mv rm chmod \
  jq gcc ld ldd
release_init

output_dir="${OUTPUT_DIR:-$root/dist}"
mkdir -p "$output_dir"
temporary="$(mktemp "$output_dir/.build-metadata.XXXXXX")"
trap 'rm -f -- "$temporary"' EXIT
go_version="$($go_bin env GOVERSION)"
cc_command="$($go_bin env CC)"
gcc_version="$(gcc -dumpfullversion -dumpversion)"
gcc_target="$(gcc -dumpmachine)"
binutils_ld_version="$(LC_ALL=C ld --version | sed -n '1p')"
glibc_version="$(LC_ALL=C ldd --version 2>&1 | sed -n '1p')"
builder_image="${RC_BUILDER_IMAGE:-NOT_PROVIDED}"
builder_image_digest="${RC_BUILDER_IMAGE_DIGEST:-NOT_PROVIDED}"
builder_reference="${RC_BUILDER_REFERENCE:-NOT_PROVIDED}"
runner_label="${RC_RUNNER_LABEL:-NOT_PROVIDED}"
runner_os="${RC_RUNNER_OS:-NOT_PROVIDED}"
runner_arch="${RC_RUNNER_ARCH:-NOT_PROVIDED}"
runner_environment="${RC_RUNNER_ENVIRONMENT:-NOT_PROVIDED}"
runner_name="${RC_RUNNER_NAME:-NOT_PROVIDED}"
runner_image_os="${RC_RUNNER_IMAGE_OS:-${ImageOS:-NOT_PROVIDED}}"
runner_image_version="${RC_RUNNER_IMAGE_VERSION:-${ImageVersion:-NOT_PROVIDED}}"
if [[ "${RELEASE_RC_BUILD:-0}" == 1 ]]; then
  trusted_builder_image='docker.io/library/golang:1.26.4-bookworm'
  trusted_builder_image_digest='sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b'
  trusted_builder_reference="${trusted_builder_image}@${trusted_builder_image_digest}"
  reproducible_runner_name='UNRECORDED_EPHEMERAL_GITHUB_HOSTED_RUNNER'
  unobservable_runner_image='UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER'
  canonical_builder_image_pattern='^docker\.io/([a-z0-9]+([._-][a-z0-9]+)*/)*[a-z0-9]+([._-][a-z0-9]+)*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$'
  [[ "$builder_image" =~ $canonical_builder_image_pattern ]] || \
    release_die "RC build metadata requires a canonical docker.io image name with an explicit tag"
  [[ "$builder_image_digest" =~ ^sha256:[0-9a-f]{64}$ ]] || \
    release_die "RC build metadata requires an immutable builder image digest"
  [[ "$builder_reference" == "${builder_image}@${builder_image_digest}" ]] || \
    release_die "RC builder reference must exactly bind the declared image name and digest"
  [[ "$builder_image" == "$trusted_builder_image" && \
    "$builder_image_digest" == "$trusted_builder_image_digest" && \
    "$builder_reference" == "$trusted_builder_reference" ]] || \
    release_die "RC build metadata requires the trusted pinned Go 1.26.4 builder reference"
  [[ "$cc_command" == gcc ]] || \
    release_die "RC build metadata requires go env CC to be exactly gcc"
  [[ "$gcc_target" == x86_64-linux-gnu ]] || \
    release_die "RC build metadata requires the native Linux amd64 GCC target"
  [[ "$runner_label" == ubuntu-24.04 ]] || \
    release_die "RC build metadata requires the exact ubuntu-24.04 runner label"
  [[ "$runner_os" == Linux ]] || \
    release_die "RC build metadata requires runner.os=Linux"
  [[ "$runner_arch" == X64 ]] || \
    release_die "RC build metadata requires runner.arch=X64"
  [[ "$runner_environment" == github-hosted ]] || \
    release_die "RC build metadata requires a GitHub-hosted build runner"
  [[ "$runner_name" == "$reproducible_runner_name" ]] || \
    release_die "RC build metadata must use the reproducible ephemeral-runner sentinel"
  [[ "$runner_image_os" == "$unobservable_runner_image" && \
    "$runner_image_version" == "$unobservable_runner_image" ]] || \
    release_die "RC build metadata must disclose that the host runner image is unobservable from the pinned job container"
fi

jq -n \
  --arg version "$RELEASE_ARTIFACT_VERSION" \
  --arg source_version "$RELEASE_SOURCE_VERSION" \
  --arg commit "$RELEASE_GIT_COMMIT" \
  --arg tree "$RELEASE_GIT_TREE" \
  --arg ruleset_version "$RELEASE_RULESET_VERSION" \
  --arg ruleset_sha256 "$RELEASE_RULESET_SHA256" \
  --arg classifier_policy_version "$RELEASE_CLASSIFIER_POLICY_VERSION" \
  --arg classifier_policy_sha256 "$RELEASE_CLASSIFIER_POLICY_SHA256" \
  --arg streaming_scanner "$RELEASE_STREAMING_SCANNER" \
  --argjson dirty "$RELEASE_DIRTY" \
  --argjson source_date_epoch "$RELEASE_SOURCE_DATE_EPOCH" \
  --arg go_version "$go_version" \
  --arg cc_command "$cc_command" \
  --arg gcc_version "$gcc_version" \
  --arg gcc_target "$gcc_target" \
  --arg binutils_ld_version "$binutils_ld_version" \
  --arg glibc_version "$glibc_version" \
  --arg builder_image "$builder_image" \
  --arg builder_image_digest "$builder_image_digest" \
  --arg builder_reference "$builder_reference" \
  --arg runner_label "$runner_label" \
  --arg runner_os "$runner_os" \
  --arg runner_arch "$runner_arch" \
  --arg runner_environment "$runner_environment" \
  --arg runner_name "$runner_name" \
  --arg runner_image_os "$runner_image_os" \
  --arg runner_image_version "$runner_image_version" \
  '{
    schema_version: 4,
    version: $version,
    source_version: $source_version,
    commit: $commit,
    tree: $tree,
    ruleset_version: $ruleset_version,
    ruleset_sha256: $ruleset_sha256,
    classifier_policy_version: $classifier_policy_version,
    classifier_policy_sha256: $classifier_policy_sha256,
    streaming_scanner: $streaming_scanner,
    dirty: $dirty,
    source_date_epoch: $source_date_epoch,
    go_version: $go_version,
    goos: "linux",
    goarch: "amd64",
    cgo_enabled: true,
    cc_command: $cc_command,
    gcc_version: $gcc_version,
    gcc_target: $gcc_target,
    binutils_ld_version: $binutils_ld_version,
    glibc_version: $glibc_version,
    builder_image: $builder_image,
    builder_image_digest: $builder_image_digest,
    builder_reference: $builder_reference,
    runner_label: $runner_label,
    runner_os: $runner_os,
    runner_arch: $runner_arch,
    runner_environment: $runner_environment,
    runner_name: $runner_name,
    runner_image_os: $runner_image_os,
    runner_image_version: $runner_image_version
  }' >"$temporary"

mv -f -- "$temporary" "$output_dir/build-metadata.json"
chmod 0644 "$output_dir/build-metadata.json"
trap - EXIT
release_assert_source_unchanged
printf 'build metadata: %s\n' "$output_dir/build-metadata.json"
