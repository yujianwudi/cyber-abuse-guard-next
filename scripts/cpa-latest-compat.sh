#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
go_launcher="${GO:-go}"
export GOTOOLCHAIN=go1.26.6
selected_go_root="$("$go_launcher" -C "$root" env GOROOT)"
if [[ "$selected_go_root" != /* || "$selected_go_root" == *$'\n'* || \
      ! -x "$selected_go_root/bin/go" ]]; then
  printf 'selected Go toolchain root is invalid: %q\n' "$selected_go_root" >&2
  exit 1
fi
go_bin="$selected_go_root/bin/go"
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
selected_go_version="$("$go_bin" env GOVERSION)"
[[ "$selected_go_version" == go1.26.6 ]] || {
  printf 'CPA compatibility requires go1.26.6, selected %s\n' \
    "$selected_go_version" >&2
  exit 1
}
printf 'CPA compatibility Go toolchain: %s\n' "$("$go_bin" version)"
work_dir="$(mktemp -d)"
git_identity_dir="$work_dir/git-identity"
mkdir -p "$git_identity_dir"
origin_modcaches=()
cleanup() {
  local cache
  for cache in "${origin_modcaches[@]:-}"; do
    [[ -n "$cache" ]] || continue
    chmod -R u+w "$cache" 2>/dev/null || true
  done
  rm -rf -- "$work_dir"
}
trap cleanup EXIT

cpa_module='github.com/router-for-me/CLIProxyAPI/v7'
cpa_origin_url='https://github.com/router-for-me/CLIProxyAPI'
cpa_origin_git_url="${cpa_origin_url}.git"
cpa_latest_release_api='https://api.github.com/repos/router-for-me/CLIProxyAPI/releases/latest'

requested_profile="${CPA_COMPAT_PROFILE:-primary}"
case "$requested_profile" in
  primary)
    profiles=(primary)
    ;;
  *)
    printf 'unsupported CPA_COMPAT_PROFILE=%s; the only supported value is primary\n' \
      "$requested_profile" >&2
    exit 2
    ;;
esac

verify_remote="${CPA_COMPAT_VERIFY_REMOTE:-0}"
case "$verify_remote" in
  0|1) ;;
  *)
    printf 'CPA_COMPAT_VERIFY_REMOTE must be 0 or 1\n' >&2
    exit 2
    ;;
esac

require_latest="${CPA_COMPAT_REQUIRE_LATEST:-0}"
case "$require_latest" in
  0|1) ;;
  *)
    printf 'CPA_COMPAT_REQUIRE_LATEST must be 0 or 1\n' >&2
    exit 2
    ;;
esac
if [[ "$require_latest" == 1 && "$verify_remote" != 1 ]]; then
  printf 'CPA_COMPAT_REQUIRE_LATEST=1 requires CPA_COMPAT_VERIFY_REMOTE=1\n' >&2
  exit 2
fi

set_profile_identity() {
  case "$1" in
    primary)
      cpa_version='v7.2.142'
      cpa_commit='1f53b2eb03b9e963bac647e5566ca2b304239116'
      cpa_module_sum='h1:30twcgoSCSjBtc4tgZBKPC4sQpsEWwgu4d9r7tIDpQQ='
      cpa_go_mod_sum='h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ='
      ;;
    *)
      printf 'internal error: unsupported CPA profile %s\n' "$1" >&2
      exit 1
      ;;
  esac
}

assert_checked_in_module_identity() {
  local directory="$1"
  local label="$2"
  local expected_version="$3"
  local expected_sum="$4"
  local expected_go_mod_sum="$5"
  local resolved expected

  expected="$expected_version $expected_sum $expected_go_mod_sum"
  resolved="$(GOWORK=off "$go_bin" -C "$directory" list -mod=readonly -m \
    -f '{{if .Replace}}REPLACED {{.Replace.Path}} {{.Replace.Version}}{{else}}{{.Version}} {{.Sum}} {{.GoModSum}}{{end}}' \
    "$cpa_module")"
  [[ "$resolved" == "$expected" ]] || {
    printf 'checked-in %s CPA module identity mismatch: got %s want %s\n' \
      "$label" "$resolved" "$expected" >&2
    exit 1
  }
}

resolve_remote_tag_commit() {
  local tag="$1"
  local attempt refs expected

  expected="${cpa_commit}"$'\t'"refs/tags/$tag"
  for attempt in 1 2 3; do
    refs=''
    if refs="$(timeout --signal=KILL 30s git -C "$git_identity_dir" \
      -c http.version=HTTP/1.1 \
      -c http.lowSpeedLimit=1 -c http.lowSpeedTime=30 \
      ls-remote --refs "$cpa_origin_git_url" "refs/tags/$tag")"; then
      [[ "$refs" == "$expected" ]] || {
        printf 'CPA lightweight tag identity mismatch for %s: got %q want %q\n' \
          "$tag" "$refs" "$expected" >&2
        return 1
      }
      printf '%s\n' "$cpa_commit"
      return 0
    fi
    if [[ "$attempt" != 3 ]]; then
      printf 'CPA tag %s resolution attempt %s/3 failed; retrying\n' \
        "$tag" "$attempt" >&2
      sleep 3
    fi
  done
  printf 'CPA tag %s could not be resolved from the official Git origin after 3 bounded attempts\n' \
    "$tag" >&2
  return 1
}

resolve_remote_latest_release_tag() {
  local response latest_tag

  if ! response="$(timeout --signal=KILL 60s curl \
    --fail --silent --show-error --location --http1.1 \
    --retry 2 --retry-delay 2 --retry-max-time 55 \
    --retry-connrefused --retry-all-errors \
    --connect-timeout 10 --max-time 18 \
    --header 'Accept: application/vnd.github+json' \
    --header 'X-GitHub-Api-Version: 2022-11-28' \
    --header 'User-Agent: cyber-abuse-guard-cpa-compat' \
    "$cpa_latest_release_api")"; then
    printf 'CPA latest release could not be resolved from the official GitHub API after bounded retries\n' >&2
    return 1
  fi
  latest_tag="$(printf '%s\n' "$response" | jq -er \
    '.tag_name | select(type == "string" and length > 0)')"
  printf '%s\n' "$latest_tag"
}

for required_command in jq timeout; do
  command -v "$required_command" >/dev/null 2>&1 || {
    printf '%s is required for CPA module identity verification\n' "$required_command" >&2
    exit 1
  }
done
if [[ "$verify_remote" == 1 ]]; then
  command -v git >/dev/null 2>&1 || {
    printf 'git is required for CPA remote tag verification\n' >&2
    exit 1
  }
else
  printf 'CPA remote latest/tag checks skipped; pinned module Origin and sums remain required\n' >&2
fi
if [[ "$require_latest" == 1 ]]; then
  command -v curl >/dev/null 2>&1 || {
    printf 'curl is required when CPA_COMPAT_REQUIRE_LATEST=1\n' >&2
    exit 1
  }
else
  printf 'CPA latest release check skipped; the compatibility target is intentionally pinned\n' >&2
fi

assert_checked_in_module_identity \
  "$root" root \
  v7.2.142 h1:30twcgoSCSjBtc4tgZBKPC4sQpsEWwgu4d9r7tIDpQQ= \
  h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
assert_checked_in_module_identity \
  "$root/integration/cpalatestcontract" cpalatestcontract \
  v7.2.142 h1:30twcgoSCSjBtc4tgZBKPC4sQpsEWwgu4d9r7tIDpQQ= \
  h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
assert_checked_in_module_identity \
  "$root/integration/pluginstorecontract" pluginstorecontract \
  v7.2.142 h1:30twcgoSCSjBtc4tgZBKPC4sQpsEWwgu4d9r7tIDpQQ= \
  h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=

verify_primary_latest=0
for profile in "${profiles[@]}"; do
  if [[ "$profile" == primary ]]; then
    verify_primary_latest=1
    break
  fi
done
if [[ "$verify_remote" == 1 && "$require_latest" == 1 && "$verify_primary_latest" == 1 ]]; then
  set_profile_identity primary
  resolved_latest_tag="$(resolve_remote_latest_release_tag)"
  [[ "$resolved_latest_tag" == "$cpa_version" ]] || {
    printf 'CPA primary is no longer the latest official release: got latest=%s want=%s\n' \
      "$resolved_latest_tag" "$cpa_version" >&2
    exit 1
  }
  printf 'CPA latest release identity PASS: %s\n' "$resolved_latest_tag"
fi

for profile in "${profiles[@]}"; do
  set_profile_identity "$profile"
  root_mod_flags=()
  contract_mod_flags=()
  contract_modfile='go.mod'

  if [[ "$verify_remote" == 1 ]]; then
    resolved_tag_commit="$(resolve_remote_tag_commit "$cpa_version")"
    [[ "$resolved_tag_commit" == "$cpa_commit" ]] || {
      printf 'CPA tag identity mismatch for %s: got commit=%s want commit=%s\n' \
        "$cpa_version" "$resolved_tag_commit" "$cpa_commit" >&2
      exit 1
    }
  fi

  download_json="$(GOWORK=off "$go_bin" -C "$root" mod download -json "$cpa_module@$cpa_version")"
  download_error="$(printf '%s\n' "$download_json" | jq -er '.Error // ""')"
  [[ -z "$download_error" ]] || {
    printf 'CPA module download metadata error for %s: %s\n' "$cpa_version" "$download_error" >&2
    exit 1
  }
  download_path="$(printf '%s\n' "$download_json" | jq -er '.Path | select(type == "string" and length > 0)')"
  download_version="$(printf '%s\n' "$download_json" | jq -er '.Version | select(type == "string" and length > 0)')"
  download_sum="$(printf '%s\n' "$download_json" | jq -er '.Sum | select(type == "string" and length > 0)')"
  download_go_mod_sum="$(printf '%s\n' "$download_json" | jq -er '.GoModSum | select(type == "string" and length > 0)')"
  [[ "$download_path" == "$cpa_module" && \
     "$download_version" == "$cpa_version" && \
     "$download_sum" == "$cpa_module_sum" && \
     "$download_go_mod_sum" == "$cpa_go_mod_sum" ]] || {
    printf 'CPA download identity mismatch for %s: got %s@%s sum=%s go_mod_sum=%s\n' \
      "$profile" "$download_path" "$download_version" "$download_sum" "$download_go_mod_sum" >&2
    exit 1
  }

  origin_json="$download_json"
  if ! printf '%s\n' "$origin_json" | jq -e '.Origin.VCS and .Origin.URL and .Origin.Hash and .Origin.Ref' >/dev/null; then
    origin_modcache="$(mktemp -d "$work_dir/origin-$profile.XXXXXX")"
    origin_modcaches+=("$origin_modcache")
    printf 'CPA module Origin missing from warm cache; refreshing pinned identity in an isolated direct cache\n' >&2
    if ! origin_json="$(timeout --signal=KILL 60s env \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_CONFIG_SYSTEM=/dev/null \
      GIT_TERMINAL_PROMPT=0 \
      GOPROXY=direct \
      GOMODCACHE="$origin_modcache" \
      GOWORK=off \
      "$go_bin" -C "$root" mod download -json "$cpa_module@$cpa_version")"; then
      printf 'CPA pinned module Origin could not be refreshed from the official Git source within 60 seconds\n' >&2
      exit 1
    fi
  fi
  origin_error="$(printf '%s\n' "$origin_json" | jq -er '.Error // ""')"
  [[ -z "$origin_error" ]] || {
    printf 'CPA pinned module Origin refresh failed: %s\n' "$origin_error" >&2
    exit 1
  }
  origin_path="$(printf '%s\n' "$origin_json" | jq -er '.Path | select(type == "string" and length > 0)')"
  origin_version="$(printf '%s\n' "$origin_json" | jq -er '.Version | select(type == "string" and length > 0)')"
  origin_sum="$(printf '%s\n' "$origin_json" | jq -er '.Sum | select(type == "string" and length > 0)')"
  origin_go_mod_sum="$(printf '%s\n' "$origin_json" | jq -er '.GoModSum | select(type == "string" and length > 0)')"
  [[ "$origin_path" == "$cpa_module" && \
     "$origin_version" == "$cpa_version" && \
     "$origin_sum" == "$cpa_module_sum" && \
     "$origin_go_mod_sum" == "$cpa_go_mod_sum" ]] || {
    printf 'CPA isolated Origin identity mismatch for %s: got %s@%s sum=%s go_mod_sum=%s\n' \
      "$profile" "$origin_path" "$origin_version" "$origin_sum" "$origin_go_mod_sum" >&2
    exit 1
  }
  download_origin_vcs="$(printf '%s\n' "$origin_json" | jq -er '.Origin.VCS | select(type == "string" and length > 0)')"
  download_origin_url="$(printf '%s\n' "$origin_json" | jq -er '.Origin.URL | select(type == "string" and length > 0)')"
  download_origin_hash="$(printf '%s\n' "$origin_json" | jq -er '.Origin.Hash | select(type == "string" and length > 0)')"
  download_origin_ref="$(printf '%s\n' "$origin_json" | jq -er '.Origin.Ref | select(type == "string" and length > 0)')"
  [[ "$download_origin_vcs" == git && \
     "$download_origin_url" == "$cpa_origin_url" && \
     "$download_origin_hash" == "$cpa_commit" && \
     "$download_origin_ref" == "refs/tags/$cpa_version" ]] || {
    printf 'CPA module Origin mismatch for %s: got vcs=%s url=%s hash=%s ref=%s\n' \
      "$profile" "$download_origin_vcs" "$download_origin_url" \
      "$download_origin_hash" "$download_origin_ref" >&2
    exit 1
  }
  origin_metadata_file="$work_dir/cpa-origin-$profile.json"
  printf '%s\n' "$origin_json" >"$origin_metadata_file"

  (
    cd "$root"
    GOWORK=off CGO_ENABLED=1 "$go_bin" test \
      "${root_mod_flags[@]}" -mod=readonly \
      -tags=sqlite_omit_load_extension -run='^$' -count=1 \
      ./cmd/cyber-abuse-guard
    GOWORK=off CGO_ENABLED=1 "$go_bin" test \
      "${root_mod_flags[@]}" -mod=readonly \
      -tags=sqlite_omit_load_extension -count=1 \
      -run='^(TestRegistrationMatchesTargetCPAContract|TestRegistrationDoesNotAdvertiseUsagePlugin|TestRouterUsesRoleAwareConversationClassification)$' \
      ./internal/plugin
    GOWORK=off CGO_ENABLED=1 "$go_bin" test \
      "${root_mod_flags[@]}" -mod=readonly \
      -tags=integration,sqlite_omit_load_extension -run='^$' -count=1 \
      ./integration
    GOWORK=off "$go_bin" test \
      "${root_mod_flags[@]}" -mod=readonly -count=1 \
      "$cpa_module/sdk/pluginabi" \
      "$cpa_module/sdk/pluginapi"
    required_request_logging_contract_tests=(
      TestLatestCPARequestLoggingStartupSourceContract
      TestLatestCPARequestLoggingReloadSourceContract
      TestLatestCPARequestLoggingErrorOnlyCaptureSourceContract
      TestLatestCPAStartupPrivacyResourceDispatchSourceContract
      TestLatestCPARequestErrorLogManagementSourceContract
    )
    required_tests_pattern="$(
      IFS='|'
      printf '^(%s)$' "${required_request_logging_contract_tests[*]}"
    )"
    listed="$(
      CPA_COMPAT_PROFILE="$profile" \
        CPA_COMPAT_MODFILE="$contract_modfile" \
        CPA_COMPAT_EXPECTED_COMMIT="$cpa_commit" \
        CPA_COMPAT_ORIGIN_FILE="$origin_metadata_file" \
        GOWORK=off "$go_bin" -C integration/cpalatestcontract test \
        "${contract_mod_flags[@]}" -mod=readonly \
        -list="$required_tests_pattern" .
    )" || exit $?
    for test_name in "${required_request_logging_contract_tests[@]}"; do
      printf '%s\n' "$listed" | grep -Fxq "$test_name" || {
        printf 'required latest CPA request-logging source-contract test %s is missing\n' \
          "$test_name" >&2
        exit 1
      }
    done
    CPA_COMPAT_PROFILE="$profile" \
      CPA_COMPAT_MODFILE="$contract_modfile" \
      CPA_COMPAT_EXPECTED_COMMIT="$cpa_commit" \
      CPA_COMPAT_ORIGIN_FILE="$origin_metadata_file" \
      GOWORK=off "$go_bin" -C integration/cpalatestcontract test \
      "${contract_mod_flags[@]}" -mod=readonly -count=1 -v .
    CPA_COMPAT_ORIGIN_FILE="$origin_metadata_file" \
      GOWORK=off "$go_bin" -C integration/pluginstorecontract test \
      -mod=readonly -count=1 .
  )

  if [[ "$verify_remote" == 1 ]]; then
    printf 'CPA pinned source/compile compatibility PASS: profile=%s %s@%s remote_tag_verified=1\n' \
      "$profile" "$cpa_version" "$cpa_commit"
  else
    printf 'CPA source/compile compatibility PASS: profile=%s %s@%s remote_tag_checks=SKIPPED\n' \
      "$profile" "$cpa_version" "$cpa_commit"
  fi
done

if [[ "$verify_remote" == 1 ]]; then
  if [[ "$require_latest" == 1 ]]; then
    printf 'CPA pinned source/compile compatibility matrix PASS: profiles=%s remote_tag_verified=1 remote_latest_verified=1\n' \
      "${profiles[*]}"
  else
    printf 'CPA pinned source/compile compatibility matrix PASS: profiles=%s remote_tag_verified=1 remote_latest_check=SKIPPED_PINNED_TARGET\n' \
      "${profiles[*]}"
  fi
else
  printf 'CPA source/compile compatibility matrix PASS: profiles=%s remote_tag_check=SKIPPED remote_latest_check=SKIPPED\n' \
    "${profiles[*]}"
fi
