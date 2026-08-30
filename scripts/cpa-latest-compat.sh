#!/usr/bin/env bash
set -euo pipefail

# Never allow a caller's Git repository-routing variables to redirect the
# lightweight tag proof or any repository metadata lookup. The compatibility
# lane owns its isolated identity directory and must start from a clean Git
# routing environment.
unset GIT_DIR GIT_WORK_TREE GIT_INDEX_FILE GIT_COMMON_DIR \
  GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES GIT_NAMESPACE \
  GIT_CONFIG_COUNT GIT_CONFIG_KEY_0 GIT_CONFIG_VALUE_0 GIT_CONFIG_GLOBAL \
  GIT_CONFIG_SYSTEM GIT_CONFIG_NOSYSTEM GIT_TERMINAL_PROMPT GIT_ASKPASS \
  GOROOT GOTOOLDIR GOENV

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cpa_module='github.com/router-for-me/CLIProxyAPI/v7'

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
  printf 'CPA compatibility requires Linux amd64 (got %s/%s)\n' "$(uname -s)" "$(uname -m)" >&2
  exit 1
}
export GOOS=linux
export GOARCH=amd64
export CGO_ENABLED=1
export GOENV=off
export GOPROXY='https://proxy.golang.org,direct'
export GOPRIVATE=
export GONOSUMDB=
export GONOPROXY=
export GOVCS='public:git|https'
export GOSUMDB="${CPA_COMPAT_GOSUMDB:-sum.golang.org}"

# Every Go process is an external dependency lookup or compiler invocation.
# Bound each one independently in addition to the aggregate contract-lane
# deadline below, so a stalled toolchain/module proxy cannot hang preflight
# before the lane timeout is installed.  The value is shared with the Go
# contract tests and is deliberately narrower than the aggregate lane.
parse_command_timeout() {
  local raw="$1"
  local number multiplier seconds
  case "$raw" in
    *s) number="${raw%s}"; multiplier=1 ;;
    *m) number="${raw%m}"; multiplier=60 ;;
    *h) number="${raw%h}"; multiplier=3600 ;;
    *)
      printf 'CPA_COMPAT_COMMAND_TIMEOUT must use an integer seconds, minutes, or hours suffix (for example 5m), got %q\n' \
        "$raw" >&2
      return 2
      ;;
  esac
  if [[ -z "$number" || ! "$number" =~ ^[0-9]+$ || "${#number}" -gt 4 ]]; then
    printf 'CPA_COMPAT_COMMAND_TIMEOUT has an invalid numeric value: %q\n' "$raw" >&2
    return 2
  fi
  seconds=$((10#$number * multiplier))
  if (( seconds < 1 || seconds > 600 )); then
    printf 'CPA_COMPAT_COMMAND_TIMEOUT must be between 1s and 600s (1s-10m), got %q\n' \
      "$raw" >&2
    return 2
  fi
  printf '%ss\n' "$seconds"
}

cpa_command_timeout="$(parse_command_timeout "${CPA_COMPAT_COMMAND_TIMEOUT:-5m}")" || exit $?
cpa_full_command_timeout="$(parse_command_timeout "${CPA_COMPAT_FULL_COMMAND_TIMEOUT:-10m}")" || exit $?

run_bounded_go() {
  timeout --signal=TERM --kill-after=10s "$cpa_command_timeout" "$@"
}

run_bounded_go_full() {
  timeout --signal=TERM --kill-after=10s "$cpa_full_command_timeout" "$@"
}

if [[ "${1:-}" == "--run-contract-lane" ]]; then
  if [[ "$#" != 6 ]]; then
    printf 'internal error: --run-contract-lane expects go, profile, commit, Origin file, and modfile\n' >&2
    exit 2
  fi
  shift
  lane_go_bin="$1"
  lane_profile="$2"
  lane_commit="$3"
  lane_origin_file="$4"
  lane_modfile="$5"
  [[ "$lane_go_bin" == /* && -x "$lane_go_bin" ]] || {
    printf 'internal error: compatibility lane Go binary is not an absolute executable: %q\n' \
      "$lane_go_bin" >&2
    exit 2
  }
  [[ "$lane_profile" == primary ]] || {
    printf 'internal error: compatibility lane profile is unsupported: %q\n' \
      "$lane_profile" >&2
    exit 2
  }
  [[ "$lane_commit" =~ ^[0-9a-f]{40}$ ]] || {
    printf 'internal error: compatibility lane commit is invalid: %q\n' \
      "$lane_commit" >&2
    exit 2
  }
  [[ -f "$lane_origin_file" && ! -L "$lane_origin_file" ]] || {
    printf 'internal error: compatibility lane Origin metadata is unavailable: %q\n' \
      "$lane_origin_file" >&2
    exit 2
  }
  [[ "$lane_modfile" == go.mod ]] || {
    printf 'internal error: compatibility lane modfile is not the checked-in go.mod: %q\n' \
      "$lane_modfile" >&2
    exit 2
  }
  cd "$root"
  # Keep every Go invocation in the caller's single bounded lane, including
  # local Guard compilation and the official SDK compile probes. This prevents
  # a stalled module cache or compiler from escaping the aggregate deadline.
  run_bounded_go env GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly \
    CPA_COMPAT_GO_BINARY="$lane_go_bin" \
    "$lane_go_bin" -C "$root" mod verify
  run_bounded_go env GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=1 \
    "$lane_go_bin" -C "$root" test -mod=readonly \
    -tags=sqlite_omit_load_extension -run='^$' -count=1 \
    ./cmd/cyber-abuse-guard
  run_bounded_go env GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=1 \
    "$lane_go_bin" -C "$root" test -mod=readonly \
    -tags=sqlite_omit_load_extension -count=1 \
    -run='^(TestRegistrationMatchesTargetCPAContract|TestRegistrationDoesNotAdvertiseUsagePlugin|TestRouterUsesRoleAwareConversationClassification)$' \
    ./internal/plugin
  run_bounded_go env GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly CGO_ENABLED=1 \
    "$lane_go_bin" -C "$root" test -mod=readonly \
    -tags=integration,sqlite_omit_load_extension -run='^$' -count=1 \
    ./integration
  run_bounded_go env GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly \
    "$lane_go_bin" -C "$root" test -mod=readonly -count=1 \
    "$cpa_module/sdk/pluginabi" "$cpa_module/sdk/pluginapi"
  required_request_logging_contract_tests=(
    TestLatestCPARequestLoggingStartupSourceContract
    TestLatestCPARequestLoggingReloadSourceContract
    TestLatestCPARequestLoggingErrorOnlyCaptureSourceContract
    TestLatestCPAStartupPrivacyResourceDispatchSourceContract
    TestLatestCPARequestErrorLogManagementSourceContract
  )
  required_tests_pattern="$({
    IFS='|'
    printf '^(%s)$' "${required_request_logging_contract_tests[*]}"
  })"
  listed="$(
    CPA_COMPAT_PROFILE="$lane_profile" \
      CPA_COMPAT_MODFILE="$lane_modfile" \
      CPA_COMPAT_EXPECTED_COMMIT="$lane_commit" \
      CPA_COMPAT_ORIGIN_FILE="$lane_origin_file" \
      CPA_COMPAT_GO_BINARY="$lane_go_bin" \
      CPA_COMPAT_GOROOT="${CPA_COMPAT_GOROOT:-}" \
      CPA_COMPAT_GOMODCACHE="${CPA_COMPAT_GOMODCACHE:-}" \
      run_bounded_go env GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly \
      "$lane_go_bin" -C integration/cpalatestcontract test \
      -mod=readonly -list="$required_tests_pattern" .
  )" || exit $?
  for test_name in "${required_request_logging_contract_tests[@]}"; do
    printf '%s\n' "$listed" | grep -Fxq "$test_name" || {
      printf 'required latest CPA request-logging source-contract test %s is missing\n' \
        "$test_name" >&2
      exit 1
    }
  done
  CPA_COMPAT_PROFILE="$lane_profile" \
    CPA_COMPAT_MODFILE="$lane_modfile" \
    CPA_COMPAT_EXPECTED_COMMIT="$lane_commit" \
    CPA_COMPAT_ORIGIN_FILE="$lane_origin_file" \
    CPA_COMPAT_GO_BINARY="$lane_go_bin" \
    CPA_COMPAT_GOROOT="${CPA_COMPAT_GOROOT:-}" \
    CPA_COMPAT_GOMODCACHE="${CPA_COMPAT_GOMODCACHE:-}" \
    run_bounded_go_full env GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly \
    "$lane_go_bin" -C integration/cpalatestcontract test \
    -mod=readonly -count=1 -timeout=25m -v .
  CPA_COMPAT_ORIGIN_FILE="$lane_origin_file" \
    CPA_COMPAT_GO_BINARY="$lane_go_bin" \
    CPA_COMPAT_GOROOT="${CPA_COMPAT_GOROOT:-}" \
    CPA_COMPAT_GOMODCACHE="${CPA_COMPAT_GOMODCACHE:-}" \
    run_bounded_go env GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly \
    "$lane_go_bin" -C integration/pluginstorecontract test \
    -mod=readonly -count=1 .
  exit 0
fi

go_launcher="${GO:-go}"
export GOTOOLCHAIN=go1.26.6
selected_go_root="$(run_bounded_go env GOTOOLCHAIN=local "$go_launcher" -C "$root" env GOROOT)"
if [[ "$selected_go_root" != /* || "$selected_go_root" == *$'\n'* || \
      ! -x "$selected_go_root/bin/go" ]]; then
  printf 'selected Go toolchain root is invalid: %q\n' "$selected_go_root" >&2
  exit 1
fi
go_bin="$selected_go_root/bin/go"
export CPA_COMPAT_GOROOT="$selected_go_root"
selected_go_modcache="$(run_bounded_go env GOTOOLCHAIN=local "$go_bin" env GOMODCACHE)"
[[ "$selected_go_modcache" == /* && "$selected_go_modcache" != *$'\n'* ]] || {
  printf 'selected Go module cache path is invalid: %q\n' "$selected_go_modcache" >&2
  exit 1
}
export CPA_COMPAT_GOMODCACHE="$selected_go_modcache"
export GOTOOLCHAIN=local
export GOFLAGS=-mod=readonly
selected_go_version="$(run_bounded_go "$go_bin" env GOVERSION)"
[[ "$selected_go_version" == go1.26.6 ]] || {
  printf 'CPA compatibility requires go1.26.6, selected %s\n' \
    "$selected_go_version" >&2
  exit 1
}
selected_go_os="$(run_bounded_go "$go_bin" env GOOS)"
selected_go_arch="$(run_bounded_go "$go_bin" env GOARCH)"
[[ "$selected_go_os" == linux && "$selected_go_arch" == amd64 ]] || {
  printf 'CPA compatibility requires Go linux/amd64 (selected %s/%s)\n' \
    "$selected_go_os" "$selected_go_arch" >&2
  exit 1
}
printf 'CPA compatibility Go toolchain: %s\n' "$(run_bounded_go "$go_bin" version)"
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

parse_lane_timeout() {
  local raw="$1"
  local number multiplier seconds
  case "$raw" in
    *s) number="${raw%s}"; multiplier=1 ;;
    *m) number="${raw%m}"; multiplier=60 ;;
    *h) number="${raw%h}"; multiplier=3600 ;;
    *)
      printf 'CPA_COMPAT_LANE_TIMEOUT must use an integer seconds, minutes, or hours suffix (for example 15m), got %q\n' \
        "$raw" >&2
      return 2
      ;;
  esac
  if [[ -z "$number" || ! "$number" =~ ^[0-9]+$ || "${#number}" -gt 4 ]]; then
    printf 'CPA_COMPAT_LANE_TIMEOUT has an invalid numeric value: %q\n' "$raw" >&2
    return 2
  fi
  seconds=$((10#$number * multiplier))
  if (( seconds < 60 || seconds > 2700 )); then
    printf 'CPA_COMPAT_LANE_TIMEOUT must be between 60s and 2700s (1m-45m), got %q\n' \
      "$raw" >&2
    return 2
  fi
  printf '%ss\n' "$seconds"
}

cpa_lane_timeout="$(parse_lane_timeout "${CPA_COMPAT_LANE_TIMEOUT:-25m}")" || exit $?

set_profile_identity() {
  case "$1" in
    primary)
      cpa_version='v7.2.145'
      cpa_commit='d9cea8904b14fbbebb77ef26e98ef08f6b48a724'
      cpa_module_sum='h1:5AG1q4MhRK+IU5oP5PPvm04AJYvEkj60br85jiBan5o='
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
  resolved="$(run_bounded_go env GOWORK=off "$go_bin" -C "$directory" list -mod=readonly -m \
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
    if refs="$(timeout --signal=KILL 30s env \
      GIT_CONFIG_GLOBAL=/dev/null \
      GIT_CONFIG_SYSTEM=/dev/null \
      GIT_CONFIG_NOSYSTEM=1 \
      GIT_TERMINAL_PROMPT=0 \
      GIT_ASKPASS=/bin/false \
      git -C "$git_identity_dir" \
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
  v7.2.145 h1:5AG1q4MhRK+IU5oP5PPvm04AJYvEkj60br85jiBan5o= \
  h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
assert_checked_in_module_identity \
  "$root/integration/cpalatestcontract" cpalatestcontract \
  v7.2.145 h1:5AG1q4MhRK+IU5oP5PPvm04AJYvEkj60br85jiBan5o= \
  h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
assert_checked_in_module_identity \
  "$root/integration/pluginstorecontract" pluginstorecontract \
  v7.2.145 h1:5AG1q4MhRK+IU5oP5PPvm04AJYvEkj60br85jiBan5o= \
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
  contract_modfile='go.mod'

  if [[ "$verify_remote" == 1 ]]; then
    resolved_tag_commit="$(resolve_remote_tag_commit "$cpa_version")"
    [[ "$resolved_tag_commit" == "$cpa_commit" ]] || {
      printf 'CPA tag identity mismatch for %s: got commit=%s want commit=%s\n' \
        "$cpa_version" "$resolved_tag_commit" "$cpa_commit" >&2
      exit 1
    }
  fi

  download_json="$(run_bounded_go env GOWORK=off "$go_bin" -C "$root" mod download -json "$cpa_module@$cpa_version")"
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

  if timeout --signal=TERM --kill-after=10s "$cpa_lane_timeout" \
    bash ./scripts/cpa-latest-compat.sh --run-contract-lane \
    "$go_bin" "$profile" "$cpa_commit" "$origin_metadata_file" "$contract_modfile"; then
    :
  else
    lane_status=$?
    if [[ "$lane_status" == 124 || "$lane_status" == 137 || "$lane_status" == 143 ]]; then
      printf 'CPA compatibility cpalatest+pluginstore lane timed out after %s\n' \
        "$cpa_lane_timeout" >&2
    else
      printf 'CPA compatibility cpalatest+pluginstore lane failed with status %s\n' \
        "$lane_status" >&2
    fi
    exit "$lane_status"
  fi

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
