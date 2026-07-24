#!/usr/bin/env bash
set -euo pipefail

# Read-only production watchdog for CPA Cyber Abuse Guard. It talks only to
# authenticated /v0/management plugin routes. The malicious readiness string
# is built into the plugin and classified in-process; this script never sends a
# dangerous prompt to /v1, a provider route, an auth selector, or an upstream.

BASE_URL="${CPA_BASE_URL:-http://127.0.0.1:8317}"
EXPECTED_MODE="${EXPECTED_MODE:-balanced}"
EXPECTED_PRIORITY="${EXPECTED_PRIORITY:-300}"
MAX_ROUTER_ERRORS="${MAX_ROUTER_ERRORS:-}"
MAX_PANICS_RECOVERED="${MAX_PANICS_RECOVERED:-}"
MAX_NEW_UNKNOWN_SOURCE_FORMATS="${MAX_NEW_UNKNOWN_SOURCE_FORMATS:-}"
ALLOW_AUDIT_DEGRADED="${ALLOW_AUDIT_DEGRADED:-0}"
ALLOW_PERSISTENCE_DEGRADED="${ALLOW_PERSISTENCE_DEGRADED:-0}"
ALLOW_UNSTABLE_HMAC="${ALLOW_UNSTABLE_HMAC:-0}"
ALLOW_UNVERIFIED_BUILD="${ALLOW_UNVERIFIED_BUILD:-0}"
CONNECT_TIMEOUT_SECONDS="${CONNECT_TIMEOUT_SECONDS:-3}"
REQUEST_TIMEOUT_SECONDS="${REQUEST_TIMEOUT_SECONDS:-10}"
MANAGEMENT_PATH="/v0/management/plugins/cyber-abuse-guard"

fail() {
  printf 'cyber-abuse-guard health check FAILED: %s\n' "$*" >&2
  exit 1
}

for command_name in curl jq; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: ${command_name}"
done

if [[ ! "$BASE_URL" =~ ^https?://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]{1,5})?$ ]]; then
  fail "CPA_BASE_URL must contain only a loopback host and optional numeric port; paths, userinfo, queries, and fragments are forbidden"
fi
BASE_URL="${BASE_URL%/}"

case "$EXPECTED_MODE" in
  observe | audit | balanced | strict) ;;
  *) fail "EXPECTED_MODE must be observe, audit, balanced, or strict" ;;
esac
case "$EXPECTED_PRIORITY:$ALLOW_AUDIT_DEGRADED:$ALLOW_PERSISTENCE_DEGRADED:$ALLOW_UNSTABLE_HMAC:$ALLOW_UNVERIFIED_BUILD" in
  *[!0-9:]* | *::* | :* | *:) fail "priority and allow flags must be non-negative integers" ;;
esac
[[ -z "$MAX_ROUTER_ERRORS" || "$MAX_ROUTER_ERRORS" =~ ^[0-9]+$ ]] || fail "MAX_ROUTER_ERRORS must be empty or a non-negative integer"
[[ -z "$MAX_PANICS_RECOVERED" || "$MAX_PANICS_RECOVERED" =~ ^[0-9]+$ ]] || fail "MAX_PANICS_RECOVERED must be empty or a non-negative integer"
[[ -z "$MAX_NEW_UNKNOWN_SOURCE_FORMATS" || "$MAX_NEW_UNKNOWN_SOURCE_FORMATS" =~ ^[0-9]+$ ]] || fail "MAX_NEW_UNKNOWN_SOURCE_FORMATS must be empty or a non-negative integer"

management_key="${CPA_MANAGEMENT_KEY:-}"
if [[ -z "$management_key" && -n "${CPA_MANAGEMENT_KEY_FILE:-}" ]]; then
  [[ -f "$CPA_MANAGEMENT_KEY_FILE" ]] || fail "CPA_MANAGEMENT_KEY_FILE is not a regular file"
  IFS= read -r management_key < "$CPA_MANAGEMENT_KEY_FILE" || true
fi
[[ -n "$management_key" ]] || fail "set CPA_MANAGEMENT_KEY or CPA_MANAGEMENT_KEY_FILE"
[[ "$management_key" != *$'\n'* && "$management_key" != *$'\r'* ]] || fail "management key contains a newline"

response_body=""
response_code=""

management_request() {
  local method="$1"
  local path="$2"
  local body="${3:-}"
  local -a arguments=(
    --disable
    --silent --show-error
    --noproxy '*'
    --proxy ''
    --proto '=http,https'
    --proto-redir '=http,https'
    --connect-timeout "$CONNECT_TIMEOUT_SECONDS"
    --max-time "$REQUEST_TIMEOUT_SECONDS"
    --request "$method"
    --header @-
    --header "Accept: application/json"
    --write-out $'\n%{http_code}'
  )
  if [[ -n "$body" ]]; then
    arguments+=(--header "Content-Type: application/json" --data-binary "$body")
  fi
  local output
  # Feed the credential header through stdin so the key is not exposed in the
  # curl process argument list.
  if ! output="$(printf 'X-Management-Key: %s\n' "$management_key" | curl "${arguments[@]}" "${BASE_URL}${path}")"; then
    fail "CPA is unreachable at the configured loopback URL"
  fi
  response_code="${output##*$'\n'}"
  response_body="${output%$'\n'*}"
  [[ "$response_code" =~ ^[0-9]{3}$ ]] || fail "management endpoint returned an invalid HTTP status"
}

status_mode=""
status_priority=""
status_ruleset_version=""
status_router_errors=""
status_panics_recovered=""
status_unknown_source_formats=""

validate_status() {
  local phase="$1"
  local commit=""
  local ruleset_sha256=""
  local last_reconfigure_error=""

  jq -e . >/dev/null 2>&1 <<<"$response_body" || fail "${phase} plugin status is not JSON"
  jq -e '.loaded == true' >/dev/null <<<"$response_body" || fail "${phase} status reports that the plugin is not loaded/registered"
  jq -e '.enforcement_ready == true' >/dev/null <<<"$response_body" || fail "${phase} status reports that the enforcement engine is not ready"

  status_mode="$(jq -r '.mode // ""' <<<"$response_body")"
  [[ "$status_mode" == "$EXPECTED_MODE" ]] || fail "${phase} status mode is ${status_mode}, expected ${EXPECTED_MODE}"
  status_priority="$(jq -er '.priority | numbers' <<<"$response_body")" || fail "${phase} status priority is missing"
  [[ "$status_priority" == "$EXPECTED_PRIORITY" ]] || fail "${phase} status priority is ${status_priority}, expected ${EXPECTED_PRIORITY}"
  status_ruleset_version="$(jq -r '.ruleset_version // ""' <<<"$response_body")"
  [[ -n "$status_ruleset_version" ]] || fail "${phase} status ruleset_version is empty"

  if [[ "$ALLOW_UNVERIFIED_BUILD" != "1" ]]; then
    commit="$(jq -r '.commit // ""' <<<"$response_body")"
    ruleset_sha256="$(jq -r '.ruleset_sha256 // ""' <<<"$response_body")"
    [[ -n "$commit" && "$commit" != "unknown" ]] || fail "${phase} status build commit is not pinned"
    [[ "$ruleset_sha256" =~ ^[0-9a-f]{64}$ ]] || fail "${phase} status ruleset_sha256 is not a pinned SHA-256 digest"
    jq -e '.dirty == false and .ruleset_version_match == true' >/dev/null <<<"$response_body" \
      || fail "${phase} status build is dirty or linked ruleset metadata does not match the loaded rules"
  fi

  last_reconfigure_error="$(jq -r '.last_reconfigure_error // ""' <<<"$response_body")"
  [[ -z "$last_reconfigure_error" ]] || fail "${phase} status reports that the last reconfiguration was rejected"
  if [[ "$ALLOW_AUDIT_DEGRADED" != "1" ]]; then
    jq -e '.audit_degraded == false' >/dev/null <<<"$response_body" || fail "${phase} status reports degraded audit storage/queue"
  fi
  if [[ "$ALLOW_PERSISTENCE_DEGRADED" != "1" ]]; then
    jq -e '.persistence_degraded == false' >/dev/null <<<"$response_body" || fail "${phase} status reports degraded subject persistence"
  fi
  if [[ "$ALLOW_UNSTABLE_HMAC" != "1" ]]; then
    jq -e '.hmac_stable == true' >/dev/null <<<"$response_body" || fail "${phase} status reports that HMAC subject identity is not restart-stable"
  fi

  status_router_errors="$(jq -er '.router_errors | numbers' <<<"$response_body")" || fail "${phase} status router_errors is missing"
  status_panics_recovered="$(jq -er '.panics_recovered | numbers' <<<"$response_body")" || fail "${phase} status panics_recovered is missing"
  status_unknown_source_formats="$(jq -er '.counters.unknown_source_formats | numbers' <<<"$response_body")" \
    || fail "${phase} status counters.unknown_source_formats is missing"
}

management_request GET "${MANAGEMENT_PATH}/status"
[[ "$response_code" == "200" ]] || fail "authenticated plugin status returned HTTP ${response_code}"
validate_status "initial"
actual_mode="$status_mode"
actual_priority="$status_priority"
ruleset_version="$status_ruleset_version"
router_errors_before="$status_router_errors"
panics_before="$status_panics_recovered"
unknown_source_formats_before="$status_unknown_source_formats"
if [[ -n "$MAX_ROUTER_ERRORS" ]]; then
  max_router_errors=$((10#$MAX_ROUTER_ERRORS))
  (( router_errors_before <= max_router_errors )) || fail "router_errors=${router_errors_before} exceeds ${max_router_errors}"
elif (( router_errors_before > 0 )); then
  printf 'NOTICE: cumulative router_errors=%s; set MAX_ROUTER_ERRORS to enforce an absolute restart-scoped budget.\n' "$router_errors_before" >&2
fi
if [[ -n "$MAX_PANICS_RECOVERED" ]]; then
  max_panics_recovered=$((10#$MAX_PANICS_RECOVERED))
  (( panics_before <= max_panics_recovered )) || fail "panics_recovered=${panics_before} exceeds ${max_panics_recovered}"
elif (( panics_before > 0 )); then
  printf 'NOTICE: cumulative panics_recovered=%s; set MAX_PANICS_RECOVERED to enforce an absolute restart-scoped budget.\n' "$panics_before" >&2
fi
if (( unknown_source_formats_before > 0 )); then
  printf 'NOTICE: cumulative unknown_source_formats=%s; investigate unsupported CPA/provider source labels.\n' "$unknown_source_formats_before" >&2
fi

if jq -e '.conflict_detection.router_enumeration_supported == false' >/dev/null <<<"$response_body"; then
  printf '%s\n' 'NOTICE: CPA plugin ABI v1 cannot enumerate router ordering; verify higher-priority routers in deployment configuration.' >&2
fi
if jq -e '.conflict_detection.duplicate_plugin_binary_scan_supported == false' >/dev/null <<<"$response_body"; then
  printf '%s\n' 'NOTICE: CPA plugin ABI v1 cannot inspect the plugin directory; verify that only one cyber-abuse-guard .so is deployed.' >&2
fi

# Both probes are local Management API operations with built-in text. They do
# not mutate subject state, counters, SQLite, CPA configuration, or accounts.
management_request POST "${MANAGEMENT_PATH}/health/probe" '{"kind":"benign"}'
[[ "$response_code" == "200" ]] || fail "built-in benign local probe returned HTTP ${response_code}"
jq -e '.kind == "benign" and .action == "allow" and .local_only == true and .upstream_attempted == false' >/dev/null <<<"$response_body" \
  || fail "built-in benign local probe failed"
benign_runtime_mode="$(jq -r '.runtime_mode // ""' <<<"$response_body")"
benign_ruleset_version="$(jq -r '.ruleset_version // ""' <<<"$response_body")"
[[ "$benign_runtime_mode" == "$actual_mode" ]] || fail "runtime mode changed before/during the benign local probe"
[[ "$benign_ruleset_version" == "$ruleset_version" ]] || fail "ruleset changed before/during the benign local probe"

management_request POST "${MANAGEMENT_PATH}/health/probe" '{"kind":"malicious"}'
[[ "$response_code" == "403" ]] || fail "built-in malicious local probe returned HTTP ${response_code}, expected 403"
jq -e '.kind == "malicious" and .action == "block" and .local_only == true and .self_route == true and .target_kind == "self" and .upstream_attempted == false' >/dev/null <<<"$response_body" \
  || fail "built-in malicious probe was not a local self-route decision"
malicious_runtime_mode="$(jq -r '.runtime_mode // ""' <<<"$response_body")"
malicious_ruleset_version="$(jq -r '.ruleset_version // ""' <<<"$response_body")"
[[ "$malicious_runtime_mode" == "$actual_mode" ]] || fail "runtime mode changed before/during the malicious local probe"
[[ "$malicious_ruleset_version" == "$ruleset_version" ]] || fail "ruleset changed before/during the malicious local probe"

management_request GET "${MANAGEMENT_PATH}/status"
[[ "$response_code" == "200" ]] || fail "post-probe status returned HTTP ${response_code}"
validate_status "post-probe"
[[ "$status_mode" == "$actual_mode" ]] || fail "runtime mode changed during local probes"
[[ "$status_priority" == "$actual_priority" ]] || fail "plugin priority changed during local probes"
[[ "$status_ruleset_version" == "$ruleset_version" ]] || fail "ruleset changed during local probes"
router_errors_after="$status_router_errors"
panics_after="$status_panics_recovered"
unknown_source_formats_after="$status_unknown_source_formats"
[[ "$router_errors_after" == "$router_errors_before" ]] || fail "router_errors increased during local probes"
[[ "$panics_after" == "$panics_before" ]] || fail "panics_recovered increased during local probes"
(( unknown_source_formats_after >= unknown_source_formats_before )) || fail "unknown_source_formats decreased during local probes; CPA/plugin may have restarted"
new_unknown_source_formats=$((unknown_source_formats_after - unknown_source_formats_before))
if [[ -n "$MAX_NEW_UNKNOWN_SOURCE_FORMATS" ]]; then
  max_new_unknown_source_formats=$((10#$MAX_NEW_UNKNOWN_SOURCE_FORMATS))
  (( new_unknown_source_formats <= max_new_unknown_source_formats )) \
    || fail "unknown_source_formats increased by ${new_unknown_source_formats}, exceeding probe-window budget ${max_new_unknown_source_formats}"
elif (( new_unknown_source_formats > 0 )); then
  printf 'NOTICE: unknown_source_formats increased by %s during the watchdog window; set MAX_NEW_UNKNOWN_SOURCE_FORMATS to enforce a delta budget.\n' \
    "$new_unknown_source_formats" >&2
fi

printf 'cyber-abuse-guard health check OK: mode=%s ruleset=%s router_errors=%s panics_recovered=%s unknown_source_formats=%s\n' \
  "$actual_mode" "$ruleset_version" "$router_errors_after" "$panics_after" "$unknown_source_formats_after"
