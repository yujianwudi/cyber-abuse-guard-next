#!/usr/bin/env bash
set -euo pipefail

# Production watchdog for CPA Cyber Abuse Guard. It talks to authenticated
# /v0/management routes plus two one-time local plugin resource challenges. Its
# only filesystem mutation is an exact temporary log-root marker that it removes.
# The malicious readiness string is built into the plugin and classified
# in-process; this script never sends a dangerous prompt to /v1, a provider
# route, an auth selector, or an upstream.

BASE_URL="${CPA_BASE_URL:-http://127.0.0.1:8317}"
DIRECT_BASE_URL="${CPA_DIRECT_BASE_URL:-}"
EXPECTED_MODE="${EXPECTED_MODE:-balanced}"
EXPECTED_PRIORITY="${EXPECTED_PRIORITY:-300}"
MAX_ROUTER_ERRORS="${MAX_ROUTER_ERRORS:-0}"
MAX_PANICS_RECOVERED="${MAX_PANICS_RECOVERED:-0}"
MAX_NEW_UNKNOWN_SOURCE_FORMATS="${MAX_NEW_UNKNOWN_SOURCE_FORMATS:-}"
ALLOW_UNVERIFIED_BUILD="${ALLOW_UNVERIFIED_BUILD:-0}"
CONNECT_TIMEOUT_SECONDS="${CONNECT_TIMEOUT_SECONDS:-3}"
REQUEST_TIMEOUT_SECONDS="${REQUEST_TIMEOUT_SECONDS:-10}"
CPA_LOG_DIR="${CPA_LOG_DIR:-}"
CPA_CONFIG_PATH="/v0/management/config"
MANAGEMENT_PATH="/v0/management/plugins/cyber-abuse-guard"

fail() {
  printf 'cyber-abuse-guard health check FAILED: %s\n' "$*" >&2
  exit 1
}

for command_name in curl jq python3; do
  command -v "$command_name" >/dev/null 2>&1 || fail "required command not found: ${command_name}"
done

if [[ ! "$BASE_URL" =~ ^https?://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]{1,5})?$ ]]; then
  fail "CPA_BASE_URL must contain only a loopback host and optional numeric port; paths, userinfo, queries, and fragments are forbidden"
fi
# Do not trust the host resolver to keep the convenience spelling on loopback.
# The strict regex above makes this replacement unambiguous and preserves the
# reviewed scheme and optional port.
BASE_URL="${BASE_URL/\/\/localhost/\/\/127.0.0.1}"
BASE_URL="${BASE_URL%/}"
[[ -n "$DIRECT_BASE_URL" ]] || fail "set CPA_DIRECT_BASE_URL to the CPA v7.2.142 process listener; reverse proxies are forbidden for the startup privacy proof"
if [[ ! "$DIRECT_BASE_URL" =~ ^https?://(127\.0\.0\.1|localhost|\[::1\])(:[0-9]{1,5})?$ ]]; then
  fail "CPA_DIRECT_BASE_URL must contain only the CPA process loopback listener and optional numeric port; paths, userinfo, queries, and fragments are forbidden"
fi
DIRECT_BASE_URL="${DIRECT_BASE_URL/\/\/localhost/\/\/127.0.0.1}"
DIRECT_BASE_URL="${DIRECT_BASE_URL%/}"

case "$EXPECTED_MODE" in
  observe | audit | balanced | strict) ;;
  *) fail "EXPECTED_MODE must be observe, audit, balanced, or strict" ;;
esac
case "$EXPECTED_PRIORITY:$ALLOW_UNVERIFIED_BUILD" in
  *[!0-9:]* | *::* | :* | *:) fail "priority and allow flags must be non-negative integers" ;;
esac
[[ "$MAX_ROUTER_ERRORS" =~ ^[0-9]+$ ]] || fail "MAX_ROUTER_ERRORS must be a non-negative integer"
[[ "$MAX_PANICS_RECOVERED" =~ ^[0-9]+$ ]] || fail "MAX_PANICS_RECOVERED must be a non-negative integer"
[[ -z "$MAX_NEW_UNKNOWN_SOURCE_FORMATS" || "$MAX_NEW_UNKNOWN_SOURCE_FORMATS" =~ ^[0-9]+$ ]] || fail "MAX_NEW_UNKNOWN_SOURCE_FORMATS must be empty or a non-negative integer"
[[ -n "$CPA_LOG_DIR" ]] || fail "set CPA_LOG_DIR to the dedicated CPA v7.2.142 runtime log directory visible from this watchdog"

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
status_startup_privacy_instance_id=""

validate_status() {
  local phase="$1"
  local commit=""
  local ruleset_sha256=""
  local last_reconfigure_error=""

  jq -e . >/dev/null 2>&1 <<<"$response_body" || fail "${phase} plugin status is not JSON"
  jq -e '.loaded == true' >/dev/null <<<"$response_body" || fail "${phase} status reports that the plugin is not loaded/registered"
  jq -e '.enforcement_ready == true' >/dev/null <<<"$response_body" || fail "${phase} status reports that the enforcement engine is not ready"
  if ! jq -e '.operational_ready == true and (.readiness_reasons | type == "array" and length == 0)' >/dev/null <<<"$response_body"; then
    readiness_reasons="$(jq -c '.readiness_reasons // ["status_contract_missing"]' <<<"$response_body" 2>/dev/null || printf '["status_contract_invalid"]')"
    fail "${phase} status is not operationally ready: ${readiness_reasons}"
  fi
  jq -e '
    ((.audit | type) == "object")
    and (.audit.enabled == true)
    and (.audit.persistence_expected == true)
    and (.audit.persistence_verified == true)
    and (.audit.persistence_reason == null)
  ' >/dev/null <<<"$response_body" \
    || fail "${phase} status requires enabled audit with verified persistent storage"

  status_mode="$(jq -r '.mode // ""' <<<"$response_body")"
  [[ "$status_mode" == "$EXPECTED_MODE" ]] || fail "${phase} status mode is ${status_mode}, expected ${EXPECTED_MODE}"
  status_priority="$(jq -er '.priority | numbers' <<<"$response_body")" || fail "${phase} status priority is missing"
  [[ "$status_priority" == "$EXPECTED_PRIORITY" ]] || fail "${phase} status priority is ${status_priority}, expected ${EXPECTED_PRIORITY}"
  status_ruleset_version="$(jq -r '.ruleset_version // ""' <<<"$response_body")"
  [[ -n "$status_ruleset_version" ]] || fail "${phase} status ruleset_version is empty"
  status_startup_privacy_instance_id="$(jq -r '.startup_privacy_instance_id // ""' <<<"$response_body")"
  [[ "$status_startup_privacy_instance_id" =~ ^[0-9a-f]{64}$ ]] \
    || fail "${phase} status startup_privacy_instance_id is not a 256-bit lowercase hexadecimal process identity"

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
  # operational_ready already includes these states. Keep the explicit fields
  # fail-closed as a contract cross-check; no ALLOW_* switch may turn a red
  # production readiness signal green.
  jq -e '.audit_degraded == false' >/dev/null <<<"$response_body" || fail "${phase} status reports degraded audit storage/queue"
  jq -e '.persistence_degraded == false' >/dev/null <<<"$response_body" || fail "${phase} status reports degraded subject persistence"
  jq -e '.hmac_stable == true' >/dev/null <<<"$response_body" || fail "${phase} status reports that HMAC subject identity is not restart-stable"

  status_router_errors="$(jq -er '.router_errors | numbers' <<<"$response_body")" || fail "${phase} status router_errors is missing"
  status_panics_recovered="$(jq -er '.panics_recovered | numbers' <<<"$response_body")" || fail "${phase} status panics_recovered is missing"
  status_unknown_source_formats="$(jq -er '.counters.unknown_source_formats | numbers' <<<"$response_body")" \
    || fail "${phase} status counters.unknown_source_formats is missing"
}

validate_cpa_logging_config() {
  local phase="$1"
  management_request GET "$CPA_CONFIG_PATH"
  [[ "$response_code" == "200" ]] || fail "${phase} authenticated CPA config returned HTTP ${response_code}"
  jq -e '
    (type == "object")
    and ((.["commercial-mode"] | type) == "boolean")
    and ((.["request-log"] | type) == "boolean")
    and ((.["logging-to-file"] | type) == "boolean")
    and (.["commercial-mode"] == true)
    and (.["request-log"] == false)
    and (.["logging-to-file"] == false)
  ' >/dev/null <<<"$response_body" \
    || fail "${phase} CPA request/file logging controls must be strict booleans: commercial-mode=true request-log=false logging-to-file=false"
}

# The config response is current-state evidence only. In CPA v7.2.142 a process
# that started with commercial-mode=false keeps RequestLoggingMiddleware after a
# hot reload. The active proof below binds a unique mode-0600 marker to CPA's
# authenticated error-log inventory. The incomplete-body proof independently
# detects an installed RequestLoggingMiddleware before ResourceRoute dispatch,
# so it remains fail-closed even if CPA resolves a relative logger path and its
# inventory path differently. Authenticated Management then issues complete and
# partial one-time challenges carrying the same process identity first reported
# by status and consumed only by this CAG process through its hidden
# non-management resource. Raw lowercase
# get traverses CPA v7.2.142 request logging but the resource handler does not
# read the body. The complete probe detects raw error-log artifacts; a partial
# timeout is only an inconclusive fail-closed signal. Management paths remain
# unsuitable because shouldLogRequest() skips them.
prove_cpa_startup_request_logging_absent() {
  local proof_detail=""
  if ! proof_detail="$({
    python3 - "$BASE_URL" "$DIRECT_BASE_URL" "$CPA_LOG_DIR" "$CONNECT_TIMEOUT_SECONDS" "$REQUEST_TIMEOUT_SECONDS" "$startup_privacy_instance_id" 3<<<"$management_key" <<'PY'
import http.client
import json
import math
import os
import secrets
import socket
import ssl
import stat
import sys
import time
import urllib.parse

EXPECTED_VERSION = "7.2.137"
EXPECTED_COMMIT = "1f53b2eb03b9e963bac647e5566ca2b304239116"
MIN_COMMIT_PREFIX_LENGTH = 7
MAX_RESPONSE_BYTES = 1 << 20
STARTUP_PROOF_MANAGEMENT_PATH = "/v0/management/plugins/cyber-abuse-guard/health/startup-privacy-proof"
STARTUP_PROOF_RESOURCE_PATH = "/v0/resource/plugins/cyber-abuse-guard/health/startup-privacy-proof"
STARTUP_PROOF_HEADER = "X-Cyber-Abuse-Guard-Startup-Proof"
STARTUP_PROOF_STATUS = 418


class ProofFailure(Exception):
    pass


def reject(code):
    raise ProofFailure(code)


def open_directory_no_symlinks(path):
    if not path or "\x00" in path or "\n" in path or "\r" in path:
        reject("invalid_log_dir")
    if not os.path.isabs(path) or path == "/" or os.path.normpath(path) != path:
        reject("invalid_log_dir")
    required = ("O_DIRECTORY", "O_NOFOLLOW")
    if any(not hasattr(os, name) for name in required):
        reject("secure_open_not_supported")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    flags |= getattr(os, "O_CLOEXEC", 0)
    current = os.open("/", flags)
    try:
        for component in path.split("/")[1:]:
            if not component or component in (".", ".."):
                reject("invalid_log_dir")
            next_fd = os.open(component, flags, dir_fd=current)
            os.close(current)
            current = next_fd
        info = os.fstat(current)
        if not stat.S_ISDIR(info.st_mode):
            reject("log_dir_not_directory")
        return current
    except OSError:
        os.close(current)
        reject("invalid_log_dir")
    except Exception:
        os.close(current)
        raise


def directory_identity(fd):
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode):
        reject("log_dir_not_directory")
    return info.st_dev, info.st_ino


def assert_path_identity(path, expected):
    reopened = open_directory_no_symlinks(path)
    try:
        if directory_identity(reopened) != expected:
            reject("log_dir_changed_during_proof")
    finally:
        os.close(reopened)


def directory_entries(fd):
    try:
        names = os.listdir(fd)
    except OSError:
        reject("log_dir_unreadable")
    for name in names:
        if not isinstance(name, str) or not name or "/" in name or "\x00" in name:
            reject("invalid_log_dir_entry")
    return sorted(names)


def remaining_seconds(deadline, code):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        reject(code)
    return remaining


def connection_for(parts, connect_timeout):
    host = parts.hostname
    if not host:
        reject("invalid_base_url")
    try:
        port = parts.port
    except ValueError:
        reject("invalid_base_url")
    if parts.scheme == "http":
        return http.client.HTTPConnection(host, port or 80, timeout=connect_timeout)
    if parts.scheme == "https":
        return http.client.HTTPSConnection(
            host,
            port or 443,
            timeout=connect_timeout,
            context=ssl.create_default_context(),
        )
    reject("invalid_base_url")


def request(
    parts,
    connect_timeout,
    request_timeout,
    method,
    path,
    body=None,
    management_key=None,
):
    headers = {
        "Accept": "application/json",
        "Connection": "close",
    }
    if management_key is not None:
        headers["X-Management-Key"] = management_key
    if body is not None:
        headers["Content-Type"] = "application/json"
    request_deadline = time.monotonic() + request_timeout
    connection = connection_for(parts, min(connect_timeout, request_timeout))
    try:
        connection.connect()
        if connection.sock is None:
            reject("local_connect_failed")
        transport = connection.sock
        transport.settimeout(remaining_seconds(request_deadline, "local_request_timeout"))
        connection.request(method, path, body=body, headers=headers)
        transport.settimeout(remaining_seconds(request_deadline, "local_request_timeout"))
        response = connection.getresponse()
        payload = bytearray()
        while len(payload) <= MAX_RESPONSE_BYTES:
            if response.isclosed():
                break
            transport.settimeout(remaining_seconds(request_deadline, "local_request_timeout"))
            chunk = response.read(min(65536, MAX_RESPONSE_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_RESPONSE_BYTES:
            reject("management_response_too_large")
        return response.status, response.getheaders(), bytes(payload)
    except socket.timeout:
        reject("local_request_timeout")
    except (OSError, http.client.HTTPException, ssl.SSLError):
        reject("local_request_failed")
    finally:
        connection.close()


def header_value(headers, name, rejection_code="missing_runtime_identity"):
    wanted = name.lower()
    values = [value for key, value in headers if key.lower() == wanted]
    if len(values) != 1 or not isinstance(values[0], str):
        reject(rejection_code)
    return values[0].strip()


def validate_runtime_identity(headers):
    version = header_value(headers, "X-CPA-VERSION")
    commit = header_value(headers, "X-CPA-COMMIT")
    normalized_version = version[1:] if version[:1].lower() == "v" else version
    if normalized_version != EXPECTED_VERSION:
        reject("unexpected_cpa_version")
    normalized_commit = commit.lower()
    # Official CPA builds may expose Git's dynamically sized abbreviated hash
# (v7.2.142 currently emits eight characters). Keep the identity pinned to
    # the reviewed full commit while accepting no prefix weaker than the
    # seven-character form already supported by this watchdog.
    if (
        len(normalized_commit) < MIN_COMMIT_PREFIX_LENGTH
        or len(normalized_commit) > len(EXPECTED_COMMIT)
        or not EXPECTED_COMMIT.startswith(normalized_commit)
    ):
        reject("unexpected_cpa_commit")


def error_log_files(parts, connect_timeout, request_timeout, management_key):
    status_code, headers, raw = request(
        parts,
        connect_timeout,
        request_timeout,
        "GET",
        "/v0/management/request-error-logs",
        management_key=management_key,
    )
    if status_code != 200:
        reject("error_log_inventory_unavailable")
    validate_runtime_identity(headers)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("invalid_error_log_inventory")
    if type(payload) is not dict or type(payload.get("files")) is not list:
        reject("invalid_error_log_inventory")
    files = {}
    for item in payload["files"]:
        if type(item) is not dict:
            reject("invalid_error_log_inventory")
        name = item.get("name")
        size = item.get("size")
        modified = item.get("modified")
        if (
            type(name) is not str
            or not name.startswith("error-")
            or not name.endswith(".log")
            or "/" in name
            or "\\" in name
            or "\x00" in name
            or type(size) is not int
            or size < 0
            or type(modified) is not int
            or modified < 0
            or name in files
        ):
            reject("invalid_error_log_inventory")
        files[name] = item
    return files


def issue_startup_privacy_challenge(
    parts, connect_timeout, request_timeout, management_key, expected_instance_id,
):
    status_code, headers, raw = request(
        parts,
        connect_timeout,
        request_timeout,
        "POST",
        STARTUP_PROOF_MANAGEMENT_PATH,
        body=b"{}",
        management_key=management_key,
    )
    if status_code != 200:
        reject("startup_privacy_challenge_unavailable")
    validate_runtime_identity(headers)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("invalid_startup_privacy_challenge")
    if type(payload) is not dict or set(payload) != {"challenge", "instance_id", "expires_at_unix"}:
        reject("invalid_startup_privacy_challenge")
    challenge = payload["challenge"]
    instance_id = payload["instance_id"]
    expires_at = payload["expires_at_unix"]
    if (
        type(challenge) is not str
        or len(challenge) != 64
        or challenge.lower() != challenge
        or any(character not in "0123456789abcdef" for character in challenge)
        or type(instance_id) is not str
        or len(instance_id) != 64
        or instance_id.lower() != instance_id
        or any(character not in "0123456789abcdef" for character in instance_id)
        or type(expires_at) is not int
        or expires_at <= int(time.time())
    ):
        reject("invalid_startup_privacy_challenge")
    if instance_id != expected_instance_id:
        reject("startup_privacy_instance_mismatch")
    return challenge


def prove_startup_privacy_challenge(
    management_parts,
    resource_parts,
    connect_timeout,
    request_timeout,
    management_key,
    expected_instance_id,
    challenge,
    partial,
):
    host = resource_parts.hostname
    if not host:
        reject("invalid_base_url")
    try:
        port = resource_parts.port or (443 if resource_parts.scheme == "https" else 80)
    except ValueError:
        reject("invalid_base_url")
    request_deadline = time.monotonic() + request_timeout
    host_header = "[%s]" % host if ":" in host else host
    if port not in (80, 443):
        host_header = "%s:%d" % (host_header, port)
    declared_length = 64 if partial else 2
    body = b"{" if partial else b"{}"
    request_head = (
        "get %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Accept: application/json\r\n"
        "Content-Type: application/json\r\n"
        "%s: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close, %s\r\n\r\n"
        % (
            STARTUP_PROOF_RESOURCE_PATH,
            host_header,
            STARTUP_PROOF_HEADER,
            challenge,
            declared_length,
            STARTUP_PROOF_HEADER,
        )
    ).encode("ascii")
    sock = None
    response = None
    try:
        sock = socket.create_connection(
            (host, port),
            timeout=min(connect_timeout, request_timeout),
        )
        if resource_parts.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=host)
        sock.settimeout(remaining_seconds(request_deadline, "startup_privacy_probe_timeout"))
        sock.sendall(request_head + body)
        response = http.client.HTTPResponse(sock)
        response.begin()
        payload = bytearray()
        while len(payload) <= MAX_RESPONSE_BYTES:
            if response.isclosed():
                break
            sock.settimeout(remaining_seconds(request_deadline, "startup_privacy_probe_timeout"))
            chunk = response.read(min(65536, MAX_RESPONSE_BYTES + 1 - len(payload)))
            if not chunk:
                break
            payload.extend(chunk)
        if len(payload) > MAX_RESPONSE_BYTES:
            reject("startup_privacy_proof_response_too_large")
        status_code = response.status
        headers = response.getheaders()
        raw = bytes(payload)
    except socket.timeout:
        if partial:
            reject("startup_privacy_partial_probe_inconclusive")
        reject("startup_privacy_probe_timeout")
    except (OSError, http.client.HTTPException, ssl.SSLError):
        reject("startup_privacy_probe_failed")
    finally:
        if response is not None:
            response.close()
        if sock is not None:
            try:
                sock.close()
            except OSError:
                pass
    if status_code != STARTUP_PROOF_STATUS:
        reject("startup_privacy_proof_not_terminated_locally")
    if header_value(
        headers,
        STARTUP_PROOF_HEADER,
        "startup_privacy_proof_response_mismatch",
    ) != challenge:
        reject("startup_privacy_proof_response_mismatch")
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("startup_privacy_proof_response_mismatch")
    if payload != {
        "challenge": challenge,
        "instance_id": expected_instance_id,
        "consumed": True,
        "local_only": True,
        "upstream_attempted": False,
    }:
        reject("startup_privacy_proof_response_mismatch")

    query = urllib.parse.urlencode({"challenge": challenge})
    status_code, headers, raw = request(
        management_parts,
        connect_timeout,
        request_timeout,
        "GET",
        STARTUP_PROOF_MANAGEMENT_PATH + "?" + query,
        management_key=management_key,
    )
    if status_code != 200:
        reject("startup_privacy_proof_not_confirmed_by_plugin")
    validate_runtime_identity(headers)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("startup_privacy_proof_not_confirmed_by_plugin")
    if payload != {
        "challenge": challenge,
        "instance_id": expected_instance_id,
        "consumed": True,
    }:
        reject("startup_privacy_proof_not_confirmed_by_plugin")


def validate_direct_logging_config(parts, connect_timeout, request_timeout, management_key):
    status_code, headers, raw = request(
        parts,
        connect_timeout,
        request_timeout,
        "GET",
        "/v0/management/config",
        management_key=management_key,
    )
    if status_code != 200:
        reject("direct_logging_config_unavailable")
    validate_runtime_identity(headers)
    try:
        payload = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        reject("invalid_direct_logging_config")
    if (
        type(payload) is not dict
        or type(payload.get("commercial-mode")) is not bool
        or type(payload.get("request-log")) is not bool
        or type(payload.get("logging-to-file")) is not bool
        or payload["commercial-mode"] is not True
        or payload["request-log"] is not False
        or payload["logging-to-file"] is not False
    ):
        reject("unsafe_direct_logging_config")


def devino(info):
    return info.st_dev, info.st_ino


def write_all(fd, payload):
    view = memoryview(payload)
    offset = 0
    while offset < len(view):
        try:
            written = os.write(fd, view[offset:])
        except InterruptedError:
            continue
        except OSError:
            reject("marker_write_failed")
        if written <= 0 or written > len(view) - offset:
            reject("marker_write_failed")
        offset += written


def validate_marker_checkpoint(
    log_dir,
    log_fd,
    expected_directory_identity,
    marker_name,
    marker_fd,
    marker_devino,
    expected_size,
):
    if directory_identity(log_fd) != expected_directory_identity:
        reject("log_dir_changed_during_proof")
    assert_path_identity(log_dir, expected_directory_identity)
    try:
        held = os.fstat(marker_fd)
        named = os.stat(marker_name, dir_fd=log_fd, follow_symlinks=False)
    except FileNotFoundError:
        reject("marker_changed_during_proof")
    except OSError:
        reject("marker_state_unavailable")
    for info in (held, named):
        if (
            not stat.S_ISREG(info.st_mode)
            or devino(info) != marker_devino
            or info.st_size != expected_size
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            reject("marker_changed_during_proof")
    if directory_entries(log_fd) != [marker_name]:
        reject("startup_request_logging_artifact_detected")


def unlink_owned_marker(log_fd, marker_name, marker_fd, marker_devino):
    if marker_fd is None or not marker_name:
        return None
    identity = marker_devino
    if identity is None:
        try:
            identity = devino(os.fstat(marker_fd))
        except OSError:
            return "marker_cleanup_identity_unavailable"
    try:
        named = os.stat(marker_name, dir_fd=log_fd, follow_symlinks=False)
    except FileNotFoundError:
        return "marker_missing_during_proof"
    except OSError:
        return "marker_cleanup_stat_failed"
    if not stat.S_ISREG(named.st_mode) or devino(named) != identity:
        return "marker_replaced_during_proof"
    try:
        os.unlink(marker_name, dir_fd=log_fd)
    except FileNotFoundError:
        return "marker_changed_during_cleanup"
    except OSError:
        return "marker_cleanup_failed"
    try:
        held = os.fstat(marker_fd)
    except OSError:
        return "marker_cleanup_unverified"
    if devino(held) != identity or held.st_nlink != 0:
        return "marker_cleanup_unverified"
    return None


def main():
    if len(sys.argv) != 7:
        reject("invalid_proof_arguments")
    (
        base_url, direct_base_url, log_dir, connect_timeout_raw,
        request_timeout_raw, expected_instance_id,
    ) = sys.argv[1:]
    if (
        len(expected_instance_id) != 64
        or expected_instance_id.lower() != expected_instance_id
        or any(character not in "0123456789abcdef" for character in expected_instance_id)
    ):
        reject("invalid_startup_privacy_instance_identity")
    try:
        connect_timeout = float(connect_timeout_raw)
        request_timeout = float(request_timeout_raw)
    except ValueError:
        reject("invalid_timeout")
    if (
        not math.isfinite(connect_timeout)
        or not math.isfinite(request_timeout)
        or connect_timeout <= 0
        or request_timeout <= 0
    ):
        reject("invalid_timeout")
    management_parts = urllib.parse.urlsplit(base_url)
    direct_parts = urllib.parse.urlsplit(direct_base_url)
    for parts in (management_parts, direct_parts):
        if parts.path not in ("", "/") or parts.query or parts.fragment or parts.username or parts.password:
            reject("invalid_base_url")

    raw_key = os.read(3, 65537)
    if len(raw_key) == 0 or len(raw_key) > 65536 or not raw_key.endswith(b"\n"):
        reject("invalid_management_key")
    raw_key = raw_key[:-1]
    if not raw_key or b"\n" in raw_key or b"\r" in raw_key:
        reject("invalid_management_key")
    try:
        management_key = raw_key.decode("latin-1")
    except UnicodeDecodeError:
        reject("invalid_management_key")

    log_fd = open_directory_no_symlinks(log_dir)
    marker_name = ""
    marker_fd = None
    marker_devino = None
    proof_error = None
    try:
        expected_identity = directory_identity(log_fd)
        if directory_entries(log_fd):
            reject("log_dir_not_empty_before_proof")

        token = secrets.token_hex(16)
        marker_name = "error-cag-watchdog-root-%s.log" % token
        marker_payload = ("cyber-abuse-guard watchdog log-root binding %s\n" % token).encode("ascii")
        marker_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        marker_flags |= getattr(os, "O_CLOEXEC", 0)
        marker_fd = os.open(marker_name, marker_flags, 0o600, dir_fd=log_fd)
        try:
            marker_info = os.fstat(marker_fd)
            marker_devino = devino(marker_info)
            if not stat.S_ISREG(marker_info.st_mode) or marker_info.st_nlink != 1 or marker_info.st_size != 0:
                reject("invalid_marker_type")
            os.fchmod(marker_fd, 0o600)
            validate_marker_checkpoint(
                log_dir, log_fd, expected_identity,
                marker_name, marker_fd, marker_devino, 0,
            )
            write_all(marker_fd, marker_payload)
            try:
                os.fsync(marker_fd)
            except OSError:
                reject("marker_fsync_failed")
            validate_marker_checkpoint(
                log_dir, log_fd, expected_identity,
                marker_name, marker_fd, marker_devino, len(marker_payload),
            )
        except Exception:
            raise

        validate_direct_logging_config(direct_parts, connect_timeout, request_timeout, management_key)
        files = error_log_files(direct_parts, connect_timeout, request_timeout, management_key)
        if set(files) != {marker_name} or files[marker_name]["size"] != len(marker_payload):
            reject("log_dir_not_bound_to_cpa_runtime_root")
        validate_marker_checkpoint(
            log_dir, log_fd, expected_identity,
            marker_name, marker_fd, marker_devino, len(marker_payload),
        )

        challenge = issue_startup_privacy_challenge(
            management_parts, connect_timeout, request_timeout, management_key,
            expected_instance_id,
        )
        prove_startup_privacy_challenge(
            management_parts, direct_parts, connect_timeout, request_timeout,
            management_key, expected_instance_id, challenge, False,
        )

        # FileRequestLogger writes synchronously in Finalize. A short delay also
        # closes the narrow window in which the HTTP body reached the client just
        # before Gin's outer middleware returned.
        time.sleep(0.05)
        validate_marker_checkpoint(
            log_dir, log_fd, expected_identity,
            marker_name, marker_fd, marker_devino, len(marker_payload),
        )
        files = error_log_files(direct_parts, connect_timeout, request_timeout, management_key)
        if set(files) != {marker_name} or files[marker_name]["size"] != len(marker_payload):
            reject("startup_request_logging_artifact_detected")
        validate_marker_checkpoint(
            log_dir, log_fd, expected_identity,
            marker_name, marker_fd, marker_devino, len(marker_payload),
        )

        partial_challenge = issue_startup_privacy_challenge(
            management_parts, connect_timeout, request_timeout, management_key,
            expected_instance_id,
        )
        prove_startup_privacy_challenge(
            management_parts, direct_parts, connect_timeout, request_timeout,
            management_key, expected_instance_id, partial_challenge, True,
        )
        validate_marker_checkpoint(
            log_dir, log_fd, expected_identity,
            marker_name, marker_fd, marker_devino, len(marker_payload),
        )
        files = error_log_files(direct_parts, connect_timeout, request_timeout, management_key)
        if set(files) != {marker_name} or files[marker_name]["size"] != len(marker_payload):
            reject("startup_request_logging_artifact_detected")
    except BaseException as error:
        proof_error = error
    finally:
        cleanup_error = unlink_owned_marker(log_fd, marker_name, marker_fd, marker_devino)

    if proof_error is None and cleanup_error is None:
        assert_path_identity(log_dir, expected_identity)
        verification_fd = open_directory_no_symlinks(log_dir)
        try:
            if directory_entries(verification_fd):
                reject("log_dir_not_empty_after_proof")
        finally:
            os.close(verification_fd)
        if error_log_files(direct_parts, connect_timeout, request_timeout, management_key):
            reject("error_log_inventory_not_empty_after_proof")

    if marker_fd is not None:
        os.close(marker_fd)
    os.close(log_fd)
    if proof_error is not None:
        raise proof_error
    if cleanup_error is not None:
        reject(cleanup_error)


try:
    main()
except ProofFailure as failure:
    print(str(failure))
    raise SystemExit(1)
except Exception:
    print("startup_privacy_proof_internal_error")
    raise SystemExit(1)
print("verified")
PY
  } 2>&1)"; then
    fail "CPA startup request-logging proof failed: ${proof_detail:-unknown_error}"
  fi
  [[ "$proof_detail" == "verified" ]] || fail "CPA startup request-logging proof returned an invalid result"
}

validate_cpa_logging_config "initial"

management_request GET "${MANAGEMENT_PATH}/status"
[[ "$response_code" == "200" ]] || fail "authenticated plugin status returned HTTP ${response_code}"
validate_status "initial"
actual_mode="$status_mode"
actual_priority="$status_priority"
ruleset_version="$status_ruleset_version"
startup_privacy_instance_id="$status_startup_privacy_instance_id"
router_errors_before="$status_router_errors"
panics_before="$status_panics_recovered"
unknown_source_formats_before="$status_unknown_source_formats"
max_router_errors=$((10#$MAX_ROUTER_ERRORS))
(( router_errors_before <= max_router_errors )) || fail "router_errors=${router_errors_before} (Router/RequestInterceptor protocol failures) exceeds ${max_router_errors}"
max_panics_recovered=$((10#$MAX_PANICS_RECOVERED))
(( panics_before <= max_panics_recovered )) || fail "panics_recovered=${panics_before} exceeds ${max_panics_recovered}"
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
benign_instance_id="$(jq -r '.instance_id // ""' <<<"$response_body")"
[[ "$benign_instance_id" == "$startup_privacy_instance_id" ]] \
  || fail "built-in benign local probe came from a different plugin process"
benign_runtime_mode="$(jq -r '.runtime_mode // ""' <<<"$response_body")"
benign_ruleset_version="$(jq -r '.ruleset_version // ""' <<<"$response_body")"
[[ "$benign_runtime_mode" == "$actual_mode" ]] || fail "runtime mode changed before/during the benign local probe"
[[ "$benign_ruleset_version" == "$ruleset_version" ]] || fail "ruleset changed before/during the benign local probe"

management_request POST "${MANAGEMENT_PATH}/health/probe" '{"kind":"malicious"}'
[[ "$response_code" == "403" ]] || fail "built-in malicious local probe returned HTTP ${response_code}, expected 403"
jq -e '.kind == "malicious" and .action == "block" and .local_only == true and .self_route == true and .target_kind == "self" and .upstream_attempted == false' >/dev/null <<<"$response_body" \
  || fail "built-in malicious probe was not a local self-route decision"
malicious_instance_id="$(jq -r '.instance_id // ""' <<<"$response_body")"
[[ "$malicious_instance_id" == "$startup_privacy_instance_id" ]] \
  || fail "built-in malicious local probe came from a different plugin process"
malicious_runtime_mode="$(jq -r '.runtime_mode // ""' <<<"$response_body")"
malicious_ruleset_version="$(jq -r '.ruleset_version // ""' <<<"$response_body")"
[[ "$malicious_runtime_mode" == "$actual_mode" ]] || fail "runtime mode changed before/during the malicious local probe"
[[ "$malicious_ruleset_version" == "$ruleset_version" ]] || fail "ruleset changed before/during the malicious local probe"

# The management 403 above is intentionally skipped by CPA's request logger.
# Follow it with the bound non-management fixed-418 proof that can distinguish a
# clean commercial-mode startup from an unsafe startup followed by hot reload.
prove_cpa_startup_request_logging_absent
validate_cpa_logging_config "post-proof"

management_request GET "${MANAGEMENT_PATH}/status"
[[ "$response_code" == "200" ]] || fail "post-probe status returned HTTP ${response_code}"
validate_status "post-probe"
[[ "$status_mode" == "$actual_mode" ]] || fail "runtime mode changed during local probes"
[[ "$status_priority" == "$actual_priority" ]] || fail "plugin priority changed during local probes"
[[ "$status_ruleset_version" == "$ruleset_version" ]] || fail "ruleset changed during local probes"
[[ "$status_startup_privacy_instance_id" == "$startup_privacy_instance_id" ]] \
  || fail "plugin process identity changed during local probes"
router_errors_after="$status_router_errors"
panics_after="$status_panics_recovered"
unknown_source_formats_after="$status_unknown_source_formats"
[[ "$router_errors_after" == "$router_errors_before" ]] || fail "router_errors (Router/RequestInterceptor protocol failures) increased during local probes"
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

printf 'cyber-abuse-guard health check OK: mode=%s ruleset=%s cpa=7.2.130 startup_request_logging=absent_under_admitted_listener_contract direct_listener_binding=deployment_required router_errors=%s (Router/RequestInterceptor protocol failures) panics_recovered=%s unknown_source_formats=%s\n' \
  "$actual_mode" "$ruleset_version" "$router_errors_after" "$panics_after" "$unknown_source_formats_after"
