#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

# Exercise the real watchdog against a local management stub while every
# standard proxy variable points at a hostile capture listener. The watchdog
# must connect directly and must not send even a TCP connection to the proxy.
python3 - "$root/scripts/check-production-health.sh" <<'PY'
import http.client
import http.server
import json
import os
import secrets
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

watchdog = sys.argv[1]
management_key = "proxy-negative-test-management-key"
base_path = "/v0/management/plugins/cyber-abuse-guard"
config_path = "/v0/management/config"
error_logs_path = "/v0/management/request-error-logs"
startup_proof_path = base_path + "/health/startup-privacy-proof"
startup_proof_resource_path = "/v0/resource/plugins/cyber-abuse-guard/health/startup-privacy-proof"
startup_proof_header = "X-Cyber-Abuse-Guard-Startup-Proof"
proxy_connections = 0
proxy_bytes = bytearray()
proxy_lock = threading.Lock()


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True

    def handle_error(self, _request, _client_address):
        pass


class ManagementHandler(http.server.BaseHTTPRequestHandler):
    startup_privacy_instance_id = "a" * 64
    router_errors = 0
    panics_recovered = 0
    unknown_source_formats = 0
    status_requests = 0
    final_status_mode = ""
    increment_unknown_on_final = False
    probe_runtime_mode = "balanced"
    probe_ruleset_version = "1.0.7"
    operational_ready = True
    audit_contract = "valid"
    audit_degraded = False
    persistence_degraded = False
    hmac_stable = True
    config_contract = "valid"
    error_logs_contract = "valid"
    startup_request_logging_installed = False
    emit_request_log_artifact = False
    swap_log_dir_on_probe = False
    runtime_version = "7.2.137"
    runtime_commit = "85d2fadd"
    log_dir = ""
    swapped_log_dir = ""
    request_paths = []
    startup_challenges = {}
    startup_proof_requests = 0
    last_consumed_challenge = ""
    startup_proof_response_delay = 0.0
    startup_proof_header_mode = "valid"
    delayed_error_log_responses = 0
    error_log_response_delay = 0.0
    replace_marker_on_error_inventory = False
    replacement_marker_name = ""
    replacement_marker_inode = None
    replacement_marker_payload = b""

    def log_message(self, _format, *_args):
        pass

    def send_json(self, status, payload, extra_headers=None):
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("X-CPA-VERSION", self.runtime_version)
        self.send_header("X-CPA-COMMIT", self.runtime_commit)
        self.send_header("Content-Type", "application/json")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self):
        if self.headers.get("X-Management-Key") == management_key:
            return True
        self.send_json(401, {"error": "unauthorized"})
        return False

    def do_GET(self):
        if not self.authorized():
            return
        ManagementHandler.request_paths.append(self.path)
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == config_path and not parsed.query:
            payload = {
                "commercial-mode": True,
                "request-log": False,
                "logging-to-file": False,
            }
            if self.config_contract == "wrong":
                payload["request-log"] = True
            elif self.config_contract == "missing":
                del payload["commercial-mode"]
            elif self.config_contract == "string":
                payload["logging-to-file"] = "false"
            self.send_json(200, payload)
            return
        if parsed.path == error_logs_path and not parsed.query:
            if self.delayed_error_log_responses > 0:
                ManagementHandler.delayed_error_log_responses -= 1
                time.sleep(self.error_log_response_delay)
            if self.replace_marker_on_error_inventory:
                ManagementHandler.replace_marker_on_error_inventory = False
                marker_entries = [
                    entry for entry in os.scandir(self.log_dir)
                    if entry.name.startswith("error-cag-watchdog-root-") and entry.name.endswith(".log")
                ]
                if len(marker_entries) != 1:
                    self.send_json(500, {"error": "marker replacement fixture could not find marker"})
                    return
                marker = marker_entries[0]
                marker_size = marker.stat(follow_symlinks=False).st_size
                replacement_path = os.path.join(self.log_dir, ".replacement-marker")
                replacement_payload = b"R" * marker_size
                with open(replacement_path, "wb") as stream:
                    stream.write(replacement_payload)
                os.chmod(replacement_path, 0o600)
                os.replace(replacement_path, marker.path)
                replacement_info = os.stat(marker.path, follow_symlinks=False)
                ManagementHandler.replacement_marker_name = marker.name
                ManagementHandler.replacement_marker_inode = (replacement_info.st_dev, replacement_info.st_ino)
                ManagementHandler.replacement_marker_payload = replacement_payload
            if self.error_logs_contract == "files_string":
                self.send_json(200, {"files": "not-an-array"})
                return
            if self.error_logs_contract == "bad_field_type":
                self.send_json(200, {"files": [{
                    "name": "error-invalid.log",
                    "size": "1",
                    "modified": 1,
                }]})
                return
            files = []
            try:
                entries = tuple(os.scandir(self.log_dir))
            except FileNotFoundError:
                entries = ()
            for entry in entries:
                if not entry.name.startswith("error-") or not entry.name.endswith(".log"):
                    continue
                info = entry.stat(follow_symlinks=False)
                files.append({
                    "name": entry.name,
                    "size": info.st_size,
                    "modified": int(info.st_mtime),
                })
            if self.error_logs_contract == "hide_files":
                files = []
            self.send_json(200, {"files": files})
            return
        if parsed.path == startup_proof_path:
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            values = query.get("challenge", [])
            if set(query) != {"challenge"} or len(values) != 1:
                self.send_json(400, {"error": {"code": "invalid_query"}})
                return
            challenge = values[0]
            consumed = ManagementHandler.startup_challenges.pop(challenge, None)
            if consumed is None:
                self.send_json(404, {"error": {"code": "challenge_not_found"}})
                return
            if not consumed:
                self.send_json(409, {"error": {"code": "challenge_not_consumed"}})
                return
            self.send_json(200, {
                "challenge": challenge,
                "instance_id": self.startup_privacy_instance_id,
                "consumed": True,
            })
            return
        if parsed.path != base_path + "/status" or parsed.query:
            self.send_json(404, {"error": "not found"})
            return
        ManagementHandler.status_requests += 1
        final_status = ManagementHandler.status_requests == 2
        if final_status and ManagementHandler.increment_unknown_on_final:
            ManagementHandler.unknown_source_formats += 1
        mode = "balanced"
        if final_status and ManagementHandler.final_status_mode:
            mode = ManagementHandler.final_status_mode
        audit_status = {
            "enabled": True,
            "persistence_expected": True,
            "persistence_verified": True,
            "persistence_reason": None,
        }
        if self.audit_contract == "disabled":
            audit_status["enabled"] = False
        elif self.audit_contract == "not_expected":
            audit_status["persistence_expected"] = False
        elif self.audit_contract == "unverified":
            audit_status = {
                "enabled": True,
                "persistence_expected": True,
                "persistence_verified": False,
                "persistence_reason": "container_layer",
            }
        elif self.audit_contract == "malformed":
            audit_status = {"persistence_expected": "yes"}

        payload = {
            "loaded": True,
            "enforcement_ready": True,
            "operational_ready": self.operational_ready,
            "readiness_reasons": [] if self.operational_ready else ["audit_persistence_unverified"],
            "startup_privacy_instance_id": self.startup_privacy_instance_id,
            "mode": mode,
            "priority": 300,
            "ruleset_version": "1.0.7",
            "last_reconfigure_error": "",
            "audit_degraded": self.audit_degraded,
            "persistence_degraded": self.persistence_degraded,
            "hmac_stable": self.hmac_stable,
            "router_errors": self.router_errors,
            "panics_recovered": self.panics_recovered,
            "counters": {
                "unknown_source_formats": self.unknown_source_formats,
            },
        }
        if self.audit_contract != "missing":
            payload["audit"] = audit_status
        self.send_json(200, payload)

    def do_POST(self):
        parsed = urllib.parse.urlsplit(self.path)
        if not self.authorized():
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if parsed.path == startup_proof_path and not parsed.query:
            if body.strip() != b"{}":
                self.send_json(400, {"error": {"code": "invalid_request"}})
                return
            challenge = secrets.token_hex(32)
            ManagementHandler.startup_challenges[challenge] = False
            self.send_json(200, {
                "challenge": challenge,
                "instance_id": self.startup_privacy_instance_id,
                "expires_at_unix": 4102444800,
            })
            return
        if parsed.path != base_path + "/health/probe" or parsed.query:
            self.send_json(404, {"error": "not found"})
            return
        try:
            kind = json.loads(body)["kind"]
        except (ValueError, KeyError, TypeError):
            self.send_json(400, {"error": "invalid probe"})
            return
        if kind == "benign":
            self.send_json(200, {
                "kind": "benign",
                "instance_id": self.startup_privacy_instance_id,
                "action": "allow",
                "runtime_mode": self.probe_runtime_mode,
                "ruleset_version": self.probe_ruleset_version,
                "local_only": True,
                "upstream_attempted": False,
            })
            return
        if kind == "malicious":
            self.send_json(403, {
                "kind": "malicious",
                "instance_id": self.startup_privacy_instance_id,
                "action": "block",
                "runtime_mode": self.probe_runtime_mode,
                "ruleset_version": self.probe_ruleset_version,
                "local_only": True,
                "self_route": True,
                "target_kind": "self",
                "upstream_attempted": False,
            })
            return
        self.send_json(400, {"error": "unknown probe"})

    def do_get(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path != startup_proof_resource_path or parsed.query:
            self.send_json(404, {"error": {"code": "not_found"}})
            return
        connection_tokens = {
            token.strip().lower()
            for value in self.headers.get_all("Connection", [])
            for token in value.split(",")
        }
        challenge_values = self.headers.get_all(startup_proof_header, [])
        if (
            startup_proof_header.lower() not in connection_tokens
            or len(challenge_values) != 1
            or not ManagementHandler.startup_challenges.get(challenge_values[0]) is False
        ):
            self.send_json(404, {"error": {"code": "not_found"}})
            return
        challenge = challenge_values[0]
        length = int(self.headers.get("Content-Length", "0"))
        body = b""
        if self.startup_request_logging_installed or self.emit_request_log_artifact:
            body = self.rfile.read(length)
        ManagementHandler.startup_challenges[challenge] = True
        ManagementHandler.startup_proof_requests += 1
        ManagementHandler.last_consumed_challenge = challenge
        if self.swap_log_dir_on_probe:
            os.replace(self.log_dir, self.swapped_log_dir)
            os.mkdir(self.log_dir, 0o700)
        if self.startup_request_logging_installed or self.emit_request_log_artifact:
            with open(os.path.join(self.log_dir, "error-stranded-startup-middleware.log"), "wb") as stream:
                stream.write((startup_proof_header + ": " + challenge + "\n").encode("ascii"))
                stream.write(body)
        if self.startup_proof_response_delay > 0:
            time.sleep(self.startup_proof_response_delay)
        proof_headers = {}
        if self.startup_proof_header_mode == "valid":
            proof_headers[startup_proof_header] = challenge
        self.send_json(418, {
            "challenge": challenge,
            "instance_id": self.startup_privacy_instance_id,
            "consumed": True,
            "local_only": True,
            "upstream_attempted": False,
        }, proof_headers)


class ProxyCaptureHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global proxy_connections
        self.request.settimeout(1)
        captured = bytearray()
        try:
            while len(captured) < 65536:
                chunk = self.request.recv(4096)
                if not chunk:
                    break
                captured.extend(chunk)
                if b"\r\n\r\n" in captured:
                    break
        except OSError:
            pass
        with proxy_lock:
            proxy_connections += 1
            proxy_bytes.extend(captured)
        try:
            self.request.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass


class SplitFrontProxyHandler(http.server.BaseHTTPRequestHandler):
    backend_address = None
    startup_proof_backend_address = None
    health_probe_backend_address = None
    intercepted_proofs = 0

    def log_message(self, _format, *_args):
        pass

    def forward(self):
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length else None
        if parsed.path == startup_proof_resource_path:
            SplitFrontProxyHandler.intercepted_proofs += 1
            challenge = self.headers.get(startup_proof_header, "")
            raw = json.dumps({
                "challenge": challenge,
                "instance_id": ManagementHandler.startup_privacy_instance_id,
                "consumed": True,
                "local_only": True,
                "upstream_attempted": False,
            }, separators=(",", ":")).encode("utf-8")
            self.send_response(418)
            self.send_header(startup_proof_header, challenge)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
            return
        headers = {
            name: value for name, value in self.headers.items()
            if name.lower() not in ("host", "connection", "content-length")
        }
        if body is not None:
            headers["Content-Length"] = str(len(body))
        backend_address = self.backend_address
        if parsed.path == startup_proof_path and self.startup_proof_backend_address is not None:
            backend_address = self.startup_proof_backend_address
        if parsed.path == base_path + "/health/probe" and self.health_probe_backend_address is not None:
            backend_address = self.health_probe_backend_address
        connection = http.client.HTTPConnection(*backend_address, timeout=10)
        try:
            connection.request(self.command, self.path, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
            self.send_response(response.status)
            for name, value in response.getheaders():
                if name.lower() not in ("connection", "content-length", "transfer-encoding"):
                    self.send_header(name, value)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)
        finally:
            connection.close()

    do_GET = forward
    do_get = forward
    do_POST = forward


class IsolatedDirectHandler(http.server.BaseHTTPRequestHandler):
    startup_privacy_instance_id = "b" * 64
    runtime_version = "7.2.137"
    runtime_commit = "85d2fadd"
    log_dir = ""
    startup_challenges = {}
    startup_proof_requests = 0

    def log_message(self, _format, *_args):
        pass

    def send_json(self, status, payload, extra_headers=None):
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("X-CPA-VERSION", self.runtime_version)
        self.send_header("X-CPA-COMMIT", self.runtime_commit)
        self.send_header("Content-Type", "application/json")
        if extra_headers:
            for name, value in extra_headers.items():
                self.send_header(name, value)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def authorized(self):
        if self.headers.get("X-Management-Key") == management_key:
            return True
        self.send_json(401, {"error": "unauthorized"})
        return False

    def do_GET(self):
        if not self.authorized():
            return
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == config_path and not parsed.query:
            self.send_json(200, {
                "commercial-mode": True,
                "request-log": False,
                "logging-to-file": False,
            })
            return
        if parsed.path == error_logs_path and not parsed.query:
            files = []
            for entry in os.scandir(self.log_dir):
                if not entry.name.startswith("error-") or not entry.name.endswith(".log"):
                    continue
                info = entry.stat(follow_symlinks=False)
                files.append({
                    "name": entry.name,
                    "size": info.st_size,
                    "modified": int(info.st_mtime),
                })
            self.send_json(200, {"files": files})
            return
        if parsed.path == startup_proof_path:
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            values = query.get("challenge", [])
            if set(query) != {"challenge"} or len(values) != 1:
                self.send_json(400, {"error": {"code": "invalid_query"}})
                return
            challenge = values[0]
            consumed = self.startup_challenges.pop(challenge, None)
            if consumed is None:
                self.send_json(404, {"error": {"code": "challenge_not_found"}})
            elif not consumed:
                self.send_json(409, {"error": {"code": "challenge_not_consumed"}})
            else:
                self.send_json(200, {
                    "challenge": challenge,
                    "instance_id": self.startup_privacy_instance_id,
                    "consumed": True,
                })
            return
        self.send_json(404, {"error": "not found"})

    def do_POST(self):
        if not self.authorized():
            return
        parsed = urllib.parse.urlsplit(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if parsed.path == base_path + "/health/probe" and not parsed.query:
            try:
                kind = json.loads(body)["kind"]
            except (ValueError, KeyError, TypeError):
                self.send_json(400, {"error": "invalid probe"})
                return
            if kind == "benign":
                self.send_json(200, {
                    "kind": "benign",
                    "instance_id": self.startup_privacy_instance_id,
                    "action": "allow",
                    "runtime_mode": "balanced",
                    "ruleset_version": "1.0.7",
                    "local_only": True,
                    "upstream_attempted": False,
                })
                return
            if kind == "malicious":
                self.send_json(403, {
                    "kind": "malicious",
                    "instance_id": self.startup_privacy_instance_id,
                    "action": "block",
                    "runtime_mode": "balanced",
                    "ruleset_version": "1.0.7",
                    "local_only": True,
                    "self_route": True,
                    "target_kind": "self",
                    "upstream_attempted": False,
                })
                return
            self.send_json(400, {"error": "invalid probe"})
            return
        if parsed.path != startup_proof_path or parsed.query or body.strip() != b"{}":
            self.send_json(404, {"error": "not found"})
            return
        challenge = secrets.token_hex(32)
        self.startup_challenges[challenge] = False
        self.send_json(200, {
            "challenge": challenge,
            "instance_id": self.startup_privacy_instance_id,
            "expires_at_unix": 4102444800,
        })

    def do_get(self):
        parsed = urllib.parse.urlsplit(self.path)
        challenge_values = self.headers.get_all(startup_proof_header, [])
        connection_tokens = {
            token.strip().lower()
            for value in self.headers.get_all("Connection", [])
            for token in value.split(",")
        }
        if (
            parsed.path != startup_proof_resource_path
            or parsed.query
            or startup_proof_header.lower() not in connection_tokens
            or len(challenge_values) != 1
            or self.startup_challenges.get(challenge_values[0]) is not False
        ):
            self.send_json(404, {"error": {"code": "not_found"}})
            return
        challenge = challenge_values[0]
        self.startup_challenges[challenge] = True
        type(self).startup_proof_requests += 1
        self.send_json(418, {
            "challenge": challenge,
            "instance_id": self.startup_privacy_instance_id,
            "consumed": True,
            "local_only": True,
            "upstream_attempted": False,
        }, {startup_proof_header: challenge})


log_parent = tempfile.TemporaryDirectory(prefix="cag-watchdog-log-contract-")
fault_shim_parent = tempfile.TemporaryDirectory(prefix="cag-watchdog-python-shim-")
log_dir = os.path.join(log_parent.name, "runtime-logs")
swapped_log_dir = os.path.join(log_parent.name, "runtime-logs-before-swap")
isolated_direct_log_dir = os.path.join(log_parent.name, "isolated-direct-runtime-logs")
os.mkdir(log_dir, 0o700)
os.mkdir(isolated_direct_log_dir, 0o700)
ManagementHandler.log_dir = log_dir
ManagementHandler.swapped_log_dir = swapped_log_dir
IsolatedDirectHandler.log_dir = isolated_direct_log_dir

fault_python = os.path.join(fault_shim_parent.name, "python3")
with open(fault_python, "w", encoding="utf-8", newline="\n") as stream:
    stream.write("#!%s\n" % sys.executable)
    stream.write(r'''
import os
import sys

source = sys.stdin.read()
if len(sys.argv) < 2 or sys.argv[1] != "-":
    raise SystemExit("python fault shim requires stdin source mode")
sys.argv = ["-"] + sys.argv[2:]
fault = os.environ.get("CAG_WATCHDOG_TEST_FAULT", "")
real_write = os.write
real_fsync = os.fsync
state = {"marker_writes": 0, "fsync_failed": False}


def marker_write(fd, data):
    raw = bytes(data)
    if fault in ("short", "short-zero") and (
        state["marker_writes"] > 0 or raw.startswith(b"cyber-abuse-guard watchdog log-root binding ")
    ):
        state["marker_writes"] += 1
        if fault == "short-zero" and state["marker_writes"] > 1:
            return 0
        if len(raw) > 1:
            real_write(fd, raw[:1])
            return 1
    return real_write(fd, data)


def marker_fsync(fd):
    if fault == "fsync" and not state["fsync_failed"]:
        state["fsync_failed"] = True
        raise OSError(5, "injected marker fsync failure")
    return real_fsync(fd)


os.write = marker_write
os.fsync = marker_fsync
namespace = {"__name__": "__main__", "__file__": "<cag-watchdog-proof>"}
exec(compile(source, "<cag-watchdog-proof>", "exec"), namespace, namespace)
''')
os.chmod(fault_python, 0o700)

management = ThreadingServer(("127.0.0.1", 0), ManagementHandler)
isolated_direct = ThreadingServer(("127.0.0.1", 0), IsolatedDirectHandler)
SplitFrontProxyHandler.backend_address = management.server_address
split_front = ThreadingServer(("127.0.0.1", 0), SplitFrontProxyHandler)
proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), ProxyCaptureHandler)
proxy.daemon_threads = True
management_thread = threading.Thread(target=management.serve_forever, daemon=True)
isolated_direct_thread = threading.Thread(target=isolated_direct.serve_forever, daemon=True)
split_front_thread = threading.Thread(target=split_front.serve_forever, daemon=True)
proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
management_thread.start()
isolated_direct_thread.start()
split_front_thread.start()
proxy_thread.start()

try:
    proxy_url = "http://127.0.0.1:%d" % proxy.server_address[1]
    env = os.environ.copy()
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env[name] = proxy_url
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""
    env["CPA_BASE_URL"] = "http://127.0.0.1:%d" % management.server_address[1]
    env["CPA_DIRECT_BASE_URL"] = env["CPA_BASE_URL"]
    env["CPA_MANAGEMENT_KEY"] = management_key
    env["CPA_LOG_DIR"] = log_dir
    env["ALLOW_UNVERIFIED_BUILD"] = "1"
    def run_watchdog(extra=None):
        ManagementHandler.status_requests = 0
        ManagementHandler.request_paths = []
        ManagementHandler.startup_challenges = {}
        ManagementHandler.startup_proof_requests = 0
        ManagementHandler.last_consumed_challenge = ""
        IsolatedDirectHandler.startup_challenges = {}
        IsolatedDirectHandler.startup_proof_requests = 0
        current_env = env.copy()
        if extra:
            current_env.update(extra)
        return subprocess.run(
            ["bash", watchdog],
            env=current_env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=20,
            check=False,
        )

    completed = run_watchdog()
    initial_request_paths = tuple(ManagementHandler.request_paths)
    initial_startup_proof_requests = ManagementHandler.startup_proof_requests

    ManagementHandler.startup_proof_response_delay = 1.2
    slow_safe_proof = run_watchdog({
        "CONNECT_TIMEOUT_SECONDS": "1",
        "REQUEST_TIMEOUT_SECONDS": "3",
    })
    ManagementHandler.startup_proof_response_delay = 0.0

    ManagementHandler.startup_proof_header_mode = "missing"
    missing_startup_proof_header = run_watchdog()
    ManagementHandler.startup_proof_header_mode = "valid"

    ManagementHandler.delayed_error_log_responses = 1
    ManagementHandler.error_log_response_delay = 4.0
    slow_management = run_watchdog({
        "CONNECT_TIMEOUT_SECONDS": "3",
        "REQUEST_TIMEOUT_SECONDS": "10",
    })
    delayed_error_log_responses_remaining = ManagementHandler.delayed_error_log_responses
    ManagementHandler.error_log_response_delay = 0.0

    fault_env = {
        "PATH": fault_shim_parent.name + os.pathsep + env.get("PATH", ""),
    }
    short_write = run_watchdog({**fault_env, "CAG_WATCHDOG_TEST_FAULT": "short"})
    short_write_dir_empty = not os.listdir(log_dir)
    short_zero = run_watchdog({**fault_env, "CAG_WATCHDOG_TEST_FAULT": "short-zero"})
    short_zero_dir_empty = not os.listdir(log_dir)
    fsync_failure = run_watchdog({**fault_env, "CAG_WATCHDOG_TEST_FAULT": "fsync"})
    fsync_failure_dir_empty = not os.listdir(log_dir)

    ManagementHandler.replace_marker_on_error_inventory = True
    replaced_marker_result = run_watchdog()
    replacement_marker_name = ManagementHandler.replacement_marker_name
    replacement_marker_path = os.path.join(log_dir, replacement_marker_name)
    replacement_marker_preserved = False
    if replacement_marker_name and os.path.isfile(replacement_marker_path):
        replacement_info = os.stat(replacement_marker_path, follow_symlinks=False)
        with open(replacement_marker_path, "rb") as stream:
            replacement_marker_preserved = (
                (replacement_info.st_dev, replacement_info.st_ino) == ManagementHandler.replacement_marker_inode
                and stream.read() == ManagementHandler.replacement_marker_payload
            )
        os.unlink(replacement_marker_path)

    backend_url = env["CPA_BASE_URL"]
    split_front_url = "http://127.0.0.1:%d" % split_front.server_address[1]
    SplitFrontProxyHandler.intercepted_proofs = 0
    ManagementHandler.startup_request_logging_installed = True
    split_proxy_false_green_attempt = run_watchdog({
        "CPA_BASE_URL": split_front_url,
        "CPA_DIRECT_BASE_URL": split_front_url,
    })
    split_proxy_intercepted_proofs = SplitFrontProxyHandler.intercepted_proofs
    split_proxy_backend_proofs = ManagementHandler.startup_proof_requests
    split_proxy_artifacts = tuple(os.listdir(log_dir))

    split_proxy_direct_backend = run_watchdog({
        "CPA_BASE_URL": split_front_url,
        "CPA_DIRECT_BASE_URL": backend_url,
    })
    ManagementHandler.startup_request_logging_installed = False
    split_direct_backend_artifact = os.path.join(log_dir, "error-stranded-startup-middleware.log")
    if os.path.isfile(split_direct_backend_artifact):
        os.unlink(split_direct_backend_artifact)

    isolated_direct_url = "http://127.0.0.1:%d" % isolated_direct.server_address[1]
    split_instance_false_green = run_watchdog({
        "CPA_BASE_URL": backend_url,
        "CPA_DIRECT_BASE_URL": isolated_direct_url,
        "CPA_LOG_DIR": isolated_direct_log_dir,
    })
    split_instance_direct_proofs = IsolatedDirectHandler.startup_proof_requests
    split_instance_artifacts = tuple(os.listdir(isolated_direct_log_dir))

    # A loopback BASE proxy can otherwise route status/probes to A while
    # routing only the startup-proof management path to B. The process identity
    # published by A's status must therefore match B's challenge response
    # before any ResourceRoute proof is accepted.
    SplitFrontProxyHandler.startup_proof_backend_address = isolated_direct.server_address
    try:
        path_split_false_green = run_watchdog({
            "CPA_BASE_URL": split_front_url,
            "CPA_DIRECT_BASE_URL": isolated_direct_url,
            "CPA_LOG_DIR": isolated_direct_log_dir,
        })
    finally:
        SplitFrontProxyHandler.startup_proof_backend_address = None
    path_split_direct_proofs = IsolatedDirectHandler.startup_proof_requests
    path_split_artifacts = tuple(os.listdir(isolated_direct_log_dir))

    SplitFrontProxyHandler.health_probe_backend_address = isolated_direct.server_address
    try:
        probe_split_false_green = run_watchdog({
            "CPA_BASE_URL": split_front_url,
            "CPA_DIRECT_BASE_URL": backend_url,
        })
    finally:
        SplitFrontProxyHandler.health_probe_backend_address = None
    probe_split_backend_proofs = ManagementHandler.startup_proof_requests
    probe_split_artifacts = tuple(os.listdir(log_dir))

    ManagementHandler.router_errors = 1
    ManagementHandler.panics_recovered = 1
    ManagementHandler.unknown_source_formats = 3
    default_zero_budget = run_watchdog()
    historical = run_watchdog({
        "MAX_ROUTER_ERRORS": "1",
        "MAX_PANICS_RECOVERED": "1",
    })

    ManagementHandler.router_errors = 8
    ManagementHandler.panics_recovered = 9
    leading_zero_budgets = run_watchdog({
        "MAX_ROUTER_ERRORS": "08",
        "MAX_PANICS_RECOVERED": "09",
        "MAX_NEW_UNKNOWN_SOURCE_FORMATS": "00",
    })

    ManagementHandler.router_errors = 9
    leading_zero_budget_exceeded = run_watchdog({
        "MAX_ROUTER_ERRORS": "08",
        "MAX_PANICS_RECOVERED": "09",
        "MAX_NEW_UNKNOWN_SOURCE_FORMATS": "00",
    })

    ManagementHandler.router_errors = 0
    ManagementHandler.panics_recovered = 0
    ManagementHandler.final_status_mode = "observe"
    final_status_drift = run_watchdog()
    ManagementHandler.final_status_mode = ""

    ManagementHandler.probe_runtime_mode = "audit"
    probe_identity_drift = run_watchdog()
    ManagementHandler.probe_runtime_mode = "balanced"

    ManagementHandler.increment_unknown_on_final = True
    unknown_delta_budget = run_watchdog({"MAX_NEW_UNKNOWN_SOURCE_FORMATS": "0"})
    ManagementHandler.increment_unknown_on_final = False

    ManagementHandler.operational_ready = False
    not_operational = run_watchdog({
        "ALLOW_AUDIT_DEGRADED": "1",
        "ALLOW_PERSISTENCE_DEGRADED": "1",
        "ALLOW_UNSTABLE_HMAC": "1",
    })
    ManagementHandler.operational_ready = True

    ManagementHandler.audit_degraded = True
    legacy_degrade_allow = run_watchdog({"ALLOW_AUDIT_DEGRADED": "1"})
    ManagementHandler.audit_degraded = False

    rejected_audit_contracts = []
    for contract in ("disabled", "not_expected", "unverified"):
        ManagementHandler.audit_contract = contract
        rejected_audit_contracts.append((contract, run_watchdog()))
    ManagementHandler.audit_contract = "missing"
    missing_audit_contract = run_watchdog()
    ManagementHandler.audit_contract = "malformed"
    malformed_audit_contract = run_watchdog()
    ManagementHandler.audit_contract = "valid"

    rejected_logging_contracts = []
    for contract in ("wrong", "missing", "string"):
        ManagementHandler.config_contract = contract
        rejected_logging_contracts.append((contract, run_watchdog()))
    ManagementHandler.config_contract = "valid"

    # A current safe config must not mask middleware installed by an unsafe
    # startup. The non-management fixed-418 proof models CPA v7.2.137's synchronous
    # error-only raw-body artifact.
    ManagementHandler.startup_request_logging_installed = True
    stranded_startup_middleware = run_watchdog()
    stranded_middleware_challenge = ManagementHandler.last_consumed_challenge
    ManagementHandler.startup_request_logging_installed = False
    stranded_artifact = os.path.join(log_dir, "error-stranded-startup-middleware.log")
    stranded_middleware_artifact_contains_canary = False
    if os.path.isfile(stranded_artifact):
        with open(stranded_artifact, "rb") as stream:
            stranded_middleware_artifact_contains_canary = (
                bool(stranded_middleware_challenge)
                and stranded_middleware_challenge.encode("ascii") in stream.read()
            )
        os.unlink(stranded_artifact)

    ManagementHandler.emit_request_log_artifact = True
    stranded_startup_artifact = run_watchdog()
    stranded_artifact_challenge = ManagementHandler.last_consumed_challenge
    ManagementHandler.emit_request_log_artifact = False
    stranded_artifact_contains_canary = False
    if os.path.isfile(stranded_artifact):
        with open(stranded_artifact, "rb") as stream:
            stranded_artifact_contains_canary = (
                bool(stranded_artifact_challenge)
                and stranded_artifact_challenge.encode("ascii") in stream.read()
            )
        os.unlink(stranded_artifact)

    stale_artifact_path = os.path.join(log_dir, "error-stale-request-body.log")
    with open(stale_artifact_path, "wb") as stream:
        stream.write(b"historical raw request")
    stale_artifact = run_watchdog()
    os.unlink(stale_artifact_path)

    rejected_error_log_contracts = []
    for contract in ("files_string", "bad_field_type", "hide_files"):
        ManagementHandler.error_logs_contract = contract
        rejected_error_log_contracts.append((contract, run_watchdog()))
    ManagementHandler.error_logs_contract = "valid"

    ManagementHandler.runtime_version = "7.2.112"
    wrong_cpa_version = run_watchdog()
    ManagementHandler.runtime_version = "7.2.137"
    ManagementHandler.runtime_commit = "85d2fadd"
    official_eight_character_commit = run_watchdog()
    ManagementHandler.runtime_commit = "85d2fa"
    too_short_cpa_commit = run_watchdog()
    ManagementHandler.runtime_commit = "85d2fad0"
    divergent_cpa_commit = run_watchdog()
    ManagementHandler.runtime_commit = "deadbeef"
    wrong_cpa_commit = run_watchdog()
    ManagementHandler.runtime_commit = "85d2fad"
    minimum_seven_character_commit = run_watchdog()

    missing_log_dir = run_watchdog({"CPA_LOG_DIR": ""})
    missing_direct_base = run_watchdog({"CPA_DIRECT_BASE_URL": ""})
    relative_log_dir = run_watchdog({"CPA_LOG_DIR": "relative/runtime-logs"})
    file_log_dir_path = os.path.join(log_parent.name, "not-a-directory")
    with open(file_log_dir_path, "wb") as stream:
        stream.write(b"not a directory")
    file_log_dir = run_watchdog({"CPA_LOG_DIR": file_log_dir_path})

    final_symlink_path = os.path.join(log_parent.name, "runtime-logs-link")
    os.symlink(log_dir, final_symlink_path)
    final_symlink_log_dir = run_watchdog({"CPA_LOG_DIR": final_symlink_path})
    os.unlink(final_symlink_path)

    real_parent = os.path.join(log_parent.name, "real-parent")
    os.mkdir(real_parent, 0o700)
    nested_log_dir = os.path.join(real_parent, "logs")
    os.mkdir(nested_log_dir, 0o700)
    parent_symlink = os.path.join(log_parent.name, "parent-link")
    os.symlink(real_parent, parent_symlink)
    parent_symlink_log_dir = run_watchdog({
        "CPA_LOG_DIR": os.path.join(parent_symlink, "logs"),
    })
    os.unlink(parent_symlink)

    with tempfile.TemporaryDirectory(prefix="cag-watchdog-wrong-root-") as wrong_root:
        wrong_runtime_root = os.path.join(wrong_root, "logs")
        os.mkdir(wrong_runtime_root, 0o700)
        unbound_log_dir = run_watchdog({"CPA_LOG_DIR": wrong_runtime_root})

    ManagementHandler.swap_log_dir_on_probe = True
    try:
        swapped_log_dir_result = run_watchdog()
    finally:
        ManagementHandler.swap_log_dir_on_probe = False
        if os.path.isdir(swapped_log_dir):
            if os.path.isdir(log_dir):
                os.rmdir(log_dir)
            os.replace(swapped_log_dir, log_dir)

    ManagementHandler.router_errors = 1
    ManagementHandler.panics_recovered = 1
    strict_budget = run_watchdog({"MAX_ROUTER_ERRORS": "0", "MAX_PANICS_RECOVERED": "0"})
finally:
    management.shutdown()
    isolated_direct.shutdown()
    split_front.shutdown()
    proxy.shutdown()
    management.server_close()
    isolated_direct.server_close()
    split_front.server_close()
    proxy.server_close()
    log_parent.cleanup()
    fault_shim_parent.cleanup()

if completed.returncode != 0:
    sys.stderr.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    raise SystemExit("watchdog failed its direct management request")
if not initial_request_paths or initial_request_paths[0] != config_path:
    raise SystemExit("CPA logging controls were not checked before plugin health routes")
if initial_startup_proof_requests != 2:
    raise SystemExit("watchdog did not complete both plugin-bound non-management startup privacy proofs")
if slow_safe_proof.returncode != 0:
    sys.stderr.write(slow_safe_proof.stdout)
    sys.stderr.write(slow_safe_proof.stderr)
    raise SystemExit("safe startup privacy proof did not use the configured response budget")
if (
    missing_startup_proof_header.returncode == 0
    or "startup_privacy_proof_response_mismatch" not in missing_startup_proof_header.stderr
    or "missing_runtime_identity" in missing_startup_proof_header.stderr
):
    sys.stderr.write(missing_startup_proof_header.stdout)
    sys.stderr.write(missing_startup_proof_header.stderr)
    raise SystemExit("missing startup proof header did not report the proof-specific failure")
if slow_management.returncode != 0 or delayed_error_log_responses_remaining != 0:
    sys.stderr.write(slow_management.stdout)
    sys.stderr.write(slow_management.stderr)
    raise SystemExit("slow management response did not retain the independent request timeout budget")
if short_write.returncode != 0 or not short_write_dir_empty:
    sys.stderr.write(short_write.stdout)
    sys.stderr.write(short_write.stderr)
    raise SystemExit("write-all marker handling rejected a recoverable short write or left a marker")
if short_zero.returncode == 0 or "marker_write_failed" not in short_zero.stderr or not short_zero_dir_empty:
    sys.stderr.write(short_zero.stdout)
    sys.stderr.write(short_zero.stderr)
    raise SystemExit("zero-progress marker write did not fail with exact cleanup")
if fsync_failure.returncode == 0 or "marker_fsync_failed" not in fsync_failure.stderr or not fsync_failure_dir_empty:
    sys.stderr.write(fsync_failure.stdout)
    sys.stderr.write(fsync_failure.stderr)
    raise SystemExit("marker fsync failure did not preserve exact cleanup")
if replaced_marker_result.returncode == 0 or "marker_changed_during_proof" not in replaced_marker_result.stderr:
    sys.stderr.write(replaced_marker_result.stdout)
    sys.stderr.write(replaced_marker_result.stderr)
    raise SystemExit("same-name same-size marker inode replacement was not rejected")
if not replacement_marker_preserved:
    raise SystemExit("watchdog deleted or modified a replacement inode it did not create")
if (
    split_proxy_false_green_attempt.returncode == 0
    or "startup_privacy_proof_not_confirmed_by_plugin" not in split_proxy_false_green_attempt.stderr
    or split_proxy_intercepted_proofs != 1
    or split_proxy_backend_proofs != 0
    or split_proxy_artifacts
):
    sys.stderr.write(split_proxy_false_green_attempt.stdout)
    sys.stderr.write(split_proxy_false_green_attempt.stderr)
    raise SystemExit("front proxy could fake the non-management proof without same-process challenge consumption")
if (
    split_proxy_direct_backend.returncode == 0
    or "startup_request_logging_artifact_detected" not in split_proxy_direct_backend.stderr
):
    sys.stderr.write(split_proxy_direct_backend.stdout)
    sys.stderr.write(split_proxy_direct_backend.stderr)
    raise SystemExit("explicit direct CPA listener did not expose the stranded startup request logger")
if (
    split_instance_false_green.returncode == 0
    or "startup_privacy_proof_not_terminated_locally" not in split_instance_false_green.stderr
    or split_instance_direct_proofs != 0
    or split_instance_artifacts
):
    sys.stderr.write(split_instance_false_green.stdout)
    sys.stderr.write(split_instance_false_green.stderr)
    raise SystemExit("watchdog combined production status with a different direct CPA process")
if (
    path_split_false_green.returncode == 0
    or "startup_privacy_instance_mismatch" not in path_split_false_green.stderr
    or path_split_direct_proofs != 0
    or path_split_artifacts
):
    sys.stderr.write(path_split_false_green.stdout)
    sys.stderr.write(path_split_false_green.stderr)
    raise SystemExit("BASE path routing combined production status with another plugin instance's proof")
if (
    probe_split_false_green.returncode == 0
    or "built-in benign local probe came from a different plugin process" not in probe_split_false_green.stderr
    or probe_split_backend_proofs != 0
    or probe_split_artifacts
):
    sys.stderr.write(probe_split_false_green.stdout)
    sys.stderr.write(probe_split_false_green.stderr)
    raise SystemExit("BASE path routing combined one plugin's status with another plugin's health probes")
with open(watchdog, "r", encoding="utf-8") as stream:
    if "startup_request_logging_middleware_detected" in stream.read():
        raise SystemExit("watchdog still over-attributes an ambiguous timeout to request-logging middleware")
if default_zero_budget.returncode == 0:
    raise SystemExit("default zero router/panic budget was not enforced")
if historical.returncode != 0:
    sys.stderr.write(historical.stdout)
    sys.stderr.write(historical.stderr)
    raise SystemExit("historical cumulative counters permanently failed the watchdog")
if leading_zero_budgets.returncode != 0:
    sys.stderr.write(leading_zero_budgets.stdout)
    sys.stderr.write(leading_zero_budgets.stderr)
    raise SystemExit("leading-zero decimal watchdog budgets were rejected")
if leading_zero_budget_exceeded.returncode == 0:
    raise SystemExit("leading-zero decimal watchdog budget was not enforced")
if final_status_drift.returncode == 0:
    raise SystemExit("post-probe mode drift was not rejected")
if probe_identity_drift.returncode == 0:
    raise SystemExit("probe runtime identity drift was not rejected")
if unknown_delta_budget.returncode == 0:
    raise SystemExit("probe-window unknown source delta budget was not enforced")
if not_operational.returncode == 0:
    raise SystemExit("operational readiness failure was not rejected")
if legacy_degrade_allow.returncode == 0:
    raise SystemExit("legacy ALLOW_AUDIT_DEGRADED bypassed the production gate")
for name, result in tuple(rejected_audit_contracts) + (
    ("missing", missing_audit_contract),
    ("malformed", malformed_audit_contract),
):
    if result.returncode == 0:
        raise SystemExit("%s audit persistence contract was not rejected" % name)
    if "status requires enabled audit with verified persistent storage" not in result.stderr:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("%s audit contract did not reach the audit-specific failure" % name)
for name, result in rejected_logging_contracts:
    if result.returncode == 0:
        raise SystemExit("%s CPA logging contract was not rejected" % name)
    if "CPA request/file logging controls must be strict booleans" not in result.stderr:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("%s CPA logging contract did not reach the config-specific failure" % name)
if stranded_startup_middleware.returncode == 0:
    raise SystemExit("safe current booleans masked request middleware installed at startup")
if "startup_request_logging_artifact_detected" not in stranded_startup_middleware.stderr:
    sys.stderr.write(stranded_startup_middleware.stdout)
    sys.stderr.write(stranded_startup_middleware.stderr)
    raise SystemExit("stranded startup middleware did not reach the plugin-bound artifact failure")
if not stranded_middleware_artifact_contains_canary:
    raise SystemExit("stranded startup middleware did not persist the local proof canary")
if stranded_startup_artifact.returncode == 0:
    raise SystemExit("safe current booleans masked a startup request-log artifact")
if "startup_request_logging_artifact_detected" not in stranded_startup_artifact.stderr:
    sys.stderr.write(stranded_startup_artifact.stdout)
    sys.stderr.write(stranded_startup_artifact.stderr)
    raise SystemExit("stranded startup artifact did not reach the artifact-specific failure")
if not stranded_artifact_contains_canary:
    raise SystemExit("stranded startup middleware fixture did not persist the raw canary")
if stale_artifact.returncode == 0 or "log_dir_not_empty_before_proof" not in stale_artifact.stderr:
    sys.stderr.write(stale_artifact.stdout)
    sys.stderr.write(stale_artifact.stderr)
    raise SystemExit("pre-existing request log artifact was not rejected")
for name, result in rejected_error_log_contracts:
    if result.returncode == 0:
        raise SystemExit("%s error-log inventory contract was not rejected" % name)
    if "CPA startup request-logging proof failed" not in result.stderr:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("%s error-log inventory did not reach startup proof" % name)
if official_eight_character_commit.returncode != 0:
    sys.stderr.write(official_eight_character_commit.stdout)
    sys.stderr.write(official_eight_character_commit.stderr)
    raise SystemExit("official eight-character CPA commit abbreviation was rejected")
if minimum_seven_character_commit.returncode != 0:
    sys.stderr.write(minimum_seven_character_commit.stdout)
    sys.stderr.write(minimum_seven_character_commit.stderr)
    raise SystemExit("minimum seven-character CPA commit abbreviation was rejected")
for name, result, failure in (
    ("version", wrong_cpa_version, "unexpected_cpa_version"),
    ("too-short commit", too_short_cpa_commit, "unexpected_cpa_commit"),
    ("divergent commit", divergent_cpa_commit, "unexpected_cpa_commit"),
    ("commit", wrong_cpa_commit, "unexpected_cpa_commit"),
):
    if result.returncode == 0 or failure not in result.stderr:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("wrong CPA %s identity was not rejected" % name)
for name, result in (
    ("missing", missing_log_dir),
    ("missing direct base", missing_direct_base),
    ("relative", relative_log_dir),
    ("file", file_log_dir),
    ("final symlink", final_symlink_log_dir),
    ("parent symlink", parent_symlink_log_dir),
    ("unbound", unbound_log_dir),
    ("TOCTOU swap", swapped_log_dir_result),
):
    if result.returncode == 0:
        raise SystemExit("%s CPA log directory was not rejected" % name)
    if name == "missing":
        expected_failure = "set CPA_LOG_DIR"
    elif name == "missing direct base":
        expected_failure = "set CPA_DIRECT_BASE_URL"
    else:
        expected_failure = "CPA startup request-logging proof failed"
    if expected_failure not in result.stderr:
        sys.stderr.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit("%s CPA log directory did not reach its specific failure" % name)
if strict_budget.returncode == 0:
    raise SystemExit("explicit zero cumulative error budget was not enforced")
if proxy_connections != 0:
    raise SystemExit("hostile proxy received %d connection(s)" % proxy_connections)
if management_key.encode("utf-8") in proxy_bytes:
    raise SystemExit("hostile proxy captured the management key")
for index, result in enumerate((
    completed,
    slow_safe_proof,
    slow_management,
    short_write,
    short_zero,
    fsync_failure,
    replaced_marker_result,
    split_proxy_false_green_attempt,
    split_proxy_direct_backend,
    default_zero_budget,
    historical,
    leading_zero_budgets,
    leading_zero_budget_exceeded,
    final_status_drift,
    probe_identity_drift,
    unknown_delta_budget,
    not_operational,
    legacy_degrade_allow,
    *(result for _, result in rejected_audit_contracts),
    missing_audit_contract,
    malformed_audit_contract,
    *(result for _, result in rejected_logging_contracts),
    stranded_startup_middleware,
    stranded_startup_artifact,
    stale_artifact,
    *(result for _, result in rejected_error_log_contracts),
    wrong_cpa_version,
    official_eight_character_commit,
    minimum_seven_character_commit,
    too_short_cpa_commit,
    divergent_cpa_commit,
    wrong_cpa_commit,
    missing_log_dir,
    missing_direct_base,
    relative_log_dir,
    file_log_dir,
    final_symlink_log_dir,
    parent_symlink_log_dir,
    unbound_log_dir,
    swapped_log_dir_result,
    strict_budget,
)):
    combined = (result.stdout + result.stderr).encode("utf-8", errors="replace")
    if management_key.encode("utf-8") in combined:
        raise SystemExit("watchdog output retained management-key canary in result %d" % index)

print("check-production-health proxy isolation test: PASS")
PY
