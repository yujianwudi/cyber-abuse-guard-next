#!/usr/bin/env bash
set -euo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"

# Exercise the real watchdog against a local management stub while every
# standard proxy variable points at a hostile capture listener. The watchdog
# must connect directly and must not send even a TCP connection to the proxy.
python3 - "$root/scripts/check-production-health.sh" <<'PY'
import http.server
import json
import os
import socketserver
import subprocess
import sys
import threading

watchdog = sys.argv[1]
management_key = "proxy-negative-test-management-key"
base_path = "/v0/management/plugins/cyber-abuse-guard"
proxy_connections = 0
proxy_bytes = bytearray()
proxy_lock = threading.Lock()


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class ManagementHandler(http.server.BaseHTTPRequestHandler):
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

    def log_message(self, _format, *_args):
        pass

    def send_json(self, status, payload):
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
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
        if self.path != base_path + "/status":
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
        if not self.authorized():
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.path != base_path + "/health/probe":
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


management = ThreadingServer(("127.0.0.1", 0), ManagementHandler)
proxy = socketserver.ThreadingTCPServer(("127.0.0.1", 0), ProxyCaptureHandler)
proxy.daemon_threads = True
management_thread = threading.Thread(target=management.serve_forever, daemon=True)
proxy_thread = threading.Thread(target=proxy.serve_forever, daemon=True)
management_thread.start()
proxy_thread.start()

try:
    proxy_url = "http://127.0.0.1:%d" % proxy.server_address[1]
    env = os.environ.copy()
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env[name] = proxy_url
    env["NO_PROXY"] = ""
    env["no_proxy"] = ""
    env["CPA_BASE_URL"] = "http://127.0.0.1:%d" % management.server_address[1]
    env["CPA_MANAGEMENT_KEY"] = management_key
    env["ALLOW_UNVERIFIED_BUILD"] = "1"
    def run_watchdog(extra=None):
        ManagementHandler.status_requests = 0
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

    ManagementHandler.router_errors = 1
    ManagementHandler.panics_recovered = 1
    strict_budget = run_watchdog({"MAX_ROUTER_ERRORS": "0", "MAX_PANICS_RECOVERED": "0"})
finally:
    management.shutdown()
    proxy.shutdown()
    management.server_close()
    proxy.server_close()

if completed.returncode != 0:
    sys.stderr.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    raise SystemExit("watchdog failed its direct management request")
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
if strict_budget.returncode == 0:
    raise SystemExit("explicit zero cumulative error budget was not enforced")
if proxy_connections != 0:
    raise SystemExit("hostile proxy received %d connection(s)" % proxy_connections)
if management_key.encode("utf-8") in proxy_bytes:
    raise SystemExit("hostile proxy captured the management key")
for index, result in enumerate((
    completed,
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
    strict_budget,
)):
    combined = (result.stdout + result.stderr).encode("utf-8", errors="replace")
    if management_key.encode("utf-8") in combined:
        raise SystemExit("watchdog output retained management-key canary in result %d" % index)

print("check-production-health proxy isolation test: PASS")
PY
