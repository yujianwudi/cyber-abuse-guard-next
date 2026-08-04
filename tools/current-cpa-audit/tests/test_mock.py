from __future__ import annotations

import http.client
import json
import sys
import threading
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL))

from audit_contract import validate_allow_response
from counted_mock import AuditServer, CONTRACT, MODEL


class CountedMockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.control = "control-" + "a" * 40
        self.upstream = "upstream-" + "b" * 40
        self.server = AuditServer(("127.0.0.1", 0), self.control, self.upstream)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.host, self.port = self.server.server_address

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(
        self, method: str, path: str, body: dict | None = None, token: str | None = None
    ) -> tuple[int, bytes, dict[str, str]]:
        connection = http.client.HTTPConnection(self.host, self.port, timeout=3)
        headers: dict[str, str] = {}
        raw = None
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        if body is not None:
            raw = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
            headers["Content-Length"] = str(len(raw))
        connection.request(method, path, body=raw, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        status = response.status
        connection.close()
        return status, payload, response_headers

    def test_health_and_control_are_separate(self) -> None:
        status, raw, _ = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(raw),
            {"contract": CONTRACT, "healthy": True, "request_body_retention": False},
        )
        status, _, _ = self.request("GET", "/__cag/stats")
        self.assertEqual(status, 401)

    def test_allow_increments_auth_mock_and_provider_once(self) -> None:
        body = {"messages": [{"role": "user", "content": "benign"}], "model": MODEL, "stream": False}
        status, raw, headers = self.request(
            "POST", "/v1/chat/completions", body, self.upstream
        )
        self.assertEqual(status, 200)
        self.assertEqual(validate_allow_response("chat", False, raw, headers, MODEL), (True, True))
        status, raw, _ = self.request("GET", "/__cag/stats", token=self.control)
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(raw), {"schema": CONTRACT, "auth": 1, "mock": 1, "provider": 1}
        )

    def test_wrong_upstream_key_stops_before_auth_and_provider(self) -> None:
        body = {"messages": [], "model": MODEL, "stream": False}
        status, _, _ = self.request("POST", "/v1/chat/completions", body, "wrong")
        self.assertEqual(status, 401)
        _, raw, _ = self.request("GET", "/__cag/stats", token=self.control)
        self.assertEqual(
            json.loads(raw), {"schema": CONTRACT, "auth": 0, "mock": 1, "provider": 0}
        )

    def test_stream_contracts_terminate(self) -> None:
        for protocol, path, body in (
            ("chat", "/v1/chat/completions", {"messages": [], "model": MODEL, "stream": True}),
            ("responses", "/v1/responses", {"input": [], "model": MODEL, "stream": True}),
        ):
            self.request("POST", "/__cag/reset", token=self.control)
            status, raw, headers = self.request("POST", path, body, self.upstream)
            self.assertEqual(status, 200)
            self.assertEqual(
                validate_allow_response(protocol, True, raw, headers, MODEL), (True, True)
            )


if __name__ == "__main__":
    unittest.main()
