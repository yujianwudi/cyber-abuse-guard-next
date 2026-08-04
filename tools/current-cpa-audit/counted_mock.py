#!/usr/bin/env python3
"""Private counted upstream for the current-CPA isolated audit.

This repository-owned process retains no request body and exposes its control
surface only on the audit's internal Docker network with a run-random token.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Sequence


CONTRACT = "cag-current-cpa-counted-mock/v1"
MAX_BODY = 16 * 1024 * 1024
MODEL = "current-cpa-audit-model"


def compact_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def reject_constant(value: str) -> None:
    raise ValueError(f"non-finite number: {value}")


class Counters:
    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._values = {"auth": 0, "mock": 0, "provider": 0}

    def increment(self, key: str) -> None:
        with self._lock:
            self._values[key] += 1

    def reset(self) -> dict[str, Any]:
        with self._lock:
            self._values = {"auth": 0, "mock": 0, "provider": 0}
            return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            values = dict(self._values)
        return {"schema": CONTRACT, **values}


class AuditServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address: tuple[str, int], control_token: str, upstream_key: str) -> None:
        super().__init__(address, Handler)
        self.control_token = control_token
        self.upstream_key = upstream_key
        self.counters = Counters()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "cag-counted-mock/1"
    sys_version = ""

    @property
    def audit_server(self) -> AuditServer:
        return self.server  # type: ignore[return-value]

    def log_message(self, format: str, *args: Any) -> None:
        del format, args

    def _authorized_control(self) -> bool:
        return self.headers.get("Authorization", "") == "Bearer " + self.audit_server.control_token

    def _send(self, status: int, payload: bytes, content_type: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()

    def _json(self, status: int, value: Any) -> None:
        self._send(status, compact_json(value), "application/json")

    def _read_json(self) -> dict[str, Any] | None:
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            self._json(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, {"error": "invalid_content_type"})
            return None
        raw_length = self.headers.get("Content-Length", "")
        try:
            length = int(raw_length)
        except ValueError:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_content_length"})
            return None
        if length <= 0 or length > MAX_BODY:
            self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "body_limit"})
            return None
        raw = self.rfile.read(length)
        try:
            payload = json.loads(
                raw.decode("utf-8", "strict"),
                object_pairs_hook=reject_duplicate_pairs,
                parse_constant=reject_constant,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_json"})
            return None
        finally:
            # Do not retain request bytes beyond parsing/dispatch.
            raw = b""
        if not isinstance(payload, dict):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_schema"})
            return None
        return payload

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/healthz":
            self._json(
                HTTPStatus.OK,
                {"contract": CONTRACT, "healthy": True, "request_body_retention": False},
            )
            return
        if self.path == "/__cag/stats":
            if not self._authorized_control():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            self._json(HTTPStatus.OK, self.audit_server.counters.snapshot())
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        if self.path == "/__cag/reset":
            if not self._authorized_control():
                self._json(HTTPStatus.UNAUTHORIZED, {"error": "unauthorized"})
                return
            self.audit_server.counters.reset()
            self._json(HTTPStatus.OK, self.audit_server.counters.snapshot())
            return
        if self.path not in ("/v1/chat/completions", "/v1/responses"):
            self._json(HTTPStatus.NOT_FOUND, {"error": "not_found"})
            return
        self.audit_server.counters.increment("mock")
        if self.headers.get("Authorization", "") != "Bearer " + self.audit_server.upstream_key:
            self._json(HTTPStatus.UNAUTHORIZED, {"error": "invalid_upstream_key"})
            return
        self.audit_server.counters.increment("auth")
        payload = self._read_json()
        if payload is None:
            return
        if payload.get("model") != MODEL or type(payload.get("stream")) is not bool:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "invalid_request_contract"})
            return
        self.audit_server.counters.increment("provider")
        if self.path == "/v1/chat/completions":
            self._chat(bool(payload["stream"]))
        else:
            self._responses(bool(payload["stream"]))

    def _chat(self, stream: bool) -> None:
        usage = {"completion_tokens": 3, "prompt_tokens": 5, "total_tokens": 8}
        if not stream:
            self._json(
                HTTPStatus.OK,
                {
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "index": 0,
                            "message": {"content": "synthetic allowed response", "role": "assistant"},
                        }
                    ],
                    "id": "chatcmpl-current-cpa-audit",
                    "model": MODEL,
                    "object": "chat.completion",
                    "usage": usage,
                },
            )
            return
        frames = [
            {
                "choices": [{"delta": {"content": "synthetic allowed response", "role": "assistant"}, "finish_reason": None, "index": 0}],
                "id": "chatcmpl-current-cpa-audit",
                "model": MODEL,
                "object": "chat.completion.chunk",
            },
            {
                "choices": [{"delta": {}, "finish_reason": "stop", "index": 0}],
                "id": "chatcmpl-current-cpa-audit",
                "model": MODEL,
                "object": "chat.completion.chunk",
                "usage": usage,
            },
        ]
        raw = b"".join(b"data: " + compact_json(frame) + b"\n\n" for frame in frames)
        raw += b"data: [DONE]\n\n"
        self._send(HTTPStatus.OK, raw, "text/event-stream")

    @staticmethod
    def _completed_response() -> dict[str, Any]:
        return {
            "id": "resp_current_cpa_audit",
            "model": MODEL,
            "object": "response",
            "output": [
                {
                    "content": [{"text": "synthetic allowed response", "type": "output_text"}],
                    "id": "msg_current_cpa_audit",
                    "role": "assistant",
                    "status": "completed",
                    "type": "message",
                }
            ],
            "status": "completed",
            "usage": {"input_tokens": 5, "output_tokens": 3, "total_tokens": 8},
        }

    def _responses(self, stream: bool) -> None:
        completed = self._completed_response()
        if not stream:
            self._json(HTTPStatus.OK, completed)
            return
        events: list[tuple[str, dict[str, Any]]] = [
            ("response.created", {"response": {"id": completed["id"], "model": MODEL, "object": "response", "status": "in_progress"}}),
            ("response.in_progress", {"response": {"id": completed["id"], "model": MODEL, "object": "response", "status": "in_progress"}}),
            ("response.output_item.added", {"item": {"id": "msg_current_cpa_audit", "role": "assistant", "status": "in_progress", "type": "message"}, "output_index": 0}),
            ("response.content_part.added", {"content_index": 0, "item_id": "msg_current_cpa_audit", "output_index": 0, "part": {"text": "", "type": "output_text"}}),
            ("response.output_text.delta", {"content_index": 0, "delta": "synthetic allowed response", "item_id": "msg_current_cpa_audit", "output_index": 0}),
            ("response.output_text.done", {"content_index": 0, "item_id": "msg_current_cpa_audit", "output_index": 0, "text": "synthetic allowed response"}),
            ("response.content_part.done", {"content_index": 0, "item_id": "msg_current_cpa_audit", "output_index": 0, "part": {"text": "synthetic allowed response", "type": "output_text"}}),
            ("response.output_item.done", {"item": completed["output"][0], "output_index": 0}),
            ("response.completed", {"response": completed}),
        ]
        blocks: list[bytes] = []
        for sequence, (event, payload) in enumerate(events, start=1):
            body = {"sequence_number": sequence, "type": event, **payload}
            blocks.append(b"event: " + event.encode("ascii") + b"\n")
            blocks.append(b"data: " + compact_json(body) + b"\n\n")
        self._send(HTTPStatus.OK, b"".join(blocks), "text/event-stream")


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=18080)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    control = os.environ.get("CAG_MOCK_CONTROL_TOKEN", "")
    upstream = os.environ.get("CAG_MOCK_UPSTREAM_KEY", "")
    if len(control) < 32 or len(upstream) < 32 or control == upstream:
        raise SystemExit("counted-Mock requires two distinct run-random tokens")
    server = AuditServer((args.host, args.port), control, upstream)

    def graceful_stop(signum: int, frame: Any) -> None:
        del signum, frame
        # shutdown() must run outside serve_forever's thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, graceful_stop)
    signal.signal(signal.SIGINT, graceful_stop)
    try:
        server.serve_forever(poll_interval=0.25)
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
