#!/usr/bin/env bash
set -euo pipefail

for command_name in nginx python3 curl mktemp kill sleep seq tr mkdir rm cat; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'required management proxy fixture command not found: %s\n' "$command_name" >&2
    exit 127
  }
done

work="$(mktemp -d)"
nginx_pid=""
upstream_pid=""
cleanup() {
  if [[ -n "$nginx_pid" ]]; then
    kill "$nginx_pid" 2>/dev/null || true
    wait "$nginx_pid" 2>/dev/null || true
  fi
  if [[ -n "$upstream_pid" ]]; then
    kill "$upstream_pid" 2>/dev/null || true
    wait "$upstream_pid" 2>/dev/null || true
  fi
  rm -rf -- "$work"
}
trap cleanup EXIT

read -r proxy_port upstream_port < <(python3 - <<'PY'
import socket

ports = []
for _ in range(2):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    ports.append(sock.getsockname()[1])
    sock.close()
print(*ports)
PY
)

count_file="$work/upstream-count"
printf '0\n' >"$count_file"
python3 - "$upstream_port" "$count_file" <<'PY' &
import http.server
import pathlib
import sys

port = int(sys.argv[1])
count_path = pathlib.Path(sys.argv[2])


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(length)
        count = int(count_path.read_text(encoding="utf-8").strip()) + 1
        count_path.write_text(str(count) + "\n", encoding="utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")


server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
server.serve_forever()
PY
upstream_pid="$!"

mkdir -p "$work/client-body" "$work/proxy-temp" "$work/fastcgi-temp" \
  "$work/uwsgi-temp" "$work/scgi-temp"
cat >"$work/nginx.conf" <<EOF
pid $work/nginx.pid;
error_log $work/nginx-error.log notice;
events {}
http {
  access_log off;
  client_body_temp_path $work/client-body;
  proxy_temp_path $work/proxy-temp;
  fastcgi_temp_path $work/fastcgi-temp;
  uwsgi_temp_path $work/uwsgi-temp;
  scgi_temp_path $work/scgi-temp;
  server {
    listen 127.0.0.1:$proxy_port;
    client_max_body_size 1k;
    location / {
      proxy_pass http://127.0.0.1:$upstream_port;
      proxy_request_buffering on;
    }
  }
}
EOF

nginx -p "$work" -c "$work/nginx.conf" -g 'daemon off;' &
nginx_pid="$!"

ready=0
for _ in $(seq 1 100); do
  if curl --noproxy '*' -fsS "http://127.0.0.1:$proxy_port/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.1
done
if [[ "$ready" != 1 ]]; then
  printf 'management proxy fixture did not become ready\n' >&2
  exit 1
fi

status="$(python3 - <<'PY' | curl --noproxy '*' -sS -o "$work/oversized-response" -w '%{http_code}' \
  -H 'Content-Type: application/json' --data-binary @- \
  "http://127.0.0.1:$proxy_port/v0/management/plugins/cyber-abuse-guard/config"
import json
print(json.dumps({"payload": "A" * 4096}), end="")
PY
)"
if [[ "$status" != 413 ]]; then
  printf 'oversized Management request status = %s, want 413\n' "$status" >&2
  exit 1
fi
sleep 0.2
if [[ "$(tr -d '[:space:]' <"$count_file")" != 0 ]]; then
  printf 'oversized Management request reached the CPA upstream fixture\n' >&2
  exit 1
fi

small_status="$(curl --noproxy '*' -sS -o "$work/small-response" -w '%{http_code}' \
  -H 'Content-Type: application/json' --data-binary '{"kind":"benign"}' \
  "http://127.0.0.1:$proxy_port/v0/management/plugins/cyber-abuse-guard/health/probe")"
if [[ "$small_status" != 200 || "$(tr -d '[:space:]' <"$count_file")" != 1 ]]; then
  printf 'small Management control request did not traverse the proxy fixture\n' >&2
  exit 1
fi

printf 'management proxy 413 fixture: PASS (oversized request rejected before counted upstream CPA-handler stub)\n'
