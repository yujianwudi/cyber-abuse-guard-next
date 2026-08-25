#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
fixture="$root/scripts/release-doc-consistency-test.sh"
gate="$root/scripts/release-doc-consistency.sh"
expected_fixture_sha256='11e02f5d3ebf3a7bf98a950338f1175624b98f84e9a0cd30e6f5302d3e368e05'
expected_gate_sha256='3b861bcc075cfc67806f1ccb92bc80a544d505d3fc5f88a4dfbe860541692037'

for required in sha256sum awk; do
  command -v "$required" >/dev/null 2>&1 || {
    printf '%s is required for the Round14 document fixture wrapper\n' "$required" >&2
    exit 127
  }
done
for path in "$fixture" "$gate"; do
  [[ -f "$path" && ! -L "$path" ]] || {
    printf 'Round14 document fixture dependency must be a regular non-symlink file\n' >&2
    exit 1
  }
done

fixture_sha256="$(sha256sum "$fixture" | awk '{print $1}')"
gate_sha256="$(sha256sum "$gate" | awk '{print $1}')"
[[ "$fixture_sha256" == "$expected_fixture_sha256" ]] || {
  printf 'Round14 document mutation fixture changed outside the reviewed contract\n' >&2
  exit 1
}
[[ "$gate_sha256" == "$expected_gate_sha256" ]] || {
  printf 'Round14 document consistency gate changed outside the reviewed contract\n' >&2
  exit 1
}

exec "$fixture"
