#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
fixture="$root/scripts/release-doc-consistency-test.sh"
gate="$root/scripts/release-doc-consistency.sh"
expected_fixture_sha256='83bf5cd80004907f56fc60de713c801b1c7b8829a63224a8af4436e22ae2e4bf'
expected_gate_sha256='e29360ec3100a8809637ef477f603ad0e3eec227dbd1032f820efed91a5a1947'

for required in sha256sum awk; do
  command -v "$required" >/dev/null 2>&1 || {
    printf '%s is required for the Round6 document fixture wrapper\n' "$required" >&2
    exit 127
  }
done
for path in "$fixture" "$gate"; do
  [[ -f "$path" && ! -L "$path" ]] || {
    printf 'Round6 document fixture dependency must be a regular non-symlink file\n' >&2
    exit 1
  }
done

fixture_sha256="$(sha256sum "$fixture" | awk '{print $1}')"
gate_sha256="$(sha256sum "$gate" | awk '{print $1}')"
[[ "$fixture_sha256" == "$expected_fixture_sha256" ]] || {
  printf 'Round6 document mutation fixture changed outside the reviewed contract\n' >&2
  exit 1
}
[[ "$gate_sha256" == "$expected_gate_sha256" ]] || {
  printf 'Round6 document consistency gate changed outside the reviewed contract\n' >&2
  exit 1
}

exec "$fixture"
