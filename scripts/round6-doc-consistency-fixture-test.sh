#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
fixture="$root/scripts/release-doc-consistency-test.sh"
gate="$root/scripts/release-doc-consistency.sh"
expected_fixture_sha256='fc1378f06d963c8205d9e14748b1c94a4c387f4682b156e1950292044b2e826e'
expected_gate_sha256='949591be91a4813e17794de3bb3c368ac388650917fa850ed3b901f045dc63a6'

for required in sha256sum awk; do
  command -v "$required" >/dev/null 2>&1 || {
    printf '%s is required for the Round16 document fixture wrapper\n' "$required" >&2
    exit 127
  }
done
for path in "$fixture" "$gate"; do
  [[ -f "$path" && ! -L "$path" ]] || {
    printf 'Round16 document fixture dependency must be a regular non-symlink file\n' >&2
    exit 1
  }
done

fixture_sha256="$(sha256sum "$fixture" | awk '{print $1}')"
gate_sha256="$(sha256sum "$gate" | awk '{print $1}')"
[[ "$fixture_sha256" == "$expected_fixture_sha256" ]] || {
  printf 'Round16 document mutation fixture changed outside the reviewed contract\n' >&2
  exit 1
}
[[ "$gate_sha256" == "$expected_gate_sha256" ]] || {
  printf 'Round16 document consistency gate changed outside the reviewed contract\n' >&2
  exit 1
}

exec "$fixture"
