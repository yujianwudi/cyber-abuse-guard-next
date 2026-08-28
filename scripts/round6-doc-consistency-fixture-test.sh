#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
fixture="$root/scripts/release-doc-consistency-test.sh"
gate="$root/scripts/release-doc-consistency.sh"
expected_fixture_sha256='90308d0ef0925f2228f5d1a1a3e184b2bdd07ba20e390a8b12b5b68cf01a18b2'
expected_gate_sha256='babf55be9a5960a2c0bcede5ca95d72d27f6df90fbf9d32761d95c4eec34eca2'

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
