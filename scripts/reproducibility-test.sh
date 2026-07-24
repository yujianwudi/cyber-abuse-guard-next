#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
printf 'reproducibility-test delegates to the Round6 restricted-data-safe implementation\n' >&2
exec "$root/scripts/round6-reproducibility-test.sh" "$@"
