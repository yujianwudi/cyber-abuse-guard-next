#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
runner="$root/scripts/round8_host_evidence.py"

[[ -f "$runner" && ! -L "$runner" ]] || {
  printf 'Round 8 Host runner is missing or is a symlink\n' >&2
  exit 1
}
command -v python3 >/dev/null 2>&1 || {
  printf 'python3 is required\n' >&2
  exit 1
}

command_name="${1:-}"
if [[ "$command_name" == run ]]; then
  [[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
    printf 'Round 8 Host execution requires Linux amd64\n' >&2
    exit 1
  }
  command -v docker >/dev/null 2>&1 || {
    printf 'docker is required for Round 8 Host execution\n' >&2
    exit 1
  }
  execute_seen=0
  for argument in "$@"; do
    if [[ "$argument" == --execute ]]; then
      execute_seen=1
    fi
  done
  (( execute_seen == 1 )) || {
    printf 'run requires the explicit --execute acknowledgement\n' >&2
    exit 2
  }
fi

exec python3 -B "$runner" "$@"
