#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
generator="$root/scripts/generate-hmac-key.sh"
for required in mktemp chmod ln sha256sum stat rm grep mkdir awk sync; do
  command -v "$required" >/dev/null 2>&1 || {
    printf 'required generator-test command not found: %s\n' "$required" >&2
    exit 127
  }
done

stat_mode() {
  local path="$1" value
  if value="$(stat -c '%a' -- "$path" 2>/dev/null)"; then
    printf '%s\n' "$value"
    return 0
  fi
  if value="$(stat -f '%Lp' "$path" 2>/dev/null)"; then
    printf '%s\n' "$value"
    return 0
  fi
  printf 'could not read file mode with GNU or BSD stat: %s\n' "$path" >&2
  return 1
}

stat_size() {
  local path="$1" value
  if value="$(stat -c '%s' -- "$path" 2>/dev/null)"; then
    printf '%s\n' "$value"
    return 0
  fi
  if value="$(stat -f '%z' "$path" 2>/dev/null)"; then
    printf '%s\n' "$value"
    return 0
  fi
  printf 'could not read file size with GNU or BSD stat: %s\n' "$path" >&2
  return 1
}

work="$(mktemp -d)"
cleanup() {
  rm -rf -- "$work"
}
trap cleanup EXIT
chmod 0700 "$work"

private="$work/private"
mkdir -m 0700 "$private"
key="$private/cyber-abuse-guard-hmac.key"
output="$($generator "$key" 2>"$work/success.err")"
[[ "$output" == "generated mode-0600 HMAC key: $key" ]]
[[ ! -s "$work/success.err" ]]
[[ -f "$key" && ! -L "$key" ]]
[[ "$(stat_mode "$key")" == 600 ]]
[[ "$(stat_size "$key")" == 65 ]]

# The generator must not require GNU sync's -d/-f extensions. A strict shim
# accepts only the no-argument POSIX form and records that it was invoked.
sync_bin="$work/sync-bin"
sync_log="$work/sync.log"
mkdir -m 0700 "$sync_bin"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'set -euo pipefail' \
  '[[ $# -eq 0 ]] || { printf "sync received non-portable arguments: %s\\n" "$*" >&2; exit 64; }' \
  'printf "called\\n" >> "$SYNC_LOG"' \
  > "$sync_bin/sync"
chmod 0700 "$sync_bin/sync"
portable_key="$private/portable-sync.key"
SYNC_LOG="$sync_log" PATH="$sync_bin:$PATH" "$generator" "$portable_key" \
  >"$work/portable-sync.out" 2>"$work/portable-sync.err"
[[ "$(grep -Fxc 'called' "$sync_log")" == 1 ]]
[[ -f "$portable_key" && ! -L "$portable_key" ]]
[[ "$(stat_mode "$portable_key")" == 600 ]]

before="$(sha256sum "$key" | awk '{print $1}')"
if "$generator" "$key" >"$work/overwrite.out" 2>"$work/overwrite.err"; then
  echo "generator overwrote an existing key" >&2
  exit 1
fi
after="$(sha256sum "$key" | awk '{print $1}')"
[[ "$before" == "$after" ]]

target="$private/target"
printf 'unchanged\n' >"$target"
link="$private/link.key"
ln -s "$target" "$link"
if "$generator" "$link" >"$work/symlink.out" 2>"$work/symlink.err"; then
  echo "generator accepted a symlink destination" >&2
  exit 1
fi
grep -Fxq 'unchanged' "$target"

writable="$work/writable"
mkdir -m 0777 "$writable"
chmod 0777 "$writable"
if "$generator" "$writable/key" >"$work/writable.out" 2>"$work/writable.err"; then
  echo "generator accepted a group/world-writable output directory" >&2
  exit 1
fi

real_parent="$work/real-parent"
mkdir -m 0700 "$real_parent" "$real_parent/child"
linked_parent="$work/linked-parent"
ln -s "$real_parent" "$linked_parent"
if "$generator" "$linked_parent/child/key" >"$work/linked.out" 2>"$work/linked.err"; then
  echo "generator accepted a symlinked directory component" >&2
  exit 1
fi

race_key="$private/concurrent.key"
set +e
"$generator" "$race_key" >"$work/race-one.out" 2>"$work/race-one.err" &
race_one=$!
"$generator" "$race_key" >"$work/race-two.out" 2>"$work/race-two.err" &
race_two=$!
wait "$race_one"
race_one_status=$?
wait "$race_two"
race_two_status=$?
set -e
if ! { [[ "$race_one_status" -eq 0 && "$race_two_status" -ne 0 ]] ||
       [[ "$race_one_status" -ne 0 && "$race_two_status" -eq 0 ]]; }; then
  printf 'concurrent generators returned %d and %d; want exactly one success\n' \
    "$race_one_status" "$race_two_status" >&2
  exit 1
fi
[[ -f "$race_key" && ! -L "$race_key" ]]
[[ "$(stat_mode "$race_key")" == 600 ]]
[[ "$(stat_size "$race_key")" == 65 ]]

echo "generate-hmac-key security tests: PASS"
