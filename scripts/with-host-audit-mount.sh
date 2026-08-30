#!/usr/bin/env bash
set -euo pipefail

if (($# == 0)); then
  printf 'usage: %s command [args...]\n' "$0" >&2
  exit 2
fi

# Never inherit a caller-selected audit carrier. The wrapped Host test opens,
# migrates, purges and checkpoints events.db, so accepting an existing path
# could mutate production state when a developer shell retains this variable.
# This wrapper creates and owns the only directory it exports.
unset CYBER_ABUSE_GUARD_HOST_AUDIT_DATA_DIR

for command_name in mount mountpoint stat umount; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf '%s is required for the isolated Host audit mount fixture\n' "$command_name" >&2
    exit 1
  }
done

use_sudo=0
if ((EUID != 0)); then
  command -v sudo >/dev/null 2>&1 || {
    printf 'sudo is required to create the isolated Host audit bind mount\n' >&2
    exit 1
  }
  sudo -n true >/dev/null 2>&1 || {
    printf 'passwordless sudo is required to create the isolated Host audit bind mount\n' >&2
    exit 1
  }
  use_sudo=1
fi

fixture_root="${CYBER_ABUSE_GUARD_HOST_AUDIT_FIXTURE_ROOT:-/var/tmp}"
[[ "$fixture_root" == /* && -d "$fixture_root" ]] || {
  printf 'CYBER_ABUSE_GUARD_HOST_AUDIT_FIXTURE_ROOT must be an existing absolute directory\n' >&2
  exit 2
}
work="$(mktemp -d "$fixture_root/cag-host-audit.XXXXXX")"
source_dir="$work/source"
mount_dir="$work/mount"
mkdir -p -- "$source_dir" "$mount_dir"
chmod 0700 -- "$work" "$source_dir" "$mount_dir"
mounted=0

cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if ((mounted)); then
    if ((use_sudo)); then
      if sudo -n umount -- "$mount_dir"; then
        mounted=0
      else
        printf 'failed to unmount isolated Host audit fixture: %s\n' "$mount_dir" >&2
        status=1
      fi
    elif umount -- "$mount_dir"; then
      mounted=0
    else
      printf 'failed to unmount isolated Host audit fixture: %s\n' "$mount_dir" >&2
      status=1
    fi
  fi
  if ((!mounted)); then
    rm -rf -- "$work"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

filesystem_type="$(stat -f -c %T -- "$source_dir")"
case "$filesystem_type" in
  tmpfs | ramfs)
    printf 'isolated Host audit backing filesystem must be persistent, got %s\n' \
      "$filesystem_type" >&2
    exit 1
    ;;
esac

if ((use_sudo)); then
  sudo -n mount --bind "$source_dir" "$mount_dir"
else
  mount --bind "$source_dir" "$mount_dir"
fi
mounted=1
mountpoint -q -- "$mount_dir" || {
  printf 'isolated Host audit fixture is not a mount point: %s\n' "$mount_dir" >&2
  exit 1
}

export CYBER_ABUSE_GUARD_HOST_AUDIT_DATA_DIR="$mount_dir"
"$@"
