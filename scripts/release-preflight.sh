#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
go_bin="${GO:-go}"
release_require_commands "$go_bin" git sed awk sha256sum sort
release_init
release_assert_tag
release_assert_formal_build
go_version="$($go_bin env GOVERSION)"
[[ "$go_version" == go1.26.6 ]] || release_die "release requires Go go1.26.6, got $go_version"

mapfile -t tracked_scripts < <(git -C "$root" ls-files -- 'scripts/*.sh')
((${#tracked_scripts[@]} > 0)) || release_die "no tracked release scripts found"

untracked_scripts="$(git -C "$root" ls-files --others --exclude-standard -- 'scripts/*.sh')"
if [[ -n "$untracked_scripts" ]]; then
  release_error "release scripts must be tracked before formal release"
  printf '%s\n' "$untracked_scripts" >&2
  exit 1
fi

for relative in "${tracked_scripts[@]}"; do
  script="$root/$relative"
  [[ -f "$script" && ! -L "$script" ]] || \
    release_die "$relative must be a regular non-symlink file"
  [[ -x "$script" ]] || release_die "$relative is not executable"

  mapfile -t index_entries < <(git -C "$root" ls-files --stage -- "$relative")
  ((${#index_entries[@]} == 1)) || \
    release_die "$relative must have exactly one stage-0 Git index entry"
  read -r index_mode _ index_stage _ <<<"${index_entries[0]}"
  [[ "$index_mode" == 100755 && "$index_stage" == 0 ]] || \
    release_die "$relative must be tracked in Git with index mode 100755 (got mode=$index_mode stage=$index_stage)"
done

printf 'release preflight passed: version=%s commit=%s dirty=%s\n' \
  "$RELEASE_ARTIFACT_VERSION" "$RELEASE_GIT_COMMIT" "$RELEASE_DIRTY"
