#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands git tar grep sha256sum mktemp chmod mv rm mkdir basename
release_init
release_assert_tag
release_assert_formal_build

dist="${DIST_DIR:-$root/dist}"
mkdir -p "$dist"
[[ -d "$dist" && ! -L "$dist" ]] || release_die "DIST_DIR must be a real directory"
archive="cyber-abuse-guard-v${RELEASE_SOURCE_VERSION}-source.tar.gz"
temporary="$(mktemp "$dist/.source-release.XXXXXX")"
cleanup() {
  rm -f -- "$temporary"
}
trap cleanup EXIT

archive_pathspecs=(
  .
  ':(exclude,glob).round9-local-sandbox/**'
  ':(exclude,glob,icase)cmd/**/*evaluation*'
  ':(exclude,glob,icase)cmd/**/*holdout*'
  ':(exclude,glob,icase)cmd/**/*consumed*'
  ':(exclude,glob,icase)cmd/**/*private*'
  ':(exclude,glob,icase)cmd/**/*blind*'
  ':(exclude,glob,icase)cmd/**/*retired*'
  ':(exclude,glob,icase)docs/**/*EVALUATION_*'
  ':(exclude,glob,icase)docs/**/*HOLDOUT_*'
  ':(exclude,glob,icase)docs/**/*HOLDOUT_REPORT.md'
  ':(exclude,glob,icase)docs/**/*consumed*'
  ':(exclude,glob,icase)docs/**/*private*'
  ':(exclude,glob,icase)docs/**/*blind*'
  ':(exclude,glob,icase)docs/**/*retired*'
  ':(exclude,glob,icase)internal/classifier/**/*evaluation*'
  ':(exclude,glob,icase)internal/classifier/**/*holdout*'
  ':(exclude,glob,icase)internal/classifier/**/*consumed*'
  ':(exclude,glob,icase)internal/classifier/**/*private*'
  ':(exclude,glob,icase)internal/classifier/**/*blind*'
  ':(exclude,glob,icase)internal/classifier/**/*retired*'
  ':(exclude,glob,icase)testdata/**/*evaluation*'
  ':(exclude,glob,icase)testdata/**/*holdout*'
  ':(exclude,glob,icase)testdata/**/*consumed*'
  ':(exclude,glob,icase)testdata/**/*private*'
  ':(exclude,glob,icase)testdata/**/*blind*'
  ':(exclude,glob,icase)testdata/**/*retired*'
)
git -C "$root" archive --format=tar.gz \
  --prefix="cyber-abuse-guard-v${RELEASE_SOURCE_VERSION}/" \
  --output="$temporary" "$RELEASE_GIT_COMMIT" -- "${archive_pathspecs[@]}"

listing="$(tar -tzf "$temporary")"
[[ -n "$listing" ]] || release_die "source release archive is empty"
secret_key_path_pattern='(^|/)(id_(ed25519|ed25519_servers|rsa|dsa|ecdsa)(\.pub)?|[^/]*\.ppk)($|/)'
local_sandbox_path_pattern='(^|/)\.round9-local-sandbox($|/)'
if grep -Ev "^cyber-abuse-guard-v${RELEASE_SOURCE_VERSION}/" <<<"$listing" | grep -q .; then
  release_die "source release archive contains an entry outside its fixed prefix"
fi
if grep -Eiq '(^|/)(\.git($|/)|dist($|/)|build($|/)|[^/]*\.(db|sqlite|sqlite3|key|pem|p12|pfx|jks|keystore|log)($|[-.])|\.env($|[./]))' <<<"$listing" ||
  grep -Eiq "$secret_key_path_pattern" <<<"$listing" ||
  grep -Eiq "$local_sandbox_path_pattern" <<<"$listing"; then
  release_die "source release archive contains a forbidden repository, build, database, secret, local sandbox, or log path"
fi
if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<"$listing"; then
  release_die "source release archive contains evaluation, holdout, consumed, private, blind, or retired material"
fi
if tar -tvzf "$temporary" | grep -Eq '^l'; then
  release_die "source release archive contains a symbolic link"
fi

chmod 0644 "$temporary"
mv -f -- "$temporary" "$dist/$archive"
temporary=""
(cd "$dist" && sha256sum "$archive" >"$archive.sha256" && sha256sum -c "$archive.sha256")
release_assert_source_unchanged
printf 'source release archive generated: %s\n' "$dist/$archive"
