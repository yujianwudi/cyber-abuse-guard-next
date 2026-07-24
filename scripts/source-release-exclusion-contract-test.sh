#!/usr/bin/env bash
set -euo pipefail

root="$(cd "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
# shellcheck source=release-common.sh
source "$root/scripts/release-common.sh"
release_require_commands git tar grep sha256sum awk mktemp rm mkdir

work="$(mktemp -d)"
trap 'rm -rf -- "$work"' EXIT
archive="$work/source.tar"
verifier_path='scripts/round9_external_evaluation_contract.py'
verifier_sha256='4c330ece27ce5e000f13ebc06bff6dbcaa2f18b5b62f73f940e78591051fae7e'
verifier_test_path='scripts/round9_external_evaluation_contract_test.py'
verifier_test_sha256='f42625714cb46b89a4bc32a1ec52c2352d6f9c67f5f782ea117d08e7650c43c9'

tracked_independent="$(git -C "$root" ls-files -- \
  ':(glob)testdata/round9-independent-*/**')"
[[ -z "$tracked_independent" ]] ||
  release_die "independent corpus plaintext is tracked in Git history: $tracked_independent"
tracked_local_sensitive="$(git -C "$root" ls-files -- \
  ':(glob).round9-local-sandbox/**' \
  ':(glob)**/id_ed25519' ':(glob)**/id_ed25519.pub' \
  ':(glob)**/id_ed25519_servers' ':(glob)**/id_ed25519_servers.pub' \
  ':(glob)**/id_rsa' ':(glob)**/id_rsa.pub' \
  ':(glob)**/id_dsa' ':(glob)**/id_dsa.pub' \
  ':(glob)**/id_ecdsa' ':(glob)**/id_ecdsa.pub' \
  ':(glob)**/*.ppk')"
[[ -z "$tracked_local_sensitive" ]] ||
  release_die "local sandbox or SSH key material is tracked in Git history: $tracked_local_sensitive"
for path in \
  testdata/round9-independent-benign-v1/cases.jsonl \
  testdata/round9-independent-malicious-v1/cases.jsonl \
  .round9-local-sandbox/synthetic-note.txt \
  id_ed25519 \
  nested/id_ed25519_servers \
  id_rsa \
  id_dsa \
  id_ecdsa \
  keys/operator.ppk; do
  git -C "$root" check-ignore --quiet -- "$path" ||
    release_die "restricted local path is not protected by .gitignore: $path"
done

export_ignored_paths=(
  cmd/consumed-contract-probe
  cmd/safe/nested-consumed
  cmd/safe/nested-Consumed
  docs/reports/consumed-contract-probe.md
  docs/safe/nested-consumed
  docs/safe/nested-Consumed
  internal/classifier/consumed_contract_probe_test.go
  internal/classifier/safe/nested-consumed
  internal/classifier/safe/nested-Consumed
  testdata/consumed-contract-probe.json
  testdata/safe/nested-consumed
  testdata/safe/nested-Consumed
  testdata/round9-independent-synthetic-probe/cases.jsonl
  .round9-local-sandbox/synthetic-note.txt
)
for path in "${export_ignored_paths[@]}"; do
  [[ "$(git -C "$root" check-attr export-ignore -- "$path")" == \
    "$path: export-ignore: set" ]] || \
    release_die "source archive export-ignore contract does not exclude restricted path: $path"
done

git -C "$root" archive --worktree-attributes --format=tar \
  --output="$archive" HEAD
listing="$(tar -tf "$archive")"

if [[ "$(grep -Fxc "$verifier_path" <<<"$listing")" != 1 ]] ||
  [[ "$(grep -Fxc "$verifier_test_path" <<<"$listing")" != 1 ]]; then
  release_die "source archive lost the exact reviewed external-evaluation verifier sources"
fi
verifier_sha="$(tar -xOf "$archive" "$verifier_path" | sha256sum | awk '{print $1}')"
verifier_test_sha="$(tar -xOf "$archive" "$verifier_test_path" | sha256sum | awk '{print $1}')"
[[ "$verifier_sha" == "$verifier_sha256" ]] ||
  release_die "source archive external-evaluation verifier source identity differs"
[[ "$verifier_test_sha" == "$verifier_test_sha256" ]] ||
  release_die "source archive external-evaluation verifier test identity differs"
restricted_listing="$(awk -v verifier="$verifier_path" -v verifier_test="$verifier_test_path" \
  '$0 != verifier && $0 != verifier_test { print }' <<<"$listing")"

grep -Fxq README.md <<<"$listing" || \
  release_die "source archive exclusion fixture lost a required public source file"
grep -Fxq Dockerfile.test <<<"$listing" || \
  release_die "source archive exclusion fixture lost the tracked Dockerfile.test source"
grep -Fxq docs/ROUND9_HOST_RUNNER.md <<<"$listing" || \
  release_die "source archive lost the Round 9 Host runner contract"
grep -Fxq integration/round9countedmock/README.md <<<"$listing" || \
  release_die "source archive lost the Round 9 counted-Mock documentation"
grep -Fq '[Round 9 Linux Host runner and counted-Mock contract](ROUND9_HOST_RUNNER.md)' \
  "$root/docs/README.md" || \
  release_die "documentation index lost the Round 9 Host runner link"
grep -Fq '`docs/ROUND9_HOST_RUNNER.md`' \
  "$root/integration/round9countedmock/README.md" || \
  release_die "Round 9 counted-Mock README lost its Host contract link"
if grep -Eiq '(^|/)[^/]*(evaluation|holdout|consumed|private|blind|retired)[^/]*($|/)' <<<"$restricted_listing"; then
  release_die "source archive export-ignore contract exposed restricted material"
fi
if grep -Eiq '(^|/)testdata/round9-independent-[^/]+(/|$)' <<<"$listing"; then
  release_die "source archive contains a Round 9 independent corpus path"
fi

transient_path_pattern='(^|/)(classifier_(candidate|single)_[^/]*|[^/]*\.(cpu|mem|pprof|test\.exe|exe))($|/)'
test_binary_path_pattern='(^|/)[^/]*\.test($|/)'
safe_test_source_pattern='(^|/)Dockerfile\.test($|/)'
backup_binary_archive_path_pattern='(^|/)[^/]*\.(bak|backup|so|dll|zip|tar|tgz|gz)($|/)'
secret_key_path_pattern='(^|/)(id_(ed25519|ed25519_servers|rsa|dsa|ecdsa)(\.pub)?|[^/]*\.ppk)($|/)'
local_sandbox_path_pattern='(^|/)\.round9-local-sandbox($|/)'
expected_archive_guard="  local backup_binary_archive_path_pattern='$backup_binary_archive_path_pattern'"
expected_secret_key_guard="  local secret_key_path_pattern='$secret_key_path_pattern'"
expected_local_sandbox_guard="  local local_sandbox_path_pattern='$local_sandbox_path_pattern'"
grep -Fxq "$expected_archive_guard" "$root/scripts/round6-rc-artifacts.sh" ||
  release_die "source archive production guard lost the reviewed backup/binary/archive pattern"
grep -Fxq "$expected_secret_key_guard" "$root/scripts/round6-rc-artifacts.sh" ||
  release_die "source archive production guard lost the reviewed SSH-key pattern"
grep -Fxq "$expected_local_sandbox_guard" "$root/scripts/round6-rc-artifacts.sh" ||
  release_die "source archive production guard lost the reviewed local-sandbox pattern"
is_forbidden_source_archive_path() {
  local path="$1"
  grep -Eiq "$backup_binary_archive_path_pattern" <<<"$path" && return 0
  grep -Eiq "$transient_path_pattern" <<<"$path" && return 0
  grep -Eiq "$secret_key_path_pattern" <<<"$path" && return 0
  grep -Eiq "$local_sandbox_path_pattern" <<<"$path" && return 0
  if grep -Eiq "$test_binary_path_pattern" <<<"$path" &&
    ! grep -Eiq "$safe_test_source_pattern" <<<"$path"; then
    return 0
  fi
  return 1
}
for path in \
  classifier.accept.cpu \
  profiles/classifier.mem \
  profiles/heap.pprof \
  classifier.test \
  classifier.test.exe \
  tools/probe.exe \
  classifier_candidate_exact \
  tmp/classifier_candidate_fixed \
  classifier_single_fixed \
  tmp/classifier_single_tree/member.go \
  audit.db.pre-v5-20260722T000000.000000000Z.bak \
  snapshots/audit.backup \
  plugins/cyber-abuse-guard.so \
  plugins/cyber-abuse-guard.dll \
  release/package.zip \
  release/source.tar \
  release/source.tar.gz \
  release/source.tgz \
  release/transcript.gz \
  id_ed25519 \
  keys/id_ed25519.pub \
  nested/id_ed25519_servers \
  id_rsa \
  id_dsa \
  id_ecdsa \
  keys/operator.ppk \
  .round9-local-sandbox/cache.txt; do
  is_forbidden_source_archive_path "cyber-abuse-guard-fixture/$path" || \
    release_die "source archive forbidden-payload guard missed: $path"
done
for path in \
  Dockerfile.test \
  integration/fixture/Dockerfile.test \
  internal/classifier/profile.cpu.go \
  internal/classifier/memory.mem.go \
  internal/classifier/trace.pprof.go \
  internal/classifier/package.test.go \
  internal/classifier/windows.exe.go \
  internal/classifier/classifier_candidate.go \
  internal/classifier/classifier_single.go \
  docs/classifier-candidate-notes.md \
  internal/plugin/cyber-abuse-guard.so.go \
  internal/platform/provider.dll.go \
  internal/audit/migration_backup_test.go \
  docs/archive.zip.md \
  testdata/fixture.tar.json \
  scripts/package-tar-gz.sh \
  docs/id_ed25519.md \
  internal/config/id_rsa_policy.go; do
  if is_forbidden_source_archive_path "cyber-abuse-guard-fixture/$path"; then
    release_die "source archive forbidden-payload guard rejected safe source: $path"
  fi
done

sparse_fixture="$work/sparse-fixture"
git init --quiet "$sparse_fixture"
restricted_paths=(
  cmd/safe/nested-evaluation/payload.go
  cmd/safe/nested-private/payload.go
  docs/safe/nested-retired/report.md
  internal/classifier/safe/nested-consumed/payload.go
  testdata/safe/nested-blind/payload.json
  cmd/safe/nested-Evaluation/payload.go
  cmd/safe/nested-HoldOut/payload.go
  cmd/safe/nested-Consumed/payload.go
  docs/safe/nested-Private/report.md
  internal/classifier/safe/nested-Blind/payload.go
  testdata/safe/nested-Retired/payload.json
  testdata/round9-independent-benign-v1/cases.jsonl
  testdata/round9-independent-malicious-v1/cases.jsonl
  .round9-local-sandbox/id_ed25519
)
mkdir -p "$sparse_fixture/public"
printf 'synthetic safe neighbor\n' >"$sparse_fixture/public/safe.txt"
for path in "${restricted_paths[@]}"; do
  mkdir -p "$sparse_fixture/${path%/*}"
  printf 'synthetic restricted marker\n' >"$sparse_fixture/$path"
done
git -C "$sparse_fixture" add .
git -C "$sparse_fixture" \
  -c user.name='Round6 Contract' \
  -c user.email=round6-contract@example.invalid \
  commit --quiet --message fixture
sparse_patterns=(
  '/*'
  '!/.round9-local-sandbox/**'
  '!/cmd/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*'
  '!/cmd/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*'
  '!/cmd/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'
  '!/cmd/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*'
  '!/cmd/**/*[Bb][Ll][Ii][Nn][Dd]*'
  '!/cmd/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
  '!/docs/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*'
  '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*'
  '!/docs/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]_[Rr][Ee][Pp][Oo][Rr][Tt].[Mm][Dd]'
  '!/docs/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'
  '!/docs/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*'
  '!/docs/**/*[Bb][Ll][Ii][Nn][Dd]*'
  '!/docs/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
  '!/internal/classifier/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*'
  '!/internal/classifier/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*'
  '!/internal/classifier/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'
  '!/internal/classifier/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*'
  '!/internal/classifier/**/*[Bb][Ll][Ii][Nn][Dd]*'
  '!/internal/classifier/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
  '!/testdata/**/*[Ee][Vv][Aa][Ll][Uu][Aa][Tt][Ii][Oo][Nn]*'
  '!/testdata/**/*[Hh][Oo][Ll][Dd][Oo][Uu][Tt]*'
  '!/testdata/round9-independent-*/**'
  '!/testdata/**/*[Cc][Oo][Nn][Ss][Uu][Mm][Ee][Dd]*'
  '!/testdata/**/*[Pp][Rr][Ii][Vv][Aa][Tt][Ee]*'
  '!/testdata/**/*[Bb][Ll][Ii][Nn][Dd]*'
  '!/testdata/**/*[Rr][Ee][Tt][Ii][Rr][Ee][Dd]*'
)
git -C "$sparse_fixture" sparse-checkout set --no-cone "${sparse_patterns[@]}"
[[ -f "$sparse_fixture/public/safe.txt" ]] || \
  release_die "recursive sparse contract removed a safe neighbor"
for path in "${restricted_paths[@]}"; do
  [[ ! -e "$sparse_fixture/$path" ]] || \
    release_die "recursive sparse contract materialized restricted path: $path"
done

printf 'source release exclusion contract passed\n'
