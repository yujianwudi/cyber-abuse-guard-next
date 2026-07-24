#!/usr/bin/env bash
set -euo pipefail

umask 077
root="$(cd -- "${BASH_SOURCE[0]%/*}/.." && pwd -P)"
helper="$root/scripts/round9_old_so_rollback.py"
go_bin="${GO:-go}"

historical_tag='v0.16-rc.2'
historical_repository='https://github.com/yujianwudi/cyber-abuse-guard.git'
historical_tag_object='58bd9b78886da04c03b2c6d8f28e8cd7f2436e84'
historical_commit='9665fdd1aacab0d79b8790d68c87c6c8c80f8911'
historical_tree='84c6636b2012c825627bad34f922dfa0329d0a1e'
historical_version='0.16-rc.2'
historical_classifier='classifier-policy-v7'
historical_classifier_sha256='ea8c4dcfacacc6478f86fd2ca5de96d667ae98f2fc6ff0c83d8e6092e9f6a82d'
historical_ruleset='1.0.9'
historical_ruleset_sha256='a3de344d3f6dc8eea86d946a823996494d4d297c41efcc6346a6ef757f263a7d'
fixed_migration_time='2026-07-24T00:00:00Z'

for command_name in git tar sha256sum awk sort grep file readelf stat install timeout wc python3 "$go_bin"; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf 'Round 9 old-SO rollback gate: missing command %s\n' "$command_name" >&2
    exit 1
  }
done
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
  echo 'Round 9 old-SO rollback gate requires Linux x86_64' >&2
  exit 1
}
[[ "$($go_bin env GOOS)" == linux && "$($go_bin env GOARCH)" == amd64 ]] || {
  echo 'Round 9 old-SO rollback gate requires GOOS=linux GOARCH=amd64' >&2
  exit 1
}
[[ "$($go_bin env GOVERSION)" == go1.26.4 ]] || {
  printf 'Round 9 old-SO rollback gate requires Go go1.26.4, got %s\n' \
    "$($go_bin env GOVERSION)" >&2
  exit 1
}
[[ "$($go_bin env GOFLAGS)" == -mod=readonly ]] || {
  echo 'Round 9 old-SO rollback gate requires GOFLAGS=-mod=readonly' >&2
  exit 1
}
[[ -f "$helper" && ! -L "$helper" ]] || {
  echo 'Round 9 old-SO rollback helper is missing or unsafe' >&2
  exit 1
}
cd "$root"

work_dir="$(mktemp -d "${TMPDIR:-/tmp}/cag-round9-old-so-rollback.XXXXXXXX")"
chmod 0700 "$work_dir"
cleanup() {
  chmod -R u+w "$work_dir" 2>/dev/null || true
  rm -rf -- "$work_dir"
}
trap cleanup EXIT
printf 'isolated-synthetic-fixture-only-v1\n' > \
  "$work_dir/.round9-old-so-rollback-sandbox"
chmod 0600 "$work_dir/.round9-old-so-rollback-sandbox"

# The current project lives in cyber-abuse-guard-next, but v0.16-rc.2 belongs
# to the immutable predecessor repository.  Fetch only that annotated tag into
# an execution-private bare repository; never resolve it from this repository,
# one of its remotes, or a caller-provided URL.
history_repo="$work_dir/historical-source.git"
git init --bare --quiet "$history_repo"
git -C "$history_repo" remote add origin "$historical_repository"
[[ "$(git -C "$history_repo" remote get-url origin)" == "$historical_repository" ]] || {
  echo 'historical source URL was rewritten away from the frozen predecessor repository' >&2
  exit 1
}
timeout --signal=KILL 120s git -C "$history_repo" \
  -c http.lowSpeedLimit=1 -c http.lowSpeedTime=60 \
  fetch --no-tags --depth=1 origin \
  "refs/tags/$historical_tag:refs/tags/$historical_tag" || {
  echo 'v0.16-rc.2 could not be fetched from the frozen predecessor repository' >&2
  exit 1
}

actual_tag_object="$(git -C "$history_repo" rev-parse --verify "refs/tags/$historical_tag")"
actual_tag_type="$(git -C "$history_repo" cat-file -t "$actual_tag_object")"
actual_commit="$(git -C "$history_repo" rev-parse --verify "refs/tags/$historical_tag^{commit}")"
actual_tree="$(git -C "$history_repo" rev-parse --verify "$actual_commit^{tree}")"
[[ "$actual_tag_object" == "$historical_tag_object" && "$actual_tag_type" == tag ]] || {
  echo 'v0.16-rc.2 annotated tag object identity mismatch' >&2
  exit 1
}
[[ "$actual_commit" == "$historical_commit" && "$actual_tree" == "$historical_tree" ]] || {
  echo 'v0.16-rc.2 commit/tree identity mismatch' >&2
  exit 1
}

remote_verified=false
verify_remote="${ROUND9_OLD_SO_VERIFY_REMOTE:-0}"
case "$verify_remote" in
  0) ;;
  1)
    remote_refs="$(timeout --signal=KILL 60s git \
      -c http.lowSpeedLimit=1 -c http.lowSpeedTime=60 \
      ls-remote --tags "$historical_repository" \
      "refs/tags/$historical_tag" "refs/tags/$historical_tag^{}")" || {
      echo 'v0.16-rc.2 remote tag identity could not be verified' >&2
      exit 1
    }
    [[ "$(printf '%s\n' "$remote_refs" | grep -Fxc \
      "$historical_tag_object"$'\t'"refs/tags/$historical_tag")" == 1 ]] || {
      echo 'v0.16-rc.2 remote annotated tag object mismatch' >&2
      exit 1
    }
    [[ "$(printf '%s\n' "$remote_refs" | grep -Fxc \
      "$historical_commit"$'\t'"refs/tags/$historical_tag^{}")" == 1 ]] || {
      echo 'v0.16-rc.2 remote peeled commit mismatch' >&2
      exit 1
    }
    [[ "$(printf '%s\n' "$remote_refs" | wc -l)" == 2 ]] || {
      echo 'v0.16-rc.2 remote tag query returned an unexpected ref set' >&2
      exit 1
    }
    remote_verified=true
    ;;
  *)
    echo 'ROUND9_OLD_SO_VERIFY_REMOTE must be 0 or 1' >&2
    exit 2
    ;;
esac

source_dir="$work_dir/source"
mkdir -m 0700 "$source_dir"
git -C "$history_repo" archive --format=tar "$historical_commit" | tar -xf - -C "$source_dir"

[[ "$(grep -Fxc 'const ClassifierPolicyVersion = "classifier-policy-v7"' \
  "$source_dir/internal/classifier/policy_identity.go")" == 1 ]] || {
  echo 'historical classifier version differs from reviewed v0.16-rc.2 source' >&2
  exit 1
}
[[ "$(grep -Fxc 'const ClassifierPolicySHA256 = "ea8c4dcfacacc6478f86fd2ca5de96d667ae98f2fc6ff0c83d8e6092e9f6a82d"' \
  "$source_dir/internal/classifier/policy_identity.go")" == 1 ]] || {
  echo 'historical classifier SHA-256 differs from reviewed v0.16-rc.2 source' >&2
  exit 1
}
[[ "$(grep -Fxc 'const currentSchemaVersion = 5' \
  "$source_dir/internal/audit/migrations.go")" == 1 ]] || {
  echo 'historical source does not declare audit schema v5' >&2
  exit 1
}
[[ "$(grep -Fxc 'version: "1.0.9"' "$source_dir/rules/manifest.yaml")" == 1 ]] || {
  echo 'historical ruleset version differs from reviewed v0.16-rc.2 source' >&2
  exit 1
}
historical_ruleset_actual_sha256="$({
  printf '%s\n' "$source_dir"/rules/*.yaml | LC_ALL=C sort | while IFS= read -r rule_file; do
    relative="${rule_file#"$source_dir"/}"
    printf '%s  %s\n' "$(sha256sum "$rule_file" | awk '{print $1}')" "$relative"
  done
} | sha256sum | awk '{print $1}')"
[[ "$historical_ruleset_actual_sha256" == "$historical_ruleset_sha256" ]] || {
  echo 'historical ruleset aggregate SHA-256 mismatch' >&2
  exit 1
}

historical_so="$work_dir/cyber-abuse-guard-v0.16-rc.2-source-built.so"
source_date_epoch="$(git -C "$history_repo" show -s --format=%ct "$historical_commit")"
ldflags="-s -w -buildid="
ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.Version=$historical_version"
ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.Commit=$historical_commit"
ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.RulesetVersion=$historical_ruleset"
ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.RulesetSHA256=$historical_ruleset_sha256"
ldflags+=" -X github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo.Dirty=false"
SOURCE_DATE_EPOCH="$source_date_epoch" GOWORK=off CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
  "$go_bin" -C "$source_dir" build -mod=readonly -trimpath -buildvcs=false \
  -buildmode=c-shared -tags=sqlite_omit_load_extension -ldflags="$ldflags" \
  -o "$historical_so" ./cmd/cyber-abuse-guard
[[ -f "$historical_so" && ! -L "$historical_so" ]] || {
  echo 'historical SO build output is missing or unsafe' >&2
  exit 1
}
file "$historical_so" | grep -Fq 'ELF 64-bit LSB shared object'
readelf -h "$historical_so" | grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64'
"$go_bin" version -m "$historical_so" | grep -Fq $'build\t-buildmode=c-shared'
"$go_bin" version -m "$historical_so" | grep -Fq $'build\tCGO_ENABLED=1'
"$go_bin" version -m "$historical_so" | grep -Fq $'build\tGOARCH=amd64'
"$go_bin" version -m "$historical_so" | grep -Fq $'build\tGOOS=linux'
historical_so_sha256="$(sha256sum "$historical_so" | awk '{print $1}')"
historical_so_bytes="$(stat -c '%s' "$historical_so")"

v5_dir="$work_dir/v5-source"
mkdir -m 0700 "$v5_dir"
python3 -B ./scripts/round9_old_so_rollback.py old-so --so "$historical_so" --data-dir "$v5_dir" \
  --expect create-v5 --expected-version "$historical_version" \
  --output "$work_dir/create-v5.json"
v5_database="$v5_dir/events.db"
python3 -B ./scripts/round9_old_so_rollback.py seed-v5 --database "$v5_database" \
  --output "$work_dir/seed-v5.json"

GOWORK=off "$go_bin" -C "$root" run -tags=sqlite_omit_load_extension \
  ./cmd/round9-old-so-rollback-fixture \
  --sandbox-root "$work_dir" --database "$v5_database" --now "$fixed_migration_time" \
  > "$work_dir/migration-v6.json"
python3 -B ./scripts/round9_old_so_rollback.py inspect --database "$v5_database" --expected-version 6 \
  --output "$work_dir/inspect-v6.json"
for suffix in -wal -shm; do
  [[ ! -e "$v5_database$suffix" && ! -L "$v5_database$suffix" ]] || {
    echo 'schema-v6 fixture retained a SQLite sidecar after the migration process exited' >&2
    exit 1
  }
done

shopt -s nullglob
backups=("$v5_database".pre-v6-*.bak)
shopt -u nullglob
[[ "${#backups[@]}" == 1 ]] || {
  printf 'expected exactly one pre-v6 backup, found %d\n' "${#backups[@]}" >&2
  exit 1
}
backup="${backups[0]}"
manifest="$backup.manifest.json"
python3 -B ./scripts/round9_old_so_rollback.py verify-backup --backup "$backup" --manifest "$manifest" \
  --output "$work_dir/manifest.json"

v6_probe_dir="$work_dir/v6-old-so-probe"
mkdir -m 0700 "$v6_probe_dir"
install -m 0600 "$v5_database" "$v6_probe_dir/events.db"
python3 -B ./scripts/round9_old_so_rollback.py old-so --so "$historical_so" --data-dir "$v6_probe_dir" \
  --expect reject-v6 --expected-version "$historical_version" \
  --output "$work_dir/reject-v6.json"

restore_dir="$work_dir/restored-v5"
mkdir -m 0700 "$restore_dir"
restored_database="$restore_dir/events.db"
python3 -B ./scripts/round9_old_so_rollback.py restore --backup "$backup" --manifest "$manifest" \
  --destination "$restored_database" --output "$work_dir/restore-v5.json"
python3 -B ./scripts/round9_old_so_rollback.py old-so --so "$historical_so" --data-dir "$restore_dir" \
  --expect accept-v5 --expected-version "$historical_version" \
  --output "$work_dir/accept-v5.json"

report_path="${ROUND9_OLD_SO_ROLLBACK_REPORT:-dist/round9-worklogs/round9-old-so-rollback.json}"
case "$report_path" in
  /*) ;;
  *) report_path="$root/$report_path" ;;
esac
python3 -B ./scripts/round9_old_so_rollback.py report \
  --create-result "$work_dir/create-v5.json" \
  --migration-result "$work_dir/migration-v6.json" \
  --manifest-result "$work_dir/manifest.json" \
  --rejection-result "$work_dir/reject-v6.json" \
  --restore-result "$work_dir/restore-v5.json" \
  --acceptance-result "$work_dir/accept-v5.json" \
  --repository "$historical_repository" \
  --tag "$historical_tag" \
  --tag-object "$historical_tag_object" \
  --commit "$historical_commit" \
  --tree "$historical_tree" \
  --classifier "$historical_classifier" \
  --classifier-sha256 "$historical_classifier_sha256" \
  --ruleset "$historical_ruleset" \
  --ruleset-sha256 "$historical_ruleset_sha256" \
  --go-runtime go1.26.4 \
  --remote-verified "$remote_verified" \
  --so-sha256 "$historical_so_sha256" \
  --so-bytes "$historical_so_bytes" \
  --output "$report_path"

printf 'Round 9 old-SO rollback gate: PASS: report=%s\n' "$report_path"
cat -- "$report_path"
