#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cpa_origin='https://github.com/router-for-me/CLIProxyAPI.git'
cpa_source='https://github.com/router-for-me/CLIProxyAPI'
candidate_source='https://github.com/yujianwudi/cyber-abuse-guard-next'
candidate_tag='v0.16-rc.2'
mock_contract='round8-counted-mock/v1'
primary_version='v7.2.95'
primary_commit='f71ec0eb6776854457892452cf28c47f0d658251'
cpa_dockerfile_sha256='4383961a3b97fe728e2226bf417686063569aa43f9d103f37871922561e40488'
mock_dockerfile_sha256='1b64460ca278059d7d08414c546173a4e8b239bbbdf76a3cffe5a1a1771e12ee'
golang_canonical='docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b'
golang_platform_digest='sha256:5a94593d87a066df5abb02969be911524963f53908292aa5a1a6096fc019012a'
golang_image_id='sha256:9d9d715d688ced62374388302667e31a6d3a0655c4c9e0ceaf1a4c4886752a62'
golang_local='cag-round8-base:golang-1.26.4-bookworm-amd64-5a94593d87a0'
debian_canonical='docker.io/library/debian:bookworm-20260623@sha256:30482e873082e906a4908c10529180aefb6f77620aea7404b909829fadc5d168'
debian_platform_digest='sha256:129588494497601baa5dbca1df687c835ff166ec4dd3bf307be684f34da07ab5'
debian_image_id='sha256:ee37b64a84a5a803ef11061304de62741b41b1f1b9e2a743b1e7686b12029d79'
debian_local='cag-round8-base:debian-bookworm-20260623-amd64-129588494497'
base_transport='github-attested-digest-bundle/v1'

execute=0
work_parent=''
candidate_commit=''
candidate_tree=''
sandbox_id=''
daemon_id=''
probe_image_id=''
host_challenge=''
base_images_archive=''
base_images_manifest=''
while (( $# > 0 )); do
  case "$1" in
    --execute)
      execute=1
      shift
      ;;
    --work)
      (( $# >= 2 )) || { printf '%s\n' '--work requires a value' >&2; exit 2; }
      work_parent="$2"
      shift 2
      ;;
    --candidate-commit)
      (( $# >= 2 )) || { printf '%s\n' '--candidate-commit requires a value' >&2; exit 2; }
      candidate_commit="$2"
      shift 2
      ;;
    --candidate-tree)
      (( $# >= 2 )) || { printf '%s\n' '--candidate-tree requires a value' >&2; exit 2; }
      candidate_tree="$2"
      shift 2
      ;;
    --sandbox-id)
      (( $# >= 2 )) || { printf '%s\n' '--sandbox-id requires a value' >&2; exit 2; }
      sandbox_id="$2"
      shift 2
      ;;
    --daemon-id)
      (( $# >= 2 )) || { printf '%s\n' '--daemon-id requires a value' >&2; exit 2; }
      daemon_id="$2"
      shift 2
      ;;
    --probe-image-id)
      (( $# >= 2 )) || { printf '%s\n' '--probe-image-id requires a value' >&2; exit 2; }
      probe_image_id="$2"
      shift 2
      ;;
    --challenge)
      (( $# >= 2 )) || { printf '%s\n' '--challenge requires a value' >&2; exit 2; }
      host_challenge="$2"
      shift 2
      ;;
    --base-images-archive)
      (( $# >= 2 )) || { printf '%s\n' '--base-images-archive requires a value' >&2; exit 2; }
      base_images_archive="$2"
      shift 2
      ;;
    --base-images-manifest)
      (( $# >= 2 )) || { printf '%s\n' '--base-images-manifest requires a value' >&2; exit 2; }
      base_images_manifest="$2"
      shift 2
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 2
      ;;
  esac
done

(( execute == 1 )) || { printf '%s\n' 'pass --execute to build the three private Host images' >&2; exit 2; }
[[ -n "$work_parent" ]] || { printf '%s\n' '--work is required' >&2; exit 2; }
[[ "$candidate_commit" =~ ^[0-9a-f]{40}$ ]] || { printf '%s\n' 'candidate commit must be lowercase 40-hex' >&2; exit 2; }
[[ "$candidate_tree" =~ ^[0-9a-f]{40}$ ]] || { printf '%s\n' 'candidate tree must be lowercase 40-hex' >&2; exit 2; }
[[ "$sandbox_id" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$ ]] || { printf '%s\n' 'sandbox ID is invalid' >&2; exit 2; }
[[ "$daemon_id" =~ ^[A-Za-z0-9][A-Za-z0-9_.:-]{7,127}$ ]] || { printf '%s\n' 'daemon ID is invalid' >&2; exit 2; }
[[ "$probe_image_id" =~ ^sha256:[0-9a-f]{64}$ ]] || { printf '%s\n' 'probe image ID is invalid' >&2; exit 2; }
[[ "$host_challenge" =~ ^[0-9a-f]{64}$ ]] || { printf '%s\n' 'Host challenge is invalid' >&2; exit 2; }
[[ -n "$base_images_archive" ]] || { printf '%s\n' '--base-images-archive is required' >&2; exit 2; }
[[ -n "$base_images_manifest" ]] || { printf '%s\n' '--base-images-manifest is required' >&2; exit 2; }

for command_name in git docker mktemp python3 sed; do
  command -v "$command_name" >/dev/null 2>&1 || {
    printf '%s is required\n' "$command_name" >&2
    exit 1
  }
done
[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
  printf '%s\n' 'Round 8 Host images must be built on Linux amd64' >&2
  exit 1
}

mkdir -p -- "$work_parent"
[[ -d "$work_parent" && ! -L "$work_parent" ]] || {
  printf '%s\n' 'image-build work parent must be a real directory' >&2
  exit 1
}
python3 -B "$root/scripts/round8_docker_sandbox.py" \
  --sandbox-id "$sandbox_id" \
  --daemon-id "$daemon_id" \
  --probe-image-id "$probe_image_id" \
  --challenge "$host_challenge" \
  --challenge-root "$work_parent" >/dev/null
registry_mirrors="$(docker info --format '{{json .RegistryConfig.Mirrors}}')"
[[ "$registry_mirrors" == '[]' || "$registry_mirrors" == null ]] || {
  printf '%s\n' 'Round 8 Host daemon must not configure a registry mirror' >&2
  exit 1
}

[[ "$(git -C "$root" rev-parse HEAD)" == "$candidate_commit" ]]
[[ "$(git -C "$root" rev-parse 'HEAD^{tree}')" == "$candidate_tree" ]]
[[ -z "$(git -C "$root" status --porcelain)" ]] || {
  printf '%s\n' 'candidate checkout must be clean before Host image construction' >&2
  exit 1
}
python3 -B "$root/scripts/round8_host_evidence.py" validate-base-bundle \
  --manifest "$base_images_manifest" \
  --archive "$base_images_archive" >/dev/null

build_root="$(mktemp -d "$work_parent/round8-host-images.XXXXXXXX")"
build_nonce="${build_root##*.}"
[[ "$build_nonce" =~ ^[A-Za-z0-9]{8}$ ]] || {
  printf '%s\n' 'cannot derive a unique Host image build identity' >&2
  exit 1
}
cleanup() {
  [[ -n "${build_root:-}" && -d "$build_root" && ! -L "$build_root" ]] || return 0
  rm -rf -- "$build_root"
}
trap cleanup EXIT

docker load --input "$base_images_archive" >"$build_root/base-image-load.log" 2>&1

admit_loaded_base() {
  local image="$1" expected_id="$2" identity
  identity="$(docker image inspect --format '{{.Os}}/{{.Architecture}} {{.Id}}' "$image")"
  [[ "$identity" == "linux/amd64 $expected_id" ]] || {
    printf 'loaded base image %s has identity %s, expected linux/amd64 %s\n' \
      "$image" "$identity" "$expected_id" >&2
    exit 1
  }
}

admit_loaded_base "$golang_local" "$golang_image_id"
admit_loaded_base "$debian_local" "$debian_image_id"

rewrite_cpa_dockerfile() {
  local source="$1" destination="$2"
  python3 -B - "$source" "$destination" "$cpa_dockerfile_sha256" \
    "$golang_local" "$debian_local" <<'PY'
import hashlib
import stat
import sys
from pathlib import Path

source, destination = map(Path, sys.argv[1:3])
expected_sha, golang_local, debian_local = sys.argv[3:]
info = source.lstat()
if not stat.S_ISREG(info.st_mode) or source.is_symlink():
    raise SystemExit("CPA Dockerfile must be a regular non-symlink")
raw = source.read_bytes()
if hashlib.sha256(raw).hexdigest() != expected_sha:
    raise SystemExit("CPA Dockerfile differs from the reviewed immutable source")
text = raw.decode("utf-8")
from_lines = [line for line in text.splitlines() if line.startswith("FROM ")]
expected = ["FROM golang:1.26-bookworm AS builder", "FROM debian:bookworm"]
if from_lines != expected or text.count(expected[0]) != 1 or text.count(expected[1]) != 1:
    raise SystemExit("CPA Dockerfile base stages differ from the reviewed contract")
rewritten = text.replace(expected[0], f"FROM {golang_local} AS builder").replace(
    expected[1], f"FROM {debian_local}"
)
with destination.open("x", encoding="utf-8", newline="\n") as output:
    output.write(rewritten)
PY
}

rewrite_mock_dockerfile() {
  local source="$1" destination="$2"
  python3 -B - "$source" "$destination" "$mock_dockerfile_sha256" \
    "$golang_canonical" "$golang_local" <<'PY'
import hashlib
import stat
import sys
from pathlib import Path

source, destination = map(Path, sys.argv[1:3])
expected_sha, canonical, golang_local = sys.argv[3:]
info = source.lstat()
if not stat.S_ISREG(info.st_mode) or source.is_symlink():
    raise SystemExit("counted-Mock Dockerfile must be a regular non-symlink")
raw = source.read_bytes()
if hashlib.sha256(raw).hexdigest() != expected_sha:
    raise SystemExit("counted-Mock Dockerfile differs from the reviewed immutable source")
text = raw.decode("utf-8")
expected = f"FROM {canonical} AS builder"
from_lines = [line for line in text.splitlines() if line.startswith("FROM ")]
if from_lines != [expected, "FROM scratch"] or text.count(expected) != 1:
    raise SystemExit("counted-Mock Dockerfile base stage differs from the reviewed contract")
rewritten = text.replace(expected, f"FROM {golang_local} AS builder")
with destination.open("x", encoding="utf-8", newline="\n") as output:
    output.write(rewritten)
PY
}

verify_cpa_image() {
  local image="$1" version="$2" commit="$3" build_date="$4"
  local os_name architecture source_label revision_label version_label created_label first_line
  local transport_label golang_source_label golang_platform_label golang_id_label
  local debian_source_label debian_platform_label debian_id_label
  os_name="$(docker image inspect --format '{{.Os}}' "$image")"
  architecture="$(docker image inspect --format '{{.Architecture}}' "$image")"
  source_label="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$image")"
  revision_label="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$image")"
  version_label="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$image")"
  created_label="$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.created"}}' "$image")"
  transport_label="$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.base-transport"}}' "$image")"
  golang_source_label="$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.golang.canonical-reference"}}' "$image")"
  golang_platform_label="$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.golang.platform-digest"}}' "$image")"
  golang_id_label="$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.golang.image-id"}}' "$image")"
  debian_source_label="$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.debian.canonical-reference"}}' "$image")"
  debian_platform_label="$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.debian.platform-digest"}}' "$image")"
  debian_id_label="$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.debian.image-id"}}' "$image")"
  [[ "$os_name" == linux && "$architecture" == amd64 ]]
  [[ "$source_label" == "$cpa_source" ]]
  [[ "$revision_label" == "$commit" ]]
  [[ "$version_label" == "$version" ]]
  [[ "$created_label" == "$build_date" ]]
  [[ "$transport_label" == "$base_transport" ]]
  [[ "$golang_source_label" == "$golang_canonical" ]]
  [[ "$golang_platform_label" == "$golang_platform_digest" ]]
  [[ "$golang_id_label" == "$golang_image_id" ]]
  [[ "$debian_source_label" == "$debian_canonical" ]]
  [[ "$debian_platform_label" == "$debian_platform_digest" ]]
  [[ "$debian_id_label" == "$debian_image_id" ]]
  first_line="$(docker run --rm --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges \
    --pids-limit 64 --memory 128m --memory-swap 128m --cpus 0.50 \
    --ulimit nofile=128:128 \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --entrypoint /CLIProxyAPI/CLIProxyAPI "$image" -h 2>/dev/null | sed -n '1p')"
  [[ "$first_line" == "CLIProxyAPI Version: $version, Commit: $commit, BuiltAt: $build_date" ]]
}

build_cpa_image() {
  local version="$1" commit="$2" destination="$3" source_dir dockerfile build_date fetched
  source_dir="$build_root/cpa-${version#v}"
  mkdir -- "$source_dir"
  env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    git -C "$source_dir" init --quiet
  env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null \
    git -C "$source_dir" remote add origin "$cpa_origin"
  env GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0 \
    git -C "$source_dir" -c protocol.file.allow=never fetch --quiet --depth=1 --no-tags \
      origin "refs/tags/$version"
  fetched="$(git -C "$source_dir" rev-parse FETCH_HEAD)"
  [[ "$fetched" == "$commit" ]] || {
    printf 'CPA tag %s resolved to %s, expected %s\n' "$version" "$fetched" "$commit" >&2
    exit 1
  }
  git -C "$source_dir" checkout --quiet --detach "$commit"
  [[ "$(git -C "$source_dir" rev-parse HEAD)" == "$commit" ]]
  [[ -z "$(git -C "$source_dir" status --porcelain)" ]]
  build_date="$(git -C "$source_dir" show -s --format=%cI HEAD)"
  [[ "$build_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}([.][0-9]+)?(Z|[+-][0-9]{2}:[0-9]{2})$ ]]
  dockerfile="$build_root/cpa-${version#v}.Dockerfile"
  rewrite_cpa_dockerfile "$source_dir/Dockerfile" "$dockerfile"
  docker build --pull=false --platform linux/amd64 \
    --memory 4g --memory-swap 4g --cpu-period 100000 --cpu-quota 200000 \
    --ulimit nofile=1024:1024 --shm-size 256m \
    --file "$dockerfile" \
    --build-arg "VERSION=$version" \
    --build-arg "COMMIT=$commit" \
    --build-arg "BUILD_DATE=$build_date" \
    --label "org.opencontainers.image.source=$cpa_source" \
    --label "org.opencontainers.image.revision=$commit" \
    --label "org.opencontainers.image.version=$version" \
    --label "org.opencontainers.image.created=$build_date" \
    --label "io.cyber-abuse-guard.round8.base-transport=$base_transport" \
    --label "io.cyber-abuse-guard.round8.golang.canonical-reference=$golang_canonical" \
    --label "io.cyber-abuse-guard.round8.golang.platform-digest=$golang_platform_digest" \
    --label "io.cyber-abuse-guard.round8.golang.image-id=$golang_image_id" \
    --label "io.cyber-abuse-guard.round8.debian.canonical-reference=$debian_canonical" \
    --label "io.cyber-abuse-guard.round8.debian.platform-digest=$debian_platform_digest" \
    --label "io.cyber-abuse-guard.round8.debian.image-id=$debian_image_id" \
    --tag "$destination" "$source_dir"
  verify_cpa_image "$destination" "$version" "$commit" "$build_date"
}

primary_image="cag-round8-cpa:${primary_version}-${primary_commit:0:12}-c${candidate_commit:0:12}-t${candidate_tree:0:12}-${build_nonce}"
mock_image="cag-round8-counted-mock:v1-c${candidate_commit:0:12}-t${candidate_tree:0:12}-${build_nonce}"
mock_dockerfile="$build_root/round8-counted-mock.Dockerfile"

build_cpa_image "$primary_version" "$primary_commit" "$primary_image"
rewrite_mock_dockerfile "$root/integration/round8countedmock/Dockerfile" "$mock_dockerfile"
docker build --pull=false --platform linux/amd64 \
  --memory 2g --memory-swap 2g --cpu-period 100000 --cpu-quota 100000 \
  --ulimit nofile=1024:1024 --shm-size 128m \
  --file "$mock_dockerfile" \
  --label "org.opencontainers.image.source=$candidate_source" \
  --label "org.opencontainers.image.revision=$candidate_commit" \
  --label "org.opencontainers.image.version=$candidate_tag" \
  --label "io.cyber-abuse-guard.source-tree=$candidate_tree" \
  --label "io.cyber-abuse-guard.round8.base-transport=$base_transport" \
  --label "io.cyber-abuse-guard.round8.golang.canonical-reference=$golang_canonical" \
  --label "io.cyber-abuse-guard.round8.golang.platform-digest=$golang_platform_digest" \
  --label "io.cyber-abuse-guard.round8.golang.image-id=$golang_image_id" \
  --tag "$mock_image" "$root/integration/round8countedmock"
[[ "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$mock_image")" == linux/amd64 ]]
[[ "$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.mock-contract"}}' "$mock_image")" == "$mock_contract" ]]
[[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.source"}}' "$mock_image")" == "$candidate_source" ]]
[[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' "$mock_image")" == "$candidate_commit" ]]
[[ "$(docker image inspect --format '{{index .Config.Labels "org.opencontainers.image.version"}}' "$mock_image")" == "$candidate_tag" ]]
[[ "$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.source-tree"}}' "$mock_image")" == "$candidate_tree" ]]
[[ "$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.base-transport"}}' "$mock_image")" == "$base_transport" ]]
[[ "$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.golang.canonical-reference"}}' "$mock_image")" == "$golang_canonical" ]]
[[ "$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.golang.platform-digest"}}' "$mock_image")" == "$golang_platform_digest" ]]
[[ "$(docker image inspect --format '{{index .Config.Labels "io.cyber-abuse-guard.round8.golang.image-id"}}' "$mock_image")" == "$golang_image_id" ]]
[[ "$(docker image inspect --format '{{.Id}}' "$mock_image")" =~ ^sha256:[0-9a-f]{64}$ ]]

printf 'PRIMARY_IMAGE=%s\n' "$primary_image"
printf 'MOCK_IMAGE=%s\n' "$mock_image"
