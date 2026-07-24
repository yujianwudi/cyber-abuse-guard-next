#!/bin/bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
unset BASH_ENV CDPATH ENV GLOBIGNORE PYTHONHOME PYTHONPATH
for command_name in id uname install mktemp python3 rm sha256sum stat awk chmod; do
  unset -f "$command_name" 2>/dev/null || true
done
hash -r

if [[ "$(id -u)" != 0 ]]; then
  printf '%s\n' 'install.sh must run as root' >&2
  exit 1
fi
if [[ "$(uname -s)/$(uname -m)" != Linux/x86_64 ]]; then
  printf '%s\n' 'Round 9 external evaluator supports Linux amd64 only' >&2
  exit 1
fi
if [[ "$#" != 4 || "$1" != --config || "$3" != --adapter-config ]]; then
  printf 'usage: %s --config /root/reviewed-broker.json --adapter-config /root/reviewed-adapter.json\n' "$0" >&2
  exit 2
fi

source_dir="$(cd "${BASH_SOURCE[0]%/*}" && pwd -P)"
repository_root="$(cd "$source_dir/../.." && pwd -P)"
config_source="$2"
adapter_config_source="$4"
[[ "$config_source" == /* && -f "$config_source" && ! -L "$config_source" ]]
[[ "$adapter_config_source" == /* && -f "$adapter_config_source" && ! -L "$adapter_config_source" ]]

for command in install mktemp python3 rm sha256sum stat; do
  command -v "$command" >/dev/null
done

core_source="$source_dir/round9_eval_core.py"
evaluator_source="$source_dir/cag_round9_external_evaluator.py"
broker_source="$source_dir/cag_round9_eval_broker.py"
adapter_source="$source_dir/cag_round9_cpa_sandbox_adapter.py"
docker_sandbox_source="$repository_root/scripts/round9_docker_sandbox.py"
for source in \
  "$core_source" \
  "$evaluator_source" \
  "$broker_source" \
  "$adapter_source" \
  "$docker_sandbox_source"; do
  [[ -f "$source" && ! -L "$source" ]]
done

# Snapshot every reviewed input exactly once into a root-only directory before
# hashing, compiling, validating, or installing it.  All later operations use
# only these immutable-by-permission snapshots, closing the check/use race that
# would otherwise exist if a writable checkout path changed after validation.
staging_dir="$(mktemp -d /tmp/cag-round9-install.XXXXXXXX)"
chmod 0700 "$staging_dir"
cleanup_staging() {
  case "$staging_dir" in
    /tmp/cag-round9-install.*) rm -rf -- "$staging_dir" ;;
    *) printf '%s\n' 'refusing to remove an unexpected installer staging path' >&2 ;;
  esac
}
trap cleanup_staging EXIT

python3 -I -B - \
  "$staging_dir" \
  "$config_source" broker-config.json private \
  "$adapter_config_source" adapter-config.json private \
  "$core_source" round9_eval_core.py source \
  "$evaluator_source" cag_round9_external_evaluator.py source \
  "$broker_source" cag_round9_eval_broker.py source \
  "$adapter_source" cag_round9_cpa_sandbox_adapter.py source \
  "$docker_sandbox_source" round9_docker_sandbox.py source <<'PY'
import os
from pathlib import Path
import stat
import sys


def snapshot(source: str, destination: Path, role: str) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(source, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise SystemExit(f"installer input is not a regular file: {source}")
        if metadata.st_size <= 0 or metadata.st_size > 4_194_304:
            raise SystemExit(f"installer input is empty or exceeds the reviewed bound: {source}")
        if role == "private" and (
            metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise SystemExit(
                f"reviewed installer configuration must be root-owned and private: {source}"
            )
        output_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        output = os.open(destination, output_flags, 0o600)
        try:
            remaining = metadata.st_size
            while remaining:
                chunk = os.read(descriptor, min(1_048_576, remaining))
                if not chunk:
                    raise SystemExit(f"installer input changed while being snapshotted: {source}")
                view = memoryview(chunk)
                while view:
                    written = os.write(output, view)
                    view = view[written:]
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise SystemExit(f"installer input grew while being snapshotted: {source}")
            os.fchmod(output, 0o600)
            os.fsync(output)
        finally:
            os.close(output)
    finally:
        os.close(descriptor)


root = Path(sys.argv[1])
arguments = sys.argv[2:]
if len(arguments) % 3:
    raise SystemExit("installer snapshot argument contract is invalid")
for index in range(0, len(arguments), 3):
    source, name, role = arguments[index : index + 3]
    if role not in {"private", "source"} or Path(name).name != name:
        raise SystemExit("installer snapshot identity is invalid")
    snapshot(source, root / name, role)
PY

config_source="$staging_dir/broker-config.json"
adapter_config_source="$staging_dir/adapter-config.json"
core_source="$staging_dir/round9_eval_core.py"
evaluator_source="$staging_dir/cag_round9_external_evaluator.py"
broker_source="$staging_dir/cag_round9_eval_broker.py"
adapter_source="$staging_dir/cag_round9_cpa_sandbox_adapter.py"
docker_sandbox_source="$staging_dir/round9_docker_sandbox.py"

for source in \
  "$core_source" \
  "$evaluator_source" \
  "$broker_source" \
  "$adapter_source" \
  "$docker_sandbox_source"; do
  python3 -I -B -m py_compile "$source"
done

# Parse both reviewed configurations with duplicate-key rejection before any
# authoritative file is installed.  Bind every installed component, including
# the shared core and Docker locality verifier, to the reviewed SHA-256 values.
python3 -I -B - \
  "$config_source" "$adapter_config_source" \
  "$broker_source" "$core_source" "$evaluator_source" "$adapter_source" \
  "$docker_sandbox_source" <<'PY'
import hashlib
import json
from pathlib import Path
import re
import sys


def duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise SystemExit(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"), object_pairs_hook=duplicate_keys)


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


broker_config_path, adapter_config_path, broker, core, evaluator, adapter, helper = sys.argv[1:]
config = load(broker_config_path)
adapter_config = load(adapter_config_path)
if set(config) != {"schema", "repository", "github", "paths", "identities", "signing", "corpus", "sandbox"}:
    raise SystemExit("broker configuration top-level keys are not exact")
if config["schema"] != "round9-eval-broker-config/v1":
    raise SystemExit("broker configuration schema differs")
if adapter_config.get("schema") != "round9-cpa-sandbox-adapter-config/v1":
    raise SystemExit("sandbox adapter configuration schema differs")
identities = config["identities"]
expected_hashes = {
    "broker_sha256": digest(broker),
    "core_sha256": digest(core),
    "evaluator_sha256": digest(evaluator),
    "sandbox_adapter_sha256": digest(adapter),
    "docker_sandbox_sha256": digest(helper),
    "sandbox_adapter_config_sha256": digest(adapter_config_path),
}
for key, actual in expected_hashes.items():
    expected = identities.get(key)
    if not isinstance(expected, str) or re.fullmatch(r"[0-9a-f]{64}", expected) is None:
        raise SystemExit(f"configured {key} is not lowercase SHA-256")
    if expected != actual:
        raise SystemExit(f"configured {key} does not match the reviewed source")
paths = config["paths"]
fixed = {
    "broker": "/usr/local/libexec/cag-round9-eval-broker",
    "core": "/usr/local/libexec/round9_eval_core.py",
    "evaluator": "/usr/local/libexec/cag-round9-external-evaluator",
    "sandbox_adapter": "/usr/local/libexec/cag-round9-cpa-sandbox",
    "docker_sandbox": "/usr/local/libexec/cag-round9-docker-sandbox",
    "sandbox_adapter_config": "/etc/cag-round9-eval-broker/sandbox-adapter.json",
}
for key, expected in fixed.items():
    if paths.get(key) != expected:
        raise SystemExit(f"configuration does not use fixed {key} path")
if adapter_config.get("docker_sandbox") != fixed["docker_sandbox"]:
    raise SystemExit("adapter configuration does not use the fixed Docker locality verifier")
if adapter_config.get("docker_sandbox_sha256") != identities["docker_sandbox_sha256"]:
    raise SystemExit("adapter configuration Docker locality verifier digest differs")
for key in ("sandbox_id", "daemon_id", "probe_image_id", "cpa_image_id", "counted_mock_image_id", "model", "scan_limit_bytes"):
    if adapter_config.get(key) != config["sandbox"].get(key):
        raise SystemExit(f"adapter/broker sandbox identity differs at {key}")
if config.get("repository") != "yujianwudi/cyber-abuse-guard-next":
    raise SystemExit("broker configuration does not bind the successor repository")
ruleset_id = config["github"].get("ledger_ruleset_id")
if type(ruleset_id) is not int or ruleset_id <= 0:
    raise SystemExit("broker configuration ledger ruleset ID must be a positive integer")
if config["github"].get("ledger_ruleset_name") != "round9-eval-ledger-immutable":
    raise SystemExit("broker configuration does not bind the live protected ledger ruleset")
PY

install -d -o root -g root -m 0755 /usr/local/libexec
install -d -o root -g root -m 0700 \
  /etc/cag-round9-eval-broker \
  /var/lib/cag-round9-eval-broker \
  /var/lib/cag-round9-eval-broker/work \
  /var/lib/cag-round9-eval-broker/state \
  /var/lib/cag-round9-eval-broker/corpus
install -d -o root -g root -m 0755 /var/lib/cag-round9-eval-broker/public
install -o root -g root -m 0644 \
  "$core_source" \
  /usr/local/libexec/round9_eval_core.py
install -o root -g root -m 0755 \
  "$evaluator_source" \
  /usr/local/libexec/cag-round9-external-evaluator
install -o root -g root -m 0755 \
  "$broker_source" \
  /usr/local/libexec/cag-round9-eval-broker
install -o root -g root -m 0755 \
  "$adapter_source" \
  /usr/local/libexec/cag-round9-cpa-sandbox
install -o root -g root -m 0755 \
  "$docker_sandbox_source" \
  /usr/local/libexec/cag-round9-docker-sandbox
install -o root -g root -m 0600 \
  "$config_source" \
  /etc/cag-round9-eval-broker/config.json
install -o root -g root -m 0600 \
  "$adapter_config_source" \
  /etc/cag-round9-eval-broker/sandbox-adapter.json

python3 -I -B -m py_compile \
  /usr/local/libexec/round9_eval_core.py \
  /usr/local/libexec/cag-round9-external-evaluator \
  /usr/local/libexec/cag-round9-eval-broker \
  /usr/local/libexec/cag-round9-cpa-sandbox \
  /usr/local/libexec/cag-round9-docker-sandbox

for installed in \
  /usr/local/libexec/round9_eval_core.py \
  /usr/local/libexec/cag-round9-external-evaluator \
  /usr/local/libexec/cag-round9-eval-broker \
  /usr/local/libexec/cag-round9-cpa-sandbox \
  /usr/local/libexec/cag-round9-docker-sandbox \
  /etc/cag-round9-eval-broker/sandbox-adapter.json; do
  printf 'installed %s sha256=%s\n' "$installed" "$(sha256sum "$installed" | awk '{print $1}')"
done
printf '%s\n' 'Provision evaluator keys, author public key, age bundle/identity, root PAT and pinned images separately; author private key stays offline.'
