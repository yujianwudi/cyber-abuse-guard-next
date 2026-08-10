# Docker Sandbox Installation, Staged Rollout, Rollback, and Cleanup

> [!IMPORTANT]
> For Round 13, substitute only the exact Linux amd64 `v1.0.0-rc.1` candidate
> and CPA `v7.2.125@2e6b1d83f6c304a102aa33c1faf0a4f94d0d331e`. The Round 12
> v7.2.124 commands and hashes retained below are historical; they must not be
> used as current artifacts or PASS evidence. Production deployment remains
> outside this candidate runbook.

```text
current_classifier_policy_version: classifier-policy-v18
current_classifier_policy_sha256: 9f9541fe30a3b95aeb89fba0dc400fc8cdf89c4ad94880bc61bd4b1895036eaa
```

## Frozen historical Round 12 installation body

## Current source status

This checkout is the source-only `main` development line. No current
plugin release, production approval, or Balanced-mode admission is implied.
Historical `v0.15` and `v0.16-rc.*` assets are immutable evidence only; do not
reuse or relabel them as a build of the current source.

Linux amd64 and CPA v7.2.124
(`197f520426374e514218ed155933ac546c98d345`) are the only compatibility target.
C ABI 1 and RPC schema 2 are unchanged. The required upstream Linux amd64
asset SHA-256 is
`bb1597e5faa19bd67f4cecb88e14d6306f7f54bffdeedf2d0b973d7cfb5dc176`.
Runtime validation must use an isolated counted-Mock upstream with no real
Provider or account pool. A sandbox PASS is engineering evidence only and does
not replace independent source review or the external admission policy.

Development artifacts containing `-dirty` are test-only. Do not place them in
any production plugin directory. Do not enable Raw Capture merely to validate
the candidate, and never include a capture database in CI or release assets.

See [RELEASE_POLICY.md](RELEASE_POLICY.md) for the frozen release-policy
snapshot. [ROUND9_OPERATOR_ROLLOUT.md](ROUND9_OPERATOR_ROLLOUT.md) and
[ROUND9_EXECUTION_RECORD.md](reports/ROUND9_EXECUTION_RECORD.md) are historical
CPA v7.2.113 references, not the v7.2.124 execution protocol. Any v7.2.124 Host
run must create a newly versioned evidence lane rather than rewriting those
records. Later v0.15/Round 8 command sequences are also historical operations
references unless a future release-specific document explicitly supersedes
them.

## Host controls outside the Router boundary

Before any isolated Host validation, the owner must independently enforce:

- a path allowlist for local high-priority instruction files, including
  `model_instructions_file` and `AGENTS.md`;
- owner/mode and write-access checks that prevent ordinary business users from
  replacing those files;
- SHA-256 or signature binding at startup and before every reload;
- fixed audit records for instruction/configuration changes;
- human approval and pinned commit/hash for every remote instruction template;
- a versioned Provider schema allowlist that rejects or forcibly overwrites
  unsafe `safetySettings`, `generationConfig`, `options`, and equivalent
  controls before the request reaches the Router.

The Guard cannot attest to any of those pre-CPA files or configuration values.
Prompt-keyword scanning is not a substitute. Embedded ruleset `1.0.9` also
identifies only YAML Cyber Abuse assets; it does not include the Go
`META-OVERRIDE-001` overlay or the complete classifier/extractor policy.

## Preconditions

- Run the candidate bytes against CPA v7.2.124 built with `CGO_ENABLED=1`.
  Assets labelled `_no-plugin`
  cannot load native plugins. Source/compile compatibility does not substitute
  for loading the candidate `.so`. Earlier CPA checks are historical
  non-gating evidence.
- The container is Linux amd64 with glibc 2.34 or newer. Debian Bookworm is the
  intended base; musl/Alpine is unsupported.
- The deployment host has `curl`, `jq`, `python3`, `unzip`, `sha256sum`, and
  `openssl`.
- The CPA Management Key is available through a secret file for local health
  checks; do not place it on a shared command line.
- Back up CPA configuration, count CPA auth files, and record other enabled
  plugins before changing anything.
- Inspect Router priorities manually. `cyber-abuse-guard` should use priority
  300; no higher-priority Router may handle the same request first. Disable the
  obsolete `antigravity-coding-filter` after verifying this plugin. Routers at
  the same priority run by plugin ID ascending, so also inspect same-priority
  IDs for a lexicographically earlier handler.
- Exercise Multi-Agent v2 on `/v1/responses`. CPA v7.2.124 rewrites tool
  definitions before `RequestInterceptor`, so the Host evidence must bind the
  rewritten schema-2 envelope and prove tool-schema inertness, tool-call/result
  provenance, and allow/block behavior. Historical v7.2.116 CI,
  second-machine, and five-repository data do not satisfy this precondition.
- Only one `cyber-abuse-guard` `.so` may exist in the active plugin directory.
  CPA ABI v1 cannot enumerate ordering or detect duplicate versions for the
  plugin itself.

The release verifier rejects a binary that imports a glibc symbol newer than
`GLIBC_2.34`, has a wrong ELF target, lacks CPA ABI symbols, carries mismatched
build/ruleset identity, or has a checksum/SBOM/archive mismatch.

## Historical v0.15 download and verification reference

The commands below are retained to explain the older formal-release bundle
shape. They are not valid v0.16-rc.2 installation instructions and do not
authorize installing the current candidate:

```bash
set -eu
VERSION=0.15
STORE_ARCHIVE="cyber-abuse-guard_${VERSION}_linux_amd64.zip"
AUDIT_BUNDLE="cyber-abuse-guard-v${VERSION}-audit-bundle.zip"
EVIDENCE="release-evidence-final.md"
SOURCE="cyber-abuse-guard-v${VERSION}-source.tar.gz"
ROUND6_ATTESTATION="round6-prerelease-attestation.json"
FORMAL_ATTESTATION="formal-release-attestation.json"
RELEASE_BASE="${CYBER_ABUSE_GUARD_RELEASE_BASE:-https://github.com/yujianwudi/cyber-abuse-guard-next/releases/download/v${VERSION}}"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

curl -fL "$RELEASE_BASE/$STORE_ARCHIVE" -o "$work/$STORE_ARCHIVE"
curl -fL "$RELEASE_BASE/$AUDIT_BUNDLE" -o "$work/$AUDIT_BUNDLE"
curl -fL "$RELEASE_BASE/checksums.txt" -o "$work/checksums.txt"
curl -fL "$RELEASE_BASE/$EVIDENCE" -o "$work/$EVIDENCE"
curl -fL "$RELEASE_BASE/$EVIDENCE.sha256" -o "$work/$EVIDENCE.sha256"
curl -fL "$RELEASE_BASE/$SOURCE" -o "$work/$SOURCE"
curl -fL "$RELEASE_BASE/$SOURCE.sha256" -o "$work/$SOURCE.sha256"
curl -fL "$RELEASE_BASE/$ROUND6_ATTESTATION" -o "$work/$ROUND6_ATTESTATION"
curl -fL "$RELEASE_BASE/$ROUND6_ATTESTATION.sha256" -o "$work/$ROUND6_ATTESTATION.sha256"
curl -fL "$RELEASE_BASE/$FORMAL_ATTESTATION" -o "$work/$FORMAL_ATTESTATION"
curl -fL "$RELEASE_BASE/$FORMAL_ATTESTATION.sha256" -o "$work/$FORMAL_ATTESTATION.sha256"
(cd "$work" && \
  sha256sum -c "$EVIDENCE.sha256" && \
  sha256sum -c "$SOURCE.sha256" && \
  sha256sum -c "$ROUND6_ATTESTATION.sha256" && \
  sha256sum -c "$FORMAL_ATTESTATION.sha256")
(cd "$work" && grep -F "  $STORE_ARCHIVE" checksums.txt | sha256sum -c -)
(cd "$work" && grep -F "  $AUDIT_BUNDLE" checksums.txt | sha256sum -c -)
mkdir -p "$work/store" "$work/audit"
unzip -q "$work/$STORE_ARCHIVE" -d "$work/store"
unzip -q "$work/$AUDIT_BUNDLE" -d "$work/audit"
test "$(find "$work/store" -mindepth 1 -maxdepth 1 -type f -name '*.so' | wc -l)" -eq 1
test "$(find "$work/store" -mindepth 1 -maxdepth 1 | wc -l)" -eq 1
(cd "$work/audit/plugins/linux/amd64" && \
  sha256sum -c "cyber-abuse-guard-v${VERSION}.so.sha256")
cmp "$work/store/cyber-abuse-guard-v${VERSION}.so" \
  "$work/audit/plugins/linux/amd64/cyber-abuse-guard-v${VERSION}.so"
```

The store ZIP is deliberately minimal: its root contains exactly one `.so`.
The audit bundle is separate and must not be passed to CPA's plugin store.
The formal audit bundle and source archive exclude evaluation, Holdout, private,
blind, and retired material. They may contain only low-sensitivity attestation
identities and hashes, never the underlying evaluation/Holdout payloads.

Inspect `$work/audit/build-metadata.json` and require:

- `source_version` equals `0.15`;
- `dirty` is `false`;
- `commit` is a full 40-character release commit;
- `ruleset_version` and `ruleset_sha256` match the standalone ruleset manifest;
- historical v0.15 `classifier_policy_version` equals `classifier-policy-v5` and
  `classifier_policy_sha256` equals
`0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b`;
- `$work/release-evidence-final.md` identifies the same commit, annotated tag,
  rules snapshot, source archive, command-log digest, and artifact hashes.
- `$work/round6-prerelease-attestation.json` schema v2 binds the exact Host-tested
  candidate commit/tree, candidate run, SO/Store hashes, the CPA Host identity
  and evidence hash through `cpa_version`, `cpa_commit`, and `cpa_host_sha256`,
  the independent-audit hash, and an external `evaluation-v11` or later ID
  plus its low-sensitivity report SHA-256;
- `$work/formal-release-attestation.json` binds exact tag `v0.15`, the same
  commit/tree and candidate-attestation SHA-256, and the byte-compared formal
  SO/Store hashes.

Historical evaluation-v10 remains `CONSUMED / FAIL`, cannot be rerun, and must
not appear as the formal evaluation identity or as bundle content.

`checksums.txt` intentionally covers the eight reproducible core files: the
shared object, its sidecar, the CPA store ZIP, the audit bundle, build metadata,
ruleset manifest, ruleset sidecar, and SBOM. Run-specific command logs, final
evidence, and the source archive are outside both reproducible ZIPs and each has
its own SHA-256 sidecar; their hashes are also bound by the verified final
evidence document.

Do not bypass checksum validation for an internal mirror; set
`CYBER_ABUSE_GUARD_RELEASE_BASE` to the mirror directory that contains the same
files.

## 2. Prepare directories and record rollback state

Run from the deployment directory that contains `config.yaml` and the Compose
file:

```bash
set -eu
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 rollback/cyber-abuse-guard
cp -p config.yaml "rollback/cyber-abuse-guard/config.${stamp}.yaml"

mkdir -p plugins/linux/amd64
find plugins/linux/amd64 -maxdepth 1 -type f \
  -name 'cyber-abuse-guard*.so' -print \
  > "rollback/cyber-abuse-guard/active-binaries.${stamp}.txt"

# Record, but do not modify, the CPA auth inventory.
find "${CPA_AUTH_DIR:?set CPA_AUTH_DIR to the CPA auth directory}" \
  -maxdepth 1 -type f -print | sort \
  > "rollback/cyber-abuse-guard/auth-files.${stamp}.txt"
```

If a prior plugin exists, copy it to the rollback directory and remove it from
the active directory before installing v0.15. Do not leave a prior version and v0.15
active together:

```bash
old_so="$(find plugins/linux/amd64 -maxdepth 1 -type f \
  -name 'cyber-abuse-guard*.so' -print -quit)"
if [ -n "$old_so" ]; then
  cp -p "$old_so" "rollback/cyber-abuse-guard/"
  rm -f -- "$old_so"
fi
```

The rollback copy is outside CPA's plugin discovery directory.

## 3. Create a stable HMAC secret

Generate a regular mode-0600 file without printing the secret:

```bash
sudo install -d -m 0700 -o root -g root /opt/cliproxyapi/secrets
sudo ./scripts/generate-hmac-key.sh \
  /opt/cliproxyapi/secrets/cyber-abuse-guard-hmac.key
sudo chown root:root \
  /opt/cliproxyapi/secrets/cyber-abuse-guard-hmac.key
sudo stat -c '%a %U %G %F' \
  /opt/cliproxyapi/secrets/cyber-abuse-guard-hmac.key
```

The generator rejects an output directory that is not owned by the current
user, contains a symlink component, or is group/world writable. It never
overwrites an existing path and does not print the key. Expected mode is `600`.
The target must be a regular non-symlink file. Do not
commit it, copy it into a Docker build context, include it in a release archive,
print it, or put it in YAML. The plugin status exposes only stability/degraded
state and a one-way key identity, never the key.

v0.15 has no dual-key rotation implementation. Preserve this file for normal
upgrades and rollbacks. Changing it is an explicit subject-correlation reset;
with persistence enabled, a mismatch is reported and old state is not
overwritten.

## 4. Install the binary and data directory

Continue in the same shell where `$work` and `$VERSION` exist:

```bash
install -d -m 0755 plugins/linux/amd64
install -d -m 0700 plugin-data/cyber-abuse-guard
install -m 0755 \
  "$work/store/cyber-abuse-guard-v${VERSION}.so" \
  "plugins/linux/amd64/cyber-abuse-guard-v${VERSION}.so"

test "$(find plugins/linux/amd64 -maxdepth 1 -type f \
  -name 'cyber-abuse-guard*.so' | wc -l)" -eq 1
```

An existing audit directory must not be group/world writable. The database,
WAL, SHM, and final data directory must not be symlinks. Keep the entire path
outside attacker-controlled or same-user-writable ancestors.

The Linux readiness guard opens and records the data-directory and existing
DB/WAL/SHM device+inode identities, records the mount identity, rechecks after
SQLite opens, and probes them again for every authenticated status read. This
narrows replacement races but does not claim a complete same-UID TOCTOU fix:
the current Go SQLite driver does not provide this project a fd-relative custom
VFS/openat2 database open. Production must therefore keep every ancestor and
the mounted data directory outside an untrusted process sharing the plugin UID.

Mount code read-only, data read-write, and the HMAC file read-only:

```yaml
services:
  cli-proxy-api:
    volumes:
      - ./plugins:/CLIProxyAPI/plugins:ro
      - ./plugin-data/cyber-abuse-guard:/plugin-data/cyber-abuse-guard
      - /opt/cliproxyapi/secrets/cyber-abuse-guard-hmac.key:/run/secrets/cyber-abuse-guard-hmac.key:ro
    environment:
      CYBER_ABUSE_GUARD_HMAC_KEY_FILE: /run/secrets/cyber-abuse-guard-hmac.key
```

Some Compose secret mechanisms force mode 0444; this plugin intentionally
rejects that. Use a regular mode-0600 bind-mounted file or a secret runtime that
preserves the required permissions.

### Management request-body limit at the reverse proxy

CPA currently performs `io.ReadAll` in `ServeManagementHTTP` before invoking a
plugin management handler. The plugin's 1 MiB body limit and 2 MiB RPC-envelope
limit therefore do not bound CPA's HTTP-side memory use. Put the management
prefix behind a reverse-proxy limit, for example:

```nginx
location /v0/management/plugins/cyber-abuse-guard/ {
    client_max_body_size 1m;
    proxy_request_buffering on;
    proxy_pass http://cli-proxy-api:8317;
}
```

This is a deployment control, not a plugin-internal proof. The repository's
`make management-proxy-413-test` starts an isolated Nginx and counted CPA-handler
stub and is designed to assert an oversized request returns HTTP 413 with
handler count zero, followed by a small traversing control. Its authoritative
result must come from GitHub CI, and Leo must repeat the equivalent check in the
target deployment. Do not apply a 1 MiB limit
indiscriminately to model-request routes that intentionally support larger
bodies.

## 5. Configure Observe first

Add the three CPA controls at the document root, and merge the Guard stanza
from `config.example.yaml` below `plugins.configs`. Start with:

```yaml
# CPA top-level production request-log privacy controls. Keep these outside
# plugins; all three current values are checked by the production watchdog.
commercial-mode: true
request-log: false
logging-to-file: false

plugins:
  enabled: true
  dir: plugins
  configs:
    cyber-abuse-guard:
      enabled: true
      priority: 300
      mode: observe
      opaque_media_policy: audit
      subject_control:
        enabled: false
        persistence: false
        max_subjects: 10000
      audit:
        enabled: true
        data_dir: /plugin-data/cyber-abuse-guard
        require_persistent_storage: true
        backup_before_migration: true
        max_migration_backups: 3
        log_original_text: false
    antigravity-coding-filter:
      enabled: false
```

`log_original_text: true` is always rejected. There is no debug override.

Historical CPA v7.2.116 analysis established that `request-log: false` by itself
was not a raw-body logging boundary: an installed request-logging middleware
could still capture request bodies and retain an HTTP error-only log, including
a Guard block on a normal model route. The active v7.2.124 lane conservatively
retains `commercial-mode: true` as the startup control and must revalidate the
middleware behavior rather than relabel the v7.2.116 result.
`logging-to-file: false` keeps ordinary CPA application logs on stdout instead
of rotating files. The operational cost is the loss of CPA's detailed
request/error artifacts for incident diagnosis; use container stdout, plugin
status/counters, and the Guard's typed audit records instead.

The authenticated `/v0/management/config` response reports current values; it
does not report which middleware was installed at process start. After editing
the on-disk CPA configuration, recreate or restart CPA before validation. A hot
reload can change ordinary logging flags but cannot remove middleware that was
installed at startup.

Observe leaves subject control disabled, so requests are not correlated and no
cross-request risk is accumulated. If subject control is explicitly enabled in
a later Audit/Balanced stage, `persistence: false` means a restart clears risk,
cooldown, and manual-block state. To enable persistence later, keep audit
enabled, keep `max_subjects <= 10000`, and first verify `hmac_stable: true`.
Subject-state rows contain only HMAC IDs and typed state.

Authenticated local status exposes the persistence contract under `audit`:
`storage_type`, `persistence_expected`, `persistence_verified`,
`persistence_reason`, and `database_path`. The database path is operator data;
it is not returned by unauthenticated management responses or written into
request audit events. `enforcement_ready` remains true when classification can
still fail open around audit storage, while `operational_ready` is false whenever
required persistence is unverified. Raw capture and persistent subject control
are rejected unless `require_persistent_storage: true` is explicit and
`audit.data_dir` is an explicit absolute path.

## 6. Upgrade and database migration

The current source uses audit schema v6. A supported schema v1-v5 database is
migrated atomically to v6 only after a mandatory, exact mode-0400 SQLite Online
Backup is created as `events.db.pre-v6-*.bak`. Its adjacent manifest binds the
source/target schema versions, byte count, SHA-256, `quick_check: ok`, and
`exact_snapshot: true`; only the newest configured number is retained. Crossing
into v6 cannot be made backup-free by setting `backup_before_migration: false`,
because an older binary must be paired with the exact pre-v6 database.

Before restart, make a cold operator backup while CPA is stopped. Treat the
database and every present `-wal`/`-shm` sidecar as one consistency unit; never
copy only `events.db` from a live or incompletely stopped runtime. Archive the
complete data directory from one quiescent point:

```bash
docker compose stop cli-proxy-api
test -z "$(docker compose ps -q --status running cli-proxy-api)"
mkdir -p rollback/cyber-abuse-guard
archive="$(pwd -P)/rollback/cyber-abuse-guard/audit-data.${stamp}.tar.gz"
tar -C plugin-data -czpf \
  "$archive" \
  cyber-abuse-guard
sha256sum "$archive" >"${archive}.sha256"
tar -tzf "$archive" >/dev/null
docker compose up -d cli-proxy-api
```

Restore that cold archive only while CPA is stopped, replacing the complete
data directory as one unit. Do not mix an archived database with live WAL/SHM
sidecars, and do not retain a destination sidecar absent from the archive.
Schema-migration backups are different: they are verified standalone exact
SQLite Online Backup snapshots, so the documented schema rollback removes live
sidecars before installing exactly one backup whose manifest and SHA-256 have
been verified.

Migration failure must not partially advance the schema, but it can leave audit
degraded and must block promotion. Check status `audit.schema_version` and
`audit_degraded`. Older binaries are not claimed to read schema v6; restore the
matching exact pre-v6 database before loading an older binary.

## 7. Restart and baseline checks

```bash
# Recreate from the edited on-disk configuration. A hot reload is insufficient
# for commercial-mode because request middleware is selected at process start.
docker compose up -d --force-recreate cli-proxy-api
docker compose logs --since=2m cli-proxy-api \
  | grep -E 'plugin (loaded|registered)|cyber-abuse-guard'

CPA_MANAGEMENT_KEY_FILE=/run/secrets/cpa-management.key \
CPA_DIRECT_BASE_URL=http://127.0.0.1:8317 \
CPA_LOG_DIR=/absolute/path/to/the/cpa-runtime-log-root \
EXPECTED_MODE=observe \
./scripts/check-production-health.sh
```

`CPA_LOG_DIR` is mandatory and must be an existing, dedicated, empty absolute
directory visible from the watchdog. For the admitted production contract, CPA
must start with `WRITABLE_PATH` set to an absolute, dedicated directory and
`CPA_LOG_DIR` must name the host-visible side of that exact
`WRITABLE_PATH/logs` bind mount. Do not rely on the relative `./logs` fallback:
historical v7.2.116 analysis found that the request logger and management
inventory could resolve it against different roots, and the exact v7.2.124
lane must recheck that boundary. No path component may be a symlink.

`CPA_DIRECT_BASE_URL` is also mandatory. It must be the loopback HTTP/1.1
listener of this exact CPA process, not Nginx or another reverse proxy. The
usual in-container value is the same `http://127.0.0.1:<port>` used for
`CPA_BASE_URL`. The watchdog issues and confirms each challenge through
`CPA_BASE_URL`, but consumes it through the hidden ResourceRoute and reads the
CPA configuration/error-log inventory through `CPA_DIRECT_BASE_URL`. A run can
therefore succeed only when the initial/final status identity, both classifier
health probes, challenge issue, ResourceRoute response, and challenge
confirmation all report the same random 256-bit process identity. This rejects
a non-rewriting BASE proxy that routes status/proof to one instance but health
probes or only the startup-proof management path to another. Production ingress
must also be deployment-bound to that same CPA instance; health paths cannot
prove how an arbitrary external proxy routes ordinary `/v1` traffic. The
active resource proof deliberately marks its challenge header hop-by-hop; a
conforming intermediary removes that header, so a proxied path fails closed
instead of being mistaken for direct evidence.

CPA v7.2.124's unchanged ABI 1 cannot cryptographically identify the owning
listener
or detect a non-conforming same-host proxy that deliberately preserves the
hop-by-hop challenge header while normalizing lowercase `get` to uppercase
`GET`. Do not place such an intermediary on `CPA_DIRECT_BASE_URL`. The operator
must bind that URL to the real CPA listener/socket using container/network or
service-manager controls; loopback syntax alone is not proof of socket
ownership. A deployment that cannot establish this binding is outside the
admitted startup-privacy contract and the watchdog result must not be treated
as production evidence.

The watchdog mechanically binds `CPA_LOG_DIR` to CPA's authenticated management
error-log inventory:
it opens every path component without following symlinks, requires the root to
be empty, creates one unique mode-0600 `error-cag-watchdog-root-*.log` marker,
and requires CPA's authenticated `/v0/management/request-error-logs` inventory
to report that exact marker name and byte size. The watchdog retains the opened
directory and marker file descriptors through the probes and repeatedly
compares the held descriptors with the no-follow path device, inode, size, link
count, and mode. A missing or replaced marker fails closed and the watchdog
does not delete the replacement; only a name still resolving to the inode it
created is removed. Linux does not expose an atomic compare-and-unlink primitive
to Python, so the log root must not be writable by an untrusted same-UID
concurrent process. The final `stat`/`unlink` interval is not claimed to resist
such an actor.
The marker/inventory check is not the sole evidence that startup middleware is
absent. The incomplete-body proof below blocks before ResourceRoute dispatch
whenever CPA's pinned request-logging middleware is installed, independent of
where a relative logger path would write. The absolute `WRITABLE_PATH` contract
still removes the logger/inventory path ambiguity and makes the complete
artifact check meaningful.
Review and remove historical request/error artifacts before running this gate;
the watchdog never deletes artifacts it did not create.

The production watchdog defaults both cumulative restart-scoped budgets,
`MAX_ROUTER_ERRORS` and `MAX_PANICS_RECOVERED`, to zero. A reviewed non-zero
budget must be explicit. Audit, subject-persistence, or HMAC degradation cannot
be bypassed with an `ALLOW_*` switch; a red operational readiness signal stays
red.

The watchdog is loopback-only and does not mutate CPA configuration, accounts,
usage, or provider traffic. Its bounded process-local plugin mutation is two
random 30-second, one-time startup-proof challenges; the plugin admits at most
16 outstanding challenges. A status check before resource consumption returns
`409` without invalidating the challenge; a consumed confirmation deletes it,
and every unconsumed challenge expires after 30 seconds. The watchdog's sole filesystem
mutation is the exact temporary marker described above. Before its first plugin
health request,
it checks the authenticated CPA configuration and strictly requires the boolean
values `commercial-mode: true`, `request-log: false`, and
`logging-to-file: false`. It then checks CPA reachability, authenticated status,
enforcement and operational readiness, verified audit persistence, exact mode
and priority, build/ruleset identity, degradation, router/panic counters, and
two built-in local probes. The malicious probe never enters a provider route,
auth selector, usage queue, or upstream.

The malicious built-in probe is a `/v0/management` 403. Historical CPA v7.2.116
analysis found that management paths were skipped by request logging, so that
old 403 is not a v7.2.124 startup proof. Immediately afterward the watchdog
must verify the exact runtime headers for CPA `7.2.124` at commit `197f5204` and
use the authenticated CAG
management route on `CPA_BASE_URL` to issue two independent 256-bit challenges.
The initial status, both built-in classifier probes, each challenge response,
each ResourceRoute body, each confirmation, and the final status must carry one
unchanged random 256-bit plugin process identity. Each challenge is consumed through
`CPA_DIRECT_BASE_URL` by the hidden non-management resource
`/v0/resource/plugins/cyber-abuse-guard/health/startup-privacy-proof`, whose
fixed `418`, challenge header/body echo, and authenticated consumed status must
all agree; confirmation is then required from the issuing plugin through
`CPA_BASE_URL`. This cross-entry one-time challenge binds the two configured
request paths to one plugin process, subject to the listener-ownership and
non-conforming-proxy boundary above.
The complete request makes a stranded error-only logger produce an
artifact; the intentionally incomplete request fails closed if the stranded
middleware waits for the missing body. Historical CPA v7.2.113 accepted the raw
lowercase
`get` resource method case-insensitively while its request logger skips only
exact uppercase `GET`; the exact v7.2.124 source and Host contracts must recheck
rather than inherit that behavior. Timeouts
are reported only as inconclusive failures, never as proof that middleware was
detected. Both requests are local, contain no user prompt or credential, and
never enter `/v1`, an auth selector, usage accounting, a provider, or upstream.

`enforcement_ready` is the request-decision engine state; `operational_ready`
also requires the configured audit persistence contract and other local
readiness dependencies. Neither field alone proves the binary
was loaded/registered, was not fused, won Router ordering, or passed CPA's
per-request self-executor readiness checks. A missing plugin, registration
failure, fused plugin, Router error/panic, invalid or empty target, not-ready
executor, or earlier handled Router can cause CPA to continue routing.

The explicit Host harness is designed to make this boundary concrete with a
real pure-C second Router/executor. It asserts higher-priority bypass,
same-priority plugin-ID ordering, invalid/error/not-ready continuation, guard
  missing/registration failure/disabled behavior, and native fallback. It is not
  invoked by ordinary Round 6 CI. Panic/fuse remain covered only by the
checksum-pinned official-source Host overlay because ABI v1 cannot safely
inject those private Go states from a C plugin.

Also verify from the deployment environment:

```bash
# CPA remains authenticated: no client key must not list models.
test "$(curl -sS -o /dev/null -w '%{http_code}' \
  http://127.0.0.1:8317/v1/models)" = 401
```

Verify New API → CPA using an ordinary harmless request, confirm other plugins
still behave normally, and compare the current CPA auth-file list with the saved
inventory. Installation must not create, delete, or modify auth files.

Any newly versioned CPA v7.2.124 Host matrix must cover OpenAI Chat, OpenAI
Responses,
Claude, and Gemini allow/refusal paths, including streaming pre-SSE 403,
Anthropic/Gemini token-count 403, and zero Auth Selector, Provider, Usage, and
Mock Upstream counters for blocked requests. It must also cover the Multi-Agent
v2 `/v1/responses` tool-definition rewrite before `RequestInterceptor`.
Ordinary CI does not execute that
harness. Earlier implementation-freeze Host results are historical only; all
exact-candidate run and independent review remain `NOT RUN` before any
release decision.

`executor.http_request` is different: current tests reach the official
`ProviderExecutor.HttpRequest` adapter as `(nil, error)` with `StatusCode()==405`
and a project-owned `httptest.Server` that manually maps that error to HTTP.
The current CPA matrix exposes `POST /v1/alpha/search`, but its ordinary selection path
is fixed to `codex` and it maps every `HttpRequest` error to HTTP 502. No current
official public route maps Guard's status error to a final client 405. That
result is `NOT AVAILABLE / NOT RUN`, cannot be created by the current CI job,
and remains an explicit `BLOCKED FOR HANDOFF` item.

## Future Observe → Audit → Balanced rollout

**Do not execute this historical rollout for the current source line.** Dual
CPA counted-Mock Host evidence, independent audit, external admission, and
production approval are pending. These stages document a possible future
process only after a new versioned rollout contract binds all gates to the
exact unchanged candidate.

### Stage 1: Observe (24–48 hours)

Keep `mode: observe`. It never blocks and does not persist per-request audit
events. Monitor:

- request/classification counts and latency;
- CPU, memory, goroutines, and CPA 5xx;
- `router_errors` and `panics_recovered` deltas;
- `loaded`, `enforcement_ready`, `operational_ready`, an empty
  `readiness_reasons`, `ruleset_version_match`, and dirty build state;
- HMAC, audit, queue, and persistence degradation;
- opaque-media counts and expected traffic mix.

Abort if the plugin unloads, readiness is false, router/panic counters increase,
the build identity mismatches, or CPA availability regresses.

### Stage 2: Audit (24–48 hours)

Change only `mode: audit`, restart or use the supported CPA configuration path,
then run the watchdog with `EXPECTED_MODE=audit`. Review would-block events and
coarse categories. No raw prompt exists in the DB; use controlled local test
fixtures when adjudication needs text. Record every threshold or policy change
with timestamp, owner, reason, before/after values, and review result.

Keep `subject_control.enabled: false` during the first audit pass unless the
rollout explicitly includes reviewed cross-request correlation.

Do not send a dangerous probe through `/v1` to a real upstream. Use the built-in
management health probe or the repository's Mock Upstream integration test.

Abort on unexplained legitimate impact, database/queue degradation, growing
router/panic counters, or CPA 5xx increase.

### Stage 3: Balanced

After approval, set `mode: balanced`, keep `opaque_media_policy: audit` unless a
documented local risk decision says otherwise, restart, and run:

Subject control remains a separate opt-in. Enabling Balanced does not require
enabling cross-request risk accumulation.

```bash
CPA_MANAGEMENT_KEY_FILE=/run/secrets/cpa-management.key \
CPA_DIRECT_BASE_URL=http://127.0.0.1:8317 \
CPA_LOG_DIR=/absolute/path/to/the/cpa-runtime-log-root \
EXPECTED_MODE=balanced \
./scripts/check-production-health.sh
```

During the initial window check at least hourly:

- block count and category distribution;
- legitimate-user complaints and sampled adjudication records;
- CPA 4xx/5xx and upstream health;
- loaded/registered/readiness and Router/Panic deltas;
- SQLite size, queue dropped/failed/rejected counts, migration schema;
- HMAC and optional subject persistence health;
- opaque-media allowed/audited/blocked counters.

Do not promote directly to Strict. Strict requires a separate risk review of its
lower threshold and default opaque-media block behavior.

## 9. Shortest disable rollback

Set:

```yaml
cyber-abuse-guard:
  enabled: false
```

Then:

```bash
docker compose restart cli-proxy-api
```

Verify all of the following before declaring rollback complete:

- the plugin is not loaded/registered or reports `effective_enabled: false`;
- CPA root/health is normal;
- `/v1/models` without a key returns 401;
- New API can reach CPA with a harmless authenticated request;
- other plugins are normal;
- the CPA auth-file inventory is unchanged;
- no automation deleted or modified an upstream account.

Do not delete the audit database or HMAC secret as part of the fastest rollback.

## 10. Roll back to the previous binary and database

Stop CPA, remove the exact currently deployed candidate from the active
directory, restore exactly one previous `.so`, and restore its matching
configuration. If that binary cannot read schema v6, it must be paired with the
exact pre-v6 Online Backup named in its verified manifest:

```bash
set -eu
: "${CURRENT_PLUGIN_FILE:?set the exact active candidate filename}"
: "${PREVIOUS_PLUGIN_ROLLBACK_FILE:?set the exact reviewed rollback filename}"
: "${PREVIOUS_CONFIG_ROLLBACK_FILE:?set the exact reviewed config backup filename}"
case "$CURRENT_PLUGIN_FILE" in
  */*|*\\*) exit 64 ;;
  cyber-abuse-guard*.so) ;;
  *) exit 64 ;;
esac
case "$PREVIOUS_PLUGIN_ROLLBACK_FILE" in
  */*|*\\*) exit 64 ;;
  cyber-abuse-guard*.so) ;;
  *) exit 64 ;;
esac
case "$PREVIOUS_CONFIG_ROLLBACK_FILE" in
  */*|*\\*) exit 64 ;;
  config.*.yaml) ;;
  *) exit 64 ;;
esac
test -f "plugins/linux/amd64/$CURRENT_PLUGIN_FILE"
test -f "rollback/cyber-abuse-guard/$PREVIOUS_PLUGIN_ROLLBACK_FILE"
test -f "rollback/cyber-abuse-guard/$PREVIOUS_CONFIG_ROLLBACK_FILE"
docker compose stop cli-proxy-api
rm -f -- "plugins/linux/amd64/$CURRENT_PLUGIN_FILE"
install -m 0755 -- \
  "rollback/cyber-abuse-guard/$PREVIOUS_PLUGIN_ROLLBACK_FILE" \
  "plugins/linux/amd64/$PREVIOUS_PLUGIN_ROLLBACK_FILE"
cp -p -- \
  "rollback/cyber-abuse-guard/$PREVIOUS_CONFIG_ROLLBACK_FILE" \
  config.yaml

# Only for a full schema rollback after verifying the pre-v6 manifest,
# exact_snapshot=true, sqlite_quick_check=ok, and the backup SHA-256:
# rm -f -- plugin-data/cyber-abuse-guard/events.db-wal \
#   plugin-data/cyber-abuse-guard/events.db-shm
# install -m 0600 rollback/cyber-abuse-guard/events.db.pre-v6-REPLACE.bak \
#   plugin-data/cyber-abuse-guard/events.db

test "$(find plugins/linux/amd64 -maxdepth 1 -type f \
  -name 'cyber-abuse-guard*.so' | wc -l)" -eq 1
docker compose up -d cli-proxy-api
```

Run the previous version's matching health/integration procedure. Preserve the
same HMAC secret unless the rollback intentionally resets subject correlation.

## 11. Complete removal (explicit and destructive)

First complete the disable rollback and verify CPA without the plugin. Then stop
CPA and inspect every path before removal. These commands require an explicit
operator opt-in and never touch CPA auth files:

```bash
set -eu
: "${REMOVE_CYBER_ABUSE_GUARD:?set to YES only after backup and review}"
: "${CURRENT_PLUGIN_FILE:?set the exact active candidate filename}"
case "$CURRENT_PLUGIN_FILE" in
  */*|*\\*) exit 64 ;;
  cyber-abuse-guard*.so) ;;
  *) exit 64 ;;
esac
test "$REMOVE_CYBER_ABUSE_GUARD" = YES
test -f "plugins/linux/amd64/$CURRENT_PLUGIN_FILE"
if [ "${REMOVE_PLUGIN_DATA:-NO}" = YES ]; then
  test -d plugin-data/cyber-abuse-guard
fi
if [ "${REMOVE_HMAC_SECRET:-NO}" = YES ]; then
  sudo test -f /opt/cliproxyapi/secrets/cyber-abuse-guard-hmac.key
fi

docker compose stop cli-proxy-api
rm -f -- "plugins/linux/amd64/$CURRENT_PLUGIN_FILE"

# Remove the cyber-abuse-guard config block from config.yaml manually. Do not
# delete the global plugins section or another plugin's configuration.

if [ "${REMOVE_PLUGIN_DATA:-NO}" = YES ]; then
  rm -rf -- plugin-data/cyber-abuse-guard
fi

if [ "${REMOVE_HMAC_SECRET:-NO}" = YES ]; then
  sudo rm -f -- /opt/cliproxyapi/secrets/cyber-abuse-guard-hmac.key
fi

docker compose up -d cli-proxy-api
```

`REMOVE_PLUGIN_DATA=YES` deletes events, WAL/SHM, migration backups, and optional
subject persistence. `REMOVE_HMAC_SECRET=YES` permanently breaks correlation
with any retained HMAC subject IDs. Keep both unset unless retention and audit
requirements permit deletion.

Final removal checks are the same as rollback: plugin absent, CPA healthy,
unauthenticated `/v1/models` returns 401, New API connectivity works, other
plugins work, and CPA auth-file counts and hashes are unchanged.
