# Docker Sandbox Installation, Staged Rollout, Rollback, and Cleanup

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: 971d41d053473e68ff4b9f8bbe1c6e63753ac712ab570c54a27f594d7a6b318f
```

## Round 8 release warning

The current source version is `0.16`; the only Round 8 artifact target is the
Linux amd64 prerelease `v0.16-rc.2`. It must be published as non-latest and does
not authorize production deployment or Balanced mode. Stable `v0.16` does not
exist. The earlier local `v0.16-rc.1` package and all v0.15 procedures below are
historical evidence and must not be overwritten or reused as the Round 8
candidate.

Only isolated counted-Mock sandbox validation is in scope. The exact candidate
must be tested on CPA v7.2.95
(`f71ec0eb6776854457892452cf28c47f0d658251`) without a real Provider. A sandbox
PASS is engineering evidence only; independent source/artifact audit and the
external admission policy remain required before production canary discussion.

Development artifacts containing `-dirty` are test-only. Do not place them in
any production plugin directory. Do not enable Raw Capture merely to validate
the candidate, and never include a capture database in CI or release assets.

See [RELEASE_POLICY.md](RELEASE_POLICY.md) and
[ROUND8_RELEASE_READINESS.md](reports/ROUND8_RELEASE_READINESS.md) for the
authoritative current status. The command sequence later in this file is a
historical v0.15 operations reference unless a future release-specific document
explicitly supersedes it.

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

- Run the candidate bytes against CPA v7.2.95 built with `CGO_ENABLED=1`.
  Assets labelled `_no-plugin`
  cannot load native plugins. Source/compile compatibility does not substitute
  for loading the candidate `.so`. Earlier CPA checks are historical
  non-gating evidence.
- The container is Linux amd64 with glibc 2.34 or newer. Debian Bookworm is the
  intended base; musl/Alpine is unsupported.
- The deployment host has `curl`, `jq`, `unzip`, `sha256sum`, and `openssl`.
- The CPA Management Key is available through a secret file for local health
  checks; do not place it on a shared command line.
- Back up CPA configuration, count CPA auth files, and record other enabled
  plugins before changing anything.
- Inspect Router priorities manually. `cyber-abuse-guard` should use priority
  300; no higher-priority Router may handle the same request first. Disable the
  obsolete `antigravity-coding-filter` after verifying this plugin. Routers at
  the same priority run by plugin ID ascending, so also inspect same-priority
  IDs for a lexicographically earlier handler.
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

Mount code read-only, data read-write, and the HMAC file read-only:

```yaml
services:
  cli-proxy-api:
    volumes:
      - ./plugins:/CLIProxyAPI/plugins:ro
      - ./plugin-data:/root/.cli-proxy-api/plugins
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

Merge `config.example.yaml` below `plugins.configs`. Start with:

```yaml
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
        backup_before_migration: true
        max_migration_backups: 3
        log_original_text: false
    antigravity-coding-filter:
      enabled: false
```

`log_original_text: true` is always rejected. There is no debug override.

Observe leaves subject control disabled, so requests are not correlated and no
cross-request risk is accumulated. If subject control is explicitly enabled in
a later Audit/Balanced stage, `persistence: false` means a restart clears risk,
cooldown, and manual-block state. To enable persistence later, keep audit
enabled, keep `max_subjects <= 10000`, and first verify `hmac_stable: true`.
Subject-state rows contain only HMAC IDs and typed state.

## 6. Upgrade and database migration

At first v0.15 open, supported legacy databases are migrated atomically to
schema v3. With backup enabled, a consistent mode-0400
`events.db.pre-v3-*.bak` is created through SQLite `VACUUM INTO`; only the
newest configured number is retained.

Before restart, make a separate operator backup while CPA is stopped if the
database is business-critical:

```bash
docker compose stop cli-proxy-api
cp -p plugin-data/cyber-abuse-guard/events.db \
  "rollback/cyber-abuse-guard/events.${stamp}.db" 2>/dev/null || true
docker compose up -d cli-proxy-api
```

Migration failure must not partially advance the schema, but it can leave audit
degraded and must block promotion. Check status `audit.schema_version` and
`audit_degraded`. Older binaries are not claimed to read schema v3; restore the
matching pre-migration database when rolling the binary back.

## 7. Restart and baseline checks

```bash
docker compose restart cli-proxy-api
docker compose logs --since=2m cli-proxy-api \
  | grep -E 'plugin (loaded|registered)|cyber-abuse-guard'

CPA_MANAGEMENT_KEY_FILE=/run/secrets/cpa-management.key \
EXPECTED_MODE=observe \
./scripts/check-production-health.sh
```

The watchdog is read-only and loopback-only. It checks CPA reachability,
authenticated status, loaded/ready state, exact mode and priority, build/ruleset
identity, degradation, router/panic counters, and two built-in local probes. The
malicious probe never enters a provider route, auth selector, usage queue, or
upstream.

`enforcement_ready` is plugin-internal state only. It does not prove the binary
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

The CPA v7.2.95 Host matrix must cover OpenAI Chat, OpenAI Responses,
Claude, and Gemini allow/refusal paths, including streaming pre-SSE 403,
Anthropic/Gemini token-count 403, and zero Auth Selector, Provider, Usage, and
Mock Upstream counters for blocked requests. Ordinary CI does not execute that
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

**Do not execute this rollout for v0.16-rc.2.** Dual CPA counted-Mock Host
evidence, independent audit, external admission, and production approval are
pending. These stages document a possible future process only after all of
those gates bind the exact unchanged candidate.

### Stage 1: Observe (24–48 hours)

Keep `mode: observe`. It never blocks and does not persist per-request audit
events. Monitor:

- request/classification counts and latency;
- CPU, memory, goroutines, and CPA 5xx;
- `router_errors` and `panics_recovered` deltas;
- `loaded`, `enforcement_ready`, `ruleset_version_match`, and dirty build state;
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

Stop CPA, remove v0.15 from the active directory, restore exactly one previous
`.so`, restore the matching configuration, and—when moving back to v0.1.1—use
the saved pre-migration database:

```bash
set -eu
docker compose stop cli-proxy-api
rm -f -- plugins/linux/amd64/cyber-abuse-guard-v0.15.so
install -m 0755 \
  rollback/cyber-abuse-guard/cyber-abuse-guard-v0.1.1.so \
  plugins/linux/amd64/cyber-abuse-guard-v0.1.1.so
cp -p rollback/cyber-abuse-guard/config.REPLACE_WITH_STAMP.yaml config.yaml

# Only for a full schema rollback after operator review:
# rm -f -- plugin-data/cyber-abuse-guard/events.db-wal \
#   plugin-data/cyber-abuse-guard/events.db-shm
# install -m 0600 rollback/cyber-abuse-guard/events.REPLACE_WITH_STAMP.db \
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
test "$REMOVE_CYBER_ABUSE_GUARD" = YES

docker compose stop cli-proxy-api
rm -f -- plugins/linux/amd64/cyber-abuse-guard-v0.15.so

# Remove the cyber-abuse-guard config block from config.yaml manually. Do not
# delete the global plugins section or another plugin's configuration.

if [ "${REMOVE_PLUGIN_DATA:-NO}" = YES ]; then
  test -d plugin-data/cyber-abuse-guard
  rm -rf -- plugin-data/cyber-abuse-guard
fi

if [ "${REMOVE_HMAC_SECRET:-NO}" = YES ]; then
  sudo test -f /opt/cliproxyapi/secrets/cyber-abuse-guard-hmac.key
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
