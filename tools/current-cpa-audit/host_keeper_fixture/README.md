# Host admission Keeper fixture

This directory is the tracked, isolated Keeper/usage adapter for the RC3 Host
admission lane. It is not a production usage service and it must never be
connected to a real Provider, an OAuth store, a production database, or a
public/host-published port.

The source consumes only CPA v7.2.145's authenticated destructive endpoint
`GET /v0/management/usage-queue?count=100`. Every popped item must be the exact
successful internal provider `openai-compatible-current-cpa-counted-mock` /
model `current-cpa-audit-model` record with the counted-Mock token result
`5 + 3 = 8`. The CPA YAML display name remains `current-cpa-counted-mock`;
CPA v7.2.145 deliberately turns it into the prefixed internal executor/provider
identity before publishing usage. The fixture persists only:

- a sequence and monotonic `usage_records` count;
- an HMAC-SHA-256 event identity derived from the bounded CPA request ID;
- bounded poll/error counters and a SQLite health nonce.

It never persists a request or response body, API key, management key, control
token, request ID, usage payload, client metadata, or header. The HMAC key is
derived in memory from the run-random control token and is not stored. Invalid
or duplicate popped records fail the poller closed and are never counted. The
SQLite schema prevents counter rollback, event mutation, and event deletion.

There is intentionally no `/record` endpoint. Operator-authored records could
make an allow probe look successful without a real CPA/Mock execution and are
therefore outside this contract.

## Build and immutable source identity

The Dockerfile has no floating base. The operator supplies an audited
repository-qualified base image digest that already contains standard-library
Python 3.11+ and SQLite 3.37+, together with the tracked source digest:

```bash
BASE_IMAGE='registry.example.invalid/audited-python@sha256:<64-lowercase-hex>'
SOURCE_SHA256="$(sha256sum keeper_fixture.py | awk '{print $1}')"
test "$SOURCE_SHA256" = "$(awk '{print $1}' keeper_fixture.py.sha256)"

docker build --pull=false \
  --build-arg "KEEPER_BASE_IMAGE=$BASE_IMAGE" \
  --build-arg "KEEPER_SOURCE_SHA256=$SOURCE_SHA256" \
  --tag "local/cag-host-keeper:$RUN_ID" \
  .
```

The build rejects a base without `@sha256:<64 hex>`, rejects source/argument/
sidecar hash disagreement, installs no packages, and records the contract,
base identity, source path, and source SHA in image labels. The Host collector
must inspect those labels and independently copy out
`/opt/cag-host-keeper/keeper_fixture.py` from the selected image/container,
hash it, and compare it with both the approved config and the repository
sidecar. Merely trusting the tag or label is insufficient.

The local `:$RUN_ID` tag is only a build handle. If the runbook requires a
repository digest, push it to the approved private audit registry, inspect the
resulting `RepoDigests`, and put the exact `registry/name@sha256:<64 hex>` in
the Host config. Never synthesize a RepoDigest from the local tag or image ID.
The config also binds the separately reviewed base image RepoDigest. The
collector must require image label `cag.current-cpa-audit.base-image` to equal
that exact value and must reject any image whose entrypoint or command differs
from the Dockerfile's fixed standard-library invocation and port/database
arguments. Keeper image ref, image ID, base ref, source path, and source SHA
remain explicit in portable admission identities; the tracked-source hash alone
does not attest the runtime image.

## Isolated runtime contract

The image declares numeric user `65532:65532`; the operator still controls and
must verify all runtime hardening. A representative shape is:

```bash
AUDIT_UID="$(id -u)"
AUDIT_GID="$(id -g)"

docker run --detach --name "$RUN_ID-host-keeper" \
  --network "$RUN_ID-host-net" \
  --network-alias keeper \
  --label "cag.current-cpa-audit.run=$RUN_ID" \
  --label 'cag.current-cpa-audit.role=host-admission-keeper' \
  --user "$AUDIT_UID:$AUDIT_GID" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --restart no --pids-limit 64 --memory 128m --cpus 0.50 \
  --cpuset-cpus "$AUDIT_CPUSET" \
  --tmpfs "/tmp:rw,noexec,nosuid,nodev,size=8m,uid=$AUDIT_UID,gid=$AUDIT_GID,mode=0700" \
  --tmpfs "/var/lib/cag-host-keeper:rw,noexec,nosuid,nodev,size=64m,uid=$AUDIT_UID,gid=$AUDIT_GID,mode=0700" \
  --mount type=bind,src="$SECRETS_DIR/control-token",dst=/run/secrets/control-token,readonly \
  --mount type=bind,src="$SECRETS_DIR/cpa-management-key",dst=/run/secrets/cpa-management-key,readonly \
  --env "CAG_KEEPER_RUN_ID=$RUN_ID" \
  --env 'CAG_KEEPER_CPA_ORIGIN=http://cpa:8317' \
  --env "CAG_KEEPER_EXPECTED_MODE=$EXPECTED_MODE" \
  --env "CAG_KEEPER_EXPECTED_CAG_COMMIT=$CAG_COMMIT" \
  --env 'CAG_KEEPER_CONTROL_TOKEN_FILE=/run/secrets/control-token' \
  --env 'CAG_KEEPER_CPA_MANAGEMENT_KEY_FILE=/run/secrets/cpa-management-key' \
  "$KEEPER_IMAGE"
```

The Dockerfile's final `USER 65532:65532` is a non-root safe default for a bare
run. The admission run deliberately overrides it with the same non-root audit
UID/GID used by CPA and counted-Mock so the collector can bind one exact Host
owner identity. The tracked source and hash sidecar are public code artifacts
with modes 0555/0444, so that override can read them; neither is a secret.

The actual runbook must additionally prove that the named Docker network is an
internal, non-attachable IPv4 bridge; the CPA, Keeper, and counted-Mock are its
only run-owned members; every role has zero host ports; CPA configuration has
exactly one `http://mock:18080/v1` compatibility provider; real Provider/OAuth/
proxy configuration is absent; the SQLite directory is a fresh run-owned
tmpfs; and all three containers have restart count zero and OOM false. Do not
pass either secret on a command line or put it into an evidence file.

Start counted-Mock and CPA first, wait until CPA root/models/CAG readiness and
the isolated runtime configuration all pass, and only then start Keeper. A
usage-queue transport/schema failure is intentionally fatal for that Keeper
process; it does not silently recover and erase the fact that destructive
`PopOldest` acquisition may have become inconclusive. Use a new run ID and a
fresh database after such a failure.

Before `docker run`, create `$SECRETS_DIR` without symlink traversal, owned by
`$AUDIT_UID:$AUDIT_GID`, and mode 0700. Write each run-random secret without
shell command-line expansion (for example from the collector's in-memory
random bytes) as a distinct `$AUDIT_UID:$AUDIT_GID`-owned, single-link regular
file with mode 0400 or 0600. The in-container
secret reader rejects relative paths, symlinked parents/files, hard links,
wrong UID/GID, any group/world permission, and files outside 32–4096 UTF-8
bytes. The direct environment form exists for bounded unit harnesses; the Host
runbook uses only `_FILE`. Docker inspection/evidence may record the `_FILE`
paths but must prove that neither secret value appears in container environment,
argv, labels, logs, config, SQLite, or collected evidence.

## Exact HTTP interface

All responses are canonical compact JSON with `Cache-Control: no-store`. Query
strings, unexpected bodies, duplicate JSON keys, non-finite numbers, extra
fields, unsupported methods, and oversized bodies are rejected.

### `GET /keeper/healthz`

No credential is sent. A 200 response is possible only after at least one real
successful usage-queue poll and while every current probe passes:

```json
{
  "checks": {
    "cag_status": true,
    "cpa_root": true,
    "cpa_unauthorized_models": true,
    "poller": true,
    "sqlite_quick_check": "ok",
    "sqlite_writable": true,
    "usage_records": 0
  },
  "schema": "cag-current-cpa-host-keeper/v1",
  "state": "healthy"
}
```

`cpa_root` is a private-network `GET /` with status 200.
`cpa_unauthorized_models` is a private-network `GET /v1/models` with no
Authorization header and status 401. `cag_status` is the authenticated CAG
status endpoint bound to CPA v7.2.145, the exact CAG commit and expected mode,
ready enforcement/operations, healthy schema-7 persistence, no degraded state,
zero audit dropped/failed/rejected counters, and Raw Capture disabled, combined
with an authenticated runtime-config check:
usage statistics enabled, exactly one `current-cpa-counted-mock` provider and
model, private `http://mock:18080/v1`, and no proxy or real-Provider key sets.
The four CPA probes run concurrently with a 0.5-second per-probe hard bound so
an unhealthy peer cannot stall the Host sample clock. SQLite must accept a real write and return only
`quick_check=ok`. Any failure returns the same bounded shape with state
`unhealthy` and HTTP 503; it never emits the failed response body or secret.

### `GET /keeper/stats`

Requires exactly `Authorization: Bearer <run-random-control-token>` and has no
request body. HTTP 200 has exactly:

```json
{
  "duplicate_records": 0,
  "invalid_records": 0,
  "last_sequence": 0,
  "observation_source": "CPA_AUTHENTICATED_POP_OLDEST",
  "poll_cycles": 1,
  "poll_errors": 0,
  "request_body_retention": false,
  "run_id": "round17-host-example",
  "schema": "cag-current-cpa-host-keeper/v1",
  "usage_payload_retention": false,
  "usage_records": 0
}
```

`usage_records` and `last_sequence` are persistent and equal. They can only
increase after the fixture itself pops and validates a real CPA usage record.
Any poll/validation/duplicate error makes health fail closed.

### `POST /keeper/reset`

Requires the same control header, `Content-Type: application/json`, and an
exact body of at most 1024 bytes:

```json
{"expected_usage_records":0,"run_id":"round17-host-example","schema":"cag-current-cpa-host-keeper/v1"}
```

This endpoint is a fresh-state assertion, not a mutation. It returns 200 only
when the same run database still contains zero usage observations. Once any
record exists it returns `409 rollback_forbidden`, leaving the count unchanged.

## Collector allow/block side-effect proof

The collector must never derive an allow result from Keeper alone. For each
representative probe, it snapshots CAG counters, counted-Mock counters, and the
authenticated Keeper stats before the request; sends exactly one real request
through the CPA private bridge; waits for all asynchronous counters to settle;
and snapshots the same sources again.

- An allow requires HTTP 200; CAG before/after/complete/router/executor deltas
  exactly one; counted-Mock auth/mock/provider deltas exactly one; and Keeper
  `usage_records` delta exactly one. The Keeper event can only originate from
  the real CPA PopOldest queue.
- A block requires HTTP 403 and zero delta for every CAG downstream callback,
  counted-Mock counter, and Keeper `usage_records`, including a bounded quiet
  window after the response.

The collector also requires `poll_errors=invalid_records=duplicate_records=0`,
`last_sequence=usage_records`, healthy HTTP 200 throughout both Host windows,
and a final SQLite `quick_check=ok`. A count rollback, jump larger than the real
allow count, stale health, duplicate event, queue parse error, or attempted use
of a nonexistent `/record` endpoint invalidates the run. Evidence stores only
the integer snapshots/deltas and fixed identities, never the request, CPA usage
payload, control token, or management credential.

At teardown, stop the Keeper, perform its bounded WAL checkpoint, copy only the
approved SQLite integrity/count receipt if the admission contract requires it,
remove the exact run-owned tmpfs/container/network/secrets, and prove absence.
Never run a global Docker prune.
