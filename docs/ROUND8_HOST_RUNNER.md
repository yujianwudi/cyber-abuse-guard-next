# Round 8 Linux Host evidence runner

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: e0cbc975c126a12649a1b8e309e4e2a95efc64e46346467771ecae61b3e14971
```

`round8-host-validation.yml` is the only publication-admissible producer of
`round8-host-evidence.json` for the `v0.16-rc.2` Phase 2 release workflow.
`scripts/round8-host-evidence.sh` is its Linux-amd64 execution engine, but output
from a manual shell invocation is not release evidence because it lacks the
protected workflow run identity and GitHub signer attestation. The workflow does
not SSH to a server, inspect an existing CPA deployment, reuse an existing
container, or contact a real model Provider.

The runner consumes exactly the complete 17-file Phase 1 asset set: standalone
SO and sidecar, Store ZIP, audit-bundle ZIP, build metadata, `checksums.txt`,
ruleset manifest and digest, SBOM, test summary and sidecar, release evidence
and sidecar, source archive and sidecar, and RC manifest and sidecar. Missing,
extra, empty, oversized, non-regular, or symlink assets are rejected. The eight
entries emitted by Phase 1 into `checksums.txt` are required in their exact
order and each digest is recomputed. Phase 1 does not publish a separate Store
ZIP sidecar, so the Store ZIP is bound by `checksums.txt` and by byte equality
between its internal SO and the standalone SO. It rejects evaluation/holdout
material, unsafe archive paths, and release commit/tree drift. Restricted path
components containing `evaluation`, `holdout`, `consumed`, `private`, `blind`,
or `retired` are all rejected. The SO loaded by the Host execution is extracted from that
exact Store ZIP, installed only at
`plugins/linux/amd64/cyber-abuse-guard-v0.16-rc.2.so`, and never rebuilt on the
Host.

## Fixed Host target

The only release-admissible CPA identity is closed, not a moving alias:

| CPA version | Commit |
|---|---|
| `v7.2.95` | `f71ec0eb6776854457892452cf28c47f0d658251` |

The repository-supported image builder fetches that exact official Git tag,
requires it to resolve to the commit above, and builds the checked-out commit
with deterministic `VERSION`, `COMMIT`, and commit-time `BUILD_DATE` values.
Each resulting image must be `linux/amd64`; its OCI `source`, `revision`,
`version`, and `created` labels are exact and mandatory. The runner also
requires the binary's first line to equal all three embedded values byte for
byte. It resolves and starts the immutable local image ID, not the mutable tag.
The counted-Mock image is separately bound to the Guard repository source,
candidate revision, `v0.16-rc.2` tag, candidate tree, private contract, and
immutable image ID. The builder gives both images a fresh
invocation-unique tag containing candidate commit/tree prefixes and prints
those exact tags for the runner. It never relies on a shared `latest` or
reusable `v1` tag.

The reviewed base-image supply chain is also closed:

| Upstream `FROM` | Canonical Docker Official Image | Linux-amd64 manifest | Image ID |
|---|---|---|---|
| `golang:1.26-bookworm` | `docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b` | `sha256:5a94593d87a066df5abb02969be911524963f53908292aa5a1a6096fc019012a` | `sha256:9d9d715d688ced62374388302667e31a6d3a0655c4c9e0ceaf1a4c4886752a62` |
| `debian:bookworm` | `docker.io/library/debian:bookworm-20260623@sha256:30482e873082e906a4908c10529180aefb6f77620aea7404b909829fadc5d168` | `sha256:129588494497601baa5dbca1df687c835ff166ec4dd3bf307be684f34da07ab5` | `sha256:ee37b64a84a5a803ef11061304de62741b41b1f1b9e2a743b1e7686b12029d79` |

The GitHub-hosted supply-chain job contacts Docker Hub directly, hashes the raw
multi-platform index and selected Linux-amd64 manifest, verifies the manifest's
config digest against the expected image ID, pulls by the immutable index
digest, and verifies the loaded OS, architecture, and image ID. It then saves
only the two reviewed local tags, writes a canonical closed manifest and archive
sidecar, attests all three files from the tagged workflow commit, and relays the
bundle as an exact GitHub Actions artifact.

The protected Tencent Host never pulls a base image from Docker Hub, a registry
mirror, or the production Docker daemon. It downloads the exact same-run GitHub
artifact by ID, verifies the artifact digest and GitHub provenance, validates
the closed manifest plus archive SHA-256/size, loads it into the isolated
rootless daemon, and requires both local image IDs to match before any build.
The builder accepts only the reviewed CPA and Mock Dockerfile hashes, rewrites
only their exact `FROM` lines to those admitted local tags, and uses
`docker build --pull=false`. The resulting CPA/Mock images carry and are checked
for the canonical base reference, platform digest, image ID, and attested-bundle
transport labels. This is the immutable equivalent of `--pull`; the rootless
Host cannot silently fall back to a mutable tag or an unreviewed proxy.

The single primary Host execution proves, from counted observations:

- Chat Completions and Responses benign allow / malicious local block;
- all 42 synthetic benign fixtures allow and all 42 paired malicious mutations
  block;
- benign and malicious Chat/Responses in both stream and non-stream transport;
- valid non-stream Chat/Responses objects and usage, valid SSE frame shapes,
  Chat's terminal `[DONE]`, and Responses' terminal `response.completed` event;
- Audit, Balanced, and Strict mode behavior;
- the same valid benign JSON request larger than the fixed 16,384-byte text
  window and cumulative-text limits: Balanced incomplete allow and Strict
  incomplete block;
- one usage-queue record for an allowed request and none for a local block;
- benign and malicious tool-schema ownership boundaries in both protocols;
- blocked-only Raw Capture, exact-body deduplication, startup TTL cleanup,
  schema-v3 redaction metadata, disable-purge, and WAL truncation;
- SQLite schema v5, an exact `migration_history` sequence `1,2,3,4,5`,
  `PRAGMA quick_check`, final WAL checkpoint, exactly one successful controlled
  restart transcript observation, zero
  unexpected restart, no OOM, and no panic/fatal/plugin-load error.

## Counted-Mock private contract

The auditable Mock source and Dockerfile are checked in at
`integration/round8countedmock`. Build that source with
`scripts/round8-build-host-images.sh`; the runner rejects an image without all
of the exact contract/source/revision/tag/tree labels. The Mock decodes only the top-level `stream`
boolean, never logs, saves, or echoes request bodies, and keeps only an atomic
request count.

It listens on port `18080` and implements exactly:

| Request | Response |
|---|---|
| `GET /healthz` | `200` JSON `{"contract":"round8-counted-mock/v1","healthy":true,"request_body_retention":false}` |
| `POST /__cag/reset` | `200` JSON `{"total":0}` and atomically reset the model-request count |
| `GET /__cag/stats` | `200` JSON `{"total":N}` where `N` is a non-negative JSON integer |
| `POST /v1/chat/completions` | increment once and return a valid OpenAI-compatible non-stream or SSE response |
| `POST /v1/responses` | increment once and return a valid OpenAI Responses-compatible non-stream or SSE response |

Health, reset, and stats calls do not increment `total`. The runner gives the
Mock no bind mount, proxy, or Linux capability, a read-only root filesystem,
and only an internal Docker network. Contract JSON has an exact schema; extra
fields and boolean-as-integer drift are rejected.

## Isolation model

Both the builder and runner reject TCP, SSH, HTTP(S), named-pipe, TLS, or
context/`DOCKER_HOST`-mismatched Docker endpoints. A real non-symlink Unix socket
is necessary but is not treated as proof of locality: SSH or a forwarding proxy
can expose a remote daemon through a local Unix socket. Before any formal build,
network, or workload container, the preflight therefore requires the protected
daemon ID, exactly one sandbox label
`io.cyber-abuse-guard.round8-sandbox=<sandbox-id>`, exactly one
`io.cyber-abuse-guard.production=false` label, and an exact preinstalled
Linux-amd64 probe image ID. It then creates an unpredictable Host directory and
nonce and requires a resource-bounded, read-only, capability-free, no-network
probe container to read that bind mount byte-for-byte. A forwarded daemon cannot
see that Host path and must fail before workload actions.

The primary execution uses random `cag-r8-primary-<id>-*` names and a new Docker network
created with `--internal`. The network must contain exactly the CPA and Mock
containers. CPA receives one provider URL, `http://mock:18080/v1`, an empty
authentication directory, synthetic keys, `-local-model`, cleared proxy
variables, `NO_PROXY=*`, and a management port published only on a random
`127.0.0.1` Host port.

Both containers use the invoking UID/GID, `--restart no`, `--read-only`,
`--cap-drop ALL`, `no-new-privileges`, and a bounded PID limit. CPA receives
only five execution-private mounts: exact Store SO, config, empty auth directory,
audit directory, and a synthetic HMAC secret. Cleanup removes only the exact
names recorded by this execution; the runner contains no prune, broad label
filter, SSH, or production endpoint.

The Mock is limited to 0.5 CPU and 128 MiB; CPA is limited to 1 CPU and
512 MiB. Memory swap is capped at the same value. Both use Docker's `local` log
driver with `max-size=8m`, `max-file=1`, and `compress=false` so current Docker
releases accept the single-file rotation contract. The Host HTTP client uses a fixed
proxy-disabled opener and accepts only explicit unprivileged
`http://127.0.0.1:<port>` endpoints. Redirect following is disabled, so Host
proxy environment variables or redirect targets cannot receive CPA/Mock bodies
or bearer headers.

## Protected workflow invocation

Repository administrators must configure these controls before any Host run is
release-admissible:

- GitHub environment `round8-host-validation`, with required reviewers,
  `prevent_self_review=true`, `can_admins_bypass=false`, and an exact deployment
  policy for the reviewed RC tag/ref;
- a dedicated runner carrying exactly the `self-hosted`, `linux`, `x64`, and
  `cag-round8-sandbox` labels and no production credentials or mounts;
- environment variables `ROUND8_SANDBOX_ID`, `ROUND8_DAEMON_ID`, and
  `ROUND8_PROBE_IMAGE_ID`, bound to the protected non-production daemon and the
  immutable preinstalled Linux-amd64 probe image;
- GitHub environment `round8-rc-publication` with the same reviewer, self-review,
  admin-bypass, and exact deployment-policy protections.

After a successful Phase 1 `release-rc.yml` run with
`publish_rc_release=false`, dispatch `round8-host-validation.yml` from the exact
`v0.16-rc.2` tag. Supply the annotated tag object, commit, tree, Phase 1
run/attempt, Phase 1 artifact ID/digest, and a freshly generated lowercase
64-hex challenge. The workflow first creates the exact attested base-image
bundle on a GitHub-hosted Linux runner, then admits and attests the candidate
before building the pinned CPA v7.2.95 image and repository Mock on the protected
Host. The Host build uses only the loaded local bases and `--pull=false`; it may
still contact the official CPA Git origin, Debian package service, and Go module
sources required by the reviewed upstream Dockerfile, but it never contacts
Docker Hub, a registry mirror, a model Provider, or a production service.

The workflow output artifact contains exactly:

- `round8-host-evidence.json` — canonical schema-v2 JSON with no trailing newline;
- `round8-host-evidence.json.sha256` — its standard SHA-256 sidecar.

The evidence binds the protected Host workflow run/attempt, one-time challenge,
Phase 1 run/attempt/artifact ID/digest, runner identity, daemon ID and labels,
sandbox ID, probe image ID, and locality `PASS`. GitHub attests both files from
the protected Host workflow. Record the Host run ID/attempt and artifact
ID/digest from the workflow summary, then supply those exact values and the same
challenge to `release-rc.yml` with `publish_rc_release=true`.

The shell runner still supports offline validation for diagnosis, but that does
not replace GitHub attestation:

```bash
./scripts/round8-host-evidence.sh validate \
  --artifacts /srv/cag/phase1 \
  --evidence /srv/cag/round8-output/round8-host-evidence.json \
  --commit 0123456789abcdef0123456789abcdef01234567 \
  --tree 89abcdef0123456789abcdef0123456789abcdef
```

The offline `assemble` recovery mode emits schema v1. It can reconstruct closed
results from canonical transcripts and rejects hand-filled `PASS` objects, but
it intentionally lacks the protected workflow execution binding and therefore
cannot satisfy Phase 2 publication admission.

## Failure semantics and evidence boundary

Any failed assertion prevents final Host evidence from being written. A
privacy-safe transcript may remain for diagnosis; it contains fixture family
IDs, status codes, counts, build identity, and SHA-256 values, never request
text or response text. Execution-sensitive files are removed only after the exact
private Docker resources have been removed. Planned container/network names are
registered before the Docker create/run request, so a lost CLI response is still
reconciled. Cleanup accepts absence only after a successful exact-name Docker
listing; an inspect, daemon, or API error is never treated as proof that a
resource is gone.

The resulting JSON preserves the CPA v7.2.95 image's immutable ID and build date,
plus the counted-Mock contract, source, revision, tag, tree, and immutable image
ID. Phase 2 fetches only the exact two-file artifact identified by the protected
Host run and artifact identity, then verifies the GitHub signer
workflow, signer commit, source ref/commit, artifact digest, challenge, and
schema-v2 execution binding. This proves that the protected workflow produced
the admitted bytes under the configured runner/environment trust root. It is
still not real-Provider validation, production approval, an independent audit,
or stable-release approval; GitHub environment and runner administration remain
explicit external trust boundaries.
