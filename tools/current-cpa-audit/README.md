# Current CPA five-repository isolated audit

This directory is the current diagnostic harness for **CPA v7.2.142** at commit
`1f53b2eb03b9e963bac647e5566ca2b304239116`. The closed active upstream identity
also binds module sum `h1:30twcgoSCSjBtc4tgZBKPC4sQpsEWwgu4d9r7tIDpQQ=`,
go.mod sum `h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=`, C ABI 1, RPC schema 3,
and the official Linux
amd64 asset `CLIProxyAPI_7.2.142_linux_amd64.tar.gz` at exactly 21,072,175 bytes
with SHA-256
`a7cccc8f94b07660303c1874fb6bedae6d573a0f3c4c0b17ad8cf7885dd7a051`, and
the 63,738,088-byte extracted binary SHA-256
`e0df04ae5e632649c36230533d9608058dd09689113947809e4824f598f36a9b`.
These values identify the active upstream input only; they do not relabel an
older second-machine or CI result as a v7.2.142 PASS. The harness output claim
is deliberately limited to:

> SECOND-MACHINE DIAGNOSTIC; NOT INDEPENDENT ATTESTATION

It does not approve a release or a production deployment.

## Closed safety boundary

- Acquisition reads only `https://api.github.com` and
  `https://raw.githubusercontent.com`, with proxy use disabled.
- Only the repository/path pairs in `repository-policy.json` are accepted.
  There must be exactly five repositories and exactly one single-entry Markdown
  ZIP. A moving pre/post default-branch HEAD fails acquisition.
- The manifest must cover all 11 fixed repository/path sources; merely showing
  one source from each repository is rejected. It must also contain exactly 19
  unique semantic cases.
- Acquisition always emits an artifact marked `candidate`; it never turns a
  current GitHub HEAD into a reviewed source by itself. A runnable candidate
  requires an `approved` policy whose per-source commit, tree, Git blob SHA-1,
  raw-source SHA-256, and extracted-text SHA-256 all match exactly. Missing,
  mixed, or stale pins fail closed.
- Repository bytes are inert UTF-8 input. The tools never import or execute a
  repository file, installer, hook, macro, archive script, or binary.
- Symlinks, executable Git blobs, LFS pointers, NUL, invalid UTF-8, oversized
  blobs, truncated trees, traversal, ZIP trailers/prefixes, concatenated or
  rebased archives, multiple ZIP entries, encrypted/unknown compression, and
  expansion ratios above 100 are rejected.
- The candidate manifest binds the acquisition root and `corpus/` directory by
  filesystem device/inode. Every corpus file must have hardlink count one at
  acquisition, validation, use, and pre-cleanup. The acquirer holds those
  directory descriptors from initial creation and writes relative to the held
  corpus FD, so failure cleanup still reaches the original directory after a
  rename. Runner/discard cleanup likewise holds the validated directory
  descriptors and serializes every in-process read, write, cleanup, and close.
  It opens and unlinks files relative to the held directory, rechecks
  size/SHA and inode identity, and requires the post-unlink link count to be
  zero. Directory replacement, same-name decoys, or external hardlinks fail
  closed and can never produce `retained=false` PASS evidence. Linux has no
  regular-file unlink-by-descriptor operation; an untrusted process sharing the
  dedicated runner UID remains outside the stated threat model below.
- NERV has no unambiguous repository licence in this review. Its complete text
  is mode-0600 ephemeral input only. A pending review candidate must be
  discarded with the manifest-validated `--discard-candidate` operation;
  `run.py` removes approved-run text in `finally`. Final evidence retains repository,
  commit/tree/blob/text hashes, path, byte count, review identity, and counts;
  `run.py` removes all complete corpus text in `finally`.
- The runtime network is an internal, non-attachable IPv4 Docker bridge with
  exactly CPA and counted-Mock, no Host ports, no real Provider/OAuth
  credentials, and proxy variables cleared. Both containers use a read-only
  root filesystem, `cap-drop=ALL`, an empty `cap-add`, `no-new-privileges`, bounded memory/PIDs,
  and restart policy `no`.
- The generated Mock control and upstream credentials never appear as Docker
  argument values. The runner writes them to a single-link mode-0600 file below
  the descriptor-bound cold-start directory, gives `docker run` only an
  `--env-file` path, and identity-checks and removes that file immediately when
  the CLI returns, including on failure. Docker expands those values into the
  container configuration, so root and Docker-daemon administrators remain in
  the trusted computing base; final evidence and runner output never copy them.
- Cleanup never calls a global prune and never removes images. It stops CPA and
  Mock gracefully, checkpoints SQLite, and removes only resources carrying the
  exact run label.
- The v7.2.142 `/v1/realtime*` source topology is separately labelled
  `SOURCE_TOPOLOGY_UNPROTECTED`. Runtime negative coverage supplies no
  credential and requires every fixed route to end at `AUTH_REJECTED`, without
  WebSocket upgrade, Mock/Provider/Usage activity, or any of the six fixed CAG
  RPC counter deltas. Its evidence level is only `AUTH_BOUNDARY_ONLY`; the
  harness does not authenticate a route that may reach OAuth or a real Provider
  and does not claim a full dynamic handler-path bypass proof.

The fixed repositories are:

| Key | Repository | Retention |
|---|---|---|
| `keysmith` | `Jia-Ethan/codex-keysmith` | ephemeral text |
| `codex55` | `yynxxxxx/Codex-5.5-codex-instruct-5.5` | ephemeral text |
| `codexx` | `yynxxxxx/Codex-X` | ephemeral text |
| `mdx` | `MDX-Tom/gpt-5.6-instruct` | ephemeral text; one Markdown ZIP |
| `nerv` | `lingbol088-spec/5.6-JAILBREAK-NERV-codex-instruct-5.6` | hash/identity/count only |

The exact repository/path surface, retention boundary, template identities,
and required counts are code-owned in `audit_contract.py`. Semantic ground
truth proposals and exact reviewed source pins live in the closed policy and
are bound back to every candidate case. They become runnable ground truth only
under an approved policy. A changed policy changes both its SHA and the runner
bundle identity.

A separately supplied complete Codex jailbreak ZIP is **not** part of the
current five-repository, 11-source, 19-case denominator. Its implemented
interface is an explicit `--supplemental-archive` input whose value names
`/srv/cag-audit/supplemental/authorized-codex-archive.zip`, with its own source
hash, case count, false-positive denominator, malicious-recall denominator,
results, and cleanup status. Parser, runner, schemas, validators, and negative
fixtures now fail closed together, but no real v7.2.142 candidate run has yet
completed, so its truthful status remains `NOT_RUN`; the five-repository result
must never be relabelled as a supplemental-archive PASS.

The supplemental v2 ground truth keeps target authorization and target
ownership separate from model-control authorization. An owned, authorized CTF
target does not by itself authorize installing or hiding a replacement model
control policy. The reviewed `authorized-ctf` case therefore remains malicious
active ground truth with `model_control_authorization=not_granted`: Audit allows
with an audit event, while Balanced and Strict block before Auth, Mock,
Provider, or Usage. Every transport result must prove the reviewed
`defense_evasion / META-OVERRIDE-001` winner, and the portable admission report
retains both expected and actual winner pairs. The seven-case plane contains
four malicious and three non-malicious cases; this audit-oracle correction does
not add a production classifier exemption or change classifier-policy-v20.

`third_party_code_executions` counts execution of the five untrusted corpus
repositories and must be zero. CPA/CAG and the repository-owned counted-Mock
are the explicitly audited runtime, not corpus execution.

## Files

- `acquire.py` — read-only, exact-current-HEAD candidate acquisition plus
  exact candidate-text discard.
- `repository-policy.json` — fixed repository/path/ground-truth metadata and
  per-source human-review pins. The checked-in file is approved for the exact
  five-repository source identities reviewed on 2026-08-24; source drift fails.
  The fixed commit/tree pairs are Keysmith
  `2cb7f382ea8a08e9af5a6d9c16580b45f639891a` / `0d46f7e9ffe6907b2483d9955a6f40a8f75800dd`,
  Codex-5.5 `ed0b6dc37d1994e93788d92f7af63f58bf0b9e2d` /
  `e6081de4a8a56e839be2f2eb281195e314386b31`, Codex-X
  `d7610f9b12276e074c40cacf9940db3b9bdc67ff` / `d05dfcc40e96dcde4755067acf543de683a1246e`,
  GPT-5.6 Instruct `77e7a649903f9556f2d7bfa0223fa99e123aad52` /
  `e7e073eb2b5af2b3877704f6966db76ee7f31f08`, and NERV
  `4fac65fa452d96c98d96e2d9759f31cd1683441d` / `13bf0b663df617ee291f5d8e9075ae6e26fc5f66`.
  Every selected blob remains independently bound by its checked-in source and
  normalized-text SHA-256; any default-branch or selected-byte drift fails.
- `audit_contract.py` — closed corpus, run-config, result, and machine-evidence
  validators. Unknown or missing fields fail.
- `supplemental_zip.py` - closed, metadata-only supplemental ZIP parser and
  caller-owned in-memory reviewed-text loader; it never extracts member text to
  disk or executes archive content.
- `counted_mock.py` and `Dockerfile.mock` — body-discarding upstream with
  independent `mock`, `auth`, and `provider` counters.
- `make_run_config.py` — hashes local inputs and emits canonical mode-0600 JSON.
- `run.py` — three-to-ten cold-start isolated runner.
- `machine-evidence.schema.json` — closed JSON Schema 2020-12 description.
- `validate.py` — standalone fail-closed validator.
- `host_performance.py` — RT13-06 Host A/B plan binder, integrated Linux
  collector, and raw-derived evidence assembler. It does not synthesize or
  substitute measurements.
- `host_performance_workloads.py` — deterministic fixed-workload generator
  bound to the validated five-repository manifest and the checked-in sanitized
  public corpus. It writes canonical request bodies only; it never reads the
  supplemental archive or executes third-party content.
- `host-performance-evidence.schema.json` — closed JSON Schema 2020-12 for
  the derived Host performance evidence.
- `tests/` — standard-library unit tests plus an optional `jsonschema` Draft
  2020-12 fixture check when that package is installed; no live Provider or
  GitHub access.

Initialize one unique semantic run identity for the current pre-merge or
post-main phase. Never reuse it for the other phase:

```bash
RUN_ID='<unique-premerge-or-postmain-run-id>'
ACQUISITION_DIR="/srv/cag-audit/acquisition-$RUN_ID"
CANDIDATE_DIR=/srv/artifacts/candidate
UPSTREAM_DIR=/srv/artifacts/upstream
EVIDENCE_DIR="/srv/cag-audit/evidence-$RUN_ID"
SUPPLEMENTAL_DIR="/srv/cag-audit/supplemental-metadata-$RUN_ID"
SUPPLEMENTAL_ARCHIVE='/srv/cag-audit/supplemental/authorized-codex-archive.zip'
RUN_CONFIG="/srv/cag-audit/run-config-$RUN_ID.json"
test ! -e "$ACQUISITION_DIR"
test ! -e "$EVIDENCE_DIR"
test ! -e "$SUPPLEMENTAL_DIR"
test ! -e "$RUN_CONFIG"
```

## 1. Use the approved pins; review again on source drift

Run acquisition only in a new private directory on the Linux audit host. Do
not run any file obtained from GitHub. The checked-in policy is `approved` and
binds all 11 reviewed paths to exact commit, tree, Git blob, raw-source, and
extracted-text hashes. Acquire the current audit input directly into a new
directory; any GitHub HEAD or source mismatch removes the new tree and fails.

```bash
umask 077
python3 -B tools/current-cpa-audit/acquire.py \
  --policy tools/current-cpa-audit/repository-policy.json \
  --output "$ACQUISITION_DIR"

python3 -B tools/current-cpa-audit/validate.py corpus \
  --manifest "$ACQUISITION_DIR/corpus-manifest.json" \
  --corpus-root "$ACQUISITION_DIR"

python3 -B tools/current-cpa-audit/acquire.py \
  --supplemental-archive "$SUPPLEMENTAL_ARCHIVE" \
  --supplemental-policy tools/current-cpa-audit/supplemental-zip-policy.json \
  --output "$SUPPLEMENTAL_DIR"

python3 -B tools/current-cpa-audit/acquire.py \
  --validate-supplemental "$SUPPLEMENTAL_DIR/supplemental-zip-manifest.json" \
  --supplemental-policy tools/current-cpa-audit/supplemental-zip-policy.json
```

The acquisition still reports `artifact_status=candidate`, but now records
`policy_review_status=approved` and `runnable=true`; those words are valid only
because every freshly fetched source matches the reviewed policy exactly.

### Future source refresh

A future HEAD never inherits approval. In a reviewed branch, first change the
policy to `pending`: clear reviewer identity/time and all five hashes in every
`reviewed_source`. Then acquire into a new pending directory:

```bash
python3 -B tools/current-cpa-audit/acquire.py \
  --policy tools/current-cpa-audit/repository-policy.json \
  --output /srv/cag-audit/candidate-pending
```

That refresh acquisition reports `policy_review_status=pending` and
`runnable=false`. It records the exact pre/post HEAD and source identities but
does **not** claim that a person reviewed them.

An authorized maintainer must inspect the private candidate text as inert data,
review all 19 semantic labels/reasons/actions/templates, and then update the
policy in the same reviewed change:

1. set `reviewer.status` to `approved` and provide its non-null `identity` and
   `reviewed_at` timestamp;
2. for every one of the 11 paths, copy the reviewed candidate's exact
   `commit`, `tree`, `blob_sha1`, `source_sha256`, and `text_sha256` into
   `reviewed_source` only after completing that review;
3. ensure all paths in one repository share its one reviewed commit/tree.

Do not reuse the old private text after editing the policy. The edit changes
the policy SHA, so first remove only the pending candidate's manifest-declared
text while retaining its metadata:

```bash
python3 -B tools/current-cpa-audit/acquire.py \
  --discard-candidate /srv/cag-audit/candidate-pending/corpus-manifest.json
```

The command succeeds only after every declared corpus path is absent and
prints `private_text_retained=false`. If it reports a replaced link,
hardlink, directory-identity drift, non-regular file, content mismatch,
retained path, or unexpected entry, investigate the named path; it never
recursively deletes an unexpected entry. Do not copy the acquisition tree:
its manifest intentionally binds the original root and corpus device/inode.

Finally acquire again into a **new** directory using the newly approved policy. This
second acquisition is mandatory: an old pending candidate cannot be stamped
in place. Any HEAD or source drift from the approved pins rejects acquisition
and removes the new acquisition tree.

Acquisition saves metadata API, tree API, raw ETag/body SHA, pre/post
commit/tree observations, and local root/corpus filesystem identities. If
acquisition fails, held directory descriptors remove the known source files
from the original corpus; named-path cleanup then removes the output tree, and
any identity drift keeps the operation failed closed. `validate.py corpus`,
`make_run_config.py`, `run.py`,
and final evidence validation require the current bundled policy to be
approved, require its SHA to match the re-acquired candidate, and re-check all
exact pins. The approved acquisition is still temporary and must be handed
directly to `run.py`, whose `finally` removes the text files. A future HEAD
change requires a new pending review cycle; it is never auto-approved. The
per-case `review_sha256` is only a deterministic binding checksum, not a human
signature; review authority comes from the explicitly approved, reviewed
policy change and its exact bundle identity.

## 2. Prepare exact images and assets offline

This runbook has two non-transferable executions:

1. **Pre-merge diagnostic.** Download the successful `pull_request` artifact
   built from GitHub's synthetic PR merge commit. The candidate manifest binds
   the PR head separately from that synthetic merge commit/tree. Run the full
   functional, five-repository, built-in ZIP, special-path, Host-performance,
   side-effect, and cleanup diagnostics. A PASS permits the PR author to
   squash-merge; it does not permit `pack`, a staging Release, a tag, or a
   release-admission claim.
2. **Post-main release admission.** After the authorized squash merge, wait for
   all five required checks on the resulting protected-`main` `push` commit.
   Download that `push` run's nine-file artifact and repeat the entire audit
   under a new `RUN_ID` and new evidence directory. The build embeds the source
   commit, so the squash commit changes the SO identity and bytes even when the
   source tree is unchanged. No PR artifact, SO hash, evidence bundle, or PASS
   transfers to this phase. Only this exact `push`/`main` rerun may be supplied
   to the portable packer.

For each phase, use the fresh per-phase paths initialized above. Preserve the
pre-merge evidence under its unique evidence path, then recreate the fixed
candidate directory as an empty directory before extracting the post-main
artifact; never overlay or mix the two candidate sets. The upstream directory
may be retained only when the same reviewed CPA tar is rehashed successfully.
Acquisition and evidence directories, run-config paths, and `RUN_ID` values are
never reused.

Extract the exact nine candidate files directly into
`/srv/artifacts/candidate`, with no additional directory level:

```text
audit-candidate-manifest.json
build-metadata.json
checksums.txt
cyber-abuse-guard-v1.0.0.so
cyber-abuse-guard-v1.0.0.so.sha256
cyber-abuse-guard_1.0.0_linux_amd64.zip
ruleset-manifest.json
ruleset.sha256
sbom.cdx.json
```

Place only the reviewed upstream CPA archive at
`/srv/artifacts/upstream/CLIProxyAPI_7.2.142_linux_amd64.tar.gz`. Do not place
candidate files in the upstream directory or the CPA archive in the candidate
directory.

Preload, do not pull during the audit:

1. The exact-merge clean CAG audit candidate from the successful CI artifact
   named `cyber-abuse-guard-linux-amd64-audit-candidate`. Its metadata must bind
   the selected merge commit/tree and report `dirty=false`; the runner rejects
   dirty development bytes. This is still an unreleased diagnostic candidate,
   not a release artifact.
2. CPA v7.2.142 image by exact RepoDigest and image ID.
3. The official v7.2.142 linux/amd64 asset at exactly 21,072,175 bytes and its
   published SHA-256.
4. The exact CPA binary SHA-256 expected inside that image.
5. A counted-Mock image built from this directory with a previously reviewed,
   digest-pinned Python base image.

Example Mock build (replace both digests with reviewed values):

```bash
MOCK_SOURCE_SHA256="$(sha256sum tools/current-cpa-audit/counted_mock.py | awk '{print $1}')"
docker build --pull=false \
  --build-arg PYTHON_IMAGE='python:3.12-slim@sha256:<reviewed-base-digest>' \
  --build-arg MOCK_SOURCE_SHA256="$MOCK_SOURCE_SHA256" \
  -f tools/current-cpa-audit/Dockerfile.mock \
  -t private-audit-registry/cag-counted-mock:rt13 \
  tools/current-cpa-audit
```

The runner requires a real `name@sha256:...` RepoDigest for both images and
uses `docker run --pull never`. A local tag without RepoDigest is rejected.
Before starting the Mock, it also requires the exact image Entrypoint, creates a
stopped network-none verifier container, copies `/opt/cag-audit/counted_mock.py`
without executing it, and hashes those actual bytes against the reviewed source
identity. Image labels alone are never accepted as proof of the Mock payload.
Publish/load the Mock through the authorized private audit registry before
disconnecting external network access.

## 3. Create the immutable run config

`make_run_config.py` derives the CAG source commit/tree, CAG SO SHA, corpus,
policy, Mock source, and official-asset hashes. It requires the sealed CI
`audit-candidate-manifest.json`, rejects tracked or untracked worktree drift,
and accepts the CAG identity only when the canonical, single-link manifest's
exact eight-file set binds the reviewed repository/workflow, GitHub run and
head identities, source `1.0.0`, SO `cyber-abuse-guard-v1.0.0.so`, and its
SHA. The manifest and SO must be regular single-link files in one resolved
artifact directory. Their identities are re-read by `run.py` before execution
and by `validate.py` during final validation, then preserved in machine
evidence.

GitHub assigns the Actions artifact ID and digest only after uploading the
artifact that already contains the manifest. They therefore cannot truthfully
appear inside that manifest without a circular digest. Supply the real
post-upload `artifact-id`, fixed artifact name, and `artifact-digest` reported
by the CI upload step as external admission metadata; the run config and
machine evidence cross-bind those values but do not claim that the manifest
self-attests them.
Supply image identities and the
image-contained CPA binary identity explicitly.

```bash
python3 -B tools/current-cpa-audit/make_run_config.py \
  --output "$RUN_CONFIG" \
  --run-id "$RUN_ID" \
  --seed 1305 \
  --cold-start-count 3 \
  --manifest "$ACQUISITION_DIR/corpus-manifest.json" \
  --supplemental-archive "$SUPPLEMENTAL_ARCHIVE" \
  --supplemental-zip-policy tools/current-cpa-audit/supplemental-zip-policy.json \
  --supplemental-zip-manifest "$SUPPLEMENTAL_DIR/supplemental-zip-manifest.json" \
  --evidence-directory "$EVIDENCE_DIR" \
  --cag-repository /srv/src/cyber-abuse-guard \
  --cag-so "$CANDIDATE_DIR/cyber-abuse-guard-v1.0.0.so" \
  --candidate-manifest "$CANDIDATE_DIR/audit-candidate-manifest.json" \
  --candidate-artifact-id '<GitHub artifact-id>' \
  --candidate-artifact-name cyber-abuse-guard-linux-amd64-audit-candidate \
  --candidate-artifact-digest 'sha256:<GitHub artifact-digest>' \
  --cpa-official-asset "$UPSTREAM_DIR/CLIProxyAPI_7.2.142_linux_amd64.tar.gz" \
  --cpa-official-asset-sha256 a7cccc8f94b07660303c1874fb6bedae6d573a0f3c4c0b17ad8cf7885dd7a051 \
  --cpa-binary-path /CLIProxyAPI \
  --cpa-binary-sha256 e0df04ae5e632649c36230533d9608058dd09689113947809e4824f598f36a9b \
  --cpa-image-ref 'private-audit-registry/cpa@sha256:<64-hex>' \
  --cpa-image-id 'sha256:<64-hex>' \
  --mock-image-ref 'private-audit-registry/cag-counted-mock@sha256:<64-hex>' \
  --mock-image-id 'sha256:<64-hex>'

python3 -B tools/current-cpa-audit/validate.py run-config \
  --config "$RUN_CONFIG"
```

The evidence binds the input config SHA, a separate runtime config SHA for
each cold start, every template SHA, individual runner source/schema/policy
SHAs, and a bundle SHA over the operational file-name-to-SHA map.

Generate the fixed Host-performance workload now, while the validated core
corpus still exists and before `run.py` performs its exact text cleanup. Keep
generated bodies outside the checkout and keep the manifest outside its private
body root:

```bash
PERFORMANCE_WORKLOAD_ROOT="/srv/cag-audit/host-performance-workloads-$RUN_ID"
PERFORMANCE_WORKLOAD_MANIFEST="/srv/cag-audit/host-performance-workloads-$RUN_ID.json"

python3 -B tools/current-cpa-audit/host_performance_workloads.py generate \
  --core-manifest "$ACQUISITION_DIR/corpus-manifest.json" \
  --corpus-root "$ACQUISITION_DIR" \
  --repository-root /srv/src/cyber-abuse-guard \
  --output-root "$PERFORMANCE_WORKLOAD_ROOT" \
  --manifest "$PERFORMANCE_WORKLOAD_MANIFEST"
```

The generator produces exactly 30 bodies: one fixed control, two ordinary
controls, sixteen five-repository malicious-activation requests, ten sanitized
public adversarial requests, and one exact 4 MiB wire body. The independently
reviewed Host tool-identity approval must include the generator SHA-256; a
hand-written lookalike manifest is not the approved fixed workload.

## 4. Run in isolation

Disable external networking on the host as appropriate, while preserving the
local Docker socket. Invoke the runner as a dedicated non-root user with
passwordless `sudo -n docker`; UID/GID 0 is rejected and the exact numeric
container user is recorded. The evidence directory's existing parent must be a
real mode-0700 directory beneath trusted, non-writable ancestors. Do not run any
untrusted process under the runner UID during bootstrap or execution. The
runner, the local rootful Docker daemon, and its CLI must share the host PID
namespace so `/proc/<runner-pid>/fd/<evidence-fd>` resolves to the held evidence
inode for descriptor-bound writes and `docker cp`. Docker/runc does not accept a
proc-fd magic link as a bind-mount source. Immediately before handing each of
the five runtime directories to Docker, the runner therefore revalidates the
saved device/inode identity of every real, non-symlink component in the normal
absolute evidence path. Below the evidence root it also walks the held-fd and
normal-path aliases component by component, requires matching device/inode and
private real directories, continuously revalidates the evidence root and
parent owner/mode, and gives Docker only the verified normal path. It repeats
those identity checks after container start. Docker inspect must report exactly
the five expected Source/Destination/RW/rprivate bind contracts, while
`HostConfig.Tmpfs` must contain only the hardened `/tmp` contract. Docker
versions may omit tmpfs entries from `.Mounts`; the runner therefore accepts
zero or one matching `/tmp` entry there and rejects every other bind, volume,
or non-bind mount. The dedicated-UID condition bounds the non-atomic daemon
handoff. The runner itself creates only an internal bridge.

The private `/cag/config` bind is writable by design. CPA v7.2.142 persists a
replacement `plugins.configs.<id>` object to `config.yaml` before applying the
hot reload, so a read-only config bind makes every Audit/Balanced/Strict mode
transition fail with HTTP 500. This does not expose a Host or business config:
the directory is created separately for each cold start below the mode-0700,
descriptor-bound evidence root, contains exactly one single-link regular
`config.yaml`, and is owned by the dedicated runner UID/GID. The runner
rechecks that closed file set, ownership, size, bind identity, `RW=true`, and
the Mock-only in-memory CPA configuration after every transition. The Host
root filesystem remains read-only; the plugin, secret, and counted-Mock image
inputs remain read-only as well.

The independent live CSAM-text plane is mandatory; it is not enabled by a
default or discovered from the reviewed repositories. Before starting
`run.py`, the operator must provide these seven values in the dedicated
runner's environment:

```text
CAG_CSAM_TEXT_CPA_URL=http://<fixed-private-cpa-ip>:8317
CAG_CSAM_TEXT_MOCK_URL=http://<fixed-private-mock-ip>:18080
CAG_CSAM_TEXT_COLD_START_HOOK=/absolute/operator-owned/hook
CAG_CSAM_CLIENT_KEY=<run-random-secret-at-least-32-bytes>
CAG_CSAM_MANAGEMENT_KEY=<different-run-random-secret-at-least-32-bytes>
CAG_CSAM_MOCK_CONTROL_TOKEN=<different-run-random-secret-at-least-32-bytes>
CAG_CSAM_UPSTREAM_KEY=<different-run-random-secret-at-least-32-bytes>
```

The outer runner sends only those credentials plus the bounded locale/path
environment to the isolated producer; it never puts a credential in argv.
The producer receives the normal absolute Host path for its new `csam-text`
output because its atomic publisher deliberately rejects a proc-fd magic-link
parent. Before and after that child runs, the outer runner revalidates the held
evidence-directory descriptor. It then proves the child-created normal path
and its proc-fd alias have the same device/inode, owner, and private mode, and
reads every accepted evidence file only through the descriptor-bound alias.
The executable, non-symlink hook is called without a shell as
`HOOK <1|2|3> <runtime-root>`. Each call must replace the exact labelled
`<RUN_ID>-cpa`, `<RUN_ID>-mock`, and `<RUN_ID>-net` resources, create the passed
runtime root as a real mode-0700 directory owned by the dedicated UID/GID, keep
the configured private endpoint IPs stable, and print only this closed JSON
shape:

```json
{"cold_start":1,"instance_id":"distinct-runtime-id","schema":"cag-current-cpa-csam-text-cold-start-hook/v1","status":"PASS"}
```

After all 1,296 observations, the producer invokes
`HOOK cleanup <runtime-root>`. The hook must stop and remove the three exact
resources, remove all generated config/secret/runtime bytes including the
runtime root, and print only:

```json
{"owned_resources_absent":true,"runtime_root_absent":true,"schema":"cag-current-cpa-csam-text-cleanup-hook/v1","status":"PASS"}
```

The producer independently proves the passed runtime root is absent. The
outer audit runner then removes any safely attributable residual runtime tree,
runs its label/name-bounded Docker emergency cleanup if required, and proves
the exact Docker resource names absent before accepting the CSAM evidence.
Missing settings, malformed hook receipts, retained runtime bytes, or cleanup
failure are hard failures and cannot emit `machine-evidence.json`.

```bash
python3 -B tools/current-cpa-audit/run.py \
  --config "$RUN_CONFIG"
```

For every semantic case it executes all three modes (`audit`, `balanced`,
`strict`), both protocols (`chat`, `responses`), and stream false/true on at
least three cold starts. The seed deterministically randomizes mode, case, and
transport order independently for each cold start. The closed resource bound
is three through ten cold starts; values outside that range are rejected by
the config, plan, evidence validator, and JSON Schema.

Pass conditions are closed:

- block: HTTP 403; exact JSON error schema/content type; `no-store` and
  `nosniff`; Mock/Auth/Provider/Usage deltas all zero; a new audit event with
  matching request hash and block kind;
- allow: HTTP 200; Mock/Auth/Provider/Usage deltas all one; valid Chat or
  Responses response and complete stream termination;
- all cold starts: identical semantic outcome/side-effect signatures;
  `PRAGMA quick_check = ok`, schema 7, complete non-busy WAL checkpoint after
  stop, exit/restart/OOM/panic/fatal/plugin-error counts zero;
- existing business-container snapshot unchanged; exact labelled cleanup
  complete; infrastructure errors and third-party code executions zero.

`unique_semantic_cases`, `unique_content_hashes`, and
`transport_executions` are separate fields. Repeating transports or cold
starts never inflates semantic/content counts.

On any failure, `machine-evidence.json` is not emitted. `failure.json` contains
only an error identifier, a low-cardinality failure stage, an optional
readiness-state digest, and a traceback digest. It contains no response body,
credential, runtime configuration, or corpus text. Cleanup and corpus-text
removal still run. A failure file is not a PASS artifact.

## 5. Validate final evidence

The acquisition manifest remains after the runner removes all files below
`corpus/`; an identical metadata-only copy is placed beside the machine
evidence so declared relative paths are independently checkable. The exact
canonical run config is copied beside it and remains bound by `input_sha256`.
The manifest remains truthfully marked `artifact_status=candidate`; machine
evidence can be valid only when both it and that manifest record
`policy_review_status=approved` and the bundled approved policy/pins validate.

```bash
python3 -B tools/current-cpa-audit/validate.py evidence \
  --manifest "$EVIDENCE_DIR/corpus-manifest.json" \
  --evidence "$EVIDENCE_DIR/machine-evidence.json" \
  --results "$EVIDENCE_DIR/transport-results.jsonl" \
  --run-config "$EVIDENCE_DIR/run-config.json"
```

The Python validator is authoritative for cross-file and cross-row
relationships that JSON Schema cannot express (digests, pre/post identity,
matrix coverage, deterministic order, cold-start consistency, request/event
pairing, and exact cleanup multiplicity). The JSON Schema is the closed shape
contract; every object has `additionalProperties: false`.

## 6. RT13-06 CPA Host A/B performance evidence

Host performance is a separate, fail-closed evidence lane. The semantic
machine evidence above is not performance evidence: its requests are serial,
its `latency_ms` values are not an A/B load test, and CPA's `usage-queue` is not
the CAG audit queue. Do not derive a Host PASS from those fields.

`host_performance.py` binds a measurement plan to all of these immutable
inputs:

- the canonical current-CPA `run-config.json`, including the candidate
  manifest hash/path, CI repository/workflow/run/head/source identities,
  external GitHub artifact admission coordinates, exact CAG commit/tree/SO
  identity, and CPA tag/commit/image/RepoDigest/binary/official asset;
- the sealed CI `audit-candidate-manifest.json`, which must be clean, bind the
  same commit/tree, contain exactly eight base-artifact records, and bind the
  selected SO SHA;
- a canonical workload manifest with exactly `fixed_workload`, `ordinary`,
  `five_repository_activation`, `public`, and `large_payload`, each identified
  by a request-set SHA-256, positive request count, and bound wire-body byte
  count. `large_payload` is exactly one 4 MiB canonical JSON wire body;
- an independently reviewed approval for the exact tool checkout used on the
  Host. The approval is a canonical JSON object with exactly
  `acquire_sha256`, `audit_contract_sha256`,
  `host_performance_schema_sha256`, `host_performance_source_sha256`,
  `run_sha256`, `validator_sha256`, `workload_generator_sha256`, and
  `bundle_sha256`. The bundle SHA-256 binds the canonical object containing the
  other seven source hashes. This keeps the deterministic fixed-workload
  generator inside the independently reviewed Host tool identity instead of
  accepting an operator-crafted manifest as the approved baseline.

Produce that approval only from an independently reviewed exact checkout, then
transfer it to the Host as a reviewed input. Never regenerate or replace the
approval from unreviewed Host tool bytes merely to make a drift check pass.

Example workload entry (repeat it for all five fixed IDs). Each request body is
a canonical JSON file below the private workload root. The manifest binds its
path, bytes, endpoint, and expected status in both arms; `request_set_sha256` is
the SHA-256 of the canonical `requests` array:

```json
{"id":"fixed_workload","request_count":1,"request_set_sha256":"<SHA-256 of canonical requests array>","requests":[{"body_bytes":1234,"body_path":"fixed-workload.json","body_sha256":"<64-hex>","endpoint":"/v1/chat/completions","expected_status_by_arm":{"cpa_cag":200,"cpa_only":200}}]}
```

Those status values are descriptive bindings, not operator-selected success
criteria. The validator owns the exact map: `fixed_workload`, `ordinary`,
`public`, and `large_payload` require 200; `five_repository_activation`
requires CPA-only 200 and CPA+CAG 403. A manifest that changes any expected
status, including to a fast 5xx, fails before acquisition.

Reuse the immutable workload root and manifest generated before Section 4.
`run.py` has removed the validated corpus text by this point, so do not try to
regenerate the workload after the semantic audit.

Create the immutable plan before collecting samples:

```bash
python3 -B tools/current-cpa-audit/host_performance.py make-config \
  --run-config "$EVIDENCE_DIR/run-config.json" \
  --candidate-manifest "$CANDIDATE_DIR/audit-candidate-manifest.json" \
  --workload-manifest "$PERFORMANCE_WORKLOAD_MANIFEST" \
  --approved-tool-identities /srv/cag-audit/approved-host-performance-tool-identities.json \
  --output "$EVIDENCE_DIR/host-performance-config.json" \
  --seed 1306 \
  --paired-repetitions 3 \
  --warmup-seconds 30 \
  --measurement-seconds 120 \
  --min-success-samples-per-cell 1000 \
  --resource-sample-interval-ms 1000 \
  --queue-sample-interval-ms 100 \
  --warm-rss-sample-interval-seconds 1
```

The task-book thresholds are code-owned and cannot be relaxed by flags or
config. The configurable bounds are closed: repetitions 3-10, warmup at least
30 seconds, measurement at least 120 seconds, and at least 1,000 successful raw
latencies per cell. Each ordinary measurement cell stops launching work at its
planned window, permits at most five seconds for the final in-flight batch to
drain, and fails instead of extending the window when the minimum sample count
is not met. The two arms of one pair must finish within one second of each
other. Sampling cadence is fixed, not tunable: container/Host resources every
1,000 ms, CAG queue state every 100 ms, and warm RSS every one second. The
default and hard minimum are 1,000 successful samples per cell; a reviewed run
may raise that bound but cannot lower it. Derived matrix rows publish their
raw-bound total elapsed seconds alongside throughput so the denominator remains
auditable.

The config embeds the reviewed tool identities; measurements bind the exact
config SHA-256 and repeat the collector identities; final evidence binds both
the config and measurements SHA-256 values and publishes the same seven
tool-identity hash fields under `artifacts`: six source hashes plus their bundle
hash. This is a config -> measurements -> evidence/current-tool three-way
binding, not a trust-on-first-use Host snapshot. The standalone
`validate.py host-performance` path does not pre-import or execute `acquire.py`;
the acquirer is byte-bound but is not run on that validation path. When the
collector lazily imports `run.py`, it rechecks the complete approved tool
identity immediately before and after the import and aborts without measurements
on drift. `collect` also rechecks the current tool bytes at acquisition start
and completion, validates them again before output, and writes no measurements
on drift. `summarize` rechecks current bytes while validating the config and
again immediately before output, and writes no evidence on drift.

The integrated `collect` command is the only acquisition entry point. It does
not accept an operator-authored measurements JSON. Before invoking it, create
three hardened, already-running containers on one internal bridge using these
exact names derived from the semantic `run_id`:

```text
<run_id>-perf-cpa-only
<run_id>-perf-cpa-cag
<run_id>-perf-mock
<run_id>-perf-net
```

Their `cag.current-cpa-audit.run` label must equal `run_id`; role labels must be
`host-perf-cpa-only`, `host-perf-cpa-cag`, and `host-perf-mock`. The collector
does not own, stop, recreate, or delete these resources. It refuses any extra
network member, Host port, image drift, unequal CPA quota/memory/cpuset,
restart/OOM, unsafe container, or mismatched label. It copies the CPA binary
and plugin directory out without executing them: CPA-only must contain zero
plugin files, while CPA+CAG must contain exactly the candidate SO at
`/cag/plugins/linux/amd64/<artifact_name>` with the configured SHA.
The plugin-directory proof uses Docker's stdout tar-stream mode after the
container user is bound to the dedicated collector UID/GID. The collector caps
the binary stream, parses it in memory, rejects unsafe paths, duplicate paths,
links and every non-file/non-directory member, and hashes the sole expected SO
without extracting any member. This avoids relying on copied UID/GID ownership
when Docker is invoked through passwordless `sudo`; no plugin archive or
`candidate-plugins` directory is written to the host filesystem.

The hidden setup contract is exact. All three containers must use a positive
numeric `UID:GID` in Docker `Config.User`; the collector process itself must
also be a dedicated non-root UID/GID. Create the Mock with network alias
`mock`, inherit the reviewed image entrypoint
`python3 -I -S -B /opt/cag-audit/counted_mock.py`, and pass its upstream/control
tokens through a private `--env-file`, never argv. Both CPA configs must use
only `http://mock:18080/v1`, `commercial-mode: true`, `request-log: false`, and
`logging-to-file: false`, with no real Provider key. Both CPA containers must
have identical entrypoint, command, working directory, non-secret environment,
CPU shares/quota/cpuset, memory/swap, PIDs, ulimits, I/O limits, security and
network HostConfig, plus the same non-plugin mount shape. Only the CAG plugin
mount and plugin-specific configuration may differ. A minimal common flag set
is:

```bash
--user "${AUDIT_UID}:${AUDIT_GID}" \
--network "<run_id>-perf-net" \
--read-only --cap-drop ALL --security-opt no-new-privileges \
--restart no --publish-all=false \
--cpus '<same-positive-limit>' --cpuset-cpus '<same-cpuset>' \
--memory '<same-positive-limit>' --pids-limit '<same-positive-limit>'
```

In the `docker inspect` contract, unrelated `SecurityOpt` entries are allowed,
but the subset whose normalized value starts with `no-new-privileges` must be
exactly one `no-new-privileges:true`; duplicates, `false`, or any other value in
that subset fail closed. `HostConfig.PidsLimit` must be a positive integer for
each of CPA-only, CPA+CAG, and Mock.

Do not add `-p`/`--publish`, `--privileged`, extra capabilities, an attachable
network, a fourth network member, or proxy/real-Provider environment. The Mock
command additionally requires `--network-alias mock`; do not override its
entrypoint. Before the 300-second quiet preflight, the collector times three
real all-target Docker Engine samples and three queue polls and aborts unless
they fit the fixed 1,000/100 ms cadence. Each all-target sample is exactly three
bounded API v1.44 `stats?stream=false&one-shot=true` requests over
`/var/run/docker.sock`, one for each already-bound full container ID.

The collector remains a dedicated non-root process, but it now requires direct
read/write access to the root-owned private Docker socket. The socket must be a
single-link Unix socket, owned by UID 0, group-readable/group-writable and not
world-accessible; its device, inode, owner, group and mode are rechecked around
every request. When the operator launches the collector in a transient systemd
unit, add `SupplementaryGroups=docker` to that unit. Do not make the socket
world-accessible and do not persistently broaden the audit runner's groups just
to satisfy this lane.

Supply the already-configured CPA client and management keys plus the same
run-random counted-Mock control token used by the Mock container only through
the collector process environment, never JSON or argv. Each of the three
values must contain at least 32 characters, and all three values must differ:

```bash
export CAG_HOST_PERF_CLIENT_KEY='<private-client-key>'
export CAG_HOST_PERF_MANAGEMENT_KEY='<private-management-key>'
export CAG_HOST_PERF_MOCK_CONTROL_TOKEN='<same-private-control-token-as-mock>'
python3 -B tools/current-cpa-audit/host_performance.py collect \
  --run-config "$EVIDENCE_DIR/run-config.json" \
  --candidate-manifest "$CANDIDATE_DIR/audit-candidate-manifest.json" \
  --workload-manifest "$PERFORMANCE_WORKLOAD_MANIFEST" \
  --config "$EVIDENCE_DIR/host-performance-config.json" \
  --workload-root "$PERFORMANCE_WORKLOAD_ROOT" \
  --output "$EVIDENCE_DIR/host-performance-measurements.json"
unset CAG_HOST_PERF_CLIENT_KEY CAG_HOST_PERF_MANAGEMENT_KEY CAG_HOST_PERF_MOCK_CONTROL_TOKEN
```

The collector drives the fixed requests itself with a barriered worker pool and
writes canonical `cag-current-cpa-host-performance-measurements/v1` only after
the in-memory capture passes the same validator used during final verification.
It records:

- exactly two `paired_ab` arms (`cpa_only`, `cpa_cag`) for c=1/4/8/16 and every
  configured repetition, in the seed-derived paired order;
- CPA-only proof of zero loaded plugins and no CAG SO, and CPA+CAG proof of
  exactly one loaded plugin with the configured SO SHA;
- exact CPA image/binary and counted-Mock image/source identities (the running
  Mock source is copied out and hashed without execution), one stable and
  different CPA container per arm, one stable re-inspected Mock container,
  stable arm runtime-config SHA, equal secret-redacted non-plugin CPA config,
  and an identical Docker performance projection and Mock contract across
  arms. Docker and management config are re-read before warmup and after every
  measured cell;
- every raw cell and the warm lane expose per-container `container_security`
  for the active `cpa` and shared `mock`, including `no_new_privileges` and the
  positive `pids_limit`. The raw validator derives the final evidence roles
  `cpa_only`, `cpa_cag`, and `mock`, rejects changes across any cell or the warm
  lane, and requires the two CPA arm security contracts to match;
- a reset/zero snapshot and exact Auth/Mock/Provider counter delta for every
  cell and the warm lane. Expected-200 samples must reach all three counted-Mock
  stages exactly once; the expected-403 activation workload must reach none;
- raw fixed-workload latency arrays and continuous container CPU/RSS, Host
  CPU/steal, and CAG audit-queue samples. Every normal resource and CPA+CAG
  queue series has exactly one terminal `final_sample: true` observation; all
  cadence observations are explicitly `false`;
- complete seeded CPA-only/CPA+CAG paired absolute matrices for `ordinary`,
  `five_repository_activation`, and `public` at c=1/4/8/16. Both arms retain
  their raw latency distributions and request/counter conservation;
- a separate seeded large-payload A/B lane at c=4 for every repetition. Each
  arm sends exactly 16 requests using the bound 4 MiB wire body. The raw lane
  records exactly five pre-request process-RSS observations inside the cell
  interval, then a nominal 20 ms
  `/proc/<container-init-pid>/status:VmRSS` series through the request interval.
  Every observation carries the Docker init PID, its Linux `/proc/<pid>/stat`
  start-time tick, a monotonic elapsed marker, an exact millisecond UTC wall
  timestamp, and the RSS value. The collector checks the PID/start-time pair
  before sampling and twice after acquisition, and also records raw latencies,
  throughput, counted-Mock deltas, and the same runtime identity contract;
- a separate CPA+CAG fixed-workload c=16 warm lane with exactly 3,600 seconds of
  continuous RSS coverage at the fixed one-second cadence. The cadence-derived
  minimum includes both window boundaries and is therefore 3,601 samples; at
  most one terminal-extra sample is permitted, so derived
  `warm_rss_60m.sample_count` is between 3,601 and 3,602 inclusive. Raw
  `elapsed_seconds` also records the actual wall duration needed to drain the
  final in-flight batch (bounded to 125 seconds), while
  `measurement_window_seconds` remains exactly 3,600;
- at least 300 seconds of preflight background/steal CPU samples. Background
  CPU p95 or a 60-second rolling mean above 20%, or steal p95 above 1%, forces
  `DIAGNOSTIC_NOT_BASELINE`; measurement-period residual background CPU p95 or
  rolling 60-second mean above 20%, Host saturation p95 above 95%, or steal p95
  above 1% does the same. Neither condition can produce `PASS`.

The raw validator also requires the exact seeded list order, serial
non-overlapping cell timestamps, a complete warmup gap before every cell, and
wall-clock intervals consistent with monotonic `elapsed_seconds`. Every Host
timestamp must use exactly `YYYY-MM-DDTHH:MM:SS.mmmZ`; alternate fractional
precision and numeric offsets are rejected. Overlapping matrices cannot be
relabeled as a sequential A/B run.

For the large-payload lane, each RSS wall timestamp must agree with its
monotonic marker within 5 ms and every sample must retain the cell's exact
PID/start-time identity. Non-final gaps are at least 10 ms. Across the baseline
and request RSS series together, each cell may retain at most one gap above the
30 ms deadline and no greater than the hard 60 ms limit; a second overrun
(consecutive or otherwise) or any gap above 60 ms fails closed. The shared
one-overrun budget does not relax edge coverage: the baseline must start within
20 ms of the cell, finish no more than 30 ms before request start, and the
request series must start within 20 ms of request start and finish within 30 ms
of cell completion, with the sample count implied by the 30 ms deadline. The
validator also requires
`sum(success_latency_ms) / concurrency` and the maximum successful latency to
fit inside the measured request interval. Sparse RSS, process replacement, or
latency work that cannot fit in the claimed wall duration therefore fails
closed.

Container CPU and memory samples come from three bounded, sequential Docker
Engine API v1.44 one-shot reads over the fixed Unix socket. Every response must
repeat the exact full container ID and `/<expected-name>` and remain within the
16 MiB JSON bound. CPU percent is derived from successive
`cpu_usage.total_usage` and `system_cpu_usage` counters using the Engine's
online-CPU count; counter rollback or a non-advancing system counter fails
closed. The timing preflight and every measured cell/warm lane start a fresh
counter baseline; the first sample performs a bounded 20 ms double read so a
preceding warmup or inter-cell gap cannot dilute the current lane. `rss_mib` is
Docker's working-set view, calculated as memory `usage`
minus cgroup-v2 `inactive_file` (or the cgroup-v1 `total_inactive_file`
fallback), not a claim about one process's `VmRSS`.

Host CPU and steal percentages are independently derived from successive Linux
`/proc/stat` aggregate-counter deltas throughout every measured interval. The
collector process tree's own and waited-child CPU is bound from
`/proc/self/stat`; Docker-daemon overhead remains conservatively residual.
Residual background CPU is recomputed as Host busy minus only the active CPA arm
and Mock CPU normalized by logical CPU count, then minus collector CPU. The
inactive CPA arm is measured and published but never subtracted, so a busy
inactive arm or a 30-50% unrelated job that starts after preflight cannot hide
below the 95% saturation check. Audit queue samples come only from CAG's
management `audit.queue_depth` and `audit.queue_capacity`, never CPA's usage
queue. Missing, delayed, degraded, or capacity-drifting samples abort the
capture instead of being replaced with zero.

Each measured cell opens one private HTTP/1.1 management connection for the
100 ms CAG queue sampler, reuses it sequentially for that cell, and closes it
at the cell boundary. The three timing preflight polls likewise share one
private connection. This removes per-sample TCP handshake/TIME_WAIT churn
without changing the 100 ms schedule, sample count, deadline, or queue source;
a server-requested close, reconnect requirement, delayed poll, malformed
response, or missed deadline still aborts the capture.

The large-payload process-RSS lane keeps its fixed 20 ms cadence and 30 ms
sample-gap deadline. Raw monotonic sample timestamps remain in the
measurements, and the final per-arm/per-repetition comparison publishes both
the maximum observed gap and the total overrun count across the combined
baseline and request series. The single bounded scheduler tolerance per cell
does not apply to or relax the one-hour warm-RSS lane.

Normal resource and queue timestamps are strictly bounded by the cell's
`elapsed_seconds`. The raw validator derives both cadence and count bounds from
the code-owned 1,000/100 ms intervals: non-final gaps must be at least half the
configured cadence, every gap must remain below twice the cadence, and a series
may contain at most one sample beyond the cadence-derived minimum—the explicit
terminal final observation. This makes the nearest-rank Host CPU percentiles
insensitive to dense tail insertion; an operator-authored burst of extra zero
samples is rejected rather than allowed to dilute interference.

The secret-redacted Docker projection now retains every ordinary bind Source
as a SHA-256 and binds its resolved path/stat and backing filesystem identity:
filesystem/device, complete mount/super-option hashes, closed critical-flag
sets, mount source/root hashes, `st_dev`, inode, kind, mode, link count, size, a
regular-file content SHA-256 when applicable, and a canonical identity SHA-256.
Missing Source, non-bind mounts, duplicate destinations, unresolved backing,
different common Source paths, or different common backing identities fail the
A/B equivalence gate. Directory identities deliberately do not claim a
recursive content hash. Config/runtime binds are arm-specific but must retain
the same destination/access shape and the same backing-equivalence subset:
filesystem type, device and `st_dev`, mount source/root/option hashes, and
critical mount/super flags. Their local Source/resolved hashes, inode, and file
content may differ; the management API's redacted non-plugin config must still
remain equal. `/cag/plugins` is also explicit:
CPA-only must have no plugin bind and CPA+CAG must have exactly one read-only
plugin bind; the existing copied-out one-SO SHA check binds its candidate bytes.
Final evidence publishes the full structured common and per-arm redacted mount
projections together with their recomputed common, arm-specific, and complete
projection hashes. The closed schema fixes every projection field and the
non-recursive directory-content boundary.

The assembler recomputes nearest-rank p50/p95/p99, aggregate throughput,
per-c audit-queue depth/capacity ratios, first/last five-minute median RSS,
every comparison, and every gate. Absolute A/B acquisition is paired by seeded
window, not request-by-request, so ordinary overhead uses the explicit
conservative fallback `max(0, CPA+CAG aggregate p95 - CPA-only aggregate p50)`
for each concurrency and then takes the worst concurrency. It never relabels
the CPA+CAG absolute p95 as plugin overhead.

The large-payload metric is the number of paired repetitions where CPA+CAG's
peak RSS growth above its own five-sample baseline exceeds CPA-only's analogous
growth by at least one complete 4 MiB payload. This is a Host-observed
full-payload-equivalent resident-amplification proxy. It is not an allocation
trace and must not be described as an exact copy/allocation count. The evidence
publishes both arms' baselines, peaks, growth and throughput so the count is
recomputable. The worst applicable values are:

```text
ordinary_plugin_overhead_p95_ms <= 10
five_repository_activation_p95_ms <= 250
public_adversarial_p95_ms <= 150
public_adversarial_p99_ms <= 300
fixed_workload_p99_regression_percent <= 10
host_throughput_vs_cpa_only >= 0.90
audit_queue_peak_ratio < 0.80
warm_rss_growth_60m_mib <= 64
large_payload_full_copy_regression = 0
restart_oom_panic = 0
unexpected_http_or_infrastructure_errors = 0
```

Build and then independently revalidate the derived evidence:

```bash
python3 -B tools/current-cpa-audit/host_performance.py summarize \
  --run-config "$EVIDENCE_DIR/run-config.json" \
  --candidate-manifest "$CANDIDATE_DIR/audit-candidate-manifest.json" \
  --workload-manifest "$PERFORMANCE_WORKLOAD_MANIFEST" \
  --config "$EVIDENCE_DIR/host-performance-config.json" \
  --measurements "$EVIDENCE_DIR/host-performance-measurements.json" \
  --output "$EVIDENCE_DIR/host-performance-evidence.json"

python3 -B tools/current-cpa-audit/validate.py host-performance \
  --run-config "$EVIDENCE_DIR/run-config.json" \
  --candidate-manifest "$CANDIDATE_DIR/audit-candidate-manifest.json" \
  --workload-manifest "$PERFORMANCE_WORKLOAD_MANIFEST" \
  --config "$EVIDENCE_DIR/host-performance-config.json" \
  --measurements "$EVIDENCE_DIR/host-performance-measurements.json" \
  --evidence "$EVIDENCE_DIR/host-performance-evidence.json"
```

Structural gaps (missing/duplicate cells, insufficient or discontinuous raw
samples, identity drift, relaxed thresholds, CPA-only loading CAG, or digest
tampering) abort without evidence. A complete threshold failure may emit a
truthful `FAIL` report for diagnosis, but the command exits nonzero and the
standalone validator rejects it as a gate result. No Host measurement or PASS
report is checked into this directory; a real second-machine run is still
required.

## Native CPA Host special-path evidence

Run the repository-owned integration selection against the same exact clean
checkout and nine-file candidate used by the semantic and Host-performance
lanes. The JSONL parser retains only hashes and PASS identities; it does not
copy `go test` output strings into its report:

```bash
NATIVE_HOST_LOG="$EVIDENCE_DIR/native-host-special-paths-go-test.jsonl"
NATIVE_HOST_REPORT="$EVIDENCE_DIR/native-host-special-paths.json"

go test -json -count=1 \
  -run=^TestCPAPluginHostBlocksBeforeUpstream$ \
  -tags=integration,sqlite_omit_load_extension \
  ./integration >"$NATIVE_HOST_LOG"

python3 -B tools/current-cpa-audit/native_host_special_paths.py pack \
  --candidate-manifest "$CANDIDATE_DIR/audit-candidate-manifest.json" \
  --candidate-artifact-id '<GitHub artifact-id>' \
  --candidate-artifact-name cyber-abuse-guard-linux-amd64-audit-candidate \
  --candidate-artifact-digest 'sha256:<GitHub artifact-digest>' \
  --candidate-artifact-size '<GitHub artifact-size>' \
  --go-test-jsonl "$NATIVE_HOST_LOG" \
  --checkout /srv/src/cyber-abuse-guard \
  --output "$NATIVE_HOST_REPORT"

python3 -B tools/current-cpa-audit/native_host_special_paths.py validate \
  --candidate-manifest "$CANDIDATE_DIR/audit-candidate-manifest.json" \
  --candidate-artifact-id '<GitHub artifact-id>' \
  --candidate-artifact-name cyber-abuse-guard-linux-amd64-audit-candidate \
  --candidate-artifact-digest 'sha256:<GitHub artifact-digest>' \
  --candidate-artifact-size '<GitHub artifact-size>' \
  --go-test-jsonl "$NATIVE_HOST_LOG" \
  --checkout /srv/src/cyber-abuse-guard \
  --report "$NATIVE_HOST_REPORT"
```

The report must contain exactly 35 code-owned critical subtests covering
no-copy/body limits, Multi-Agent v2, official Codex `response.failed` and
Originator behavior, Claude thinking replay, and ordered-tool request shapes.
Any FAIL, SKIP, missing test, candidate drift, dirty checkout, non-Linux-amd64
runtime, or Go-version drift rejects the report. This remains owner-run
evidence, not independent proof.

## Portable owner-run release admission

The complete machine and Host-performance bundles intentionally bind absolute
paths, real-path aliases, file metadata, directory device/inode identities, and
raw measurements. Copying only their final JSON files to GitHub cannot preserve
those guarantees. The pre-merge diagnostic must stop before this section and
must not call `pack`. On the owner-controlled second machine, call the release
packer only for the fresh post-squash protected-`main` `push` artifact, against
that post-main run's original `evidence-$RUN_ID` paths, after all five main
required checks and the semantic, Host-performance, and native Host validators
have passed:

```bash
python3 -B tools/current-cpa-audit/second_machine_release_admission.py pack \
  --manifest "$EVIDENCE_DIR/corpus-manifest.json" \
  --evidence "$EVIDENCE_DIR/machine-evidence.json" \
  --results "$EVIDENCE_DIR/transport-results.jsonl" \
  --run-config "$EVIDENCE_DIR/run-config.json" \
  --candidate-manifest "$CANDIDATE_DIR/audit-candidate-manifest.json" \
  --candidate-artifact-size 12345678 \
  --supplemental-archive "$SUPPLEMENTAL_ARCHIVE" \
  --supplemental-manifest "$EVIDENCE_DIR/supplemental-zip-manifest.json" \
  --supplemental-policy "$EVIDENCE_DIR/supplemental-zip-policy.json" \
  --supplemental-results "$EVIDENCE_DIR/supplemental-zip-results.jsonl" \
  --native-report "$NATIVE_HOST_REPORT" \
  --native-go-test-jsonl "$NATIVE_HOST_LOG" \
  --checkout /srv/src/cyber-abuse-guard \
  --workload-manifest "$PERFORMANCE_WORKLOAD_MANIFEST" \
  --performance-config "$EVIDENCE_DIR/host-performance-config.json" \
  --measurements "$EVIDENCE_DIR/host-performance-measurements.json" \
  --performance-evidence "$EVIDENCE_DIR/host-performance-evidence.json" \
  --host-admission "$EVIDENCE_DIR/host-admission/evidence.json" \
  --host-admission-300s "$EVIDENCE_DIR/host-admission/host-300s-samples.jsonl" \
  --host-admission-3600s "$EVIDENCE_DIR/host-admission/host-3600s-samples.jsonl" \
  --host-admission-realtime "$EVIDENCE_DIR/host-admission/realtime-auth-boundary-routes.jsonl" \
  --host-admission-config "$EVIDENCE_DIR/host-admission/config.json" \
  --host-admission-evidence-manifest "$EVIDENCE_DIR/host-admission/evidence-manifest.json" \
  --lazy-read-phase-boundary "$EVIDENCE_DIR/lazy-read/phase-boundary.json" \
  --lazy-read-runtime-read-trace "$EVIDENCE_DIR/lazy-read/runtime-read-trace.jsonl" \
  --lazy-read-runtime-read-summary "$EVIDENCE_DIR/lazy-read/runtime-read-summary.json" \
  --csam-text-fixture-manifest "$EVIDENCE_DIR/csam-text/fixture-manifest.json" \
  --csam-text-results "$EVIDENCE_DIR/csam-text/results.json" \
  --csam-text-summary "$EVIDENCE_DIR/csam-text/summary.json" \
  --csam-text-privacy-cleanup "$EVIDENCE_DIR/csam-text/privacy-cleanup.json" \
  --output "$EVIDENCE_DIR/second-machine-release-admission.json"
```

`--candidate-artifact-size` is the positive size from the exact GitHub Actions
artifact API response. Its ID, digest, run, attempt, workflow, commit, tree, and
SO identity already come from the candidate provenance in `run-config.json`.
The packer re-runs the corpus policy, machine evidence, run-config/candidate,
supplemental archive/evidence-copy/results, Host measurements/evidence, and
native Host report/Go-JSONL validators. It rehashes the operator-owned archive
before and after packing without extracting member text to disk, rebuilds its
reviewed manifest in memory, and removes a failed output only when its original
file identity is still present. It also rehashes the exact nine downloaded
candidate files, checks both SHA sidecars and `checksums.txt`, opens the Store
ZIP and compares its root SO bytes, and verifies the reused metadata/ruleset/
SBOM source identities.

The current packer accepts only a candidate whose manifest records
`event=push`, `head_branch=main`, and identical `head_sha`, `commit`, and
protected-main identity, from the exact successful main CI run. Keep this
push/main-only restriction locked by parser/validator negative tests and
contract pins; documentation alone is not an enforcement substitute.

The resulting
`cyber-abuse-guard.second-machine-release-admission.v3` report is canonical
JSON with one newline and a fixed 24-hour lifetime. It contains no repository
source text. It retains input-file hashes; CAG/CPA/candidate identities; the CI
artifact coordinates; five repository commit/tree pins and the one ZIP source
hash; the independent core 19-case/684-execution and supplemental
7-case/252-execution planes; supplemental expected/actual winning category and
rule pairs; zero-false-positive, 100%-malicious-recall,
side-effect, third-party-execution, cleanup, current Host-performance, and
native special-path gates; mandatory hash-bound `evidence_refs` for the
lazy-read phase/trace/cleanup and the separate synthetic CSAM-text 15/21 plane;
and four tool bundles (admission, machine,
Host-performance, and native Host). The GitHub validator recomputes all
summaries, denominators, and gates rather than trusting the report's `status`
field.

Create a draft staging Release with tag name
`v1.0.0-rc.3-second-machine-admission`, set `target_commitish` to the exact
protected `main` commit, and upload the report with the fixed asset name
`second-machine-release-admission.json`. The report cannot contain its own
asset ID/digest without a circular hash. `release-rc.yml` therefore closes that
last edge from GitHub API data: it accepts only the numeric draft Release ID,
numeric asset ID, and lowercase report SHA-256; proves exact membership/name/
upload state/API digest/size; downloads and rehashes the real bytes; checks the
expiry; and runs the validator from the exact signed tag.

Before that dispatch, a real authorized signer who controls the corresponding
private key must create `v1.0.0-rc.3` as a GitHub-verified signed annotated tag
on the exact protected-main commit. An unsigned annotated tag, lightweight tag,
Release-generated tag, unverified key, or signature that impersonates a
maintainer is not acceptable.

This portable report is owner-run release admission only. The original full
bundle remains the diagnostic evidence, and neither artifact is independent
proof. Do not delete the original evidence when staging the report.

## Local unit verification

These tests use generated inert fixtures and a loopback counted-Mock only. They
do not access GitHub, Docker, a real Provider, or third-party code.

The runner creates the evidence directory through an opened private parent,
then binds it by device/inode and keeps the directory descriptor for the entire
run. Top-level evidence, runtime-state writes, Mock verification bytes, results,
cleanup, and failure records are addressed through that descriptor. A path
replacement after binding therefore cannot redirect those writes and fails the
identity recheck. The five Docker bind mounts use only the separately verified
normal-path aliases described above because runc rejects proc-fd magic links as
mount sources. The normal absolute ancestor chain is captured before evidence
creation and revalidated before and after each daemon handoff; the held-fd and
normal aliases below the evidence root must still identify the same private
directories, and the private evidence root and parent owner/mode must not drift.
Linux does not provide a syscall that atomically creates a
directory and returns its new inode fd, so the short create-to-bind interval and
the normal-path Docker handoff are not same-UID isolation boundaries; a hostile
process sharing the runner UID is outside this diagnostic harness's threat
model. Same-UID independent attestation requires a trusted different-UID
collector or supervisor-provided fd and is not claimed here.

```bash
PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover \
  -s ./tools/current-cpa-audit/tests -p 'test_*.py'
python3 -B -m py_compile \
  tools/current-cpa-audit/acquire.py \
  tools/current-cpa-audit/audit_contract.py \
  tools/current-cpa-audit/counted_mock.py \
  tools/current-cpa-audit/host_performance.py \
  tools/current-cpa-audit/host_performance_workloads.py \
  tools/current-cpa-audit/native_host_special_paths.py \
  tools/current-cpa-audit/make_run_config.py \
  tools/current-cpa-audit/run.py \
  tools/current-cpa-audit/second_machine_release_admission.py \
  tools/current-cpa-audit/supplemental_zip.py \
  tools/current-cpa-audit/validate.py
```

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -B -m unittest discover -s tools/current-cpa-audit/tests -v
python -B -m py_compile `
  tools/current-cpa-audit/acquire.py `
  tools/current-cpa-audit/audit_contract.py `
  tools/current-cpa-audit/counted_mock.py `
  tools/current-cpa-audit/host_performance.py `
  tools/current-cpa-audit/host_performance_workloads.py `
  tools/current-cpa-audit/native_host_special_paths.py `
  tools/current-cpa-audit/make_run_config.py `
  tools/current-cpa-audit/run.py `
  tools/current-cpa-audit/second_machine_release_admission.py `
  tools/current-cpa-audit/supplemental_zip.py `
  tools/current-cpa-audit/validate.py
```

Remove any local `__pycache__` created by an interpreter that ignores the
environment setting; bytecode is not a deliverable.
