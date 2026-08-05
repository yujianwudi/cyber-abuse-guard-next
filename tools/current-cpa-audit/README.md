# Current CPA five-repository isolated audit

This directory is the RT12-05 diagnostic harness for **CPA v7.2.116** at commit
`a88197f845c979132c8978ea223c6af05cc81536`. Its output claim is deliberately
limited to:

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
  descriptors, opens and unlinks files relative to them, rechecks
  size/SHA and inode identity, and requires the post-unlink link count to be
  zero. Directory replacement, same-name decoys, or external hardlinks fail
  closed and can never produce `retained=false` PASS evidence.
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
- Cleanup never calls a global prune and never removes images. It stops CPA and
  Mock gracefully, checkpoints SQLite, and removes only resources carrying the
  exact run label.

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

`third_party_code_executions` counts execution of the five untrusted corpus
repositories and must be zero. CPA/CAG and the repository-owned counted-Mock
are the explicitly audited runtime, not corpus execution.

## Files

- `acquire.py` — read-only, exact-current-HEAD candidate acquisition plus
  exact candidate-text discard.
- `repository-policy.json` — fixed repository/path/ground-truth metadata and
  per-source human-review pins. The checked-in file is approved for the exact
  five-repository source identities reviewed on 2026-08-05; source drift fails.
- `audit_contract.py` — closed corpus, run-config, result, and machine-evidence
  validators. Unknown or missing fields fail.
- `counted_mock.py` and `Dockerfile.mock` — body-discarding upstream with
  independent `mock`, `auth`, and `provider` counters.
- `make_run_config.py` — hashes local inputs and emits canonical mode-0600 JSON.
- `run.py` — three-to-ten cold-start isolated runner.
- `machine-evidence.schema.json` — closed JSON Schema 2020-12 description.
- `validate.py` — standalone fail-closed validator.
- `tests/` — standard-library unit tests; no live Provider or GitHub access.

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
  --output /srv/cag-audit/acquisition-approved

python3 -B tools/current-cpa-audit/validate.py corpus \
  --manifest /srv/cag-audit/acquisition-approved/corpus-manifest.json \
  --corpus-root /srv/cag-audit/acquisition-approved
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

Preload, do not pull during the audit:

1. CPA v7.2.116 image by exact RepoDigest and image ID.
2. The official v7.2.116 linux/amd64 asset and its published SHA-256.
3. The exact CPA binary SHA-256 expected inside that image.
4. A counted-Mock image built from this directory with a previously reviewed,
   digest-pinned Python base image.

Example Mock build (replace both digests with reviewed values):

```bash
MOCK_SOURCE_SHA256="$(sha256sum tools/current-cpa-audit/counted_mock.py | awk '{print $1}')"
docker build --pull=false \
  --build-arg PYTHON_IMAGE='python:3.12-slim@sha256:<reviewed-base-digest>' \
  --build-arg MOCK_SOURCE_SHA256="$MOCK_SOURCE_SHA256" \
  -f tools/current-cpa-audit/Dockerfile.mock \
  -t private-audit-registry/cag-counted-mock:rt12 \
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
policy, Mock source, and official-asset hashes. Supply image identities and the
image-contained CPA binary identity explicitly.

```bash
python3 -B tools/current-cpa-audit/make_run_config.py \
  --output /srv/cag-audit/run-config.json \
  --run-id rt12-cpa-20260804-001 \
  --seed 1205 \
  --cold-start-count 3 \
  --manifest /srv/cag-audit/acquisition-approved/corpus-manifest.json \
  --evidence-directory /srv/cag-audit/evidence-rt12-cpa-20260804-001 \
  --cag-repository /srv/src/cyber-abuse-guard \
  --cag-so /srv/artifacts/cyber-abuse-guard.so \
  --cpa-official-asset /srv/artifacts/CLIProxyAPI_7.2.116_linux_amd64.tar.gz \
  --cpa-official-asset-sha256 <published-64-hex> \
  --cpa-binary-path /CLIProxyAPI \
  --cpa-binary-sha256 <64-hex> \
  --cpa-image-ref 'private-audit-registry/cpa@sha256:<64-hex>' \
  --cpa-image-id 'sha256:<64-hex>' \
  --mock-image-ref 'private-audit-registry/cag-counted-mock@sha256:<64-hex>' \
  --mock-image-id 'sha256:<64-hex>'

python3 -B tools/current-cpa-audit/validate.py run-config \
  --config /srv/cag-audit/run-config.json
```

The evidence binds the input config SHA, a separate runtime config SHA for
each cold start, every template SHA, individual runner source/schema/policy
SHAs, and a bundle SHA over the operational file-name-to-SHA map.

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
the five expected Source/Destination/RW/rprivate bind contracts and the one
closed `/tmp` tmpfs contract; any other bind, volume, or non-bind mount fails
closed. The dedicated-UID condition bounds the non-atomic daemon handoff. The
runner itself creates only an internal bridge.

```bash
python3 -B tools/current-cpa-audit/run.py \
  --config /srv/cag-audit/run-config.json
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
  `PRAGMA quick_check = ok`, schema 6, complete non-busy WAL checkpoint after
  stop, exit/restart/OOM/panic/fatal/plugin-error counts zero;
- existing business-container snapshot unchanged; exact labelled cleanup
  complete; infrastructure errors and third-party code executions zero.

`unique_semantic_cases`, `unique_content_hashes`, and
`transport_executions` are separate fields. Repeating transports or cold
starts never inflates semantic/content counts.

On any failure, `machine-evidence.json` is not emitted. `failure.json` contains
only an error identifier and traceback digest. Cleanup and corpus-text removal
still run. A failure file is not a PASS artifact.

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
  --manifest /srv/cag-audit/evidence-rt12-cpa-20260804-001/corpus-manifest.json \
  --evidence /srv/cag-audit/evidence-rt12-cpa-20260804-001/machine-evidence.json \
  --results /srv/cag-audit/evidence-rt12-cpa-20260804-001/transport-results.jsonl \
  --run-config /srv/cag-audit/evidence-rt12-cpa-20260804-001/run-config.json
```

The Python validator is authoritative for cross-file and cross-row
relationships that JSON Schema cannot express (digests, pre/post identity,
matrix coverage, deterministic order, cold-start consistency, request/event
pairing, and exact cleanup multiplicity). The JSON Schema is the closed shape
contract; every object has `additionalProperties: false`.

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
  tools/current-cpa-audit/make_run_config.py \
  tools/current-cpa-audit/run.py \
  tools/current-cpa-audit/validate.py
```

```powershell
$env:PYTHONDONTWRITEBYTECODE='1'
python -B -m unittest discover -s tools/current-cpa-audit/tests -v
python -B -m py_compile `
  tools/current-cpa-audit/acquire.py `
  tools/current-cpa-audit/audit_contract.py `
  tools/current-cpa-audit/counted_mock.py `
  tools/current-cpa-audit/make_run_config.py `
  tools/current-cpa-audit/run.py `
  tools/current-cpa-audit/validate.py
```

Remove any local `__pycache__` created by an interpreter that ignores the
environment setting; bytecode is not a deliverable.
