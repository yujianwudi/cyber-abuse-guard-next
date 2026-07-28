# Round 9 Linux old-SO rollback gate

This gate is an isolated compatibility drill for audit schema v6. It is not a
production rollback command and does not authorize Balanced admission,
deployment, a tag, or a release.

## Frozen historical identity

The original source provenance remains the predecessor repository:

```text
https://github.com/yujianwudi/cyber-abuse-guard.git
```

That remote is no longer available, so a live fetch is not a reproducible CI
dependency. Before it became unavailable, the exact annotated `v0.16-rc.2` tag
was used to derive a reviewed non-test source capsule at:

```text
testdata/round9-old-so-v0.16-rc.2-source
```

The capsule contains exactly 76 reviewed module and non-`*_test.go` source
files and is sufficient to build the plugin: `go.mod`, `go.sum`,
`cmd/cyber-abuse-guard`, files below `internal`, and `rules`. It is intentionally
not described as a minimal Linux import closure: historical build-inert helper
packages below `internal/round8test` and `internal/fixturepublish` remain frozen
in the reviewed set but are not imported by the plugin build. Every `*_test.go`
file and every `testdata`, evaluation, holdout, consumed, private, blind, or
retired path is excluded. Its deterministic file/path aggregate is:

```text
SHA-256: 0934503d90f08a7df0403f6325d7f30b6c9bfb0a6ec713d1b160469ee3857f4b
files: 76
source date epoch: 1784752111
```

The current working source, tags, objects, remotes, and caller-provided paths
are never used to substitute the historical plugin. The gate verifies the
capsule file set and aggregate before checking this recorded provenance:

```text
tag object: 58bd9b78886da04c03b2c6d8f28e8cd7f2436e84
commit: 9665fdd1aacab0d79b8790d68c87c6c8c80f8911
tree: 84c6636b2012c825627bad34f922dfa0329d0a1e
classifier: classifier-policy-v7
classifier SHA-256: ea8c4dcfacacc6478f86fd2ca5de96d667ae98f2fc6ff0c83d8e6092e9f6a82d
ruleset: 1.0.9
ruleset SHA-256: a3de344d3f6dc8eea86d946a823996494d4d297c41efcc6346a6ef757f263a7d
supported audit schema: 5
```

The tag object, peeled commit, and tree remain provenance records; each run
cryptographically verifies the reviewed capsule, classifier constants, schema
constant, and aggregate ruleset digest. It then builds a temporary Linux amd64
SO with Go 1.26.4 and `GOFLAGS=-mod=readonly`. Historical build metadata uses
the predecessor module path
`github.com/yujianwudi/cyber-abuse-guard/internal/buildinfo`, never the current
`cyber-abuse-guard-next` module path. The generated report explicitly records
`remote_ref_verified=false` and does not claim a live remote verification.

This proves the reviewed source-capsule identity used for the
compatibility executable. It does **not** claim byte equality with a previously
published v0.16-rc.2 release SO; no such archived release-asset byte identity is
supplied to this gate, so that field is reported as `NOT_PROVIDED`.

## Mechanical sequence

All paths are created below one mode-`0700` `mktemp` directory carrying a fixed
synthetic-only marker. The current migration fixture refuses any database
outside that directory.

1. Load the source-built v0.16-rc.2 SO through the CPA native ABI and call only
   `plugin.register`, with no Host API and no executor/model route call.
2. Let that SO create schema v5, then insert one synthetic audit event and one
   synthetic Raw Capture preview. No Provider, account pool, production
   database, customer request, or restricted evaluation material is used.
3. Open the v5 fixture with the current audit package. It must migrate to v6 and
   create exactly one `.pre-v6-*.bak` plus paired manifest even though the
   optional legacy backup switch is false.
4. Strictly validate the closed manifest fields, mode `0400`, filename, bytes,
   SHA-256, source `5`, target `6`, `exact_snapshot=true`, rollback instruction,
   synthetic sentinel rows, and SQLite `PRAGMA quick_check=ok`.
5. Give an isolated copy of schema v6 to the historical SO. Registration must
   fail with `database schema version 6 is newer than supported version 5`, and
   the probe database hash and sidecar state must remain unchanged.
6. Restore the verified backup with no-overwrite file creation, mode `0600`,
   file and directory `fsync`, and a byte-for-byte SHA-256 comparison with the
   manifest.
7. Load the historical SO against that restored schema-v5 copy. Registration,
   sentinel retention, and `quick_check` must pass.

The generated report uses schema `round9-old-so-rollback-gate/v2`, records that
only `plugin.register` ran, and fixes the final conclusion to:

```text
BLOCKED / NOT PROVIDED / REQUIRES INDEPENDENT AUDIT
```

`restricted_material_zero_access_claim=false` is intentional. This isolated
gate does not read restricted material, but it must not turn that local fact
into a broader zero-access attestation for the whole candidate.

## Run on Linux amd64

The gate never fetches the predecessor repository, a Git tag, or any GitHub
asset. It reads the byte-frozen capsule from the reviewed checkout and fails
closed if its path set, file count, or aggregate SHA-256 changes. A cold Go
module cache may still resolve the capsule's pinned dependencies through the
operator-configured module proxy. For a fully network-isolated run, prewarm and
verify that module cache, then set `GOPROXY=off`.

```bash
GO=/home/yujian/.cache/codex-go/go1.26.4/bin/go \
GOFLAGS=-mod=readonly \
make round9-old-so-rollback-gate
```

The default report path is
`dist/round9-worklogs/round9-old-so-rollback.json`. Temporary source, SO, v5,
v6, backup, restore, and ABI probe files are deleted when the gate exits.

## Remaining external conditions

- Byte identity for an archived/published v0.16-rc.2 SO: `NOT_PROVIDED`.
- Independent review of the exact Round 9 candidate and this evidence:
  `REQUIRES_INDEPENDENT_AUDIT`.
- Production rollback rehearsal with the real CPA service stopped, its real
  owner/group/mode, and operator health checks: `BLOCKED`; this task does not
  authorize or execute it.
