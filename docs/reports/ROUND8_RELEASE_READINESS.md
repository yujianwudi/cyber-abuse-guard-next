# Round 8 v0.16-rc.2 release readiness

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: 72976ff80ca9c25478fda5b50f4fd129ffc04e4c5fdcfde478ff06024a6839e1
```

Last updated: 2026-07-22 (Asia/Shanghai)

> **Frozen historical snapshot.** This report preserves the Round 8
> `v0.16-rc.2` source-tree release contract as recorded on the date above. Every
> embedded CPA v7.2.95 value and every "current" or "only current" statement is
> relative to that frozen Round 8 snapshot; none is the active repository release
> identity.
>
> The current formal CPA identity is:
>
> ```text
> current_formal_cpa: v7.2.102@8423cce2d1004e80948a9e2c60ee69354c0aabc3
> current_module_sum: h1:YimLZX/B4X5KA9v3Ss2afTmZtORYfT6UNMMteUKo+XA=
> current_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
> ```

This document describes the source-tree release contract. It is not a Host
attestation, independent audit, production authorization, or Release record.

## Candidate identity

```text
source_version: 0.16
candidate_tag: v0.16-rc.2 / NOT CREATED
platform: linux-amd64
release_kind: prerelease
latest: false
stable_v0.16: NOT_RELEASED
independent_audit: REQUIRED / NOT_PROVIDED
production_approval: NOT_GRANTED
source_tree_snapshot: NOT_ARTIFACT_BOUND / NOT_RELEASED
exact_main_ci: NOT_RUN / REQUIRED
counted_mock_host: NOT_RUN / REQUIRED_FOR_CPA_V7.2.95
release_workflow_phase_1: PRIVATE_HOST_TEST_CANDIDATE / 17_ASSETS / NO_RELEASE
release_workflow_phase_2: STRICT_HOST_EVIDENCE / 19_ASSETS / NON_LATEST_PRERELEASE
```

The earlier `v0.16-rc.1` package is historical production-incident evidence.
It must not be overwritten, relabeled, or treated as Round 8 output.

## CPA target

| Version | Official tag commit | Purpose |
|---|---|---|
| `v7.2.95` | `f71ec0eb6776854457892452cf28c47f0d658251` | Only current CPA release target |

With `CPA_COMPAT_VERIFY_REMOTE=1`, the source-contract script verifies the exact
lightweight tag in addition to Go module Origin, module sum, and go.mod sum.
With remote verification disabled, the script reports the tag lookup as skipped
instead of claiming it ran. The root and latest-contract modules are checked in
at v7.2.95, including `integration/pluginstorecontract`. The only accepted
profile is `primary`; the release invocation never claims
compatibility with a moving `latest` target.

Current source-tree evidence must be kept separate from that release-time
remote-verification contract:

| Current Linux development check | Result |
|---|---|
| Go toolchain | `go1.26.4 linux/amd64` |
| Unit / race / vet / module / vulnerability gates | **DEVELOPMENT SELF-CHECK PASS**; race reported no data race (plugin 379.920 s, classifier 69.762 s); 0 reachable vulnerabilities |
| Safe Gate | **DEVELOPMENT SELF-CHECK PASS** — `Ran 178 tests`, `OK`; real-tree gate passed with `entrypoints=8 make_targets=33 scripts=33`; actionlint v1.7.12 passed all eight active workflows using the reviewed custom-runner-label config |
| Benchmark gate | **DEVELOPMENT SELF-CHECK PASS** — isolated short p50/p95/p99 105.272/146.139/263.117 us; candidate-rich 45.245564 ms/op; single-clause 132.119 us/op with 35,667 B/op and 76 allocs/op; standalone full long-text test RSS 46,616 KiB |
| CPA v7.2.95 | **SOURCE/COMPILE/CONTRACT PASS** for the checked-in primary profile, including pluginhost, Responses `additional_tools`, Interactions, fail-open, Raw Capture management, and Store contracts |
| CPA tag identity | **REMOTE TAG IDENTITY PASS** for the exact tag commit shown above; official latest metadata remained `v7.2.95` |
| CPA remote latest/tag/Origin verification | **FULL REMOTE-ENABLED MATRIX PASS** — one `CPA_COMPAT_VERIFY_REMOTE=1` primary-profile run verified official `releases/latest == v7.2.95`, the exact Git tag commit, module Origin, and pinned module/go.mod sums without a repository token, then completed the full source/compile/contract matrix |
| Source-tree snapshot | **NOT TAG-, ARTIFACT-, OR RELEASE-BOUND** |
| Exact-main CI / counted-Mock Host / independent audit / production approval | **NOT_RUN or NOT_PROVIDED / STILL REQUIRED** |

These checks are source/compile evidence only. The phase-1 private candidate
still needs Linux amd64 CPA Host validation with a counted Mock upstream on the
single v7.2.95 identity. No real Provider, account, or production service may be contacted.

## Release workflow contract

The active `.github/workflows/release-rc.yml` accepts only an annotated
exact-main `v0.16-rc.2` tag. It requires the exact successful main CI run and
attempt, runs the complete Linux gate set, runs the CPA v7.2.95 contract, and performs
two independent clean-clone reproducibility builds. Its ten dispatch inputs
match the repository's stricter reviewed cap; GitHub's platform limit is 25.

The build lane runs on the declared `ubuntu-24.04` GitHub-hosted runner label
and carries that build job's `runner.os`, `runner.arch`, and
`runner.environment` into `build-metadata.json`. Ephemeral `runner.name` and
release-workflow run/attempt values are represented by stable
`UNRECORDED_EPHEMERAL_*` sentinels rather than being falsely treated as
reproducible artifact identity. The actual compiler environment is the
immutable container reference
`docker.io/library/golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b`.
Because the pinned job container cannot reliably observe the host image's
`ImageOS` or `ImageVersion`, both fields are honestly recorded as
`UNOBSERVABLE_FROM_PINNED_JOB_CONTAINER`; no admission or publication runner is
substituted for the build runner.

### Phase 1: private Host-test candidate

Set `publish_rc_release=false` and leave all four top-level protected-Host inputs
empty. The `host_run` input encodes the run ID and attempt as
`RUN_ID:RUN_ATTEMPT`; the other three bind the artifact ID, artifact digest, and
one-time challenge. The
workflow builds and byte-compares exactly 17 final assets, then uploads them as
a private GitHub Actions artifact retained for Host testing. The publish job is
skipped and no GitHub Release is created or modified.

Manifest schema 4 records:

```text
release_phase: candidate
publish_rc_release: false
host_evidence_validation: NOT_RUN / HOST_TEST_REQUIRED
primary_counted_mock_validation: NOT_RUN / HOST_TEST_REQUIRED
independent_audit: NOT_PROVIDED / required
independent_evaluation: NOT_PROVIDED / required
production_approval: NOT_GRANTED (expressed by the release status)
stable_v0.16: NOT_RELEASED (expressed by the release status)
```

### Phase 2: evidence-bound prerelease publication

First dispatch the protected `round8-host-validation.yml` workflow with the exact
successful Phase 1 run/attempt and artifact ID/digest plus a fresh lowercase
64-hex challenge. Its GitHub-hosted supply-chain job pulls the reviewed Go and
Debian Docker Official Images by immutable index digest, verifies the selected
Linux-amd64 manifest digest and config/image ID, and uploads an attested exact
bundle. The fixed self-hosted Linux x64 sandbox runner verifies that same-run
artifact ID/digest and signer, loads the two exact image IDs into only the
rootless sandbox daemon, and builds with `--pull=false`; it has no Docker Hub or
registry-mirror dependency. It also downloads the 17-file candidate, verifies
each Phase 1 GitHub attestation, proves the protected daemon/sandbox/probe
identity and Host bind-mount locality, runs the v7.2.95 counted-Mock lane, and creates
a GitHub attestation for exactly the canonical evidence and sidecar.

Then set `publish_rc_release=true` and provide the exact successful Host
run/attempt, Host artifact ID/digest, and the same challenge. The release workflow
downloads those two files directly from GitHub and verifies the signer workflow,
signer/source commit and ref, artifact digest, run identity, Phase 1 binding, and
schema-v2 execution identity. The JSON schema is closed: duplicate keys, missing
or extra top-level or nested keys, free-form fields, malformed values, and
identity drift are rejected. It must contain exactly:

```json
{
  "schema_version": 2,
  "validation_scope": "CPA_HOST_COUNTED_MOCK_ONLY",
  "candidate": {
    "tag": "v0.16-rc.2",
    "commit": "<exact 40-hex commit>",
    "tree": "<exact 40-hex tree>",
    "platform": "linux/amd64",
    "so_name": "cyber-abuse-guard-v0.16-rc.2.so",
    "so_sha256": "<exact 64-hex candidate SO SHA-256>"
  },
  "execution": {
    "trust": "GITHUB_ATTESTED_ROUND8_HOST_WORKFLOW",
    "challenge": "<fresh lowercase 64-hex challenge>",
    "execution_id": "<UUID>",
    "started_at": "<RFC3339 UTC timestamp>",
    "completed_at": "<RFC3339 UTC timestamp>",
    "workflow": {
      "repository": "yujianwudi/cyber-abuse-guard",
      "path": ".github/workflows/round8-host-validation.yml",
      "ref": "refs/tags/v0.16-rc.2",
      "sha": "<exact candidate commit>",
      "run_id": 123456789,
      "run_attempt": 1
    },
    "phase1": {
      "workflow_path": ".github/workflows/release-rc.yml",
      "run_id": 123456788,
      "run_attempt": 1,
      "artifact_id": 987654321,
      "artifact_digest": "sha256:<64 lowercase hex>"
    },
    "runner": {
      "name": "<protected runner name>",
      "environment": "self-hosted",
      "os": "Linux",
      "arch": "X64"
    },
    "sandbox": {
      "sandbox_id": "<protected sandbox ID>",
      "daemon_id": "<protected daemon ID>",
      "daemon_label": "io.cyber-abuse-guard.round8-sandbox=<sandbox ID>",
      "production_label": "io.cyber-abuse-guard.production=false",
      "probe_image_id": "sha256:<64 lowercase hex>",
      "locality_challenge": "PASS"
    }
  },
  "cpa": {
    "primary": {
      "version": "v7.2.95",
      "commit": "f71ec0eb6776854457892452cf28c47f0d658251",
      "image_id": "sha256:<64 lowercase hex>",
      "build_date": "<exact RFC3339 OCI build date>",
      "counted_mock_validation": "PASS",
      "host_results": {
        "protocol_requests": {
          "chat_benign_upstream": 1,
          "chat_malicious_upstream": 0,
          "responses_benign_upstream": 1,
          "responses_malicious_upstream": 0
        },
        "matrix": {
          "benign_total": 42,
          "benign_passed": 42,
          "paired_malicious_total": 42,
          "paired_malicious_blocked": 42
        },
        "transports": {"nonstream_passed": true, "stream_passed": true},
        "modes": {
          "audit_passed": true,
          "balanced_passed": true,
          "strict_passed": true
        },
        "policy_outcomes": {
          "balanced_incomplete_allow": true,
          "strict_incomplete_block": true,
          "usage_queue_allow_delta": 1,
          "usage_queue_blocked_zero": true
        },
        "database": {
          "quick_check": "ok",
          "schema_version": 5,
          "migration_versions": [1, 2, 3, 4, 5],
          "wal_checkpoint_passed": true
        },
        "raw_capture": {
          "only_blocked_passed": true,
          "ttl_dedup_passed": true,
          "schema_v3_redaction_metadata_passed": true,
          "purge_wal_passed": true
        },
        "lifecycle": {
          "restart_cycle_passed": true,
          "unexpected_restart_count": 0,
          "oom": false,
          "panic_count": 0,
          "fatal_count": 0,
          "plugin_error_count": 0
        }
      }
    }
  },
  "mock": {
    "contract": "round8-counted-mock/v1",
    "source": "https://github.com/yujianwudi/cyber-abuse-guard-next",
    "revision": "<exact 40-hex candidate commit>",
    "tag": "v0.16-rc.2",
    "tree": "<exact 40-hex candidate tree>",
    "image_id": "sha256:<64 lowercase hex>"
  },
  "safety": {
    "real_provider_contacted": false,
    "production_accessed": false,
    "unexpected_restart_count": 0,
    "oom": false,
    "panic_count": 0,
    "fatal_count": 0,
    "plugin_error_count": 0
  }
}
```

The Host artifact digest and GitHub attestation must match the exact protected
Host run before the evidence is parsed. The evidence SO hash must equal the SO
reproduced in that same release workflow run.
The CPA v7.2.95 result must bind its immutable local image ID and exact RFC3339 build date
to the runtime-identity transcript observation. The counted-Mock section
must bind its contract, repository source, candidate revision/tag/tree, and
immutable image ID. The primary result must carry the closed numeric/boolean
`host_results` object above; a
standalone self-reported `PASS` is rejected. JSON scalar types are exact, so
booleans or floating-point lookalikes cannot stand in for integer counters. Required facts are Chat and
Responses benign upstream deltas of 1, malicious upstream deltas of 0, all 42
benign cases passed, all 42 paired malicious cases blocked, streaming and
non-streaming coverage, audit/balanced/strict coverage, SQLite `quick_check=ok`,
Balanced-incomplete allow and Strict-incomplete block outcomes, usage-queue allow
delta 1 with blocked zero, Raw Capture only-blocked/TTL-dedup/schema-v3-redaction/
purge-WAL checks, WAL checkpoint success, a restart-cycle pass, zero unexpected
restarts, no OOM, and zero panic/fatal/plugin errors.
The evidence and `round8-host-evidence.json.sha256` are copied into each clean
build, the audit bundle, `checksums.txt`, manifest, private transfer artifact,
and final Release allowlist. All 19 final assets must be byte-identical across
the root build and both independent clean clones.

Only then may the publish job create or repair a draft. Existing Phase 1 assets
are enumerated and downloaded for byte comparison; any extra asset or same-name
byte mismatch fails. The job never clobbers an asset: after every existing byte
has been verified, it uploads only the missing Phase 1 assets, reverifies the
complete 17-asset Phase 1 set, fingerprints it, and then uploads only missing
Host-evidence assets. This also permits safe retry after an interrupted partial
Phase 1 upload without replacing any established asset. The complete 19-asset
draft is downloaded again before publication with `prerelease=true` and
`latest=false`. The workflow checks that a stable `v0.16` tag is absent and
requires the GitHub latest-release API to remain exactly `v0.15` after the RC is
published. It does not create the tag, bypass exact-main CI, contact a real
Provider, access production, or authorize production deployment.

### Immutable published-RC read-only recovery

If `v0.16-rc.2` is already published with `draft=false`, **Re-run failed jobs**
on the same workflow run may reuse that run's exact 19-file transfer artifact
and enter the publish step's existing no-mutation verification branch.

A new workflow dispatch or **Re-run all jobs** reruns admission. Admission
classifies the existing Release as `already_public=true`; the write-capable
build and publish jobs are skipped before their setup, cache, provenance
generation, or Actions artifact upload. A separate `verify_published` job with
only `actions: read`, `attestations: read`, and `contents: read` uses the same
pinned builder container and restricted checkout, explicitly sets
`setup-go cache:false`, reruns the complete Linux gates, and rebuilds the exact
19-asset publish candidate. It verifies the exact Release `tag_name`, annotated
tag object and target commit/tree, exact-main CI run and attempt, canonical
title and body, `draft=false`, `immutable=true`, `prerelease=true`, and the fact
that latest remains exactly `v0.15`.

The dedicated verifier requires exactly 19 canonical asset names with no
missing or extra item. For every asset it checks the Release API SHA-256 digest,
then verifies all checksum sidecars, the canonical timing-free test summary,
manifest-bound hashes and identity, and the GitHub signed build attestation. It
byte-compares every rebuilt artifact with its downloaded public counterpart and
rechecks the immutable Release fingerprint after the build. It does not upload,
replace, edit, create, or delete any remote state. The policy is read-only and
no-state-mutation rather than an inaccurate promise that all underlying
read-only protocols use only specific HTTP verbs. Any identity, metadata,
asset-count, digest, byte, title/body, flag, latest-release, manifest, or
attestation mismatch is fail-only and requires manual investigation.

The phase-2 manifest states
`HOST_EVIDENCE_ATTESTED_PROTECTED_WORKFLOW / SANDBOX_IDENTITY_AND_LOCALITY_VERIFIED`
and records the evidence source as an attested protected Host workflow artifact.
This is GitHub-signer, workflow/ref/commit, run/artifact, sandbox-identity, and
counted-Mock evidence—not real Provider validation or production validation.
Independent audit and independent evaluation remain `NOT_PROVIDED` and
`required`.

The repository cannot create its own trust root. Publication remains blocked
until administrators configure protected `round8-host-validation` and
`round8-rc-publication` environments, required reviewers, disabled self-review
and admin bypass, exact deployment policies, the dedicated runner, and the three
protected sandbox identity variables.

## External gates still required

Before Balanced can be reconsidered, all of the following remain mandatory:

1. independent source, rules, privacy, and artifact audit;
2. phase-2 CPA v7.2.95 counted-Mock Host evidence bound to the reproduced SO hash;
3. exact-commit GitHub CI and reproducible 19-asset publication package;
4. 7-14 days of production `audit` observation with no confirmed predicted-block
   false positives and no latency/database regression;
5. a separately approved 1% -> 5% -> 10% Balanced canary with automatic rollback.

Development self-tests do not satisfy these external gates. There is no stable
`v0.16`, and production approval has not been granted.
