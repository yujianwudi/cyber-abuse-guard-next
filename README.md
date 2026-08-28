# Cyber-Abuse-Guard Next

```text
current_classifier_policy_version: classifier-policy-v20
current_classifier_policy_sha256: f98ee38cea5b38b60130b98bd3ca6100cb6aeeee223128311235469af40ec9e3
```

English | [简体中文](README_CN.md)

## Project identity

```text
current_source_version: 1.0.0
current_rc_tag: v1.0.0-rc.3
current_cpa_target: v7.2.144 / d36b776c790a4d58027fd4fb434800fb5334bceb
current_cpa_contract: C_ABI_1 / RPC_SCHEMA_4
current_cpa_module_sum: h1:ZNLmwkaMZ+4KbR8BqLHUUDdDzWsQKpXZQbLYesh4ttk=
current_cpa_go_mod_sum: h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=
current_platform: linux-amd64
current_audit_sqlite_schema: 7
current_csam_text_policy: csam-text-policy-v1 / 85437c9e1bd94603f2a837bd66ede6a102b844143e3e869e768901ce9b56276e
current_second_machine_release_admission_schema: cyber-abuse-guard.second-machine-release-admission.v3
current_active_workflows: 4_REPOSITORY_YAMLS / ci.yml / codeql.yml / policy-gate.yml / release-rc.yml / PLATFORM_DYNAMIC_DEPENDABOT_ALLOWLIST
current_status: ROUND16_ADMISSION_INCOMPLETE / REAL_SECOND_MACHINE_REQUIRED / RC_NOT_PUBLISHED
```

Cyber-Abuse-Guard Next (CAG) is a native, deterministic, pre-routing policy and
audit plugin for [CLIProxyAPI (CPA)](https://github.com/router-for-me/CLIProxyAPI).
It is designed to reduce cyber-abuse risk while preserving ordinary coding,
defensive security, incident-response, compliance and authorized operations.
The active source line is `main`. CPA `v7.2.144` with RPC schema 4 is the only
supported compatibility target in this tree.

The RC1 base code is merged on `main` and its exact post-merge Linux CI passed.
The immutable `v1.0.0-rc.1` tag produced no Release after GitHub began exposing
platform-owned Dependabot workflows in the Actions inventory. The immutable RC2
tag is also historical; `v1.0.0-rc.3` updates the active CPA/schema and admission
contracts without weakening the four repository-owned workflow allowlist. The
reviewed workflow requires a canonical, non-expired real second-machine v3
admission report bound to the exact candidate. Cancellation, a missing remote
run, an old candidate, or a local self-check cannot satisfy the RC release gate.

## What the plugin does

The supported request path is evaluated before authentication scheduling,
provider execution, usage accounting, SSE establishment and upstream work.
Classification is local and deterministic; request content is not sent to a
public classifier. A confirmed policy violation can terminate at the plugin
boundary with HTTP 403. Runtime and coverage failures follow the explicit mode
contract rather than silently becoming a security PASS.

The project is not an all-traffic proxy. CPA `/v1/realtime*` currently bypasses
the CAG RequestInterceptor, ModelRouter and request lifecycle, so realtime is
`OUT_OF_SCOPE / UNPROTECTED / CAG_NOT_VISIBLE`. The claim is limited to paths
where CPA actually invokes the registered plugin callbacks.

## Runtime architecture

```text
CPA schema-4 request
        |
        v
RequestInterceptor (before-auth)
        |
        +--> bounded extractor and role/provenance normalizer
        |          |
        |          v
        |    streaming classifier session
        |          |
        |          +--> policy winner / coverage / explanation
        |          +--> bounded audit event and counters
        |
        +--> disposition: allow, observe, audit, balanced block, strict block
        |
        v
CPA authentication -> provider/router -> usage/SSE/upstream
```

The main Go packages are separated by trust boundary:

- `internal/extract` parses CPA-visible JSON, multipart and stream fields while
  preserving logical field boundaries, role and provenance.
- `internal/classifier` performs bounded streaming normalization, semantic
  matching, winner ordering and policy identity checks.
- `internal/csamtext` contains the text-only CSAM policy and benign protective
  output regressions. It does not inspect or retain real media inputs.
- `internal/plugin` owns CPA callbacks, disposition, lifecycle state, audit
  persistence, management status and fail-closed error handling.
- `internal/audit` implements SQLite schema 7, bounded retention, readiness and
  raw-capture controls. Raw Capture is opt-in and never a license to log secrets.
- `internal/subject` owns bounded subject identifiers and risk state; it does not
  make a provider or OAuth decision.
- `rules` embeds the reviewed policy manifest; `cmd/` contains the plugin entry
  point and development-only validators.

## Policy modes and false-positive posture

The safe startup configuration is `mode: observe` with subject control disabled.
The modes are intentionally explicit:

| Mode | Complete harmful request | Incomplete inspection |
|---|---|---|
| `off` | allow | allow |
| `observe` | observe only | allow + observe |
| `audit` | audit only | allow + audit |
| `balanced` | block at the reviewed threshold | allow + audit |
| `strict` | block at the strict threshold | fail closed + audit |

Normal, defensive and authorized requests are first-class regression inputs.
The classifier does not treat a risk word, repository name or security term as
an automatic block. A winner must satisfy the bounded semantic and ownership
contracts; ambiguous, incomplete or cross-field evidence cannot be promoted by
an unrelated carrier. This is the central protection against overblocking.

## Audit, privacy and CSAM boundaries

Audit events contain bounded decision metadata, coverage state, explanation
variants and fixed low-cardinality counters. They do not store full prompts by
default. If an operator enables Raw Capture for review, access control,
retention, redaction and storage-capacity rules still apply; a storage failure
does not change the classification result.

The CSAM lane is text-only and policy-scoped. Benign prevention guides, hotline
notices, reporting instructions and quoted safety research are regression cases.
No real media input, provider credential, OAuth session or third-party repository
code is required by the repository tests.

## CPA and Host compatibility

The active contract is CPA `v7.2.144@d36b776c790a4d58027fd4fb434800fb5334bceb`,
C ABI 1 and RPC schema 4. schema 4 retains `OriginalRequest` and `RequestBody`
only in header-init; payload chunks omit them. The plugin does not register a
successful-response or stream-chunk interceptor.

Host-performance collection is Linux-only. Docker Engine API v1.44 reads are
bounded and identity-checked. The queue sampler uses one private HTTP/1.1
management connection per measured cell, reuses it sequentially, rejects public
targets and server-requested closes, and fails closed on malformed, oversized or
non-strict JSON. Cadence, sample count, deadline and acceptance thresholds are
unchanged by this optimization.

Any future protected evaluator must use an internal-only Docker network that
publishes no CPA or counted-Mock ports to the Host. The accepted topology records
`host_ip=internal-only, host_port=0, container_port=8317`, reaches only the exact
two Docker-inspect-verified, distinct RFC1918 bridge IPv4 addresses, and treats
any Host binding, additional container, or non-internal network as inadmissible.

## Build and install (Linux amd64)

Requirements: Go 1.26.6, a Linux amd64 toolchain, CPA v7.2.144, and a CPA plugin
loader compatible with C ABI 1 / RPC schema 4.

```bash
git clone https://github.com/yujianwudi/cyber-abuse-guard-next.git
cd cyber-abuse-guard-next
make round6-format-check round6-module-verify
make unit-test
make build-linux-amd64
```

The normal output is `dist/cyber-abuse-guard-v1.0.0.so`. Install it through the
CPA plugin mechanism and verify the CPA management status endpoint before
enabling a blocking mode. Do not copy a `.so` built for another CPA ABI/schema.

## Verification

The repository-owned Linux audit tool currently closes `315/315` tests with zero
skips. Exact GitHub CI additionally runs Go unit/vet/race, bounded fuzzing,
policy and public-corpus contracts, dependency vulnerability checks, Linux Host
artifact loading and reproducibility. Local receipts are traceability records,
not independent attestations.

```bash
python3 -I -B -m unittest discover -s tools/current-cpa-audit/tests -p 'test_*.py'
bash scripts/release-doc-consistency.sh
python3 -B scripts/round6_safe_gate_contract.py --root .
make repository-secret-scan
```

The five-repository and supplemental ZIP lanes are identity-bound, do not
execute third-party code, and are separate from ordinary unit tests. A fresh
real second-machine run for the exact candidate is mandatory and remains
pending; without its admitted report, the RC release gate stays closed.

## Repository layout and archive policy

| Path | Purpose | Lifecycle |
|---|---|---|
| `cmd/` | plugin entry point and validators | maintained |
| `internal/` | runtime, classifier, audit and CPA integration | maintained |
| `rules/` | embedded policy manifest | maintained |
| `tools/current-cpa-audit/` | Linux audit, Host and admission contracts | maintained |
| `testdata/` | versioned, hashed regression fixtures | retained when referenced by tests or evidence |
| `docs/` | architecture, governance, status and evidence | current plus explicitly labeled history |
| `docs/archive/` | retired workflows and superseded notes | immutable archive; not an execution entry point |
| `.github/workflows/` | the four reviewed workflow YAML files | active only where indexed |

Historical test fixtures are not “dead code” when a validator proves an old
identity, rollback boundary or evidence non-transfer rule. They remain in place
until the corresponding contract is deliberately versioned. Retired workflow
definitions are already under `docs/archive/workflows/`; the archive index is
the authoritative map. No generated reports, credentials, raw prompts or local
`_cag_*` run helpers belong in Git.

## Documentation and governance

- [Round 16 CPA v7.2.144 task book](docs/ROUND16_CPA_V7_2_144_TASK_BOOK.md)
- [Round 16 status and evidence boundary](docs/ROUND16_STATUS.md)
- [Historical Round 15 CPA v7.2.142 status](docs/ROUND15_STATUS.md)
- [Release policy](docs/RELEASE_POLICY.md)
- [Repository governance](docs/REPOSITORY_GOVERNANCE.md)
- [Security policy](SECURITY.md)
- [Archive index](docs/archive/README.md)

The Release workflow is fail-closed and may publish only after every applicable
acceptance gate passes. In particular, no old PASS, local receipt or historical
CPA result can substitute for a new exact candidate and its required admission
evidence.

<!-- The Round 12 block retained below is historical v7.2.124 evidence. -->
<!-- Historical evidence remains in docs/ROUND12_STATUS.md and is not a current release claim. -->
