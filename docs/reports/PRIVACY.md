# Privacy Verification Report — post-v10 development handoff

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: 06cbec97880403268ebd8c41ce3e6f7ff9413e195539c79368d607ed3e86e1b4
```

Last updated: 2026-07-22 (Asia/Shanghai)

## Status

Current privacy work has **DEVELOPMENT SELF-CHECK** evidence on Linux/WSL ext4
with Go 1.26.4 and CGO/race enabled, plus exact implementation-freeze
**GITHUB CI PASS** evidence for real-Host management authentication, proxy 413,
development-candidate artifact/SBOM scans, race, vet, and privacy scripts. Leo's
independent real-Host/artifact review remains `NOT RUN`.

Earlier over-broad read-only searches displayed evaluation/holdout test or
historical-report filenames, historical ruleset SHA-256 references, caller-path
lines, and aggregate summaries. During the current closure, one additional broad
`git grep` unexpectedly emitted several individual request and label lines from
retired holdout fixture files. The possessive-browser-target false negative had
already been identified by classifier review before that search; none of the
emitted lines was copied into source, tests, or documentation or used to choose
rules, predicates, scores, or thresholds. A separate over-broad
`go test ./internal/classifier` may also have compiled or run the restricted gate
and is excluded from current evidence. This session therefore cannot claim
fixture non-access, zero-access, blind, or independent evidence; those statuses
remain `NOT_PROVIDED`, and a new untouched holdout under an independent reviewer
is required. The frozen aggregate v10 result remains `CONSUMED / FAIL` and is
unrelated to the privacy PASS rows below.

The WSL command `make cpa-router-fixture-blackbox`, the now-removed legacy
target `cpa-v7272-host-blackbox`, and
`scripts/management-proxy-413-test.sh` were mistakenly executed outside the
authorized evidence path. They used random loopback ports and Mock components
only, contacted no production service or real provider, and cleanup left no
fixture process running. Their results are excluded:

```text
LOCAL MIS-EXECUTION RECORDED / EXCLUDED; NOT AUTHORITATIVE
```

## Privacy invariants

With `audit.raw_capture.enabled: false` (the default), the plugin must never
persist, log, or return through management or executor surfaces:

- raw Prompt, Messages, Instructions, Tool Arguments, tool output, or uploaded
  code;
- `Authorization`, plaintext downstream API keys, Cookie, OAuth/refresh/session
  tokens, or provider credentials;
- plaintext subject, IP address, arbitrary domain, full model name, HMAC secret,
  or Management Key;
- decoded dangerous payloads, matched spans, victim identifiers, or panic/error
  values containing attacker-controlled text.

`audit.log_original_text=true` is rejected at initial configuration and hot
reconfigure. There is no debug or test override. The only supported content
review exception is the separate `audit.raw_capture` facility: it requires
ordinary audit storage, applies only to final blocking decisions (`block`,
including subject cooldown), mandates secret
redaction, truncates each preview, and deletes captures under a bounded TTL.
Allowed, observed, and audit-only requests never enter the capture table.

Allowed retained values are limited to fixed/coarse metadata: timestamps,
disposition, mode, category, score, stable rule/reason IDs, a domain-separated
request digest, subject HMAC, domain-separated model digest, canonical source
format, stream flag, scanned-byte count, latency, aggregate counters, build/
ruleset/classifier-policy identity, and bounded persistence state. When raw
capture is explicitly enabled, the additional allowed record is limited to
block-event correlation metadata, redaction/truncation flags, a bounded
redacted preview, and a SHA-256 digest of the original complete request bytes.

The classifier `BehaviorGraph` contains only stable booleans/relations and never
contains a prompt span or decoded content.

## Implemented controls

- Request correlation is `sha256:` over an explicit domain separator plus the
  request bytes; it is distinct from model and subject correlation domains.
- Raw-capture previews are secret-redacted before UTF-8-safe truncation. The
  feature is default-off, blocking-disposition-only, separately TTL-bound, and
  queryable only through CPA's authenticated exact management route. Redaction
  is best-effort and is not represented as a complete DLP guarantee.
- Subjects are `hmac-sha256:` values only. Optional persisted idempotency
  receipts store request digests, not raw requests.
- Model names are stored only as `sha256-model-v1:` digests; source formats are
  canonicalized to a fixed enum.
- SQLite, CSV, management, panic recovery, logger callbacks, migration backups,
  subject snapshots, release evidence, and watchdog output have typed canary
  tests.
- SQLite/config errors exposed through management are coarse and do not echo
  attacker-controlled paths, SQL, or data.
- Unix secret loading rejects short/empty keys, wrong owner/mode, symlinks,
  FIFOs/devices, and validates/reads the same descriptor.
- Before a v1→v2 migration publishes a backup or writes schema v2, legacy
  `request_hash`, `subject_hash`, `model`, and `source_format` values are checked
  against the digest/fixed-provider privacy contract. Any nonconforming value
  fails closed: no backup is published, no migration occurs, and the original
  database is retained for operator repair. The plugin does not automatically
  sanitize a legacy plaintext database.
- Schema v4 isolates sensitive previews in `raw_request_captures`; each row has
  an audit-event foreign key with `ON DELETE CASCADE`, one capture per event,
  and fixed indexes for timestamp and request correlation. Opening the database
  removes expired captures before serving queries.
- Classifier and media handling perform no guard-originated DNS lookup, remote
  classification, media fetch, archive expansion, or telemetry call.

The persisted subject snapshot still has no keyed whole-snapshot MAC. A local
writer who already controls the SQLite file can delete otherwise valid rows;
filesystem ownership remains a trust boundary.

## Development canary method

Tests inject unique synthetic prompt/key/auth/cookie/OAuth/domain/model/subject
canaries into allowed, blocked, parse-error, truncation, panic, audit,
persistence, migration, management, and watchdog paths. They then scan:

1. SQLite DB/WAL/SHM and migration backups;
2. subject snapshots and sidecars;
3. JSON/CSV audit exports;
4. management status/events/test and executor responses;
5. panic recovery, host logger, stdout, and stderr;
6. release-evidence inputs and generated evidence text;
7. disposable integration artifacts before cleanup.

Tests report only the surface/category and PASS/FAIL; they do not print the
secret canary value on failure.

## Executed development checks

| Evidence class | Command/scope | Result |
|---|---|---|
| DEVELOPMENT SELF-CHECK, WSL/ext4 | `go test -race ./internal/subject ./internal/config -count=1 -v` | **PASS** |
| DEVELOPMENT SELF-CHECK, WSL/ext4 | `go test -race ./internal/audit -count=1 -v` | **PASS** |
| DEVELOPMENT SELF-CHECK, WSL/ext4 | plugin tests matching `EndToEndPrivacyCanaries`, `CallerControlledAuditMetadata`, `ProductionStatus`, `SubjectPersistenceRestores`, pending/logger/lifecycle race cases | **PASS** |
| DEVELOPMENT SELF-CHECK, WSL/ext4 | `go vet ./internal/audit ./internal/config ./internal/plugin ./internal/subject` | **PASS** |
| DEVELOPMENT SELF-CHECK, script | `scripts/check-production-health-test.sh` | **PASS** |
| DEVELOPMENT SELF-CHECK, script | `scripts/release-evidence-privacy-test.sh` | **PASS** |
| Windows native SQLite/race | native CGO/NTFS release-equivalent path | **NOT RUN / NOT A SUPPORTED RELEASE PATH** |
| Real CPA management authentication | missing/wrong/client/correct Management Key 401/200 matrix on the implementation-freeze Host | **GITHUB CI PASS** |
| Reverse-proxy request ceiling | >1 MiB returns 413 before CPA `io.ReadAll` | **GITHUB CI PASS**; local mis-execution remains excluded |
| Development-candidate `.so`/store ZIP/audit bundle/SBOM scan | exact implementation-freeze candidates | **GITHUB CI PASS**; not a formal release |
| GitHub CI | implementation freeze | **PASS** — push `29292693070`, PR `29292695293` |
| Leo independent review | final Host and artifacts | **NOT RUN** |

The PASS rows apply only to the named commands and current development tree.
They do not establish the NOT RUN rows.

## Management and Host boundary

CPA's Management Key middleware is the authentication authority. Exact-freeze
CI proved missing, wrong, and normal downstream keys return 401; only the
correct Management Key succeeds. Responses remained canary-free. Leo must
repeat this independently.

CPA v7.2.72 performs `io.ReadAll` before the plugin management handler. The
plugin's 1 MiB body and 2 MiB RPC-envelope limits therefore do not protect Host
memory. Deployment evidence requires a reverse proxy to return 413 before CPA
receives the oversized request.

## Final evidence block

```text
starting_baseline: a121a444cb0d82cba4e27754914a1f88258e1d7b
reliability_checkpoint_commit: 573def2649d164161e2dfdfeb3f59b1e1b38ebbc
implementation_freeze_commit: 9c8114e22841f9a19b15b1f4b3c48531aa2453a0
evidence_document_commit: SELF (resolve with git log -1 -- this file)
historical_classifier_policy_version: classifier-policy-v2
historical_classifier_policy_sha256: dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2
development_canary_tests: PASS FOR RECORDED WSL/SCRIPT SELF-CHECKS
real_host_management_auth: GITHUB CI PASS
management_proxy_413: GITHUB CI PASS
development_candidate_artifact_canary_scan: GITHUB CI PASS; not formal release
github_ci_privacy: PASS — push 29292693070; pull_request 29292695293
leo_independent_privacy_review: NOT RUN
formal_privacy_gate: BLOCKED
```
