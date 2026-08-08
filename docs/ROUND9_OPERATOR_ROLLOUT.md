# Round 9 operator-owned Balanced rollout, circuit breaker, and rollback

```text
current_classifier_policy_version: classifier-policy-v12
current_classifier_policy_sha256: 795dbcf90f94bdebdc1c66abbeeb6c9d92cb82e84b56b602832f89014cd7593c
```

> **Active-tree identity overlay refreshed 2026-08-04 (Asia/Shanghai).** The
> prologue above is repository navigation metadata, not a rebind of this frozen
> Round 9 design. Its historical classifier identity remains
> `classifier-policy-v10` / `db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594`
> on CPA `v7.2.113@bc71c77f5cc42f3fbe1bf040cf14d4f166894835`.

Status: **NOT AUTHORIZED FOR EXECUTION BY CODEX**.

This runbook is a reviewable production-change design only. It does not grant
deployment authority. An operator may use it only after all Round 9 local and
Tencent counted-Mock gates pass, the candidate receives an independent audit,
and the maintainer gives a new explicit production approval for the exact
candidate SHA-256.

## 1. Non-negotiable admission conditions

Before touching a production pool, record and independently verify:

- annotated release tag, exact commit and tree;
- Linux amd64 SO byte count and SHA-256;
- classifier version and SHA-256;
- ruleset version and SHA-256;
- CPA `v7.2.113@bc71c77f5cc42f3fbe1bf040cf14d4f166894835`;
- checksum, SBOM, release manifest, artifact attestation, local counted-Mock
  evidence, Tencent counted-Mock evidence, and independent benign/malicious
  reports;
- independent-audit decision for that exact candidate;
- current configuration, plugin, audit database, WAL/SHM state, and health
  backups for every pool.

Any identity mismatch, missing evidence, failed gate, or newer unreviewed
commit stops the rollout. CI success, merge status, a GitHub Release, or a
counted-Mock result alone is not production approval.

## 2. Required production policy

The approved target configuration is limited to:

```yaml
mode: balanced
subject_control:
  enabled: false
audit:
  raw_capture:
    enabled: false
```

Additional invariants:

- request-level cyber-policy blocking only;
- no automatic account, IP, subject, Provider, or pool punishment;
- identity-unverified traffic never accumulates subject state;
- incomplete inspection remains allow plus audit in Balanced;
- opaque-media behavior remains the separately reviewed configured policy;
- Raw Capture stays disabled unless a separate, time-bounded approval names
  synthetic-only inputs, TTL, maximum bytes, redaction, and cleanup evidence;
- no real request text is copied into rollout reports, tickets, or chat.

## 3. Predeclared monitoring contract

Before Pool 1, the operator must fill and approve this table. Values cannot be
changed after observing candidate results without restarting the admission
process.

| Parameter | Approved value |
|---|---|
| Pool 1 minimum unique requests | `REQUIRED` |
| Pool 1 minimum observation window | `REQUIRED` |
| Pool 2/3/4 minimum unique requests | `REQUIRED` |
| Pool 2/3/4 minimum observation window | `REQUIRED` |
| Cyber-policy unique-request ratio warning threshold | `REQUIRED` |
| Cyber-policy unique-request ratio circuit-break threshold | `REQUIRED` |
| Unique-request deduplication key | `REQUIRED` |
| Retry horizon | `REQUIRED` |
| Synthetic-probe exclusion rule | `REQUIRED` |
| Pool approver | `REQUIRED` |
| Circuit-break owner | `REQUIRED` |
| Rollback owner | `REQUIRED` |

The deduplication key must identify one logical user request without using a
shared egress IP as the user identity. Retries of the same request ID count
once for ratio and incident decisions. Synthetic probes are separately tagged
and excluded from customer-rate calculations, while their pass/fail outcome is
still retained as deployment evidence.

## 4. Four-pool rollout

Pools are changed one at a time. Simultaneous restart or automatic time-only
promotion is forbidden.

### Pool 1: minimum-traffic canary

1. Confirm Pool 2/3/4 remain on their previous frozen candidate and mode.
2. Stop only Pool 1 according to the existing CPA operations procedure.
3. Back up its config and database state. If the database is below audit schema
   v6, preserve the generated pre-v6 database plus its manifest.
4. Install the exact approved SO and config, then start only Pool 1.
5. Verify health, New API to CPA routing, Keeper, database `quick_check`, WAL,
   queue health, plugin identity, and that production still exposes no subject
   control or Raw Capture.
6. Run approved harmless and explicitly malicious synthetic probes. Harmless
   probes must reach upstream; malicious probes must be locally rejected and
   must not increment upstream or usage.
7. Observe at least both predeclared Pool 1 minima. Review every first-seen block
   family, every unique blocked request, retry deduplication, incomplete
   decisions, and the cyber-policy unique-request ratio.
8. An independent operator explicitly approves or rejects Pool 2 promotion.

### Pools 2, 3, and 4

Repeat the Pool 1 procedure independently for each pool. Before each promotion:

- the previous upgraded pools must remain healthy;
- the next pool must still be on the prior frozen state;
- all first-seen block families since the previous promotion require human
  review;
- no confirmed normal request may have been blocked;
- no circuit-break condition may be open;
- the named independent operator must explicitly approve that one promotion.

## 5. Automatic circuit-break conditions

Any one condition immediately freezes promotion and starts rollback:

1. one confirmed normal request is blocked;
2. the deduplicated cyber-policy unique-request ratio crosses its predeclared
   circuit-break threshold or rises anomalously against the approved baseline;
3. one logical request is counted more than once because of retry behavior;
4. an incomplete request is labeled malicious, receives a malicious category
   or winning rule, or enters subject accumulation;
5. panic, fatal error, database corruption, failed `quick_check`, unexpected
   restart, OOM, or plugin error;
6. New API, CPA, Keeper, usage queue, audit writer, or database health fails;
7. classifier, ruleset, SO, config, or CPA identity differs from the approved
   freeze;
8. Raw Capture or subject control is unexpectedly enabled;
9. a synthetic benign probe does not reach the counted upstream, or a synthetic
   malicious probe reaches upstream or increments usage.

The circuit breaker is safety-oriented: operators do not wait for a fixed
sample count after any confirmed normal block.

## 6. Shortest rollback path

1. Stop promotion and remove the affected pool from service.
2. Preserve the failing config, SO hash, logs, audit database, WAL/SHM, and
   health evidence without copying request text into the incident record.
3. Restore the previous approved config and SO.
4. If Round 9 migrated the audit database to schema v6 and the previous SO
   supports only v5, do **not** open the v6 database with the old SO. Verify the
   matching `.pre-v6-*.bak.manifest.json`, restore that exact pre-v6 database,
   and keep the v6 database isolated for incident review.
5. Start the affected pool, run health and harmless probes, and confirm the
   previous identity and routing behavior.
6. If the previous state cannot be restored quickly, set the pool to `mode:
   audit` with `subject_control.enabled: false`, keep Raw Capture disabled, and
   obtain a new operator approval before returning it to service.
7. Roll back already promoted pools one at a time in reverse order when the
   fault may affect the shared candidate.

Rollback completion requires healthy New API, CPA, Keeper, usage queue, audit
writer, database `quick_check`, and a harmless request reaching upstream. It
does not authorize deleting the incident evidence or resuming promotion.

## 7. Required operator record

For each pool, retain a text-free record of:

- operator and approver;
- start/end time;
- pool identifier;
- exact candidate identities;
- pre/post health results;
- unique request and block counts;
- deduplication and synthetic-exclusion method;
- first-seen block-family review decisions;
- circuit-break state;
- promotion or rollback decision;
- backup and restore identities.

The final status remains:

```text
BLOCKED / NOT PROVIDED / REQUIRES INDEPENDENT AUDIT
```

until the independent audit and the maintainer's separate production approval
both exist for the exact candidate.
