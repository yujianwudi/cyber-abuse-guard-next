# Round 9 Linux Host runner and counted-Mock contract

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: 06cbec97880403268ebd8c41ce3e6f7ff9413e195539c79368d607ed3e86e1b4
```

`.github/workflows/round9-host-validation.yml` is the only admissible Round 9
Host evaluation path for `v0.16-rc.4`, but it is not publication authorization
by itself. The job deliberately performs no source checkout. It passes only
immutable candidate, Phase 1, workflow, challenge, dispatch ref/SHA, and
workflow ref/SHA identities to the separately reviewed command:

```text
sudo -n /usr/local/libexec/cag-round9-eval-broker evaluate
```

The fixed root-owned broker owns the encrypted independent corpus, evaluator,
CPA sandbox adapter, fixed image identities, PAT, signing keys, temporary work,
result state, and protected one-shot ledger. A local development run, direct
adapter invocation, or hand-authored JSON is diagnostic only. Even correctly
signed Host evidence cannot replace the missing exact-candidate independent
audit.

This lane is synthetic counted-Mock-only. It must not SSH to or reuse a
production host, CPA process, account pool, database, credential, Provider, or
traffic stream. `subject_control=false` remains mandatory. External evaluation
and a public RC do not authorize production Balanced mode.

## Fixed identities

| Contract | Exact identity |
|---|---|
| Candidate | annotated exact-main `v0.16-rc.4` |
| Platform | Linux amd64 only |
| CPA | `v7.2.95@f71ec0eb6776854457892452cf28c47f0d658251` |
| Host workflow | `.github/workflows/round9-host-validation.yml` |
| Dispatch ref | exact `refs/tags/v0.16-rc.4` |
| Dispatch SHA | exact candidate commit |
| Workflow ref | `OWNER/REPO/.github/workflows/round9-host-validation.yml@refs/tags/v0.16-rc.4` |
| Workflow SHA | exact candidate commit |
| Protected environment | `round9-host-validation` |
| Dedicated runner labels | `self-hosted`, `linux`, `x64`, `cag-round9-sandbox` |
| External evaluator | `cag-round9-external-evaluator-v3` |
| Signed envelope | `round9-external-evaluation-signed-envelope/v1` |
| Signed evaluation payload | `round9-external-evaluation/v3` |
| Evaluator aggregate | `round9-external-evaluator-aggregate/v3` |
| Encrypted corpus bundle manifest | `round9-independent-corpus-bundle/v1` |
| Ledger event | `round9-external-evaluation-ledger-event/v3` |
| Ledger proof | `round9-protected-git-ledger-proof/v1` |
| Counted-Mock evidence | `round9-external-counted-mock/v1` |
| Public development counted-Mock evidence | `round9-public-counted-mock/v1` |
| Public evaluator transport | `round9-public-counted-mock-transport/v1` |
| Public CPA decision audit | `round9-public-cpa-decision-audit/v1` |
| External decision audit | `round9-external-decision-audit/v3` |
| CPA audit expectations | `round9-cpa-audit-expectations/v3` |
| CPA finalize report | `round9-cpa-sandbox-finalize/v2` |
| CPA runtime checks | `round9-external-cpa-runtime-checks/v1` |
| CPA sandbox descriptor | `round9-external-cpa-sandbox/v2` |
| Development evidence | `round9-development-evidence/v1` |
| Current visible public corpus | `round9-public-adversarial-v13` / 481,448 bytes / `91a32766c17924c31365f641b2f8fed791d034524f3d3897119f721eb56fecd6`; 199 Release assets are metadata/digest-only |
| External evidence assets | `round9-external-evaluation.json`, `round9-external-ledger-proof.json` |

The public adversarial corpus is visible development regression material, not
the encrypted independent corpus. No code, workflow, installer, hook,
dependency, application, or binary from a public adversarial repository is
executed.

## Phase 1 admission and no-checkout boundary

`round9-release-rc.yml` has no publication boolean and produces/attests only an
exact 17-asset private candidate. Its admission also requires a successful
exact-main push run of `Round 9 policy gate` and requires historical workflow
IDs `315644586` and `318443961` to remain `disabled_manually`. The Host dispatch
has ten inputs: tag, tag object, commit, tree, Phase 1 run ID/attempt, artifact
ID/digest, one canonical inline `candidate_identity` object, and a fresh
lowercase 64-hex challenge.
Duplicate keys, unknown fields, non-canonical JSON, malformed identities, or an
oversized candidate object fail before ledger reservation.

The broker independently re-reads the remote tag, commit, tree, successful
Phase 1 workflow, artifact, and attestations. It rejects missing, extra, empty,
oversized, non-regular, symlinked, or digest-mismatched assets and verifies that
the Store ZIP contains the exact standalone Linux amd64 SO bytes. The signed
external result embeds the canonical Phase 1 development evidence rather than
trusting a second summary supplied by the Host workflow.

The Actions runner does not receive a corpus path, evaluator path, sandbox
command, PAT, age identity, signing key, or plaintext case. The root install
must be reviewed and provisioned before the candidate commit is frozen; do not
install evaluator code from the candidate that it is about to evaluate.
Before invoking the broker, the workflow proves that its dispatch and workflow
refs both name the exact RC tag and that both GitHub SHA values equal the exact
candidate commit. It then forwards all four values as distinct broker arguments;
the root-owned broker rejects any mismatch or substitution.

## CPA sandbox and listener

The adapter starts one counted upstream and one authenticated CPA container on
an execution-private internal Docker network. CPA has exactly one published
listener:

```text
127.0.0.1:18394 -> 8317/tcp
```

The adapter fails if the fixed port is occupied. Docker configured and runtime
bindings must agree exactly; wildcard/IPv6/random CPA ports, additional
listeners, or multiple bindings are rejected. The counted-Mock control plane
may use an invocation-random unprivileged loopback port for root-owned reset and
statistics calls and is reachable from CPA only on the private network. It has
no real Provider adapter, persistence, request-body log, or body-reading debug
endpoint.

The `round9-external-cpa-sandbox/v2` descriptor binds the exact candidate SO,
CPA and counted-Mock image IDs, sandbox/daemon/probe identities, adapter and
configuration identities, ordinary model name, 16 KiB scan limit, fixed
listener, authenticated phase protocol, and
`production_accessed=false` / `real_provider_contacted=false`. Authorization,
management, and phase configuration files remain root-owned mode-0600 inputs.

The dedicated evaluator host is the security boundary for the unauthenticated
counted-Mock reset/statistics endpoints. It must have no untrusted local user or
unrelated workload sharing the daemon, images, or network namespace. If this
boundary cannot be proven, the result is `NOT_PROVIDED`; it is not repaired by
weakening the control-plane boundary.

## Fixed phase protocol

One CPA container starts in Audit and is driven sequentially through:

```text
Audit -> Balanced -> Strict
```

Mode changes use an authenticated `PUT` to
`/v0/management/plugins/cyber-abuse-guard/config`. The evaluator must verify
`/v0/management/plugins/cyber-abuse-guard/status` after every phase transition.
The fresh workflow challenge seeds the deterministic per-phase route order, and
the signed result binds each phase permutation and execution count. A skipped,
reordered, unauthenticated, or status-unverified phase fails the evaluation.

Audit remains non-blocking. Eligible malicious requests are expected to reach
counted Mock in Audit, while Balanced and Strict enforcement routes must satisfy
their exact local-block/upstream/usage accounting. Incomplete inspection remains
allowing in Audit and Balanced and is a distinct non-malicious local block in
Strict; it cannot fabricate a malicious winner or category.

## Required runtime observations

The external aggregate must validate all route metrics and the complete
`round9-external-cpa-runtime-checks/v1` object. A Host-valid result requires:

- Chat Completions and Responses, stream and non-stream, across all three modes;
- benign zero-policy-block and exact upstream/usage accounting;
- independent malicious semantic and route recall of at least 95% overall and
  in every category, including per-category Wilson bounds;
- explicit Audit allowed routes and Balanced/Strict enforcement routes;
- distinct Audit/Balanced/Strict incomplete dispositions;
- SQLite audit schema v6, migrations `1..6`, `quick_check=ok`, and WAL checkpoint;
- exactly one controlled restart, zero unexpected restarts, and post-restart
  Audit status verification;
- a panic-recovery probe with zero panic, fatal, or plugin errors;
- usage queue delta `1` for the allowed probe and `0` for the blocked probe;
- Raw Capture observed default-disabled, zero normal-request records, and no
  normal-request plaintext persisted;
- clean lifecycle exit, no OOM kill, and zero unexpected lifecycle restart.

The counted-Mock object is mechanically derived from the already validated
execution and metrics. It must be `state=PASS`, carry the complete runtime-check
object, and have `not_observed=[]`. A bare, hand-filled `PASS`, a contradictory
counter, or `PASS` with any required observation omitted is rejected.

The same run also executes the ten manifest-bound public §13.25 payloads: eight
historical defaults, one current branch head, and one unmerged candidate carrier.
Every payload uses the fixed 12-route matrix. Expectations are frozen before the
first candidate request: Audit must account for 40 allows/upstream/usage records,
while Balanced and Strict must account for 80 local malicious-text blocks and
zero upstream/usage records. The evaluator owns only HTTP/counting observations;
the adapter owns only persisted CPA decisions. The broker validates and merges
those two objects, so neither side can self-assert the other side's counters.
The published object is development regression evidence, not an independent
holdout, production approval, or proof of third-party provenance extraction.

## Signed evaluation and protected ledger

The evaluator emits a privacy-bounded aggregate with only identities, counts,
Wilson results, bounded failure-ID hashes, runtime observations, and safety
flags. It emits no request or response text. The broker validates that aggregate,
mechanically derives counted-Mock evidence, and signs an exact external payload
binding:

```text
candidate + evaluator + corpus + execution + ledger
+ development_evidence + counted_mock + public_counted_mock + metrics + privacy
```

The encrypted bundle SHA-256 selects one protected namespace:

```text
refs/tags/round9-eval-ledger/<bundle-sha256>/reserved
refs/tags/round9-eval-ledger/<bundle-sha256>/started
refs/tags/round9-eval-ledger/<bundle-sha256>/result
refs/tags/round9-eval-ledger/<bundle-sha256>/aborted
```

Each event is a canonical signed envelope stored as an annotated tag on the
exact candidate commit. The active tag ruleset must cover the namespace, have no
bypass actor, and prohibit update and deletion. `result` binds the exact signed
evaluation digest and counted-Mock object. A failed partial run is permanently
aborted. A usable Host result requires the remote `reserved`, `started`, and
`result` events to verify and the `aborted` reference to be absent. Existing
partial or completed state is reusable only when every signed candidate,
corpus, execution, evaluator, and ledger identity still matches. These checks
remain necessary but are not sufficient for public publication.

## Attestation and current publication block

The Host workflow attests and uploads exactly:

- `round9-external-evaluation.json`;
- `round9-external-ledger-proof.json`.

`round9-release-rc.yml` keeps the 17-asset Phase 1 candidate build enabled and
private. The former Host-only 19-asset publication assembly is statically
unreachable and has no contents-write permission or Release mutation API. The
publish, publication-blocker, and legacy existing-Release verifier jobs are all
gated on `needs.admission.outputs.publication_permitted == 'true'`, while the
admission job emits exactly one hard-coded `publication_permitted=false` and no
workflow path can emit `true`. Host run identity, artifact digest, challenge, a
counted-Mock `PASS`, or Release title/body text cannot enable any of them.

The missing gate must review the exact prospective 19-asset candidate, not a
source snapshot, Phase 1 approximation, or Host result alone. Its evidence and
mechanical verifier must bind an independent signer/workflow identity; the exact
tag object, commit, and tree; the canonical manifest and allowlist; every asset
name, byte length, and SHA-256; the required build/Host attestations; and fresh,
non-replayed audit execution identity. Negative tests must reject Host-only or
title-only approval, hand-filled status, asset substitution, signer drift,
unknown fields, stale evidence, and digest drift. The verifier contract is
currently `IMPLEMENTED_FAIL_CLOSED / INDEPENDENTLY_SIGNED_EVIDENCE_NOT_PROVIDED`,
so no new public `v0.16-rc.4` prerelease is authorized or creatable through the
workflow.

Admission rejects every pre-existing `v0.16-rc.4` Release, including an exact
non-draft immutable 19-asset object. The preserved read-only verifier is legacy,
statically unreachable documentation for a future independently reviewed gate;
it is not a recovery path and cannot convert existing remote state into success.

## Claim boundary

This evidence is limited to loopback-only synthetic CPA/count-Mock, audit
database, controlled restart, lifecycle, usage-queue, and Raw Capture-disabled
observations. It does not prove real Provider behavior, production behavior,
real-user traffic safety, zero false positives, or production Balanced
readiness. An exact-candidate independent audit and mechanical verifier are
still required.

Until the exact protected external evaluation, ledger proof, exact-main gates,
and exact-candidate independent audit are supplied and mechanically bound, the
only valid conclusion remains:

```text
BLOCKED / NOT PROVIDED / REQUIRES INDEPENDENT AUDIT
```
