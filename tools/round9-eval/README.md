# Round 9 external independent evaluator

This directory defines the installable source for the Round 9 independent
evaluation authority. It is deliberately separate from the candidate Go
classifier. The authoritative path is:

    protected no-checkout GitHub job
      -> sudo -n /usr/local/libexec/cag-round9-eval-broker
      -> fixed root-owned sandbox adapter
      -> CPA v7.2.95 HTTP black box with the exact Phase 1 SO
      -> fixed root-owned external evaluator
      -> Ed25519 signed aggregate envelope
      -> protected remote Git tag one-shot ledger

The candidate repository never supplies an evaluator path, sandbox command,
GitHub PAT, age identity, signing key or plaintext corpus path at workflow run
time. Install and review this code before freezing the candidate commit. Do not
install the evaluator from the candidate that it is about to evaluate.

The Host workflow stays within GitHub's reviewed ten-input dispatch limit. Its
eight candidate artifact identities travel as one canonical inline JSON object
(`candidate_identity`) and are parsed only by the fixed root-owned broker. The
workflow must not use repository code, `jq`, or an ad-hoc shell parser to expand
that object. Duplicate keys, unknown fields, non-canonical encoding, or an
object larger than 4096 UTF-8 bytes fail before any ledger reservation.
The workflow also proves and forwards four independent GitHub identities:
`dispatch_ref=refs/tags/v0.16-rc.3`, `dispatch_sha=exact candidate commit`, the
exact tagged `round9-host-validation.yml` workflow ref, and
`workflow_sha=exact candidate commit`. The broker requires all four values for
both `evaluate` and `recover-abort`; substituting a branch ref, a different
workflow revision, or a caller-supplied approximation fails closed.

## Confidentiality boundary

Plaintext independent cases must never be added to Git. The .gitignore rules
prevent ordinary staging, but ignore and export-ignore rules are not
confidentiality controls: git add --force would permanently expose the blob in
Git history. The Safe Gate therefore runs git ls-files and fails if any path
below testdata/round9-independent-* is tracked. Source archives and sparse
checkouts reject the same namespace as defense in depth.

The only authoritative corpus is an age-encrypted, root-owned tar archive
outside the checkout. Decryption occurs in a mode-0700 temporary directory and
is removed after the run. The broker emits only hashes, counts, bounded failure
ID hashes and signed ledger material. It never emits request or response text.

## Corpus bundle contract

The encrypted tar contains exactly:

    bundle-manifest.signed.json
    benign-manifest.json
    benign-cases.jsonl
    malicious-manifest.json
    malicious-cases.jsonl

The signed bundle manifest is an Ed25519 envelope whose author key is different
from the evaluator execution key. At broker startup, the pinned OpenSSL binary
canonicalizes all three configured keys to DER SPKI, proves that the evaluator
private key matches its public key, and rejects identical author/evaluator key
material even when key IDs or PEM encodings differ. The envelope binds every
file byte length and SHA-256,
the frozen category/language counts, the pre-candidate ground-truth declaration
and plaintext_in_repository=false. JSON and JSONL are canonical and duplicate
keys are rejected.

Each private case has only id, category, language and prompt. The evaluator
constructs protocol wrappers itself, preventing the corpus from injecting
executable paths or arbitrary HTTP destinations.
The independent malicious corpus is evaluated against a pre-candidate frozen
rubric and must reach at least 9500 basis points overall and in every category.
That is separate from visible development paired evidence, whose release
manifest contract requires exactly 10000 basis points overall and per category.

## CPA sandbox adapter contract

The root configuration pins an external adapter executable and SHA-256. The
broker invokes it with the exact downloaded candidate SO and a private work
directory. The adapter must create a canonical descriptor containing:

    schema=round9-external-cpa-sandbox/v2
    base_url=http://127.0.0.1:18394
    counter_url=http://127.0.0.1:...
    authorization_token_file=<root-owned 0600 file>
    management_token_file=<root-owned 0600 file>
    balanced_plugin_config_file=<root-owned canonical 0600 file>
    strict_plugin_config_file=<root-owned canonical 0600 file>
    network_binding=127.0.0.1:18394 -> 8317/tcp
    phase_protocol=authenticated Audit -> Balanced -> Strict
    runtime_checks.schema=round9-external-cpa-runtime-checks/v1
    candidate_so_sha256=<exact Phase 1 SO>
    cpa_version=v7.2.95
    cpa_commit=f71ec0eb6776854457892452cf28c47f0d658251
    production_accessed=false
    real_provider_contacted=false

The adapter is an independently installed host component, not a repository
script executed by the candidate workflow. It must isolate CPA and counted
Mock, bind only loopback, load the exact SO, and use one CPA container. Before
the descriptor is publishable it starts in Audit and mechanically observes:

- SQLite schema v6, migrations 1 through 6, `PRAGMA quick_check=ok`, and a
  non-busy WAL checkpoint;
- one controlled stop/start cycle, post-restart Audit health, zero unexpected
  restarts, exit code 0, and no OOM;
- a malformed-request containment probe plus zero panic, fatal, or plugin-load
  errors in lifecycle logs;
- exactly one usage-queue record for an allowed synthetic request and zero for
  a locally blocked synthetic request;
- Raw Capture disabled by default, zero normal-request capture records, and no
  normal-request plaintext canary in the SQLite DB/WAL/SHM files.

The adapter then resets counted Mock, drains usage state, and leaves that same
container healthy in Audit. The evaluator verifies Audit status, performs an
authenticated management `PUT` to Balanced and then Strict, and verifies status
after both transitions. Missing, unobserved, contradictory, or drifted runtime
checks make PASS publication fail closed. Cleanup still tears down only the
adapter-owned containers and network.

Before cleanup, the evaluator writes a mode-bound, root-private audit
expectations v3 file beside its private work directory. It contains the original
audit request hashes needed to query the isolated CPA database, plus
execution-scoped HMAC correlations and the expected `decision_kind`. The
adapter's mandatory `finalize` command then stops the same CPA container and
verifies lifecycle/log health, schema v6 and migrations 1-6, WAL/quick-check,
the start-time challenge binding, one audit event per evaluated request, and
the exact schema-v6 action/disposition/explanation-schema plus
decision-kind/category/eligible-winner semantics,
zero subject-state accumulation, Raw Capture zero, plaintext-canary absence and
a quiet usage queue. Only keyed request correlations and hashed event IDs enter
the public signed result; original request hashes remain confined to the
root-private temporary work directory, which normal completion removes.

The evaluator also runs the manifest-bound public-v13 §13.25 regression subset:
8 historical payloads, 1 branch-head payload, and 1 unmerged candidate carrier,
each over Audit/Balanced/Strict, Chat/Responses, and stream/non-stream routes.
All 120 expectations are frozen before the first candidate request. Audit is
fixed to 40 allow/upstream/usage outcomes; Balanced and Strict are fixed to 80
local `block_malicious_text` outcomes with no upstream or usage delta. The
evaluator emits only `round9-public-counted-mock-transport/v1`; the adapter emits
only `round9-public-cpa-decision-audit/v1`. The broker mechanically merges both
into `round9-public-counted-mock/v1`, rejects identity/count drift, and includes
the merged object in metrics, the signed result, and the result-ledger event.
No payload text or raw public payload ID is emitted.

### Dedicated-host trust boundary

The counted-Mock control plane is intentionally not a tenant-facing service.
Its reset and statistics endpoints do not authenticate callers. Their security
boundary is the dedicated protected evaluator host: random loopback-only
ports, an internal Docker network, root-owned broker synchronization, and no
untrusted local users or workloads. Never install this evaluator on a shared
runner or expose any CPA, counted-Mock, reset, statistics, or adapter port on a
non-loopback interface.

Before every evaluation, the operator must verify that the host has no
unrelated containers using the configured images or network namespace and that
only the fixed root-owned broker can start the adapter. If the host cannot
provide that boundary, the external result is `NOT_PROVIDED`; do not weaken
the boundary by treating an unprotected reset/statistics endpoint as evidence.

## One-shot ledger

The encrypted bundle SHA-256 selects one protected namespace:

    refs/tags/round9-eval-ledger/<bundle-sha256>/reserved
    refs/tags/round9-eval-ledger/<bundle-sha256>/started
    refs/tags/round9-eval-ledger/<bundle-sha256>/result
    refs/tags/round9-eval-ledger/<bundle-sha256>/aborted

GitHub create-ref is the atomic reservation operation. Each reference points to
an annotated tag on the exact candidate commit. The tag message is a canonical
Ed25519 signed event envelope. The result event binds the SHA-256 of the exact
signed evaluation envelope. The configured tag ruleset must be active, cover
the namespace, have no bypass actor and prohibit update and deletion.

The fine-grained PAT is stored only in a root-owned file. It is not a repository
or environment secret. A completed result is idempotently recoverable only when
the root state copy and all remote signed events still verify. A partial run
receives an aborted event and cannot be reported as PASS.

If cleanup, signing, ledger publication, or proof construction fails after the
reservation is created, the broker attempts to write the signed `aborted`
event. On a later invocation it first verifies every existing partial event
against the exact candidate, evaluator, corpus, execution, key, and commit;
only that authenticated partial identity may be permanently aborted. A
mismatched partial ledger is a hard failure and must be investigated by the
operator rather than overwritten or reused.

The broker exposes a separate root-only `recover-abort` command for a run whose
reservation was authenticated but whose automatic abort publication did not
complete. Supply exactly the same repository, tag/commit/tree, Phase 1
artifact, candidate identity, challenge and Host workflow identity arguments as
the failed `evaluate` invocation, but omit `--output`:

    sudo -n /usr/local/libexec/cag-round9-eval-broker recover-abort \
      --repository OWNER/REPO --tag v0.16-rc.3 \
      --tag-object-sha TAG_OBJECT --commit COMMIT --tree TREE \
      --phase1-run-id RUN --phase1-run-attempt ATTEMPT \
      --phase1-artifact-id ARTIFACT \
      --phase1-artifact-digest sha256:DIGEST \
      --candidate-identity "$CANDIDATE_IDENTITY_JSON" \
      --challenge CHALLENGE --workflow-run-id HOST_RUN \
      --workflow-run-attempt HOST_ATTEMPT \
      --dispatch-ref refs/tags/v0.16-rc.3 \
      --dispatch-sha COMMIT \
      --workflow-ref OWNER/REPO/.github/workflows/round9-host-validation.yml@refs/tags/v0.16-rc.3 \
      --workflow-sha COMMIT

Recovery re-downloads and verifies the exact Phase 1 identity, authenticates
every existing partial ledger event, refuses a completed or mismatched ledger,
and then creates or verifies the immutable `aborted` event. The original Host
run must already have completed with a reviewed failure, cancellation, timeout,
stale, startup-failure or action-required conclusion. Active, successful,
neutral and skipped runs are not accepted as recovery authority, which prevents
recovery from racing a still-running evaluator. It never resumes an evaluation
or converts an aborted namespace into PASS.

## Installation and provisioning

1. Independently review these sources and the sandbox adapter.
2. Copy broker-config.example.json and sandbox-adapter-config.example.json
   outside Git, replace every placeholder, pin the exact evaluator and adapter
   SHA-256 values, and make both reviewed files root-owned mode 0600.
3. Provision separate Ed25519 evaluator and corpus-author keys. Keep private
   keys mode 0600 and root-owned.
4. Provision the age identity and encrypted bundle outside the checkout.
5. Provision a root-only fine-grained PAT able to read Actions/attestations and
   create ledger tag objects/refs.
6. Configure the active tag ruleset and record its immutable ID/name.
7. Install from the independently reviewed source snapshot:

       sudo ./tools/round9-eval/install.sh \
         --config /root/reviewed-round9-broker.json \
         --adapter-config /root/reviewed-round9-adapter.json

   The installer snapshots every source and reviewed configuration through
   no-follow file descriptors into a root-only staging directory before any
   hash check, compile, validation or install step. All authoritative install
   operations use those snapshots, not mutable checkout paths.

8. Configure passwordless sudo for the single fixed broker command only. Do not
   grant the Actions runner a general root shell.
9. Put the evaluator public key bytes, key ID, evaluator SHA-256 and ledger
   ruleset ID/name into both protected GitHub environments as non-secret
   variables. A future independently audited publication path would have to
   compare the same trust values again; the current lane publishes no Release.

## Public verification

The repository validator accepts the signed envelope and proof but never a
corpus path. Its verify-remote command re-reads main/tag/tree, the Phase 1 run
and artifact, annotated ledger tags, canonical signed messages, the absent
aborted ref and the active immutable tag ruleset.

This evidence supports independent audit; it does not itself authorize
production Balanced mode.
