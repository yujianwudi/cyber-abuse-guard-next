# Changelog

```text
current_classifier_policy_version: classifier-policy-v11
current_classifier_policy_sha256: f1b4665c751306a1a30c96a58ddb84714541e6e476c66db8ad436480e4c98f55
```

Source-tree status updated: 2026-08-05 (Asia/Shanghai)

## Unreleased - v0.16 main development

- Complete the Round 12 working-tree implementation without claiming final
  acceptance or a release. SQLite audit writes now enforce the configured live
  page ceiling after bounded write batches, purge Raw Capture before ordinary
  events, reject further audit writes when capacity cannot be recovered, and
  expose low-cardinality capacity state. Subject snapshots now preflight live
  pages inside their replacement transaction and roll back on overflow instead
  of evicting audit evidence; rows are encoded and inserted one at a time rather
  than retaining a second full snapshot copy. Committed event deletion, Raw
  Capture purge, and subject deletion only remeasure the gate and never evict
  evidence outside the requested maintenance scope.
  Management and RPC request limits are
  fixed at 1 MiB and 2 MiB, while case-variant duplicate `Authorization` and
  `X-API-Key` values resolve to a deterministic conflict identity. The
  classifier advances to `classifier-policy-v11` /
  `f1b4665c751306a1a30c96a58ddb84714541e6e476c66db8ad436480e4c98f55`:
  an outer defensive owner suppresses only its own inert carrier, and a later
  explicit activation must be in the same scope and a distinct logical field;
  missing paths or exhausted proof budgets remain incomplete rather than
  fabricated semantic positives. Batch and streaming paths share the same
  proof and recompute group flags after carrier omission.

- Add the closed `tools/current-cpa-audit` RT12-05 harness. The approved policy
  binds 11 reviewed paths across the five fixed repositories to exact
  commit/tree/blob/raw/text identities and 19 semantic cases; policy SHA-256 is
  `d457374f193db13fd43422104f760997c935de057ae3add7a0faf56a5260ad89`.
  The MDX repository pin advances to latest HEAD
  `7588d25d8cb67f88a75d168fcb6ca8fc357bc492`; its two selected source blobs
  remain byte-identical, while the intervening commits change only README and
  README_EN project warnings.
  Acquisition and cleanup are device/inode, SHA, size, and link-count bound;
  pending material cannot run, source drift requires a new human review, and
  private corpus text is removed after use. A final audit found and closed a
  concatenated-ZIP prefix bypass that Python's ZIP reader would otherwise
  silently rebase to the last archive. Superseded PR head
  `9782eaf9da37d466ffc0b644b052d3c842f7f1ca` passed CI `31016759352`,
  Policy and Corpus Gate `31016760807`, and CodeQL `31016759262`; Linux
  artifact `8936474093` contained a plugin SO with SHA-256
  `4fdd0914328b63f585187b970a0dc8f4501c3f6dece7819cd414d4fb3179a4ad`.
  Its second-machine harness attempt then failed closed before any counted-Mock
  request because Docker/runc rejected a `/proc/<pid>/fd/...` magic link as a
  bind-mount source (`error_id=32a64d93ec0f3ed9`). It emitted no
  `machine-evidence.json`, executed no third-party repository code, removed the
  private corpus text, and is not a PASS.

  The remediation keeps evidence/runtime/cleanup/failure writes on the held
  directory descriptor but gives Docker only a normal path after checking the
  complete absolute ancestor snapshot and every descriptor-bound subtree
  identity. It rechecks the handoff after start and closes exactly five
  Source/Destination/RW/rprivate binds. `HostConfig.Tmpfs` must contain only the
  hardened `/tmp` contract; because Docker may omit tmpfs entries from
  `.Mounts`, zero or one matching `/tmp` entry is accepted there. Changed paths,
  extra mounts, and volumes fail closed. The current runner bundle is
  `46ca04f8e39922f5023dd60082bea2ff96c79660118b46b57c20f749159fca6c`;
  its `run.py` source is
  `083f03dbe599434ae4b40300d90d792659e43dec734fb551421393b35cbc339b`.
  Linux unit verification is 68/68 PASS. The diagnostic harness explicitly
  excludes a hostile process sharing its dedicated UID because directory
  creation and the daemon path handoff are not atomic same-UID boundaries. The
  remediated working tree still requires its own exact Go 1.26.4 candidate CI
  and second-machine execution; no predecessor result is relabelled as PASS.

- Freeze the Round 12 evidence vocabulary and publication boundary. Exact
  baseline `main@21267e742b624b29a75bd3683fd6914f76c764b5` passed CI
  `30880739397`, Policy and Corpus Gate `30880739368`, and CodeQL
  `30880739360`; those are exact-main engineering results only. The supplied
  1,320-transport second-machine report remains
  `DIAGNOSTIC_ONLY / NOT_FINAL_CANDIDATE / NOT_INDEPENDENT_ATTESTATION`; the
  superseded `9782eaf` RT12-05 attempt is `FAIL_CLOSED / NOT_PASS`, and the
  remediated final-candidate run remains
  `PENDING_REMEDIATED_HEAD_EXECUTION`. Protected Host, independent attestation,
  production approval, and release readiness remain `NOT_PROVIDED`. This round
  may merge a gated PR to `main` and does not create a tag, RC, plugin asset, or
  GitHub Release. The old repository and `v0.15` Release now return GitHub API
  `404`, so legacy availability is `UNAVAILABLE` and support is `SUSPENDED`.

- Advance the sole active CPA contract from official `v7.2.113` to official
  `v7.2.116` (`a88197f845c979132c8978ea223c6af05cc81536`) with module sum
  `h1:dGGI/CeEQTyKkFNeeqMoIyK/mWx5hVaQlZLDiHPoBTU=` and the unchanged go.mod
  sum. The reviewed v7.2.113-to-v7.2.116 range retains C ABI 1, RPC schema 2,
  and all 235 scoped plugin blobs byte-identically. Its relevant runtime changes
  are outside that plugin boundary: a Home OAuth 401 may refresh the selected
  credential and retry at most once within the same logical request, while
  Claude's final upstream wire headers are generated only after request
  interceptors have run. CAG does not register `UsagePlugin`, so Home's
  result-only usage reporting does not add a CAG usage callback. The standard
  upstream Linux amd64 asset
  `CLIProxyAPI_7.2.116_linux_amd64.tar.gz` is identified by SHA-256
  `469adcf760936764781687cfc7057f8ca0db3a685d418dd3d9d84cb1910bde3b`;
  recording that upstream hash is not a download, execution, CAG artifact, or
  Host PASS. Frozen v7.2.113 results remain bound to their original commit and
  bytes. Exact v7.2.116 baseline `main@21267e7` engineering CI passed, while the
  Round 12 final candidate still needs its own exact-commit CI and second-machine
  execution; protected Host, independent, sandbox, release, and production
  conclusions remain `NOT_PROVIDED`. The final tree must rebind the classifier source
  identity because root `go.mod` and `go.sum` changed; no prior result is
  reattributed.

- Harden the retained CPA v7.2.113 Linux Host and external sandbox contracts:
  use a Docker 29-compatible internal-only bridge with no published Host ports;
  validate RFC1918 IPAM, container/network identity, isolation, resources, and
  log rotation before the first request; validate the exact nine-event
  Responses SSE sequence and CPA three-LF termination; separate the 16 KiB
  classifier window from the normal 8 MiB cumulative text budget; constrain
  16 KiB total-text mode to explicit Balanced/Strict incomplete probes; and
  preserve raw top-level tool-schema field order in Chat and Responses tests.
  CPA startup now fixes `commercial-mode: true`, `request-log: false`, and
  `logging-to-file: false`, verifies those effective booleans through Management,
  requires persistent audit storage, and rejects any auth-directory request-log
  artifact. Production examples and the watchdog enforce the same request-body
  privacy baseline with a direct-listener, a random 256-bit process identity
  shared by status/probes/challenge/resource/confirmation, complete and incomplete-body
  same-process proofs, held-inode marker checks, and independent
  connection/request timeouts. A BASE proxy that path-routes proof management
  calls to another CPA instance now fails closed before ResourceRoute dispatch.
  These changes do not alter classifier rules, thresholds, or corpus
  expectations and do not create a tag or Release.

- Advance the sole active CPA contract from official `v7.2.109` to official
  `v7.2.113` (`bc71c77f5cc42f3fbe1bf040cf14d4f166894835`) with module sum
  `h1:Aj3J7zI5VxyKpsHbG6+ChVpeW4QGkcJ+ZwWWnWmuChA=` and the unchanged go.mod
  sum. The reviewed v7.2.109-to-v7.2.113 range does not modify
  `sdk/pluginabi` or `sdk/pluginapi`, and upstream `go.mod` is byte-identical.
  Root, source-contract, Store-contract, Host-runner, external-evaluation, and
  documentation identities now use only v7.2.113. Historical v7.2.109 CI and
  second-machine results remain bound to v7.2.109 and are not relabeled as a
  v7.2.113 Host, sandbox, performance, or production PASS.
  Because the classifier identity binds root `go.mod` and `go.sum`, this
  dependency update rebinds the current `classifier-policy-v10` source identity
  from historical
  `b2b7905ace913bef793271df9cd1f3f731bfb0c4254b86bc7127a876cb322d67` to
  `db8fb0113943b544ee4d4166a42a3e1f4cb0cca067309838fba712d5e39a8594`.
  No prior classifier, performance, Host, or audit result is reattributed.

- Historical v7.2.109 Round 10 production-hardening source lane:
  add bounded historical tool-result activation for a uniquely associated
  current-user execution directive; verify persistent audit storage and live
  operational readiness; expose low-cardinality coverage dimensions and
  atomic dispositions; harden SQLite quick-check/checkpoint and DB/WAL/SHM
  identity handling; and preserve batch/stream parity across direct-compaction
  boundaries. A direct-compaction run that exceeds 8 KiB only through trailing
  ASCII padding now uses a bounded non-padding proof, while a real non-padding
  proof overflow remains incomplete. These historical behavior changes bind
  `classifier-policy-v10` to
  `b2b7905ace913bef793271df9cd1f3f731bfb0c4254b86bc7127a876cb322d67`.
  This lane publishes source and tests only; it does not create a tag, plugin
  asset, or GitHub Release.

- Reduce the executable GitHub Actions surface from eleven workflows to three:
  `CI`, `CodeQL`, and `Policy and Corpus Gate`. Retire the automated candidate,
  prerelease, Round 8, RC, Host, promotion, and release lanes; normalize the
  active policy workflow filename to `policy-gate.yml`; retain stable required
  job contexts for branch protection; and update the workflow inventory and
  repository-governance documentation.

- Advance the sole active CPA contract to official `v7.2.109`
  (`928478e4b91533cec05a763bfac3edad9c3e76cf`) and module sum
  `h1:AM6nizpKiBkIr2ZSQ+XUwz1vkNTGoxSRlrTkt5hdLG8=` while retaining C ABI 1,
  RPC schema 2, and the existing go.mod sum. The reviewed v7.2.104→v7.2.109
  upstream range changes Codex model resolution, auth-file credential weights,
  translators, and provider executors, but does not modify `sdk/pluginabi`,
  `sdk/pluginapi`, `internal/pluginhost`, RequestInterceptor, the plugin RPC
  lifecycle, or the upstream ModelRouter capability/dispatch implementation.
  ModelRouter's global registration and oversized-RPC fallback already existed
  in v7.2.104; they are documented for v7.2.109 but were not introduced by this
  upstream range. Because the classifier identity binds `go.mod` and
  `go.sum`, unchanged classifier behavior is rebound from the frozen CPA
  v7.2.104 identity `e7a00b02...` to
  `6cd7296bee90b9352a9cf1745b7760c0ff1b18a265da4af498c5877d4b542f87`.
  Earlier v7.2.104 CI and audit records remain historical evidence and are not
  promoted to a v7.2.109 Host, sandbox, or production PASS.

- Keep the required CI compatibility lane pinned to CPA v7.2.104 after the
  upstream v7.2.105 release. CI still resolves and verifies the exact official
  v7.2.104 Git tag, commit, module Origin, and checksums, while the moving
  `releases/latest` probe remains an optional drift monitor rather than a
  compatibility or release gate.
- Align the CPA Host counter contract with the Round 9 defensive-owner parity:
  complete category-free incident-response reviews now count as `allowed` for
  user, request-local system, and terminal-tool roles. HTTP/upstream/usage
  behavior is unchanged; malicious same-carrier reactivation still blocks.
- Repair the `150c25e6` isolation-audit findings with candidate-local quoted
  carrier ownership, request-local system/developer defensive-owner parity,
  bounded batch/streaming reactivation, real-credential phishing relations,
  malformed percent-decoding preservation, and inert log/console/terminal
  candidate suppression. The resulting working-tree policy identity is
  `e7a00b02d7e0e4ca837204cfed476b4f371f599facbf546e342362370111ec14`;
  exact-main CI, the complete benchmark recipe, and the authoritative
  CPA v7.2.104 counted-Mock matrix remain revalidation gates.
- Advance the sole active CPA contract to official `v7.2.104`
  (`c9417c8ae9b16fabc0386ca35d36f13bf8b1d678`) and its reviewed module sum
  while retaining C ABI 1 and RPC schema 2. The upstream plugin ABI, RPC
  request/lifecycle contracts, Linux build baseline, Dockerfile, and Alpha
  Search routing are byte-identical to v7.2.103. CPA now validates auth weights
  and records direct-peer/X-Forwarded-For/User-Agent data for its internal Redis
  usage queue, but CAG does not use `host.auth.*` and the client metadata is not
  exposed through `RequestInterceptRequest`; `trusted_proxy.enabled` therefore
  remains rejected. The v7.2.103 exact-main CI/Host result is retained as frozen
  historical evidence and is not promoted to a v7.2.104 PASS.
  Because the classifier identity deliberately binds `go.mod` and `go.sum`,
  the then-current `classifier-policy-v9` behavior was rebound for the
  v7.2.104 dependency locks to the predecessor digest
  `e0cbc975...`;
  the earlier `f9529ada...` identity remains historical v7.2.103 evidence.
- Earlier in this Round 9 line, move the active CPA contract to
  `v7.2.103` (`cade44b9cdee6b9328ea2648fd119129fdf11e2d`) with reviewed module and
  `go.mod` sums. CI now verifies that this fixed identity is still GitHub's
  `releases/latest`, executes the complete upstream Linux `internal/pluginhost`
  suite plus `sdk/pluginabi`/`sdk/pluginapi`, and loads the built candidate
  `.so` through the real Host integration path. Historical Round 6/8 and
  v0.15/v0.16-rc.2 evidence remains pinned to CPA v7.2.95.
- Migrate ordinary model-request enforcement from the schema-1 ModelRouter path
  to CPA schema 2 request interception and request lifecycle completion.
  Malicious batch and stream requests now terminate directly with HTTP 403
  before Auth, Provider, Usage, Executor, Mock upstream, or SSE side effects.
  Stable `RequestID` correlation prevents duplicate after-auth
  classification/audit. Oversized after-auth envelopes pass through in
  non-strict modes, while Strict records an incomplete block so a mutation
  cannot bypass enforcement. A bounded TTL cache uses a per-process,
  request-ID-bound HMAC-SHA256 over case-normalized header names while
  preserving exact value order. Mutated inputs are reclassified;
  fail-open operational failures are not cached as checked. The cache is cleared
  idempotently for succeeded, failed, rejected, and canceled completions.
  Because CPA v7.2.103 does not invoke RequestInterceptor for either Alpha
  Search URL, CAG retains a narrowly
  gated ModelRouter only for `codex-alpha-search`; malicious search fails closed
  as HTTP 503 before Codex auth/upstream, while all other Host-originated Router
  callbacks are O(1) unhandled. The schema-1 Router fixture remains an explicit
  legacy Host compatibility lane.
- Accept Host registration and reconfiguration schema versions greater than 2
  while always negotiating the plugin's implemented RPC schema 2; schema 1 is
  still rejected. RequestInterceptor blocks now carry their category directly
  from classification, removing the second SHA-256 lookup from the block path.
- Make the exact v0.16-rc.2 old-SO rollback gate self-contained after the
  predecessor repository became unavailable. CI now rebuilds the historical
  plugin from a byte-frozen 76-file reviewed non-`*_test.go` source capsule,
  rejects any path/file/hash drift, excludes restricted corpus surfaces, and
  records that no live predecessor-repository verification was used. A cold Go
  module cache may still use the configured module proxy for pinned dependencies.
- Prevent consented-training telemetry from masking a real credential
  solicitation by covering `prompt`, `induce`, `receive`, and `solicit` forms
  and their inflections across user/system/developer/tool batch and streaming
  paths. Narrow defense-evasion purpose binding so ordinary duplicate
  intrusion-alert suppression, monitoring maintenance, and retired-rule audit
  work remain nonblocking, while explicit alert suppression used to hide
  malware or unauthorized access still blocks.
- Repair the exact-main Round 9 paired-malicious regression introduced by the
  physical-occurrence binder. Defense-evasion, prompt-injection, and phishing
  relations now reuse narrow clause-local object, mechanism, purpose, harm,
  delivery, and collection predicates instead of losing an otherwise complete
  candidate when those dimensions are split across adjacent physical clauses.
  The strict owner requirement remains fail-closed; no request-global evidence
  or arbitrary first/last-clause fallback was restored.
- Add eight paired-malicious reproductions, their benign parents, and a narrow
  regression proving that training-event telemetry cannot hide a later real
  password-collection instruction. On Linux amd64 Go 1.26.4, the current
  working tree blocks 120/120 semantic malicious samples and passes 960/960
  serialized routes while preserving 0/1200 benign semantic blocks and 0/7200
  benign route blocks. These are visible development gates, not independent or
  CPA Host evidence.
- Restore a narrowly bounded defensive incident-response review form that asks
  only for risk explanation plus detection/remediation advice and explicitly
  forbids execution. The exact comma/colon, hyphenated/non-hyphenated
  `incident response` analysis/training introductions now enter the existing
  single-quote structural proof; they do not weaken carrier classification,
  ownership, execution-tail reactivation, proof budgets, or multilingual
  fail-closed behavior.
- Cover that form across batch classification, profiled content-kind splitting
  with whole/halves/bytewise chunks, Balanced/Strict, and OpenAI Chat,
  OpenAI Responses, Claude, and Gemini simulated routes. Appending an execution
  instruction still reactivates and blocks the credential-theft carrier.
- Add a true cross-window coarse-signal boundary regression: a distant
  qualifier-only tail cannot complete admission, all three bits still trigger
  independent malicious-carrier classification, benign educational carriers
  remain nonblocking, and field/scope boundaries cannot lend signals. A
  truncated normalized matcher remains explicitly fail-active.
- Restore batch/profiled-plugin-route parity when extraction splits one logical user field into
  natural-language and fenced content: a second malicious referent, a missing
  analysis governor, split carriers, clause overflow, or an over-budget review
  frame can no longer inherit defensive suppression in Balanced or Strict.
- Bind reconstruction to the same `FieldPathHash`, role, provenance,
  attribution, conversation, turn, and scope; retain only three content-free
  long-frame signal bits, classify the exact carrier before enforcement, and
  keep over-budget benign code reviews nonblocking.
- Remove a redundant single-carrier classification window, add tight-budget
  and 511/512/513-byte regressions, and extend the existing defensive-quote
  fuzz target with arbitrary byte cut points and UTF-8 boundary seeds.
- Preserve defensive-frame potential across the 64-scope and 64-unit profiled
  budgets with a content-free logical-field overflow run; a lost carrier now
  yields explicit incomplete coverage, while a retained benign carrier is
  reclassified and remains nonblocking. At the scope cap, a complete valid
  review or a malformed frame with a benign carrier is resolved before
  eviction, so 64 safe scopes cannot force the 65th ordinary scope incomplete.
- Generate over-512-byte frame signals after the classifier's NFKC, case, and
  zero-width normalization, using one Aho-Corasick pass instead of repeated
  literal scans. Reuse the ordinary classifier's normalized rune view when no
  compact carry is injected, while preserving the prior reference/boundary-stem
  gate so a distant qualifier-only window cannot complete an attempt; add
  full-width, zero-width, scope-eviction, unit-eviction, and maximum-window
  performance regressions.
- Extend that ambiguity gate to Chinese, Japanese, Korean, and mixed-language
  defensive frames at 511/512/513 bytes, 1 KiB, and 16 KiB. Multilingual terms
  never grant quoted-review suppression: they only require an exact same-field
  carrier to be classified independently; malicious carriers block while
  benign 16 KiB controls remain complete and nonblocking across Balanced,
  Strict, OpenAI Chat, OpenAI Responses, Claude, and Gemini source routes.
- Close the remaining public Keysmith request-local `system` and terminal
  `tool` middle/back carrier gap by requiring one unique, complete, same-scope
  META control owner; historical, assistant, nonterminal, and inert carriers
  remain nonblocking.
- Keep streaming classification in one request-level profiled ownership mode,
  normalize later legacy-shaped fields exactly like batch classification, and
  surface a late unannounced mode transition as explicit incompleteness instead
  of silently switching semantics mid-request.
- Accept the public defensive-review form `analyze ..., and do not apply it`
  only when its bounded quote, defensive purpose, terminal non-execution
  conjunct, and execution-free tail are all proven; explicit reactivation still
  blocks in Balanced and Strict.
- Correct the frozen evaluation-history guard so unrelated annotated tag
  objects cannot impersonate a restricted path, while still rejecting every
  reachable commit that touched one; failed long-fuzz jobs now retain only
  newly generated Go corpus files as a short-lived Actions artifact.
- Introduce request-local enforcement authority for structurally proven active
  system/developer/Responses-instructions and terminal tool-result carriers,
  while preserving non-user finding origin and excluding those blocks from
  subject-risk accumulation.
- Close provider-native tool authority around complete request-local
  transactions. OpenAI Chat, OpenAI Responses, and Claude now require adjacent,
  complete call/result groups with one-to-one IDs; Responses function/custom
  subtypes cannot cross-authorize. Gemini requires one adjacent terminal group
  with equal cardinality and either matching nonempty ID+name pairs or all
  ID-free name+ordinal matches. Mixed, partial, wrong-owner, orphaned,
  malformed, intervened, and nonterminal groups remain unassociated.
  Responses continuations containing only `previous_response_id` plus a result
  remain non-authoritative because Host pending/consumed/replay state is
  unavailable to the plugin.
- Restrict provider-native result authority to the exact Chat `content`,
  Responses `output`, Claude `tool_result.content`, or Gemini
  `functionResponse.response` boundary. Gemini authorizes string descendants of
  that exact response object, including CPA v7.2.103 `result` and `output`
  carriers, while siblings on `functionResponse` remain untrusted. Claude text
  blocks accept a CPA-preserved `cache_control` object without authorizing its
  metadata strings; arbitrary block siblings, aliases, and scalar cache-control
  lookalikes still fail closed. Chat calls retain the exact canonical function
  shape rather than an ID-only or legacy lookalike.
- Keep association planning linear in retained text spans by collecting exact
  authorized result-span IDs first and applying them in one span pass. ID/name
  fields are suppressed only inside proven provider-native call/result objects;
  unknown or malformed objects remain inspectable text.
- Add disarmed NERV regressions for credential/session theft,
  persistence/C2/evasion, ransomware, phishing, covert keylogging,
  unauthorized exploitation, and post-exploitation exfiltration. Cover
  Balanced/Strict batch/stream routes, four-provider roughly 7 KiB
  front/middle/back system and terminal-tool carriers, and low-false-positive
  repository, defensive-analysis, authorized-operations, and consented-
  telemetry neighbors. Exact-main five-repository counted-Mock evidence remains
  pending and is not inferred from source tests.
- Restore bounded Chinese defense-evasion eligibility for an affirmative
  `致盲` action tied to an active production/execute speech act. Explicitly
  negated actions, defensive incident analysis, quoted review, and authorized
  maintenance remain nonblocking.
- Bind creation and deployment verbs to their direct artifact: building or
  deploying a detector/scanner for a recovered persistence agent remains
  nonblocking, while a later independent instruction to create or deploy the
  agent still blocks. Reading or recovering a credential-exposure alert/finding
  for incident triage likewise remains distinct from reading and exfiltrating
  passwords.
- Bind terminal tool-result admission to the final conversation item in both
  batch and streaming paths so earlier outputs remain historical when a later
  assistant or user item exists.
- Replace the fixed defensive-quote sentence template with a bounded structural
  proof covering quote/fence/newline variants, analytical purpose, an explicit
  non-execution boundary, and fail-closed independent execution tails.
- Refresh the source behavior identity for `classifier-policy-v9` to
  the historical predecessor digest `f9529ada...`;
  the embedded YAML ruleset remains `1.0.10` and audit storage remains schema v6.
- Preserve `v0.16-rc.3` as an immutable failed Phase 1 identity. Its admission
  passed, but its fixed Go container lacked the undeclared PyYAML dependency;
  no candidate asset, attestation, or GitHub Release was created.
- Bootstrap the exact Safe Gate in both containerized Round 9 build paths with
  SHA-bound Debian `libyaml-0-2=0.2.5-1` and `python3-yaml=6.0-3+b2`, verify
  package metadata, install order, installed versions, module identity, and
  isolated Python execution, and fail closed when any command or pin drifts.
- Move the complete active Round 9 workflow, Host, evaluator, audit, artifact,
  test, and documentation identity to the unused `v0.16-rc.4` namespace. The
  old Tag is never moved, deleted, or reused.

## Historical - v0.16-rc.3 Round 9 candidate

- Redesign Balanced around candidate-bound `CandidateBlockEligibility`: score
  and hard floors cannot create block eligibility, and malicious-text blocks in
  Balanced or Strict require the same current-user/clause/scope/referent proof.
- Separate malicious-text, incomplete-inspection, opaque-media, subject-risk,
  clean, and audit-only decision kinds. Defensive, analytical, quoted,
  credential-lifecycle, code, log, fixture, and ambiguous requests fail open to
  allow+audit unless an independent current malicious clause is proven.
- Advance the classifier contract to `classifier-policy-v8`, the embedded YAML
  ruleset to `1.0.10`, and the audit database to schema v6 with mandatory
  pre-v6 backup, closed explanation variants, and explicit old-SO rollback.
- Add Round 9 development, paired-malicious, public-adversarial, and one-shot
  independent corpus contracts with unique semantic samples separated from
  serialized route executions. Public repository material remains
  development-only and no third-party repository code is executed.
- Preserve the exact public-v6 manifest as frozen-invalid history after proving
  its declared prompt-like review digest disagreed with the deterministic
  calculation; move active public evidence to immutable public-v7 with the
  corrected digest and byte-identical payload files.
- Restore the originally announced public-v8 bytes as immutable-invalid history,
  retain the rejected corrected-v8 rebind under its own identity, and move the
  corrected active schema and release evidence through public-v10 without changing any
  of the 24 payload bodies.
- Add the Linux-only `round9-gate.yml`, protected
  `round9-host-validation.yml`, and `round9-release-rc.yml` lanes. The protected
  Host workflow performs no source checkout; it invokes a reviewed root-owned
  broker that controls the encrypted independent corpora, evaluator keys,
  fixed images, and protected append-only ledger.
- Fix the CPA Host listener to exactly `127.0.0.1:18394 -> 8317/tcp`; preflight,
  Docker configured/runtime bindings, Host evidence, and publication manifest
  validation reject wildcard, random, extra, or multiple CPA bindings.
- Define a 17-asset private candidate and 19-asset immutable non-latest
  prerelease contract for `v0.16-rc.3`. The two publication-only assets are the
  signed external evaluation envelope and protected-ledger proof. Exact-main CI,
  protected counted-Mock, one-shot independent results, and independent audit
  remain required; production and real Provider access are not authorized.

## Historical - v0.16-rc.2 Round 8 candidate

- Rebuild Balanced blocking around active directive units and occurrence-owned
  evidence so unrelated history, assistant/tool content, tool schemas, code,
  logs, quotes, and separate fields cannot silently complete one harmful
  predicate.
- Tighten `EVADE-002`, `CRED-001/002`, `MAL-002`, and `DISRUPT-001`; weak
  development vocabulary cannot trigger a hard floor without a coherent active
  action, harmful object, target/outcome, and operational relationship.
- Add privacy-safe decision explanations, TTL capture deduplication by an
  internal exact request-body SHA-256, redaction metadata, and audit schema v5
  while keeping raw capture disabled, blocked-only, and independent of logged
  `request_hash` by default.
- Advance the YAML ruleset to `1.0.9` and the classifier contract to
  `classifier-policy-v7`; exact SHA-256 values are bound by the final clean
  release commit and release-document gate.
- Pin CPA `v7.2.95` (`f71ec0eb6776854457892452cf28c47f0d658251`) as
  the only current target. Source/compile checks use that exact tag, module
  Origins, and sums without
  claiming moving-latest compatibility.
- Migrate the Linux-only RC workflow to a two-stage `v0.16-rc.2` contract.
  Stage 1 produces a private 17-asset Host-test candidate and cannot create a
  Release. Stage 2 requires strict SHA-bound CPA v7.2.95 counted-Mock
  Host evidence, reproduces all 19 final assets, and may publish only a
  non-latest prerelease while the stable latest release remains exactly
  `v0.15`. A GitHub-hosted supply-chain job pulls the two Docker Official Images
  only by reviewed index/platform/config digests and relays a GitHub-attested
  bundle; the protected rootless Host verifies and loads it, then builds with
  `--pull=false` and never contacts Docker Hub or a registry mirror. The Host may
  contact only the official CPA Git/package/module sources required by the
  reviewed Dockerfile, never a model Provider or production service. Counted-Mock is not real Provider or
  production validation; independent audit/evaluation remain required,
  production approval has not been granted, and no stable `v0.16` exists.
- Harden the release-document mutation wrapper by pinning the reviewed fixture
  and gate bytes, requiring the wrapper's embedded dependency pins to agree with
  the safe-gate contract, and adding a negative regression for pin drift.
- Reconcile current release reports with the Round 8 identity and pending gate
  state: Host-evidence assembler contract tests are not Host execution evidence,
  older P1-P2 benchmarks remain historical, local Linux race/allocation and
  benchmark results remain development self-checks, and exact-main CI, Host,
  tag, and publication results are not predeclared as PASS.

## Historical - post-v0.16-rc.1 P1-P2 hardening

- Admit a blocking audit event and its optional raw-capture preview as one
  bounded composite work item. The writer uses one SQLite transaction, keeps
  the ordinary event when preview insertion fails, and exposes dedicated
  capture counters, queue high-water, and preparation latency.
- Reserve queue capacity before capture hashing/redaction. Redaction now scans
  only `max_bytes + 64 KiB` while SHA-256 still covers the complete request;
  saturated queues therefore reject without full-body capture work.
- Preserve the legacy `raw_preview` field while adding canonical
  `raw_preview_b64` for the pinned CPA v7.2.88 HTML-sanitizing transport. The
  response publishes an exact predicted Host-body size, an 8 MiB full-response
  budget, schema/deprecation metadata, and a mandatory text-only rendering
  contract.
- Replace repeated full-response management encoding with one-pass per-record
  size accounting. Add raw-capture preparation/composite/queue-full benchmarks
  and a worst-case management-response acceptance gate.
- Make deterministic fuzz-seed smoke testing fail closed over all 13 reviewed
  targets, retain time-based fuzzing in the separate CI job, and fail closed if
  long-text or raw-capture performance tests/benchmarks are renamed or removed.
- Add a minimal-permission Linux Go CodeQL workflow, pin every action by commit
  SHA, and freeze its trigger/permission/step contract in the repository safe
  gate. After GitHub rejected Go `build-mode: none`, switch to pinned Go 1.26.4
  and an exact read-only manual build for CodeQL tracing.
- Reduce the attested-prerelease manual dispatcher from 15 fields to nine by
  validating one exact-key Host/audit/evaluation JSON object, and add a
  repository safe-gate regression for GitHub's current 25-input platform cap.
- P0 remains unresolved: client-controlled assistant history can still affect
  the historical refusal-maintenance exception. This hardening is not v0.16
  release authorization.

## 0.16 — 2026-07-21

Development status: **LOCAL RC PACKAGE CREATED / EXACT-MAIN GITHUB CI FAILED /
NO REMOTE TAG OR GITHUB RELEASE**. The source version is `0.16`, the intended
formal tag is `v0.16` (never `v0.16.0`), and the current local artifact is
`v0.16-rc.1`.

### v0.16-rc.1 local Linux amd64 core package

- Add an explicit, default-off `audit.raw_capture` review path that persists
  only redacted and bounded previews for final `block` or subject `cooldown`
  decisions. Allowed, observe, and audit-only requests are never captured;
  request headers are never stored.
- Reduce ordinary-user false positives by constraining weak META score
  amplification, recognizing defensive risk-control maintenance language, and
  closing only the narrow refused-attack-then-defensive-maintenance history
  sequence. Direct execution follow-ups remain blocked.
- Target Linux amd64 and the pinned CPA v7.2.88 source contract. Windows,
  macOS, local deployment, and production deployment are outside this package
  operation.
- Bind the local package manifest to annotated tag object `4c04e465`, commit
  `7b2422e`, and tree `d586824e`. The Linux SO SHA-256 is
  `9d0ee747491dedeb83f3b3e98137d879dbaba5818e7a6922f9cf1f61d407e685`; the CPA
  Store ZIP SHA-256 is
  `86e9eba5265d5f2bb737ec41d5ed8ada51bf352b3833c2d985d3f754963540f7`.
- Record exact-main CI run `29799561002` as two failed attempts with zero
  Actions artifacts: attempt 1 timed out in `FuzzExtractText`; attempt 2 passed
  that fuzz step and later failed the Round 6 document-consistency fixture in
  `operational-script-security`.
- Treat the local RC package only as a handoff artifact. It is not a GitHub
  Release, successful GitHub Actions artifact, formal-release attestation, or
  new CPA Host validation record. The retained `v0.15-rc.*` workflows and
  evidence below are historical v0.15 records.

## 0.15 — 2026-07-18

Historical pre-publication status was **BLOCKED / PENDING HOST AND INDEPENDENT
AUDIT**. Exact project version is `0.15` and the only formal tag name is
`v0.15` (never `v0.15.0`). That status was superseded by the manual stable
publication recorded below; it was not converted into independent evidence.

### v0.15 manual stable publication — 2026-07-20

- Publish `v0.15` as non-draft, non-prerelease, latest stable with ten assets.
- Release Notes disclose that GitHub Actions did not run because of Billing and
  that the owner built the assets manually after an owner-reported production
  sandbox pass.
- No independent Host/audit/evaluation attestation is attached; the manual
  publication must not be reused as v0.16 evidence.

### v0.15-rc.4 formal-structure prerelease

- Add a dedicated active `release-rc.yml` workflow fixed to the annotated
  exact-main `v0.15-rc.4` tag and its tag-object SHA. Admission requires a
  successful exact-main push CI before checkout and rechecks immutable
  tag/commit/tree/main identity before publication.
- Run the complete Linux internal quality suite, CPA v7.2.88 source
  compatibility, RC-versioned integration, and two independent clean-clone
  rebuilds. Windows and macOS remain intentionally outside scope.
- Publish exactly 17 formal-structure RC assets: versioned SO and CPA Store ZIP,
  audit bundle, source archive, build metadata, checksums, ruleset manifest,
  SBOM, internal test summary, RC-only evidence, exact manifest, and sidecars.
- Create a draft first, upload and re-download every asset for byte comparison,
  then publish only as `prerelease=true` and `latest=false`. Post-publication
  validation failure restores the release to draft.
- Keep the status explicitly `RC_INTERNAL_GATES_PASS / SANDBOX_ONLY /
  SERVER_VALIDATION_REQUIRED / NOT_FORMAL / NOT_ROUND6_CANDIDATE`. No real CPA
  Host PASS, independent audit/evaluation PASS, formal attestation, or
  production authorization is generated.

### Historical RC3 failed attempt

The protected annotated `v0.15-rc.3` tag remains immutable at tag object
`6733a74903c7f2174a24fc53fad601e763e6a4c7`, commit
`ac1456b74edd73bec5d8a8fb8b87630cb3320d21`, tree
`5838d9bac6251fd1212cce86c2c608b6d8cbee47`. Workflow run 29728286559
passed admission but failed in the internal gate step before packaging because
the candidate contract fixture inherited the outer RC build mode. Publish was
skipped, no Actions artifact was uploaded, and no GitHub Release (including a
draft) was created. RC4 isolates that synthetic test matrix from all caller
release-mode, identity, epoch, sparse-checkout, and version variables.

### Historical RC2 state

The Round 6 implementation was merged by PR #9 at
`main@6782dfaffd4da3f09604113c7d38675f331dc759`, tree
`a8edbe2e6d19fa725fb962cdd6aaad5b416d4b85`, and exact main/tag CI passed. A
public `v0.15-rc.2` prerelease now carries ten Linux amd64 sandbox assets. It
was published through a direct owner override with automated tests and CPA Host
integration explicitly skipped as release gates. The RC source CI failed on an
HTTP 403 while checking the latest CPA source, so this prerelease is not the
private clean candidate, a formal release, Host compatibility evidence, or
deployment authorization. Windows and macOS are outside scope. The historical
v10 result remains `CONSUMED / FAIL` and cannot be rerun or used for tuning. A
future stable release still requires a newly authored independent unseen set.

- Advance the active release and Host pin to CPA v7.2.88 at
  `93d74a890a44802f656d7f39a573916b2611896e`, use the generic
  `cpa-host-blackbox` entry point, and bind Host evidence through attestation
  schema v2 fields `cpa_version`, `cpa_commit`, and `cpa_host_sha256`. Later
  upstream CPA versions do not automatically retarget the supported Host or
  formal release identity.
- Bind the fixed CPA identity to the exact official lightweight Git tag, all
  three checked-in module requirements, Go module Origin, and both checksums.
  The compatibility lane no longer depends on rate-limited GitHub REST Release
  metadata or exposes a repository token to checked-out source; remote Git
  lookup is time-bounded and isolated from repository-local Git configuration.
- Extend release-policy and CI contracts so schema-v2 Host evidence fields,
  fixed CPA verification, and the absence of checked-out repository tokens are
  covered by mutation tests rather than documentation alone.
- Give every current release document exactly one machine-readable classifier
  policy version/hash declaration. The release-document gate now rejects stale,
  conflicting, or duplicate canonical identities even when the current value is
  appended later, with dedicated mutation fixtures for each bypass shape. The
  declaration must occupy the fixed visible prologue immediately below a
  top-level H1 rather than being hidden inside HTML comments or frontmatter.
  Formal release rejects document-root, fixture, and current-identity
  environment overrides; ordinary CI, candidate, and
  attested-prerelease gates validate the real source tree. The public jailbreak
  review is now both identity-bound and included in the strict audit bundle.
- Change safe startup behavior to `mode: observe` with subject control disabled.
  Observe now updates counters without persisting per-request SQLite events,
  including streaming/incomplete and oversized request paths. Explicit
  `balanced` plus `subject_control.enabled: true` remains supported.
- Defer the domain-separated full-body request hash until it is required by an
  eligible accumulating subject hit, a final local block pending key, or a
  persisted audit event with `log_request_hash: true`. Read-only subject
  observations do not hash the request body.
- Keep complete non-user/untrusted category-free wrapper-only findings on
  bounded `audited` and
  `control_plane_meta_override` counters by default, avoiding per-request body
  hashing and SQLite writes on benign wrapper traffic. Operators can restore
  the legacy event stream with `audit.persist_wrapper_only: true`; base Cyber
  Abuse findings, trusted-user wrapper findings, blocks, incomplete
  inspections, and opaque media remain fully audited.
- Continue directive analysis after the first 64 retained risk clauses instead
  of treating overflow as either a complete allow or an unconditional active
  finding. The classifier now keeps an exact bounded suffix plus rolling
  per-rule, per-provider-pair composition, context-conflict, and semantic
  summaries, so a late malicious clause cannot escape while repeated complete
  prohibitions remain inert. Compact intent patterns and clause proof scratch
  are reused to bound high-density negation work.
- Prevent a low-score same-category candidate or an approved-workflow marker
  from suppressing a contradictory different-provider composition. Exact and
  overflow paths now apply the proven context contradiction before candidate
  suppression, so a harmless head cannot launder an active composed tail.
- Treat bounded modal lead-ins after an explanatory `and now` pivot as a strong
  directive boundary when they lead to a compiled rule intent. This covers
  unlisted English forms such as `it is necessary to`, mixed-language tails,
  and overflow while retaining legitimate approved-migration explanations.
- Tighten closed-schema user attribution for malformed provider arrays and
  Responses item discriminators. Nested history/content arrays, scalar content
  array members, and unknown or non-string Responses `type` values remain
  inspectable but untrusted; the exact Responses `type` field is transport
  metadata and no longer becomes legacy prompt text.
- Tighten subject-risk admission so only authenticated, completely inspected
  user-content base-behavior findings with `FindingCompleteRequest`, a direct
  classifier `ActionBlock`, and `score >= hard_block` add rolling risk.
  Anonymous, system, assistant, tool, tool-payload, roleless, unknown,
  mixed-role, and lower-confidence requests keep their direct per-request
  disposition but do not allocate subject state or add hits, receipts, or
  repeat multipliers. Publish the resulting code-level contract as
`classifier-policy-v5` / `0e114d98862282d2492fb62e4300297b4746eeaf8165339603d02c48d11bd60b`.
- Treat one closed, explicitly quoted Cyber Abuse request as inert only when
  the surrounding user text asks to explain why it is unsafe and ends with an
  exact non-execution boundary. Missing or multiple quotes, double negation,
  unquoted abuse, and `then`/`however`/`and now` operational continuations fail
  closed; a later explicit implementation follow-up reactivates the retained
  quoted category signals and blocks.
- Reclassify only that unique quoted referent when the newest eligible user
  review is followed by an affirmative referential directive such as
  `execute it`, `proceed`, or `go ahead`, including bounded polite and
  conditional forms. The reactivated result is the direct referent result; it
  does not inherit the safety wrapper's signals or context. Questions,
  explanations, negation, consequences, and remediation remain inert, and
  assistant/system/tool reviews cannot seed a later user referent.
- Preserve every bounded active or cancelled quoted-review action occurrence
  instead of collapsing a clause to its rightmost action and retaining only one
  cancellation. A later prohibition now cancels only an equivalent action
  family: `implement and run; do not run` remains blocked, while independently
  cancelling every requested family remains allowed. Narrow `follow`, `obey`,
  `carry out`, and `run [the] quoted request` imperatives are covered together
  with analytical, defensive, alternative-branch, and no-referent neighbors.
  Coordinated `do not A or/nor B` keeps one terminating negation scope across
  both actions, while `A or do not A` remains an optional branch. That branch
  identity persists through later `and` actions in the same arm, preventing an
  optional cancellation from erasing the active first choice.
- Recognize common directive governors including `just`, `simply`, `let's`, and
  `let us`. The follow-up parser now distinguishes active, proven inert, and
  unrecognized speech acts. Only a proven explanation, question, safety
  deliverable, or negation suppresses the conservative streaming risk fallback;
  an unrecognized phrase can no longer turn a cross-window prior risk into a
  complete allow.
- Preserve only privacy-safe quoted-review results and affirmative-follow-up
  facts across long streaming fields. Referent reclassification consumes the
  normal classification-chunk budget. When either side crosses a bounded
  scanner window and the exact relationship cannot be proved, return
  `CoverageUnavailable` / `classifier_window_incomplete` instead of a silent
  complete allow; budget exhaustion remains separately reported as
  `classification_chunk_limit`.
- Exclude a bounded adjacent head/tail reclassification whenever either field
  already proved a complete inert quoted referent. This prevents a long review's
  truncated tail from losing one side of the safety wrapper, and avoids charging
  an unnecessary classification window.
- Add a separate, zero-value-untrusted user-attribution proof. Only an explicit
  recognized `role: user` content path or an allowlisted multipart prompt is
  trusted; unknown top-level fields, unknown message siblings, roleless/future
  items, assistant/system/tool content, and tool payload/output remain
  non-user-or-untrusted. A composite finding is user-originated only when every
  contributing user-like field is trusted.
- Bind that proof to the CPA `SourceProfile`: only a matching root history
  container can establish a user role; Responses scalar `input` is supported,
  while nested histories, cross-provider envelopes, unknown content types,
  function responses, and roleless unknown items stay untrusted. Responses
  reasoning replay treats `encrypted_content` as opaque only after the closed
  `reasoning` item type is proven.
- Recognize CPA v7.2.88 Codex Desktop `input[].type="additional_tools"` as a
  closed Responses item. Namespace/function/custom descriptions remain
  system-originated and untrusted, while a following exact user message keeps
  trusted attribution. The official exact `role: "developer"` sibling and the
  translator's roleless form are accepted; canonical aliases and every other
  explicit role on a type-derived item fail closed.
- Add repository-neutral regression coverage for authority wrappers, developer
  and tool carriers, Chat/Responses tool descriptions, assistant/tool-call
  history, all four control families across 17 non-user carriers, defensive
  domain catalogs, 1.4-17.4 KiB size variants, 16 KiB boundaries, exact-tie user
  winners, and clean same-identity follow-ups.
- Skip authenticated subject HMAC derivation and controller locking for a
  complete classifier `allow`: the subject contract already guarantees that a
  below-audit clean request is safe even when prior cooldown/manual metadata
  exists. Audit/block paths and accumulating trusted-user findings are unchanged.
- Reduce clean-request scanner overhead without changing coverage: short JSON
  strings no longer reserve a full 16 KiB decode buffer twice per field, and a
  single-window field skips cross-window risk-potential synthesis when no
  multi-window contribution can exist. Valid unescaped JSON strings now stream
  directly from the request buffer without an intermediate decode buffer.
- Make the Linux `round6-benchmark` lane fail on full-route regressions instead
  of reporting measurements only. It now enforces latency/allocation ceilings
  for ordinary clean traffic, the 17 KiB wrapper-audit counter fast path, and
  parallel clean subject-enabled traffic, and also executes the parallel
  benchmark explicitly.
- Clear inherited Git repository-routing variables in every shared release
  helper before fixture or source operations. Contract validation freezes this
  guard so temporary sparse/archive work cannot silently regain access to the
  caller's checkout.
- Require every current release-facing report to declare the source-derived
  classifier policy version and SHA-256. Historical reports may retain their
  recorded identities, but stale current identities now fail the documentation
  consistency fixture.

- Add a dedicated, manual `v0.15-rc.2` prerelease workflow for clean Linux
  amd64 server-sandbox assets. It binds an annotated RC tag to the exact main
  commit/tree and successful main push CI, embeds `0.15-rc.2` in the SO and CPA
  Store ZIP identity, verifies the historically pinned CPA v7.2.86 contracts,
  and reproduces the bytes
  in two independent canonical sparse partial clones before publication. The
  RC-only packaging path normalizes CycloneDX's generated main component to the
  exact annotated RC identity before rebuilding final checksums, so the root
  and both reproductions remain byte-identical without changing formal paths.
- Emit `rc-release-manifest.json` with exact source, workflow, CI, CPA, and
  artifact hashes. The manifest is explicitly sandbox-only, not formal, and not
  a Round 6 candidate or external Host/audit/evaluation attestation.
- Bind every headless `gh release` create/upload/edit operation to the canonical
  repository explicitly, so publication and rollback do not depend on a local
  Git checkout after the build artifact has been verified.
- Pass the workflow token to the CPA latest-source identity check and run that
  external check after core regressions, unit/race/vet, build, and artifact
  generation, so a transient GitHub API failure remains visible without
  suppressing the local verification evidence.
- Add a documentation index, archive the obsolete v0.1.2 next-version notes,
  and synchronize both README entry points with the published RC state.
- Rename the active candidate and externally attested prerelease workflows to
  stable purpose-based paths, and move the retired attempted `v0.15-rc.2`
  workflow definition out of GitHub Actions into the documentation archive.
  Its recorded runs failed and did not publish the public RC; that Release
  remains the separately disclosed direct owner override. Publication inputs,
  permissions, identity checks, and fail-closed release gates are unchanged.

### Round 6 long-text streaming candidate

- Record `21ceb57e6b6030e56d7820c9a67a8eecd068c669` (tree
  `e55437442f30bdb1b6b748b9611c6760172784cd`) as a passed
  **pre-version-migration checkpoint**: push CI `29578024185` and PR CI
  `29578025961` passed, including the then-current CPA v7.2.83 latest-source
  lane. This checkpoint is engineering evidence only and is not
  the final v0.15 source, artifact, Host, audit, tag, or release identity.
- Migrate the active project/build/release identity from the historical `0.1.2`
  development line to exact version `0.15`, Linux amd64 only. Historical
  Round 5 `0.1.2` tags, hashes, assets, and evaluation records remain frozen.

- Remove production parsing of `body[:max_scan_bytes]`. Supported JSON requests
  now traverse the complete CPA-visible envelope and replay proven
  model-visible string spans incrementally.
- Migrate legacy `max_scan_bytes` into a compatibility alias for the retained
  classifier window. Add bounded `max_total_text_bytes` and
  `max_classification_chunks` controls so cumulative coverage and retained
  memory are independent.
- Add a streaming classifier session with derived overlap/carry, logical field
  boundaries, role/provenance isolation, bounded cross-window reconstruction,
  and fixed coverage states.
- Retain only bounded classifier signal facts inside each logical field. If
  independently safe-looking windows contribute different risk ingredients
  whose aggregate reaches the balanced threshold, report classifier-window
  coverage as unavailable instead of incorrectly returning complete allow.
- Treat assistant/system safety quotes as provisional until a real closing
  delimiter is observed. Closed quotations discard their bounded provisional
  result; an unclosed logical field commits it as ordinary content, including
  later-window and cross-window malicious text.
- Inspect oversized Base64 candidates with a constant-memory full-stream syntax
  and decoded-text signal so a binary first sample cannot hide printable text
  near the end, malformed trailing bytes cannot erase an already proven strong
  printable Base64 prefix, and high-density text cannot evade detection by
  inserting a control byte before every 32-byte run. Enforce `max_classification_chunks`
  before every actual emitted UTF-8-safe chunk rather than relying only on a
  byte-length estimate.
- Keep media, metadata, tool-schema, multipart, and role decisions
  transactional. Add `RoleUnknown` so unknown schema cannot impersonate proven
  user text.
- Replace the CPA-transformed OpenAI image multipart JSON legacy collector with
  a schema-bound raw-span streaming planner. Approved 270 KiB and 1 MiB prompts
  now receive complete classification in balanced/strict mode, while unknown
  fields, non-string prompts, opaque files, binary controls, and oversized
  encoded views retain their fixed multipart contracts.
- Neutralize every partial finding when envelope or text coverage is
  incomplete. The optional verified-local-hard exception remains disabled:
  `balanced` allows plus audits, `strict` blocks plus audits, and incomplete
  input never updates subject risk.
- Add audit schema v3 fields `decision`, `coverage`,
  `incomplete_reason`, and `scanner`, scanner identity
  `streaming-scanner-v1`, effective-limit status, and fixed low-cardinality
  counters.
- Publish classifier identity `classifier-policy-v3` /
  `1294c6fd587522829d07220d5a6f4214092eba6ce1837636da5b3e3d461ba2a3`.
- Compact the transactional shadow plan by collapsing caller-controlled keys
  and semantic values to closed representatives, skipping metadata spans, and
  using short base-36 markers. Residual allocation remains bounded by structural
  token/node/field limits and awaits authoritative Linux memory evidence.
- Add Linux long-text coverage tiers at 64 KiB, 255 KiB, 256 KiB,
  256 KiB + 1, 270 KiB, 512 KiB, 1 MiB, 4 MiB, and near the effective RPC
  boundary, plus classifier/extractor fuzz and scaling benchmarks. The
  `21ceb57` push/PR checkpoint passed these Linux engineering gates; final v0.15
  evidence remains pending after the version/release-chain migration.
- Isolate consumed evaluation/Holdout gate tests behind the
  `consumed_evaluation` build tag and restrict ordinary Round 6 CI to explicit
  safe targets and sparse source checkout.
- Make the Linux build itself audit the complete `readelf --version-info` set,
  reject non-numeric GLIBC ABI tags and numeric versions above 2.34, and make
  the long-JSON benchmark fail if its exact extract-package benchmark name is
  absent instead of accepting a zero-match run.
- Add a dedicated private, untagged clean-candidate Actions workflow. It binds a
  post-merge `main` commit/tree to its successful main push CI run, requires
  dispatch from `main` after the workflow exists on the default branch, requires
  the formal `v0.15` tag to be absent, produces clean reproducible Linux amd64
  bytes plus `candidate-manifest.json`, and uploads an expiring Actions artifact.
  The bytes are explicitly unreleased and cannot invoke a formal operation.
- Add the neutral source policy in
  [RELEASE_POLICY.md](docs/RELEASE_POLICY.md). Future external decisions are
  carried by `round6-prerelease-attestation.json` and
  `formal-release-attestation.json`; reusable source documents do not hardcode
  future PASS hashes or Release state.
- Require the CPA v7.2.88 Host + Mock record, the independent
  audit, and a candidate-bound external `evaluation-v11` or later first-and-only
  `CONSUMED / PASS` report to cite the same candidate identity. If a durable development handoff
  is needed after those gates pass, an existing annotated
  `v0.15-dev.round6[.N]` may create a draft prerelease marked
  `BLOCKED / NOT A FORMAL RELEASE`. A later annotated formal `v0.15` tag and
  formal draft remain separate and consume that candidate-level external
  evaluation attestation. The formal workflow consumes the
  prerelease attestation, rebuilds and byte-compares the Host-tested bytes, and
  emits `formal-release-attestation.json`; a protected promotion workflow
  publishes the unchanged draft only after another approval.
- Keep historical evaluation-v10 immutable at `CONSUMED / FAIL`: it cannot be
  rerun and is not a formal-build input. Formal source and audit bundles exclude
  evaluation, Holdout, private, blind, and retired material; they carry only
  low-sensitivity attestation identities and hashes.
- Preserve two deliberate compatibility boundaries: dense encoded derived
  views beyond the 128 KiB source / 64 KiB retained decoded budget are
  incomplete, and legacy `ExtractText` keeps materialized `Parts` segmentation
  semantics while production routing uses streaming APIs.
- Make CPA v7.2.88 the only current source/compile and real Linux Host +
  Mock-upstream release target; its Host matrix is **NOT RUN / PENDING**. Earlier
  v7.2.85/v7.2.84/v7.2.83/v7.2.82/v7.2.81 compatibility results remain historical non-gating engineering
  evidence. The merged implementation baseline passed exact-main and tag CI;
  any later source cleanup must pass its own exact-main CI before candidate
  dispatch. The public source-only `v0.15-rc.1` prerelease is not admitted as
  candidate evidence. Do not create the formal tag or asset-bearing Release
  before the v7.2.88 Host gate, independent audit, and candidate-level
  evaluation pass.
- Remove the legacy `cpa-v7285-host-blackbox`, `cpa-v7284-host-blackbox`,
  `cpa-v7283-host-blackbox`, `cpa-v7275-host-blackbox`, and
  `cpa-v7272-host-blackbox` Make aliases. Active CPA tests now expose only the
  v7.2.88 Host, source/fixture, pinned-compatibility, Router, and Store paths.
- Align the v7.2.88 Host black-box expectation with Round 6 streaming semantics:
  legacy `max_scan_bytes` is a migrated text-window alias, not a total-text
  truncation limit, so an already proven malicious request must still return a
  local 403 with zero provider-side effects.
- Make the formal audit bundle self-contained for README navigation by adding
  `SECURITY.md` and the referenced Round 6 design, migration, limitation,
  release-gate, and development-handoff documents to the strict package and
  verification allowlists.
- Fix clean-candidate sparse-checkout admission by matching the lower-cased
  restricted document paths with lower-case patterns. Add a contract test for
  mixed-case Evaluation/Holdout paths so candidate packaging cannot regress at
  the first artifact-build step.
- Require the final PR head to have no unresolved, non-outdated actionable
  review threads before merge. Automated review is advisory and does not
  constitute independent approval.
- Add the Round 6 design, configuration migration, limitations, release-gate,
  and development-handoff documents.

## 0.1.2 — Historical unreleased development line

The following Round 5 material, hashes, prerelease tags, and v10 facts are
frozen historical evidence. They are not renamed to 0.15 and do not validate
the Round 6 candidate.

- Complete the Phase 0 CPA contract alignment without changing the root runtime
  baseline from CPA v7.2.67. Local `execute`, `execute_stream`, and
  `count_tokens` refusals now emit policy RPC error envelopes requesting HTTP
  403, while unsupported `http_request` remains an envelope requesting 405.
- Split the CPA Store archive from the audit/operator bundle. The Store ZIP
  contains exactly one executable `.so` at its root; documentation, build
  metadata, SBOM, and verification material are packaged separately in the
  Audit Bundle. The root `checksums.txt` remains a separate release asset that
  covers both the Store ZIP and Audit Bundle.
- Add an isolated CPA v7.2.72 source-contract module for the official
  `pluginstore.InstallArchive` naming/layout/install behavior and official
  Host Router ordering/fallback tests. These tests do not load this plugin and
  are not CPA v7.2.72 runtime-compatibility evidence.
- Document that the audited CPA v7.2.72 management path calls `io.ReadAll`
  before the plugin handler, so plugin body limits are not host HTTP memory
  limits and an external reverse-proxy limit still requires server evidence.

- Add the development-only deterministic `META-OVERRIDE-001` classifier
  overlay for instruction-hierarchy inversion, refusal suppression,
  unrestricted persona claims, sandbox/placeholder laundering, forced-output
  controls, explicit negative authorization, and system/developer-prompt or
  hidden-reasoning disclosure. It requires independent evidence families; a
  lone `jailbreak`, `benchmark`, or `developer` token is not a block rule.
- Re-extract supported-provider bodies conservatively when role proof fails;
  recursively inspect JSON-looking strings inside established tool payloads;
  re-decode content joined from split provider blocks; reconstruct tightly
  bounded isolated-character fragments; extend the reviewed homoglyph map; and
  reject malicious policy wording that negates refusal or filtering rather
  than the abusive action.
- Record this work as post-v10 developer-visible engineering evidence only.
  The targeted source package tests, vet, module verification, and diff checks
  are recorded in `docs/reports/TEST_REPORT.md`. Server sandbox validation,
  current-diff real-CPA integration, native loading, deployment, and formal
  Holdout remain pending, not run, or prohibited. A development prerelease may
  be published only as a blocked audit snapshot; the v10 release failure is
  unchanged.
- Document that ruleset `1.0.7` and its canonical SHA-256 identify only the
  embedded YAML cyber-abuse assets. The complete post-v10 classifier policy —
  including the meta overlay plus matcher, normalizer, role, and extractor
  semantics — is identified only by the containing source/build commit, not by
  the ruleset manifest; a future release must add a separately versioned policy
  identity or bind all behavior to verified build provenance.

- Harden the post-v10 development tree after independent review. Carrier
  authors now prove that production extraction recovers the authored semantic
  text; validators fail on schema, duplication, extraction, overlap, taxonomy,
  scale, distribution, and frozen prior-corpus inventory errors; snapshot globs
  must all match; and one shared fixture publisher keeps incomplete staging
  private before a no-replace atomic rename. Files and Unix directory metadata
  are synced; non-Unix directory sync is explicitly best-effort. Unix tests
  now assert that the destination name stays absent throughout staging.
  Windows uses native `MoveFileEx` without replace semantics and is exercised
  against existing files, symlinks, and concurrent publishers.
- Preserve v9/v10 corpus and historical implementation hashes without forcing
  later development HEADs to equal consumed-run snapshots. Full-history CI now
  binds the recorded hashes to commit `0f1d68717daadfd5dfc514ff2174cfb641a5d845`
  and tree `df878c537bca9fd71256b1c81ced18e72b583cf3`, then recomputes them from Git
  blobs. The frozen v9/v10 corpus and formal report blobs are bound to the same
  commit so changing current files and constants together cannot rewrite the
  consumed record. Missing Git metadata or shallow history fails this gate
  closed instead of silently passing. Current source remains unevaluated until
  a new independent unseen set exists.
- Harden malformed and permissively decoded Base64 handling, including
  horizontal whitespace and valid padded prefixes followed by ignored suffix
  bytes. Also harden atomic no-follow HMAC secret opening across Unix, callback
  synchronization tests, decimal watchdog budgets, and portable HMAC-key
  publication synchronization.
- Update `golang.org/x/crypto` to `v0.52.0` and `golang.org/x/net` to `v0.55.0`
  plus their required `x/text`, `x/sync`, and `x/sys` versions, meeting the
  minimum patched versions for all 14 alerts against the prior module graph.

- Add bounded textual decoding for URL percent escapes, HTML entities,
  inspectable Base64, textual data URLs, JSON escapes, and nested tool JSON.
  Decoding is limited to two layers, eight variants, a 128 KiB encoded source,
  and 64 KiB retained decoded text; no decompression, archive expansion, or
  network fetch is performed.
- Separate opaque image/audio/video handling from text truncation. Add
  `opaque_media_policy: block|audit|allow` with mode-aware defaults: Off allows,
  Observe/Audit/Balanced audit, and Strict blocks. Public media URLs are never
  fetched.
- Publish embedded ruleset `1.0.7` and expose linked version plus canonical
  ruleset SHA-256 through build metadata and authenticated status.
- Add router error and recovered-panic counters, `enforcement_ready`, explicit
  audit/HMAC/persistence degradation, build identity, reconfigure error, and
  ABI conflict-detection limitations to management status.
- Add a read-only production health checker. Its benign and fixed-malicious
  probes are evaluated locally through authenticated management routes and
  never reach `/v1`, CPA auth selection, usage accounting, or an upstream.
- Bound and harden management request bodies, query parameters, pagination,
  method handling, delete/unblock inputs, and database-degraded responses. CPA
  Management Key middleware remains the authentication authority; ordinary
  downstream keys cannot authorize plugin management routes.
- Keep `audit.log_original_text` only as a rejected compatibility field.
  `true` fails configuration; no debug mode persists raw prompt/request text.
- Introduce atomic SQLite schema migrations with `schema_version` and
  `migration_history`. Schema v2 adds optional subject-state storage. Optional
  pre-migration `VACUUM INTO` backups are mode 0400 and retention-bounded.
- Add optional `subject_control.persistence`. It stores only HMAC subject IDs
  and bounded risk/cooldown/manual-block state, applies expiry/decay/capacity on
  restore, requires a stable HMAC key, and explicitly degrades on key mismatch
  without overwriting the old snapshot. In-memory enforcement remains active.
- Add a race-resistant HMAC secret-file generator that does not print secret
  material. Document a future active/previous dual-key rotation state machine;
  dual-key rotation is not implemented in v0.1.2.
- Add a versioned build identity (`version`, commit, ruleset version/hash,
  dirty state), clean-tag preflight, deterministic timestamps, strict
  verification failure, ruleset manifest, CycloneDX SBOM, pinned
  `govulncheck`, and two-clean-clone reproducibility comparison.
- Refactor CI into explicit format, diff, module, unit, race, vet, fuzz,
  regression, Holdout, benchmark, vulnerability, build, real-CPA integration,
  verification-fault, artifact-hash, clean-tree, and reproducibility gates.
  Format checking includes tracked and untracked Go files and exits cleanly
  when a repository contains none.
- Add production operations documentation for Observe → Audit → Balanced
  rollout, watchdog alarms, router-order/duplicate-binary manual checks,
  binary/database rollback, HMAC retention, and opt-in complete cleanup.
- Add evidence templates for tests, performance, CPA integration, privacy, and
  release provenance. Missing formal artifacts are labelled `NOT CREATED —
  RELEASE BLOCKED`; no v0.1.1 result is presented as v0.1.2 evidence.

## 0.1.1 — 2026-07-12

- Treat artificial scan boundaries inside JSON escapes or UTF-8 sequences as
  truncation instead of parse errors, so enforcing modes fail closed rather
  than surfacing a CPA router-error fail-open path.
- Scan metadata-named fields such as `name`, `url`, `type`, and `model` when
  they occur inside tool payloads, including order-independent Anthropic
  `tool_use.input`, while continuing to skip transport metadata.
- Add role-aware standard OpenAI/Anthropic/Gemini conversation extraction.
  Classify every retained segment independently, join adjacent user turns for
  follow-ups, use a conservative fallback for role-less provider items, and
  fail closed instead of silently discarding over-capacity history.
- Historical v0.1.1 behavior handled over-8-MiB Base64-expanded model-route
  RPCs without copying the giant payload: at that release, Balanced/Strict
  self-routed to a local scan-limit refusal while non-enforcing modes retained
  their documented behavior. This is not the current Round 9 contract: only
  Strict model-route self-routes; Balanced and every other non-strict mode pass
  through with incomplete-inspection accounting, while a directly invoked
  oversized executor returns a non-strict local 413. Record a privacy-minimal
  scan-limit event without inventing unavailable request metadata.
- Scope negation and prohibition cues to nearby evidence so unrelated prefixes
  cannot suppress a later operational-abuse request.
- Publish embedded ruleset `1.0.1`, including targeted indirect
  data-exfiltration coverage for corpus cases `M128` and `M150`.
- Bound subject state with `subject_control.max_subjects` (default 10,000), LRU
  eviction of non-manual entries, protected manual blocks, capacity counters,
  and fail-closed handling when protected entries consume all capacity.
- Preserve risk, cooldown, and manual-block state across compatible enabled-to-
  enabled hot reconfiguration; reject unsafe capacity shrink atomically, keep
  `started_at` stable, and expose the latest `configured_at` plus capacity
  counters in status.
- Leave safe existing audit-directory permissions unchanged; reject writable
  directories plus database/sidecar symlinks; surface runtime permission
  failures; add deadline-bounded shutdown and reentrant, rate-limited audit
  degradation logs.
- Harden Linux HMAC secret loading with `O_NOFOLLOW` and validate/read from the
  same opened file descriptor.
- Require the release path to pass the pinned real-CPA integration suite and
  reject binaries importing glibc symbol versions newer than `GLIBC_2.34`.
- Reduce ordinary classifier latency/allocation and remove the two retained
  exfiltration misses: the locked Balanced corpus now measures 0/142 false
  positives and 154/154 malicious exact-category recall.

## 0.1.0 — 2026-07-12

- Initial CPA v7.2.67 C-ABI v1 plugin.
- Pre-auth ModelRouter and local 403 executor.
- Embedded bilingual deterministic rules across eight abuse categories.
- Bounded multi-protocol text extraction and fuzz coverage.
- Balanced/strict enforcement plus observe/audit modes.
- HMAC subject correlation, decay, cooldown, and manual unblock.
- Minimal SQLite audit events and authenticated management API.
- Linux amd64 reproducible build, checksums, release ZIP, and real-host test.
