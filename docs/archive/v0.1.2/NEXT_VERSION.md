# Next-Version Recommendations

These items remain after the v0.1.2 candidate work. They are not claims about
implemented behavior.

1. Propose a CPA ABI-v2 block result carrying HTTP status, headers, and a
   protocol-native body so cooldown responses can include `Retry-After`, a
   blocked stream can have an explicit terminal event without HTTP 200, and the
   host can offer a true fail-closed Router policy.
2. Ask CPA to expose authenticated downstream principal/key-policy ID, verified
   direct-peer address, loaded Router ordering, and active plugin binary
   inventory. Only then enable trusted-proxy subjects and in-process conflict/
   duplicate-version checks.
3. Implement the documented dual-key HMAC rotation state machine: one active
   and one previous read-only key, one-way fingerprints, bounded transition
   state, finite overlap, active-key-only writes, and explicit finalization.
4. Add an authenticated operator action for deliberately archiving/resetting a
   key-mismatched subject snapshot. It must not expose raw subjects or silently
   overwrite state.
5. Establish an independent blind-Holdout generation and review pipeline outside
   the rule-development loop. Each release should freeze new SHA-256 inputs,
   emit aggregate-only results, and prevent row-level access before the gate.
6. Extend role/provenance support with provider-versioned quotation and citation
   markers while preserving conservative unsupported-role and history-cap
   behavior.
7. Add signed, licensed external rule bundles only if they are restricted to a
   trusted plugin-data directory, permission checked, signature/hash verified,
   atomically activated, offline by default, and backed by the embedded rules.
   Never auto-download rules.
8. If a local model classifier is added, require explicit loopback/private
   endpoint allowlists, address pinning per connection, redirect rejection,
   bounded request/response sizes, rules-only fallback, and privacy canaries.
   Public endpoints must remain unsupported by default.
9. Add an authenticated management UI mechanism only after CPA offers a safe
   private resource route. CPA v7.2.72 public resource routes must never carry
   audit or subject data.
10. Preserve the achieved near-budget allocation gate (currently well below
    1,000,000 bytes/op). Consider streaming/byte-oriented normalization only if
    future rule or decoder growth regresses the measured gate, and never reduce
    scan, decode, history, or rule coverage to recover performance.
11. Add long-running nightly fuzz, soak, migration-fault, and memory-leak jobs,
    signed provenance/attestation, and reproducibility comparison across two
    independent Linux builders rather than two local clones only.
12. Qualify newer CPA releases and architectures one at a time with the full
    Mock Upstream/Auth Selector/Usage isolation suite. Do not infer compatibility
    from ABI numbers alone.
13. Add a privacy-safe cross-request control-plane state model that stores only
    bounded semantic flags and expiry, never prompt fragments. Alternatively,
    require and verify complete caller-supplied history for continuation cases.
14. Add launcher/deployment attestation for local instruction files: trusted
    owner, restrictive mode, allowlisted path, pinned hash, and visible drift
    status without exposing file contents.
15. Carry the existing `classifier-policy-v2` identity through build metadata,
    linker metadata, release manifests, artifact verification, reproducibility
    comparison, and Leo evidence. The source digest and authenticated status now
    exist; artifact-level provenance binding remains unfinished.
16. Consider additional strongly marked bounded decoders (for example selected
    Base32, hex, or quoted-printable forms) only with strict source/size/layer
    signals, adversarial resource tests, and benign multilingual contrasts. Do
    not add general-purpose decompression or arbitrary transform execution.
17. Add schema-aware handling for provider safety-control fields and suspicious
    key-only tool controls without treating every JSON property name as prompt
    text.
18. Extend the behavior graph with bounded pronoun/reference resolution and
    longer conversation linking without storing prompt fragments or turning
    generic variables into targets. Any extension needs positive/negative
    minimal pairs and resource caps.
19. Add a recoverable Host fixture seam for fused and pre-result-panic cases if
    CPA exposes one. Continue using official source-overlay tests meanwhile; do
    not substitute a process crash or `segfault` for a valid Host outcome.
20. Replace the visible 35-case development corpus with a newly authored,
    independently isolated evaluation only at verification time. The current
    development cases and derived wording are permanently ineligible for that
    holdout.
