# Round 9 malicious-text producer inventory

The machine-readable inventory is
[`reports/ROUND9_MALICIOUS_TEXT_PRODUCER_INVENTORY.json`](reports/ROUND9_MALICIOUS_TEXT_PRODUCER_INVENTORY.json).
It is a tracked, closed-schema static source contract for task-book item 13.19.

The contract parses every production Go source below `cmd/` and `internal/`
without reading corpus data. It inventories direct `ActionBlock` and
`decisionBlockMaliciousText` producers plus every call to the two functions
that can return a classifier block, `actionFor` and `candidateActionFor`.
Locations are bound by package-relative path, enclosing function, AST
occurrence order, canonical AST SHA-256, and reviewed gate relationship; source
line numbers are deliberately not part of the identity. Package-level
initializers and their function literals are scanned under a synthetic
`<package-init>` identity; the reviewed tree has no such producer, so any future
one fails closed as unregistered.

The current closure has four layers:

1. `actionFor` is the raw threshold-to-action source. Every caller is closed in
   the inventory.
2. Candidate-bearing classifier paths call `candidateActionFor`, whose only
   delegation to `actionFor` is structurally dominated by
   `eligibility.Eligible`. The two direct zero-score calls produce no malicious
   winner and remain subject to the plugin proof gate.
3. `inspectionDisposition` converts a classifier block into
   `block_malicious_text` only after `eligibleMaliciousWinner` validates
   `CandidateBlockEligibility`, candidate identity, occurrences, explanation,
   category, and winning-rule parity. Incomplete, opaque-media, and subject
   blocks retain separate decision kinds.
4. The management test response can project a typed transport block back to
   `ActionBlock`; it does not create a malicious-text decision and inherits the
   already-computed `inspectionDecision` kind.

The Go contract fails closed when a new producer or block-capable caller is not
registered, a registered AST identity drifts, a gate function drifts, or the
`CandidateBlockEligibility` branch is bypassed. Its negative fixtures exercise
all three failure classes.

This is static closure evidence for the reviewed source tree. It is not runtime
audit evidence, independent review, exact-candidate Host evidence, or proof
that a deployed binary executed the inventoried path. It must be rerun and
bound to the final candidate commit and tree.
