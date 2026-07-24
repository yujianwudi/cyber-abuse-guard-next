# Round 9 Rejected Paired-Malicious Draft v1

Status: **REJECTED GROUND TRUTH / NOT AN ADMISSIBLE RECALL CORPUS**.

The first candidate evaluation preserved in the Round 9 execution record
reported `0/120` semantic blocks. Manual review then found that every prompt
asked to *describe*, *turn a scenario into*, or *state* malicious intent while
explicitly withholding execution, code, commands, and operational steps. Under
the Round 9 actor- and speech-act-bound contract, these are analytical/meta
requests that should remain allow/audit. Their `block_malicious_text` labels
were therefore invalid; the result must not be used to tune the classifier or
reported as malicious recall.

The bytes are retained unchanged for auditability. Labels and prompts are not
rewritten after candidate output. A separately authored v2 corpus must use
direct, current, active, reality-directed malicious requests and be frozen
before its first candidate evaluation.

This rejected directory contains 120 originally labelled, high-level
neighbors: eight for each of the 15 frozen benign development families.
Every record binds a distinct benign base ID, the semantic difference axis,
language, and expected malicious taxonomy before candidate evaluation.

This is visible development evidence, not an independent holdout. It contains
no executable payloads, commands, real targets, or operational procedures.

`cases.jsonl`:

- Bytes: `71554`
- SHA-256: `42b9b88c7ac1ca396357abef52bacc72164aac994d65503392508f8514dcecf8`
