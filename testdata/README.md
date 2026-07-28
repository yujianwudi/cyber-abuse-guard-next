# Test-data inventory

This directory contains public, synthetic, or frozen historical regression
fixtures only. Restricted independent evaluation material is intentionally
absent from repository history.

| Category | Directories | Status |
|---|---|---|
| Core synthetic regression | `corpus/` | Active ordinary tests |
| Public jailbreak development | `development-public-jailbreak-patterns-v1/` | Active public development fixture |
| Round 9 benign and paired development | `round9-development-benign-v1/`, `round9-development-paired-malicious-v3/` | Current development evidence |
| Rejected authoring evidence | `round9-development-paired-malicious-rejected-v1/`, `round9-development-paired-malicious-v2/`, `round9-public-adversarial-v8-rejected-rebind/` | Retain byte-for-byte; never promote silently |
| Public adversarial history | `round9-public-adversarial-v1/` through `round9-public-adversarial-v13/` | v13 is current; older versions are frozen provenance |
| Compatibility and rollback | `round9-old-so-v0.16-rc.2-source/` | Frozen old-SO rollback fixture |
| Preparation snapshots | `development-adversarial-v11-prep/` | Historical development input, not release evidence |

The ignored `round9-independent-benign-v1/` and
`round9-independent-malicious-v1/` paths are external audit inputs. Plaintext
must never be staged, copied into another tracked directory, or used for normal
development tuning.

Do not deduplicate, rename, or reformat frozen directories merely because their
contents appear similar; manifests, hashes, and negative tests bind their exact
bytes and paths.
