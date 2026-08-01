# Historical Round 9 exact-candidate independent-audit design

> [!CAUTION]
> **HISTORICAL / NON-EXECUTABLE DESIGN.** The workflow files
> `.github/workflows/round9-host-validation.yml` and
> `.github/workflows/round9-release-rc.yml` were deleted from the executable
> workflow directory. This document and its command examples are preserved as a
> point-in-time contract, not a current Actions entry point or gate. Only
> `ci.yml`, `codeql.yml`, and `policy-gate.yml` are active; none performs this
> independent audit or grants publication or production approval.

This document describes a verifier, not an audit result. No independent-audit
evidence package is stored in this repository, and the current candidate remains
`NOT_PROVIDED / REQUIRES INDEPENDENT AUDIT`.

Commit `aaa71d9924bef935196790976c838968408dcdeb` is a confirmed green
engineering baseline, while the current feature branch still requires its own
PR checks. Engineering CI is not a Host PASS, independent-audit PASS, or
production PASS.

## Trust boundary

The independent auditor is separate from both the candidate-building workflow
and the protected CPA Host evaluator. The verifier accepts only:

- the exact 19 candidate publication assets;
- a canonical, Ed25519-signed privacy-bounded audit envelope;
- a canonical protected-ledger proof containing signed `reserved`, `started`,
  and `result` events;
- a separately pinned auditor public key and workflow/run identity; and
- read-only GitHub metadata for the candidate, auditor run/artifact, ledger
  ruleset, and annotated ledger tags.

It never accepts independent prompt text, response text, request bodies,
production data, a real Provider endpoint, or a corpus path. A release title,
Host evaluation `PASS`, or hand-written Boolean `PASS` is not audit evidence.
Unknown fields, missing fields, duplicate JSON keys, non-canonical JSON,
signature drift, key reuse, asset substitution, or ledger replay fail closed.

The evidence must keep
`restricted_material_zero_access_claim=false`. This prevents the development
session from converting its existing disclosure into a false zero-access claim.

## Exact schemas

The external package contains exactly two top-level regular files:

```text
round9-independent-audit.json
round9-independent-audit-ledger-proof.json
```

The trust-configured public key is not taken from that package. Active schema
identities are:

```text
signed envelope: round9-independent-audit-signed-envelope/v1
audit evidence:  round9-independent-audit-evidence/v1
ledger event:    round9-independent-audit-ledger-event/v1
ledger proof:    round9-independent-audit-ledger-proof/v1
```

The evidence envelope binds the repository, annotated tag object, exact commit
and tree, source/artifact versions, classifier and ruleset identities, canonical
release manifest, SO, build metadata, ruleset manifest, external evaluation,
external evaluation ledger, and every asset byte length and SHA-256. The asset
list is the exact sorted 19-name release allowlist. Seventeen entries bind the
Round 9 RC workflow provenance; the two external-evaluation entries bind the
protected Round 9 Host workflow provenance.

The signed audit identity binds an independent repository/workflow/ref/SHA,
run ID and attempt, key ID/fingerprint, and one-time challenge hash. It must
declare no production access and no real-Provider contact. The structured audit
decision requires complete source, artifact, supply-chain, external-evaluation,
and release-contract review records; title-only, Host-only, or Boolean-only
objects cannot satisfy the schema.

The one-shot ledger namespace is:

```text
refs/tags/round9-independent-audit-ledger/<candidate-commit>/<challenge-sha256>/reserved
refs/tags/round9-independent-audit-ledger/<candidate-commit>/<challenge-sha256>/started
refs/tags/round9-independent-audit-ledger/<candidate-commit>/<challenge-sha256>/result
```

Each reference must be an annotated tag on the exact candidate commit. Events
are Ed25519 signed, strictly ordered, timestamp ordered, and hash-chained. Only
the result event may contain the exact audit-envelope SHA-256. An `aborted`
reference is a hard failure. The active tag ruleset must cover the namespace,
have no bypass actors or exclusions, and contain both `deletion` and `update`
protection; `non_fast_forward` does not replace `update`.

## Verification commands

`validate` performs local schema, signature, manifest, 19-asset, provenance,
hash, and ledger-proof validation. `verify-remote` repeats those checks and also
binds remote `main`, the annotated candidate tag/tree, the independent auditor
workflow run and artifact, the protected ruleset, all three ledger tags, and
absence of an aborted event.

```bash
python3 -B scripts/round9_independent_audit_contract.py validate \
  --evidence /protected/input/round9-independent-audit.json \
  --proof /protected/input/round9-independent-audit-ledger-proof.json \
  --asset-dir /verified/round9-19-assets \
  --public-key /protected/trust/round9-independent-auditor.pem \
  ...exact candidate, signer, challenge, run, and ruleset identities...
```

Exit status `0` means the supplied package passed this mechanical contract.
Exit status `1` means supplied evidence was invalid. Exit status `3` means the
evidence package or trust anchor was not provided. The verifier does not create,
sign, repair, or infer evidence.

## Historical workflow integration state

When it existed, `.github/workflows/round9-release-rc.yml` ran the verifier tests
in both build contexts and wired the remote verifier behind protected
configuration. That workflow has been deleted, and none of the three active
workflows invokes this verifier. The repository also supplies no
independent-audit artifact or trust configuration. The historical admission
design emitted `publication_permitted=false`, had no `contents: write`, and had
no Release create/edit/upload/delete command. Preserving the verifier source and
this design record does not authorize publication or production Balanced mode.

The only valid current conclusion remains:

```text
BLOCKED / NOT PROVIDED / REQUIRES INDEPENDENT AUDIT
```
