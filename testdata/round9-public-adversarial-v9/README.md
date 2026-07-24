# Round 9 public adversarial corpus v9

This is the active visible development-only public adversarial corpus. Its
manifest is 105,888 bytes / SHA-256
`dd22068b452cb4183405bfe7697d52a1b7dd272de25ebef0790add46a71c9c38`
under schema `round9-public-adversarial-corpus/v9`.

V9 repairs the corpus identity chain without changing a payload byte:

- the previously announced v8 remains exact at 105,299 bytes / SHA-256
  `5def53300bad07c65717ed8f8a32d2da49952528275df77ea55703713f9e330f`;
- v8 is immutable-invalid because its declared review digest `52b1e97c…`
  differs from the deterministic digest `6772278f…`;
- the 105,298-byte / `2f953da4…` corrected in-place v8 rebind remains in
  `../round9-public-adversarial-v8-rejected-rebind` as rejected evidence; and
- v9 binds the corrected review digest under a new dataset/schema and records
  the exact announced v8 identity in refresh history.

The live read-only GitHub refresh represented here found only an
architecture-documentation change in `MDX-Tom/gpt-5.6-instruct`: the default
head advanced from `d1face34885e3c24972d7b959e120e9acc546202` to
`a2476cd2ba6fac605348f06b621e5e1d7d4f74fe`. The seven changed or added blobs
were README image references, one Draw.io source, and four rendered WebP
images. No instruction or prompt-like payload blob changed.

Corpus accounting remains 24 payload records, 23 formal unique payloads, one
unmerged candidate-carrier execution, and 120 serialized context routes. The
12 reviewed defensive or dual-use direct-user texts remain `allow_or_audit`;
the 12 explicitly adversarial direct-user scenarios remain
`block_malicious_text`; every inert carrier context remains `allow_or_audit`.

These bytes are visible development regressions only. They are not a blind or
independent holdout, production approval, or population-level false-positive
or recall proof. No third-party repository code, installer, dependency, hook,
workflow, test, application, or binary was executed.
