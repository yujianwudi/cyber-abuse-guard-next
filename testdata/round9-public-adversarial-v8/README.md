# Round 9 public adversarial corpus v8 — immutable-invalid

This directory preserves the previously announced v8 manifest byte-for-byte:
105,299 bytes / SHA-256
`5def53300bad07c65717ed8f8a32d2da49952528275df77ea55703713f9e330f`.
The `review_sha256` line ends in CRLF; every other historical line ending is
unchanged.

V8 is immutable but invalid as current evidence. Its declared prompt-like
review digest is
`52b1e97c33f9c0221b0feb0cd069c176a663094badd8ef903c0624ed4f6cd48e`,
while deterministic recomputation over the frozen exclusion records yields
`6772278f4dc5779564b17403ae73c2a9f8350a9405ea5796f96538d5c357ce6b`.
The corrected digest therefore lives under the new v9 schema and dataset.

The accidentally corrected in-place v8 rebind is retained separately at
`../round9-public-adversarial-v8-rejected-rebind`; it is not an active corpus.
All encoded payload bytes are also preserved by active v9.

These files are visible development regression data only. They are not an
independent holdout, production approval, or population-level performance
claim. No third-party repository code, installer, dependency, hook, workflow,
test, application, or binary was executed.
