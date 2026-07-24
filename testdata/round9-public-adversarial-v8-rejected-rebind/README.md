# Round 9 public adversarial v8 corrected rebind — rejected

This directory retains the superseded in-place v8 rebind as explicit recovery
evidence. Its manifest is exactly 105,298 bytes / SHA-256
`2f953da42d3bb485b08562e4011f20fdeae6ebe76be02da31c27bb3b151e727d`
and declares the deterministically correct review digest
`6772278f4dc5779564b17403ae73c2a9f8350a9405ea5796f96538d5c357ce6b`.

The content correction was valid, but rebinding already announced v8 bytes in
place violated the immutable corpus identity contract. This snapshot is
therefore rejected and must never be selected as the active corpus. The exact
announced v8 identity is retained in `../round9-public-adversarial-v8`; the
corrected content is active only as v9.

All encoded payload files remain inert public-text fixtures. No third-party
repository code was executed. This snapshot is neither independent evidence
nor release approval.
