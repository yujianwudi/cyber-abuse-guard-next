# Synthetic CSAM text regression contract

This directory contains metadata only. It is a development regression
contract, not an evaluation or training corpus. The synthetic placeholder
strings are kept in a Go test source file solely for transient execution;
`fixture_text_retained` means no fixture text is copied into this corpus
directory or into generated evidence.

- No request text, media, URLs, Base64, reversible encodings, or real-person
  data are stored here.
- The executable synthetic placeholders live only in the Go test source and
  are never persisted by the runtime. The manifest binds that source by
  SHA-256 and records only case IDs, labels, intents, and expected actions.
- No third-party repository code is downloaded or executed by this test.
- Additions must remain non-explicit, synthetic, and paired with protective
  benign and ambiguous-review cases. Runtime vocabulary changes require a
  separate policy review and identity update.

Run the contract with:

```text
go test ./internal/csamtext -count=1
```
