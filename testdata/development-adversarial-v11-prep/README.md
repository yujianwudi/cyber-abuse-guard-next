# Development adversarial v11 preparation corpus

This corpus is deliberately **development-only**. It is visible to implementers,
may be used for local tuning and regression tests, and must never be reused or
presented as an independent future holdout, blind evaluation, or formal v11
score.

All cases were constructed from public classifier mechanisms and the documented
taxonomy. They do not copy any consumed blind-evaluation text. The validator
uses the production extractor and classifier, checks schema/taxonomy/identity,
duplicate and near-duplicate handling, balanced decisions, protocol/language/
carrier coverage, bounded extraction, and the permanent holdout prohibition.

Run only this development validator with:

```text
go test ./cmd/development-adversarial-v11-prep-validator -run ^TestDevelopmentAdversarialV11PrepCorpus$ -count=1
```

Schema v2 uses the fixed production source profile for every protocol. Under
the Round 9 ownership contract, assistant-emitted tool calls and function-call
arguments are inert unless a current trusted user explicitly reactivates a
unique referent. Those dangerous carrier fixtures therefore expect `audit`,
while the corresponding current-user requests remain blocking regressions.

The fixture is not a release metric. A future independent quality claim requires
a newly authored and isolated blind set that has never been visible during
development.
