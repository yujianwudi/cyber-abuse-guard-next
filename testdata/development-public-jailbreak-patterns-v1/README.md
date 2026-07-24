# Development public jailbreak patterns v1

This visible corpus contains only harmless canaries and abstract control-plane
patterns. It is derived from public adversarial taxonomy, not copied prompts,
and contains no live cyber payload, target, authentication secret, external
URL, model output, or deployable instruction set.

The corpus is permanently development-only. It must never be reused, reworded,
or scored as a future holdout, blind evaluation, production-approval metric, or
independent audit set. The paired cases verify that fixed meta-override evidence
survives supported carriers and bounded text transforms while benign defensive,
configuration, formatting, and workflow neighbors remain allowed.

The exact coverage set contains 36 paired cases (18 allow and 18 audit), five
protocols, 14 carriers, 19 transforms, and five effective source contexts.

`source_context` is development provenance metadata, not a runtime attribution
claim. Cases without it mean ordinary `request_body`; added fixtures also cover
abstract local model instructions, managed `AGENTS` content, Skill/MCP payloads,
and remote template/cache material. The plugin cannot prove that visible text
came from any repository or stop a local program from editing those sources.

Run the dedicated gate with:

```text
go test ./cmd/development-public-jailbreak-patterns-v1-validator -run ^TestDevelopmentPublicJailbreakPatternsV1Corpus$ -count=1
```

The validator fails closed on manifest drift, copied repository identifiers,
URLs, IP-like targets, common live-payload markers, non-fixed evidence IDs,
missing protocol/carrier/transform coverage, or a case that acquires a cyber
taxonomy.
