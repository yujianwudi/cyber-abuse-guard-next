# Classifier redesign baseline

Status: development baseline and redesign contract
Ruleset at this branch: `1.0.7`
Classifier policy: `classifier-policy-v2` / `dc9a174099cb2f621e5333a508d4645604f96f470a6d9ae12a1acfb363d29cf2`
Date: 2026-07-14

## Isolation statement

This report was produced from public repository source, public development
fixtures, and the frozen aggregate report in
`docs/reports/EVALUATION_V10_REPORT.md`. No file below
`testdata/evaluation-v10/` was opened, printed, parsed, extracted, classified,
or obtained through Git history, test output, a helper program, or debug logs.
The consumed evaluation was not rerun.

The default v10 unit-test path now enforces that boundary: it checks only frozen
aggregate constants, aggregate-report markers, and consumed-rerun rejection. It
does not open the consumed corpus or ask Git to read its historical blob.

## Production call graph

```text
rules/*.yaml (embedded, strict schema and version validation)
    -> rules.LoadDefault / rules.LoadFS
    -> classifier.New
       -> literal matcher compilation
       -> context signals
       -> category semantic profiles
       -> meta-wrapper families

CPA model.route request
    -> plugin.router
       -> extract.ExtractText (known provider)
          -> bounded JSON walk
          -> bounded URL / HTML entity / Base64 / nested-JSON decoding
          -> OpenAI Chat / Responses, Anthropic, Gemini role provenance
       -> extract.ExtractUntrustedText when provider role proof is absent
       -> classifier.ClassifySegmentsWithPolicy (role-aware)
          OR classifier.ClassifyUntrustedPartsWithPolicy (conservative fallback)
          -> classifier.classifyWithPolicy
             -> NFKC, case, zero-width, limited homoglyph/leet normalization
             -> standard and compact literal matchers
             -> rule-local intent + object candidate
             -> qualifier and category-level composition
             -> bounded semantic-window relation model
             -> authorization / defensive context deductions
             -> wrapper assessment (amplifier only)
             -> candidate ordering and action thresholds
             -> privacy-safe BehaviorGraph and policy identity
       -> truncation / opaque-media / subject-control policy
       -> allow, observe, audit, or block
```

Role-aware classification does not flatten trusted and untrusted text into one
bag. Clear system safety policies and assistant refusals are not attributed as
user intent. User-to-user follow-ups may be joined inside bounded windows;
provider-native tool payloads are independently scanned; unknown roles use a
conservative fallback. The classifier remains stateless and retains no prompt
text after the call.

## How score, category, and action are formed

### Rule-local candidates

Each rule requires an intent/object core. The rule contributes its configured
base score, then independent evidence may add:

| Dimension | Points |
|---|---:|
| Operationalization | 20 |
| Real target | 18 |
| Evasion | 16 |
| Scale | 16 |
| At least two qualifiers | 5 |

A core split across unrelated parts receives a penalty. Narrow credential
fallbacks require an object plus multiple independent operational/target/evasion
signals. Hard floors apply only under their documented category and context
conditions; global thresholds were not lowered.

### Category composition and semantic relations

Related rules in the same taxonomy may contribute complementary evidence only
inside one current directive clause. Category-level semantic profiles require
an object, agency (harm/action/outcome), and at least two additional risk axes
inside a bounded related window. The semantic path starts at 27 and adds fixed
dimension weights; at least four independently owned dimensions are required.

The privacy-safe `BehaviorGraph` records stable booleans and relations for:
requester, action, object, target, destination, technique,
delivery/execution, credential/access, persistence, evasion, exfiltration,
impact, scale, authorization/defensive scope, wrapper/amplifier, role scope,
carrier, composition mode, and reason codes. It contains no matched spans or raw
request fragments.

### Wrapper and amplifier boundary

`META-OVERRIDE-001` now represents wrapper/control-plane evidence only:

- wrapper-only text never creates a Cyber Abuse category;
- a strong wrapper-only combination is capped at the configured audit boundary
  and returns audit/observe rather than block, including strict classifier mode;
- a single weak hierarchy phrase attached to a harmless task remains allow;
- quoted wrapper material under explicit defensive analysis remains allow;
- when an independently established dangerous behavior exists, wrapper evidence
  may raise that candidate's score and is recorded as an amplifier without
  replacing its taxonomy.

This directly separates `WrapperEvidence` and `AmplifierEvidence` from the base
behavior, intent, operationalization, target, impact, evasion, scale,
authorization, remediation, defensive, role, conversation, and carrier axes.

### Winner and action

The highest-scoring candidate wins. Ties use the stable category order
`credential_theft`, `phishing_deployment`, `malware_deployment`,
`ransomware_deployment`, `unauthorized_exploitation`, `service_disruption`,
`data_exfiltration`, then `defense_evasion`, followed by stable rule IDs.

Default thresholds remain:

| Threshold | Score |
|---|---:|
| Audit | 35 |
| Balanced block | 60 |
| Hard block | 80 |

Ordinary candidates use the existing mode matrix: observe records above audit;
audit mode audits; balanced audits at 35 and blocks at 60; strict blocks at 35;
the hard ceiling blocks ordinary dangerous behavior in all enabled enforcing
paths. Wrapper-only control signals use a separate non-blocking audit action and
cannot independently reach the balanced or hard threshold.

## Public aggregate baseline

The consumed aggregate report records a valid first-and-only run with:

| Aggregate | Result |
|---|---:|
| Benign false positives | 28 / 320 (8.75%) |
| Policy blocked | 49 / 320 (15.31%) |
| Policy exact taxonomy | 33 / 320 (10.31%) |
| Role-aware policy blocked | 38 / 260 |
| Untrusted policy blocked | 11 / 60 |

Aggregate taxonomy results were:

| Taxonomy | Blocked | Exact |
|---|---:|---:|
| `credential_theft` | 8 / 40 | 8 / 40 |
| `phishing_deployment` | 0 / 40 | 0 / 40 |
| `malware_deployment` | 16 / 40 | 0 / 40 |
| `ransomware_deployment` | 24 / 40 | 24 / 40 |
| `unauthorized_exploitation` | 0 / 40 | 0 / 40 |
| `service_disruption` | 0 / 40 | 0 / 40 |
| `data_exfiltration` | 0 / 40 | 0 / 40 |
| `defense_evasion` | 1 / 40 | 1 / 40 |

These are frozen aggregate facts, not row-level tuning data.

## Systematic false-positive boundary visible from public source

The following were confirmable from public implementation behavior and public
development tests; they do not assert knowledge of any consumed row:

- Meta-wrapper families previously could independently synthesize a
  `defense_evasion` candidate. This was a direct taxonomy false-positive source
  for wrapper-only, policy quotation, and harmless-task combinations.
- Broad rule cores can still produce an allow/audit candidate when a sentence
  quotes dangerous language. Negation, legitimate-workflow recognition, role
  provenance, and context deductions are therefore essential and remain a
  continuing regression surface.
- Generic operational words such as code, script, plan, deploy, and tool are
  useful only when bound to a dangerous object/action relation; treating them
  as independent harm would overblock ordinary engineering work.
- Flattening system policies, assistant refusals, tool output, and user intent
  would contaminate later harmless requests. The role-aware path prevents that,
  while unknown-format fallback remains intentionally conservative.
- Authorization, lab, CTF, incident response, remediation, static analysis, and
  high-level discussion are not blanket allow labels. Contradictory real-target
  or harmful operational relations must override laundering, while genuinely
  bounded safety work must retain deductions.
- Protected categories intentionally resist bare authorization claims. That
  safety choice raises the importance of accurate defensive/remediation scope
  and is a known false-positive boundary for loosely phrased legitimate work.

## Systematic false-negative boundary visible from public source and aggregates

- Literal intent/object cores miss paraphrases when action, object, target,
  delivery, destination, and impact are expressed through unfamiliar wording.
- Requiring one rule-local core can miss vocabulary split across related rules;
  same-category and semantic-window composition reduce, but do not eliminate,
  that seam.
- Bounded conversation composition handles adjacent and explicitly linked user
  turns. Longer-distance references, ambiguous pronouns, renamed variables, and
  cross-message bindings remain necessarily conservative.
- Placeholders such as `<target>`, `${host}`, or `VICTIM_IP` are meaningful only
  when earlier text binds them to a victim/asset. Generic template variables
  cannot safely be treated as targets by themselves.
- Bounded URL, HTML entity, Base64, JSON Unicode, nested tool JSON, split text,
  and limited homoglyph recovery improve carrier coverage, but resource limits
  deliberately leave arbitrarily deep encoding, archives, scripts, remote
  fetches, and unbounded transformations unsupported.
- The aggregate zero/near-zero results for phishing, unauthorized exploitation,
  disruption, exfiltration, and evasion demonstrate a broad generalization gap,
  but without row access they do not identify which wording or carrier caused
  each miss. Fixes must therefore be mechanism-based and verified on new data.
- The malware blocked/exact mismatch shows that detection and exact taxonomy are
  separate problems. Winner ordering and cross-category evidence ownership need
  dedicated tests even when a request is blocked.

## Development adversarial corpus

`testdata/development-adversarial-v11-prep/` contains 35 visible development
cases: 16 block, 14 allow, 2 audit, and 3 resource-boundary fixtures. It covers
all eight taxonomies with at least two blocked cases each, OpenAI Chat,
OpenAI Responses, Anthropic Messages, Gemini, English, Chinese, mixed language,
role-aware and conservative extraction, wrapper-only and wrapper-plus-behavior,
minimal positive/negative pairs, policies/refusals, defensive/remediation/
static/CTF/lab/authorized/incident/legal/news contexts, multi-turn continuation,
tool payload/output, URL percent, HTML entity, Base64, JSON Unicode, nested tool
JSON, placeholders, max parts, near scan budget, and truncation.

The validator checks strict schema, fixed taxonomy enum, unique IDs, exact and
near duplicates (allowing only explicitly marked opposite-label minimal pairs),
decision balance, coverage, production extraction, expected recovered semantics,
role/truncation behavior, and classifier action/category. The manifest and every
record carry the development dataset identity. The manifest permanently marks
the corpus `development_only=true` and `future_holdout_eligible=false`.

This corpus must never be used as a future holdout or formal v11 evaluation.

## Policy identity and privacy

`classifier.CurrentPolicyIdentity()` exposes a stable version and SHA-256 in
every `classifier.Result`. The digest test binds the deterministic classifier,
matcher, normalization, role logic, wrapper assessment, behavior graph,
semantic composition, bounded extractor, rule loader/schema, and embedded YAML
policy source list, plus `go.mod` and `go.sum` dependency locks. The declaration
file containing the digest constant is excluded to avoid a self-referential
hash; the tested source-list file is itself inside the digest.

The identity, behavior graph, evidence IDs, category, action, score, and reason
codes are safe metadata. No management or audit output needs raw text, decoded
payloads, match spans, victim identifiers, URLs, credentials, or tool arguments.

## What only a future blind evaluation can establish

A new independently authored, isolated, never-before-seen holdout is required to
measure:

- actual post-redesign benign false-positive rate;
- actual overall blocked and exact-taxonomy rates;
- whether the historically weak taxonomies generalize beyond visible wording;
- unseen carrier, language, paraphrase, placeholder, multi-turn, and role mixes;
- whether new relation composition introduces cross-category regressions;
- performance under realistic long inputs without revealing or tuning to rows.

No claim that these aggregate quality gates are now met is made by this report
or by the visible development corpus.
