# Script inventory

The script directory contains reviewed automation and contract tests. A file's
age or round number does not by itself make it disposable.

| Group | Role | Maintenance rule |
|---|---|---|
| General scripts | Build, compatibility, privacy, operational security, packaging, and repository checks | Active when referenced by `Makefile`, CI, or another reviewed script |
| `round6-*` / `round6_*` | Safe Gate, reproducibility, and release-document contract foundation | Retained because current CI still executes or imports these contracts |
| `round8-*` / `round8_*` | Frozen historical Host and evidence validators | Historical regression evidence; do not rewrite as current CPA proof |
| `round9-*` / `round9_*` | Current policy, public-corpus, request-local, rollback, and evaluator contracts | Active engineering checks unless explicitly described as an archived workflow validator |
| `release-*` | Packaging and historical release-contract validators | Source-only audit machinery; no executable GitHub publication workflow remains |

Use `Makefile` targets instead of invoking an arbitrary script chain. The Safe
Gate intentionally rejects unreviewed command paths and restricted-data access.
Independent, private, blind, consumed, retired, evaluation, and Holdout inputs
must remain outside ordinary development and repository history.

Generated `__pycache__` directories are disposable and ignored. Do not use a
blanket `git clean` command because the checkout may contain user-owned local
tests or ignored security state.
