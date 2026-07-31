# Archived workflow evidence

Files in this directory are historical records, not active GitHub Actions
entry points. GitHub executes workflows only from `.github/workflows/`, so the
YAML stored here cannot be dispatched or triggered.

`release-rc-v0.15-rc.2.yml` is the exact retired workflow definition retained
from the failed publication attempts associated with the Linux amd64
`v0.15-rc.2` sandbox prerelease. Its recorded runs failed and did not produce
the public Release; that RC was published separately through the disclosed
direct owner override. The embedded reference to
`.github/workflows/release-rc.yml` records the path used by those historical
runs and is intentionally unchanged. Do not copy that RC2 definition back into
the executable workflow directory or treat it as authorization for a new RC
publication. There is no active RC publication workflow now: the executable
workflow directory contains only CI, CodeQL, and policy/corpus validation. The
archived RC2 record remains immutable historical evidence.

Historical release policy is documented in
[the release policy](../../RELEASE_POLICY.md). The complete current executable
workflow inventory is maintained in
[the active workflow README](../../../.github/workflows/README.md).
