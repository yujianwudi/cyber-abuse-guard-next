# CPA v7.2.95 integration report

```text
current_classifier_policy_version: classifier-policy-v9
current_classifier_policy_sha256: fb7cbb7b162b6ada7e4a2aeea2b7da2d54522e2399f2a28518da233e461a225c
```

## Active compatibility target

Cyber Abuse Guard pins the current Round 9 compatibility lane to one exact
identity of `github.com/router-for-me/CLIProxyAPI/v7`:

- target: `v7.2.95` at `f71ec0eb6776854457892452cf28c47f0d658251`.

The checked-in module layout is:

- root `go.mod`: v7.2.95 primary;
- `integration/cpalatestcontract/go.mod`: v7.2.95;
- `integration/pluginstorecontract/go.mod`: v7.2.95 Store reference.

The reviewed module identities are:

```text
primary_module_sum: h1:QHQuGuPwOOTdyk5G7s0gjirdQtCM7NtxHRGS1I2xNtA=
primary_go_mod_sum: h1:he/Nx8K5RKvpcnedn0dmR8vVgHmetQ3/wutuPibWuRM=
```

`CPA_COMPAT_PROFILE=primary` is the only accepted profile and is the release
default. Old observations remain historical and are not current Host evidence.

## Active validation commands

Only the following CPA validation paths are supported:

```bash
make cpa-host-fixture-contract
CPA_COMPAT_PROFILE=primary CPA_COMPAT_VERIFY_REMOTE=1 make cpa-latest-compat
make cpa-host-blackbox
make cpa-router-fixture-blackbox
make round6-cpa-store-contract
```

With `CPA_COMPAT_VERIFY_REMOTE=1`, the compatibility contract verifies the
fixed Git tag-to-commit identity directly against the official Git origin and
binds the Go module Origin plus both checksums. All checked-in modules use the
same v7.2.95 identity. No repository token is used. The target is intentionally
pinned, so a later upstream Release does not silently change the supported
source or Host target. Upstream-latest monitoring is separate and explicit:
`CPA_COMPAT_REQUIRE_LATEST=1` additionally queries the official unauthenticated
GitHub `releases/latest` endpoint and fails when the fixed target is no longer
latest; that monitoring result does not invalidate compatibility with the
reviewed v7.2.95 pin.
`ALLOW_DIRTY_BUILD=1` is a development-only override and is not release
evidence.

The current Linux development run used Go 1.26.4 and
`CPA_COMPAT_VERIFY_REMOTE=1`. It verified the exact v7.2.95 tag commit, the
official module Origin, and the pinned module/go.mod sums before completing the
primary source/compile matrix. The upstream delta from
the preceding pin to v7.2.95 did not change
`sdk/pluginabi` or `sdk/pluginapi`, and the Guard required no API adaptation.
The primary module's
transitive dependency graph did move `github.com/tiktoken-go/tokenizer` from
v0.7.0 to v0.8.1 and `github.com/dlclark/regexp2` v1 to
`github.com/dlclark/regexp2/v2` v2.5.1; the checked-in root module files reflect
that reviewed upstream change. These results remain development self-checks,
not exact-main or Host evidence.

The pinned compatibility rerun is retained as
`dist/round9-worklogs/cpa-v7.2.95-pinned-compat-go1.26.4-20260724.log`
(59657 bytes, SHA-256
`748eb1ecdaa79c2b2ccfd07c5b55be3bf9a56ab8ecd1e19b152d12bc43ed8eae`).
The separate `CPA_COMPAT_REQUIRE_LATEST=1` monitoring probe observed the
official latest Release as v7.2.97 and therefore failed as designed. That
result does not invalidate the user-selected v7.2.95 compatibility pin.

## Coverage

The current single-primary-profile matrix covers:

- Guard compilation, registration, and routing contracts;
- official Host Router ordering, fallback, panic/fuse, target-readiness, and
  metadata-sanitization contracts;
- checksum-pinned fail-open overlays applied only to an ephemeral CPA source
  copy;
- Interactions route, handler, translator, auth-selection, and direct-executor
  format contracts;
- Raw Capture management-response transport and HTML-sanitization contracts on
  the pinned CPA v7.2.95 source;
- official v7.2.95 Responses continuation selectors for
  `previous_response_id`, Gemini interactions function calls and response-name
  backfill, and Gemini-to-OpenAI FIFO/fallback/explicit-ID translation paths;
- CPA Store archive naming, root layout, checksum, installation, repeat-install,
  overwrite, and published-artifact identity;
- an available native Linux integration target for plugin load and pre-upstream
  blocking; this target was not executed by the cited main/tag CI runs;
- an available second pure-C Router/executor fixture for priority, tie-break,
  fallback, and target-readiness scenarios; it is not claimed as executed by
  the cited main/tag CI runs.

The shared test fixtures under `integration/pluginstorecontract/testfixtures/`
remain the current v7.2.95 contract inputs and must not be treated as
unsupported legacy fixtures.

For the 2026-07-26 working tree, the nested `integration/cpalatestcontract`
module compiled with Linux Go 1.26.4 using `go test . -run a^ -count=1` after
the official selector additions. A later remote-verification attempt genuinely
refreshed and validated the module `Origin`; no Origin was fabricated. The
complete compatibility gate was still not credited because subsequent pinned
dependency downloads and official GitHub connections timed out before the full
source/compile matrix completed. A network-backed
`CPA_COMPAT_VERIFY_REMOTE=1 make cpa-latest-compat` rerun therefore remains
required for the final working tree.

## Historical pre-cleanup baseline (not the current RC target)

The merged Round 6 source is:

```text
main_commit: 6782dfaffd4da3f09604113c7d38675f331dc759
source_tree: a8edbe2e6d19fa725fb962cdd6aaad5b416d4b85
public_source_only_prerelease_tag: v0.15-rc.1
attached_release_assets: none
private_untagged_clean_candidate: not created
formal_tag_v0.15: absent / blocked
historical_classifier_policy_version: classifier-policy-v3
historical_classifier_policy_sha256: 1294c6fd587522829d07220d5a6f4214092eba6ce1837636da5b3e3d461ba2a3
```

GitHub Actions validation for that exact commit passed:

- main push CI `29630844605`;
- tag push CI `29630926354`.

Both runs passed the quality/artifact job, long fuzz job, and clean-clone
reproducibility job. The matrix included v7.2.86 latest-source compatibility,
Host source/fail-open contracts, Round 4/5/6 regressions, unit and race tests,
vet, fuzz, benchmarks, vulnerability checks, Linux build, artifact hashing,
Store validation, integration compilation, and clean-tree verification. It did
not run the native Host black-box or pure-C Router fixture targets.

These commit, asset, and older CPA statements are retained only as historical
baseline evidence. The current contract is fixed to CPA v7.2.95; exact
tag/commit/tree, current CI, 17 asset hashes, and RC-versioned integration
results are recorded at runtime in `rc-release-evidence.md` and
`rc-release-manifest.json` rather than self-recorded in this source file.
The immutable RC3 attempt (run 29728286559) failed before packaging and produced
no Actions artifact or GitHub Release; it is not reused as RC4 evidence.

## Evidence boundary

Source contracts, fixture contracts, and CI build/artifact plus
integration-compile PASS do not replace the owner-operated isolated server
sandbox. No local validation in this report is a claim that a production CPA
process, real Provider, account pool, or production traffic was used.

The remaining server evidence must load the exact Linux artifact in CPA v7.2.95
with a counted Mock upstream and prove zero deltas for locally
blocked requests at Auth Selector, Provider execution, usage accounting, and
Mock-upstream request layers.

The v0.16-rc.2 manifest schema 4 records both source identities and the explicit
release phase. Phase 1 packages a private 17-asset Host-test candidate with both
counted-Mock states still `NOT_RUN / HOST_TEST_REQUIRED`. Phase 2 accepts only a
closed-schema `round8-host-evidence.json` bound to the same reproduced candidate
SO hash, records counted-Mock `PASS` for each CPA identity, and packages the
evidence plus sidecar in the exact 19-asset prerelease. This evidence must also
carry per-lane Chat/Responses 1/0 upstream deltas, 42/42 benign and paired
malicious matrices, stream/nonstream and audit/balanced/strict coverage,
quick-check/WAL and restart-cycle facts, plus zero unexpected restart/OOM/error
counters. The same closed object covers Balanced-incomplete allow,
Strict-incomplete block, usage-queue allow/blocked deltas, and Raw Capture
only-blocked, TTL dedup, schema-v3 redaction metadata, and purge/WAL checks. A
bare `PASS` is rejected. It must also state that no real Provider was contacted
and production was not accessed.

The supported platform for this release line is Linux amd64. Windows, macOS,
and musl/Alpine validation are outside scope. Source/compile PASS is not real
Host evidence; independent audit is still required, production approval has not
been granted, and no stable v0.16 exists.
