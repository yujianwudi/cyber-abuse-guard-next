# Third-Party Notices

## Direct build dependencies

- CLIProxyAPI SDK v7.2.137 — MIT license. Active pin:
  `85d2faddd17e6f4f8675a84ee28b131f702e8eaa`, module sum
  `h1:CYYByMn7/NwnsCJEMiLI2F8kIJMTb5jRrLaIK6H0c0w=`, go.mod sum
  `h1:lTHwMAGajc1wKGQiRtDvYbwV0FWsM7sy+N0ZU5/gxJQ=`.
- `github.com/mattn/go-sqlite3` — MIT license.
- `golang.org/x/sys` — BSD-3-Clause license.
- `golang.org/x/text` — BSD-3-Clause license.
- `gopkg.in/yaml.v3` — MIT and Apache-2.0 notices in the upstream project.

Release automation must retain dependency license information and re-run
`go-licenses` or an equivalent review before publishing a public binary.
The embedded default rule terms are original project data and do not import a
third-party signature/rule library.

This dependency identity is the Round 14 C ABI 1 / RPC schema 3 target. Round
13 v7.2.125/schema 2 notices and PASS evidence remain historical and do not
transfer. CPA v7.2.137 `/v1/realtime*` bypasses CAG `RequestInterceptor`,
`ModelRouter`, and request lifecycle and is **OUT_OF_SCOPE / UNPROTECTED**;
only registered callback paths such as chat and Responses are covered.

## Public adversarial development corpus

The development-only corpus under `testdata/round9-public-adversarial-v*`
contains exact, Base64-encoded text bytes copied from the following public
MIT-licensed repositories. The manifests bind every retained copy to its source
repository, commit, path, Git blob and SHA-256. These files are inert regression
data; no third-party installer, hook, script, binary or dependency is executed.

The active attribution/provenance index is
`testdata/round9-public-adversarial-v13/manifest.json`; older versioned manifest
paths remain immutable records for their own retained bytes. Each payload entry
lists every applicable `repository`, `commit`, `path`, Git blob and decoded
content digest rather than relying on an unversioned branch URL.

- `Jia-Ethan/codex-keysmith` — Copyright (c) 2026 Jia-Ethan.
- `yynxxxxx/Codex-X` — Copyright (c) 2026 yynxxxxx.
- `yynxxxxx/Codex-5.5-codex-instruct-5.5` — Copyright (c) 2026 li lingbo;
  Copyright (c) 2026 yynxxxxx.
- `MDX-Tom/gpt-5.6-instruct` — Copyright (c) 2026 li lingbo;
  Copyright (c) 2026 yynxxxxx.

The following `LICENSE` blobs were re-read through the GitHub Contents API on
2026-08-04 at every source commit referenced by the active v13 payload set:

| Repository | Referenced source commits | `LICENSE` Git blob |
|---|---|---|
| `Jia-Ethan/codex-keysmith` | `0a4fc661`, `700f1be2`, `d8335f99` | `2af4ac3ae3f7c585bcc08f96abdbff0df8032ce3` |
| `yynxxxxx/Codex-X` | `5b665575`, `752078b2`, `e8b0e5b7` | `88d7ae0b141454b4a7c708fd0b04c6003d643258` |
| `yynxxxxx/Codex-5.5-codex-instruct-5.5` | `3b64052a`, `ed0b6dc3` | `4a139c06388bd870b72dad9088ae549f20d9e116` |
| `MDX-Tom/gpt-5.6-instruct` | `0755da37`, `18fea37f`, `61feb6a1`, `bcda62e3` | `4a139c06388bd870b72dad9088ae549f20d9e116` |

The current-CPA external diagnostic may fetch additional allowlisted public
text transiently. If a source has no explicit redistribution license, its exact
text must not be committed or packaged: checked-in regressions use source
hashes, metadata and repository-neutral synthetic fixtures instead.
`lingbol088-spec/5.6-JAILBREAK-NERV-codex-instruct-5.6` returned no detected
license and no `LICENSE` API object on 2026-08-04, so its exact text is excluded
from the source tree and durable evidence.

### MIT License text for the corpus sources above

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
