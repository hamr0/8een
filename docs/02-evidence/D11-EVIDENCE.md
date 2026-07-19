# D11 — prebuilt verifier binaries: evidence log

**Date:** 2026-07-18 · **Status: SHIPPED (linux-x64)** · Decision: PRD §9 D11

**Riskiest assumption under test:** "A clean GitHub runner can build the
longfellow C++/cgo verifier at all, and the binary it produces runs on other
machines" (glibc/libstdc++ symbol coupling being the classic way a
built-elsewhere binary dies on arrival).

## What ran (reproducible)

Two runs of `.github/workflows/binaries.yml` on a clean `ubuntu-22.04` runner
(oldest supported image, deliberately: glibc/libstdc++ symbols are
forward-compatible only, so building old runs everywhere newer):

1. **Spike** — [run 29631231191](https://github.com/hamr0/8een/actions/runs/29631231191):
   clone upstream `d8ad8f65`, apply the tracked patch series (0001/0002/0003),
   build, prove, upload artifact.
2. **Publish** — [run 29631499141](https://github.com/hamr0/8een/actions/runs/29631499141):
   identical build, then the `release` job attached the binary + `SHA256SUMS` to
   the [`longfellow-bin-1`](https://github.com/hamr0/8een/releases/tag/longfellow-bin-1)
   release (`--latest=false`, so it never displaces a package release).

The workflow refuses to publish a binary the full integration suite has not
passed **on the runner**, and asserts the suite's skip count is zero — a
mispathed prerequisite would otherwise let the suite go green by skipping,
which is this project's signature failure shape.

## Results (observed, not asserted)

| What | Measured |
|---|---|
| C++ core build (cmake/clang, Release, `make install`) | 2 m 59 s |
| Go service build (cgo, links `libmdoc_static.a`) | 19 s |
| Integration suite on the runner, against the fresh binary | 4 m 25 s — **38/38, 0 skipped** |
| Whole job, dispatch to done | ~8.5 min |
| Binary | ELF x86-64, dynamically linked, 10,124,224 bytes |
| `ldd` | `libcrypto.so.3`, `libzstd.so.1`, `libstdc++.so.6`, `libgcc_s.so.1`, `libc.so.6`, `libm.so.6` — ubiquitous system libraries only (matches upstream's own runtime-image list: `libssl3 libzstd1 zlib1g`) |
| sha256, spike run | `756869602c84c116e9d94aa07b138a22373acd6f59b2b331e5bf7c0272175b00` |
| sha256, publish run (released asset) | `7568696…2175b00` — **byte-identical to the spike's.** Two independent clean-runner builds reproduced the same binary. Not a property we designed for or rely on (the manifest pins the released asset, whatever its bytes), but worth recording. |

Pinned into `src/binary.manifest.json`: that sha256 + 10,124,224 bytes, keyed
`linux-x64`, release `longfellow-bin-1`.

## The adopter path, exercised for real on this machine (Fedora 44)

1. `provisionBinary()` fetched the released asset into
   `~/.cache/zk8een/longfellow-verifier-linux-x64`, hash verified — so the
   Ubuntu-built binary runs on a different distro, as the `ldd` list predicted.
2. Fresh fixtures minted (`tools/mkfixture`, real clock), then
   `Verifier.start` **with `binary:` omitted** — the release-built binary
   resolved from the default dir, re-hashed against the pin, and:

   | fixture | verdict |
   |---|---|
   | valid | `ok:true over:true verified` |
   | underage | `ok:true over:false claim_false` |
   | tampered | `ok:true over:false zk_proof_invalid` |
   | untrusted-issuer | `ok:true over:false issuer_untrusted` |

3. Unit suite with the pinned manifest: **89/89, 0 skipped** — including the
   previously-red placeholder guards and the real-bytes accept-path tests
   (executable bit, idempotence, rot-detection), which run against the
   genuinely released bytes.
4. The same path is a permanent integration test
   (`D11: with binary omitted, …` in `test/integration.test.js`), skip-gated on
   a provisioned binary being present.

## Post-review corrections (2026-07-19)

A high-effort review's verifier agents all died on a spend limit, so its
"no findings" verdict proved nothing and its 18 finder candidates were checked
by hand instead. Six were real and are fixed here; each was **measured**, and
each fix has a regression test watched failing against the pre-fix code.

| Found | Measured evidence | Fix |
|---|---|---|
| **The proof gate did not gate.** Actions' default shell is `bash -e {0}` — no `pipefail` — so `npm run test:integration \| tee` exits with *tee's* status. A failing suite would have been released. | Reproduced under `bash -e`: a suite returning 1 with `# fail 7` gave step exit **0**. | `set -o pipefail` + asserted pass/fail/test counts. Re-probed against 4 scenarios: failing suite, mispathed prereqs, empty run, healthy — only the healthy one releases. |
| **The zero-skip assertion would fail every future dispatch**, because the new D11 test legitimately skips on a build runner (it needs a binary provisioned from the release). | Reproduced with an empty `XDG_CACHE_HOME`: skip count 1 → job fails. | Skips matched against that one specific reason instead of being tolerated by count, so a genuinely mispathed prerequisite still fails the run. |
| **`--clobber` could swap a published asset's bytes**, breaking `provisionBinary()` for every zk8een already on npm, which pins the old hash. | Read from the release job as written. | The job now refuses to overwrite a published tag whose pin ≠ built bytes; a real rebuild needs a new `longfellow-bin-N` and a manifest update in the same commit. |
| **The published `.d.ts` did not typecheck for adopters** — `import './circuits.manifest.json'` leaks into the public types, and no JSON is shipped to `types/`. **Present since 0.1.0; shipped in 0.4.1.** | `npm pack` → install into a consumer project → `tsc`: two `TS2307`s from inside `node_modules/zk8een`. | Both manifests declare their shape in JSDoc. Re-verified on a clean reinstall: **exit 0**. |
| **`startGate`'s type still required `binary`**, contradicting the README example and CHANGELOG claim written alongside it. | `tsc` on the documented call: `TS2345: Property 'binary' is missing`. | `startGate` JSDoc mirrors `Verifier.start`. Both documented examples now typecheck. |
| **A restrictive umask left the fetched binary non-executable** (hash-perfect, unspawnable), and an empty-string `binary:` bypassed resolution to reach `spawn('')`. | `umask 0111` → file lands `0644`; `'' ?? x` keeps `''`. | `chmod` after rename, an executability check in resolve, and a loud `TypeError` for empty/non-string `binary`. |

Also changed while in there: the cached binary filename now carries the release
tag (two zk8een versions pinning different releases would have shared one cache
file), and the workflow reads commit/patches/release from the manifest rather
than keeping second copies that can drift from what the package verifies.

## Deviations / notes

- `workflow_dispatch` cannot trigger a workflow that is not yet on `main`; the
  spike ran via a temporary `push:` trigger on the feature branch, removed
  before merge. Post-merge, dispatch is the only trigger.
- The binary ships `not stripped` (with debug info), matching upstream's own
  Dockerfile build. Stripping would shrink the download but would also mean
  shipping bytes other than the ones the integration suite passed — not worth
  it at 10 MB.
- Platforms beyond linux-x64 remain open work (D11 names them), as does a
  richer identity for future binary releases (bump `longfellow-bin-N` on any
  patch-series or upstream-commit change; the manifest pins exact bytes either
  way, so a stale package can never fetch a newer, unpinned binary).
