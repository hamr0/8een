# 8een

**The verifier the EU didn't ship.**

A small, stateless, open component that checks a zero-knowledge age proof and
answers exactly one bit — `over_threshold: true/false` — while learning
nothing else about the person. No name, no birthdate, no document, no
identifier crosses the boundary. Proofs are fresh per presentation and
mathematically unlinkable: two sites comparing notes see two strangers.

The cryptography is never ours: proofs are generated and verified by
[google/longfellow-zk](https://github.com/google/longfellow-zk) (Apache-2.0,
IETF [draft-google-cfrg-libzk](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)) —
the same scheme the EU age-verification blueprint designates and the EU app's
demo build already uses. 8een is the missing verifier half: the wrapper, the
trust-anchor handling, the tests, the drop-in gate, and the documentation
that make it adoptable.

## Why

eIDAS 2.0 Art. 5a(16) mandates unlinkability as an outcome. The EU
age-verification blueprint concedes zero-knowledge proofs are the mechanism —
then marks them optional, ships them only in a demo build, and fields a
verifier stack that cannot consume them. The production fallback (batches of
30 single-use credentials) is rate-limited linkability, not unlinkability.

8een exists to make the unlinkable version so cheap to adopt that shipping
the linkable one becomes the expensive, embarrassing, indefensible option.
Not a campaign against the lock — a component that removes its premise.

## Status: pre-M1 (nothing to install yet)

| Milestone | State |
|---|---|
| M0 — POC: build the core, verify a real proof, reject tampered/replayed/stale | **PASSED** — [poc/M0-EVIDENCE.md](poc/M0-EVIDENCE.md) |
| M1 — verify module (pure verdict, never-throw, full negative test matrix) | next |
| M2 — full local loop (runtime-generated test-CA, offline fixtures) | planned |
| M3 — interop with the EU AV app's demo build | planned |
| M4 — HTTP gate + drop-in middleware + demo site | planned |
| M5 — the dossier (statute → spec → shipped default → working demo) | planned |

M0 highlights (measured, not asserted): a real Google-Wallet-produced
`age_over_18` proof verifies in **0.46 s**; a single flipped byte, a tampered
session transcript, and an expired trust chain are all **rejected** — the
tamper rejections after full ZK verification time, the chain rejection in
5 ms before the proof is even touched. Byte-identical replay is accepted *by
design* (the verifier is stateless); per-session nonce freshness is the
relying party's duty and a hard M4 requirement.

Product intent, scope, and the NO-GO table live in
[docs/01-product/8een-prd.md](docs/01-product/8een-prd.md).

## Reproduce M0

See [poc/M0-EVIDENCE.md](poc/M0-EVIDENCE.md) — every step, measurement, and
deviation is recorded there. Short version: clone longfellow-zk (upstream
`d8ad8f65`) into `poc/`, apply `poc/patches/0001-zkverify-fake-time.patch`,
build (`cmake`/`clang`), regenerate the negative fixtures with
`node poc/make-fixtures.mjs`, and drive the repo's reference verifier service
with the four cases. The vendored clone and derived fixtures are gitignored;
everything needed to re-materialize them is committed.

## License

[Apache-2.0](LICENSE), matching longfellow-zk.
