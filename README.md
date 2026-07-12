```
                    ╭──────────────────────────────────────╮
                    │   ╔═╗ ╔═╗ ╔═╗ ╔╗╔                    │
                    │   ╚═╬═╣╣╣ ╠╣  ║║║                    │
                    │   ╚═╝ ╚═╝ ╚═╝ ╝╚╝  ·  8een           │
                    │                                      │
                    │   proof in ──────→ one bit out       │
                    │   (and nothing else, ever)           │
                    ╰──╮───────────────────────────────────╯
                       ╰── the verifier the EU didn't ship
```

<p align="center">
  <img src="https://img.shields.io/badge/license-Apache%202.0-2a4f8c" alt="license: Apache 2.0">
  <img src="https://img.shields.io/badge/status-pre--M1%20·%20M0%20passed-2a8c4f" alt="status: pre-M1, M0 passed">
  <!-- CI + version badges land with M1 (first workflow, first package.json) -->
</p>

**Stateless, one-bit, unlinkable age verification. Proof in → `true/false` out — no name, no birthdate, no document, no identifier, nothing stored.**

Small enough to understand completely, boring enough to run forever. 8een checks a zero-knowledge age proof against an issuer trust list and answers exactly one bit. Proofs are fresh per presentation and mathematically unlinkable — two sites comparing notes see two strangers. There is nothing to breach, subpoena, or sell, because identity never arrives. The cryptography is never ours: proofs are generated and verified by [google/longfellow-zk](https://github.com/google/longfellow-zk) (Apache-2.0, IETF [draft-google-cfrg-libzk](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)) — the same scheme the EU age-verification blueprint designates and the EU app's demo build already produces. 8een is the missing half: the verifier, the trust-anchor handling, the tests, the drop-in gate, and the documentation that make it adoptable.

## Why

eIDAS 2.0 Art. 5a(16) mandates unlinkability as an *outcome*. The EU age-verification blueprint concedes zero-knowledge proofs are the *mechanism* — then marks them optional, ships them only in a demo build, and fields an official verifier stack that cannot consume them. The production fallback (batches of 30 single-use credentials) is rate-limited linkability, not unlinkability.

8een exists to make the unlinkable version so cheap to adopt that shipping the linkable one becomes the expensive, embarrassing, indefensible option. Not a campaign against the lock — a component that removes its premise.

## Quick start (honest pre-M1 edition)

There is nothing to `npm install` yet. What you can do today:

```bash
# read what this is and deliberately is not (incl. the NO-GO table)
docs/01-product/8een-prd.md

# reproduce the M0 spike — every step, measurement, and deviation recorded
poc/M0-EVIDENCE.md
```

The vendored longfellow-zk clone and derived fixtures are gitignored by design; everything needed to re-materialize them is committed (upstream SHA `d8ad8f65`, `poc/patches/0001-zkverify-fake-time.patch`, `poc/make-fixtures.mjs` — regenerates the negative fixtures byte-identically).

## What's inside

### The ladder — each rung gated, nothing ships from `poc/`

| Milestone | Deliverable | State |
|---|---|---|
| **M0** | POC spike: build the core, verify a real proof, reject what must be rejected | **PASSED** — [evidence](poc/M0-EVIDENCE.md) |
| **M1** | `verify` module: pure verdict, never-throw `{ok, over_threshold, reason}`, full negative matrix | next |
| **M2** | Full local loop: test-CA (keys generated at runtime, never in the tree), offline fixtures | planned |
| **M3** | Interop with the EU AV app's demo-build proofs | planned |
| **M4** | HTTP gate + drop-in middleware + demo site (per-session nonce, single-use) | planned |
| **M5** | The dossier: statute → spec → shipped default → working demo | planned |

### The components (from the PRD)

| Component | What it does |
|---|---|
| **core wrapper** | Drives the longfellow-zk C++ verifier via subprocess — timeout/kill, output classified, exit codes never trusted blind |
| **verify** | The pure verdict function: proof + trust anchors + nonce + threshold in → one bit + machine-readable reason out. Never throws |
| **test-CA + prover CLI** | Mints synthetic credentials under a runtime-generated CA so the whole loop runs offline — valid, tampered, underage, stale-nonce fixtures |
| **gate** | HTTP verify endpoint + one-config-block middleware (`age: 18`) + session cookie. Vanilla `node:http`, zero frameworks |
| **demo site** | A live age-gated page proving the loop end to end, mobile-first |
| **dossier** | The refutation page — every claim measured by this repo's code or cited to a primary source |

## How it works

Three actors; 8een is only the third:

1. **Issuer** (government/bank) — signs a credential (ISO mdoc with a birthdate) onto the holder's phone, once. *Exists; never ours.*
2. **Holder** (wallet on the phone) — per visit, generates a fresh ZK proof: *"a validly-signed credential behind this proof clears the threshold"*, bound to the site's fresh nonce. The credential never leaves the phone; no two proofs are matchable. *Exists (EU app demo build).*
3. **Verifier** (8een) — proof + issuer trust anchor + nonce in, one bit out, amnesia after.

The visitor sees: one button → wallet prompt showing exactly what's disclosed ("over 18: yes/no") → one tap → in. The threshold (15/16/18/21) is the site's *question*, never the visitor's *answer* — the API physically cannot return an age.

## M0 — measured, not asserted

| Case | Result | Time |
|---|---|---|
| Real Wallet-produced `age_over_18` proof (324 KB) | **accepted**, claim verified | **0.458 s** |
| Same proof, one byte flipped | **rejected** after full ZK verification | 0.413 s |
| Valid proof, tampered session transcript | **rejected** (binding is cryptographic) | 0.408 s |
| Expired issuer chain, real clock | **rejected before ZK even runs** | 0.005 s |
| Byte-identical replay | **accepted — by design**; the verifier is stateless | — |

That last row is a feature of honest scoping, not a hole: replay defense is the relying party's nonce-freshness duty, and it is a hard M4 requirement. Independent of the HTTP path, the C++ suite passed 10/10 including a full prove→verify roundtrip (42.9 s — proving is the *phone's* cost; verifying is the cheap half) and a prover that refuses a lying witness. Full log with deviations and retractions: [poc/M0-EVIDENCE.md](poc/M0-EVIDENCE.md).

---

For intent, scope, and the NO-GO table (the scope-creep firewall), see the **[PRD](docs/01-product/8een-prd.md)**. For the spike record, see **[M0 evidence](poc/M0-EVIDENCE.md)**.

## License

Apache License, Version 2.0 — see [LICENSE](LICENSE).
