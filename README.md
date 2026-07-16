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
  <img src="https://img.shields.io/badge/status-M4%20passed%20·%20M5%20dossier-2a8c4f" alt="status: M4 passed, M5 dossier">
  <a href="https://github.com/hamr0/8een/actions/workflows/ci.yml"><img src="https://github.com/hamr0/8een/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <!-- No npm version badge: the only thing on the registry is an inert 0.0.0
       placeholder holding the name. A version badge would advertise it as a
       release. It lands when a version ships that can actually verify a proof. -->
</p>

**Stateless, one-bit, unlinkable age verification. Proof in → `true/false` out — no name, no birthdate, no document, no identifier, nothing stored.**

Small enough to understand completely, boring enough to run forever. 8een checks a zero-knowledge age proof against an issuer trust list and answers exactly one bit. Proofs are fresh per presentation and mathematically unlinkable — two sites comparing notes see two strangers. There is nothing to breach, subpoena, or sell, because identity never arrives. The cryptography is never ours: proofs are generated and verified by [google/longfellow-zk](https://github.com/google/longfellow-zk) (Apache-2.0, IETF [draft-google-cfrg-libzk](https://datatracker.ietf.org/doc/draft-google-cfrg-libzk/)) — the same scheme the EU age-verification blueprint designates and the EU app already carries in every build. 8een is the missing half: the verifier, the trust-anchor handling, the tests, the drop-in gate, and the documentation that make it adoptable.

## Why

**The full argument, written down with citations — statute, spec, shipped default, working demo, and the claims of ours the evidence killed: [the dossier](https://hamr0.github.io/8een/).**

eIDAS 2.0 Art. 5a(16)(a) says the framework must not let attestation providers *or any other party* obtain data that allows transactions to be "tracked, linked or correlated." It names the **issuer** as an adversary.

The EU blueprint's default answer is batch-issued single-use credentials. Against colluding websites those genuinely work — each is bound to its own device key, so two sites comparing notes really do see two strangers. But they do not defend against the issuer, who signs every credential and could recognise it; the spec's only safeguard is that it *"does not require"* the issuer to retain anything — a policy, not a cryptographic guarantee. The blueprint's own Annex B concedes that zero-knowledge proofs are what *"ensur[e] unlinkability."*

ZK is where the blueprint stops short. It is `SHOULD`, not `SHALL`, and it sits in the chapter titled **"Experimental features"** — so the mandatory path remains full disclosure, where the relying party sees the actual credential. And where ZK *is* implemented, the path is broken end-to-end on the protocol the web actually uses: the EU wallet never receives the ZK machinery on its OpenID4VP path, so it cannot produce a proof there, and the flagship OpenID4VP verifier contains no ZK code at all and cannot check one. When proof generation does fail, the wallet's default policy is `FallbackToFullDisclosure` — it silently hands over the whole document instead.

A working ZK verifier does exist: one server-side component, a vendored copy of OpenWallet's Multipaz, deployed and live. It is a wallet SDK, not something a mid-size site drops into a request path.

8een exists to make the unlinkable version so cheap to adopt that shipping the linkable one becomes the expensive, embarrassing, indefensible option. Not a campaign against the lock — a component that removes its premise.

Every claim above is pinned to a file, a line, and a commit in [`docs/02-evidence/EU-STACK-AUDIT.md`](docs/02-evidence/EU-STACK-AUDIT.md) — including four earlier claims of ours that the audit **retracted**.

## Quick start

There is still nothing worth `npm install`-ing — 8een drives a longfellow verifier binary it does not yet ship, so the published package cannot verify a proof on its own. The name `zk8een` is reserved on npm, but the only version published there is an empty `0.0.0` placeholder. What exists today: the verify module (below) and the HTTP gate that drops in front of it ([further down](#the-gate--replay-safe-by-default)). Zero runtime dependencies, vanilla Node ≥22.

```js
import { Verifier, provision } from 'zk8een';

await provision('./circuits');            // 17 pinned circuits, sha256-verified

const verifier = await Verifier.start({
  binary: './longfellow-verifier',
  circuitDir: './circuits',
  caCerts: './issuers.pem',               // THE trust boundary — choose it deliberately
  threshold: 18,                          // configurable; the output stays one bit
});

const v = await verifier.check({ transcript, deviceResponse });

if (!v.ok) serveError();                  // we are broken — do NOT say "underage"
else if (v.over_threshold) allowEntry();
else denyEntry();                         // a real, cryptographic no
```

**`ok` and `over_threshold` are different questions.** `ok` says whether we got an answer at all; `over_threshold` says what the answer was. When `ok` is false, `over_threshold` is `null` — never `false`. A verifier that cannot verify is broken, and a broken verifier reporting "no" would turn away every legitimate adult while sounding exactly like a working one.

**The bare `Verifier` does not stop replay, and does not pretend to.** It is stateless: hand it the same valid proof a thousand times and it will say "valid" a thousand times, because it is. Freshness is the relying party's job — a nonce per visit, bound into the transcript, spent once. Shipping the bare verifier alone as an age gate would verify beautifully and still admit a fourteen-year-old holding a borrowed proof. **So don't — use the gate below, which does the nonce for you.**

## The gate — replay-safe by default

`startGate()` is the drop-in for a real site: it starts the verifier and gives you two HTTP routes, and — unlike the bare `Verifier` — it is **replay-safe by default**. It issues a one-time nonce and spends it for you; running replay-open takes a deliberate `requireSingleUse: false`, and if single-use is on without the secret and store it needs, it refuses to boot (before the slow circuit load, not after).

```js
import { startGate } from 'zk8een';
import express from 'express';

const gate = await startGate({
  binary: './longfellow-verifier',
  circuitDir: './circuits',
  caCerts: './issuers.pem',               // THE trust boundary — choose it deliberately
  challengeSecret: process.env.EIGHTEEN_SECRET,  // ≥16 bytes, stable, shared across replicas
  store: 'memory',                        // single-process DEV shortcut; use a Redis-backed
                                          // nonceStore ({ spend(key, ttlMs) }) in production
});

const app = express();
app.use(gate.express());                  // mounts GET /8een/challenge + POST /8een/verify
app.listen(3000, '127.0.0.1');            // loopback; never 0.0.0.0 unless deliberately public
```

No Express? The same gate is a bare `node:http` handler:

```js
import http from 'node:http';
http.createServer(gate.handler).listen(3000, '127.0.0.1');
```

The browser flow is two round-trips: `GET /8een/challenge` returns a nonce the wallet stamps its proof with; `POST /8een/verify` with `{ transcript, deviceResponse }` (base64url) returns the verdict. **`ok:true` → HTTP 200** (branch on `over_threshold` in the body); **`ok:false` → HTTP 503** ("could not verify — re-challenge"), never a status that reads as "denied person". A recorded proof replayed → `503 { ok:false, over_threshold:null, reason:"replay_detected" }`.

A runnable, fully-real version of exactly this — accept, then replay-refused, then fresh-accept — is in [`demo/`](demo/) (`node demo/server.js`).

```bash
# what this is and deliberately is not (incl. the NO-GO table)
docs/01-product/8een-prd.md

# the M0 spike and the M1 module — every step, measurement, and deviation recorded
poc/M0-EVIDENCE.md
docs/02-evidence/M1-EVIDENCE.md
```

The vendored longfellow-zk clone and every fixture are gitignored by design; everything needed to re-materialize them is committed (upstream SHA `d8ad8f65`, plus the tracked patch series in `poc/patches/`).

Since **M2** the integration suite mints its own credentials at run time via `tools/mkfixture` — a valid proof, an underage one, a wrong-issuer one, a tampered one, a proof replayed into another session, a mangled chain, a relabelled claim, and three presentations for the unlinkability check. Running it therefore needs the clone built **with its `install/` prefix** (mkfixture links longfellow via cgo) **and a Go toolchain**; the circuit and trust-list guards need neither and run regardless. No key material or fixture is ever written to the tree (PRD §10).

`poc/make-fixtures.mjs` remains only as part of the **M0** evidence trail — it regenerates the old `post1`-derived fixtures byte-identically. Nothing in the test suite reads them any more: their cert chain expired 2026-05-07, so on the real clock they are refused at chain validation before reaching the layer they were meant to exercise.

## What's inside

### The ladder — each rung gated, nothing ships from `poc/`

| Milestone | Deliverable | State |
|---|---|---|
| **M0** | POC spike: build the core, verify a real proof, reject what must be rejected | **PASSED** — [evidence](poc/M0-EVIDENCE.md) |
| **M1** | `verify` module: pure verdict, never-throw `{ok, over_threshold, reason}`, full negative matrix | **PASSED** — [evidence](docs/02-evidence/M1-EVIDENCE.md) |
| **M2** | Full local loop: test-CA (keys generated at runtime, never in the tree), offline fixtures | **PASSED** — [evidence](docs/02-evidence/M2-EVIDENCE.md) |
| **M3** | Interop with the EU AV app's demo-build proofs | **PASSED** — [evidence](docs/02-evidence/M3-EVIDENCE.md) (via the PRD §6 fallback: the EU's own longfellow prover; on-phone capture pending — emulator unusable on this kernel) |
| **M4** | HTTP gate + drop-in middleware + demo site. Owns freshness, both halves: per-session single-use nonce, **and** credential expiry (an expired credential must not verify — see PRD §7.4) | planned |
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
2. **Holder** (wallet on the phone) — per visit, generates a fresh ZK proof: *"a validly-signed credential behind this proof clears the threshold"*, bound to the site's fresh nonce. The credential never leaves the phone; no two proofs are matchable. *Exists in every EU app build — but only over the browser DC API or proximity, never over OpenID4VP.*
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
