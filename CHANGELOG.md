# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

**No change to the shipped package** — `src/` and `types/` are untouched, dependencies are
still zero, the tarball is byte-identical. The work here is milestone evidence, dev-only
tooling, tests, and a documented corrections pass.

### M3 — EU interop (PASSED)
- **8een verifies a genuine EU-prover-generated ZK proof.** Rung 1: 8een reads the EU AV
  docType (`eu.europa.ec.av.1`) exactly as an mDL — the full §7.1 matrix passes under the
  EU docType, and the EU's Longfellow circuits are byte-identical (12/12) to the ones 8een
  pins. Rung 3: a proof made by the EU's own longfellow prover verifies end-to-end
  (`verified` / `age_over_18`), rejects when tampered (`zk_proof_invalid`) and when the
  issuer is untrusted (`issuer_untrusted`). [evidence](docs/02-evidence/M3-EVIDENCE.md).
- **Finding + bridge: circuit-id convention mismatch.** The Google reference verifier keys
  circuits by bare `circuit_id`; the EU's Multipaz stack labels them compositely, so a
  verbatim EU proof missed circuit lookup (`circuit_unavailable`, invariant intact). Bridged
  with a tracked, label-resolution-only patch (`poc/patches/0002-eu-circuit-id-compat.patch`)
  that resolves a composite id to its verified trailing `circuit_id` — no crypto, no trust
  boundary touched (NO-GO #8 intact). A verbatim EU proof now verifies; full regression 24/24.
- **Dev tooling:** `tools/mkfixture` gained `-doctype` / `-namespace` flags (default ISO mDL).
- **Scope note:** met via the PRD §6 fallback — the EU's JVM prover, not the shipping phone
  app (the Android emulator is unusable on this host's kernel). On-phone `ZkSystemId` capture
  is pending; the bridge is robust to it.

### Retracted — claims that were false
- **"The EU app enables ZK proofs only in the demo build."** Both flavors (`Dev`,
  `Demo`) configure Longfellow identically; there is no flavor without it. The two
  config files differ by a trailing comma and two comments.
- **"The EU's ZK verifier is off by default, browser-only, behind a Chrome flag."**
  The feature flag (`VITE_FEATURE_FLAG_DC_API`) is **dead code** — declared, never
  read. The real gate is runtime browser capability detection, so the ZK path switches
  itself **on**. The Digital Credentials API shipped unflagged in **Chrome 141**
  (Oct 2025). The service is **deployed and live** — reached over plain HTTP with
  `curl`, across three transports. We had reasoned from an empty `.env.example` to
  "it's off" instead of reading what actually runs — the exact mistake `CLAUDE.md`
  forbids, committed against someone else's config file.

### Retracted — a claim that was unfair to the EU
- **"Batches of 30 single-use credentials are rate-limited linkability, not
  unlinkability."** Against **colluding relying parties this is genuinely unlinkable**
  — each attestation is bound to a distinct device key, so there is no
  credential-borne correlator. The claim was inherited from a secondary source and
  never checked. It was also the sentence most likely to discredit everything around
  it. The real gap is *who* batching protects you from: **not the issuer**, who signs
  each attestation and could recognise it — and the spec's only safeguard there is
  that it *"does not require"* the issuer to retain anything, which is a policy, not a
  cryptographic guarantee.

### Corrected
- ZKP is **`SHOULD` (RFC 2119: RECOMMENDED)**, not "optional" (`MAY`) — and the
  mechanism sits in the chapter titled **"Experimental features."**
- **eIDAS 5a(16):** lean on limb **(a)**, which names the **attestation provider** —
  the issuer — as a party that must not be able to link transactions. The published OJ
  text spells it **"unlikeability"** *[sic]*; quoting it as "unlinkability" misquotes
  the law.

### Added — two findings, both stronger than the claims they replace
- **The EU wallet cannot emit a ZK proof over OpenID4VP at all.**
  `DcqlRequestProcessor` is never handed the ZK repository (wallet-core 0.28.1). On the
  protocol the web actually uses, the unlinkable path **does not exist end-to-end**:
  the wallet cannot produce a proof, and the flagship OpenID4VP verifier — **zero ZK
  code, zero ZK commits in its entire history** — cannot check one.
- **On proof-generation failure the wallet silently discloses the entire document.**
  The default `ZkResponsePolicy` is `FallbackToFullDisclosure`; the library's own docs
  call the safe setting *"recommended for production use to prevent unintended full
  document disclosure"* — and **neither the app nor wallet-core ever sets it.** This is
  8een's own recurring failure shape — a security-critical step fails, the status stays
  green, and the system silently does the *wrong* thing — **found in someone else's
  code.**

### Changed
- **The thesis is narrower and better evidenced.** Not *"nobody can verify these"* — a
  working ZK verifier exists, is vendored from OpenWallet's Multipaz, and is live. The
  argument that survives: the unlinkable path is not **reachable** on the mainstream
  protocol, not **default** anywhere, not **fail-safe** when it breaks, and not
  **adoptable** as a small stateless dependency.
- **M3 and decision D2 amended.** Any app flavor will do, but a proof **must be
  captured over the DC API or proximity, never OpenID4VP** — which cannot emit one.
  `av-dc-api-backend` is now available as a **live differential oracle** to test 8een
  against.

### Method
Every claim above was handed to an independent check instructed to **refute** it and to
default to REFUTED on thin evidence. **Three of the four went in and came back
altered.** Each surviving claim is pinned to a file, a line, and a commit in
[`docs/02-evidence/EU-STACK-AUDIT.md`](docs/02-evidence/EU-STACK-AUDIT.md).

## [0.1.2] — 2026-07-14

**M2 PASSED.** The test suite now mints its own credentials and runs against the
real verifier on the real clock. As with `0.1.1`, the runtime is **byte-identical**:
`src/` and `types/` are untouched, dependencies are still zero, and every gap listed
under `0.1.0` is still open. Nothing here changes what an adopter installs — it
changes what we can *prove* about it, which had been weaker than we said.

### Changed (test + dev-only — nothing in the tarball changes but this README)
- **The pinned verification clock is gone.** Every earlier suite ran the accept path
  under `ZKVERIFY_FAKE_TIME`, because the only real proof available carried a cert
  chain that expired 2026-05-07. That pin was quietly load-bearing: with x509
  verification frozen at a date where the one chain happened to be valid, **no test
  could tell a working certificate-chain validator from a broken one.** The suite now
  mints unexpired credentials at run time and verifies them on the real clock.
- **The §7.1 negative matrix is complete**, and two rows are new:
  - **a proof replayed into a different session** is refused — the device signature
    will not match a preimage rebuilt over another transcript. (A byte-identical
    replay in its *own* session is still **accepted**, by design: the verifier is
    stateless. Freshness is the gate's job — M4. **8een is not replay-safe.**)
  - **a minor cannot relabel their own valid proof as over-18.** An honest
    `age_over_18=false` proof, with one byte of the wire envelope edited to claim
    `true`, is refused by the ZK binding. Nothing is forged; only the envelope lies.
    A false accept here would have admitted a minor on their own valid proof, and
    nothing was testing for it.
- **§7.3 unlinkability is now evidenced by a check that can fail.** Two earlier
  versions were written and **retracted** — both passed on first run and neither
  could fail. The check that stands measures the longest contiguous byte run shared
  by two presentations, and **plants a known identifier as a positive control** so
  the detector is watched catching one before its null result is believed. Its
  detection floor is ~11 bytes and that is stated, not buried: an 8-byte serial, or
  an encrypted identifier, would not be caught. Full cryptographic unlinkability
  remains **cited, not claimed**.

### Known gap (scheduled, not hidden)
- **Credential expiry is exercised by no test.** M2 made the *certificate chain*
  clock real; the *credential's own* clock is still a frozen constant, so the mdoc
  validity window is never checked against real time. An expired credential is
  currently refused by nothing we test. Scheduled as **PRD §7.4, owned by M4**,
  alongside the nonce — "is this presentation still good right now" is one question
  with two halves, and a stateless verifier can answer neither alone.

## [0.1.1] — 2026-07-14

A documentation correction to the adopter contract, plus the M2 test-CA and
fixture tooling — which is **dev-only and does not ship**. The runtime is
byte-identical to `0.1.0`: `src/` and `types/` are untouched, dependencies are
still zero, and every gap listed under `0.1.0` is still open. If you are an
adopter, the only thing that changed for you is that one paragraph below was
wrong.

### Fixed
- **The EU AV Trusted List exists, and `8een.context.md` said it didn't.** The
  contract told EU deployers their anchors could only come from a PEM bundle they
  assembled by hand, and implied there was no official source. There is: the EU now
  publishes a dedicated **AV Trusted List** (ETSI-signed XML, service type `PAA`,
  for `eu.europa.ec.av.*` credentials), with an acceptance environment for testing.
  8een still does not parse ETSI XML — you extract the PAA X.509 certificates and
  drop them into the PEM bundle you pass as `caCerts`, and because 8een does not
  verify that XML signature, the list is input you vouch for. But an EU deployment
  is no longer a dead end, and telling adopters otherwise was the kind of error that
  makes people build the wrong thing.

### Added (dev-only — outside the `files` allowlist, not in the tarball)
- **`tools/mkfixture`** — a test-CA and fixture generator. Mints a synthetic ISO
  18013-5 credential under a runtime-generated P-256 CA, proves it with
  longfellow's own prover, and emits the negative matrix as fixtures: `valid`,
  `untrusted-issuer`, `underage`, `tampered`. Certificates are issued on the real
  wall clock, which is what will let the integration harness drop
  `ZKVERIFY_FAKE_TIME`. No cryptography is authored (PRD NO-GO #8): signing is Go
  stdlib, proving and verifying are longfellow's compiled code. Keys are generated
  at runtime and never written to disk (PRD §10).
- **The generator refuses to emit a fixture it has not verified.** It checks the
  circuit by its **id** — via longfellow's own `circuit_id()`, because
  `mdoc_zk.cc` disables that enforcement internally and states the application must
  do it — rather than trusting the filename; and it re-verifies every fixture before
  writing, asserting the document-signer certificate carries the exact key that
  signed the MSO and that each proof reaches the verdict its scenario claims. A
  truncated circuit, or a "tampered" proof whose byte-flip landed somewhere inert,
  now fails generation instead of shipping as a test that silently passes.
- **`poc/m2-spike/`** and **`docs/02-evidence/M2-EVIDENCE.md`** — the de-risking
  spike and its measurements, including the load-bearing byte-layout constraints
  the minter depends on.

### Still true from 0.1.0
M2 is **in progress, not passed**: the integration suite does not yet consume these
fixtures, `ZKVERIFY_FAKE_TIME` is therefore still in the harness, and the
stale/wrong-nonce row of the negative matrix is not written. Replay is still
accepted by design. Nothing is published to npm at `0.1.1` — the package still
drives a longfellow binary it does not ship.

## [0.1.0] — 2026-07-13

M1 — the verify module. A ZK age proof goes in; one trustworthy bit comes out.
Not yet a gate a site can drop in (that is M4), and **not** replay-safe (see
below).

**The package is `zk8een`.** npm permanently refuses the bare name `8een` — its
typo-squat filter rejects it as too close to `open`/`when`/`leven`/`levn`, for
everyone. The project is still 8een; only the npm name differs. Nothing is
published at `0.1.0` yet: it drives a longfellow binary it does not ship (see
[Known gaps](#known-gaps--stated-not-glossed)), and until that is solved,
`npm install zk8een` would hand you a verifier that cannot verify.

### Added
- `Verifier` — the public surface. `check(proof)` → `{ok, over_threshold, reason}`.
- **TypeScript types**, generated from JSDoc (`tsc`, `checkJs` + `strictNullChecks`)
  and built into the tarball on publish. JSDoc is the only hand-authored source of
  types, so the `.d.ts` cannot drift from the code — `tsc --noEmit` gates every
  push and every publish.
- **`8een.context.md`** — the complete adopter contract: every option, the public
  API, the trust-anchor decision, the threat model, and the refusals. Ships in the
  package. Point an integrating agent at this file.
- `verdict.js` — pure, never throws, zero dependencies. Turns one exchange with
  the verifier into one bit.
- `service.js` — supervises the longfellow Go verifier as a long-lived child
  (circuit load is 44–73s, so spawn-per-request is a non-starter). Binds
  loopback; upstream's default binds every interface.
- `circuits.js` — fetches the 17 pinned circuits (4.3 MB) on first run,
  sha256-verified against upstream `d8ad8f65`. Atomic, idempotent, self-healing.
- Configurable threshold (PRD D6). The output stays a single bit.

### The rule this release exists to hold
`ok` (did we get an answer) is separate from `over_threshold` (what the answer
was), and **`ok:false` ⇒ `over_threshold:null`, never `false`**. A verifier that
cannot verify is broken, and a broken verifier reporting "no" would deny every
legitimate adult while sounding exactly like a working one. It says *"I cannot
verify"*. It never says *"you are underage"*.

### Security
- **Trust anchors are project config; nothing is fetched over the network.**
  Upstream defaults `-vical_url` to AAMVA's US motor-vehicle trust list and pulls
  22 issuer certs at every boot, with a non-fatal failure path that silently
  varies the anchor set. 8een never inherits that default: no trust list is
  fetched unless you explicitly ask for one.
- **A silently-truncated trust list is now fatal.** Upstream's
  `LoadIssuerRootCA` breaks out of its parse loop and returns *success* on a
  malformed PEM boundary — its own `certs.pem` has 19 certificates and loads 17,
  without a word. An operator appending their issuer CA to such a bundle would
  have it dropped in silence, and every proof from that issuer then rejected as
  untrusted by a verifier reporting perfect health. We count the bundle and
  refuse to serve if fewer loaded.
- **Zero trust anchors is fatal**, for the same reason: it rejects everyone,
  confidently.
- **A partially-loaded circuit set is fatal.** Upstream skips a bad circuit and
  carries on; we refuse to start.
- Downloads are size-checked before being read into memory; circuit ids are
  validated before becoming paths or URLs; the child gets a minimal environment
  rather than the host's entire env.

### Known gaps — stated, not glossed
- **Replay is accepted.** The verifier is stateless and a replayed proof is
  genuinely valid; the maths cannot know it was spent. Freshness is the relying
  party's duty and a hard M4 requirement. There is a passing test that asserts
  this, so it cannot be quietly forgotten.
- **Under-threshold**: the logic is written and unit-tested, but no real underage
  credential exists to run it against until M2's test-CA.
- **The accept path runs under a pinned verification clock** — the only real proof
  available carries a chain that expired 2026-05-07. The switch is injected by the
  test harness and appears nowhere in 8een's code. Every reject path is
  clock-independent or runs on the real clock. M2's test-CA removes the
  scaffolding.

[0.1.1]: https://github.com/hamr0/8een/releases/tag/v0.1.1
[0.1.0]: https://github.com/hamr0/8een/releases/tag/v0.1.0
