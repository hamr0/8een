# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] — 2026-07-18

**Runtime change:** prebuilt verifier binaries (PRD §9 D11) — on linux-x64,
`npm install zk8een` is now the whole install. Everywhere else the package stays
bring-your-own-binary (D10) exactly as in `0.4.1`.

### Added
- **`provisionBinary(dir?, opts?)`** — fetches the prebuilt longfellow verifier
  service for this platform (linux-x64 today) and refuses any byte that does not
  match the sha256 pinned in `src/binary.manifest.js`, the same trust model as
  the circuits: the download host (a GitHub release of this repo) is untrusted.
  Idempotent, atomic; default target is the per-user cache
  (`$XDG_CACHE_HOME`/`~/.cache` + `/zk8een`). `opts.platform` provisions for
  another target (e.g. into a container image).
- **`binary:` is now optional** on `Verifier.start` / `startGate`: when omitted,
  the provisioned binary is found in the default dir and — because a binary,
  unlike a circuit, cannot be integrity-checked by the service at load — is
  **re-hashed against the pin on every start**, and checked for executability. A
  binary that rots, is swapped, or has lost its execute bit is refused with the
  fix named, never run. An explicit `binary:` path still wins, and the pin
  deliberately does not apply to it (bring-your-own stays first-class); an empty
  or non-string `binary:` is a loud config error, not a silent fallback.
- **`.github/workflows/binaries.yml`** — the public build: clones upstream at the
  pinned commit, applies the tracked patch series (`poc/patches/`), builds the
  C++ core + cgo Go service on a clean runner, and **refuses to release a binary
  the full integration suite has not passed on that runner** — asserting its
  pass/fail counts and matching every skip against the one legitimate reason,
  because green-by-skipping is this project's own recurring failure shape. Assets land on the `longfellow-bin-1` release with
  checksums; every released byte is auditable back to the workflow run that built
  it. No `postinstall` auto-download — provisioning stays an explicit step.

### Fixed
- **The published TypeScript types did not typecheck in an adopter's project**
  (present since `0.1.0`, shipped in `0.4.1`). `types/circuits.d.ts` carried
  `import manifest from './circuits.manifest.json'`, but no JSON is shipped into
  `types/` — so any TS adopter running `tsc` got `TS2307` from inside
  `node_modules/zk8een`. **The manifests are now plain ESM modules**
  (`src/*.manifest.js`) rather than JSON imported through an import attribute,
  per LIBRARY_CONVENTIONS §1 — so their types are generated from the data itself
  and nothing unresolvable reaches the public `.d.ts`. Found by typechecking a
  real `npm pack` + install, not by reading the source.
- **CI now typechecks the published artifact, not just the source.** `tsc
  --noEmit` never looks at the generated `.d.ts` the way an adopter resolves it,
  which is exactly how the above shipped green for four releases. The push/PR
  workflow now packs the tarball, installs it into a throwaway consumer project,
  and typechecks the documented usage against it — verified non-vacuous by
  reintroducing the JSON import and watching the step fail.

### Internal
- **`src/pinned.js`** — the fetch-and-verify sequence (reachability, advertised
  size before the body is read, actual size, sha256, atomic write-then-rename)
  existed twice, once for circuits and once for the binary, drifting
  independently. It is the package's integrity boundary, so it now lives in one
  place that can be audited once. Verified behaviour-preserving: every refusal
  message on both paths is byte-identical to before.
- **Only `provisionBinary` is public** of the four functions the binary work
  added (LIBRARY_CONVENTIONS §1 — default OUT on new API surface). `Verifier.start`
  resolves the binary itself, so the rest stay internal rather than becoming a
  promise that is breaking to take back.

### Dev-only
- CHANGELOG's bottom link-reference table completed (0.2.0–0.4.1 were missing).
- `ci.yml` coverage comment corrected: a clean runner *can* run the integration
  suite now — `binaries.yml` does exactly that on every build.
- `binaries.yml` hardened after a review found its proof gate did not gate:
  under Actions' default `bash -e {0}` the suite's exit status was `tee`'s, so a
  **failing** integration suite would have released its binary. Now `pipefail`
  plus asserted pass/fail/skip counts, with skips matched against the one
  legitimate reason rather than tolerated by count; the release job refuses to
  overwrite a published asset whose bytes differ from the manifest pin; and the
  upstream commit, patch list, and release tag are read from
  `src/binary.manifest.js` instead of being second copies that can drift.

## [0.4.1] — 2026-07-16

**Docs-only:** the dossier (M5). No runtime change.

### M5 — the dossier (PASSED, exit amended by PRD D9)
- **`docs/index.html`** — the refutation page: statute → spec → shipped default → the
  missing half, plus the project's own retracted claims (Exhibit V) and an honesty ledger
  of what is measured, cited, and still open (Exhibit VI). Zero JavaScript, zero external
  requests; light/dark; every claim lifted from an existing evidence doc, all 8 external
  citations and 9 internal links verified. Served via GitHub Pages from `/docs` — enabling
  Pages is a repo-settings step at merge time, verified live before this claim is trusted
  ([evidence](docs/02-evidence/M5-EVIDENCE.md)).
- **`docs/assets/replay-demo.webm`** — the demo recorded unedited at `a023174` (v0.4.0):
  a real proof accepted (HTTP 200), its byte-identical replay refused
  (`503 replay_detected`, `over_threshold:null`), a fresh session accepted again.
- **PRD D9:** the M5 exit criterion "live demo embedded" amended to a GitHub-hosted page
  with the recorded demo — no VPS, no public endpoint. Consequence stated on the page
  itself: the on-phone `ZkSystemId` gap (M3) remains open.
- README: status badge brought current; the dossier linked from §Why.
- **Published to npm as bring-your-own-binary** (PRD §9 D10, 2026-07-17): the package
  states plainly that `npm install zk8een` verifies nothing until the adopter builds the
  longfellow binary from the documented steps. First real version on the registry.

## [0.4.0] — 2026-07-16

**Runtime change:** the HTTP gate, M4 piece 3 of 3 — the "adopt without thinking" layer,
**replay-safe by default**. M4 (the gate) is now complete: credential currency (0.2.0),
single-use nonce (0.3.0), and now the endpoint/middleware/demo that wires them for a site.

### M4 — the HTTP gate (piece 3, PASSED)
- **`startGate(opts)`** — starts the verifier and returns two HTTP routes over it, with
  `requireSingleUse` defaulting **on** (it defaults off on the bare `Verifier`). Running
  replay-open is a deliberate `requireSingleUse: false`; single-use on without a
  `challengeSecret` and a `nonceStore`/`store:'memory'` **throws before the circuit load**,
  never fails open. Returns `{handler, express, verifier, stop}`.
- **`createGate({verifier, ...})`** — the gate over a verifier you started yourself.
- **Two routes.** `GET {basePath}/challenge` → `{nonce, transcript, expiresAt}` (base64url);
  `POST {basePath}/verify` with `{transcript, deviceResponse}` (base64url) → the `Verdict`.
  **`ok:true` → HTTP 200** (read `over_threshold` in the body); **`ok:false` → HTTP 503**
  ("could not verify — re-challenge"), never a status that reads as "denied person".
- **Framework-agnostic.** `handler` is a bare `node:http` listener; `express()` is a
  middleware (`app.use(gate.express())`). Zero runtime dependencies still holds (NO-GO #9).
- **AGENT_RULES invariants on the wire:** a bounded request body (413 over `maxBodyBytes`,
  default 1 MB), a per-IP rate limiter (default 60/min, `rateLimit:false` to disable),
  loopback in every example, no leaked internals. Closes PRD §6 / §7.4a end-to-end.
- **`demo/`** (repo-only, not shipped): a runnable, fully-real showcase — a real proof is
  accepted, its byte-identical replay is refused (`503 replay_detected`), and a fresh
  session is accepted again. Boots against the built POC verifier; needs no phone.
- **Owner directive (M4 piece 3):** the gate flips the primitive's default-off stance so
  the lazy path is the safe path. The bare `Verifier` default stays off (a library
  primitive cannot invent a shared secret and store).

## [0.3.0] — 2026-07-16

**Runtime change:** opt-in replay defence (the single-use nonce), M4 piece 2 of 3. The
endpoint/middleware/demo site is the last piece. 8een is now replay-safe **when
`requireSingleUse` is on** — it stays not-replay-safe by default.

### M4 — the single-use nonce (piece 2, PASSED)
- **Replay defence, opt-in.** With `requireSingleUse` on, only a proof bound to a live,
  unspent challenge THIS verifier issued is accepted. A replay is `ok:false, replay_detected`;
  an unrecognized/expired challenge is `ok:false, session_unknown` — never a "no". Closes PRD
  §7.4a. [evidence](docs/02-evidence/M4-EVIDENCE.md).
- **New `src/challenge.js`:** `issueChallenge()` mints a self-authenticating nonce
  (`random ‖ expiry ‖ HMAC`) so issuance stores nothing; `applySingleUse()` spends it once
  through the adopter's store. Also exported: `inspectChallenge`, `InMemoryNonceStore` (dev only).
- **New `Verifier` options:** `requireSingleUse` (default **off**), `challengeSecret` (HMAC key,
  ≥16 bytes, shared across replicas), `nonceStore` (atomic `spend(key, ttlMs)`; e.g. Redis
  `SET NX PX`), `challengeTtlMs` (default 5 min). New method `verifier.issueChallenge()`.
- **Fails closed when on:** enabling `requireSingleUse` without a secret **and** a store throws
  at construction — 8een never falls back to a per-process store that only looks replay-safe.
- **New `REASONS`:** `replay_detected` and `session_unknown` (both `ok:false, over_threshold:null`).
- **`nonceStore` is the adopter's** — the one piece of state 8een refuses to hold (NO-GO #7).
  Owner decision §9 D8. No server patch required (the transcript already binds).

## [0.2.0] — 2026-07-16

**Runtime change** (first since `0.1.0`): a credential-currency gate is now enforced by
default. M4 piece 1 of 3 — the endpoint/middleware/demo and the per-session nonce are still
to come, and 8een remains **not replay-safe**.

### M4 — the credential-currency gate (piece 1, PASSED)
- **An expired credential no longer verifies.** The verifier was checking the credential's
  validity window against a `now` the *prover* supplies inside the proof, never the real
  clock — so an expired credential verified, indistinguishable from a live one (measured
  fail-first). The verifier now echoes the timestamp it used and 8een bounds it against the
  real clock. [evidence](docs/02-evidence/M4-EVIDENCE.md), closes PRD §7.1a.
- **New option `requireCurrentValidity`** (default **on**). An expired presentation is a real
  verdict — `over_threshold: false`, reason `credential_expired` — never "underage"; an
  unreadable presentation date is `ok: false`, reason `freshness_unknown`, never a "no". Turn
  it **off** for age-only sites: an expired ID still proves adulthood (age is monotonic), so
  a KYC-style flow keeps the secure default while an age-gate may opt out. Amends PRD §7.4b
  to "reject by default, configurable" (owner decision §9 D7).
- **New option `toleranceMs`** (default 5 min) — how far the presentation date may sit from
  the real clock. Validated at construction; a malformed value fails **closed**.
- **New `REASONS`:** `credential_expired` (`ok:true, over_threshold:false`) and
  `freshness_unknown` (`ok:false, over_threshold:null`).
- **Requires a verifier that echoes the timestamp** (`poc/patches/0003-m4-echo-verified-timestamp.patch`,
  now part of the build baseline). Against a verifier without it, the default-on gate returns
  `freshness_unknown` (fail-closed) until you rebuild or set `requireCurrentValidity: false`.

### Dev-only
- `tools/mkfixture` threads a per-credential clock (real-time *fresh* / past *expired*) and
  adds an `expired-credential` fixture; the deterministic byte-exact layout path is unchanged.

## [0.1.3] — 2026-07-15

**No runtime change** — `src/` and `types/` are byte-identical and dependencies are still
zero, so `require('zk8een')` behaves exactly as in `0.1.2`. The shipped `README.md` and this
`CHANGELOG.md` do change (both are in `files`); the work here is milestone evidence, dev-only
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

[0.5.0]: https://github.com/hamr0/8een/releases/tag/v0.5.0
[0.4.1]: https://github.com/hamr0/8een/releases/tag/v0.4.1
[0.4.0]: https://github.com/hamr0/8een/releases/tag/v0.4.0
[0.3.0]: https://github.com/hamr0/8een/releases/tag/v0.3.0
[0.2.0]: https://github.com/hamr0/8een/releases/tag/v0.2.0
[0.1.3]: https://github.com/hamr0/8een/releases/tag/v0.1.3
[0.1.2]: https://github.com/hamr0/8een/releases/tag/v0.1.2
[0.1.1]: https://github.com/hamr0/8een/releases/tag/v0.1.1
[0.1.0]: https://github.com/hamr0/8een/releases/tag/v0.1.0
