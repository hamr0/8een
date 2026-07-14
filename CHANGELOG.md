# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
