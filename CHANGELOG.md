# Changelog

All notable changes to this project are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) ·
Versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-13

M1 — the verify module. A ZK age proof goes in; one trustworthy bit comes out.
Not yet a gate a site can drop in (that is M4), and **not** replay-safe (see
below).

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

[0.1.0]: https://github.com/hamr0/8een/releases/tag/v0.1.0
