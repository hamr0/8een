# 8een — Integration Guide

## What this is

8een verifies a zero-knowledge age proof against an issuer trust list and answers
exactly one bit: is this person over the threshold, or not. It never learns a
name, a birthdate, or a document number — there is no birthdate in the proof to
learn. The cryptography is not ours: proofs are verified by
[google/longfellow-zk](https://github.com/google/longfellow-zk), the scheme the EU
age-verification blueprint designates. 8een is the missing half — the verifier,
the trust-anchor handling, and the honesty about what a verdict does and does not
mean.

## What 8een is and is not

**Is:** a verify module. Proof in → `{ok, over_threshold, reason}` out.

**Is not — and this matters more than anything else on this page:**

- **Not a gate.** It does not manage sessions, nonces, cookies, or rate limits.
- **Not replay-safe.** See [Threat model](#threat-model-summary). This is the one
  that will bite you.
- **Not an issuer.** It mints nothing and stores nothing.
- **Not usable standalone yet.** It drives a longfellow verifier binary that this
  package does not ship. See [Constraints](#constraints).

## Minimal usage

```js
import { Verifier, provision } from 'zk8een';

await provision('./circuits');              // 17 pinned circuits, sha256-verified

const verifier = await Verifier.start({
  binary: './longfellow-verifier',          // you supply this — see Constraints
  circuitDir: './circuits',
  caCerts: './issuers.pem',                 // THE trust boundary
  threshold: 18,
});

const v = await verifier.check({ transcript, deviceResponse });

if (!v.ok) serveError();                    // we are broken — do NOT say "underage"
else if (v.over_threshold) allowEntry();
else denyEntry();                           // a real, cryptographic no
```

Start the verifier **once, at boot**, and keep it: the circuit load takes 44–73
seconds. It is a startup cost, never a per-request one.

## The one rule: `ok` and `over_threshold` are different questions

```
ok              → did we get a trustworthy answer at all?
over_threshold  → what was the answer?
```

**When `ok` is `false`, `over_threshold` is `null` — never `false`.**

A verifier that cannot verify is *broken*, and a broken verifier that reports "no"
would turn away every legitimate adult while sounding exactly like a working one.
So: **deny entry on `ok:false` (fail closed), but do not tell the visitor they are
underage.** Those are different sentences, and conflating them is the single
easiest way to ship a confidently-wrong age gate.

```js
if (!v.ok) {
  // 503 / "we couldn't verify right now" — and page someone.
} else if (v.over_threshold) {
  // in
} else {
  // "you do not meet the age requirement" — this is a real cryptographic verdict
}
```

## Public API

### `provision(dir, opts?) → Promise<{dir, present, fetched}>`

Fetches the 17 pinned circuit files (4.3 MB) into `dir`, verifying every byte
against a sha256 pinned to upstream commit `d8ad8f65`. Idempotent, atomic, and
self-healing: a circuit that rots on disk is detected and re-fetched. A byte that
does not match the pin is deleted and provisioning stops.

- `opts.onProgress` — `({id, action, n, of}) => void`
- `opts.fetchImpl` — inject a `fetch` (used by the test suite; no network needed)

### `Verifier.start(opts) → Promise<Verifier>`

Throws if it cannot produce a verifier you can trust. See [All options](#all-options).

### `verifier.check(proof) → Promise<Verdict>`

Never throws. `proof` is `{transcript: Uint8Array, deviceResponse: Uint8Array}`.

### `verifier.stop() → Promise<void>`

SIGTERM, then SIGKILL after the grace period.

### `verifier.trustAnchors → {pem, vical, total}`

Exactly whom this verifier trusts, counted from the child's own log — not from
what you asked for. Audit it.

### `REASONS`

The closed set of `reason` values. Branch on these, never on `detail`.

| `ok` | `reason` | Means |
|---|---|---|
| `true` | `verified` | Over the threshold. The only path to a pass. |
| `true` | `zk_proof_invalid` | The proof does not verify. Tampered, or bound to another transcript. |
| `true` | `issuer_untrusted` | Chains to no root in your `caCerts`. |
| `true` | `proof_malformed` | Unparseable envelope or certificate chain. |
| `true` | `claim_absent` | Valid proof, but it does not attest the claim you required. |
| `true` | `claim_false` | The claim is present and it is `false`. Under the threshold. |
| `false` | `service_not_ready` | Still loading circuits, or not running. |
| `false` | `service_unreachable` | The child is not answering. |
| `false` | `service_timeout` | It answered too slowly. |
| `false` | `circuit_unavailable` | Misconfigured — we cannot answer, and this is **not** a verdict. |
| `false` | `response_unintelligible` | We did not understand the response. Refusing to guess. |
| `false` | `invalid_request` | You handed us something that is not a proof. |

### `classify(raw, opts?) → Verdict`

The pure verdict function, exported for testing and for anyone wrapping a
different transport. Never throws, whatever you hand it.

## All options

| Option | Default | What it does |
|---|---|---|
| `binary` | *required* | Path to the longfellow verifier service binary. |
| `circuitDir` | *required* | Directory of circuit files. Use `provision()`. |
| `caCerts` | *required* | **PEM bundle of trusted issuer roots. THE TRUST BOUNDARY.** |
| `threshold` | `18` | The age in "over N". The output stays one bit. |
| `vicalUrl` | **none** | Opt in to a network-fetched issuer trust list (VICAL). |
| `host` | `127.0.0.1` | Loopback, deliberately. |
| `port` | `8899` | |
| `startupTimeoutMs` | `180000` | Circuit load measured at 44–73 s. |
| `requestTimeoutMs` | `10000` | A verify is ~0.4–0.7 s. |
| `shutdownGraceMs` | `5000` | Then SIGKILL. |
| `env` | — | Extra environment for the child. It otherwise gets a *minimal* env, not yours. |

## Trust anchors — the whole security decision

**`caCerts` is the security boundary.** A proof is accepted only if its issuer
chains to a root in that bundle. Everything else in this library is plumbing
around that one decision.

**8een fetches no trust list over the network unless you explicitly ask.** The
upstream reference verifier defaults to pulling AAMVA's US motor-vehicle VICAL —
22 issuer certificates, over the network, at every boot, with a *non-fatal* failure
path that silently varies the anchor set. A trust boundary that changes with the
weather is not a trust boundary. Set `vicalUrl` only if you are deliberately
choosing to trust whoever it serves.

**8een refuses to start rather than serve a trust list it cannot vouch for:**

- **Zero anchors** → refuses. It would reject everyone as `issuer_untrusted`,
  confidently, and that is indistinguishable from a genuine "no".
- **A silently truncated bundle** → refuses. Upstream's PEM loader breaks out of
  its parse loop on a malformed boundary and *returns success*. Its own
  `certs.pem` has 19 certificates and loads 17, without a word. If you append your
  issuer CA to a bundle with a bad boundary, it is dropped in silence and every
  proof from that issuer is then rejected by a verifier reporting perfect health.
  8een counts the bundle and refuses if fewer loaded.
- **Anchors you did not configure** → refuses.
- **A partial circuit set** → refuses, for the same family of reasons.

If `start()` throws, read the message. It is telling you that a verifier you were
about to trust would have been quietly wrong.

## Architecture

Three layers. `circuits.js` puts the pre-computed circuit files on disk and
refuses any byte that is not the one we pinned. `service.js` supervises the
longfellow Go verifier as a long-lived child, and establishes readiness by reading
the child's **own log** — `/healthz` returns a hardcoded `200` and `/specs` lists
the binary's compiled-in specs rather than what actually loaded, so neither can be
trusted. `verdict.js` is pure, never throws, and turns one exchange into one bit.

## Threat model summary

**Replay is accepted. This module does not stop it and does not pretend to.**

The verifier is stateless. Hand it the same valid proof a thousand times and it
will say "valid" a thousand times — because it *is* valid. A replayed proof is
mathematically indistinguishable from a fresh one; the cryptography cannot know a
proof has been spent, because knowing that requires *memory*.

**Freshness is your job.** The relying party must:

1. Mint a **nonce** per visit — a random number *you* generate, before any proof exists.
2. Send it to the wallet, which binds it into the session transcript.
3. On the way back: check the nonce is one you issued, **spend it** (delete it), and
   refuse any proof carrying a nonce you have already spent or never issued.

Skip step 3 and a fourteen-year-old walks in with a borrowed proof file, while
8een correctly reports "valid" every single time. **A gate built on this module
without nonce bookkeeping is not an age gate.**

Other properties:

- **Claims are attacker-controlled until `Status` is true.** A *rejected* proof
  still echoes `age_over_18: true` from its unverified envelope. 8een gates on the
  verdict, never on the claims, and so must anything you build on it. Do not read
  raw claims out of the underlying service.
- **Stores nothing.** No proofs, no transcripts, no identifiers. There is nothing
  to breach, subpoena, or sell.
- **Loopback by default.** The child binds `127.0.0.1`; upstream's default binds
  every interface.
- **Minimal child environment.** The verifier does not inherit your process's env.

## Gotchas

- **Startup is 44–73 seconds**, not "about 45". Anything assuming a fixed number is
  wrong. Start once, at boot, and keep the instance.
- **`ok:false` is not a "no".** See [the one rule](#the-one-rule-ok-and-over_threshold-are-different-questions).
- **`detail` is diagnostic.** It carries upstream's wording and may change. Branch
  on `reason`.
- **An over-18 proof does not satisfy `threshold: 21`.** You get `claim_absent`,
  not a pass. The threshold is what *you* asked for, not what the proof offers.

## Constraints

- **Node ≥ 22.** Zero runtime dependencies.
- **You must supply the `binary`.** 8een drives the longfellow verifier service
  (~10.5 MB, built from C++/cgo). **This package does not ship it**, so
  `npm install zk8een` alone will not verify anything. Bundling or building it is
  tracked work, not a decision you can configure around today.
- **No EU trust-list ingestion — but the anchors now exist.** 8een consumes a PEM
  bundle and an ISO 18013-5 VICAL (the US/AAMVA format); it does **not** parse the
  ETSI-signed XML that eIDAS trust lists use. What has changed is the source: the EU
  now publishes a dedicated **AV Trusted List** (ETSI XML, service type `PAA`, for
  `eu.europa.ec.av.*` credentials), with an acceptance environment for testing. So
  an EU deployment is no longer a dead end — you extract the PAA X.509 certificates
  from that list and drop them into the PEM bundle you pass as `caCerts`. That
  extraction is your step, not 8een's: the XML is signed and 8een does not verify
  that signature, so treat the list as input you vouch for, exactly as you would any
  PEM you assemble by hand.
