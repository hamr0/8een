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

- **The bare `Verifier` is not a full gate.** It does not manage sessions, cookies, or
  rate limits. It *can* issue and spend single-use nonces (opt-in `requireSingleUse`),
  but you still own the shared store it spends against. **The `startGate()` HTTP gate
  ([Public API](#startgateopts--promisehandler-express-verifier-stop)) is the full
  drop-in** — routes, rate limiting, and replay defence wired for you.
- **The bare `Verifier` is not replay-safe by default** (`requireSingleUse` off): a
  byte-identical proof replayed in its own session is accepted. **The gate flips this —
  `startGate()` is replay-safe by default** and refuses to boot single-use-on without a
  secret and store. So: use the gate, or turn `requireSingleUse` on yourself. Shipping
  the bare verifier as an age gate is the mistake that will bite you.
- **Not an issuer.** It mints nothing and stores nothing.
- **It drives a longfellow verifier binary this package does not bundle.** On
  **linux-x64**, `provisionBinary()` fetches a prebuilt, sha256-pinned one for you;
  on every other platform you build it yourself. See [Constraints](#constraints).

## Minimal usage

```js
import { Verifier, provision, provisionBinary } from 'zk8een';

await provision('./circuits');              // 17 pinned circuits, sha256-verified
await provisionBinary();                    // prebuilt verifier (linux-x64), sha256-pinned

const verifier = await Verifier.start({
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

### `provisionBinary(dir?, opts?) → Promise<{path, action}>`

Fetches the prebuilt longfellow verifier binary for this platform into `dir`
(default: the per-user cache, `$XDG_CACHE_HOME`/`~/.cache` + `/zk8een`), verifying
every byte against a sha256 pinned inside this package — the download host
(a GitHub release of this repo) is *untrusted*. The binary is built by a public
workflow from the pinned upstream commit plus 8een's tracked patch series, and a
binary is only released after the full integration suite passed against it on the
build runner. Idempotent; `action` is `'present'` or `'fetched'`.

Only **linux-x64** is pinned today. Any other platform throws, naming the
build-it-yourself path (`binary:`). Provision into the default dir and
`Verifier.start` / `startGate` find the binary with no `binary:` option;
provision elsewhere (`opts.platform` provisions for another target, e.g. into a
container image) and you pass the returned `path` yourself.

The cached filename carries the release tag
(`longfellow-verifier-linux-x64-longfellow-bin-1`), so two zk8een versions
pinning different releases coexist in one cache instead of overwriting each
other. Treat the path as ours: read it from the return value, do not construct it.

- `opts.platform` — default `${process.platform}-${process.arch}`
- `opts.onProgress` — `({asset, action}) => void`
- `opts.fetchImpl` — inject a `fetch` (used by the test suite; no network needed)

**What happens at start.** When `binary:` is omitted, the provisioned binary is
**re-hashed against the pin on every start**, and checked for executability: one
that rots, is swapped, or has lost its execute bit is refused with an error
naming the fix, never run. Unlike a circuit, a binary cannot be
integrity-checked by the service at load time, so start is the last moment
anyone can check it. This is automatic — there is no call for you to make.

### `Verifier.start(opts) → Promise<Verifier>`

Throws if it cannot produce a verifier you can trust. See [All options](#all-options).

### `verifier.check(proof) → Promise<Verdict>`

Never throws. `proof` is `{transcript: Uint8Array, deviceResponse: Uint8Array}`.

### `verifier.issueChallenge() → Challenge`

Only when started with `requireSingleUse`. Mints a single-use challenge
`{nonce, transcript, expiresAt}` bound to this verifier's secret and TTL. Send
`transcript` to the wallet; on the way back, `check()` spends the nonce. 8een stores
nothing to issue it — the nonce authenticates itself (`random ‖ expiry ‖ HMAC`).

### `InMemoryNonceStore`

A `nonceStore` for single-process **development only**. It is not shared across
processes, so it does **not** stop replays behind multiple replicas — use Redis
(`SET key NX PX ttl`) or an equivalent in production. You must construct it by name;
8een never falls back to it silently.

### `startGate(opts) → Promise<{handler, express, verifier, stop}>`

The drop-in HTTP gate, **replay-safe by default**. Takes the same options as
`Verifier.start` plus the gate options below, starts the verifier, and returns two
HTTP routes over it. `requireSingleUse` defaults **`true`** here (it defaults `false`
on the bare `Verifier`); running replay-open is a deliberate `requireSingleUse: false`.
With single-use on it needs a `challengeSecret` (≥16 bytes) and either a `nonceStore`
or `store: 'memory'` (single-process dev); missing either **throws before the circuit
load**, never fails open.

- `GET {basePath}/challenge` → `{nonce, transcript, expiresAt}` (base64url). Hand
  `transcript` to the wallet.
- `POST {basePath}/verify` — body `{transcript, deviceResponse}` (base64url) → the
  `Verdict` as JSON. **`ok:true` → HTTP 200** (read `over_threshold` in the body);
  **`ok:false` → HTTP 503** ("could not verify"), never a "denied person" status.
- `handler` — a bare `node:http` request listener. `express()` — a middleware; mount
  at root (`app.use(gate.express())`), it owns `basePath` and calls `next()` for
  everything else.
- Gate options: `basePath` (default `/8een`), `maxBodyBytes` (default 1 MB),
  `rateLimit` (`{limit, windowMs}`, default 60/min per IP; `false` to disable),
  `trustProxy` (default `false` — read `X-Forwarded-For` only behind a vetted proxy).

### `createGate({verifier, ...}) → {handler, express}`

The gate over a verifier you already started yourself. `startGate` is this plus the
replay-safe-by-default boot; reach for `createGate` only if you manage the `Verifier`
lifecycle directly. **Replay-safe by default here too:** it throws unless the verifier
reports `requiresSingleUse` (i.e. was started with `requireSingleUse`), or you pass
`allowReplay: true` to deliberately wrap a replay-open verifier — in which case
`/challenge` answers `404 challenge_disabled`. A malformed `rateLimit`, `maxBodyBytes`,
or `maxBodyReadMs` throws rather than silently un-bounding the endpoint.

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
| `true` | `credential_expired` | Valid proof, but the credential is not current (only when `requireCurrentValidity`). A real "no" — *not* under-age. |
| `false` | `service_not_ready` | Still loading circuits, or not running. |
| `false` | `service_unreachable` | The child is not answering. |
| `false` | `service_timeout` | It answered too slowly. |
| `false` | `circuit_unavailable` | Misconfigured — we cannot answer, and this is **not** a verdict. |
| `false` | `response_unintelligible` | We did not understand the response. Refusing to guess. |
| `false` | `invalid_request` | You handed us something that is not a proof. |
| `false` | `freshness_unknown` | Currency required, but no presentation date could be read. We could not judge — **not** a "no". |
| `false` | `replay_detected` | Single-use required and this nonce was already spent — a replay. We cannot confirm freshness. **Not** a "no". |
| `false` | `session_unknown` | Single-use required, but the proof is not bound to a live challenge we issued (unrecognized/forged/expired nonce). **Not** a "no". |

### `GATE_REASONS`

The closed set of `reason` values the **HTTP gate** returns for transport-level
refusals — the ones that never reach the verifier at all. Verdict reasons above
come back in the same `reason` field, so branch on both from one place.

Routes below are written against `{basePath}`, which defaults to `/8een` and is
configurable — a gate mounted at `/verify-age` answers `404 not_found` on
`/8een/challenge`.

| HTTP | `reason` | Means |
|---|---|---|
| 400 | `bad_request` | Body is not the `{transcript, deviceResponse}` shape (or the URL is unparseable). |
| 404 | `not_found` | No such gate route. Standalone handler only — under `express()` an unmatched path calls `next()` instead. |
| 404 | `challenge_disabled` | `GET {basePath}/challenge` on a replay-open gate — `startGate({requireSingleUse: false})`, or `createGate({allowReplay: true})`. No nonces are issued, so the route is off. |
| 405 | `method_not_allowed` | Right route, wrong verb. |
| 408 | `request_timeout` | The body arrived too slowly (`maxBodyReadMs`). |
| 413 | `payload_too_large` | The body exceeded `maxBodyBytes`. |
| 429 | `rate_limited` | **Rate**, not concurrency: more than `rateLimit.limit` requests from one client key within `rateLimit.windowMs` (default **60 per 60 s**). A strictly sequential client trips this. Per-process and best-effort — front your own limiter across replicas, or `rateLimit: false`. |
| 500 | `internal_error` | The gate itself failed. Never leaks detail to the client. |

### `classify(raw, opts?) → Verdict`

The pure verdict function, exported for testing and for anyone wrapping a
different transport. Never throws, whatever you hand it.

### `circuitsManifest`

The frozen pin the circuit downloads are checked against — upstream `commit`,
`path`, and a `sha256` + `bytes` per circuit. Read it if you want to vendor or
audit the artefacts; you never need it for normal use.

> **Deprecated, still working, gone in 0.6.0.** `manifest` (now
> `circuitsManifest` — same value, so migrating is a rename), `VerifierService`
> (the raw subprocess driver; `Verifier` wraps it), and `inspectChallenge` /
> `applySingleUse` (the internals `check()` calls) were exported before 0.5.0 and
> documented nowhere. They still resolve and still typecheck; they just carry
> `@deprecated` now. Hand-rolling replay defence out of the challenge internals is
> the failure `requireSingleUse` fails closed to prevent — use the gate.

## All options

| Option | Default | What it does |
|---|---|---|
| `binary` | *provisioned* | Path to the longfellow verifier service binary. Omit it after `provisionBinary()` — the provisioned binary is found in the default dir and re-hashed against the pin at every start. Pass a path to run your own build (the pin then deliberately does not apply). An empty or non-string value is a **config error and throws**, rather than silently falling back — it is what an unset `process.env.VERIFIER_BIN` looks like. |
| `circuitDir` | *required* | Directory of circuit files. Use `provision()`. |
| `caCerts` | *required* | **PEM bundle of trusted issuer roots. THE TRUST BOUNDARY.** |
| `threshold` | `18` | The age in "over N". The output stays one bit. |
| `requireCurrentValidity` | `true` | Refuse a credential whose validity window is not current. Expired → `credential_expired` (a real "no"); unreadable date → `freshness_unknown` (`ok:false`). See [Credential currency](#credential-currency). |
| `toleranceMs` | `300000` | How far the presentation date may sit from the real clock (5 min). Only used when `requireCurrentValidity`. |
| `requireSingleUse` | `false` | Turn on replay defence: only a proof bound to a live, unspent challenge THIS verifier issued is accepted. Needs `challengeSecret` **and** `nonceStore`; enabling without both throws at construction. See [Replay defence](#threat-model-summary). |
| `challengeSecret` | *req. if `requireSingleUse`* | HMAC key that authenticates 8een's own nonces. **≥ 16 bytes, stable across restarts, shared across every replica.** A per-process secret would reject a sibling's nonces. |
| `nonceStore` | *req. if `requireSingleUse`* | Your shared spent-nonce set: `{ spend(key, ttlMs) → boolean }`, atomic (e.g. Redis `SET NX PX`). `InMemoryNonceStore` is provided for single-process **dev only** — it does not stop replays across replicas. |
| `challengeTtlMs` | `300000` | Nonce lifetime (5 min). A spent nonce need only be remembered this long. |
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

## Credential currency

By default (`requireCurrentValidity: true`) 8een refuses a credential whose validity
window is not current. This is a separate question from age: a proof attests *"at time
T, the holder was over 18,"* and 8een confirms **T is really now** (within `toleranceMs`,
default 5 min) before accepting. Without this the ZK layer checks the window against a
time the *prover* supplies, so an expired credential would verify.

- **Expired / stale** → `ok:true, over_threshold:false`, `credential_expired`. A real "no"
  — distinct from `claim_false` (a genuinely under-age holder). Deny entry; do not say
  "expired ID" unless your flow wants to.
- **Date could not be read** → `ok:false`, `freshness_unknown`. We could not judge, so we
  refuse to — **never** reported as a "no". Fail closed on `ok:false`, as always.

**Turn it off (`requireCurrentValidity: false`) only if you care about age alone.** An
expired ID still *proves adulthood* — age does not run backwards — so an age-gate may
accept it, while a KYC-style flow that needs a *current* government credential must not.
This does **not** affect replay: a byte-identical proof replayed in its own session is
still accepted (the verifier is stateless — bind a per-visit nonce into the transcript
yourself; see the note on freshness).

## Architecture

Three layers. `circuits.js` puts the pre-computed circuit files on disk and
refuses any byte that is not the one we pinned. `service.js` supervises the
longfellow Go verifier as a long-lived child, and establishes readiness by reading
the child's **own log** — `/healthz` returns a hardcoded `200` and `/specs` lists
the binary's compiled-in specs rather than what actually loaded, so neither can be
trusted. `verdict.js` is pure, never throws, and turns one exchange into one bit.

## Threat model summary

**Replay defence is opt-in. With `requireSingleUse` off (the default), replay is
accepted and 8een does not pretend otherwise.**

The verifier itself is stateless. Hand it the same valid proof a thousand times and
it will say "valid" a thousand times — because it *is* valid. A replayed proof is
mathematically indistinguishable from a fresh one; the cryptography cannot know a
proof has been spent, because knowing that requires *memory*.

### Replay defence (`requireSingleUse`)

Turn it on and 8een supplies the memory-shaped part of the flow while staying
stateless itself:

1. `const {nonce, transcript} = verifier.issueChallenge()` — a per-visit challenge,
   self-authenticating (8een stores nothing to mint it).
2. Send `transcript` to the wallet, which binds the proof to it. longfellow enforces
   that binding: a proof bound to nonce A is refused under nonce B.
3. `verifier.check({transcript, deviceResponse})` — on an otherwise-valid proof, 8een
   confirms the nonce is one it issued and unexpired, **spends it once**, and refuses
   the byte-identical replay: `ok:false, replay_detected`.

**What is still yours:** the session plumbing, and a **shared** `nonceStore` (the
spent-nonce set — Redis or equivalent). That store is the one irreducible piece of
state; 8een holds none of it. `InMemoryNonceStore` is dev-only and does not hold
across replicas.

**With it off**, skip nonce bookkeeping entirely and a fourteen-year-old walks in
with a borrowed proof file, while 8een correctly reports "valid" every single time.
**A gate built on the bare `Verifier` without single-use is not an age gate** unless
you do the equivalent nonce bookkeeping yourself.

**The `startGate()` HTTP gate does that bookkeeping for you, and defaults it ON.** It
issues and spends the nonce across its two routes, and refuses to boot if single-use is
on without a secret and store — so "adopt without reading this section" lands on the
safe path, not the footgun. Running it replay-open is a deliberate, typed
`requireSingleUse: false`. The bare-`Verifier` default stays OFF because a library
primitive cannot invent a shared secret and store; the gate, one layer up, can demand
them.

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
- **The verifier binary is fetched, not bundled.** 8een drives the longfellow
  verifier service (10.1 MB, built from C++/cgo); the npm tarball does not contain
  it. On **linux-x64**, `provisionBinary()` downloads a prebuilt one and verifies
  it against a sha256 pinned in this package (see the API section) — it needs
  ordinary system libraries only (glibc, libstdc++, libssl3, libzstd, zlib). On
  any other platform you build the binary from the documented steps
  ([`poc/M0-EVIDENCE.md`, step 1](https://github.com/hamr0/8een/blob/main/poc/M0-EVIDENCE.md))
  and pass its path as `binary:` — `npm install zk8een` alone still verifies
  nothing there.
- **glibc, not musl.** The prebuilt binary is glibc-linked, and Alpine reports
  itself as `linux-x64` exactly as Debian does — so it would match the manifest,
  download 10 MB, and only then fail to spawn. 8een detects musl and refuses at
  `provisionBinary()` / `Verifier.start()` with a message naming the cause. Use a
  glibc image (`node:22-bookworm-slim`) or build against musl and pass `binary:`.
- **`os`/`cpu` are intentionally unrestricted.** Bring-your-own-binary is
  first-class on every platform, so `package.json` does not block the install; the
  platform gap surfaces as a named runtime error instead of an install failure.
- **Pinned, not mirrored.** Circuits come from `google/longfellow-zk` at a pinned
  commit, the binary from this repo's releases. Substituted bytes are refused by
  sha256; an unreachable origin has no fallback host. Vendor the artefacts into
  your own image if you need that guarantee.
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
