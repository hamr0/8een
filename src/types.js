// SPDX-License-Identifier: Apache-2.0
/**
 * Shared shapes, as JSDoc typedefs. This file emits its own `.d.ts`, so adopters
 * see these types in their editor; nothing here has a runtime body.
 *
 * JSDoc is the ONLY hand-authored source of types in this package. The `.d.ts`
 * files are generated from it by `tsc` and never committed, so the two cannot
 * drift apart (LIBRARY_CONVENTIONS §2).
 */

/**
 * A proof as it arrives from a wallet: the session transcript it was bound to,
 * and the ZK device response (CBOR) that carries the proof itself.
 *
 * @typedef {object} Proof
 * @property {Uint8Array} transcript      OpenID4VP session transcript (CBOR).
 * @property {Uint8Array} deviceResponse  ZK device response (CBOR).
 */

/**
 * A single-use challenge, minted by `issueChallenge()`. Send `transcript` to the
 * wallet to bind the proof to; keep nothing (the nonce authenticates itself).
 *
 * @typedef {object} Challenge
 * @property {Uint8Array} nonce        The self-authenticating nonce (random ‖ expiry ‖ HMAC).
 * @property {Uint8Array} transcript   The session transcript bytes to hand the wallet.
 * @property {number} expiresAt        When the challenge stops being answerable (ms since epoch).
 */

/**
 * The adopter's spent-nonce set -- the ONE piece of state 8een refuses to hold.
 * A single atomic operation, so there is no check-then-set race under concurrent
 * replays. Maps directly onto Redis `SET key 1 NX PX ttl`.
 *
 * @typedef {object} NonceStore
 * @property {(nonceKey: string, ttlMs: number) => Promise<boolean> | boolean} spend
 *   Record `nonceKey` if absent and return `true` (first, legitimate use); return
 *   `false` if it was already present (a replay). `ttlMs` is how long to remember
 *   it -- exactly until the nonce expires, never longer.
 */

/**
 * One exchange with the verifier, before it means anything. `service.verify()`
 * produces these; `classify()` turns them into a verdict.
 *
 * @typedef {{kind: 'response', status: number, body: unknown}
 *   | {kind: 'timeout', detail?: string}
 *   | {kind: 'unreachable', detail?: string}
 *   | {kind: 'not_ready', detail?: string}
 *   | {kind: 'invalid_request', detail?: string}} Outcome
 */

/**
 * The answer. Read `ok` before `over_threshold`, always.
 *
 * `ok` says whether we got an answer at all. `over_threshold` says what the
 * answer was. When `ok` is false, `over_threshold` is `null` -- never `false` --
 * because a verifier that cannot verify is broken, and a broken verifier
 * reporting "no" would turn away every legitimate adult while sounding exactly
 * like a working one. Deny entry on `ok:false`, but do not tell the visitor they
 * are underage. Those are different sentences.
 *
 * @typedef {object} Verdict
 * @property {boolean} ok                    Did we get a trustworthy answer at all?
 * @property {boolean|null} over_threshold   The answer, or `null` if there isn't one.
 * @property {string} reason                 A value from `REASONS`.
 * @property {string} [detail]               Diagnostic only. Never branch on this.
 */

/**
 * How the verifier subprocess is configured.
 *
 * @typedef {object} ServiceInit
 * @property {string} binary       Path to the longfellow verifier service binary.
 * @property {string} circuitDir   Directory of circuit files (see `provision()`).
 * @property {string} caCerts      PEM bundle of trusted issuer roots. THE trust boundary.
 * @property {string} [vicalUrl]   Opt in to a network-fetched issuer trust list. Default: none.
 * @property {string} [host]       Default `127.0.0.1`. Loopback, deliberately.
 * @property {number} [port]       Default `8899`.
 * @property {number} [startupTimeoutMs]  Default 180000. Circuit load is 44-73s.
 * @property {number} [requestTimeoutMs]  Default 10000. A verify is ~0.4-0.7s.
 * @property {number} [shutdownGraceMs]   Default 5000, then SIGKILL.
 * @property {Record<string, string>} [env]  Extra environment for the child.
 */

/**
 * The same, with every default resolved.
 *
 * @typedef {object} ServiceOptions
 * @property {string} binary
 * @property {string} circuitDir
 * @property {string} caCerts
 * @property {string|null} vicalUrl
 * @property {string} host
 * @property {number} port
 * @property {number} startupTimeoutMs
 * @property {number} requestTimeoutMs
 * @property {number} shutdownGraceMs
 * @property {Record<string, string>} [env]
 */

/**
 * How the child exited, or the error that killed it.
 *
 * @typedef {object} ChildExit
 * @property {number|null} code
 * @property {NodeJS.Signals|null} signal
 * @property {string} [error]
 */

export {};
