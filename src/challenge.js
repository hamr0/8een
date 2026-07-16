/**
 * The single-use nonce -- freshness's second half (M4 piece 2).
 *
 * The stateless verifier cannot know a proof has been spent: hand it the same
 * valid bytes twice and it says "valid" twice, because it is. That is a replay,
 * and defeating it needs exactly one thing the verifier refuses to hold -- memory
 * of what has been seen. This module supplies that as a challenge lifecycle that
 * keeps 8een itself stateless:
 *
 *   1. ISSUE a per-visit nonce. It is self-authenticating -- `random || expiry ||
 *      HMAC(secret, random||expiry)` -- so proving "I issued this, and it has not
 *      expired" is a recomputation, not a lookup. 8een stores NOTHING to issue.
 *   2. The wallet binds the nonce into the session transcript; longfellow binds
 *      the proof to that transcript (verified end-to-end: a proof bound to nonce A
 *      is refused under nonce B -- `merkle_check failed`). So the ONLY replay left
 *      is re-sending the byte-identical proof under its own nonce.
 *   3. SPEND the nonce once. The "already spent" set is the ONE irreducible piece
 *      of state, and it lives in the ADOPTER's store (Redis/DB/...), never here --
 *      8een asks `spend()` and believes the answer. NO-GO #7 ("we store nothing")
 *      holds for the library; the adopter keeps a self-cleaning, few-minutes-long
 *      set (a spent nonce need only be remembered until it expires; after that its
 *      own expiry stamp refuses it, with no memory needed).
 *
 * The §1 invariant extends here unchanged: a replayed or unrecognized session is
 * "we cannot confirm this presentation is fresh" -- `ok:false`, `over_threshold:
 * null` -- NEVER "you are underage". A replay is not evidence about a person.
 *
 * No CBOR parsing and no cryptography of our own (NO-GO #8): the HMAC and RNG are
 * node:crypto (a vetted stdlib), and the transcript frame we read is OUR OWN
 * issued frame, not longfellow's mdoc. Zero runtime dependencies (NO-GO #9).
 */

import { randomBytes, createHmac, timingSafeEqual } from 'node:crypto';
import { REASONS, unanswerable } from './verdict.js';

const RANDOM_LEN = 16;
const EXPIRY_LEN = 8; // uint64 BE, ms since epoch
const TAG_LEN = 32; // HMAC-SHA256
const PAYLOAD_LEN = RANDOM_LEN + EXPIRY_LEN; // 24
const NONCE_LEN = PAYLOAD_LEN + TAG_LEN; // 56

// The transcript frame 8een owns: the SessionTranscript stand-in
// [null, null, h'<nonce>'] == 83 F6 F6 <bstr nonce>. For a 56-byte nonce the CBOR
// byte-string header is 58 38, so a well-formed frame is exactly 61 bytes. This
// mirrors tools/mkfixture/mint.go `sessionTranscript()` byte-for-byte, because the
// prover and verifier must hash IDENTICAL transcript bytes or the binding fails.
const FRAME_PREFIX = Buffer.from([0x83, 0xf6, 0xf6]);
const FRAME_LEN = FRAME_PREFIX.length + 2 + NONCE_LEN; // 3 + (58 38) + 56 = 61

/** The CBOR byte-string header for `n` bytes, immediate/1-byte/2-byte forms. */
function bstrHeader(n) {
  if (n < 24) return Buffer.from([0x40 | n]);
  if (n < 256) return Buffer.from([0x58, n]);
  if (n < 65536) return Buffer.from([0x59, (n >> 8) & 0xff, n & 0xff]);
  throw new RangeError('nonce too long for a session transcript');
}

function assertSecret(secret) {
  // A short or absent secret is a config error that silently weakens the whole
  // gate; fail LOUD at the boundary rather than issue forgeable nonces.
  if (!(secret instanceof Uint8Array) && typeof secret !== 'string') {
    throw new TypeError('challenge secret must be a Buffer/Uint8Array or string');
  }
  if (secret.length < 16) {
    throw new TypeError('challenge secret must be at least 16 bytes of entropy');
  }
}

function hmac(secret, payload) {
  return createHmac('sha256', secret).update(payload).digest();
}

/**
 * Mint a fresh single-use challenge. Stores nothing: the nonce authenticates
 * itself.
 *
 * @param {{secret: Buffer|Uint8Array|string, ttlMs?: number, now?: number}} opts
 *   `secret` is the HMAC key -- stable across restarts and SHARED across every
 *   replica that verifies (a per-process secret would reject a sibling's nonces).
 *   Adopter-owned, like any signing key. `ttlMs` (default 5 min) is how long the
 *   challenge is answerable. `now` is injectable for testing (default `Date.now()`).
 * @returns {import('./types.js').Challenge}
 */
export function issueChallenge({ secret, ttlMs = 300_000, now = Date.now() }) {
  assertSecret(secret);
  if (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new TypeError(`ttlMs must be a positive finite number, got ${ttlMs}`);
  }
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    throw new TypeError(`now must be a finite number, got ${now}`);
  }
  const expiresAt = Math.floor(now + ttlMs);
  const payload = Buffer.alloc(PAYLOAD_LEN);
  randomBytes(RANDOM_LEN).copy(payload, 0);
  payload.writeBigUInt64BE(BigInt(expiresAt), RANDOM_LEN);
  const nonce = Buffer.concat([payload, hmac(secret, payload)]);
  const transcript = Buffer.concat([FRAME_PREFIX, bstrHeader(nonce.length), nonce]);
  return { nonce, transcript, expiresAt };
}

/**
 * Read a presented transcript and answer, from the bytes alone, "did I issue this
 * challenge, and has it expired?". Pure, constant-time on the tag, and NEVER throws
 * -- it is handed untrusted input at the verify boundary and must classify all of
 * it. Reads only 8een's OWN issued frame (81/61 fixed bytes); it is not a CBOR
 * parser and must never become one.
 *
 * @param {unknown} transcript  the bytes the proof was bound to (`proof.transcript`)
 * @param {{secret: Buffer|Uint8Array|string, now?: number}} opts
 * @returns {{recognized: boolean, expired: boolean, expiresAt: number|null,
 *   nonceKey: string|null}}
 *   `recognized` is true only when the frame is ours AND the HMAC verifies -- i.e.
 *   this is a challenge WE minted. `nonceKey` (base64url of the nonce) is the
 *   single-use key, present only when recognized.
 */
export function inspectChallenge(transcript, { secret, now = Date.now() }) {
  const no = { recognized: false, expired: false, expiresAt: null, nonceKey: null };
  try {
    assertSecret(secret);
    const buf = toBuffer(transcript);
    // The frame is a fixed shape WE issue. Any deviation means the proof is bound
    // to a transcript we did not challenge -- unrecognized, never "our nonce".
    if (!buf || buf.length !== FRAME_LEN) return no;
    if (!buf.subarray(0, 3).equals(FRAME_PREFIX)) return no;
    if (buf[3] !== 0x58 || buf[4] !== NONCE_LEN) return no;

    const nonce = buf.subarray(5);
    const payload = nonce.subarray(0, PAYLOAD_LEN);
    const mac = nonce.subarray(PAYLOAD_LEN);
    const expect = hmac(secret, payload);
    // timingSafeEqual requires equal lengths; mac is a fixed 32 by construction.
    if (mac.length !== expect.length || !timingSafeEqual(mac, expect)) return no;

    const expiresAt = Number(payload.readBigUInt64BE(RANDOM_LEN));
    const expired = !(typeof now === 'number' && Number.isFinite(now)) || now > expiresAt;
    return { recognized: true, expired, expiresAt, nonceKey: nonce.toString('base64url') };
  } catch {
    // Any surprise in untrusted-input handling is "not a nonce we can vouch for".
    return no;
  }
}

/**
 * The single-use gate. Given an already-classified verdict and the transcript the
 * proof was cryptographically bound to, refuse a replayed or unrecognized session.
 *
 * It only ever DOWNGRADES an accept to `ok:false`. It never flips a "no" into a
 * "yes", and a replayed under-age proof stays a "no" untouched -- we do not need a
 * nonce to keep saying no. A spent or unrecognized nonce is "cannot confirm
 * freshness" (`ok:false`), never a verdict about a person (the §1 invariant).
 *
 * The nonce is taken from `transcript` -- the bytes longfellow actually bound the
 * proof to -- NOT from any separately-supplied value, so a caller cannot present a
 * fresh unspent nonce alongside a proof bound to a stale one.
 *
 * Async, because the spent-set is the adopter's. 8een spends through the hook and
 * believes it; it holds no set itself.
 *
 * @param {import('./types.js').Verdict} verdict  the verdict from `classify()`
 * @param {unknown} transcript                    `proof.transcript`
 * @param {{secret: Buffer|Uint8Array|string, store: import('./types.js').NonceStore,
 *   now?: number}} opts
 * @returns {Promise<import('./types.js').Verdict>}
 */
export async function applySingleUse(verdict, transcript, { secret, store, now = Date.now() }) {
  // Only an otherwise-clean accept is worth a nonce. A "no", or a broken-verifier
  // `ok:false`, passes straight through -- and crucially, a proof that did NOT
  // verify never reaches `spend()`, so garbage cannot exhaust a legitimate nonce.
  if (!(verdict.ok === true && verdict.over_threshold === true)) return verdict;

  const c = inspectChallenge(transcript, { secret, now });
  if (!c.recognized) {
    return unanswerable(
      REASONS.SESSION_UNKNOWN,
      'the presentation is not bound to a challenge this verifier issued',
    );
  }
  if (c.expired) {
    // A stale challenge is "ask again", not "you are underage". Still ok:false.
    return unanswerable(
      REASONS.SESSION_UNKNOWN,
      `the issued challenge expired at ${new Date(/** @type {number} */ (c.expiresAt)).toISOString()}`,
    );
  }

  // Atomic record-if-absent: true == first use (fresh), false == already spent
  // (replay). One round trip, no check-then-set race.
  const ttlMs = Math.max(0, /** @type {number} */ (c.expiresAt) - now);
  // Guaranteed a string here: `recognized` implies a nonceKey was set.
  const fresh = await store.spend(/** @type {string} */ (c.nonceKey), ttlMs);
  if (!fresh) {
    return unanswerable(
      REASONS.REPLAY_DETECTED,
      'this presentation was already spent in its session (replay)',
    );
  }
  return verdict;
}

function toBuffer(v) {
  if (Buffer.isBuffer(v)) return v;
  if (v instanceof Uint8Array) return Buffer.from(v.buffer, v.byteOffset, v.byteLength);
  return null;
}

/**
 * A non-durable, single-process spent-nonce store. FOR DEVELOPMENT ONLY.
 *
 * It satisfies the {@link import('./types.js').NonceStore} interface with a plain
 * Map, so the gate works out of the box on one machine. It does NOT survive a
 * restart and -- the reason it must never back a real deployment -- it is NOT
 * shared across processes: behind two replicas, a replay routed to the replica
 * that did not see the first use is ACCEPTED. Replay defence that silently holds
 * only per-process is the exact "looks safe, isn't" failure this project exists to
 * catch. Use Redis (`SET key NX PX ttl`) or an equivalent shared store in
 * production. You must construct this by name -- the `Verifier` never falls back to
 * it silently.
 */
export class InMemoryNonceStore {
  /** @type {Map<string, number>} nonceKey -> expiry (ms since epoch) */
  #seen = new Map();

  constructor({ quiet = false } = {}) {
    if (!quiet) {
      // eslint-disable-next-line no-console
      console.warn(
        '[8een] InMemoryNonceStore is for development only: it is not shared across ' +
          'processes, so it does NOT stop replays behind multiple replicas. Use a ' +
          'shared store (e.g. Redis SET NX PX) in production.',
      );
    }
  }

  /**
   * @param {string} nonceKey
   * @param {number} ttlMs
   * @returns {Promise<boolean>} true if newly recorded (first use), false if replay
   */
  async spend(nonceKey, ttlMs) {
    const now = Date.now();
    const existing = this.#seen.get(nonceKey);
    // `>= now` (inclusive): a nonce is still spent AT its expiry instant, so a replay
    // arriving in the exact expiry millisecond -- where the gate hands us ttlMs 0 -- is
    // still refused rather than slipping through on an exclusive `>`.
    if (existing !== undefined && existing >= now) return false;
    this.#seen.set(nonceKey, now + ttlMs);
    // Opportunistic sweep so the map cannot grow without bound under load. Delete only
    // STRICTLY-past entries, matching the inclusive "still present at expiry" above.
    if (this.#seen.size > 1024) {
      for (const [k, exp] of this.#seen) if (exp < now) this.#seen.delete(k);
    }
    return true;
  }
}
