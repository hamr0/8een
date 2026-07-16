/**
 * 8een -- the verifier half.
 *
 * A site asks one question and gets one bit back:
 *
 *     const v = await verifier.check({ transcript, deviceResponse });
 *     if (v.ok && v.over_threshold) allowEntry();
 *     else if (!v.ok) serveError();      // we are broken -- do NOT tell them they are underage
 *     else denyEntry();                  // a real, cryptographic no
 *
 * Freshness is a SEPARATE layer, off by default. The verifier is stateless: hand
 * it the same valid proof a thousand times and it will say "valid" a thousand
 * times, because it is -- the maths cannot know a proof has been spent before.
 * Replay defence is opt-in (`requireSingleUse`, M4 piece 2): when on, `check()`
 * confirms the proof is bound to a live, unspent challenge THIS verifier issued
 * (`issueChallenge()`) and spends it once through an adopter-supplied `nonceStore`
 * -- 8een still stores nothing itself. With it OFF, shipping this module without
 * your own nonce bookkeeping would verify beautifully and still admit a
 * fourteen-year-old holding a borrowed proof. The gate only ever downgrades an
 * accept to `ok:false` (`replay_detected`/`session_unknown`), never a "no".
 */

import { VerifierService } from './service.js';
import { classify, REASONS } from './verdict.js';
import { provision, manifest } from './circuits.js';
import { issueChallenge, inspectChallenge, applySingleUse, InMemoryNonceStore } from './challenge.js';

export {
  REASONS,
  classify,
  VerifierService,
  provision,
  manifest,
  issueChallenge,
  inspectChallenge,
  applySingleUse,
  InMemoryNonceStore,
};

// The HTTP gate (M4 piece 3) is the "adopt without thinking" layer: replay-safe by
// default. It lives in its own module because it imports `Verifier` from here.
export { createGate, startGate, GATE_REASONS } from './gate.js';

export class Verifier {
  /** @type {VerifierService} */
  #service;
  /** @type {string} */
  #requiredClaim;
  /** @type {boolean} */
  #requireCurrentValidity;
  /** @type {number} */
  #toleranceMs;
  /** @type {boolean} */
  #requireSingleUse;
  /** @type {Buffer|Uint8Array|string|undefined} */
  #challengeSecret;
  /** @type {import('./types.js').NonceStore|undefined} */
  #nonceStore;
  /** @type {number} */
  #challengeTtlMs;

  /**
   * @param {VerifierService} service       a service you have already started
   * @param {string} requiredClaim          e.g. `age_over_18`
   * @param {{requireCurrentValidity?: boolean, toleranceMs?: number,
   *   requireSingleUse?: boolean, challengeSecret?: Buffer|Uint8Array|string,
   *   nonceStore?: import('./types.js').NonceStore, challengeTtlMs?: number}} [policy]
   */
  constructor(service, requiredClaim, policy = {}) {
    const toleranceMs = policy.toleranceMs ?? 300_000;
    // Validate here, like the threshold: a bad tolerance must fail LOUD at construction,
    // not silently disable the freshness gate at verify time (classify also fails closed
    // on it, but the adopter should learn about their config error immediately).
    if (typeof toleranceMs !== 'number' || !Number.isFinite(toleranceMs) || toleranceMs < 0) {
      throw new TypeError(`toleranceMs must be a non-negative finite number, got ${policy.toleranceMs}`);
    }
    const requireSingleUse = policy.requireSingleUse ?? false;
    const challengeTtlMs = policy.challengeTtlMs ?? 300_000;
    // Validate the ttl BEFORE it is used to mint the eager throwaway challenge below,
    // so a bad value fails with this specific message rather than issueChallenge's.
    if (typeof challengeTtlMs !== 'number' || !Number.isFinite(challengeTtlMs) || challengeTtlMs <= 0) {
      throw new TypeError(`challengeTtlMs must be a positive finite number, got ${policy.challengeTtlMs}`);
    }
    // Single-use CANNOT fail open. If it is required, the two things it depends on --
    // the secret that authenticates our own nonces, and the shared store that
    // remembers spent ones -- must both be present, or we would silently verify
    // replays while looking replay-safe (the exact "looks safe, isn't" trap). We
    // never fall back to an in-memory store: that only holds per-process and would
    // wave replays past behind multiple replicas. Fail LOUD at construction instead.
    if (requireSingleUse) {
      if (policy.challengeSecret == null) {
        throw new TypeError('requireSingleUse needs a challengeSecret (>= 16 bytes) to authenticate nonces');
      }
      if (policy.nonceStore == null || typeof policy.nonceStore.spend !== 'function') {
        throw new TypeError(
          'requireSingleUse needs a nonceStore with an atomic spend(key, ttlMs); pass a shared ' +
            'store (e.g. Redis SET NX PX), or InMemoryNonceStore for single-process dev only',
        );
      }
      // Validate the secret eagerly by minting one throwaway challenge; a weak secret
      // must be an immediate construction error, not a first-request surprise.
      issueChallenge({ secret: policy.challengeSecret, ttlMs: challengeTtlMs });
    }
    this.#service = service;
    this.#requiredClaim = requiredClaim;
    this.#requireCurrentValidity = policy.requireCurrentValidity ?? true;
    this.#toleranceMs = toleranceMs;
    this.#requireSingleUse = requireSingleUse;
    this.#challengeSecret = policy.challengeSecret;
    this.#nonceStore = policy.nonceStore;
    this.#challengeTtlMs = challengeTtlMs;
  }

  /**
   * Provision circuits first (see {@link provision}), then start one of these and
   * keep it: the circuit load takes 44-73s, so it is a boot cost, not a per-request one.
   *
   * @param {import('./types.js').ServiceInit & {threshold?: number,
   *   requireCurrentValidity?: boolean, toleranceMs?: number,
   *   requireSingleUse?: boolean, challengeSecret?: Buffer|Uint8Array|string,
   *   nonceStore?: import('./types.js').NonceStore, challengeTtlMs?: number}} opts
   *   `caCerts` IS THE TRUST BOUNDARY: a proof is accepted only if its issuer chains
   *   to one of those roots. Choose it deliberately -- it is the whole security
   *   decision. `vicalUrl` opts in to a network-fetched issuer trust list (ISO
   *   18013-5 VICAL); the default is NONE, because a trust boundary that changes
   *   with the weather is not a trust boundary. `threshold` is the age in "over N"
   *   (PRD D6, default 18); the output stays a single bit either way.
   *
   *   `requireCurrentValidity` (default `true`) refuses a proof whose credential
   *   validity window is not current -- an expired credential is a real "no"
   *   (`over_threshold:false`, reason `credential_expired`), and an unreadable
   *   presentation date is `ok:false` (`freshness_unknown`), never a "no" (PRD §7.4).
   *   Turn it OFF only if the site cares about age alone and not credential currency:
   *   an expired credential STILL proves the holder is an adult (age does not run
   *   backwards), so age-gates may accept it while KYC-style flows must not. Replay
   *   defence is separate (the gate's per-session nonce), so this does not affect it.
   *   `toleranceMs` (default 5 min) is how far the presentation timestamp may sit
   *   from the real clock.
   *
   *   `requireSingleUse` (default `false`) turns on replay defence: only a proof
   *   bound to a live, unspent challenge THIS verifier issued is accepted; a replay
   *   is `ok:false` (`replay_detected`), an unrecognized/expired challenge is
   *   `ok:false` (`session_unknown`) -- never a "no". Unlike currency, this cannot
   *   default on: it needs adopter infrastructure it cannot invent -- a
   *   `challengeSecret` (>= 16 bytes, stable and shared across replicas) and a
   *   shared `nonceStore` with an atomic `spend(key, ttlMs)` (e.g. Redis
   *   `SET NX PX`; `InMemoryNonceStore` for single-process dev). Enabling it without
   *   both throws at construction rather than fail open. Issue challenges with
   *   `verifier.issueChallenge()`. `challengeTtlMs` (default 5 min) is the nonce
   *   lifetime. **8een is not replay-safe unless this is on.**
   * @returns {Promise<Verifier>}
   */
  static async start(opts) {
    const threshold = opts?.threshold ?? 18;
    if (!Number.isInteger(threshold) || threshold < 1) {
      throw new TypeError(`threshold must be a positive integer, got ${opts?.threshold}`);
    }
    const service = new VerifierService(opts);
    await service.start();
    return new Verifier(service, `age_over_${threshold}`, {
      requireCurrentValidity: opts?.requireCurrentValidity,
      toleranceMs: opts?.toleranceMs,
      requireSingleUse: opts?.requireSingleUse,
      challengeSecret: opts?.challengeSecret,
      nonceStore: opts?.nonceStore,
      challengeTtlMs: opts?.challengeTtlMs,
    });
  }

  get ready() {
    return this.#service.ready;
  }

  get circuitsLoaded() {
    return this.#service.circuitsLoaded;
  }

  /** Whether replay defence is on -- the gate reads this to stay replay-safe by default. */
  get requiresSingleUse() {
    return this.#requireSingleUse;
  }

  /** Exactly whom this verifier trusts, counted from the child's own log. */
  get trustAnchors() {
    return this.#service.trustAnchors;
  }

  /**
   * Verify one proof. Never throws.
   *
   * @param {import('./types.js').Proof} proof
   * @returns {Promise<import('./types.js').Verdict>}
   */
  async check(proof) {
    const now = Date.now();
    const verdict = classify(await this.#service.verify(proof), {
      requiredClaim: this.#requiredClaim,
      requireCurrentValidity: this.#requireCurrentValidity,
      toleranceMs: this.#toleranceMs,
      now,
    });
    // Single-use is layered AFTER the stateless verdict, and only downgrades an
    // accept: a replayed or unrecognized session becomes `ok:false` (never a "no").
    // It reads the nonce from the transcript the proof was actually bound to.
    if (this.#requireSingleUse) {
      // Both are guaranteed set by the constructor whenever requireSingleUse is on.
      return applySingleUse(verdict, proof?.transcript, {
        secret: /** @type {Buffer|Uint8Array|string} */ (this.#challengeSecret),
        store: /** @type {import('./types.js').NonceStore} */ (this.#nonceStore),
        now,
      });
    }
    return verdict;
  }

  /**
   * Mint a single-use challenge for one visit, bound to this verifier's secret and
   * TTL. Send `transcript` to the wallet; on the way back, `check()` spends it.
   * Only available when the verifier was started with `requireSingleUse`.
   *
   * @returns {import('./types.js').Challenge}
   */
  issueChallenge() {
    if (!this.#requireSingleUse) {
      throw new Error('issueChallenge requires the verifier to be started with requireSingleUse');
    }
    return issueChallenge({
      secret: /** @type {Buffer|Uint8Array|string} */ (this.#challengeSecret),
      ttlMs: this.#challengeTtlMs,
    });
  }

  /** @returns {Promise<void>} */
  async stop() {
    return this.#service.stop();
  }
}
