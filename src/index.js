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
 * What this does NOT do, and must not be mistaken for doing: freshness. This
 * verifier is stateless. Hand it the same valid proof a thousand times and it
 * will say "valid" a thousand times, because it is -- the maths cannot know a
 * proof has been spent before. Replay defence is the relying party's duty: mint
 * a nonce per visit, bind it into the session transcript, and refuse to spend
 * the same nonce twice. That is the gate (M4), not the verifier (M1). Shipping
 * this module alone, without nonce bookkeeping, would verify beautifully and
 * still admit a fourteen-year-old holding a borrowed proof.
 */

import { VerifierService } from './service.js';
import { classify, REASONS } from './verdict.js';
import { provision, manifest } from './circuits.js';

export { REASONS, classify, VerifierService, provision, manifest };

export class Verifier {
  /** @type {VerifierService} */
  #service;
  /** @type {string} */
  #requiredClaim;
  /** @type {boolean} */
  #requireCurrentValidity;
  /** @type {number} */
  #toleranceMs;

  /**
   * @param {VerifierService} service       a service you have already started
   * @param {string} requiredClaim          e.g. `age_over_18`
   * @param {{requireCurrentValidity?: boolean, toleranceMs?: number}} [policy]
   */
  constructor(service, requiredClaim, policy = {}) {
    const toleranceMs = policy.toleranceMs ?? 300_000;
    // Validate here, like the threshold: a bad tolerance must fail LOUD at construction,
    // not silently disable the freshness gate at verify time (classify also fails closed
    // on it, but the adopter should learn about their config error immediately).
    if (typeof toleranceMs !== 'number' || !Number.isFinite(toleranceMs) || toleranceMs < 0) {
      throw new TypeError(`toleranceMs must be a non-negative finite number, got ${policy.toleranceMs}`);
    }
    this.#service = service;
    this.#requiredClaim = requiredClaim;
    this.#requireCurrentValidity = policy.requireCurrentValidity ?? true;
    this.#toleranceMs = toleranceMs;
  }

  /**
   * Provision circuits first (see {@link provision}), then start one of these and
   * keep it: the circuit load takes 44-73s, so it is a boot cost, not a per-request one.
   *
   * @param {import('./types.js').ServiceInit & {threshold?: number,
   *   requireCurrentValidity?: boolean, toleranceMs?: number}} opts
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
    });
  }

  get ready() {
    return this.#service.ready;
  }

  get circuitsLoaded() {
    return this.#service.circuitsLoaded;
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
    return classify(await this.#service.verify(proof), {
      requiredClaim: this.#requiredClaim,
      requireCurrentValidity: this.#requireCurrentValidity,
      toleranceMs: this.#toleranceMs,
      now: Date.now(),
    });
  }

  /** @returns {Promise<void>} */
  async stop() {
    return this.#service.stop();
  }
}
