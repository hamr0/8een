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

  /**
   * @param {VerifierService} service       a service you have already started
   * @param {string} requiredClaim          e.g. `age_over_18`
   */
  constructor(service, requiredClaim) {
    this.#service = service;
    this.#requiredClaim = requiredClaim;
  }

  /**
   * Provision circuits first (see {@link provision}), then start one of these and
   * keep it: the circuit load takes 44-73s, so it is a boot cost, not a per-request one.
   *
   * @param {import('./types.js').ServiceInit & {threshold?: number}} opts
   *   `caCerts` IS THE TRUST BOUNDARY: a proof is accepted only if its issuer chains
   *   to one of those roots. Choose it deliberately -- it is the whole security
   *   decision. `vicalUrl` opts in to a network-fetched issuer trust list (ISO
   *   18013-5 VICAL); the default is NONE, because a trust boundary that changes
   *   with the weather is not a trust boundary. `threshold` is the age in "over N"
   *   (PRD D6, default 18); the output stays a single bit either way.
   * @returns {Promise<Verifier>}
   */
  static async start(opts) {
    const threshold = opts?.threshold ?? 18;
    if (!Number.isInteger(threshold) || threshold < 1) {
      throw new TypeError(`threshold must be a positive integer, got ${opts?.threshold}`);
    }
    const service = new VerifierService(opts);
    await service.start();
    return new Verifier(service, `age_over_${threshold}`);
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
    return classify(await this.#service.verify(proof), { requiredClaim: this.#requiredClaim });
  }

  /** @returns {Promise<void>} */
  async stop() {
    return this.#service.stop();
  }
}
