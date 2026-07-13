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

export { REASONS, classify, VerifierService };

export class Verifier {
  #service;
  #requiredClaim;

  constructor(service, requiredClaim) {
    this.#service = service;
    this.#requiredClaim = requiredClaim;
  }

  /**
   * @param {object} opts
   * @param {string} opts.binary      path to the longfellow verifier service
   * @param {string} opts.circuitDir  directory of circuit files
   * @param {string} opts.caCerts     PEM bundle of trusted issuer roots
   * @param {number} [opts.threshold] the age in "over N" (PRD D6). Default 18.
   */
  static async start(opts = {}) {
    const threshold = opts.threshold ?? 18;
    if (!Number.isInteger(threshold) || threshold < 1) {
      throw new TypeError(`threshold must be a positive integer, got ${opts.threshold}`);
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

  /** @returns {Promise<{ok: boolean, over_threshold: boolean|null, reason: string, detail?: string}>} */
  async check(proof) {
    return classify(await this.#service.verify(proof), { requiredClaim: this.#requiredClaim });
  }

  async stop() {
    return this.#service.stop();
  }
}
