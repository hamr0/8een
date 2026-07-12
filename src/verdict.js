/**
 * Turns one raw exchange with the longfellow verifier service into one bit.
 *
 * The rule this module exists to hold:
 *
 *     `ok` says whether we got an answer at all.
 *     `over_threshold` says what the answer was.
 *
 * When `ok` is false, `over_threshold` is `null` -- never `false`. A verifier
 * that cannot verify is BROKEN, and a broken verifier that reports "no" would
 * deny every legitimate adult while sounding exactly like a working one. The
 * caller must deny entry on `ok:false` (fail closed) but must not tell the
 * visitor they are underage. Those are different sentences.
 *
 * Pure. Never throws. Never guesses.
 */

export const REASONS = Object.freeze({
  // We got an answer.
  VERIFIED: 'verified',
  ZK_PROOF_INVALID: 'zk_proof_invalid',
  ISSUER_UNTRUSTED: 'issuer_untrusted',
  PROOF_MALFORMED: 'proof_malformed',
  CLAIM_ABSENT: 'claim_absent',
  CLAIM_FALSE: 'claim_false',

  // We got no answer.
  SERVICE_UNREACHABLE: 'service_unreachable',
  SERVICE_TIMEOUT: 'service_timeout',
  SERVICE_NOT_READY: 'service_not_ready',
  CIRCUIT_UNAVAILABLE: 'circuit_unavailable',
  RESPONSE_UNINTELLIGIBLE: 'response_unintelligible',
});

/**
 * Return codes from run_mdoc_verifier (mdoc_zk.h MdocVerifierErrorCode) that
 * mean "this proof is bad" -- a true negative about the proof in hand.
 *
 * Everything NOT on this list (circuit parse failure, null input, argument
 * size, attribute-count mismatch, bad spec version) means the fault is OURS:
 * our circuit, our request, our configuration. Those are not verdicts about a
 * person. Unknown codes default to ours too, because the cost of misreading
 * "I am broken" as "you are underage" is a locked-out adult, while the reverse
 * costs only a less specific error message -- the gate denies entry either way.
 */
const PROOF_IS_BAD = new Map([
  [2, 'proof too small'],
  [3, 'hash parsing failure'],
  [4, 'signature parsing failure'],
  [5, 'zk verification failure'],
  [11, 'invalid cbor'],
]);

const VERIFY_FAILURE = /^verification failure: return code (\d+)$/;

const answered = (over_threshold, reason, detail) => ({ ok: true, over_threshold, reason, detail });
const unanswerable = (reason, detail) => ({ ok: false, over_threshold: null, reason, detail });

/**
 * @param {object} raw   outcome of one exchange, from the service wrapper:
 *                       {kind:'response', status, body} | {kind:'timeout'}
 *                       | {kind:'unreachable', detail} | {kind:'not_ready'}
 * @param {object} opts  {requiredClaim: 'age_over_18'} -- PRD D6, configurable
 *                       threshold, single-bit output.
 */
export function classify(raw, opts = {}) {
  const requiredClaim = opts.requiredClaim ?? 'age_over_18';

  if (!raw || typeof raw !== 'object') {
    return unanswerable(REASONS.RESPONSE_UNINTELLIGIBLE, `not an outcome: ${typeof raw}`);
  }

  switch (raw.kind) {
    case 'timeout':
      return unanswerable(REASONS.SERVICE_TIMEOUT, raw.detail);
    case 'unreachable':
      return unanswerable(REASONS.SERVICE_UNREACHABLE, raw.detail);
    case 'not_ready':
      return unanswerable(REASONS.SERVICE_NOT_READY, raw.detail);
    case 'response':
      break;
    default:
      return unanswerable(REASONS.RESPONSE_UNINTELLIGIBLE, `unknown outcome kind: ${raw.kind}`);
  }

  const { status, body } = raw;

  // The shallow layer: the service refused the input before the ZK maths, at
  // CBOR decode or x509 chain validation. Both are true rejections -- the proof
  // in hand is not acceptable. The bit is solid; the split below is diagnostic
  // only, so message wording drift cannot move the verdict.
  if (status === 400) {
    const err = String(body?.error ?? '');
    const chain = /x509|certificate|chain|verify|unknown authority/i.test(err);
    return answered(false, chain ? REASONS.ISSUER_UNTRUSTED : REASONS.PROOF_MALFORMED, err);
  }

  if (status !== 200 || !body || typeof body !== 'object') {
    return unanswerable(REASONS.RESPONSE_UNINTELLIGIBLE, `http ${status}`);
  }

  if (body.Status !== true) {
    const message = String(body.Message ?? '');
    const m = message.match(VERIFY_FAILURE);
    if (!m) {
      // Not a verification failure at all -- an operational guard tripped
      // (invalid circuit id, bad spec, attribute count). We are broken.
      const circuit = /circuit/i.test(message);
      return unanswerable(
        circuit ? REASONS.CIRCUIT_UNAVAILABLE : REASONS.RESPONSE_UNINTELLIGIBLE,
        message,
      );
    }
    const code = Number(m[1]);
    if (!PROOF_IS_BAD.has(code)) {
      return unanswerable(REASONS.CIRCUIT_UNAVAILABLE, `${message} (our fault, not a verdict)`);
    }
    return answered(false, REASONS.ZK_PROOF_INVALID, `${PROOF_IS_BAD.get(code)} (code ${code})`);
  }

  // Status:true means the maths checked out. It does NOT yet mean "over 18":
  // a cryptographically perfect proof of age_over_13 is still not what we asked
  // for. The claim we required must be present, and true. (PRD 7.1, D6.)
  const value = findClaim(body.Claims, requiredClaim);
  if (value === undefined) {
    return answered(false, REASONS.CLAIM_ABSENT, `proof carries no ${requiredClaim}`);
  }

  const bit = readCborBool(value);
  if (bit === undefined) {
    return unanswerable(REASONS.RESPONSE_UNINTELLIGIBLE, `cannot read ${requiredClaim}`);
  }

  return bit
    ? answered(true, REASONS.VERIFIED, requiredClaim)
    : answered(false, REASONS.CLAIM_FALSE, `${requiredClaim} is false`);
}

/** Claims is map[namespace][]{ElementIdentifier, ElementValue} (zk.IssuerSigned). */
function findClaim(claims, id) {
  if (!claims || typeof claims !== 'object') return undefined;
  for (const items of Object.values(claims)) {
    if (!Array.isArray(items)) continue;
    for (const item of items) {
      if (item?.ElementIdentifier === id) return item.ElementValue;
    }
  }
  return undefined;
}

/**
 * The claim value is a raw CBOR byte, base64'd by Go's JSON encoder. We read
 * exactly two values -- CBOR true (0xF5) and false (0xF4) -- and refuse
 * anything else rather than guess. This is not a CBOR parser and must not
 * become one (PRD NO-GO #8: we never reimplement any part of longfellow).
 */
function readCborBool(value) {
  if (typeof value === 'boolean') return value;
  if (typeof value !== 'string') return undefined;
  let bytes;
  try {
    bytes = Buffer.from(value, 'base64');
  } catch {
    return undefined;
  }
  if (bytes.length !== 1) return undefined;
  if (bytes[0] === 0xf5) return true;
  if (bytes[0] === 0xf4) return false;
  return undefined;
}
