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
  // A cryptographically valid proof of the required claim, but the credential's own
  // validity window is not current: the presentation is stale/expired. A real "no"
  // (over_threshold:false), distinct from CLAIM_FALSE (a genuinely under-age holder).
  CREDENTIAL_EXPIRED: 'credential_expired',

  // We got no answer.
  SERVICE_UNREACHABLE: 'service_unreachable',
  SERVICE_TIMEOUT: 'service_timeout',
  SERVICE_NOT_READY: 'service_not_ready',
  CIRCUIT_UNAVAILABLE: 'circuit_unavailable',
  RESPONSE_UNINTELLIGIBLE: 'response_unintelligible',
  INVALID_REQUEST: 'invalid_request',
  // Currency was required, but the verifier reported no timestamp to check (or no
  // clock was supplied). We could not judge freshness, so we refuse to judge at all
  // -- never guess "expired". A missing reading is `ok:false`, never a "no".
  FRESHNESS_UNKNOWN: 'freshness_unknown',
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

/**
 * @param {boolean} over_threshold
 * @param {string} reason
 * @param {string} [detail]
 * @returns {import('./types.js').Verdict}
 */
const answered = (over_threshold, reason, detail) => ({ ok: true, over_threshold, reason, detail });

/**
 * @param {string} reason
 * @param {string} [detail]
 * @returns {import('./types.js').Verdict}
 */
const unanswerable = (reason, detail) => ({ ok: false, over_threshold: null, reason, detail });

/**
 * Turn one exchange with the verifier into one bit.
 *
 * @param {*} raw  An {@link import('./types.js').Outcome} in the happy case --
 *   but typed `*` deliberately, because this is the never-throws boundary. It is
 *   handed whatever the wire produced, including garbage, and must return a
 *   verdict for all of it rather than trusting its input's shape.
 * @param {{requiredClaim?: string, requireCurrentValidity?: boolean,
 *   toleranceMs?: number, now?: number}} [opts]
 *   `requiredClaim` is the claim the caller requires, e.g. `age_over_18` (PRD D6:
 *   the threshold is configurable; the output stays one bit).
 *
 *   `requireCurrentValidity` gates an otherwise-accepted proof on the credential's
 *   own validity window being current. It defaults to `false` HERE -- classify is a
 *   pure mechanism, and its own callers opt in explicitly -- while the adopter-facing
 *   `Verifier` defaults it to `true` (the secure default; PRD §7.4). When on, `now`
 *   (ms since epoch, injected so this stays pure) is compared to the presentation
 *   timestamp the verifier echoes, within `toleranceMs` (default 5 min). Stale ->
 *   `credential_expired` (a real "no"); no timestamp or no clock -> `freshness_unknown`
 *   (`ok:false`, never a "no").
 * @returns {import('./types.js').Verdict}
 */
export function classify(raw, opts = {}) {
  const requiredClaim = opts.requiredClaim ?? 'age_over_18';
  const requireCurrentValidity = opts.requireCurrentValidity ?? false;
  const toleranceMs = opts.toleranceMs ?? 300_000;
  const now = opts.now;

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
    case 'invalid_request':
      // The caller handed us something that is not a proof. We have no verdict
      // to give -- and this is emphatically not evidence about a person.
      return unanswerable(REASONS.INVALID_REQUEST, raw.detail);
    case 'response':
      break;
    default:
      return unanswerable(REASONS.RESPONSE_UNINTELLIGIBLE, `unknown outcome kind: ${raw.kind}`);
  }

  const { status, body } = raw;

  // A body we cannot even read is never a verdict about a person, whatever the
  // status line says.
  if (!body || typeof body !== 'object') {
    return unanswerable(REASONS.RESPONSE_UNINTELLIGIBLE, `http ${status}: unreadable body`);
  }

  // The shallow layer: the service refused the input before the ZK maths, at
  // CBOR decode or x509 chain validation. Both are true rejections -- the proof
  // in hand is not acceptable. The bit is solid; the split below is diagnostic
  // only, so message wording drift cannot move the verdict.
  if (status === 400) {
    const err = typeof body.error === 'string' ? body.error.trim() : '';

    // A 400 carrying the verifier's own error envelope is the VERIFIER refusing
    // this proof -- at CBOR decode or x509 chain validation, before the maths.
    // That is a true rejection. A 400 WITHOUT it is not: it could be a proxy, an
    // intermediary, a load balancer, a future upstream shape. Asserting "not over
    // 18" on a response we did not understand is the zero-circuit mistake wearing
    // a different status code.
    //
    // Discriminate on STRUCTURE (is this the verifier's error envelope?), not on
    // wording. An earlier cut of this matched on message text and duly reported
    // "we are broken" the first time a real garbage proof came back with
    // "unsupported operation" -- wording no regex had anticipated. The bit must
    // not hinge on upstream's prose.
    if (!err) {
      return unanswerable(REASONS.RESPONSE_UNINTELLIGIBLE, 'http 400 without the verifier error envelope');
    }

    // Observed:
    //   "...failed to verify certificate chain: x509: certificate has expired..."
    //   "...failed to parse certificates: x509: malformed extension"
    //   "...unsupported operation"                      (an outright garbage proof)
    // The split below is DIAGNOSTIC ONLY -- every branch rejects, so rewording
    // upstream can blur the reason string but can never move the verdict.
    // NB: not a bare /cbor/ -- every message carries the prefix "Error processing
    // cbor request:", so it discriminates nothing.
    const unparseable = /malformed|failed to parse|invalid cbor/i.test(err);
    const untrusted = /certificate|chain|x509|unknown authority|expired|not yet valid/i.test(err);
    return answered(false, untrusted && !unparseable ? REASONS.ISSUER_UNTRUSTED : REASONS.PROOF_MALFORMED, err);
  }

  if (status !== 200) {
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
  // Absent, or present but carrying nothing: either way the proof does not
  // attest the claim we required. That is a fact about the proof, not about us.
  if (value === undefined || value === null || value === '') {
    return answered(false, REASONS.CLAIM_ABSENT, `proof carries no ${requiredClaim}`);
  }

  // Present, non-empty, and we still cannot read it. Now we genuinely do not
  // know, and we refuse to guess a bit about a person.
  const bit = readCborBool(value);
  if (bit === undefined) {
    return unanswerable(REASONS.RESPONSE_UNINTELLIGIBLE, `cannot read ${requiredClaim}`);
  }

  if (!bit) {
    return answered(false, REASONS.CLAIM_FALSE, `${requiredClaim} is false`);
  }

  // The maths checked out AND the required claim is true. One question remains, and
  // only if the caller requires it: is the credential still valid RIGHT NOW? The ZK
  // layer already checked validFrom <= now <= validUntil -- but against a `now` the
  // PROVER supplied (poc/.../zk/cbor.go:191), never the real clock, so an expired
  // credential passes it (PRD §7.1a). We bound that timestamp against our own clock.
  if (requireCurrentValidity) {
    const stale = freshnessGate(body, now, toleranceMs);
    if (stale) return stale;
  }
  return answered(true, REASONS.VERIFIED, requiredClaim);
}

/**
 * The credential-currency gate. Returns a rejecting Verdict if the presentation is
 * stale or unjudgeable, or `null` if it is fresh (the caller then accepts).
 *
 * Parsing `body.Now` is `Date.parse()` of an RFC3339 string the verifier already
 * decoded from CBOR and echoed -- NOT a CBOR parse, so NO-GO #8 is intact.
 *
 * A missing timestamp or a missing clock is `freshness_unknown` (`ok:false`), never
 * `credential_expired`: if we could not read the date we refuse to judge, rather than
 * guess a "no" about a person. That is the §1 invariant on this new surface.
 *
 * @param {{Now?: unknown}} body
 * @param {number|undefined} now  ms since epoch, or undefined if none was supplied
 * @param {number} toleranceMs
 * @returns {import('./types.js').Verdict|null}
 */
function freshnessGate(body, now, toleranceMs) {
  const stamp = parseTimestamp(body.Now);
  if (stamp === undefined) {
    return unanswerable(
      REASONS.FRESHNESS_UNKNOWN,
      'currency required, but the verifier reported no presentation timestamp',
    );
  }
  if (typeof now !== 'number' || !Number.isFinite(now)) {
    return unanswerable(
      REASONS.FRESHNESS_UNKNOWN,
      'currency required, but no real-clock reference was supplied to check against',
    );
  }
  // A malformed tolerance must fail CLOSED, never silently disable the gate: `x > NaN`
  // is false, so a NaN/garbage tolerance would let a years-stale credential through as
  // current. This is a config value, and the doctrine is: do not trust one. Refuse to
  // judge rather than wave it past.
  if (typeof toleranceMs !== 'number' || !Number.isFinite(toleranceMs) || toleranceMs < 0) {
    return unanswerable(
      REASONS.FRESHNESS_UNKNOWN,
      `currency required, but the freshness tolerance is not a usable number (${String(toleranceMs)})`,
    );
  }

  // Signed, because the two directions are DIFFERENT answers. Past beyond tolerance is
  // a stale/expired presentation -- a real "no" about currency. FUTURE beyond tolerance
  // means the credential is valid at a time we have not reached (a fast device clock, or
  // a future-dated proof): it is NOT expired, and calling a currently-valid adult
  // "expired" would be a false no. We cannot confirm currency, so we refuse to judge
  // (ok:false) rather than assert one -- the §1 invariant on this surface.
  const skewMs = now - stamp;
  if (skewMs > toleranceMs) {
    return answered(
      false,
      REASONS.CREDENTIAL_EXPIRED,
      `presentation dated ${String(body.Now)} is ${Math.round(skewMs / 1000)}s stale (tolerance ${Math.round(toleranceMs / 1000)}s)`,
    );
  }
  if (skewMs < -toleranceMs) {
    return unanswerable(
      REASONS.FRESHNESS_UNKNOWN,
      `presentation dated ${String(body.Now)} is ${Math.round(-skewMs / 1000)}s in the future (tolerance ${Math.round(toleranceMs / 1000)}s); cannot confirm currency`,
    );
  }
  return null;
}

/**
 * Parse the echoed presentation timestamp (a 20-char RFC3339 tdate) to ms since
 * epoch, or undefined if absent/unreadable. Not a CBOR parser (NO-GO #8): the
 * verifier already decoded the CBOR and handed us a JSON string.
 *
 * @param {unknown} v
 * @returns {number|undefined}
 */
function parseTimestamp(v) {
  if (typeof v !== 'string') return undefined;
  const ms = Date.parse(v); // Date.parse('') and any non-date string are already NaN
  return Number.isNaN(ms) ? undefined : ms;
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
