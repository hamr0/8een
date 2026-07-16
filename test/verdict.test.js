import test from 'node:test';
import assert from 'node:assert/strict';
import { classify, REASONS } from '../src/verdict.js';
import { Verifier } from '../src/index.js';

// The Go service echoes issuer-signed claims as CBOR bytes, base64'd by Go's
// JSON encoder. CBOR true is the single byte 0xF5; false is 0xF4.
const CBOR_TRUE = ' 9Q=='.trim();
const CBOR_FALSE = '9A==';
const NS = 'org.iso.18013.5.1';

const claims = (id, value) => ({ [NS]: [{ ElementIdentifier: id, ElementValue: value }] });
const opts = { requiredClaim: 'age_over_18' };

test('valid proof carrying the required claim is the only path to a pass', () => {
  const v = classify(
    { kind: 'response', status: 200, body: { Status: true, Claims: claims('age_over_18', CBOR_TRUE) } },
    opts,
  );
  assert.equal(v.ok, true);
  assert.equal(v.over_threshold, true);
  assert.equal(v.reason, REASONS.VERIFIED);
});

test('a deep ZK failure is a real answer: no', () => {
  const v = classify(
    { kind: 'response', status: 200, body: { Status: false, Message: 'verification failure: return code 5' } },
    opts,
  );
  assert.equal(v.ok, true);
  assert.equal(v.over_threshold, false);
  assert.equal(v.reason, REASONS.ZK_PROOF_INVALID);
});

// THE TRAP. Observed from the real service (2026-07-12), byte-for-byte:
//
//   {"Status":false,
//    "Claims":{"org.iso.18013.5.1":[{"ElementIdentifier":"age_over_18",
//                                    "ElementValue":"9Q=="}]},   <- CBOR true!
//    "Message":"verification failure: return code 5"}
//
// A tampered, REJECTED proof still reports age_over_18 = true. Claims are
// echoed from the unverified CBOR envelope -- they are what the proof CLAIMS,
// not what was PROVEN, and they are attacker-controlled. Any integration that
// reads Claims without gating on Status is trivially bypassed by a forged blob.
// Status is the gate. Claims are only meaningful behind it.
test('ADVERSARIAL: a rejected proof still asserts age_over_18=true and must not pass', () => {
  const rejectedButBoastful = {
    kind: 'response',
    status: 200,
    body: {
      Status: false,
      Claims: claims('age_over_18', CBOR_TRUE),
      Message: 'verification failure: return code 5',
    },
  };
  const v = classify(rejectedButBoastful, opts);
  assert.equal(v.over_threshold, false, 'attacker-controlled Claims must never reach the verdict');
  assert.equal(v.reason, REASONS.ZK_PROOF_INVALID);
});

// Real messages captured from the running service, not invented for the test.
test('the observed rejection messages classify correctly', () => {
  const expired = classify({
    kind: 'response',
    status: 400,
    body: { error: 'Error processing cbor request: failed to verify certificate chain: x509: certificate has expired or is not yet valid: current time 2026-07-12T21:42:56+02:00 is after 2026-05-07T05:34:10Z' },
  }, opts);
  assert.equal(expired.over_threshold, false);
  assert.equal(expired.reason, REASONS.ISSUER_UNTRUSTED);

  const malformed = classify({
    kind: 'response',
    status: 400,
    body: { error: 'Error processing cbor request: failed to parse certificates: x509: malformed extension' },
  }, opts);
  assert.equal(malformed.over_threshold, false);
  assert.equal(malformed.reason, REASONS.PROOF_MALFORMED);
});

// The trap. main.go discards LoadCircuits' error, so a server with no circuits
// on disk starts, reports healthy, and answers every proof with HTTP 200 +
// Status:false + "invalid circuit id" -- shaped exactly like a genuine reject.
// Reporting that as over_threshold:false would deny every legitimate adult and
// call it a verdict.
test('a server with no circuits is BROKEN, not a "no"', () => {
  const v = classify(
    { kind: 'response', status: 200, body: { Status: false, Message: 'invalid circuit id: 4a5b6c' } },
    opts,
  );
  assert.equal(v.ok, false);
  assert.equal(v.over_threshold, null, 'must never be false: we have no answer, not a negative one');
  assert.equal(v.reason, REASONS.CIRCUIT_UNAVAILABLE);
});

test('an untrusted or expired issuer chain is a real answer: no', () => {
  const v = classify(
    { kind: 'response', status: 400, body: { error: 'x509: certificate has expired' } },
    opts,
  );
  assert.equal(v.ok, true);
  assert.equal(v.over_threshold, false);
  assert.equal(v.reason, REASONS.ISSUER_UNTRUSTED);
});

test('an unparseable proof envelope is a real answer: no', () => {
  const v = classify(
    { kind: 'response', status: 400, body: { error: 'Error processing cbor request: malformed extension' } },
    opts,
  );
  assert.equal(v.ok, true);
  assert.equal(v.over_threshold, false);
  assert.equal(v.reason, REASONS.PROOF_MALFORMED);
});

// PRD 7.1: "wrong attribute" -- a cryptographically perfect proof of something
// we did not ask about. Status:true is NOT sufficient to pass.
test('a valid proof of a claim we did not ask for does not pass', () => {
  const v = classify(
    { kind: 'response', status: 200, body: { Status: true, Claims: claims('age_over_13', CBOR_TRUE) } },
    opts,
  );
  assert.equal(v.ok, true);
  assert.equal(v.over_threshold, false);
  assert.equal(v.reason, REASONS.CLAIM_ABSENT);
});

test('a valid proof whose claim is false does not pass', () => {
  const v = classify(
    { kind: 'response', status: 200, body: { Status: true, Claims: claims('age_over_18', CBOR_FALSE) } },
    opts,
  );
  assert.equal(v.ok, true);
  assert.equal(v.over_threshold, false);
  assert.equal(v.reason, REASONS.CLAIM_FALSE);
});

// PRD D6: the threshold is configurable; the output stays one bit.
test('the threshold is what the caller asked for, not what the proof offers', () => {
  const body = { Status: true, Claims: claims('age_over_18', CBOR_TRUE) };
  assert.equal(classify({ kind: 'response', status: 200, body }, { requiredClaim: 'age_over_21' }).over_threshold, false);
  assert.equal(classify({ kind: 'response', status: 200, body }, { requiredClaim: 'age_over_18' }).over_threshold, true);
});

test('a claim value we cannot read is refused, never guessed', () => {
  const v = classify(
    { kind: 'response', status: 200, body: { Status: true, Claims: claims('age_over_18', 'AQID') } },
    opts,
  );
  assert.equal(v.ok, false);
  assert.equal(v.over_threshold, null);
  assert.equal(v.reason, REASONS.RESPONSE_UNINTELLIGIBLE);
});

// A 400 we cannot recognise could be a proxy, an intermediary, a future upstream
// error shape -- anything. Asserting "not over 18" on a response we did not
// understand is the zero-circuit mistake wearing a different status code.
test('an HTTP 400 we cannot recognise is a non-answer, not a rejection', () => {
  for (const body of [{}, { message: 'upstream proxy error' }, { error: '' }]) {
    const v = classify({ kind: 'response', status: 400, body }, opts);
    assert.equal(v.ok, false, `${JSON.stringify(body)} must not yield a verdict`);
    assert.equal(v.over_threshold, null, 'an unreadable refusal must never read as "underage"');
    assert.equal(v.reason, REASONS.RESPONSE_UNINTELLIGIBLE);
  }
});

// ...while the refusals we DO recognise stay verdicts. The fix above must not
// swallow the real ones.
test('recognised refusals remain rejections', () => {
  const chain = classify({ kind: 'response', status: 400, body: { error: 'Error processing cbor request: failed to verify certificate chain: x509: certificate has expired' } }, opts);
  assert.equal(chain.over_threshold, false);
  assert.equal(chain.reason, REASONS.ISSUER_UNTRUSTED);

  const junk = classify({ kind: 'response', status: 400, body: { error: 'Error processing cbor request: failed to parse certificates: x509: malformed extension' } }, opts);
  assert.equal(junk.over_threshold, false);
  assert.equal(junk.reason, REASONS.PROOF_MALFORMED);
});

// Caught by the integration suite when an earlier cut of the fix above matched
// on message TEXT: a real garbage proof comes back with "unsupported operation",
// wording no regex had anticipated, and we duly reported "we are broken" instead
// of "that is not a proof". The discriminator is the verifier's error envelope,
// not its prose.
test('a refusal we did not anticipate the wording of is still a rejection', () => {
  const v = classify(
    { kind: 'response', status: 400, body: { error: 'Error processing cbor request: unsupported operation' } },
    opts,
  );
  assert.equal(v.ok, true, 'the verifier spoke -- it refused the proof');
  assert.equal(v.over_threshold, false);
  assert.equal(v.reason, REASONS.PROOF_MALFORMED);
});

test('a claim present but empty is a bad proof, not a broken verifier', () => {
  const v = classify(
    { kind: 'response', status: 200, body: { Status: true, Claims: claims('age_over_18', '') } },
    opts,
  );
  assert.equal(v.ok, true, 'the peer sent us a bad claim -- that is not OUR malfunction');
  assert.equal(v.over_threshold, false);
  assert.equal(v.reason, REASONS.CLAIM_ABSENT);
});

test('a caller who hands us something that is not a proof gets no verdict', () => {
  const v = classify({ kind: 'invalid_request', detail: 'proof.transcript is missing' }, opts);
  assert.equal(v.ok, false);
  assert.equal(v.over_threshold, null, 'a bug in the caller is not evidence about a person');
  assert.equal(v.reason, REASONS.INVALID_REQUEST);
});

test('transport failures are non-answers, not negatives', () => {
  for (const [raw, reason] of [
    [{ kind: 'timeout' }, REASONS.SERVICE_TIMEOUT],
    [{ kind: 'unreachable', detail: 'ECONNREFUSED' }, REASONS.SERVICE_UNREACHABLE],
    [{ kind: 'not_ready' }, REASONS.SERVICE_NOT_READY],
    [{ kind: 'invalid_request', detail: 'proof.transcript is empty' }, REASONS.INVALID_REQUEST],
  ]) {
    const v = classify(raw, opts);
    assert.equal(v.ok, false, `${reason} must not be an answer`);
    assert.equal(v.over_threshold, null, `${reason} must not read as "underage"`);
    assert.equal(v.reason, reason);
  }
});

test('classify never throws, whatever it is handed', () => {
  const garbage = [
    undefined, null, 42, 'nonsense', [], {}, { kind: 'response' },
    { kind: 'response', status: 200, body: null },
    { kind: 'response', status: 200, body: { Status: true } },
    { kind: 'response', status: 200, body: { Status: true, Claims: { [NS]: 'not-an-array' } } },
    { kind: 'response', status: 500, body: '<html>gateway error</html>' },
    { kind: 'wat' },
  ];
  for (const raw of garbage) {
    const v = classify(raw, opts);
    assert.equal(typeof v.ok, 'boolean', `no verdict for ${JSON.stringify(raw)}`);
    assert.ok(Object.values(REASONS).includes(v.reason), `unknown reason ${v.reason}`);
  }
});

// The invariant the whole module exists to hold. If this ever fails, 8een is
// telling a site someone is underage when the truth is that it is broken.
test('INVARIANT: no answer means null, never false', () => {
  const everything = [
    undefined, null, 42, {}, { kind: 'timeout' }, { kind: 'unreachable' }, { kind: 'not_ready' },
    { kind: 'response', status: 200, body: { Status: true, Claims: claims('age_over_18', CBOR_TRUE) } },
    { kind: 'response', status: 200, body: { Status: true, Claims: claims('age_over_18', CBOR_FALSE) } },
    { kind: 'response', status: 200, body: { Status: false, Message: 'verification failure: return code 5' } },
    { kind: 'response', status: 200, body: { Status: false, Message: 'invalid circuit id: abc' } },
    { kind: 'response', status: 400, body: { error: 'x509: certificate has expired' } },
    { kind: 'response', status: 400, body: {} },
    { kind: 'response', status: 500, body: 'boom' },
    { kind: 'invalid_request', detail: 'not a proof' },
  ];
  for (const raw of everything) {
    const v = classify(raw, opts);
    if (v.ok === false) {
      assert.equal(v.over_threshold, null, `"broken" leaked as a verdict: ${JSON.stringify(raw)}`);
    } else {
      assert.equal(typeof v.over_threshold, 'boolean', `an answer must be a bit: ${JSON.stringify(raw)}`);
    }
  }
});

// ---------------------------------------------------------------------------
// M4: the credential-currency (freshness) gate.
//
// A cryptographically valid proof of the required claim can still be STALE: the ZK
// layer checks the credential's validity window against a `now` the PROVER supplies
// (poc/.../zk/cbor.go:191), never the real clock, so an expired credential verifies
// (PRD §7.1a). classify() bounds the verifier's echoed `Now` timestamp against an
// injected real clock. `now` is injected (not read here) so the classifier stays
// pure and these tests stay deterministic -- no wall clock, no flake.
// ---------------------------------------------------------------------------

const NOW = Date.parse('2026-07-15T12:00:00Z');

// An accept response (Status:true, age_over_18=true), optionally carrying the
// verifier's echoed presentation timestamp. Omitting it models an unpatched/absent
// echo -- the reading going missing.
const accept = (nowStr) => ({
  kind: 'response',
  status: 200,
  body: {
    Status: true,
    Claims: claims('age_over_18', CBOR_TRUE),
    ...(nowStr === undefined ? {} : { Now: nowStr }),
  },
});
const strict = { requiredClaim: 'age_over_18', requireCurrentValidity: true, toleranceMs: 300_000, now: NOW };

test('M4: a fresh presentation (timestamp within tolerance) verifies', () => {
  const v = classify(accept('2026-07-15T11:58:00Z'), strict); // 2 min ago
  assert.equal(v.ok, true);
  assert.equal(v.over_threshold, true);
  assert.equal(v.reason, REASONS.VERIFIED);
});

test('M4: an expired credential (timestamp years past) is a real no, not a breakage', () => {
  const v = classify(accept('2020-06-01T00:00:00Z'), strict);
  assert.equal(v.ok, true, 'we DID get an answer');
  assert.equal(v.over_threshold, false);
  assert.equal(v.reason, REASONS.CREDENTIAL_EXPIRED);
});

test('M4: a FUTURE timestamp beyond tolerance is "cannot confirm", never a false expired-no', () => {
  // A fast device clock on a genuinely-current credential. Labelling that adult's
  // credential "expired" (over_threshold:false) would be a false no; the honest answer
  // is that we cannot confirm currency (ok:false).
  const v = classify(accept('2026-07-15T12:10:00Z'), strict); // 10 min ahead, tol 5 min
  assert.equal(v.ok, false);
  assert.equal(v.over_threshold, null);
  assert.equal(v.reason, REASONS.FRESHNESS_UNKNOWN);
});

test('M4: a malformed tolerance fails CLOSED (freshness_unknown), never disables the gate', () => {
  // `skew > NaN` is false, so without the guard a years-stale credential would slip
  // through as VERIFIED. A bad config value must refuse to judge, not wave things past.
  for (const bad of [NaN, -1, 'oops', Infinity]) {
    const v = classify(accept('2020-06-01T00:00:00Z'), { ...strict, toleranceMs: bad });
    assert.equal(v.ok, false, `toleranceMs=${String(bad)} must not accept a stale credential`);
    assert.equal(v.over_threshold, null);
    assert.equal(v.reason, REASONS.FRESHNESS_UNKNOWN);
  }
});

test('M4: the tolerance boundary — just inside passes, just outside fails', () => {
  const tol = 300_000;
  const justInside = classify(accept(new Date(NOW - tol + 1000).toISOString()), { ...strict, toleranceMs: tol });
  assert.equal(justInside.reason, REASONS.VERIFIED, 'skew < tolerance must pass');
  const justOutside = classify(accept(new Date(NOW - tol - 1000).toISOString()), { ...strict, toleranceMs: tol });
  assert.equal(justOutside.reason, REASONS.CREDENTIAL_EXPIRED, 'skew > tolerance must fail');
  assert.equal(justOutside.over_threshold, false);
});

// The invariant on the new surface: a reading we could not take is NOT a "no".
test('M4: currency required but NO timestamp echoed -> cannot verify, never a no', () => {
  const v = classify(accept(undefined), strict);
  assert.equal(v.ok, false, 'a missing reading is not a verdict about a person');
  assert.equal(v.over_threshold, null, 'INVARIANT: ok:false implies over_threshold:null');
  assert.equal(v.reason, REASONS.FRESHNESS_UNKNOWN);
});

test('M4: currency required but NO clock supplied -> cannot verify', () => {
  const v = classify(accept('2026-07-15T11:59:00Z'), { ...strict, now: undefined });
  assert.equal(v.ok, false);
  assert.equal(v.over_threshold, null);
  assert.equal(v.reason, REASONS.FRESHNESS_UNKNOWN);
});

test('M4: with currency NOT required, a stale timestamp still passes — the age fact stands', () => {
  const v = classify(accept('2020-06-01T00:00:00Z'), { requiredClaim: 'age_over_18', requireCurrentValidity: false, now: NOW });
  assert.equal(v.ok, true);
  assert.equal(v.over_threshold, true);
  assert.equal(v.reason, REASONS.VERIFIED);
});

test('M4: classify defaults the gate OFF (pure mechanism) — the Verifier defaults it ON', () => {
  // No requireCurrentValidity opt: a stale stamp passes here, proving the policy
  // default lives at the Verifier boundary, not in this pure classifier.
  const v = classify(accept('2020-06-01T00:00:00Z'), { requiredClaim: 'age_over_18' });
  assert.equal(v.reason, REASONS.VERIFIED);
});

test('M4: the gate never touches the FALSE-claim path — an underage holder stays claim_false', () => {
  // Status:true, claim false, currency required, and no timestamp at all: this must
  // stay claim_false (a real no about the claim), NOT freshness_unknown. The gate is
  // only on the would-be-accept path.
  const v = classify(
    { kind: 'response', status: 200, body: { Status: true, Claims: claims('age_over_18', CBOR_FALSE) } },
    strict,
  );
  assert.equal(v.ok, true);
  assert.equal(v.over_threshold, false);
  assert.equal(v.reason, REASONS.CLAIM_FALSE);
});

// The Verifier constructor validates the tolerance up front (mirroring the threshold),
// so a bad config value fails LOUD at construction rather than silently at verify time.
// Synchronous — no service needed, so it lives in the fast suite.
test('M4: Verifier rejects a non-numeric/negative toleranceMs at construction', () => {
  for (const bad of [NaN, -1, 'oops', Infinity, {}]) {
    assert.throws(
      () => new Verifier(null, 'age_over_18', { toleranceMs: bad }),
      /toleranceMs must be a non-negative finite number/,
      `toleranceMs=${String(bad)} must be rejected`,
    );
  }
  // undefined is legitimately "use the default" -- must NOT throw.
  assert.doesNotThrow(() => new Verifier(null, 'age_over_18', { toleranceMs: undefined }));
  assert.doesNotThrow(() => new Verifier(null, 'age_over_18'));
});

// Single-use CANNOT fail open: enabling it without the secret + shared store it
// depends on must throw LOUD at construction, never fall back to something that only
// looks replay-safe. This is the guard that keeps the "looks safe, isn't" trap out --
// and per the project's own lesson, a guard you have not watched FIRE is not a guard.
// Synchronous (no service needed), so it lives in the fast suite.
test('M4 piece 2: Verifier refuses requireSingleUse without the secret and store it needs', () => {
  const goodSecret = Buffer.alloc(32, 7);
  const goodStore = { spend: () => true };

  // No secret at all.
  assert.throws(
    () => new Verifier(null, 'age_over_18', { requireSingleUse: true, nonceStore: goodStore }),
    /challengeSecret/,
    'requireSingleUse without a secret must throw',
  );
  // Secret present, but no store.
  assert.throws(
    () => new Verifier(null, 'age_over_18', { requireSingleUse: true, challengeSecret: goodSecret }),
    /nonceStore/,
    'requireSingleUse without a store must throw',
  );
  // A store that is not a real store (no atomic spend) is rejected too.
  assert.throws(
    () => new Verifier(null, 'age_over_18', {
      requireSingleUse: true, challengeSecret: goodSecret, nonceStore: { has: () => false },
    }),
    /nonceStore/,
    'a store without spend() must throw',
  );
  // A weak secret (< 16 bytes) must fail at construction, not at first request.
  assert.throws(
    () => new Verifier(null, 'age_over_18', {
      requireSingleUse: true, challengeSecret: Buffer.alloc(8), nonceStore: goodStore,
    }),
    /16 bytes/,
    'a weak secret must throw',
  );

  // Non-vacuity: fully configured single-use must NOT throw, and single-use OFF (the
  // default) must NOT require any of this -- otherwise the throws above would pass for
  // the wrong reason.
  assert.doesNotThrow(
    () => new Verifier(null, 'age_over_18', {
      requireSingleUse: true, challengeSecret: goodSecret, nonceStore: goodStore,
    }),
    'a correctly configured single-use verifier must construct',
  );
  assert.doesNotThrow(() => new Verifier(null, 'age_over_18'), 'single-use off needs no store/secret');
});
