import test from 'node:test';
import assert from 'node:assert/strict';
import { classify, REASONS } from '../src/verdict.js';

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

test('transport failures are non-answers, not negatives', () => {
  for (const [raw, reason] of [
    [{ kind: 'timeout' }, REASONS.SERVICE_TIMEOUT],
    [{ kind: 'unreachable', detail: 'ECONNREFUSED' }, REASONS.SERVICE_UNREACHABLE],
    [{ kind: 'not_ready' }, REASONS.SERVICE_NOT_READY],
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
    { kind: 'response', status: 500, body: 'boom' },
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
