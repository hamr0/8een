import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  issueChallenge,
  inspectChallenge,
  applySingleUse,
  InMemoryNonceStore,
} from '../src/challenge.js';
import { REASONS } from '../src/verdict.js';

// Generated at runtime (no key material in the tree, PRD §10). These tests assert on
// recognized/expired/replay behaviour, not on any specific nonce bytes, so a random
// secret is as deterministic as a literal -- and `now` is injected everywhere below,
// so timing stays exact.
const SECRET = randomBytes(32);
const T0 = 1_700_000_000_000; // a fixed "now" so expiry maths is exact

// An accept verdict, the only thing the gate ever acts on.
const ACCEPT = { ok: true, over_threshold: true, reason: REASONS.VERIFIED, detail: 'age_over_18' };

/** A store spy: records spends, and can be primed to report a key already spent. */
function fakeStore(primed = []) {
  const seen = new Set(primed);
  const calls = [];
  return {
    calls,
    async spend(key, ttlMs) {
      calls.push({ key, ttlMs });
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    },
  };
}

// ---------------------------------------------------------------------------
// issueChallenge / inspectChallenge -- the self-authenticating nonce.
// ---------------------------------------------------------------------------

test('a freshly issued challenge is recognized and not expired (non-vacuity)', () => {
  const { transcript, expiresAt } = issueChallenge({ secret: SECRET, ttlMs: 300_000, now: T0 });
  const c = inspectChallenge(transcript, { secret: SECRET, now: T0 });
  assert.equal(c.recognized, true, 'must recognize a nonce it just issued');
  assert.equal(c.expired, false);
  assert.equal(c.expiresAt, T0 + 300_000);
  assert.equal(expiresAt, T0 + 300_000);
  assert.equal(typeof c.nonceKey, 'string');
  assert.ok(c.nonceKey.length > 0);
});

test('the issued transcript is the exact 61-byte frame the prover binds to', () => {
  const { transcript, nonce } = issueChallenge({ secret: SECRET, now: T0 });
  assert.equal(nonce.length, 56);
  assert.equal(transcript.length, 61);
  // 83 F6 F6 (=[null,null,...]) then bstr header 58 38 (=byte-string, 56 bytes).
  assert.deepEqual([...transcript.subarray(0, 5)], [0x83, 0xf6, 0xf6, 0x58, 0x38]);
});

test('a forged tag is NOT recognized -- only the holder of the secret can mint', () => {
  const { transcript } = issueChallenge({ secret: SECRET, now: T0 });
  const forged = Buffer.from(transcript);
  forged[forged.length - 1] ^= 0xff; // flip one tag byte
  const c = inspectChallenge(forged, { secret: SECRET, now: T0 });
  assert.equal(c.recognized, false, 'a tampered HMAC must not be recognized');
  assert.equal(c.nonceKey, null);
});

test('a nonce minted under a DIFFERENT secret is not recognized (secret scoping)', () => {
  const { transcript } = issueChallenge({ secret: Buffer.from('another-secret-16+bytes-here!'), now: T0 });
  const c = inspectChallenge(transcript, { secret: SECRET, now: T0 });
  assert.equal(c.recognized, false);
});

test('an expired challenge is recognized but flagged expired', () => {
  const { transcript } = issueChallenge({ secret: SECRET, ttlMs: 1000, now: T0 });
  const c = inspectChallenge(transcript, { secret: SECRET, now: T0 + 2000 });
  assert.equal(c.recognized, true, 'still our nonce...');
  assert.equal(c.expired, true, '...but past its window');
});

test('inspectChallenge never throws on garbage input; it returns unrecognized', () => {
  for (const bad of [null, undefined, 'not bytes', 42, {}, new Uint8Array(0), new Uint8Array(61)]) {
    const c = inspectChallenge(bad, { secret: SECRET, now: T0 });
    assert.equal(c.recognized, false, `garbage ${String(bad)} must be unrecognized, not thrown`);
  }
});

test('a wrong-length transcript (right prefix, wrong body) is unrecognized', () => {
  // Correct 3-byte prefix but a too-short nonce -> not our fixed frame.
  const short = Buffer.concat([Buffer.from([0x83, 0xf6, 0xf6, 0x58, 0x10]), Buffer.alloc(16)]);
  assert.equal(inspectChallenge(short, { secret: SECRET, now: T0 }).recognized, false);
});

test('issueChallenge rejects a weak/absent secret and a non-positive ttl', () => {
  assert.throws(() => issueChallenge({ secret: 'too-short', now: T0 }), TypeError);
  assert.throws(() => issueChallenge({ secret: undefined, now: T0 }), TypeError);
  assert.throws(() => issueChallenge({ secret: SECRET, ttlMs: 0, now: T0 }), TypeError);
  assert.throws(() => issueChallenge({ secret: SECRET, ttlMs: -1, now: T0 }), TypeError);
  assert.throws(() => issueChallenge({ secret: SECRET, ttlMs: NaN, now: T0 }), TypeError);
});

// ---------------------------------------------------------------------------
// applySingleUse -- the gate. Every negative here is a real "can it fail?" case.
// ---------------------------------------------------------------------------

test('THE REPLAY: same nonce twice -> first accepts, second is REPLAY_DETECTED (ok:false)', async () => {
  const { transcript } = issueChallenge({ secret: SECRET, now: T0 });
  const store = fakeStore();

  const first = await applySingleUse(ACCEPT, transcript, { secret: SECRET, store, now: T0 });
  assert.equal(first.ok, true, 'first, legitimate use must pass');
  assert.equal(first.over_threshold, true);

  const second = await applySingleUse(ACCEPT, transcript, { secret: SECRET, store, now: T0 });
  assert.equal(second.ok, false, 'a replay must NOT verify');
  assert.equal(second.over_threshold, null, 'a replay is never a "no" about a person');
  assert.equal(second.reason, REASONS.REPLAY_DETECTED);
});

test('the spent nonce is remembered for exactly its remaining lifetime, no longer', async () => {
  const { transcript } = issueChallenge({ secret: SECRET, ttlMs: 300_000, now: T0 });
  const store = fakeStore();
  await applySingleUse(ACCEPT, transcript, { secret: SECRET, store, now: T0 + 60_000 });
  assert.equal(store.calls.length, 1);
  assert.equal(store.calls[0].ttlMs, 240_000, 'ttl = time left until the nonce expires');
});

test('an unrecognized nonce on a valid proof is SESSION_UNKNOWN, never a "no"', async () => {
  const foreign = Buffer.concat([Buffer.from([0x83, 0xf6, 0xf6, 0x58, 0x38]), Buffer.alloc(56, 7)]);
  const store = fakeStore();
  const v = await applySingleUse(ACCEPT, foreign, { secret: SECRET, store, now: T0 });
  assert.equal(v.ok, false);
  assert.equal(v.over_threshold, null);
  assert.equal(v.reason, REASONS.SESSION_UNKNOWN);
  assert.equal(store.calls.length, 0, 'an unrecognized nonce must never be spent');
});

test('an expired challenge on a valid proof is SESSION_UNKNOWN, never a "no"', async () => {
  const { transcript } = issueChallenge({ secret: SECRET, ttlMs: 1000, now: T0 });
  const store = fakeStore();
  const v = await applySingleUse(ACCEPT, transcript, { secret: SECRET, store, now: T0 + 5000 });
  assert.equal(v.ok, false);
  assert.equal(v.over_threshold, null);
  assert.equal(v.reason, REASONS.SESSION_UNKNOWN);
  assert.equal(store.calls.length, 0, 'an expired challenge must never be spent');
});

test('the gate only acts on an accept: a "no" passes through UNTOUCHED and unspent', async () => {
  const NO = { ok: true, over_threshold: false, reason: REASONS.CLAIM_FALSE, detail: 'age_over_18 is false' };
  const store = fakeStore();
  // Even with a replayed nonce, an under-age proof stays a "no" -- we don't need a
  // nonce to keep saying no, and it must not be spent.
  const { transcript } = issueChallenge({ secret: SECRET, now: T0 });
  const v = await applySingleUse(NO, transcript, { secret: SECRET, store, now: T0 });
  assert.deepEqual(v, NO, 'a "no" must be returned verbatim');
  assert.equal(store.calls.length, 0);
});

test('the gate does not spend a nonce for a broken-verifier ok:false', async () => {
  const BROKEN = { ok: false, over_threshold: null, reason: REASONS.SERVICE_TIMEOUT };
  const store = fakeStore();
  const { transcript } = issueChallenge({ secret: SECRET, now: T0 });
  const v = await applySingleUse(BROKEN, transcript, { secret: SECRET, store, now: T0 });
  assert.deepEqual(v, BROKEN);
  assert.equal(store.calls.length, 0, 'a proof that did not verify must not exhaust a nonce');
});

// ---------------------------------------------------------------------------
// InMemoryNonceStore -- the dev-only reference store.
// ---------------------------------------------------------------------------

test('InMemoryNonceStore.spend is atomic-first-wins and honours ttl', async () => {
  const store = new InMemoryNonceStore({ quiet: true });
  assert.equal(await store.spend('k', 10_000), true, 'first use is fresh');
  assert.equal(await store.spend('k', 10_000), false, 'second use is a replay');
});
