import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { createGate, startGate, GATE_REASONS } from '../src/gate.js';
import { issueChallenge, applySingleUse, InMemoryNonceStore } from '../src/challenge.js';
import { REASONS } from '../src/verdict.js';

// No key material in the tree (PRD §10): a runtime-random secret. Tests assert on
// behaviour (accept/replay/unknown), not on nonce bytes, so random is deterministic.
const SECRET = randomBytes(32);
const ACCEPT = { ok: true, over_threshold: true, reason: REASONS.VERIFIED, detail: 'age_over_18' };
const DUMMY_DR = Buffer.from('opaque-zk-device-response').toString('base64url');

/**
 * A fake verifier that wires the REAL nonce machinery (issueChallenge +
 * applySingleUse + InMemoryNonceStore) but stands in for the C++ `classify` with a
 * fixed ACCEPT. So a green here is the gate + single-use gate threading correctly;
 * the crypto path is the integration suite's job.
 */
function fakeVerifier() {
  const store = new InMemoryNonceStore({ quiet: true });
  return {
    store,
    requiresSingleUse: true, // a real Verifier reports this; the gate is replay-safe by default
    issueChallenge: () => issueChallenge({ secret: SECRET, ttlMs: 300_000 }),
    check: (proof) => applySingleUse(ACCEPT, proof.transcript, { secret: SECRET, store }),
  };
}

/** Spin an ephemeral loopback server around a gate handler; returns {port, close}. */
async function serve(handler) {
  const server = http.createServer(handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  return { port: server.address().port, close: () => new Promise((r) => server.close(r)) };
}

/** One HTTP round-trip returning {status, body}. */
function req(port, method, path, bodyObj, rawBody) {
  return new Promise((resolve, reject) => {
    const data = rawBody != null ? Buffer.from(rawBody) : bodyObj != null ? Buffer.from(JSON.stringify(bodyObj)) : null;
    const r = http.request(
      { host: '127.0.0.1', port, method, path, headers: data ? { 'content-length': data.length } : {} },
      (res) => {
        const c = [];
        res.on('data', (d) => c.push(d));
        res.on('end', () => {
          const text = Buffer.concat(c).toString();
          let parsed;
          try { parsed = JSON.parse(text); } catch { parsed = text; }
          resolve({ status: res.statusCode, body: parsed });
        });
      },
    );
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}

test('gate: the accept -> replay -> fresh -> unknown sequence over real HTTP', async (t) => {
  const { handler } = createGate({ verifier: fakeVerifier() });
  const { port, close } = await serve(handler);
  t.after(close);

  const ch = await req(port, 'GET', '/8een/challenge');
  assert.equal(ch.status, 200);
  assert.equal(typeof ch.body.nonce, 'string');
  assert.equal(typeof ch.body.transcript, 'string');
  assert.equal(typeof ch.body.expiresAt, 'number');

  const proof = { transcript: ch.body.transcript, deviceResponse: DUMMY_DR };

  await t.test('first use of the issued nonce is accepted (200)', async () => {
    const v = await req(port, 'POST', '/8een/verify', proof);
    assert.equal(v.status, 200);
    assert.equal(v.body.ok, true);
    assert.equal(v.body.over_threshold, true);
  });

  await t.test('byte-identical replay is refused: 503, replay_detected, over_threshold null', async () => {
    const v = await req(port, 'POST', '/8een/verify', proof);
    assert.equal(v.status, 503);
    assert.equal(v.body.ok, false);
    assert.equal(v.body.over_threshold, null, 'a replay is never a verdict about a person');
    assert.equal(v.body.reason, REASONS.REPLAY_DETECTED);
  });

  await t.test('a fresh nonce is accepted again (the gate, not a broken proof, refused the replay)', async () => {
    const ch2 = await req(port, 'GET', '/8een/challenge');
    const v = await req(port, 'POST', '/8een/verify', { transcript: ch2.body.transcript, deviceResponse: DUMMY_DR });
    assert.equal(v.status, 200);
    assert.equal(v.body.over_threshold, true);
  });

  await t.test('a proof bound to a nonce we never issued is session_unknown (503)', async () => {
    const bogus = { transcript: Buffer.from(randomBytes(61)).toString('base64url'), deviceResponse: DUMMY_DR };
    const v = await req(port, 'POST', '/8een/verify', bogus);
    assert.equal(v.status, 503);
    assert.equal(v.body.over_threshold, null);
    assert.equal(v.body.reason, REASONS.SESSION_UNKNOWN);
  });
});

test('gate: method, path, and malformed-input handling', async (t) => {
  const { handler } = createGate({ verifier: fakeVerifier() });
  const { port, close } = await serve(handler);
  t.after(close);

  await t.test('POST /challenge -> 405', async () => {
    const v = await req(port, 'POST', '/8een/challenge', {});
    assert.equal(v.status, 405);
    assert.equal(v.body.reason, GATE_REASONS.METHOD_NOT_ALLOWED);
  });

  await t.test('GET /verify -> 405', async () => {
    const v = await req(port, 'GET', '/8een/verify');
    assert.equal(v.status, 405);
  });

  await t.test('unknown path -> 404 (standalone handler)', async () => {
    const v = await req(port, 'GET', '/nope');
    assert.equal(v.status, 404);
    assert.equal(v.body.reason, GATE_REASONS.NOT_FOUND);
  });

  await t.test('malformed JSON body -> 400', async () => {
    const v = await req(port, 'POST', '/8een/verify', null, '{not json');
    assert.equal(v.status, 400);
    assert.equal(v.body.reason, GATE_REASONS.BAD_REQUEST);
  });

  await t.test('missing fields -> 400', async () => {
    const v = await req(port, 'POST', '/8een/verify', { transcript: 'AA' });
    assert.equal(v.status, 400);
    assert.equal(v.body.reason, GATE_REASONS.BAD_REQUEST);
  });
});

test('gate: bounded body -- an oversized POST gets a clean 413 (delivered, not an ECONNRESET)', async (t) => {
  const { handler } = createGate({ verifier: fakeVerifier(), maxBodyBytes: 1024 });
  const { port, close } = await serve(handler);
  t.after(close);

  const huge = JSON.stringify({ transcript: 'A'.repeat(5000), deviceResponse: 'AA' });
  const v = await req(port, 'POST', '/8een/verify', null, huge);
  // The JSON 413 must actually arrive -- we do NOT destroy the socket first (which would
  // hand the client an ECONNRESET). connection:close ends things after the response flushes.
  assert.equal(v.status, 413);
  assert.equal(v.body.reason, GATE_REASONS.PAYLOAD_TOO_LARGE);
});

test('gate: slow-loris -- a body that stalls is refused with 408, not held open', async (t) => {
  const { handler } = createGate({ verifier: fakeVerifier(), maxBodyReadMs: 150 });
  const { port, close } = await serve(handler);
  t.after(close);

  // Open a POST, announce a large body, then send nothing. The idle timer must fire.
  const got = await new Promise((resolve, reject) => {
    const r = http.request(
      { host: '127.0.0.1', port, method: 'POST', path: '/8een/verify',
        headers: { 'content-type': 'application/json', 'content-length': 10_000 } },
      (res) => { const c = []; res.on('data', (d) => c.push(d)); res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(c).toString()) })); },
    );
    r.on('error', reject);
    r.write('{'); // one byte, then stall (never end)
  });
  assert.equal(got.status, 408);
  assert.equal(got.body.reason, GATE_REASONS.REQUEST_TIMEOUT);
});

// The DISCRIMINATING case (review finding 7): a client that keeps dribbling bytes -- one
// every 40ms, forever -- must still be cut off. This is what a re-arming IDLE timer would
// MISS (every drip resets it, so it never fires); only the TOTAL deadline catches it. The
// 2s test timeout is the trap: under the old idle design the request never ends and this
// times out (fails); under the total deadline the 408 lands at ~120ms. So this test can
// only pass because the fix is real -- it is the guard watched firing against its own case.
test('gate: slow-DRIP -- a body dribbled under any idle window is still cut off (408)', async (t) => {
  const { handler } = createGate({ verifier: fakeVerifier(), maxBodyReadMs: 120 });
  const { port, close } = await serve(handler);
  let drip;
  let r;
  // Destroy the client socket in cleanup so a still-dribbling connection can't block
  // server.close() -- that is what turned the "old design" run into a hang instead of a
  // clean fail. Kept OUT of the assertion path so cleanup never masks the result.
  t.after(() => { clearInterval(drip); r?.destroy(); return close(); });

  // Race the response against an explicit 1s wall clock -- NOT node:test's own timeout,
  // whose buffered-until-file-end output hid the signal. Under the TOTAL deadline the 408
  // lands at ~120ms and wins the race. Under a re-arming IDLE timer the drip resets it
  // forever, no response ever comes, and the wall clock wins with NO_RESPONSE -> the
  // assert below fails cleanly. So a green here can ONLY mean the total-deadline fix works.
  const outcome = await new Promise((resolve) => {
    r = http.request(
      { host: '127.0.0.1', port, method: 'POST', path: '/8een/verify',
        headers: { 'content-type': 'application/json', 'content-length': 10_000 } },
      (res) => { const c = []; res.on('data', (d) => c.push(d)); res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(Buffer.concat(c).toString()) })); },
    );
    r.on('error', () => resolve({ status: 'ERR' }));
    r.write('{');
    drip = setInterval(() => { try { r.write(' '); } catch { /* socket closed */ } }, 40);
    setTimeout(() => resolve({ status: 'NO_RESPONSE' }), 1000).unref?.();
  });
  clearInterval(drip);
  assert.equal(outcome.status, 408, `a dribbling body must be cut off by the TOTAL deadline, got ${outcome.status}`);
  assert.equal(outcome.body.reason, GATE_REASONS.REQUEST_TIMEOUT);
});

test('gate: rate limit -- a single source flooding is bounded (429)', async (t) => {
  const { handler } = createGate({ verifier: fakeVerifier(), rateLimit: { limit: 3, windowMs: 60_000 } });
  const { port, close } = await serve(handler);
  t.after(close);

  const codes = [];
  for (let i = 0; i < 5; i++) codes.push((await req(port, 'GET', '/8een/challenge')).status);
  assert.deepEqual(codes.slice(0, 3), [200, 200, 200], 'first 3 within the window are allowed');
  assert.deepEqual(codes.slice(3), [429, 429], 'the rest are rate-limited');
});

test('gate: trustProxy keys the limiter on the RIGHTMOST XFF hop -- a spoofed leftmost cannot dodge it', async (t) => {
  const { handler } = createGate({ verifier: fakeVerifier(), trustProxy: true, rateLimit: { limit: 2, windowMs: 60_000 } });
  const { port, close } = await serve(handler);
  t.after(close);

  const hit = (xff) => new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: '/8een/challenge', headers: { 'x-forwarded-for': xff } },
      (res) => { res.resume(); res.on('end', () => resolve(res.statusCode)); }).on('error', reject);
  });
  // One real client (rightmost 9.9.9.9, what a trusted proxy appended); the attacker rotates
  // the spoofable LEFTMOST each request. Under the old leftmost-keying these were 3 distinct
  // keys and all passed; keying on the rightmost, they are ONE key and the 3rd is limited.
  const c1 = await hit('spoofed-1, 9.9.9.9');
  const c2 = await hit('spoofed-2, 9.9.9.9');
  const c3 = await hit('spoofed-3, 9.9.9.9');
  assert.deepEqual([c1, c2], [200, 200], 'first two from the same real client pass');
  assert.equal(c3, 429, 'rotating the spoofable leftmost hop must NOT mint a fresh rate-limit key');
});

test('gate: rateLimit:false disables the built-in limiter', async (t) => {
  const { handler } = createGate({ verifier: fakeVerifier(), rateLimit: false });
  const { port, close } = await serve(handler);
  t.after(close);
  const codes = [];
  for (let i = 0; i < 10; i++) codes.push((await req(port, 'GET', '/8een/challenge')).status);
  assert.ok(codes.every((c) => c === 200), 'no request is limited when the limiter is off');
});

test('gate: the express() adapter calls next() for unmatched paths and handles matched ones', async (t) => {
  const { express } = createGate({ verifier: fakeVerifier() });
  const mw = express();
  let nextCalled = false;
  // Unmatched path -> next()
  await new Promise((resolve) => {
    const fakeRes = { writeHead() {}, end() { resolve(); } };
    mw({ url: '/some/other/route', method: 'GET', socket: {}, on() {} }, fakeRes, () => { nextCalled = true; resolve(); });
  });
  assert.equal(nextCalled, true, 'a path the gate does not own falls through to next()');

  // Matched path -> handled, next() NOT called
  const { port, close } = await serve((req, res) => mw(req, res, () => { res.writeHead(500); res.end('LEAKED_TO_NEXT'); }));
  t.after(close);
  const v = await req(port, 'GET', '/8een/challenge');
  assert.equal(v.status, 200, 'a matched route is handled by the gate, not passed to next()');
});

test('createGate rejects a bad verifier', () => {
  assert.throws(() => createGate({}), /needs a started verifier/);
  assert.throws(() => createGate({ verifier: { check() {} } }), /needs a started verifier/);
});

test('createGate is replay-safe by default: refuses a replay-open verifier unless allowReplay', async (t) => {
  const replayOpen = {
    // requiresSingleUse omitted/false -> a bare Verifier with replay defence OFF
    issueChallenge: () => { throw new Error('issueChallenge requires requireSingleUse'); },
    check: async () => ACCEPT,
  };
  assert.throws(() => createGate({ verifier: replayOpen }), /replay-safe by default/,
    'wrapping a replay-open verifier without saying so must throw');

  // Opt in explicitly: the gate builds, and /challenge is cleanly disabled (not a 500).
  const { handler } = createGate({ verifier: replayOpen, allowReplay: true });
  const { port, close } = await serve(handler);
  t.after(close);
  const ch = await req(port, 'GET', '/8een/challenge');
  assert.equal(ch.status, 404);
  assert.equal(ch.body.reason, GATE_REASONS.CHALLENGE_DISABLED, 'no 500 from a swallowed issueChallenge throw');
});

test('createGate fails LOUD on a malformed bound, never silently un-caps the endpoint', () => {
  const v = fakeVerifier();
  assert.throws(() => createGate({ verifier: v, maxBodyBytes: NaN }), /maxBodyBytes must be a positive/);
  assert.throws(() => createGate({ verifier: v, maxBodyReadMs: 0 }), /maxBodyReadMs must be a positive/);
  // A rateLimit missing windowMs would NaN the reset and disable limiting -- must throw.
  assert.throws(() => createGate({ verifier: v, rateLimit: { limit: 60 } }), /rateLimit\.windowMs must be a positive/);
  assert.throws(() => createGate({ verifier: v, rateLimit: { windowMs: 1000 } }), /rateLimit\.limit must be a positive/);
});

test('startGate is replay-safe by default: fails closed BEFORE the circuit load', async () => {
  // No args at all.
  await assert.rejects(() => startGate(), /needs service options/);

  const svc = { binary: '/nonexistent', circuitDir: '/nonexistent', caCerts: '/nonexistent' };

  // Default (requireSingleUse omitted) with no secret -> throws, and the message names
  // the deliberate opt-out. This must happen WITHOUT reaching Verifier.start (no binary).
  await assert.rejects(() => startGate({ ...svc }), /replay-safe by default.*challengeSecret[\s\S]*requireSingleUse:false/);

  // Secret present but no store -> still fails closed.
  await assert.rejects(
    () => startGate({ ...svc, challengeSecret: SECRET }),
    /replay-safe by default.*nonceStore[\s\S]*store:"memory"[\s\S]*requireSingleUse:false/,
  );

  // A too-SHORT secret must be caught HERE, before the circuit load -- not deferred to
  // the Verifier constructor after a minute of loading. (svc points at nonexistent paths,
  // so if this reached Verifier.start it would fail differently / much later.)
  await assert.rejects(
    () => startGate({ ...svc, challengeSecret: randomBytes(8), store: 'memory' }),
    /challengeSecret of at least 16 bytes/,
  );
});
