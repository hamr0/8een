/**
 * Drives the real longfellow verifier service. Slow by nature: the circuit load
 * is 44-47s per server, and this suite starts three.
 *
 * Requires the POC clone to be materialized (see poc/M0-EVIDENCE.md step 1).
 * Skips cleanly when it is absent, so a fresh checkout still runs green on the
 * unit suite.
 *
 * HONESTY NOTE, stated plainly rather than buried:
 * The only real proof we have (upstream's examples/post1.json) carries a cert
 * chain that expired 2026-05-07. Exercising the ACCEPT path therefore requires
 * pinning the verification clock, via upstream's patched build and
 * ZKVERIFY_FAKE_TIME. That switch lives here, in the test harness, injected as
 * an env option -- it is not referenced anywhere in 8een's own code and never
 * ships. A natively-valid credential arrives at M2 with the test-CA, and this
 * scaffolding goes away. Every REJECT path below runs on the real clock or is
 * clock-independent.
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, mkdtempSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Verifier, VerifierService, REASONS } from '../src/index.js';

const POC = new URL('../poc/longfellow-zk/', import.meta.url).pathname;
const SERVER_DIR = join(POC, 'reference/verifier-service/server');
const RIG = {
  binary: join(SERVER_DIR, 'server'),
  circuitDir: join(POC, 'lib/circuits/mdoc/circuits'),
  caCerts: join(SERVER_DIR, 'certs.pem'),
  // Upstream defaults to fetching the AAMVA VICAL over the network at boot.
  // Point it at a closed port: trust anchors in these tests come from the PEM
  // bundle alone, so the trust list under test is the one we chose.
  vicalUrl: 'http://127.0.0.1:1/no-vical',
};
const PINNED_CLOCK = { ZKVERIFY_FAKE_TIME: '2026-04-01T00:00:00Z' };

const available = existsSync(RIG.binary) && existsSync(RIG.circuitDir);
const suite = { skip: available ? false : 'POC clone not materialized (see poc/M0-EVIDENCE.md)' };

/** Fixtures are stored as the service's own wire format: base64 in JSON. */
function proof(path) {
  const j = JSON.parse(readFileSync(path, 'utf8'));
  return {
    transcript: Buffer.from(j.Transcript, 'base64'),
    deviceResponse: Buffer.from(j.ZKDeviceResponseCBOR, 'base64'),
  };
}

const VALID = () => proof(join(SERVER_DIR, 'examples/post1.json'));
const TAMPERED = () => proof(new URL('../poc/post1-tampered.json', import.meta.url).pathname);
const WRONG_TRANSCRIPT = () => proof(new URL('../poc/post1-wrong-transcript.json', import.meta.url).pathname);
const MANGLED_CERT = () => proof(new URL('../poc/probe-flip-tail.json', import.meta.url).pathname);

// The zero-circuit trap. A server pointed at an empty directory reports
// /healthz "ok", advertises 12 specs it does not have, and rejects every valid
// proof in a shape identical to a genuine "no". We must refuse to serve at all
// rather than hand out verdicts we cannot make.
test('refuses to start when no circuits loaded, rather than serve confident nonsense', suite, async () => {
  const empty = mkdtempSync(join(tmpdir(), '8een-nocircuits-'));
  await assert.rejects(
    Verifier.start({ ...RIG, circuitDir: empty, port: 8911, startupTimeoutMs: 15_000, env: PINNED_CLOCK }),
    /loaded 0 circuits/,
    'a verifier with no circuits must not come up',
  );
});

test('trust discrimination: the same proof passes or fails on the trust list alone', suite, async (t) => {
  t.diagnostic('two servers, ~45s each -- circuit load dominates');

  // A real CA, generated at runtime, that simply is not this credential's
  // issuer. Never enters the tree (PRD §10: no key material, no exemption).
  const dir = mkdtempSync(join(tmpdir(), '8een-stranger-ca-'));
  const strangerCa = join(dir, 'stranger.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', join(dir, 'stranger.key'), '-out', strangerCa,
    '-days', '30', '-subj', '/CN=Not The Issuer/O=8een test',
  ], { stdio: 'ignore' });

  const trusted = await Verifier.start({ ...RIG, port: 8912, env: PINNED_CLOCK });
  t.after(() => trusted.stop());
  const accepted = await trusted.check(VALID());

  const stranger = await Verifier.start({ ...RIG, caCerts: strangerCa, port: 8913, env: PINNED_CLOCK });
  t.after(() => stranger.stop());
  const rejected = await stranger.check(VALID());

  assert.deepEqual(
    { ok: accepted.ok, over: accepted.over_threshold, reason: accepted.reason },
    { ok: true, over: true, reason: REASONS.VERIFIED },
    'issuer on the trust list: accept',
  );
  assert.equal(rejected.over_threshold, false, 'issuer NOT on the trust list: the very same bytes must fail');
  assert.equal(rejected.ok, true, 'and that is a real answer, not a breakage');
  assert.equal(rejected.reason, REASONS.ISSUER_UNTRUSTED);
});

test('the negative matrix (PRD §7.1)', suite, async (t) => {
  // One loaded service, two thresholds on top of it -- both via the public
  // surface, so the suite never reaches into internals to make a point.
  const service = new VerifierService({ ...RIG, port: 8914, env: PINNED_CLOCK });
  await service.start();
  t.after(() => service.stop());

  const v = new Verifier(service, 'age_over_18');
  const strict = new Verifier(service, 'age_over_21');

  assert.equal(service.circuitsLoaded, 17, 'circuits actually on disk, counted from the child log');

  await t.test('a valid proof of the required claim is accepted', async () => {
    const r = await v.check(VALID());
    assert.equal(r.ok, true);
    assert.equal(r.over_threshold, true);
  });

  await t.test('a tampered proof is rejected', async () => {
    const r = await v.check(TAMPERED());
    assert.equal(r.over_threshold, false);
    assert.equal(r.reason, REASONS.ZK_PROOF_INVALID);
  });

  await t.test('a proof bound to a different transcript is rejected', async () => {
    const r = await v.check(WRONG_TRANSCRIPT());
    assert.equal(r.over_threshold, false);
    assert.equal(r.reason, REASONS.ZK_PROOF_INVALID);
  });

  await t.test('a proof with a mangled cert chain is rejected', async () => {
    const r = await v.check(MANGLED_CERT());
    assert.equal(r.over_threshold, false);
    assert.equal(r.ok, true);
  });

  await t.test('garbage is rejected, not crashed on', async () => {
    const r = await v.check({ transcript: Buffer.from('nope'), deviceResponse: Buffer.from('nope') });
    assert.equal(r.over_threshold, false);
    assert.equal(r.ok, true);
  });

  // PRD D6: the threshold is the caller's, not the proof's. This proof attests
  // age_over_18; a site that asked for over-21 must not be told yes.
  await t.test('a proof of over-18 does not satisfy a site asking for over-21', async () => {
    const r = await strict.check(VALID());
    assert.equal(r.ok, true);
    assert.equal(r.over_threshold, false);
    assert.equal(r.reason, REASONS.CLAIM_ABSENT);
  });

  // The stateless-verifier fact, asserted as a test so it cannot quietly change:
  // the same proof verifies again, forever. Freshness is the gate's job (M4).
  await t.test('DOCUMENTS THE GAP: a byte-identical replay is accepted', async () => {
    const first = await v.check(VALID());
    const second = await v.check(VALID());
    assert.equal(first.over_threshold, true);
    assert.equal(second.over_threshold, true, 'the verifier has no memory -- by design');
  });
});
