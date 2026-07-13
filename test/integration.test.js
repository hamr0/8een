/**
 * Drives the real longfellow verifier service. Slow by nature: the circuit load
 * is 44-73s per server and this suite starts seven, so it runs ~4 minutes. The
 * trust-anchor tests use a one-circuit directory (they never verify a proof),
 * which keeps that from becoming ~8.
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
import { readFileSync, existsSync, mkdtempSync, writeFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Verifier, VerifierService, REASONS } from '../src/index.js';

const POC = new URL('../poc/longfellow-zk/', import.meta.url).pathname;
const SERVER_DIR = join(POC, 'reference/verifier-service/server');
const UPSTREAM_CERTS = join(SERVER_DIR, 'certs.pem');

/**
 * Upstream's own certs.pem is malformed: at line 142 an "-----END CERTIFICATE-----"
 * and the next "-----BEGIN CERTIFICATE-----" share a line, which stops Go's
 * pem.Decode dead -- 19 certificates in the file, 17 loaded, no error reported.
 * 8een refuses to run on a silently-truncated trust list (see the test below), so
 * the rest of the suite needs a well-formed bundle. Repairing that one boundary
 * loads all 19; verified.
 */
function wellFormedTrustList() {
  if (!existsSync(UPSTREAM_CERTS)) return UPSTREAM_CERTS;
  const dir = mkdtempSync(join(tmpdir(), '8een-certs-'));
  const out = join(dir, 'certs.pem');
  const repaired = readFileSync(UPSTREAM_CERTS, 'utf8').replaceAll(
    '-----END CERTIFICATE----------BEGIN CERTIFICATE-----',
    '-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----',
  );
  writeFileSync(out, repaired);
  return out;
}

const CIRCUIT_SOURCE = join(POC, 'lib/circuits/mdoc/circuits');

const RIG = {
  binary: join(SERVER_DIR, 'server'),
  circuitDir: CIRCUIT_SOURCE,
  caCerts: wellFormedTrustList(),
  // vicalUrl is deliberately NOT set: the suite exercises 8een's real default,
  // which fetches no trust list at all. Trust here is exactly the PEM bundle.
};

/**
 * A directory holding exactly ONE circuit. The trust-anchor tests below never
 * verify a proof -- they assert on what the verifier trusts -- so they do not
 * need all 17 circuits, and loading one takes ~4s instead of ~45-70s. The
 * all-expected-circuits-loaded guard is still satisfied (1 present, 1 loaded), so
 * this shortens the suite without weakening what it checks.
 */
function oneCircuitDir() {
  if (!existsSync(CIRCUIT_SOURCE)) return CIRCUIT_SOURCE;
  const dir = mkdtempSync(join(tmpdir(), '8een-onecircuit-'));
  const first = readdirSync(CIRCUIT_SOURCE).filter((f) => /^[0-9a-f]{64}$/.test(f)).sort()[0];
  writeFileSync(join(dir, first), readFileSync(join(CIRCUIT_SOURCE, first)));
  return dir;
}
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
    /0 circuit files/,
    'a verifier with no circuits must not come up',
  );
});

// A PARTIALLY loaded verifier is the subtler version of the same trap, and the
// one upstream actively creates: LoadCircuits skips a file whose recomputed
// circuit_id does not match its name, logs it, and carries on. Measured before
// this guard existed: 5 of 17 circuits corrupted -> the server loaded 12, opened
// its port, and we declared ourselves READY. Proofs needing one of the missing 5
// would then be rejected for reasons having nothing to do with the holder.
test('refuses to start when only SOME circuits load', suite, async () => {
  const dir = mkdtempSync(join(tmpdir(), '8een-partial-'));
  const source = new URL('../poc/longfellow-zk/lib/circuits/mdoc/circuits/', import.meta.url).pathname;
  const names = readdirSync(source).filter((f) => /^[0-9a-f]{64}$/.test(f));

  for (const [i, name] of names.entries()) {
    // Corrupt 5 of them. Upstream will skip these and start anyway.
    writeFileSync(join(dir, name), i < 5 ? 'corrupted' : readFileSync(join(source, name)));
  }

  // Not an exact count: we abort at the FIRST rejected file rather than sit
  // through 45s of loading to tally a total we already know is fatal. How many
  // skips have been logged by that instant is a race, and asserting on it would
  // be asserting on the scheduler.
  await assert.rejects(
    Verifier.start({ ...RIG, circuitDir: dir, port: 8915, env: PINNED_CLOCK }),
    /rejected at least \d+ of 17 circuit files as not matching their circuit id/,
    'a half-loaded verifier reports healthy and rejects real proofs -- it must not come up',
  );
});

// The worst place in the system for a silent partial load, and it is real.
// Upstream's LoadIssuerRootCA does `if block == nil { break }` and returns nil --
// SUCCESS -- having quietly stopped early. Its own certs.pem trips it: 19
// certificates in the file, 17 loaded, not a word logged. An operator appending
// their issuer CA to a bundle with a bad boundary would have it dropped in
// silence, and then every proof from that issuer is rejected as untrusted by a
// verifier reporting perfect health.
test('refuses a trust list that silently truncated', suite, async () => {
  const present = (readFileSync(UPSTREAM_CERTS, 'utf8').match(/-----BEGIN CERTIFICATE-----/g) || []).length;
  assert.equal(present, 19, 'upstream ships 19 certificates');

  await assert.rejects(
    Verifier.start({ ...RIG, circuitDir: oneCircuitDir(), caCerts: UPSTREAM_CERTS, port: 8918, env: PINNED_CLOCK }),
    /trust list silently truncated.*19 certificates but the verifier loaded only 17/s,
    'two issuer CAs vanishing without a word must not be survivable',
  );
});

// A verifier that trusts NOBODY rejects every proof as issuer_untrusted -- which
// is shaped exactly like a genuine "no". The circuit trap, wearing the trust
// list's clothes: every legitimate adult turned away by something that sounds
// completely certain.
test('refuses to start when it trusts nobody', suite, async () => {
  const dir = mkdtempSync(join(tmpdir(), '8een-notrust-'));
  const empty = join(dir, 'empty.pem');
  writeFileSync(empty, '# a trust list with no certificates in it\n');

  await assert.rejects(
    Verifier.start({ ...RIG, circuitDir: oneCircuitDir(), caCerts: empty, port: 8916, env: PINNED_CLOCK }),
    /trusts 0 issuer certificates/,
    'a verifier with no trust anchors must not come up',
  );
});

// Upstream defaults -vical_url to AAMVA's US motor-vehicle list and pulls 22
// issuer certs over the network at every boot. 8een must not inherit a trust
// boundary by accident -- and must verify, from the child's own log, that it did
// not get one.
test('does not silently acquire trust anchors over the network', suite, async (t) => {
  const service = new VerifierService({ ...RIG, circuitDir: oneCircuitDir(), port: 8917, env: PINNED_CLOCK });
  await service.start();
  t.after(() => service.stop());

  assert.equal(service.trustAnchors.vical, 0, 'no network trust list may load unless asked for');
  assert.equal(service.trustAnchors.pem, 19, 'every certificate in the bundle, not merely most of them');
  t.diagnostic(`trust anchors: ${JSON.stringify(service.trustAnchors)}`);
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

  // A caller bug is not evidence about a person. Before this guard,
  // Buffer.from(undefined) threw inside the fetch try-block and came back as
  // "service_unreachable" -- sending whoever is on call to debug a healthy network.
  await t.test('a malformed argument is a caller error, not a network failure', async () => {
    for (const bad of [undefined, {}, { transcript: Buffer.from('x') }, { transcript: undefined, deviceResponse: Buffer.from('x') }, { transcript: 'string', deviceResponse: Buffer.from('x') }]) {
      const r = await v.check(bad);
      assert.equal(r.ok, false, `${JSON.stringify(bad)} must not yield a verdict`);
      assert.equal(r.over_threshold, null);
      assert.equal(r.reason, REASONS.INVALID_REQUEST, 'must not masquerade as an unreachable service');
    }
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
