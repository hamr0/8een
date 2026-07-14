/**
 * Drives the real longfellow verifier service. Slow by nature: the circuit load
 * is 44-73s per server and this suite starts several, so it runs ~4 minutes.
 * The trust-anchor tests use a one-circuit directory (they never verify a proof),
 * which keeps that from growing further.
 *
 * Requires the POC clone to be materialized (see poc/M0-EVIDENCE.md step 1) and a
 * Go toolchain with cgo, because the proof fixtures are MINTED at setup by
 * tools/mkfixture rather than committed. Skips cleanly when either is absent, so a
 * fresh checkout still runs green on the unit suite.
 *
 * THE PINNED CLOCK IS GONE (M2).
 * Every earlier cut of this file ran the accept path under ZKVERIFY_FAKE_TIME,
 * because the only real proof we had -- upstream's examples/post1.json -- carried a
 * cert chain that expired 2026-05-07, and a verifier asked to accept it on the real
 * clock would rightly refuse. That pin was scaffolding, and it was load-bearing in a
 * way that made the whole suite quietly weaker: with the clock frozen, no test here
 * could tell a working chain-validator from a broken one.
 *
 * The M2 test-CA removes it. Fixtures are minted at run time under a CA whose
 * validity window straddles the real wall clock, so they verify natively. There is
 * no ZKVERIFY_FAKE_TIME in this file, in src/, or anywhere else in the tree.
 *
 * post1.json could not come with us, and this was measured rather than assumed. On
 * the real clock the service rejects EVERY post1-derived fixture at chain
 * validation -- ok=true, over=false, issuer_untrusted, "x509: certificate has
 * expired" -- the valid one and the deliberately-broken ones alike. Nothing reaches
 * the ZK layer. So the rows that assert ZK_PROOF_INVALID would have gone red, and
 * the row that asserted only ok/over would have passed while testing nothing at all.
 * Either way post1 can no longer exercise what it was there to exercise, and every
 * proof-bearing fixture below is minted instead.
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
const CIRCUIT_SOURCE = join(POC, 'lib/circuits/mdoc/circuits');
const MKFIXTURE_DIR = new URL('../tools/mkfixture/', import.meta.url).pathname;

/**
 * Upstream's own certs.pem is malformed: at line 142 an "-----END CERTIFICATE-----"
 * and the next "-----BEGIN CERTIFICATE-----" share a line, which stops Go's
 * pem.Decode dead -- 19 certificates in the file, 17 loaded, no error reported.
 * 8een refuses to run on a silently-truncated trust list (see the test below), so
 * the trust-anchor tests need a well-formed bundle. Repairing that one boundary
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

function haveGo() {
  try {
    execFileSync('go', ['version'], { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Mint the proof fixtures. They are NOT committed, for two reasons that both matter:
 * the certs would expire and hand us back the very problem the test-CA just solved,
 * and PRD §10 forbids key material in the tree.
 *
 * mkfixture verifies every fixture it emits against longfellow itself before writing
 * it -- a "tampered" proof whose byte-flip landed somewhere inert fails GENERATION
 * rather than shipping as a negative test that silently passes. So a failure here is
 * a real failure and must be loud: we deliberately do NOT catch it and skip. A
 * fixture generator that quietly produces nothing, leaving a green suite behind, is
 * this project's signature bug wearing a lab coat.
 *
 * Measured: ~16s for all nine fixtures, against a suite whose circuit loads dominate
 * at 45-70s per server.
 */
function mintFixtures() {
  const dir = mkdtempSync(join(tmpdir(), '8een-fixtures-'));
  const binary = join(dir, 'mkfixture');
  execFileSync('go', ['build', '-o', binary, '.'], {
    cwd: MKFIXTURE_DIR,
    env: { ...process.env, CGO_ENABLED: '1' },
    stdio: 'pipe',
  });
  execFileSync(binary, ['-circuit-dir', CIRCUIT_SOURCE, '-out', dir], { stdio: 'pipe' });
  return dir;
}

// Building mkfixture links longfellow's static lib through cgo, so the POC's
// install/ prefix must be present too -- not just the server binary. Checking only
// the binary would let a clone that was materialized but never fully built sail past
// the guard and blow up inside `go build` at module import, taking the whole file
// down: including the four circuit/trust-list tests that need no fixtures at all.
// Check every input we are about to depend on, rather than a proxy for them.
const INSTALL = join(SERVER_DIR, '../install');
const REQUIRED = [
  join(SERVER_DIR, 'server'),
  CIRCUIT_SOURCE,
  join(INSTALL, 'lib/libmdoc_static.a'),
  join(INSTALL, 'include/mdoc_zk.h'),
];
const missing = REQUIRED.filter((p) => !existsSync(p));
const skipReason = missing.length
  ? `POC clone not fully built -- missing ${missing.join(', ')} (see poc/M0-EVIDENCE.md step 1)`
  : !haveGo()
    ? 'Go toolchain absent -- needed to mint the M2 fixtures'
    : false;

// Minted once for the whole file. If this throws, the suite fails: see mintFixtures.
const FIXTURES = skipReason ? null : mintFixtures();

const suite = { skip: skipReason };

const RIG = {
  binary: join(SERVER_DIR, 'server'),
  circuitDir: CIRCUIT_SOURCE,
  // The trust boundary for every proof below is the minted CA bundle, and nothing
  // else. vicalUrl is deliberately NOT set: the suite exercises 8een's real default,
  // which fetches no trust list at all.
  caCerts: FIXTURES ? join(FIXTURES, 'caCerts.pem') : UPSTREAM_CERTS,
};

/** The trust-anchor tests assert on what the verifier TRUSTS; they verify no proof. */
const TRUST_RIG = { ...RIG, caCerts: wellFormedTrustList() };

/**
 * A directory holding exactly ONE circuit. The trust-anchor tests never verify a
 * proof, so they do not need all 17 circuits, and loading one takes ~4s instead of
 * ~45-70s. The all-expected-circuits-loaded guard is still satisfied (1 present, 1
 * loaded), so this shortens the suite without weakening what it checks.
 */
function oneCircuitDir() {
  if (!existsSync(CIRCUIT_SOURCE)) return CIRCUIT_SOURCE;
  const dir = mkdtempSync(join(tmpdir(), '8een-onecircuit-'));
  const first = readdirSync(CIRCUIT_SOURCE).filter((f) => /^[0-9a-f]{64}$/.test(f)).sort()[0];
  writeFileSync(join(dir, first), readFileSync(join(CIRCUIT_SOURCE, first)));
  return dir;
}

/** Fixtures are stored as the service's own wire format: base64 in JSON. */
function proof(name) {
  const j = JSON.parse(readFileSync(join(FIXTURES, `${name}.json`), 'utf8'));
  return {
    transcript: Buffer.from(j.Transcript, 'base64'),
    deviceResponse: Buffer.from(j.ZKDeviceResponseCBOR, 'base64'),
  };
}

const VALID = () => proof('valid');
const UNDERAGE = () => proof('underage');
const UNTRUSTED_ISSUER = () => proof('untrusted-issuer');
const TAMPERED = () => proof('tampered');
const STALE_NONCE = () => proof('stale-nonce');
const MANGLED_CERT = () => proof('mangled-cert');
const SUBSTITUTED_CLAIM = () => proof('substituted-claim');

// The zero-circuit trap. A server pointed at an empty directory reports
// /healthz "ok", advertises 12 specs it does not have, and rejects every valid
// proof in a shape identical to a genuine "no". We must refuse to serve at all
// rather than hand out verdicts we cannot make.
test('refuses to start when no circuits loaded, rather than serve confident nonsense', suite, async () => {
  const empty = mkdtempSync(join(tmpdir(), '8een-nocircuits-'));
  await assert.rejects(
    Verifier.start({ ...RIG, circuitDir: empty, port: 8911, startupTimeoutMs: 15_000 }),
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
  const names = readdirSync(CIRCUIT_SOURCE).filter((f) => /^[0-9a-f]{64}$/.test(f));

  for (const [i, name] of names.entries()) {
    // Corrupt 5 of them. Upstream will skip these and start anyway.
    writeFileSync(join(dir, name), i < 5 ? 'corrupted' : readFileSync(join(CIRCUIT_SOURCE, name)));
  }

  // Not an exact count: we abort at the FIRST rejected file rather than sit
  // through 45s of loading to tally a total we already know is fatal. How many
  // skips have been logged by that instant is a race, and asserting on it would
  // be asserting on the scheduler.
  await assert.rejects(
    Verifier.start({ ...RIG, circuitDir: dir, port: 8915 }),
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
    Verifier.start({ ...TRUST_RIG, circuitDir: oneCircuitDir(), caCerts: UPSTREAM_CERTS, port: 8918 }),
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
    Verifier.start({ ...TRUST_RIG, circuitDir: oneCircuitDir(), caCerts: empty, port: 8916 }),
    /trusts 0 issuer certificates/,
    'a verifier with no trust anchors must not come up',
  );
});

// Upstream defaults -vical_url to AAMVA's US motor-vehicle list and pulls 22
// issuer certs over the network at every boot. 8een must not inherit a trust
// boundary by accident -- and must verify, from the child's own log, that it did
// not get one.
test('does not silently acquire trust anchors over the network', suite, async (t) => {
  const service = new VerifierService({ ...TRUST_RIG, circuitDir: oneCircuitDir(), port: 8917 });
  await service.start();
  t.after(() => service.stop());

  assert.equal(service.trustAnchors.vical, 0, 'no network trust list may load unless asked for');
  assert.equal(service.trustAnchors.pem, 19, 'every certificate in the bundle, not merely most of them');
  t.diagnostic(`trust anchors: ${JSON.stringify(service.trustAnchors)}`);
});

// The owner's primary success criterion (PRD §7.1). The strongest form of it: the
// SAME BYTES, accepted or refused on the trust list alone. Not two different proofs
// that happen to land differently -- one proof, two verifiers.
test('trust discrimination: the same proof passes or fails on the trust list alone', suite, async (t) => {
  t.diagnostic('two servers, ~45s each -- circuit load dominates');

  // A real CA, generated at runtime, that simply is not this credential's issuer.
  // Never enters the tree (PRD §10: no key material, no exemption).
  const dir = mkdtempSync(join(tmpdir(), '8een-stranger-ca-'));
  const strangerCa = join(dir, 'stranger.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', join(dir, 'stranger.key'), '-out', strangerCa,
    '-days', '30', '-subj', '/CN=Not The Issuer/O=8een test',
  ], { stdio: 'ignore' });

  const trusted = await Verifier.start({ ...RIG, port: 8912 });
  t.after(() => trusted.stop());
  const accepted = await trusted.check(VALID());

  const stranger = await Verifier.start({ ...RIG, caCerts: strangerCa, port: 8913 });
  t.after(() => stranger.stop());
  const rejected = await stranger.check(VALID());

  assert.deepEqual(
    { ok: accepted.ok, over: accepted.over_threshold, reason: accepted.reason },
    { ok: true, over: true, reason: REASONS.VERIFIED },
    'issuer on the trust list: accept -- on the REAL clock, with no ZKVERIFY_FAKE_TIME',
  );
  assert.equal(rejected.over_threshold, false, 'issuer NOT on the trust list: the very same bytes must fail');
  assert.equal(rejected.ok, true, 'and that is a real answer, not a breakage');
  assert.equal(rejected.reason, REASONS.ISSUER_UNTRUSTED);
});

test('the negative matrix (PRD §7.1)', suite, async (t) => {
  // One loaded service, two thresholds on top of it -- both via the public
  // surface, so the suite never reaches into internals to make a point.
  const service = new VerifierService({ ...RIG, port: 8914 });
  await service.start();
  t.after(() => service.stop());

  const v = new Verifier(service, 'age_over_18');
  const strict = new Verifier(service, 'age_over_21');

  assert.equal(service.circuitsLoaded, 17, 'circuits actually on disk, counted from the child log');

  await t.test('a valid proof of the required claim is accepted', async () => {
    const r = await v.check(VALID());
    assert.equal(r.ok, true);
    assert.equal(r.over_threshold, true);
    assert.equal(r.reason, REASONS.VERIFIED);
  });

  // The row that only became testable at M2: an HONEST proof of a FALSE claim.
  // The proof is valid -- Status:true -- and the answer is still no. A consumer
  // reading Status alone accepts a validly-proven minor, which is the whole reason
  // over-18 is (Status==true AND claim==true) and never Status by itself.
  await t.test('an underage holder is refused, though the proof is perfectly valid', async () => {
    const r = await v.check(UNDERAGE());
    assert.equal(r.ok, true, 'this IS an answer -- the proof verified');
    assert.equal(r.over_threshold, false);
    assert.equal(r.reason, REASONS.CLAIM_FALSE, 'refused for what it says, not because verification broke');
  });

  await t.test('a proof from an issuer off the trust list is rejected', async () => {
    const r = await v.check(UNTRUSTED_ISSUER());
    assert.equal(r.ok, true);
    assert.equal(r.over_threshold, false);
    assert.equal(r.reason, REASONS.ISSUER_UNTRUSTED, 'refused at the chain, not at the ZK layer');
  });

  await t.test('a tampered proof is rejected', async () => {
    const r = await v.check(TAMPERED());
    assert.equal(r.ok, true);
    assert.equal(r.over_threshold, false);
    assert.equal(r.reason, REASONS.ZK_PROOF_INVALID);
  });

  // PRD §7.1's "a replayed proof (wrong/stale nonce)". A GOOD proof of a GOOD
  // credential from a TRUSTED issuer -- lifted out of the session it was bound to
  // and replayed into another one. The device signature is what catches it.
  //
  // Read alongside the byte-identical-replay test at the bottom of this file: that
  // one is accepted, this one is refused, and the difference is the whole of what
  // the verifier can and cannot do about replay. Cross-session lifting: caught here,
  // by cryptography. Same-session repetition: not caught, by design -- the verifier
  // is stateless and freshness belongs to the gate (M4).
  await t.test('a proof replayed into a different session is rejected', async () => {
    const r = await v.check(STALE_NONCE());
    assert.equal(r.ok, true, 'this is a verdict about the proof, not a breakage');
    assert.equal(r.over_threshold, false);
    assert.equal(r.reason, REASONS.ZK_PROOF_INVALID);
  });

  // A corrupted signature on an otherwise well-formed cert. The ZK proof inside is
  // valid -- mkfixture asserts that before emitting it -- so a pass here would mean
  // the chain was never checked at all.
  //
  // The reason is asserted, not just the verdict. Every other rejection row here
  // pins its reason; this one did not, which meant the chain-vs-ZK distinction it
  // exists to prove was documented and unchecked -- a regression that classified a
  // chain failure as zk_proof_invalid would have kept it green. The reason SPLIT is
  // diagnostic (both branches reject), but that is exactly why it has to be pinned:
  // it is the only thing distinguishing this row from the tampered one.
  await t.test('a proof with a mangled cert chain is rejected at the CHAIN, not crashed on', async () => {
    const r = await v.check(MANGLED_CERT());
    assert.equal(r.ok, true);
    assert.equal(r.over_threshold, false);
    assert.equal(r.reason, REASONS.ISSUER_UNTRUSTED, 'a broken chain must not be reported as a bad proof');
  });

  // The sharpest form of the Claims-echo trap, and the one a holder can mount alone:
  // an honest minor takes their own VALID age_over_18=false proof and flips one byte
  // of the wire envelope so it CLAIMS true. Nothing is forged; the proof and the
  // chain are genuine. Only the envelope lies.
  //
  // What refuses it is the binding: the service verifies against the value it reads
  // from the ENVELOPE (reference/.../zk/cbor.go:235), so the circuit is asked to show
  // a credential committing false has elementValue true, and the constraint fails. If
  // that binding broke, this would be a false ACCEPT of a minor -- the one direction
  // 8een cannot tolerate.
  await t.test('a minor cannot relabel their own valid proof as over-18', async () => {
    const r = await v.check(SUBSTITUTED_CLAIM());
    assert.equal(r.ok, true);
    assert.equal(r.over_threshold, false, 'a false ACCEPT here would be the worst bug in the system');
    assert.equal(r.reason, REASONS.ZK_PROOF_INVALID);
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
  //
  // This is NOT a failing expectation and must not be "fixed". Compare the
  // stale-nonce test above: a proof moved to a DIFFERENT session is refused. What is
  // accepted here is the identical proof in its OWN session, twice.
  await t.test('DOCUMENTS THE GAP: a byte-identical replay is accepted', async () => {
    const first = await v.check(VALID());
    const second = await v.check(VALID());
    assert.equal(first.over_threshold, true);
    assert.equal(second.over_threshold, true, 'the verifier has no memory -- by design');
  });
});

/**
 * PRD §7.3, behavioural half -- and an honest account of what it does and does not
 * establish, because the first cut of this test overstated it and a review caught it.
 *
 * WHAT THIS CANNOT SHOW. A Verdict for any accepted proof is the constant object
 * {ok:true, over_threshold:true, reason:'verified', detail:'age_over_18'} -- there is
 * no field in it that COULD carry per-presentation data. So asserting the three
 * verdicts are equal is a tautology: it is already implied by asserting they all
 * verify, and it would hold even for a verifier that leaked a holder's identity
 * somewhere else entirely. It is kept below as a smoke check, and it is NOT evidence.
 *
 * WHERE THE EVIDENCE ACTUALLY IS. The falsifiable check is
 * TestProofBytesCarryNoPerCredentialIdentifier in tools/mkfixture/unlink_test.go: it
 * compares the byte overlap between two presentations of the SAME credential against
 * two presentations of DIFFERENT credentials from the same issuer, with a
 * self-comparison as the harness control. A stable identifier hidden in the proof
 * would show up as excess same-credential overlap, and the test goes red. Measured:
 * self 360,013 shared 8-grams (the detector works), same-credential 1,
 * different-credential 1 -- background, and equal. It lives in Go because reading a
 * proof back means decoding CBOR, and 8een parses no CBOR and will not grow a parser
 * to test itself (NO-GO #8).
 *
 * STILL NOT CLAIMED: full cryptographic unlinkability. A byte-overlap probe can find
 * a naive identifier; it cannot rule out a subtle one. PRD §7.3 scopes that as cited,
 * not claimed -- it rests on the scheme's security analysis, not on us.
 */
test('unlinkability: two presentations of one credential are indistinguishable (PRD §7.3)', suite, async (t) => {
  const service = new VerifierService({ ...RIG, port: 8919 });
  await service.start();
  t.after(() => service.stop());

  const v = new Verifier(service, 'age_over_18');

  const a1 = await v.check(proof('unlinkable-a1'));
  const a2 = await v.check(proof('unlinkable-a2'));
  const b1 = await v.check(proof('unlinkable-b1'));

  // An unlinkability claim over proofs that do not verify would be worthless.
  for (const [name, r] of [['a1', a1], ['a2', a2], ['b1', b1]]) {
    assert.equal(r.ok, true, `${name} must verify`);
    assert.equal(r.over_threshold, true, `${name} must verify`);
  }

  // SMOKE CHECK, not evidence -- see the header. The verdict object is constant for
  // every accepted proof, so this cannot discriminate and cannot fail on its own. It
  // is here to catch the crude regression where a verdict starts carrying something
  // per-presentation at all (a session id, a serial, a timestamp): that WOULD break
  // these equalities, and it is the only thing they can detect.
  assert.deepEqual(a1, a2, 'the verdict must not start carrying per-presentation data');
  assert.deepEqual(a1, b1, 'nor anything that distinguishes one credential from another');

  // The presentations really were different bytes on the wire. Without this the
  // equalities above would be comparing a proof with itself.
  const wireA1 = readFileSync(join(FIXTURES, 'unlinkable-a1.json'), 'utf8');
  const wireA2 = readFileSync(join(FIXTURES, 'unlinkable-a2.json'), 'utf8');
  assert.notEqual(wireA1, wireA2, 'the two presentations must not be byte-identical, or this proves nothing');

  t.diagnostic(`verdicts identical across 3 presentations: ${JSON.stringify(a1)}`);
  t.diagnostic('the falsifiable check is TestProofBytesCarryNoPerCredentialIdentifier (tools/mkfixture)');
});
