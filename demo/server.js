/**
 * 8een replay-defense demo (M4 piece 3). REPO-ONLY -- not in package `files`, never
 * shipped (it needs the longfellow verifier binary the package deliberately does not
 * ship, exactly like poc/).
 *
 * What is REAL here: the HTTP gate, real longfellow verification of a real proof, and
 * the real single-use nonce spend. Click "verify" and the same bytes are accepted
 * once and refused on replay -- that refusal is 8een's spent-nonce memory firing, not
 * a broken proof.
 *
 * What is STUBBED, and why: the wallet. A real proof is made by a wallet on a user's
 * phone, and we cannot drive one on this host (the Android emulator is a documented
 * dead end -- see project memory). So at boot we pre-mint a small POOL of real proofs
 * with `tools/mkfixture`, each bound to a nonce 8een issued and each under its own
 * test CA; the verifier is started trusting the concatenation of those CAs. The
 * "wallet" endpoint just hands the browser the next pooled proof. Everything the GATE
 * does to it afterwards is the genuine article.
 *
 * Run:  node demo/server.js   (boot is ~1-2 min: minting proofs + the 44-73s circuit load)
 * Then: open http://127.0.0.1:3000
 */

import http from 'node:http';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes } from 'node:crypto';
import { startGate, issueChallenge } from '../src/index.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, '..');
const POC = join(ROOT, 'poc/longfellow-zk');
const SERVER_BIN = join(POC, 'reference/verifier-service/server/server');
const CIRCUIT_DIR = join(POC, 'lib/circuits/mdoc/circuits');
const MKFIXTURE_DIR = join(ROOT, 'tools/mkfixture');

const WEB_PORT = Number(process.env.PORT ?? 3000);
const VERIFIER_PORT = Number(process.env.VERIFIER_PORT ?? 8951);
const POOL_SIZE = Number(process.env.POOL_SIZE ?? 3); // verify once + a couple of "new session"s
const NONCE_TTL_MS = 24 * 60 * 60 * 1000; // long, so a leisurely demo never expires the nonce

/** Build mkfixture once (cgo links the install/ prefix via #cgo directives in the .go files). */
function buildMkfixture() {
  const bin = join(mkdtempSync(join(tmpdir(), '8een-demo-mkfixture-')), 'mkfixture');
  execFileSync('go', ['build', '-o', bin, '.'], {
    cwd: MKFIXTURE_DIR,
    env: { ...process.env, CGO_ENABLED: '1' },
    stdio: 'pipe',
  });
  return bin;
}

/** Mint one real fixture set bound to `nonceHex`; return its dir. Self-verifies before writing. */
function mint(bin, nonceHex) {
  const dir = mkdtempSync(join(tmpdir(), '8een-demo-fixtures-'));
  execFileSync(bin, ['-circuit-dir', CIRCUIT_DIR, '-out', dir, '-session-nonce', nonceHex], { stdio: 'pipe' });
  return dir;
}

const b64toUrl = (b64std) => Buffer.from(b64std, 'base64').toString('base64url');

async function boot() {
  console.log('[demo] building mkfixture (cgo)...');
  const bin = buildMkfixture();

  // ONE secret authenticates every nonce the gate issues AND every pooled proof binds to.
  const secret = randomBytes(32);

  console.log(`[demo] minting ${POOL_SIZE} real proofs (each ~18s, self-verified against longfellow)...`);
  /** @type {{id:number, nonceB64:string, proof:{transcript:string, deviceResponse:string}}[]} */
  const pool = [];
  const caChunks = [];
  for (let i = 0; i < POOL_SIZE; i++) {
    const ch = issueChallenge({ secret, ttlMs: NONCE_TTL_MS });
    const dir = mint(bin, Buffer.from(ch.nonce).toString('hex'));
    const j = JSON.parse(readFileSync(join(dir, 'single-use.json'), 'utf8'));
    pool.push({
      id: i,
      nonceB64: Buffer.from(ch.nonce).toString('base64url'),
      proof: {
        transcript: b64toUrl(j.Transcript),
        deviceResponse: b64toUrl(j.ZKDeviceResponseCBOR),
      },
    });
    caChunks.push(readFileSync(join(dir, 'caCerts.pem')));
    console.log(`[demo]   proof ${i + 1}/${POOL_SIZE} minted`);
  }
  // Trust the UNION of every pooled proof's CA. A caCerts bundle is just concatenated PEM.
  const caBundle = join(mkdtempSync(join(tmpdir(), '8een-demo-ca-')), 'caCerts.pem');
  writeFileSync(caBundle, Buffer.concat(caChunks));

  console.log('[demo] starting the gate (loads 17 circuits, 44-73s)...');
  const gate = await startGate({
    binary: SERVER_BIN,
    circuitDir: CIRCUIT_DIR,
    caCerts: caBundle,
    port: VERIFIER_PORT,
    // Replay is the whole point here; the pooled proofs are fresh, so isolate the story
    // from credential currency (which M4 piece 1 covers on its own).
    requireCurrentValidity: false,
    // Replay-safe by DEFAULT (piece 3): startGate turns requireSingleUse on and would
    // refuse to boot without these two. store:'memory' is the single-process dev shortcut.
    challengeSecret: secret,
    store: 'memory',
    challengeTtlMs: NONCE_TTL_MS,
  });
  console.log('[demo] gate ready:', gate.verifier.ready, '| circuits:', gate.verifier.circuitsLoaded);

  // The "wallet": hand out the next pooled proof. This is the ONLY stubbed step.
  let handedOut = 0;
  const indexHtml = readFileSync(join(HERE, 'index.html'));

  const gateMw = gate.express();
  const server = http.createServer((req, res) => {
    // The gate owns /8een/*; everything else is the demo shell.
    gateMw(req, res, () => {
      const url = new URL(req.url ?? '/', 'http://localhost');
      if (req.method === 'GET' && url.pathname === '/') {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
        return res.end(indexHtml);
      }
      if (req.method === 'POST' && url.pathname === '/demo/wallet') {
        if (handedOut >= pool.length) {
          res.writeHead(410, { 'content-type': 'application/json' });
          return res.end(JSON.stringify({ error: 'demo pool exhausted -- restart the server for more sessions' }));
        }
        const entry = pool[handedOut++];
        res.writeHead(200, { 'content-type': 'application/json' });
        return res.end(JSON.stringify({
          session: entry.id + 1,
          poolRemaining: pool.length - handedOut,
          // A short, friendly fingerprint of the nonce this proof is stamped with.
          nonceFingerprint: entry.nonceB64.slice(0, 10),
          proof: entry.proof,
        }));
      }
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not found' }));
    });
  });

  server.listen(WEB_PORT, '127.0.0.1', () => {
    console.log(`\n[demo] ✅ open  http://127.0.0.1:${WEB_PORT}\n`);
  });

  const shutdown = async () => {
    console.log('\n[demo] shutting down...');
    await new Promise((r) => server.close(r)); // let in-flight responses flush before we exit
    await gate.stop();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

boot().catch((e) => {
  console.error('[demo] boot failed:', e);
  process.exit(1);
});
