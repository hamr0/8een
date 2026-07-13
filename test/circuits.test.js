import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readFileSync, writeFileSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { provision, manifest } from '../src/circuits.js';

const tmp = (tag) => mkdtempSync(join(tmpdir(), `8een-${tag}-`));
const first = manifest.circuits[0];

/** A fetch that serves whatever bytes the test tells it to. No network, no mocking library. */
const serving = (bytesFor) => async (url) => {
  const id = url.split('/').pop();
  const body = bytesFor(id);
  if (!body) return { ok: false, status: 404 };
  return { ok: true, status: 200, arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength) };
};

test('the manifest is pinned to a specific upstream commit', () => {
  assert.match(manifest.commit, /^[0-9a-f]{40}$/);
  assert.equal(manifest.circuits.length, 17);
  for (const c of manifest.circuits) {
    assert.match(c.id, /^[0-9a-f]{64}$/);
    assert.match(c.sha256, /^[0-9a-f]{64}$/);
    assert.ok(c.bytes > 0);
  }
});

// The whole point of the checksum. A network that serves us something else --
// a compromised mirror, a MITM, a silently-rewritten artifact -- must not get
// its bytes anywhere near the verifier.
test('bytes that do not match the pinned hash are refused and never written', async () => {
  const dir = tmp('badhash');
  // Right length, wrong content: forces the check past the size guard onto the hash.
  const impostor = Buffer.alloc(first.bytes, 0x41);

  await assert.rejects(
    provision(dir, { fetchImpl: serving(() => impostor) }),
    /SHA256 MISMATCH/,
    'a hash mismatch must abort provisioning',
  );
  assert.equal(readdirSync(dir).length, 0, 'nothing may be left on disk, not even a partial');
});

test('a truncated download is refused', async () => {
  const dir = tmp('short');
  await assert.rejects(
    provision(dir, { fetchImpl: serving(() => Buffer.alloc(10)) }),
    /expected \d+ bytes, got 10/,
  );
  assert.equal(readdirSync(dir).length, 0);
});

test('an unreachable or erroring source fails loudly', async () => {
  const dir = tmp('http500');
  await assert.rejects(
    provision(dir, { fetchImpl: async () => ({ ok: false, status: 503 }) }),
    /HTTP 503/,
  );

  await assert.rejects(
    provision(tmp('down'), { fetchImpl: async () => { throw new Error('ECONNREFUSED'); } }),
    /cannot reach/,
  );
});

// From here on we need the genuine circuit bytes, which live in the POC clone.
const SOURCE = new URL('../poc/longfellow-zk/lib/circuits/mdoc/circuits/', import.meta.url).pathname;
const haveSource = existsSync(join(SOURCE, first.id));
const needsSource = { skip: haveSource ? false : 'POC clone not materialized (see poc/M0-EVIDENCE.md)' };
const realBytes = (id) => (existsSync(join(SOURCE, id)) ? readFileSync(join(SOURCE, id)) : null);

test('provisions every pinned circuit, then does not re-fetch them', needsSource, async () => {
  const dir = tmp('good');
  let requests = 0;
  const counting = serving((id) => { requests += 1; return realBytes(id); });

  const cold = await provision(dir, { fetchImpl: counting });
  assert.equal(cold.fetched, 17);
  assert.equal(cold.present, 0);
  assert.equal(requests, 17);

  const warm = await provision(dir, { fetchImpl: counting });
  assert.equal(warm.present, 17, 'a second run must find them all intact');
  assert.equal(warm.fetched, 0);
  assert.equal(requests, 17, 'and must not touch the network at all');
});

test('a circuit that rots on disk is detected and replaced', needsSource, async () => {
  const dir = tmp('rot');
  await provision(dir, { fetchImpl: serving(realBytes) });

  writeFileSync(join(dir, first.id), 'corrupted');

  const repaired = await provision(dir, { fetchImpl: serving(realBytes) });
  assert.equal(repaired.fetched, 1, 'the damaged one is re-fetched');
  assert.equal(repaired.present, 16, 'the intact ones are left alone');
  assert.notEqual(readFileSync(join(dir, first.id), 'utf8'), 'corrupted');
});
