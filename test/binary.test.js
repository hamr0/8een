import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  provisionBinary,
  resolveProvisionedBinary,
  defaultBinaryDir,
  binaryManifest as manifest,
} from '../src/binary.js';

const tmp = (tag) => mkdtempSync(join(tmpdir(), `8een-${tag}-`));
const HERE = `${process.platform}-${process.arch}`;
const entry = manifest.binaries[HERE];

// Only linux-x64 has a pinned prebuilt (PRD D11); on any other platform the
// refusal tests below still run by naming the platform explicitly.
const PINNED = entry ? { platform: HERE } : { platform: 'linux-x64' };
const pinnedEntry = manifest.binaries[PINNED.platform];

/** A fetch that serves whatever bytes the test tells it to. No network, no mocking library. */
const serving = (body, headers = {}) => async () => ({
  ok: true,
  status: 200,
  headers: { get: (k) => headers[k] },
  arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength),
});

test('the binary manifest is pinned: real hashes, real sizes, the patched baseline', () => {
  assert.match(manifest.commit, /^[0-9a-f]{40}$/);
  assert.match(manifest.release, /^longfellow-bin-\d+$/);
  assert.deepEqual(manifest.patches, [
    '0001-zkverify-fake-time.patch',
    '0002-eu-circuit-id-compat.patch',
    '0003-m4-echo-verified-timestamp.patch',
  ]);
  for (const [platform, e] of Object.entries(manifest.binaries)) {
    assert.match(e.asset, /^longfellow-verifier-[a-z0-9-]+$/, platform);
    assert.match(e.sha256, /^[0-9a-f]{64}$/, `${platform} must pin a real sha256, not a placeholder`);
    assert.ok(e.bytes > 1_000_000, `${platform} must pin the real size`);
  }
});

// The whole point of the pin: bytes the release host serves that are not the
// bytes the workflow built must never land on disk as an executable.
test('bytes that do not match the pinned hash are refused and never written', async () => {
  const dir = tmp('bin-badhash');
  const impostor = Buffer.alloc(pinnedEntry.bytes || 8, 0x41);

  await assert.rejects(
    provisionBinary(dir, { ...PINNED, fetchImpl: serving(impostor) }),
    /SHA256 MISMATCH/,
  );
  assert.equal(readdirSync(dir).length, 0, 'nothing may be left on disk, not even a partial');
});

test('a truncated download is refused', async () => {
  const dir = tmp('bin-short');
  await assert.rejects(
    provisionBinary(dir, { ...PINNED, fetchImpl: serving(Buffer.alloc(10)) }),
    /expected \d+ bytes, got 10/,
  );
  assert.equal(readdirSync(dir).length, 0);
});

test('an oversized advertised body is refused before it is read', async () => {
  const dir = tmp('bin-huge');
  let bodyRead = false;
  const fetchImpl = async () => ({
    ok: true,
    status: 200,
    headers: { get: (k) => (k === 'content-length' ? String(10 * 1024 * 1024 * 1024) : null) },
    arrayBuffer: async () => {
      bodyRead = true;
      return new ArrayBuffer(0);
    },
  });
  await assert.rejects(provisionBinary(dir, { ...PINNED, fetchImpl }), /advertises \d+ bytes/);
  assert.equal(bodyRead, false, 'the body must never be read into memory');
});

test('an unreachable or erroring release host fails loudly', async () => {
  await assert.rejects(
    provisionBinary(tmp('bin-500'), { ...PINNED, fetchImpl: async () => ({ ok: false, status: 503 }) }),
    /HTTP 503/,
  );
  await assert.rejects(
    provisionBinary(tmp('bin-down'), {
      ...PINNED,
      fetchImpl: async () => {
        throw new Error('ECONNREFUSED');
      },
    }),
    /cannot reach/,
  );
});

test('a platform we have no prebuilt for is refused with the way out named', async () => {
  await assert.rejects(provisionBinary(tmp('bin-plat'), { platform: 'sunos-ia32' }), (err) => {
    assert.match(err.message, /no prebuilt verifier binary for sunos-ia32/);
    assert.match(err.message, /poc\/M0-EVIDENCE\.md/, 'must point at the BYO build docs');
    assert.match(err.message, /binary:/, 'must name the escape hatch');
    return true;
  });
});

test('resolveProvisionedBinary refuses an empty or mismatched dir, naming the fix', async () => {
  const dir = tmp('bin-empty');
  await assert.rejects(resolveProvisionedBinary(dir, PINNED), /Run provisionBinary\(\)/);

  // A file with the right name and wrong bytes is exactly as unacceptable as no
  // file: unlike a circuit, nothing downstream can re-check a binary.
  writeFileSync(join(dir, pinnedEntry.asset), 'not the verifier');
  await assert.rejects(resolveProvisionedBinary(dir, PINNED), /Run provisionBinary\(\)/);
});

test('defaultBinaryDir honors XDG_CACHE_HOME at call time', () => {
  const prev = process.env.XDG_CACHE_HOME;
  try {
    process.env.XDG_CACHE_HOME = '/somewhere/cache';
    assert.equal(defaultBinaryDir(), join('/somewhere/cache', 'zk8een'));
  } finally {
    if (prev === undefined) delete process.env.XDG_CACHE_HOME;
    else process.env.XDG_CACHE_HOME = prev;
  }
});

// From here on we need the genuine released bytes. They are present exactly when
// this machine has provisioned for real (the integration environment does); the
// tests then exercise the accept path with real, uncrafted data -- and skip
// cleanly, stating why, everywhere else.
const realPath = entry ? join(defaultBinaryDir(), entry.asset) : null;
const haveReal =
  realPath != null && existsSync(realPath) && statSync(realPath).size === entry.bytes;
const needsReal = {
  skip: haveReal ? false : 'no provisioned binary in defaultBinaryDir (run provisionBinary() once)',
};
const realBytes = () => readFileSync(/** @type {string} */ (realPath));

test('provisions the pinned binary executable, then does not re-fetch it', needsReal, async () => {
  const dir = tmp('bin-good');
  let requests = 0;
  const counting = async (...args) => {
    requests += 1;
    return serving(realBytes())(...args);
  };

  const cold = await provisionBinary(dir, { fetchImpl: counting });
  assert.equal(cold.action, 'fetched');
  assert.equal(cold.path, join(dir, entry.asset));
  assert.equal(requests, 1);
  assert.ok(statSync(cold.path).mode & 0o100, 'must be executable');

  const warm = await provisionBinary(dir, { fetchImpl: counting });
  assert.equal(warm.action, 'present');
  assert.equal(requests, 1, 'a second run must not touch the network at all');

  assert.equal(await resolveProvisionedBinary(dir), cold.path);
});

test('a binary that rots on disk is refused by resolve and replaced by provision', needsReal, async () => {
  const dir = tmp('bin-rot');
  await provisionBinary(dir, { fetchImpl: serving(realBytes()) });

  writeFileSync(join(dir, entry.asset), 'corrupted');
  await assert.rejects(resolveProvisionedBinary(dir), /Run provisionBinary\(\)/);

  const repaired = await provisionBinary(dir, { fetchImpl: serving(realBytes()) });
  assert.equal(repaired.action, 'fetched', 'the damaged binary is re-fetched');
  assert.equal(await resolveProvisionedBinary(dir), repaired.path);
});
