import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, readdirSync, readFileSync, statSync, writeFileSync, chmodSync } from 'node:fs';
import { createHash } from 'node:crypto';
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

/**
 * musl detection asks about the HOST's libc, but `opts.platform` names the TARGET --
 * and the two are independent (baking a glibc container image from an Alpine CI
 * runner is the documented use of that override). A guard that conflates them
 * refuses a download that would have been correct.
 *
 * Simulating musl means removing `glibcVersionRuntime` from the diagnostic report,
 * which is precisely what Node reports on Alpine -- verified against a real
 * `node:22-alpine` container, where `process.platform`-`process.arch` also reads
 * `linux-x64`, which is the whole trap.
 */
async function asMuslHost(fn) {
  const real = process.report.getReport.bind(process.report);
  process.report.getReport = () => {
    const r = real();
    delete r.header.glibcVersionRuntime;
    return r;
  };
  try {
    return await fn();
  } finally {
    process.report.getReport = real;
  }
}

test('musl refuses an implicit provision but never an explicitly targeted one', {
  skip: manifest.binaries[HERE] ? false : 'needs a pinned platform for this host',
}, async () => {
  // Non-vacuity: on a simulated musl host, provisioning FOR THIS PROCESS is refused.
  await asMuslHost(() =>
    assert.rejects(provisionBinary(tmp('bin-musl-host')), (err) => {
      assert.match(err.message, /musl system \(Alpine\)/);
      assert.match(err.message, /binary:/, 'must name the BYO escape hatch');
      assert.match(err.message, /platform:/, 'must name the cross-provision escape hatch');
      return true;
    }),
  );

  // The regression. Both sides of a cross-provision are `linux-x64` -- the platform
  // key has no libc dimension -- so an explicit `platform:` is the ONLY way to say
  // "these bytes are for elsewhere". It must get past the musl gate.
  //
  // A fetchImpl that cannot connect proves we reached the download without pulling
  // 10 MB: reaching "cannot reach" means the musl refusal did not fire.
  await asMuslHost(() =>
    assert.rejects(
      provisionBinary(tmp('bin-musl-x'), {
        platform: HERE,
        fetchImpl: () => Promise.reject(new Error('offline')),
      }),
      (err) => {
        assert.doesNotMatch(err.message, /musl/, 'an explicit target is not about this host');
        assert.match(err.message, /cannot reach/, 'should have proceeded to the fetch');
        return true;
      },
    ),
  );
});

test('resolveProvisionedBinary refuses an empty or mismatched dir, naming the fix', async () => {
  const dir = tmp('bin-empty');
  await assert.rejects(resolveProvisionedBinary(dir, PINNED), /Run provisionBinary\(\)/);

  // A file with the right name and wrong bytes is exactly as unacceptable as no
  // file: unlike a circuit, nothing downstream can re-check a binary.
  writeFileSync(join(dir, `${pinnedEntry.asset}-${manifest.release}`), 'not the verifier');
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
const realPath = entry ? join(defaultBinaryDir(), `${entry.asset}-${manifest.release}`) : null;
// Gate on the PIN, not the size: a byte-rotted file of the right length is
// exactly what this module exists to refuse, so it must not be what unlocks
// the accept-path tests.
const haveReal =
  realPath != null &&
  existsSync(realPath) &&
  createHash('sha256').update(readFileSync(realPath)).digest('hex') === entry.sha256;
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
  // The release tag is part of the cached filename: two zk8een versions pinning
  // different releases must not share one cache file and clobber each other.
  assert.equal(cold.path, join(dir, `${entry.asset}-${manifest.release}`));
  assert.match(cold.path, new RegExp(`${manifest.release}$`));
  assert.equal(requests, 1);
  assert.ok(statSync(cold.path).mode & 0o100, 'must be executable');

  const warm = await provisionBinary(dir, { fetchImpl: counting });
  assert.equal(warm.action, 'present');
  assert.equal(requests, 1, 'a second run must not touch the network at all');

  assert.equal(await resolveProvisionedBinary(dir), cold.path);
});

// REGRESSION. writeFile's `mode` is masked by the process umask, so under a
// umask that clears execute bits the freshly-fetched binary landed 0644:
// hash-perfect and unspawnable, failing later as a bare EACCES nowhere near the
// cause. Measured before the chmod was added.
test('a restrictive umask cannot leave the fetched binary non-executable', needsReal, async () => {
  const dir = tmp('bin-umask');
  const prev = process.umask(0o111);
  try {
    const r = await provisionBinary(dir, { fetchImpl: serving(realBytes()) });
    assert.ok(statSync(r.path).mode & 0o100, 'the binary must be executable despite the umask');
  } finally {
    process.umask(prev);
  }
});

// REGRESSION. Bytes and mode are separate failures: a cache restored by a tool
// that drops modes leaves the pin satisfied and the binary unrunnable. Resolve
// must say so itself rather than let spawn fail far away.
test('resolve refuses a byte-correct binary that is not executable, naming the fix', needsReal, async () => {
  const dir = tmp('bin-noexec');
  const r = await provisionBinary(dir, { fetchImpl: serving(realBytes()) });
  chmodSync(r.path, 0o644);

  await assert.rejects(resolveProvisionedBinary(dir), (err) => {
    assert.match(err.message, /not executable/);
    assert.match(err.message, /provisionBinary\(\)|chmod/, 'must name the fix');
    return true;
  });

  // And provisioning repairs it without re-downloading.
  const repaired = await provisionBinary(dir, { fetchImpl: serving(realBytes()) });
  assert.equal(repaired.action, 'present');
  assert.equal(await resolveProvisionedBinary(dir), repaired.path);
});

test('a binary that rots on disk is refused by resolve and replaced by provision', needsReal, async () => {
  const dir = tmp('bin-rot');
  await provisionBinary(dir, { fetchImpl: serving(realBytes()) });

  writeFileSync(join(dir, `${entry.asset}-${manifest.release}`), 'corrupted');
  await assert.rejects(resolveProvisionedBinary(dir), /Run provisionBinary\(\)/);

  const repaired = await provisionBinary(dir, { fetchImpl: serving(realBytes()) });
  assert.equal(repaired.action, 'fetched', 'the damaged binary is re-fetched');
  assert.equal(await resolveProvisionedBinary(dir), repaired.path);
});

// REGRESSION. `opts.binary ?? resolve()` treats only null/undefined as omitted,
// so `binary: process.env.VERIFIER_BIN` with the var set-but-empty slipped an
// empty string through to spawn. Neither silently substituting the provisioned
// binary nor spawning '' is acceptable: it is a config error and must say so.
test('an empty or non-string binary is a loud config error, not a silent fallback', async () => {
  const { Verifier } = await import('../src/index.js');
  for (const bad of ['', '   ', 42, {}]) {
    await assert.rejects(
      Verifier.start({ binary: bad, circuitDir: './c', caCerts: './p.pem' }),
      (err) => {
        assert.ok(err instanceof TypeError, `${JSON.stringify(bad)} must be a TypeError`);
        assert.match(err.message, /binary must be a non-empty path/);
        assert.match(err.message, /omit it entirely/, 'must name the intended alternative');
        return true;
      },
      `binary: ${JSON.stringify(bad)} must be refused`,
    );
  }
});
