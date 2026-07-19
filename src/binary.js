/**
 * Puts the longfellow verifier binary on disk, and refuses bytes that are not
 * the ones we pinned (PRD §9 D11).
 *
 * The binary is longfellow's own reference verifier service -- upstream commit
 * plus the tracked patch series in `poc/patches/` (the build baseline) -- built
 * by a public GitHub Actions workflow (`.github/workflows/binaries.yml`), never
 * on someone's laptop. The workflow proves each binary by running the full
 * integration suite against it before upload, and every released byte is
 * auditable back to the workflow run that produced it.
 *
 * Same trust model as `circuits.js`: the manifest inside THIS package pins the
 * sha256, so the download host (GitHub Releases) is untrusted. A byte off and
 * we delete it and stop. And because a binary -- unlike a circuit -- cannot be
 * re-checked by the service at load time, `resolveProvisionedBinary()` re-hashes
 * it on every verifier start: a binary that rots (or is swapped) on disk is
 * refused, never silently run.
 */

import { createHash, randomUUID } from 'node:crypto';
import { access, chmod, mkdir, readFile, writeFile, rename, unlink } from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import rawManifest from './binary.manifest.json' with { type: 'json' };

/**
 * The manifest's shape is declared rather than inferred from the JSON, and that
 * is deliberate: inferring it makes `tsc` emit `import ... from
 * './binary.manifest.json'` into the PUBLIC .d.ts, which then fails in every
 * adopter's typecheck -- the JSON is not shipped into `types/`, and resolving it
 * would demand `resolveJsonModule` in their tsconfig besides. Measured against a
 * real `npm pack` + install: two TS2307s from inside node_modules. Keep the
 * annotation, or the types stop being installable.
 *
 * @typedef {{asset: string, sha256: string, bytes: number}} BinaryEntry
 * @typedef {{upstream: string, commit: string, patches: string[], release: string,
 *   binaries: Record<string, BinaryEntry>}} BinaryManifest
 */

/** @type {BinaryManifest} */
const manifest = rawManifest;

export { manifest as binaryManifest };

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

const assetUrl = (asset) =>
  `https://github.com/hamr0/8een/releases/download/${manifest.release}/${asset}`;

/**
 * Where the binary lives when the adopter does not choose: the per-user cache
 * (`$XDG_CACHE_HOME` or `~/.cache`), because that is what it is -- a re-fetchable
 * artifact, not data. 8een still stores nothing (NO-GO #7): this is our own
 * pinned executable, not anything about any user.
 *
 * @returns {string}
 */
export function defaultBinaryDir() {
  const cache = process.env.XDG_CACHE_HOME || join(homedir(), '.cache');
  return join(cache, 'zk8een');
}

/**
 * @param {string} platform e.g. `linux-x64`
 * @returns {{asset: string, sha256: string, bytes: number}}
 */
function entryFor(platform) {
  const entry = manifest.binaries[platform];
  if (!entry) {
    const have = Object.keys(manifest.binaries).join(', ');
    throw new Error(
      `no prebuilt verifier binary for ${platform} (available: ${have}). ` +
        `Build it yourself from the documented steps (poc/M0-EVIDENCE.md step 1) ` +
        `and pass its path as \`binary:\`.`,
    );
  }
  return entry;
}

/**
 * Ensures the pinned verifier binary for `platform` is present in `dir`,
 * byte-correct, and executable. Idempotent: an intact binary is not re-fetched.
 *
 * @param {string} [dir]  Default: {@link defaultBinaryDir} -- the location
 *   `Verifier.start` looks in when `binary:` is omitted. Provision somewhere
 *   else only if you also pass the returned `path` as `binary:` yourself.
 * @param {{platform?: string, onProgress?: (e: {asset: string, action: string}) => void,
 *   fetchImpl?: typeof fetch}} [opts]
 *   `platform` defaults to this machine (`process.platform`-`process.arch`);
 *   override it to provision for another target, e.g. into a container image.
 * @returns {Promise<{path: string, action: 'present'|'fetched'}>}
 */
export async function provisionBinary(dir = defaultBinaryDir(), opts = {}) {
  const { platform = `${process.platform}-${process.arch}`, onProgress = () => {}, fetchImpl = fetch } = opts;
  const entry = entryFor(platform);
  await mkdir(dir, { recursive: true });
  const path = cachedPath(dir, entry);

  if (await isIntact(path, entry.sha256)) {
    // Re-assert the mode: a binary that lost its x-bit is "present" but useless,
    // and the fix costs nothing.
    await chmod(path, 0o755);
    onProgress({ asset: entry.asset, action: 'present' });
    return { path, action: 'present' };
  }

  onProgress({ asset: entry.asset, action: 'fetching' });
  await fetchBinary(entry, path, fetchImpl);
  onProgress({ asset: entry.asset, action: 'fetched' });
  return { path, action: 'fetched' };
}

/**
 * The path `Verifier.start` uses when `binary:` is omitted -- IF what is on disk
 * is still byte-for-byte the binary we pinned. Re-hashed on every call: unlike a
 * circuit, a binary cannot be integrity-checked by the service at load, so this
 * is the last moment anyone can. Never resolves to a mismatched file.
 *
 * @param {string} [dir] Default: {@link defaultBinaryDir}.
 * @param {{platform?: string}} [opts]
 * @returns {Promise<string>}
 */
export async function resolveProvisionedBinary(dir = defaultBinaryDir(), opts = {}) {
  const { platform = `${process.platform}-${process.arch}` } = opts;
  const entry = entryFor(platform);
  const path = cachedPath(dir, entry);
  if (!(await isIntact(path, entry.sha256))) {
    throw new Error(
      `no verifier binary at ${path} (or its bytes do not match the pinned sha256). ` +
        `Run provisionBinary() first, or pass your own build as \`binary:\`.`,
    );
  }
  // Byte-correct but not executable is a real state -- a restrictive umask at
  // provision time, or a cache restored by a tool that drops modes -- and it
  // fails later as a bare EACCES from spawn, nowhere near the cause. Say it here.
  if (!(await isExecutable(path))) {
    throw new Error(
      `the verifier binary at ${path} is not executable (its bytes are correct). ` +
        `Run provisionBinary() to repair its mode, or \`chmod +x\` it.`,
    );
  }
  return path;
}

/**
 * Where a given release's binary is cached. The RELEASE TAG is part of the
 * filename on purpose: the asset name alone (`longfellow-verifier-linux-x64`)
 * is stable across releases, so two zk8een versions pinning different releases
 * would otherwise share one cache file and re-fetch over each other forever --
 * each refusing the other's bytes, correctly but uselessly.
 */
function cachedPath(dir, entry) {
  return join(dir, `${entry.asset}-${manifest.release}`);
}

async function isIntact(path, expected) {
  try {
    return sha256(await readFile(path)) === expected;
  } catch {
    return false; // absent, unreadable -- either way, not a binary we will run
  }
}

async function isExecutable(path) {
  try {
    await access(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function fetchBinary(entry, path, fetchImpl) {
  const url = assetUrl(entry.asset);

  let res;
  try {
    res = await fetchImpl(url, { signal: AbortSignal.timeout(120_000) });
  } catch (err) {
    throw new Error(`binary ${entry.asset}: cannot reach ${url}: ${err.message}`);
  }
  if (!res.ok) {
    throw new Error(`binary ${entry.asset}: ${url} returned HTTP ${res.status}`);
  }

  // Refuse an oversized body BEFORE reading it into memory (same availability
  // argument as circuits.js: the sha256 catches bad bytes, but only after they
  // fit in RAM).
  const advertised = Number(res.headers?.get?.('content-length'));
  if (Number.isFinite(advertised) && advertised > entry.bytes) {
    throw new Error(
      `binary ${entry.asset}: ${url} advertises ${advertised} bytes, ` +
        `expected ${entry.bytes}. Refusing to download it.`,
    );
  }

  const bytes = Buffer.from(await res.arrayBuffer());

  if (bytes.length !== entry.bytes) {
    throw new Error(
      `binary ${entry.asset}: expected ${entry.bytes} bytes, got ${bytes.length}. Refusing.`,
    );
  }
  const got = sha256(bytes);
  if (got !== entry.sha256) {
    throw new Error(
      `binary ${entry.asset}: SHA256 MISMATCH.\n` +
        `  expected ${entry.sha256}\n  received ${got}\n` +
        `These are not the bytes pinned from release ${manifest.release}. Refusing to install them.`,
    );
  }

  // Write beside the target then rename, exactly like circuits.js: a crash
  // mid-write must never leave a truncated executable lying at the real path.
  const partial = `${path}.part-${randomUUID()}`;
  try {
    await writeFile(partial, bytes, { flag: 'wx', mode: 0o755 });
    // writeFile's `mode` is masked by the process umask -- measured: under
    // `umask 0111` the file lands 0644 and the binary we just verified is not
    // executable. chmod is not masked, so assert the mode explicitly rather
    // than leaving a hash-perfect binary that cannot be spawned.
    await chmod(partial, 0o755);
    await rename(partial, path);
  } catch (err) {
    await unlink(partial).catch(() => {});
    throw err;
  }
}
