// SPDX-License-Identifier: Apache-2.0
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

import { access, chmod, mkdir } from 'node:fs/promises';
import { constants } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import manifest from './binary.manifest.js';
import { fetchPinned, isIntact } from './pinned.js';

export { manifest as binaryManifest };

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

// Where an adopter goes when there is no prebuilt binary for them. A bare
// `poc/M0-EVIDENCE.md` is useless from inside `node_modules` -- `poc/` is not in
// the package `files`, so the path they are told to read does not exist on their
// disk. Always hand them the URL.
const BUILD_IT_YOURSELF =
  'https://github.com/hamr0/8een/blob/main/poc/M0-EVIDENCE.md (step 1)';

/**
 * Is this a musl libc system (Alpine and friends)?
 *
 * The trap this closes: `process.platform`-`process.arch` reads `linux-x64` on
 * Alpine exactly as it does on Debian, so the manifest MATCHES, we download 10 MB,
 * and the glibc-linked binary then fails to spawn with an ENOENT-shaped error that
 * names nothing useful and surfaces far from here (`service.js`). That is this
 * project's recurring bug shape -- a check trusting a surface signal that does not
 * mean what it appears to -- so it gets diagnosed at the boundary instead.
 *
 * Detection is stdlib-only: glibc builds report a runtime glibc version in the
 * diagnostic report header; musl builds have no such field. **Fails open** -- if we
 * cannot tell, we proceed and let the spawn error stand, because wrongly refusing
 * to run on a working glibc box is the worse mistake.
 *
 * @returns {boolean}
 */
function isMuslLinux() {
  if (process.platform !== 'linux') return false;
  try {
    const raw = process.report?.getReport?.();
    /** @type {{glibcVersionRuntime?: string} | undefined} */
    const header =
      typeof raw === 'string'
        ? JSON.parse(raw).header
        : /** @type {{header?: {glibcVersionRuntime?: string}}} */ (raw)?.header;
    return header ? !header.glibcVersionRuntime : false;
  } catch {
    return false;
  }
}

/** The machine we are running ON -- not necessarily the one we are provisioning FOR. */
function hostPlatform() {
  return `${process.platform}-${process.arch}`;
}

/**
 * @param {string} platform e.g. `linux-x64`
 * @param {{explicitTarget?: boolean}} [opts]
 *   `explicitTarget` = the caller NAMED a platform, so they are provisioning
 *   deliberately (baking an image, populating a cache for another machine) rather
 *   than for the process they are running in.
 * @returns {{asset: string, sha256: string, bytes: number}}
 */
function entryFor(platform, { explicitTarget = false } = {}) {
  // `Object.hasOwn`, not a bare lookup: `binaries['__proto__']` (or `constructor`,
  // `toString`, ...) inherits a truthy value from Object.prototype, sails past the
  // `!entry` guard, and turns into a fetch of `longfellow-verifier-undefined` with
  // an undefined pin. The integrity boundary still refuses those bytes -- the length
  // check fails closed on `undefined` (verified) -- but the adopter gets a network
  // error about a URL they never asked for instead of "no prebuilt for that
  // platform". `circuits.js` already validates its ids this way; this matches it.
  const entry = Object.hasOwn(manifest.binaries, platform) ? manifest.binaries[platform] : undefined;
  if (!entry) {
    const have = Object.keys(manifest.binaries).join(', ');
    throw new Error(
      `no prebuilt verifier binary for ${platform} (available: ${have}). ` +
        `Build it yourself from the documented steps -- ${BUILD_IT_YOURSELF} -- ` +
        `and pass its path as \`binary:\`.`,
    );
  }
  // The musl check asks about THIS process's libc, so it may only speak to a binary
  // THIS process is going to run. The platform key carries no libc dimension --
  // Alpine and Debian are both `linux-x64` -- so an explicit `platform:` is the only
  // signal that the bytes are destined elsewhere (an Alpine CI runner baking a glibc
  // image is the documented use). Refusing that would be the same host-vs-target
  // confusion this check exists to catch, pointed the other way.
  if (!explicitTarget && isMuslLinux()) {
    throw new Error(
      `the prebuilt ${platform} verifier binary is glibc-linked and this looks like ` +
        `a musl system (Alpine): it would download and then fail to spawn. Either use ` +
        `a glibc image (e.g. node:22-bookworm-slim) or build the binary against musl ` +
        `yourself -- ${BUILD_IT_YOURSELF} -- and pass its path as \`binary:\`. To ` +
        `provision FOR somewhere else from here, name the target: ` +
        `provisionBinary(dir, { platform: '${platform}' }).`,
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
  const { platform = hostPlatform(), onProgress = () => {}, fetchImpl = fetch } = opts;
  const entry = entryFor(platform, { explicitTarget: opts.platform != null });
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
  const { platform = hostPlatform() } = opts;
  // Same rule as provisionBinary. The path that matters for safety is the one
  // `Verifier.start` takes -- no arguments, so `explicitTarget` is false and the
  // musl refusal still stands between an Alpine host and a binary it cannot spawn.
  const entry = entryFor(platform, { explicitTarget: opts.platform != null });
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

async function isExecutable(path) {
  try {
    await access(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function fetchBinary(entry, path, fetchImpl) {
  await fetchPinned(
    {
      url: assetUrl(entry.asset),
      label: `binary ${entry.asset}`,
      bytes: entry.bytes,
      sha256: entry.sha256,
      path,
      origin: `from release ${manifest.release}`,
      timeoutMs: 120_000,
      // The one thing a circuit does not need: this file gets executed.
      mode: 0o755,
    },
    fetchImpl,
  );
}
