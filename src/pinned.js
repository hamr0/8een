// SPDX-License-Identifier: Apache-2.0
/**
 * Fetching bytes we have pinned, and refusing anything else.
 *
 * Both things 8een downloads -- the circuit tables and the verifier binary --
 * are pinned by sha256 inside this package, so both hosts are untrusted and
 * both need the identical sequence of refusals. That sequence lived twice, once
 * per module, drifting independently. It is the integrity boundary of the whole
 * package: it belongs in ONE place that can be audited once.
 *
 * The order of the checks is the point, and it is not arbitrary:
 *
 *   1. Reachability, then HTTP status -- a dead or erroring host is not a
 *      silent "nothing to install".
 *   2. The ADVERTISED size, before the body is read. Waiting for the sha256 to
 *      catch a bad download is fine for correctness and useless for
 *      availability: a hostile or compromised host answering with a 10 GB body
 *      would exhaust memory long before we ever got to hash it.
 *   3. The ACTUAL size, then the sha256. The hash is what decides; the length
 *      check just fails a truncated download with a clearer message.
 *   4. Write beside the target, then rename. A crash mid-write must never leave
 *      a truncated file at the real path, where it would look merely corrupt.
 *
 * Nothing is written until every check has passed.
 */

import { createHash, randomUUID } from 'node:crypto';
import { chmod, readFile, writeFile, rename, unlink } from 'node:fs/promises';

/** @param {Buffer|Uint8Array} buf */
export const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

/**
 * Is the file at `path` byte-for-byte what we pinned? Absent or unreadable
 * counts as "no" -- either way it is not something we will use.
 *
 * @param {string} path
 * @param {string} expected sha256, lowercase hex
 * @returns {Promise<boolean>}
 */
export async function isIntact(path, expected) {
  try {
    return sha256(await readFile(path)) === expected;
  } catch {
    return false;
  }
}

/**
 * Downloads one pinned artifact into `spec.path`, or throws without writing.
 *
 * @param {{url: string, label: string, bytes: number, sha256: string, path: string,
 *   origin: string, timeoutMs?: number, mode?: number}} spec
 *   `label` prefixes every error (e.g. `circuit 137e5a75ce72`, `binary
 *   longfellow-verifier-linux-x64`). `origin` completes the sentence "These are
 *   not the bytes pinned ___" (e.g. `at upstream d8ad8f65`, `from release
 *   longfellow-bin-1`). `mode` is asserted with chmod after writing, because
 *   writeFile's mode argument is masked by the process umask -- measured: under
 *   `umask 0111` a 0o755 write lands 0644, which for the verifier binary means
 *   hash-perfect and unspawnable.
 * @param {typeof fetch} fetchImpl
 * @returns {Promise<void>}
 */
export async function fetchPinned(spec, fetchImpl) {
  const { url, label, bytes: expectedBytes, sha256: expectedHash, path, origin } = spec;

  let res;
  try {
    res = await fetchImpl(url, { signal: AbortSignal.timeout(spec.timeoutMs ?? 60_000) });
  } catch (err) {
    throw new Error(`${label}: cannot reach ${url}: ${err.message}`);
  }
  if (!res.ok) {
    throw new Error(`${label}: ${url} returned HTTP ${res.status}`);
  }

  const advertised = Number(res.headers?.get?.('content-length'));
  if (Number.isFinite(advertised) && advertised > expectedBytes) {
    throw new Error(
      `${label}: ${url} advertises ${advertised} bytes, ` +
        `expected ${expectedBytes}. Refusing to download it.`,
    );
  }

  const body = Buffer.from(await res.arrayBuffer());

  if (body.length !== expectedBytes) {
    throw new Error(`${label}: expected ${expectedBytes} bytes, got ${body.length}. Refusing.`);
  }
  const got = sha256(body);
  if (got !== expectedHash) {
    throw new Error(
      `${label}: SHA256 MISMATCH.\n` +
        `  expected ${expectedHash}\n  received ${got}\n` +
        `These are not the bytes pinned ${origin}. Refusing to install them.`,
    );
  }

  // The suffix is random rather than the pid, because a pid is recycled -- a
  // stale .part-<pid> from a killed run would then collide with 'wx' and wedge
  // provisioning for good, with an EEXIST that says nothing about the problem.
  const partial = `${path}.part-${randomUUID()}`;
  try {
    await writeFile(partial, body, { flag: 'wx', ...(spec.mode == null ? {} : { mode: spec.mode }) });
    if (spec.mode != null) await chmod(partial, spec.mode);
    await rename(partial, path);
  } catch (err) {
    await unlink(partial).catch(() => {});
    throw err;
  }
}
