/**
 * Puts the circuit files on disk, and refuses to accept bytes that are not the
 * ones we pinned.
 *
 * The verifier cannot answer anything without these -- they are large
 * pre-computed tables (4.3 MB across 17 files) produced by upstream, not by us.
 * They are fetched on first run rather than committed, so the repo stays free of
 * redistributed build artifacts.
 *
 * Two independent checks stand between a hostile network and the verifier:
 *
 *   1. Ours, here: every file must hash to the sha256 we pinned against upstream
 *      commit d8ad8f65. A byte off and we delete it and stop. This is the supply
 *      chain check -- "are these the bytes upstream published?"
 *   2. Theirs, at load: the Go service recomputes each circuit's id with
 *      circuit_id() and ignores any file whose content does not match its
 *      filename. This is the semantic check -- "do these bytes mean the circuit
 *      they claim to be?"
 *
 * Note what upstream's check does on failure: it SKIPS the file and logs. It
 * does not stop. A server can therefore come up with a silently-reduced circuit
 * set, which is exactly the state that makes it reject valid proofs while
 * reporting healthy -- so we fail loudly here, before it ever gets that chance.
 */

import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, rename, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import manifest from './circuits.manifest.json' with { type: 'json' };

export { manifest };

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

const sourceUrl = (id) =>
  `https://raw.githubusercontent.com/google/longfellow-zk/${manifest.commit}/${manifest.path}/${id}`;

/**
 * Ensures every pinned circuit is present in `dir` and byte-correct.
 * Idempotent: files already correct are left alone and not re-fetched.
 *
 * @param {string} dir
 * @param {{onProgress?: (e: {id: string, action: string, n: number, of: number}) => void, fetchImpl?: typeof fetch}} [opts]
 * @returns {Promise<{dir: string, present: number, fetched: number}>}
 */
export async function provision(dir, opts = {}) {
  const { onProgress = () => {}, fetchImpl = fetch } = opts;
  await mkdir(dir, { recursive: true });

  let present = 0;
  let fetched = 0;
  const total = manifest.circuits.length;

  for (const [i, circuit] of manifest.circuits.entries()) {
    const path = join(dir, circuit.id);
    const n = i + 1;

    if (await isIntact(path, circuit.sha256)) {
      present += 1;
      onProgress({ id: circuit.id, action: 'present', n, of: total });
      continue;
    }

    onProgress({ id: circuit.id, action: 'fetching', n, of: total });
    await fetchCircuit(circuit, path, fetchImpl);
    fetched += 1;
    onProgress({ id: circuit.id, action: 'fetched', n, of: total });
  }

  return { dir, present, fetched };
}

async function isIntact(path, expected) {
  try {
    return sha256(await readFile(path)) === expected;
  } catch {
    return false; // absent, unreadable -- either way, fetch it
  }
}

async function fetchCircuit(circuit, path, fetchImpl) {
  const url = sourceUrl(circuit.id);

  let res;
  try {
    res = await fetchImpl(url, { signal: AbortSignal.timeout(60_000) });
  } catch (err) {
    throw new Error(`circuit ${circuit.id.slice(0, 12)}: cannot reach ${url}: ${err.message}`);
  }
  if (!res.ok) {
    throw new Error(`circuit ${circuit.id.slice(0, 12)}: ${url} returned HTTP ${res.status}`);
  }

  const bytes = Buffer.from(await res.arrayBuffer());

  if (bytes.length !== circuit.bytes) {
    throw new Error(
      `circuit ${circuit.id.slice(0, 12)}: expected ${circuit.bytes} bytes, got ${bytes.length}. Refusing.`,
    );
  }
  const got = sha256(bytes);
  if (got !== circuit.sha256) {
    throw new Error(
      `circuit ${circuit.id.slice(0, 12)}: SHA256 MISMATCH.\n` +
        `  expected ${circuit.sha256}\n  received ${got}\n` +
        `These are not the bytes pinned at upstream ${manifest.commit.slice(0, 8)}. Refusing to install them.`,
    );
  }

  // Write beside the target, then rename: a crash mid-write must never leave a
  // truncated circuit that later looks like a merely-corrupt file.
  const partial = `${path}.part-${process.pid}`;
  try {
    await writeFile(partial, bytes, { flag: 'wx' });
    await rename(partial, path);
  } catch (err) {
    await unlink(partial).catch(() => {});
    throw err;
  }
}
