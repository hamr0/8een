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

import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import manifest from './circuits.manifest.js';
import { fetchPinned, isIntact } from './pinned.js';

export { manifest };

const CIRCUIT_ID = /^[0-9a-f]{64}$/;

const sourceUrl = (id) =>
  `https://raw.githubusercontent.com/google/longfellow-zk/${manifest.commit}/${manifest.path}/${id}`;

/**
 * A circuit id becomes both a filesystem path and a URL, so it is a trust
 * boundary even though the manifest ships in our own tree. An id of "../../x"
 * would write outside the circuit directory. Cheap to assert, so assert it.
 */
function assertCircuitId(id) {
  if (typeof id !== 'string' || !CIRCUIT_ID.test(id)) {
    throw new Error(`manifest contains a malformed circuit id: ${JSON.stringify(id)}`);
  }
}

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
    assertCircuitId(circuit.id);
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

async function fetchCircuit(circuit, path, fetchImpl) {
  await fetchPinned(
    {
      url: sourceUrl(circuit.id),
      label: `circuit ${circuit.id.slice(0, 12)}`,
      bytes: circuit.bytes,
      sha256: circuit.sha256,
      path,
      origin: `at upstream ${manifest.commit.slice(0, 8)}`,
    },
    fetchImpl,
  );
}
