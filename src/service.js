/**
 * Supervises the longfellow reference verifier (Go) as a long-lived child and
 * turns one verification into one raw outcome for verdict.classify().
 *
 * Two things upstream will not tell you, both observed on the running service:
 *
 *   - /healthz returns a hardcoded 200. It never checks whether a single
 *     circuit loaded. main.go discards LoadCircuits' error, so pointing the
 *     server at an empty directory yields a "healthy" server that rejects every
 *     valid proof.
 *   - /specs lists the specs COMPILED INTO the binary, not the ones on disk. A
 *     server holding zero circuits still advertises twelve.
 *
 * So readiness here is not a ping. We read the child's own log stream and count
 * the circuits it says it loaded, because that is the only place the truth
 * appears. Zero circuits => never ready => every verify() returns not_ready,
 * which classify() turns into ok:false / over_threshold:null. A broken 8een
 * says "I cannot verify". It never says "you are underage".
 *
 * Circuit load is slow (44-47s measured on an 8-core desktop) -- this is why the
 * service is long-lived and preloaded, never spawned per request.
 */

import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { readdirSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';

const CIRCUIT_LOADED = /(?:^|\s)Read ([0-9a-f]{64})\s*$/;
const CIRCUIT_SKIPPED = /ignoring file ([0-9a-f]{64})/;
const CIRCUIT_FILE = /^[0-9a-f]{64}$/;

const DEFAULTS = {
  host: '127.0.0.1', // loopback, never 0.0.0.0 -- upstream's ":8888" default binds every interface
  port: 8899,
  startupTimeoutMs: 180_000, // circuit load measured at 44-73s; leave room for a slower box
  requestTimeoutMs: 10_000, // a verify is ~0.4-0.7s; 10s means something is wrong
  shutdownGraceMs: 5_000,
};

/**
 * A child's stdout is a byte stream, not a line stream: a 'data' chunk may end
 * mid-line. Splitting each chunk on '\n' in isolation silently drops whatever
 * straddles the boundary -- and here that means losing a circuit from the count,
 * or, if the split lands inside the only matching line, counting zero and
 * refusing to start against a perfectly healthy server. So carry the remainder.
 */
export function splitLines(residual, chunk) {
  const parts = (residual + chunk).split('\n');
  return { lines: parts.slice(0, -1), residual: parts.at(-1) };
}

export class VerifierService {
  #child = null;
  #ready = false;
  #circuits = 0;
  #expected = 0;
  #skipped = [];
  #residual = '';
  #logTail = [];
  #exit = null;

  constructor(opts = {}) {
    const missing = ['binary', 'circuitDir', 'caCerts'].filter((k) => !opts[k]);
    if (missing.length) throw new TypeError(`VerifierService needs: ${missing.join(', ')}`);
    this.opts = { ...DEFAULTS, ...opts };
  }

  get ready() {
    return this.#ready;
  }

  get circuitsLoaded() {
    return this.#circuits;
  }

  get origin() {
    return `http://${this.opts.host}:${this.opts.port}`;
  }

  /**
   * Starts the child and resolves only once it is genuinely able to verify.
   * Throws if it cannot get there -- a caller that never got a working verifier
   * must find out at boot, not on a visitor's first proof.
   */
  async start() {
    const { binary, circuitDir, caCerts, host, port, vicalUrl, env, startupTimeoutMs } = this.opts;

    // How many circuits SHOULD load. Upstream skips-and-logs a file whose
    // recomputed circuit_id does not match its name, and keeps going, so a
    // damaged directory yields a server that serves some questions and not
    // others. Knowing the target up front is what lets us tell "ready" apart
    // from "ready enough to look fine until the wrong visitor turns up".
    this.#expected = countCircuitFiles(circuitDir);

    this.#child = spawn(
      binary,
      [
        '-port', `${host}:${port}`,
        '-circuit_dir', circuitDir,
        '-cacerts', caCerts,
        ...(vicalUrl ? ['-vical_url', vicalUrl] : []),
      ],
      { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] },
    );

    this.#child.once('exit', (code, signal) => {
      this.#exit = { code, signal };
      this.#ready = false;
    });

    // A durable 'error' listener. events.once() below installs a temporary one
    // and removes it the moment 'spawn' fires, after which an unhandled 'error'
    // (EPIPE on a closed stdio pipe, EPERM on kill) would be rethrown by
    // EventEmitter as an uncaught exception -- taking down the host web server,
    // not merely the verifier. Degrade to "not ready" like every other breakage.
    this.#child.on('error', (err) => {
      this.#ready = false;
      this.#exit ??= { code: null, signal: null, error: err.message };
      this.#logTail.push(`child error: ${err.message}`);
    });

    // ENOENT and friends: the binary isn't there, or isn't executable.
    const spawned = once(this.#child, 'spawn').catch((err) => {
      throw new Error(`cannot start verifier binary '${binary}': ${err.code ?? err.message}`);
    });

    for (const stream of [this.#child.stdout, this.#child.stderr]) {
      stream.setEncoding('utf8');
      stream.on('data', (chunk) => this.#absorb(chunk));
    }

    await spawned;
    await this.#awaitReady(startupTimeoutMs);
    return this;
  }

  /** The child's log is the only honest account of what loaded. */
  #absorb(chunk) {
    const { lines, residual } = splitLines(this.#residual, chunk);
    this.#residual = residual;
    for (const line of lines) {
      if (!line.trim()) continue;
      this.#logTail.push(line);
      if (this.#logTail.length > 50) this.#logTail.shift();
      if (CIRCUIT_LOADED.test(line)) this.#circuits += 1;
      const skipped = line.match(CIRCUIT_SKIPPED);
      if (skipped) this.#skipped.push(skipped[1]);
    }
  }

  async #awaitReady(timeoutMs) {
    // No circuit files at all: nothing to wait for, and the server would happily
    // come up, report /healthz "ok", advertise specs it does not have, and reject
    // every valid proof. Fail now rather than 45 seconds from now.
    if (this.#expected === 0) {
      await this.stop();
      throw new Error(this.#circuitFailure('found 0 circuit files'));
    }

    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      if (this.#exit) {
        throw new Error(
          `verifier exited during startup (code ${this.#exit.code}, signal ${this.#exit.signal})\n` +
            this.#logTail.slice(-10).join('\n'),
        );
      }
      // ALL of them, not merely some. Upstream skips a circuit it cannot verify
      // and carries on, so `> 0` would bless a server that answers some proofs
      // and rejects others for reasons that have nothing to do with the holder.
      if (this.#circuits >= this.#expected && (await this.#alive())) {
        this.#ready = true;
        return;
      }
      // A file the verifier has already rejected will never load, so the outcome
      // is settled -- stop now rather than wait out a 45-second clock we know we
      // are going to lose. (Which is why the message below reports the REJECTED
      // count, not the loaded one: at this instant the rest are still loading,
      // and "loaded 0 of 17" would be true but thoroughly misleading.)
      if (this.#skipped.length > 0) {
        await this.stop();
        throw new Error(
          this.#circuitFailure(
            `rejected at least ${this.#skipped.length} of ${this.#expected} circuit files as not matching ` +
              `their circuit id (stopped at the first sign of corruption; the rest were still loading, ` +
              `so there may well be more)`,
          ),
        );
      }
      await delay(250);
    }

    await this.stop();
    if (this.#circuits < this.#expected) {
      throw new Error(
        this.#circuitFailure(`loaded only ${this.#circuits} of ${this.#expected} circuits`),
      );
    }
    throw new Error(`verifier did not become ready within ${timeoutMs}ms`);
  }

  #circuitFailure(what) {
    const skipped = this.#skipped.length ? `\n  ${this.#skipped.join('\n  ')}` : '';
    return (
      `verifier ${what} in '${this.opts.circuitDir}'. A partially-loaded verifier reports ` +
      `healthy and rejects the proofs whose circuits are missing -- indistinguishably from a ` +
      `genuine "no". Refusing to serve.${skipped}`
    );
  }

  async #alive() {
    try {
      const res = await fetch(`${this.origin}/healthz`, { signal: AbortSignal.timeout(1000) });
      return res.ok;
    } catch {
      return false;
    }
  }

  /**
   * One verification. Never throws: every failure becomes a raw outcome that
   * classify() knows how to read.
   *
   * @param {{transcript: Buffer|Uint8Array, deviceResponse: Buffer|Uint8Array}} proof
   */
  async verify(proof) {
    if (!this.#ready) {
      return { kind: 'not_ready', detail: this.#exit ? 'verifier is not running' : 'verifier is still loading circuits' };
    }

    // Check the argument before the try-block, or a caller's bad input becomes
    // a TypeError inside it and gets reported as {kind:'unreachable'} -- sending
    // whoever is on call to debug a network that is perfectly fine.
    const bad = malformedProof(proof);
    if (bad) return { kind: 'invalid_request', detail: bad };

    let res;
    try {
      res = await fetch(`${this.origin}/zkverify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          Transcript: Buffer.from(proof.transcript).toString('base64'),
          ZKDeviceResponseCBOR: Buffer.from(proof.deviceResponse).toString('base64'),
        }),
        signal: AbortSignal.timeout(this.opts.requestTimeoutMs),
      });
    } catch (err) {
      if (err.name === 'TimeoutError' || err.name === 'AbortError') {
        return { kind: 'timeout', detail: `no answer in ${this.opts.requestTimeoutMs}ms` };
      }
      return { kind: 'unreachable', detail: err.cause?.code ?? err.code ?? err.message };
    }

    let body = null;
    try {
      body = await res.json();
    } catch {
      body = null; // classify() treats an unreadable body as a non-answer, not a "no"
    }
    return { kind: 'response', status: res.status, body };
  }

  /** SIGTERM, then SIGKILL if it will not go. */
  async stop() {
    const child = this.#child;
    this.#ready = false;
    if (!child || this.#exit) return;

    child.kill('SIGTERM');
    const gone = once(child, 'exit');
    const timer = AbortSignal.timeout(this.opts.shutdownGraceMs);
    const killed = new Promise((resolve) => timer.addEventListener('abort', resolve, { once: true }));

    await Promise.race([gone, killed]);
    if (!this.#exit) {
      child.kill('SIGKILL');
      await gone;
    }
  }
}

/** Circuit files are named for their own circuit id -- 64 hex chars, nothing else. */
function countCircuitFiles(dir) {
  try {
    return readdirSync(dir).filter((f) => CIRCUIT_FILE.test(f)).length;
  } catch {
    return 0; // absent or unreadable directory: zero circuits, and we refuse to serve
  }
}

/** @returns {string|null} why the proof is unusable, or null if it is fine */
function malformedProof(proof) {
  if (!proof || typeof proof !== 'object') return `proof must be an object, got ${typeof proof}`;
  for (const field of ['transcript', 'deviceResponse']) {
    const v = proof[field];
    if (v == null) return `proof.${field} is missing`;
    if (!ArrayBuffer.isView(v) && !(v instanceof ArrayBuffer)) {
      return `proof.${field} must be a Buffer/TypedArray, got ${typeof v}`;
    }
    if (v.byteLength === 0) return `proof.${field} is empty`;
  }
  return null;
}
