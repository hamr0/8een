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
import { setTimeout as delay } from 'node:timers/promises';

const CIRCUIT_LOADED = /(?:^|\s)Read ([0-9a-f]{64})\s*$/;
const DEFAULTS = {
  host: '127.0.0.1', // loopback, never 0.0.0.0 -- upstream's ":8888" default binds every interface
  port: 8899,
  startupTimeoutMs: 180_000, // circuit load measured at 44-47s; leave room for a slower box
  requestTimeoutMs: 10_000, // a verify is ~0.4-0.5s; 10s means something is wrong
  shutdownGraceMs: 5_000,
};

export class VerifierService {
  #child = null;
  #ready = false;
  #circuits = 0;
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
    for (const line of chunk.split('\n')) {
      if (!line.trim()) continue;
      this.#logTail.push(line);
      if (this.#logTail.length > 50) this.#logTail.shift();
      if (CIRCUIT_LOADED.test(line)) this.#circuits += 1;
    }
  }

  async #awaitReady(timeoutMs) {
    const deadline = Date.now() + timeoutMs;

    while (Date.now() < deadline) {
      if (this.#exit) {
        throw new Error(
          `verifier exited during startup (code ${this.#exit.code}, signal ${this.#exit.signal})\n` +
            this.#logTail.slice(-10).join('\n'),
        );
      }
      // Circuits first: the port opens only after LoadCircuits returns, but it
      // opens whether or not anything loaded.
      if (this.#circuits > 0 && (await this.#alive())) {
        this.#ready = true;
        return;
      }
      await delay(250);
    }

    await this.stop();
    if (this.#circuits === 0) {
      throw new Error(
        `verifier loaded 0 circuits from '${this.opts.circuitDir}' -- it would report healthy and ` +
          `reject every valid proof. Refusing to serve.\n${this.#logTail.slice(-10).join('\n')}`,
      );
    }
    throw new Error(`verifier did not become ready within ${timeoutMs}ms`);
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
