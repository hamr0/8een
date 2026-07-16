/**
 * The HTTP gate -- M4 piece 3, the "adopt without thinking" layer.
 *
 * A site does not want to wire `issueChallenge()`, `check()` and a nonce store
 * together by hand. This is the drop-in that does it: two routes over a running
 * verifier, and -- unlike the library primitive it sits on -- it is REPLAY-SAFE BY
 * DEFAULT. `startGate()` turns `requireSingleUse` ON unless you explicitly pass
 * `requireSingleUse:false`, and refuses to boot if single-use is on without the
 * secret and store it needs (the SAME fail-closed the `Verifier` enforces, but
 * BEFORE the 44-73s circuit load, so a config error costs a second, not a minute).
 *
 *     GET  {basePath}/challenge  -> mint a nonce; hand `transcript` to the wallet
 *     POST {basePath}/verify     -> {transcript, deviceResponse} (base64url) -> verdict
 *
 * The verdict IS the response body, and the §1 invariant reaches the wire intact:
 * `ok:true`  -> HTTP 200 (branch on `over_threshold` in the body);
 * `ok:false` -> HTTP 503 ("we could not verify -- re-challenge"), NEVER a status that
 * reads as "this person is denied". A broken or stale verifier says "ask again", not
 * "you are underage".
 *
 * Zero runtime dependencies (NO-GO #9): vanilla `node:http`. It exposes a
 * framework-agnostic `handler` and a thin `express()` adapter (our code, no new
 * dep). It consumes ONLY the verify module's public surface -- `Verifier`,
 * `issueChallenge`, `InMemoryNonceStore` -- so the gate can never reach past the
 * contract the library promises adopters (PRD §6, "probe-style").
 */

import http from 'node:http';
import { Verifier } from './index.js';
import { InMemoryNonceStore } from './challenge.js';

/** Route suffixes, matched against the path after `basePath`. */
const CHALLENGE = '/challenge';
const VERIFY = '/verify';

/**
 * Gate-level HTTP errors, shaped like a {@link import('./types.js').Verdict} so an
 * adopter gets one uniform response body everywhere. These are transport failures,
 * NOT verdicts about a person -- `over_threshold` is always `null`.
 */
const GATE_REASONS = Object.freeze({
  PAYLOAD_TOO_LARGE: 'payload_too_large',
  REQUEST_TIMEOUT: 'request_timeout',
  BAD_REQUEST: 'bad_request',
  METHOD_NOT_ALLOWED: 'method_not_allowed',
  NOT_FOUND: 'not_found',
  CHALLENGE_DISABLED: 'challenge_disabled',
  RATE_LIMITED: 'rate_limited',
  INTERNAL_ERROR: 'internal_error',
});

/**
 * A config knob that bounds an endpoint must FAIL LOUD on a bad value, never silently
 * fall open. A `NaN` maxBodyBytes (`Number(undefined)`) would make `len > max` always
 * false and un-cap the body; a malformed rateLimit would un-limit the route. Both are
 * the "trust a config value that half-works" shape this project keeps finding -- so
 * every numeric bound is validated at construction.
 */
function posNum(v, name) {
  if (typeof v !== 'number' || !Number.isFinite(v) || v <= 0) {
    throw new TypeError(`${name} must be a positive finite number, got ${v}`);
  }
  return v;
}

const DEFAULTS = Object.freeze({
  basePath: '/8een',
  // A safety CAP, not a measured cost: a ZK deviceResponse is tens of KB, so 1 MB is
  // comfortably above a real proof while refusing an unbounded body (invariant #3).
  maxBodyBytes: 1_000_000,
  // Idle timeout on the request body: a POSTed proof arrives in one burst, so a stall
  // this long is a slow-loris, not a real client. Bounds how long a slot can be held.
  maxBodyReadMs: 10_000,
  // Coarse per-IP bound so a script in a loop cannot exhaust the verifier. Per-process
  // (like InMemoryNonceStore); front a real limiter for multi-replica. Adopter-tunable.
  rateLimit: { limit: 60, windowMs: 60_000 },
  // X-Forwarded-For is spoofable; trust it only behind a vetted proxy (AGENT_RULES).
  trustProxy: false,
});

/**
 * A minimal fixed-window per-key counter. In-memory and per-process -- enough to blunt
 * a single-source flood; not a distributed limiter. Sweeps opportunistically so it
 * cannot grow without bound.
 *
 * @param {{limit: number, windowMs: number}} cfg
 */
const RL_HARD_CAP = 50_000; // absolute bound on tracked keys, so a wide many-IP flood
// cannot grow the map without limit even when nothing has expired to sweep.
function createRateLimiter({ limit, windowMs }) {
  /** @type {Map<string, {count: number, resetAt: number}>} */
  const hits = new Map();
  return function allow(key, now) {
    const e = hits.get(key);
    if (e === undefined || now >= e.resetAt) {
      if (hits.size >= RL_HARD_CAP) {
        // Sweep expired first; if a burst of DISTINCT keys still pins us at the cap
        // (nothing expired to drop), reset the whole window rather than grow unbounded.
        // Degrades the limiter under a flood -- it never leaks memory. Acceptable: this
        // is a per-process best-effort limiter (front a real one for multi-replica).
        for (const [k, v] of hits) if (now >= v.resetAt) hits.delete(k);
        if (hits.size >= RL_HARD_CAP) hits.clear();
      }
      hits.set(key, { count: 1, resetAt: now + windowMs });
      return true;
    }
    if (e.count >= limit) return false;
    e.count += 1;
    return true;
  };
}

/** The client key for rate limiting: socket address, or the first XFF hop behind a proxy. */
function clientKey(req, trustProxy) {
  if (trustProxy) {
    const xff = req.headers['x-forwarded-for'];
    if (typeof xff === 'string' && xff.length > 0) return xff.split(',')[0].trim();
  }
  return req.socket?.remoteAddress || 'unknown';
}

/**
 * Read a request body up to `max` bytes, within a total `deadlineMs` wall-clock window.
 * Rejects `TOO_LARGE` the moment the cap is crossed (it does not buffer the whole
 * oversized payload first) and `SLOW` if the whole body has not arrived in time. The
 * deadline is TOTAL, not idle: a re-arming idle timer would let a slow-drip client
 * (one byte just under the idle window, forever) hold a slot open -- a total deadline
 * stops both the full stall and the drip. A real proof POST arrives in one burst well
 * inside it; even 1 MB in 10 s is 100 KB/s, comfortable on any real link.
 *
 * It does NOT destroy the request here: the caller still needs to write a real response
 * (413/408) onto the socket, and tearing the socket down first would deliver an
 * ECONNRESET instead. The caller sends the response with `connection: close` and the
 * socket closes cleanly after it flushes.
 *
 * @param {import('node:http').IncomingMessage} req
 * @param {number} max
 * @param {number} deadlineMs  reject `SLOW` if the full body has not arrived within this
 * @returns {Promise<Buffer>}
 */
function readBody(req, max, deadlineMs) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let len = 0;
    const done = (fn, arg) => {
      clearTimeout(timer);
      req.removeListener('data', onData);
      req.removeListener('end', onEnd);
      req.removeListener('error', onErr);
      fn(arg);
    };
    // Armed ONCE, never re-armed: this is the total window for the whole body.
    const timer = setTimeout(() => done(reject, Object.assign(new Error('body stalled'), { code: 'SLOW' })), deadlineMs);
    if (typeof timer.unref === 'function') timer.unref();
    const onData = (chunk) => {
      len += chunk.length;
      if (len > max) return done(reject, Object.assign(new Error('payload too large'), { code: 'TOO_LARGE' }));
      chunks.push(chunk);
    };
    const onEnd = () => done(resolve, Buffer.concat(chunks));
    const onErr = (e) => done(reject, e);
    req.on('data', onData);
    req.on('end', onEnd);
    req.on('error', onErr);
  });
}

/** Match a full request path against our two routes, given the mount prefix. */
function matchRoute(pathname, basePath) {
  if (!pathname.startsWith(basePath)) return null;
  const rest = pathname.slice(basePath.length) || '/';
  if (rest === CHALLENGE) return 'challenge';
  if (rest === VERIFY) return 'verify';
  return null;
}

/**
 * Build the HTTP gate over an already-running verifier.
 *
 * @param {{verifier: {issueChallenge: () => import('./types.js').Challenge,
 *   check: (proof: import('./types.js').Proof) => Promise<import('./types.js').Verdict>,
 *   requiresSingleUse?: boolean}, allowReplay?: boolean,
 *   basePath?: string, maxBodyBytes?: number, maxBodyReadMs?: number,
 *   rateLimit?: {limit: number, windowMs: number}|false, trustProxy?: boolean}} opts
 *   `verifier` is a started {@link Verifier} (or anything with the same methods). It MUST
 *   report `requiresSingleUse === true` (a `Verifier` started with `requireSingleUse`)
 *   or the gate throws -- **replay-safe by default at this layer too**. Set
 *   `allowReplay:true` to deliberately wrap a replay-open verifier (then `/challenge` is
 *   disabled with `404 challenge_disabled`). `rateLimit:false` disables the built-in
 *   limiter (use when you front your own); a malformed `rateLimit`/`maxBodyBytes`/
 *   `maxBodyReadMs` throws rather than silently un-bounding the endpoint.
 * @returns {{handler: import('node:http').RequestListener,
 *   express: () => (req: any, res: any, next: () => void) => void}}
 */
export function createGate(opts) {
  if (!opts || !opts.verifier || typeof opts.verifier.check !== 'function' ||
      typeof opts.verifier.issueChallenge !== 'function') {
    throw new TypeError('createGate needs a started verifier with issueChallenge() and check()');
  }
  const verifier = opts.verifier;
  // Replay-safe by default AT THIS LAYER TOO (owner directive). The gate refuses to wrap a
  // replay-open verifier unless the caller says so out loud -- otherwise the documented
  // "manage the Verifier yourself" path silently re-opens the footgun startGate closes.
  // `requiresSingleUse` is the Verifier's own report of its state; a fake verifier in a
  // test must declare it (or pass allowReplay:true).
  const allowReplay = opts.allowReplay === true;
  if (!allowReplay && verifier.requiresSingleUse !== true) {
    throw new TypeError(
      'createGate is replay-safe by default: pass a verifier started with requireSingleUse, ' +
        'or set allowReplay:true to deliberately wrap a replay-open verifier',
    );
  }
  const basePath = opts.basePath ?? DEFAULTS.basePath;
  const maxBodyBytes = posNum(opts.maxBodyBytes ?? DEFAULTS.maxBodyBytes, 'maxBodyBytes');
  const maxBodyReadMs = posNum(opts.maxBodyReadMs ?? DEFAULTS.maxBodyReadMs, 'maxBodyReadMs');
  const trustProxy = opts.trustProxy ?? DEFAULTS.trustProxy;
  /** @type {((key: string, now: number) => boolean) | null} */
  let rl = null;
  if (opts.rateLimit !== false) {
    const cfg = opts.rateLimit ?? DEFAULTS.rateLimit;
    posNum(cfg && cfg.limit, 'rateLimit.limit');
    posNum(cfg && cfg.windowMs, 'rateLimit.windowMs');
    rl = createRateLimiter(cfg);
  }

  /** Serialize a JSON body once and end the response, with optional extra headers. */
  function send(res, code, obj, extra) {
    const body = JSON.stringify(obj);
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', ...extra });
    res.end(body);
  }
  const err = (res, code, reason, extra) => send(res, code, { ok: false, over_threshold: null, reason }, extra);
  // For a body we refused mid-flight (413/408) the client is still sending: close the
  // connection AFTER the response flushes, rather than destroy() the socket first (which
  // would deliver an ECONNRESET instead of the JSON). `connection: close` does exactly that.
  const CLOSE = { connection: 'close' };

  /**
   * @param {import('node:http').IncomingMessage} req
   * @param {import('node:http').ServerResponse} res
   * @param {() => void} onUnmatched  404 for the standalone handler; next() for Express.
   */
  async function handle(req, res, onUnmatched) {
    let pathname;
    try {
      pathname = new URL(req.url ?? '/', 'http://localhost').pathname;
    } catch {
      return err(res, 400, GATE_REASONS.BAD_REQUEST);
    }
    const which = matchRoute(pathname, basePath);
    if (which === null) return onUnmatched();

    // A rejection BEFORE we consume a POST body leaves the client still sending; close
    // the connection after the response so it lands as JSON, not an ECONNRESET (as the
    // 413/408 paths already do). Bodyless requests (GET) are unaffected.
    const inFlight = req.method === 'POST' ? CLOSE : undefined;

    try {
      // Inside the try so even a surprise in the limiter/key becomes a clean 500, never
      // an unhandled rejection that leaves the client hanging (a response is always sent).
      if (rl && !rl(clientKey(req, trustProxy), Date.now())) {
        return err(res, 429, GATE_REASONS.RATE_LIMITED, inFlight);
      }

      if (which === 'challenge') {
        if (req.method !== 'GET') return err(res, 405, GATE_REASONS.METHOD_NOT_ALLOWED, inFlight);
        // In the deliberate replay-open mode the verifier issues no nonces, so the route
        // is disabled with a clear reason -- not a 500 from a swallowed issueChallenge throw.
        if (allowReplay) return err(res, 404, GATE_REASONS.CHALLENGE_DISABLED);
        const c = verifier.issueChallenge();
        return send(res, 200, {
          nonce: Buffer.from(c.nonce).toString('base64url'),
          transcript: Buffer.from(c.transcript).toString('base64url'),
          expiresAt: c.expiresAt,
        });
      }

      // which === 'verify'
      if (req.method !== 'POST') return err(res, 405, GATE_REASONS.METHOD_NOT_ALLOWED, inFlight);
      let raw;
      try {
        raw = await readBody(req, maxBodyBytes, maxBodyReadMs);
      } catch (e) {
        if (e && e.code === 'TOO_LARGE') return err(res, 413, GATE_REASONS.PAYLOAD_TOO_LARGE, CLOSE);
        if (e && e.code === 'SLOW') return err(res, 408, GATE_REASONS.REQUEST_TIMEOUT, CLOSE);
        throw e;
      }
      let parsed;
      try {
        parsed = JSON.parse(raw.toString('utf8'));
      } catch {
        return err(res, 400, GATE_REASONS.BAD_REQUEST);
      }
      if (!parsed || typeof parsed.transcript !== 'string' || typeof parsed.deviceResponse !== 'string') {
        return err(res, 400, GATE_REASONS.BAD_REQUEST);
      }
      const proof = {
        transcript: new Uint8Array(Buffer.from(parsed.transcript, 'base64url')),
        deviceResponse: new Uint8Array(Buffer.from(parsed.deviceResponse, 'base64url')),
      };
      const verdict = await verifier.check(proof);
      // §1 invariant on the wire: ok -> 200 (read over_threshold in the body); not-ok
      // -> 503 (we could not verify), NEVER a "denied person" status.
      return send(res, verdict.ok ? 200 : 503, verdict);
    } catch {
      // Never leak internals to the client; never throw out of the handler.
      return err(res, 500, GATE_REASONS.INTERNAL_ERROR);
    }
  }

  // A last-ditch guard so nothing ever throws OUT of the gate: handle() catches its own
  // request handling, but a surprise in the tiny prologue (URL-catch's err(), or next())
  // would otherwise surface as an unhandled rejection. Swallow it, having already tried
  // to answer; a crashed process is a worse failure than a dropped connection.
  const guard = (p) => Promise.resolve(p).catch(() => {});

  return {
    /** Framework-agnostic: `http.createServer(gate.handler)`. */
    handler: (req, res) => {
      guard(handle(req, res, () => err(res, 404, GATE_REASONS.NOT_FOUND)));
    },
    /** Express/Connect: `app.use(gate.express())` (mount at root; it owns `basePath`). */
    express() {
      return (req, res, next) => {
        guard(handle(req, res, () => next()));
      };
    },
  };
}

/**
 * Start a verifier AND wrap it in the gate, replay-safe by default.
 *
 * This is where piece 3 FLIPS the primitive's stance: `requireSingleUse` defaults to
 * `true` here (it defaults `false` on the bare `Verifier`, which cannot self-configure
 * a shared secret + store). Running replay-open is a deliberate, typed opt-out
 * (`requireSingleUse:false`). With single-use on, the two things it needs -- a
 * `challengeSecret` (>= 16 bytes, stable and shared across replicas) and a shared
 * `nonceStore` -- are checked HERE, before the slow circuit load, so a missing one
 * fails in a second. `store:'memory'` is an explicit single-process dev shortcut.
 *
 * @param {import('./types.js').ServiceInit & {threshold?: number,
 *   requireCurrentValidity?: boolean, toleranceMs?: number,
 *   requireSingleUse?: boolean, challengeSecret?: Buffer|Uint8Array|string,
 *   nonceStore?: import('./types.js').NonceStore, store?: 'memory',
 *   challengeTtlMs?: number, basePath?: string, maxBodyBytes?: number,
 *   maxBodyReadMs?: number, rateLimit?: {limit: number, windowMs: number}|false,
 *   trustProxy?: boolean}} opts
 * @returns {Promise<{handler: import('node:http').RequestListener,
 *   express: () => (req: any, res: any, next: () => void) => void,
 *   verifier: Verifier, stop: () => Promise<void>}>}
 */
export async function startGate(opts) {
  if (!opts || typeof opts !== 'object') {
    throw new TypeError('startGate needs service options (binary, circuitDir, caCerts, ...)');
  }
  const requireSingleUse = opts.requireSingleUse ?? true; // FLIP: safe-by-default
  // Prefer an explicit store; otherwise the named dev shortcut; otherwise nothing.
  let nonceStore = opts.nonceStore;
  if (nonceStore == null && opts.store === 'memory') nonceStore = new InMemoryNonceStore();

  // Fail closed BEFORE the 44-73s circuit load, with a message that names the opt-out.
  if (requireSingleUse) {
    if (opts.challengeSecret == null) {
      throw new TypeError(
        'startGate is replay-safe by default and needs a challengeSecret (>= 16 bytes); ' +
          'pass requireSingleUse:false to deliberately run replay-open',
      );
    }
    // Validate the secret's SHAPE here too, not just its presence -- otherwise a too-short
    // secret slips past this check and only trips assertSecret inside the Verifier
    // constructor, AFTER the minute-long circuit load, breaking the "fails in a second"
    // contract. (Matches challenge.js assertSecret: >= 16 bytes, Buffer/Uint8Array/string.)
    const s = opts.challengeSecret;
    if ((typeof s !== 'string' && !(s instanceof Uint8Array)) || s.length < 16) {
      throw new TypeError('startGate needs a challengeSecret of at least 16 bytes (Buffer/Uint8Array or string)');
    }
    if (nonceStore == null || typeof nonceStore.spend !== 'function') {
      throw new TypeError(
        'startGate is replay-safe by default and needs a nonceStore with an atomic ' +
          'spend(key, ttlMs) (e.g. Redis SET NX PX), or store:"memory" for single-process ' +
          'dev; pass requireSingleUse:false to deliberately run replay-open',
      );
    }
  }

  const verifier = await Verifier.start({ ...opts, requireSingleUse, nonceStore });
  const gate = createGate({
    verifier,
    // The verifier we just started reports its own single-use state; when the adopter
    // opted out (requireSingleUse:false) the verifier is replay-open, so tell createGate
    // to allow it rather than throw on the very verifier startGate built.
    allowReplay: !requireSingleUse,
    basePath: opts.basePath,
    maxBodyBytes: opts.maxBodyBytes,
    maxBodyReadMs: opts.maxBodyReadMs,
    rateLimit: opts.rateLimit,
    trustProxy: opts.trustProxy,
  });
  return { ...gate, verifier, stop: () => verifier.stop() };
}

export { GATE_REASONS };
