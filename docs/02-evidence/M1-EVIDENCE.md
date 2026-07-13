# M1 — verify module: evidence log

**Date:** 2026-07-13 · **Machine:** Fedora 44, 8 cores · **Node:** v22.22.2 · **Status: PASSED**

**Exit criterion (PRD §6):** *"The binary's output can be classified into a
trustworthy one-bit verdict."*

**Riskiest assumption under test:** not "does the ZK maths work" — M0 settled
that. It is: **can the service's output be trusted to mean what it appears to
mean?** The answer turned out to be *no, not naively* — see Findings.

## What shipped

Vanilla Node ≥22, `node:test`, **zero runtime dependencies** (PRD NO-GO #9).
Three modules, each working alone before integration:

| Module | Job |
|---|---|
| `src/circuits.js` | Fetch the 17 pinned circuits on first run; refuse any byte that does not match the pinned sha256. |
| `src/service.js` | Supervise the Go verifier as a long-lived child; report readiness **honestly**; turn each exchange into a raw outcome. |
| `src/verdict.js` | Pure, never-throws. Turn a raw outcome into `{ok, over_threshold, reason}`. |

## Findings that reshaped the design

These are the reason M1 is not a thin HTTP wrapper.

**1. A rejected proof still asserts `age_over_18 = true`.** Observed, verbatim:

```json
{"Status":false,
 "Claims":{"org.iso.18013.5.1":[{"ElementIdentifier":"age_over_18","ElementValue":"9Q=="}]},
 "Message":"verification failure: return code 5"}
```

`ElementValue: "9Q=="` is base64 of `0xF5` — CBOR **true** — on a **tampered,
rejected** proof. `Claims` is echoed from the *unverified* CBOR envelope: it is
what the proof *asserts about itself*, attacker-controlled, and it survives
rejection intact. So `if (resp.Claims.age_over_18) allowEntry()` — an entirely
reasonable-looking integration — is a trivial bypass with a forged blob.
**`Status` is the gate; `Claims` mean nothing in front of it.** Locked by test.

**2. A verifier with zero circuits reports healthy and rejects everyone.**
`main.go:69` discards `LoadCircuits`' error; `/healthz` is a hardcoded `200`;
`/specs` lists the specs *compiled into the binary*, not what loaded. Measured,
pointing a server at an empty directory:

| Signal | Reports | Truth |
|---|---|---|
| `/healthz` | `ok` | broken |
| `/specs` | 12 specs | 0 loaded |
| known-good adult proof | `Status:false` in 7 ms | a valid proof |

The rejection is shaped **identically to a genuine cryptographic "no"**. A naive
8een would deny every legitimate adult and call it a verdict.

**Consequences, both now enforced:**
- Readiness is **not** a ping. `service.js` counts the `Read <circuit-id>` lines
  on the child's own log — the only place the truth appears — and **refuses to
  start** on zero circuits.
- `verdict.js` splits **`ok`** (did we get an answer) from **`over_threshold`**
  (what it was), and holds `ok:false ⇒ over_threshold:null`, **never `false`**.
  Verdicts are *allowlisted*: only `run_mdoc_verifier` codes meaning "this proof
  is bad" count as a "no"; anything unrecognised defaults to *we are broken*.
  A misconfigured 8een says **"I cannot verify"**, never **"you are underage."**

**3. Upstream binds every interface** (`-port :8888`). We default to
`127.0.0.1` (AGENT_RULES least-privilege binding).

## Measured (observed, not asserted)

| Thing | Measured |
|---|---|
| Circuit provisioning, 17 files / 4.3 MB, sha256-verified | **5.4 s** |
| Circuit load → ready | **44.1 s – 72.5 s** (varies with machine load; M0 saw 46.8 s. Startup timeout set to 180 s.) |
| Verify (accept or deep reject) | **0.40 – 0.67 s** |
| Shallow reject (x509 / CBOR, pre-maths) | **0.003 – 0.005 s** |
| Zero-circuit false reject | **0.007 s** |

Startup is **not** "about 45 seconds" — it is a range, and the top of that range
is 65% higher than the bottom. Anything that assumes a fixed figure is wrong.

## Post-review hardening (2026-07-13)

`/code-review` raised 8 findings against the branch. **All 7 code findings were
reproduced by execution before being fixed** — none was accepted on argument
alone. The core invariant (`ok:false ⇒ over_threshold:null`) held throughout; no
finding let a bad proof through or turned "broken" into "underage". But two of
them meant the readiness signal was **weaker than this document claimed**, which
is its own kind of lie.

| # | Confirmed by | Fix |
|---|---|---|
| 1 | Identical bytes counted as **3, 2, or 0** circuits depending only on where the pipe chunked. A split inside the sole matching line ⇒ `start()` refuses a **healthy** server. | Buffer the partial line across chunks (`splitLines`). A child's stdout is a byte stream, not a line stream. |
| 2 | Corrupted 5 of 17 circuits ⇒ server loaded 12, opened its port, **we declared ourselves READY**. | Require *all* expected circuits, not `> 0`. Abort at the first file upstream rejects. |
| 3 | `classify(400, {})` returned `over_threshold:false` — a confident "not over 18" from a response we could not read. | A 400 is a rejection only if it carries the verifier's own `error` envelope. Structure, not prose. |
| 4 | `verify({transcript: undefined})` reported `service_unreachable` — a caller's bug sending someone to debug a healthy network. | Validate the argument up front; new `invalid_request` reason. |
| 5 | No durable `'error'` listener on the child after spawn: a later EPIPE/EPERM would take down the **host process**, not just the verifier. | Durable listener; degrade to `ok:false` like every other breakage. |
| 6 | An empty claim value made 8een declare **itself** broken over a peer's malformed response. | Empty claim ⇒ `claim_absent` (a fact about the proof). Only a genuinely unreadable value stays "we don't know". |
| 7 | A stale `.part-<pid>` from a killed run wedged provisioning with `EEXIST` once the pid recycled. | Random suffix, not the pid. |
| 8 | `npm test` started three real verifiers, ~4 min — no fast gate. | `test` = unit (200 ms); `test:integration` separate. |

**A fix that was itself wrong, caught by the suite.** The first cut of #3
discriminated on message *text*. A real garbage proof then came back with
`"unsupported operation"` — wording no regex had anticipated — and 8een reported
*"we are broken"* instead of *"that is not a proof"*. The integration suite
caught it. The rule is now structural: **the verifier's `error` envelope is what
marks a genuine refusal**, so upstream rewording can blur a reason string but can
never move the bit. A fast unit test now pins that exact message.

## Tests — 42 green (30 unit in 200 ms, 12 integration against the real service)

**Trust discrimination (PRD §7.1, D5 — the owner's definition of success):**
the **same proof bytes** are **accepted** under the real trust list and
**rejected** under a stranger CA minted at test runtime. Same input, different
anchors, different verdict. The trust list is load-bearing, and it is checked.

| §7.1 negative | Status |
|---|---|
| Proof chained to a cert **not on the list** | **Covered** — stranger-CA test, both directions |
| **Tampered** proof (flipped byte) | **Covered** |
| Wrong **session transcript** | **Covered** |
| **Under-threshold** proof | **Logic covered, fixture pending.** `age_over_18` is an issuer-signed boolean in the mdoc, so an underage holder's proof asserts `false` (CBOR `0xF4`) and we return `over_threshold:false` via `claim_false` — unit-tested against the observed wire format. Also covered: a valid over-18 proof correctly fails a site asking for over-21 (`claim_absent`). M2's test-CA supplies a real underage credential to run the path end-to-end; nothing about the logic is in question. |
| **Replayed** proof | **NOT COVERED — BY DESIGN. See below.** |

Also covered: mangled cert chain, outright garbage, an unreadable claim value
(refused rather than guessed), transport timeouts/unreachability, sha256
mismatch and truncated downloads on provisioning, self-healing of a rotted
circuit on disk, and `classify()` never throwing on any input.

## The replay gap, stated plainly

**A byte-identical replay is ACCEPTED**, and there is a passing test that says
so. The verifier is stateless: the maths cannot know a proof has been spent
before, because a replayed proof genuinely *is* valid. Nothing is broken here —
it is a division of labour.

**Freshness is the relying party's duty.** The gate must mint a nonce per visit,
bind it into the session transcript, and refuse to spend the same nonce twice.
That is **M4**, and it is a hard requirement: shipping M1 alone as a gate would
verify beautifully and still admit a fourteen-year-old holding a borrowed proof.
M1 does not claim replay protection and must never be described as providing it.

## Honesty notes / deviations

- **The accept path runs under a pinned verification clock.** The only real proof
  available (upstream's `examples/post1.json`) carries a chain that expired
  **2026-05-07**, so exercising *accept* needs upstream's patched build plus
  `ZKVERIFY_FAKE_TIME`. That switch is **injected by the test harness as an env
  option and appears nowhere in 8een's code** — it cannot ship. Every **reject**
  path above is clock-independent or ran on the **real** clock. A natively-valid
  credential arrives with M2's test-CA and this scaffolding goes away.
- **Under-threshold: fixture pending, not logic pending** — see the matrix. M2's
  test-CA mints a real underage credential and the path runs end-to-end.
- **Circuit count is 17**, not the 16 recorded in M0 (the 18th directory entry is
  a README). Corrected here.
- Two integrity checks now stand between a hostile network and the verifier:
  ours (sha256 vs the pinned manifest at upstream `d8ad8f65`) and upstream's
  (`circuit_id()` recomputed at load). Note upstream's *skips and logs* on
  failure rather than stopping — which is precisely the silently-reduced-circuit
  state that makes a server reject valid proofs while reporting healthy. We fail
  loudly first.

## Can-this-test-fail check

- The trust-discrimination test has both arms: the same bytes accept under one
  trust list and reject under another. A rubber-stamp verifier fails it.
- The zero-circuit finding came from a **real run against a real server**, not
  from reading source — the source only told us where to look.
- Negative fixtures differ from the positive by **one byte** (M0 lineage), so the
  variable is genuinely wired in.
- The replay test asserts the **uncomfortable** result (accepted), not the one we
  would prefer.
