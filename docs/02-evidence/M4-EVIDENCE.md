# M4 — the gate: evidence log

**Date:** 2026-07-15 · **Machine:** Fedora 44, 8 cores · **Go:** 1.26 ·
**Status: IN PROGRESS.** Piece 1 of 3 — the **credential-currency (freshness) gate** —
**PASSED**. It closes the gap PRD §7.1a named: an expired credential used to verify. The
remaining pieces of M4 — the per-session **nonce** (§7.4a) and the HTTP endpoint /
middleware / demo site (§6, §7.2) — are not built yet.

M4 owns the question *"is this presentation still good **right now**"* (§7.4), which has two
independent halves. This piece is half (b): **credential validity window**. Half (a),
session freshness (the nonce), is separate and still open.

---

## The gap, precisely (PRD §7.1a / §7.4b)

There are two clocks in the verify path, and until this piece only one was real:

| Clock | Source | Real before M4? |
|---|---|---|
| x509 chain (`NotBefore`/`NotAfter`) | Go `time.Now()` via `opts.CurrentTime` (`poc/…/zk/cbor.go:289`) | ✅ (M2) |
| Credential validity window (MSO `validFrom`/`validUntil`) | `Now = zkdata.Timestamp`, read from the proof's **own CBOR** (`cbor.go:191`), fed to the circuit as `cNow` (`proofs.go:177`) | ❌ **prover-declared** |

The circuit checks `validFrom ≤ Now ≤ validUntil` — against a `Now` the **prover** supplies.
Nothing bounded that timestamp to the verifier's real clock. So a prover holding an expired
credential picks any `Now` inside the (past) window, the circuit says "valid at that time,"
and the verifier accepts. The verifier let the proof declare what time it was.

## Fail-first — the hole is real (measured before any fix)

A new fixture, `expired-credential`, was minted: an over-18 credential whose validity window
is `2020-01-01 … 2021-01-01`, presented with wire `Timestamp = 2020-06-01T00:00:00Z` (inside
that past window, so longfellow's own check passes) and an x509 chain on the **real** clock
(so it is not refused at chain validation — it reaches the ZK-accept layer). longfellow's raw
verifier **accepts** it (the fixture generator asserts `expectAccept` and it holds).

Through the actual Node `Verifier.check()`, on the **unpatched** verifier, real clock
`2026-07-15T20:18:25Z`:

```
[valid]              ok=true over_threshold=true reason=verified
[expired-credential] ok=true over_threshold=true reason=verified   ← 5+ years expired, ACCEPTED
```

Byte-for-byte the same verdict as a live credential. The `valid` row shows the harness can
also produce the positive, so this is discrimination, not an accept-everything artifact.

## The fix — Option C (engine reports the date; we decide)

Chosen over parsing the timestamp ourselves (would reimplement longfellow's CBOR parse —
NO-GO #8) and over letting the engine enforce it (would collapse "expired" and "tampered"
into one opaque `Status:false` and bury the policy in code we do not own).

1. **Engine patch** (`poc/patches/0003-m4-echo-verified-timestamp.patch`, ~8 lines): the
   verify response gains `Now` — the timestamp the circuit verified against, echoed verbatim.
   It reports; it decides nothing. No trust or ZK math touched (NO-GO #8 intact). Same shape
   as the M3 circuit-id bridge (patch 0002).
2. **Policy in `src/verdict.js`** (the layer we own): at the would-be-accept point, when the
   caller requires currency, bound the echoed date against an injected real clock.

Verdict mapping (the §1 invariant, extended to the new surface):

| Engine | Echoed date | vs real clock | Verdict | Reason |
|---|---|---|---|---|
| accept, age true | present | within tolerance | `ok:true, over:true` | `verified` |
| accept, age true | present | stale | `ok:true, over:false` | `credential_expired` |
| accept, age true | **absent** | — | `ok:false, over:null` | `freshness_unknown` |

A **missing** reading is `ok:false` (we could not judge), **never** a "no": collapsing "I
couldn't check the date" into "this ID is expired" would be this project's signature bug on a
new surface. Freshness is asserted only on a date we actually read.

## The knob — `requireCurrentValidity` (owner decision, amends §7.4b)

Default **on**. An expired credential still *proves adulthood* — age is monotonic, so
"over 18 as of a past date" implies "over 18 now" — so whether expiry should reject depends
on the relying party: an age-gate may accept it; a KYC-style flow must not. 8een is an
outside component, so this is the adopter's call. The secure default preserves §7.4b's intent
for anyone who never touches it. This relaxes §7.4b from "must not verify" (absolute) to
"must not verify **by default**, configurable." Tolerance (default 5 min) is how far the
presentation date may sit from real time; its real job is catching expiry (gaps of days to
years), while tight per-visit liveness is the nonce's (piece 2), so the exact value is not
load-bearing.

## The fix — verified end to end

Patched verifier + gate, one loaded service, real clock `2026-07-15T20:25:04Z`:

```
--- requireCurrentValidity ON (default, secure) ---
valid              ok=true  over=true   verified
expired            ok=true  over=false  credential_expired     ← now REFUSED
underage           ok=true  over=false  claim_false            ← gate untouched: false-claim path

--- requireCurrentValidity OFF (age only) ---
valid              ok=true  over=true   verified
expired            ok=true  over=true   verified                ← age fact stands
```

Non-vacuity is built in three ways: the same service accepts fresh and refuses expired; with
the gate off the expired credential verifies again (so the gate is provably what refuses it);
and `underage` stays `claim_false` (the gate never touches the false-claim path).

## Tests

- **Unit** (`test/verdict.test.js`, +9): fresh passes; stale → `credential_expired`; the exact
  tolerance boundary (just-inside vs just-outside, injected `now`, deterministic); future-skew
  caught; **no date → `freshness_unknown` (`ok:false`)**; no clock → `freshness_unknown`; gate
  off → stale passes; the gate never touches the false-claim path. Fast gate: **39/39**.
- **Integration** (`test/integration.test.js`, +1 test / 3 subtests, real clock, real
  longfellow): the fail-first hole, now closed and guarded — fresh accepted, expired refused,
  and the same expired credential accepted with the gate off. The pre-existing accept-path
  tests (trust discrimination, §7.1 matrix, EU matrix, unlinkability) test orthogonal concerns
  and deliberately opt **out** of the gate (`requireCurrentValidity:false`) — coupling them to
  the wall clock would make them flake as fixtures age, for no coverage the dedicated M4 test
  and the unit boundary do not already give. Full suite green.

### A harness note that is not a product default

The 5-min production tolerance is unit-tested at the exact boundary. The M4 integration test
widens it to 24 h because the suite mints fixtures **once** and verifies them across minutes of
per-server circuit loads (45–70 s each), so a genuinely fresh credential can be several minutes
old by the time that test checks it. 24 h covers any realistic suite runtime while still
failing the years-stale expired fixture. This is a property of the test harness, not the gate.

**A note on the tolerance's meaning (review finding #2).** With a single echoed timestamp,
`toleranceMs` is *both* the clock-skew allowance and the post-expiry grace — a credential that
expired within `toleranceMs` can still present at its last-valid instant and pass. This is
inherent (we echo one time, not the window), not a separable bug, and it is why the production
default is kept small: at 5 min the grace is negligible; widen it only for genuine skew.

### Reproduce

Apply the patch in the clone and rebuild the reference server:
`git -C poc/longfellow-zk apply poc/patches/0003-m4-echo-verified-timestamp.patch` then
`CGO_ENABLED=1 go build -o server .` in `reference/verifier-service/server`.

The **M4 freshness test** requires 0003 (it needs the echoed `Now`); the other integration
tests opt out of the gate and pass on a 0001+0002 server. But a real **adopter** running the
gate on (the default) needs a server that echoes `Now`, so the current 8een build baseline is
0001+0002+0003. Recorded in the clone-build recipe (`poc/M0-EVIDENCE.md`).

## Scope — what this piece does NOT do

- **Replay / session freshness (§7.4a).** Still open. A byte-identical proof replayed in its
  own session is still accepted by design; the per-session single-use nonce is piece 2. **8een
  remains not replay-safe and must not be described as such.**
- **The credential's clock inside the circuit.** Untouched. We bound the circuit's `now`
  *input* against real time from outside; we do not change its maths (NO-GO #8).
- **The endpoint, middleware, demo site (§6, §7.2).** Pieces 2 and 3.
