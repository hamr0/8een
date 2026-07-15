# M4 piece 1 — the credential clock (design)

**Status:** validated in brainstorm 2026-07-15, not yet built.
**Scope:** the first, isolated slice of M4 (§6). No HTTP surface. Ships as its own PR.
**Closes:** the gap named at PRD §7.1a / §7.4b — "an expired credential must not verify"
is currently untested and, as this doc shows, currently *false*.

---

## 1. The finding (grounded, not assumed)

There are two clocks in the verify path, and only one is real.

| Clock | Source | Real? |
|---|---|---|
| **x509 chain** (cert `NotBefore`/`NotAfter`) | Go `time.Now()` via `opts.CurrentTime` — `poc/.../zk/cbor.go:289` | ✅ real (M2) |
| **Credential validity window** (MSO `validFrom`/`validUntil`) | `Now = zkdata.Timestamp` — read from the proof's **own CBOR** (`cbor.go:104`, `cbor.go:191`), fed to the circuit as `cNow` (`proofs.go:177`) | ❌ **prover declares it** |

The circuit checks `validFrom ≤ Now ≤ validUntil` lexically — against a `Now` the
**prover supplied**. Nothing in the Go path (`handleZKVerify`, `VerifyProofRequest`)
compares that timestamp to the wall clock, and the response
(`ZKVerifyResponse{Status, Claims, Message}`) does not even echo it.

**Consequence — the actual bug §7.1a names:** an expired credential is still provable.
The prover picks any `Timestamp` inside the (now-past) validity window, the circuit says
"valid at that time," and the verifier accepts. Setting `validUntil` in the past is *not*
enough to cause refusal; the prover simply dates the note to match. The verifier lets the
proof declare what time it is.

**What "drive the credential clock from real time" concretely means:** the verifier must
reject when the proof's declared `Timestamp` is not within a tolerance of *its own* real
clock. One skew check catches both an expired credential (window in the past) and a stale
presentation (window fine, timestamp old).

## 2. Approach — Option C (engine reports, we decide)

Chosen over: (A) parsing the timestamp out of the CBOR ourselves — forbidden, that is
reimplementing longfellow's parsing (NO-GO #8) and needs a CBOR dep (NO-GO #9); (B) letting
the engine enforce the bound itself — collapses "expired" and "tampered" into one opaque
`Status:false` and buries the tolerance policy in code we do not own.

**Option C, two parts:**

1. **Engine patch (tiny, same shape as the M3 circuit-id bridge / patch 0002).** Add one
   field to the verify response so it *reports* the timestamp it verified against — it does
   **not** decide. `ZKVerifyResponse` gains `Now string` (`json:"Now,omitempty"`), set to
   `vreq.Now` in `handleZKVerify`. Meaningful only alongside `Status:true`. Carried as
   `poc/patches/0003-*.patch`, applied to the built binary; the source patch is documented,
   never a silent local edit.

2. **Policy in code we own (`src/verdict.js`).** After a proof has passed the maths *and*
   carries a true `age_over_18` — the existing `VERIFIED` accept at `verdict.js:191` — apply
   the freshness gate. Parsing the echoed date is `Date.parse()` of an RFC3339 string the
   engine already decoded — **not** CBOR parsing.

## 3. The verdict logic

`classify()` gains three injected opts (kept pure — no `Date.now()` inside):
`requireCurrentValidity` (default `true`), `toleranceMs` (default `300_000` = 5 min),
and `now` (ms, supplied by the `Verifier.check()` wrapper as `Date.now()`).

Two new `REASONS`:
- `CREDENTIAL_EXPIRED: 'credential_expired'` → `answered(false, …)` i.e. `ok:true,
  over_threshold:false`. A real "no", distinct from `CLAIM_FALSE` (genuinely under age).
- `FRESHNESS_UNKNOWN: 'freshness_unknown'` → `unanswerable(…)` i.e. `ok:false,
  over_threshold:null`. We could not read a date, so we refuse to judge.

At the `VERIFIED` point, when `requireCurrentValidity` is on:

| Engine | Date echoed | vs real clock | Verdict | Reason |
|---|---|---|---|---|
| `Status:true`, age true | present | within tolerance | `ok:true, over:true` | `verified` |
| `Status:true`, age true | present | stale | `ok:true, over:false` | `credential_expired` |
| `Status:true`, age true | **absent / unparseable** | — | `ok:false, over:null` | `freshness_unknown` |

When `requireCurrentValidity` is **off**: skip the block entirely → `ok:true, over:true`.
The age fact stands regardless of the credential's date; a missing date is not a failure
because freshness was not the question asked.

**The invariant holds in both modes.** We never fabricate a "no": a broken/absent reading
is `ok:false`, never `over:false`. Off-mode never falsely claims over-18 — it accepts an
old-but-genuine adult proof, the site's informed choice. Replay stays separately shut by
the nonce (piece 2), so off-mode opens no replay hole.

## 4. The knob (owner decision, amends §7.4)

`requireCurrentValidity`, surfaced on `Verifier.start(opts)`, default **on**.

An expired ID still *proves adulthood* — age is monotonic, so "over 18 as of a past date"
implies "over 18 now." Whether that suffices depends on the relying party: a page that
age-gates may accept it; a site needing a *current* government credential must not. 8een is
an outside component, so this is the adopter's call, not our hardcode.

This **amends PRD §7.4b** from "an expired credential must not verify" (absolute) to "…must
not verify *by default*, configurable." The secure default preserves §7.4's intent for any
adopter who never touches the knob. Recorded as an owner decision (§9), and
`8een.context.md` gains the new option in the same commit as the code.

## 5. Fixtures — unfreeze the clock

`tools/mkfixture` today stamps a frozen `nowStr = "2026-07-13T00:00:00Z"` (`mint.go:154`)
and a fixed `validFrom/validUntil` of `2020..2030`. Two changes:

- **Valid/fresh fixtures:** `nowStr` derives from the real wall clock (like `certWindow`
  already does at `fixture.go:91`), so a fresh credential's declared date is ≈ now and
  passes the freshness gate. This is literally §7.4b(a), "drive the credential clock from
  real time."
- **New `expired-credential` fixture:** `validUntil` in the past, `nowStr` set *inside* that
  past window (so the circuit's own `validFrom ≤ now ≤ validUntil` check passes) — the exact
  move an attacker makes. Our real-clock gate is what must catch it. Same shape as the
  existing `stale-nonce` fixture.

## 6. Tests — fail-first, and never vacuous

Per doctrine (a guard you have not watched fire is not a guard):

1. **Fail-first POC (before any fix):** mint the `expired-credential` fixture, run it through
   **today's** verifier, and *observe it is accepted*. This proves the hole is real and the
   test can produce the negative. Recorded as a measurement in the M4 evidence doc.
2. **After the fix (integration matrix):**
   - expired fixture → `ok:true, over:false, reason:credential_expired` (the "no" fires).
   - fresh fixture → `ok:true, over:true, reason:verified` (**non-vacuity** — we did not just
     break everything into refusing).
   - knob **off** + expired fixture → `ok:true, over:true` (age fact stands).
   - no-date response (patch absent / field stripped) → `ok:false,
     reason:freshness_unknown` (the reading-missing guard, unit-level on `classify()`).
3. **Unit (`classify()`):** the tolerance boundary — just inside vs just outside — with
   injected `now`, so the pure classifier is exercised without a real clock.

## 7. Out of scope for this piece

- The per-session **nonce** / single-use replay defence (§7.4a) — piece 2, the gate.
- The HTTP endpoint, Express middleware, demo site (§6, §7.2) — pieces 2 and 3.
- The circuit's *internal* clock semantics — untouched; we bound its input, we do not change
  its maths.
