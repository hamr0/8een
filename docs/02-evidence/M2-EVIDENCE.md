# M2 — test-CA + prover: evidence log

**Date:** 2026-07-14 · **Machine:** Fedora 44, 8 cores · **Go:** 1.26 ·
**Status: PASSED.**

This log opens with the de-risking spike that settled the riskiest assumption, and
closes with the milestone met: the integration suite mints its own credentials,
runs the full §7.1 negative matrix and the §7.3 unlinkability check, and does it all
on the real clock — **18/18, 0 skipped**. The `ZKVERIFY_FAKE_TIME` scaffolding that
M0 and M1 leaned on is gone from the tree.

**Exit criterion (PRD §6):** *"We can generate spec-conformant
credentials/proofs ourselves."* — **met.**

**Riskiest assumption under test:** can we mint a synthetic ISO 18013-5
credential under our own test CA that longfellow's own prover **and** verifier
both accept — **without reimplementing any longfellow crypto** (PRD NO-GO #8)?
If not, M2's whole shape changes and the negative matrix (underage, wrong-issuer)
stays untestable. The answer is **yes.**

## The spike (throwaway, `poc/m2-spike/`, not shipped)

A Go program: generate a P-256 issuer CA + device key at runtime, hand-assemble a
full `DeviceResponse` (MSO, COSE_Sign1 issuerAuth, deviceAuth over a transcript),
and drive longfellow's `run_mdoc_prover` / `run_mdoc_verifier` through a cgo
binding that mirrors upstream's own `reference/.../zk/proofs.go`. Per POC-first,
this code is **rewritten, never shipped** — M2 proper re-implements it as tested
builders under dev-only tooling.

**No cryptography is authored.** Signing is Go stdlib (`crypto/ecdsa`,
`crypto/x509`-style key handling), hashing is `crypto/sha256`. What is
hand-written is CBOR *byte layout* — assembly, not primitives. Upstream provides
no credential minter of any kind (confirmed: every test mdoc in longfellow is a
frozen byte array in `mdoc_examples.h`), so composing stdlib + exact byte
framing is the only path, and it does not cross NO-GO #8: the ZK core, witness,
and parser stay untouched.

## Measured (observed, not asserted)

Circuit `kZkSpecs[0]` (`8d079211…`, 1 attribute, ZK spec v7). Fresh keys + salt
every run; nothing pinned or memoized.

| Step | Result | Size / time |
|---|---|---|
| `run_mdoc_prover` on minted `age_over_18=true` cred | `MDOC_PROVER_SUCCESS` | proof ≈ 361 KB, ≈ 2.5 s |
| `run_mdoc_verifier` on that proof | `MDOC_VERIFIER_SUCCESS` | ≈ 0.7 s |

Reproduced independently by rebuilding from source (`go build`) and re-running —
not trusting the subagent's report.

## Discrimination — the half that usually goes untested

A verifier that says *yes* to a valid proof proves nothing on its own; one that
says yes to everything looks identical. Three properties, all enforced by
longfellow's **own** compiled code:

1. **Accept:** valid over-18 proof → `MDOC_VERIFIER_SUCCESS`.
2. **Wrong issuer → reject:** the same proof verified under a *different* (validly
   formed P-256) issuer key → `MDOC_VERIFIER_GENERAL_FAILURE`. The verdict is
   genuinely bound to the issuer; this is PRD §7.1 "rejects a proof chained to a
   cert NOT on the list."
3. **Cannot forge over-18 from under-18** *(the product-defining test)*: mint a
   validly-issuer-signed credential with `age_over_18 = false`, then have a
   malicious holder request to open it as `true`. The prover **refuses**
   (`MDOC_PROVER_GENERAL_FAILURE`) — no passing proof is producible. "Turn away
   the minor" holds at the cryptographic layer.

(Tests in `poc/m2-spike/neg_test.go`, run against the real static lib.)

## Load-bearing constraints found (carry into M2 proper)

Security-relevant, and all instances of this repo's silent-partial-load theme —
they are recorded here because the spike dir is throwaway:

- **The prover never parses `x5chain`.** `issuerAuth[0]`/`[1]` are ignored
  entirely (`mdoc_witness.h:159-167`). Issuer identity is **only** the `(pkx,pky)`
  passed in. M2 must source that key from a vetted trust list and never infer it
  from the envelope — the truncated-trust-list failure mode in CLAUDE.md.
- **Circuit must be verified by `circuit_id`, not filename.** We loaded the
  prebuilt circuit by hash; M2 must assert the loaded bytes match the `kZkSpecs`
  hash (as the reference server's `LoadCircuits` does) — same "verify what
  actually loaded" doctrine as readiness.
- **The ≥256-byte MSO / `0x59` trap.** The parser skips exactly 5 bytes assuming
  the tagged MSO uses the 2-byte length form; an MSO < 256 bytes encodes with
  `0x58` and is misread. M2's minter must guarantee ≥256 by construction; any
  ingested third-party mdoc must be validated for this before proving.
- **Validity window replaces the pinned clock.** The spike used
  `validFrom=2020…`, `validUntil=2030…`, `now=2026-07-14…` (all 20-char tdates,
  circuit asserts `C0 74` + exactly 20 date bytes). M2 generates windows relative
  to a real clock, which **removes the `ZKVERIFY_FAKE_TIME` scaffolding** the one
  real (expired) proof forced on the accept path.

## The generator (`tools/mkfixture`) — measured 2026-07-14

Dev-only Go tooling, outside the npm `files` allowlist; zero runtime deps preserved.
Observed on one full run against the real static lib:

| Scenario | Minted | Proof | longfellow's ZK verdict |
|---|---|---|---|
| `valid` | `age_over_18=true` | 361,300 B | **SUCCESS** |
| `untrusted-issuer` | `age_over_18=true` | 361,012 B | **SUCCESS** — by design; it is refused at *chain* validation, its CA withheld from the trust PEM |
| `underage` | `age_over_18=false` | 359,284 B | **SUCCESS** — an honestly-proven minor; the proof is valid, the *claim* is false |
| `tampered` | `age_over_18=true`, one proof byte flipped | 361,364 B | **REFUSED** — `MDOC_VERIFIER_GENERAL_FAILURE` (code 5) |
| `stale-nonce` | `age_over_18=true`, proven under session A, presented under session B | 360,820 B | **REFUSED** — `MDOC_VERIFIER_GENERAL_FAILURE` (code 5); the device signature does not match a preimage rebuilt over another session's transcript |
| `mangled-cert` | `age_over_18=true`, leaf signature byte corrupted | 359,924 B | **SUCCESS** — by design; the ZK proof is sound and the rejection must come from *chain* validation |
| `unlinkable-a1/a2/b1` | `age_over_18=true` ×3, one issuer, one DS cert | ~360 KB each | **SUCCESS** ×3 — a1/a2 are one credential presented twice; b1 is a *different* credential from the same issuer |

Whole run: **16.2 s** for all nine fixtures including their self-verification —
against an integration suite whose circuit loads dominate at 45–70 s *per server*.
Cheap enough that the suite mints fresh fixtures on every run and commits none.

Certificates are issued on the real wall clock (observed window
`2025-07-14 .. 2027-07-14`), which is what makes the `ZKVERIFY_FAKE_TIME`
scaffolding removable rather than merely undesirable.

The `stale-nonce` row required splitting **mint** (the issued credential: issuer key,
device key, salt, signed MSO) from **present** (the device signature over *this
session's* transcript). Before it, the transcript was a hardcoded 4-byte constant
baked into the mint, so "the same credential in a different session" was not
expressible at all — and neither was §7.3, which needs one credential presented
twice. One refactor, both rows. The device-auth preimage is pinned byte-for-byte by
`TestDeviceAuthPreimageIsByteExact`, which is what made the refactor safe to do.

Two things the generator **checks rather than assumes**, both instances of this
repo's silent-partial-load theme:

- **The circuit is verified by id, not by filename**, via longfellow's own
  `circuit_id()` (`mdoc_zk.h:191`) — the same call the reference service makes. This
  is not belt-and-braces: `mdoc_zk.cc:112-113` disables longfellow's internal id
  enforcement and states that "the application is expected to check the ID once."
  Verified empirically: a *truncated* circuit planted under the correct filename is
  refused, exit 1, zero fixtures written.
- **Every fixture is verified before it is written.** The leaf cert must carry the
  exact key that signed the MSO (otherwise the chain validates, the service extracts
  the *wrong* `(pkx,pky)`, and valid proofs fail while looking like bad crypto), and
  the proof must reach the verdict its scenario claims — so a byte-flip that landed
  on an inert byte fails generation instead of shipping as a negative test that
  silently passes. Both guards are pinned by tests that assert they *fire*.

## The pinned clock is gone — measured 2026-07-14

`ZKVERIFY_FAKE_TIME` no longer appears in `src/`, `test/` or `tools/`. The
integration suite mints its fixtures at setup and runs entirely on the real wall
clock. **18/18 pass, 0 skipped, 281 s.**

This was the point of the whole test-CA exercise, and it is worth being precise
about what it bought. Under the pinned clock, *no test in the suite could tell a
working chain-validator from a broken one* — x509 verification was frozen at a date
where the one available chain happened to be valid. Now the accept path exercises it
for real.

**post1.json could not come along, and that was measured, not assumed.** On the real
clock the service rejects *every* post1-derived fixture at chain validation —
`ok=true, over=false, issuer_untrusted`, detail `x509: certificate has expired` — the
valid one and the deliberately-broken ones alike. Nothing reaches the ZK layer. So
the rows asserting `zk_proof_invalid` would have gone **red**, and the row asserting
only `ok`/`over_threshold` would have **passed while testing nothing**. Every
proof-bearing fixture is minted now. (`poc/make-fixtures.mjs` stays: it is cited by
the M0 evidence record.)

### The negative matrix (PRD §7.1), as it now runs

| Row | Verdict | Reason |
|---|---|---|
| valid, trusted issuer | `ok:true`, `over:true` | `verified` — on the real clock |
| **underage**, honestly proven | `ok:true`, `over:false` | `claim_false` — the proof is *valid*; the answer is still no |
| issuer off the trust list | `ok:true`, `over:false` | `issuer_untrusted` — refused at the chain, not the ZK layer |
| tampered proof | `ok:true`, `over:false` | `zk_proof_invalid` |
| **replayed into another session** | `ok:true`, `over:false` | `zk_proof_invalid` |
| mangled cert chain | `ok:true`, `over:false` | rejected, not crashed on |
| garbage bytes | `ok:true`, `over:false` | rejected, not crashed on |
| malformed argument | `ok:false`, `over:null` | `invalid_request` — a caller bug is not evidence about a person |
| over-18 proof, site wants over-21 | `ok:true`, `over:false` | `claim_absent` |
| byte-identical replay | `ok:true`, `over:true` | **accepted, by design** — see below |

The last two rows of that table must be read together, because they look like a
contradiction and are not. A proof lifted into a **different** session is refused, by
cryptography — the device signature will not match a preimage rebuilt over another
transcript. The **same** proof replayed in **its own** session is accepted, because
the verifier is stateless and has no memory to detect it with. Freshness is the
gate's job (M4). 8een is not replay-safe and must never be described as such.

### §7.3 unlinkability

Split across the two places each half can be honestly asserted:

- **Structural** (`tools/mkfixture/unlink_test.go`): the verifier-visible envelope is
  **byte-identical** — 1,193 B — across a1, a2 *and* b1, while the three proofs are
  pairwise distinct. b1 is the control that gives this meaning: it is a *different*
  credential from the same issuer, so the equality says the envelope distinguishes
  nothing at the credential level. a1 is linkable to a2 by exactly as much as it is
  linkable to b1 — i.e. by the issuer's certificate, and nothing else. Non-vacuity is
  asserted in the same test: a credential from a *different* issuer does produce a
  different envelope, so the comparison demonstrably discriminates.
- **Behavioural** (integration suite): the verifier returns byte-identical verdicts
  for all three presentations, and the wire bytes of a1/a2 are confirmed non-identical
  so the result is not a tautology.

The structural half lives in Go because reading it back requires decoding CBOR, and
8een parses no CBOR itself and will not grow a parser to test itself (NO-GO #8). The
generator already depends on a CBOR library legitimately, for the wire envelope.

**Not claimed:** that longfellow's *proof bytes* hide every per-credential
identifier. That is the cryptographic result, and PRD §7.3 scopes it as *cited, not
claimed* — it rests on the scheme's own security analysis, not on any test we wrote.

## Honesty notes

- The spike passed on first execution — a statement about how byte-accurate the
  extracted spec was (`poc/m2-spike/MINT-SPEC.md`, cited to longfellow source),
  not that this was easy. The prover error enum was a precise oracle.
- `MDOC_VERIFIER_GENERAL_FAILURE` / `MDOC_PROVER_GENERAL_FAILURE` are coarse
  ("rejected", not "why"). That is fine here — the point is refusal — but M2's JS
  verdict layer already maps verifier outcomes to specific reasons, and its
  fixtures must exercise those, not just "not-success."
