# M2 — test-CA + prover: evidence log

**Date:** 2026-07-14 · **Machine:** Fedora 44, 8 cores · **Go:** 1.26 ·
**Status: SPIKE PASSED — milestone IN PROGRESS.**

This log opens with the de-risking spike. **M2 is not complete.** What is settled
is the riskiest assumption; what remains is productionization (see "Still owed").

**Exit criterion (PRD §6):** *"We can generate spec-conformant
credentials/proofs ourselves."*

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
| `valid` | `age_over_18=true` | 361,108 B | **SUCCESS** |
| `untrusted-issuer` | `age_over_18=true` | 360,372 B | **SUCCESS** — by design; it is refused at *chain* validation, its CA withheld from the trust PEM |
| `underage` | `age_over_18=false` | 360,628 B | **SUCCESS** — an honestly-proven minor; the proof is valid, the *claim* is false |
| `tampered` | `age_over_18=true`, one proof byte flipped | 360,948 B | **REFUSED** (`merkle_check failed`) |

Certificates are issued on the real wall clock (observed window
`2025-07-14 .. 2027-07-14`), which is what makes the `ZKVERIFY_FAKE_TIME`
scaffolding removable rather than merely undesirable.

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

## Still owed before M2 can be called PASSED

- Wire the JS integration suite onto these fixtures (the generator emits them; the
  suite does not yet consume them).
- The last row of the negative matrix: stale/wrong-nonce (PRD §7.1). The other four
  — valid, underage, wrong-issuer, tampered — are emitted and self-verified above.
- Remove `ZKVERIFY_FAKE_TIME` from the integration harness once the suite is on the
  minted (unexpired) certs.
- §7.3 unlinkability black-box check: two presentations of the same credential
  share no verifier-side identifier (requires proving the same credential twice).

## Honesty notes

- The spike passed on first execution — a statement about how byte-accurate the
  extracted spec was (`poc/m2-spike/MINT-SPEC.md`, cited to longfellow source),
  not that this was easy. The prover error enum was a precise oracle.
- `MDOC_VERIFIER_GENERAL_FAILURE` / `MDOC_PROVER_GENERAL_FAILURE` are coarse
  ("rejected", not "why"). That is fine here — the point is refusal — but M2's JS
  verdict layer already maps verifier outcomes to specific reasons, and its
  fixtures must exercise those, not just "not-success."
