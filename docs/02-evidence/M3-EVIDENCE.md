# M3 — EU interop: evidence log

**Date:** 2026-07-15 · **Machine:** Fedora 44, 8 cores · **Go:** 1.26 ·
**Status: IN PROGRESS** — rung 1 PASSED; rungs 2–3 pending.

**Exit criterion (PRD §6):** *"The EU app's proofs are format-compatible with
upstream longfellow."* — i.e. 8een verifies a proof it did not itself produce.

Everything through M2 was tested on proofs 8een minted. M3 exists to escape marking
our own homework: to verify a proof made by software we did not write — the EU
age-verification app. This log builds that confidence in three rungs, cheapest first,
each de-risking the next. A rung is not "done" until its check has been *run and shown*.

## The riskiest assumption, split

Format compatibility has two independent halves, and conflating them would let a
failure in one hide behind a pass in the other:

- **(A) Same proof system.** The EU app must prove with the same Longfellow circuits
  8een verifies against. If the circuit parameters differ, nothing else matters.
- **(B) No hidden mDL assumption in 8een.** 8een's own reader must not be wired to the
  ISO 18013-5 mDL docType/namespace. The EU credential is `eu.europa.ec.av.1`. If 8een
  silently assumes mDL, a real EU proof is refused for a reason unrelated to the proof
  — and that is *our* bug, indistinguishable at a glance from the app being incompatible.

Rung 1 settles (A) by measurement and (B) by running the whole §7.1 matrix under the
EU docType. Rungs 2–3 raise the confidence from "8een handles EU-shaped credentials"
to "8een verifies a genuine EU-app proof."

---

## Rung 1 — the local half (no emulator) — **PASSED**

### 1.1 (A) The EU app proves with circuits 8een already pins — measured, byte-for-byte

The EU app's Longfellow circuits ship in `eudi-lib-android-wallet-core`'s AAR
(`wallet-core/src/main/assets/circuits/longfellow-libzk-v1/`); the EU verifier's ship
in `av-dc-api-backend`'s vendored `multipaz-longfellow/src/commonMain/circuits/`. Both
sets were compared against 8een's pinned manifest (`src/circuits.manifest.json`, 17
circuits) by sha256:

| Source | circuits | vs 8een's pinned sha256 |
|---|---|---|
| EU app (prover), wallet-core AAR | 4 (the `7_*` family) | **4/4 byte-identical** |
| EU verifier, av-dc-api-backend | 8 (`6_*` and `7_*`) | **8/8 byte-identical** |

**12/12 byte-identical, 0 differing.** The EU did not fork the crypto — they ship
upstream Longfellow circuits unmodified, and every one is in the set 8een provisions.
Half (A) holds: the proof systems are the same.

### 1.2 (B) 8een sends the child no docType — read from source

`src/service.js` (the `verify` path) posts the child exactly two fields:
`Transcript` and `ZKDeviceResponseCBOR`. **No docType, no namespace.** The credential's
docType lives inside the opaque CBOR blob, which 8een never inspects. And
`findClaim` (`src/verdict.js`) scans *every* namespace for the required element
identifier, pinning none. So on inspection 8een has no mDL assumption to trip on —
but inspection is not evidence, so:

### 1.3 (B) The §7.1 matrix, re-run under the EU docType — the falsifiable check

`tools/mkfixture` gained `-doctype` / `-namespace` flags (default ISO mDL). The
element identifier stays `age_over_18` — confirmed to be the EU AV attribute name too
(`av-dc-api-backend/multipaz-doctypes/.../AgeVerification.kt:71-75`), so no flag needed.

The full fixture matrix was minted under `eu.europa.ec.av.1` and run through 8een's
**public API** (`VerifierService` + `Verifier`), asserting each row against the same
verdict its mDL twin gets (`test/integration.test.js`, "M3 rung 1"):

| Row | Verdict | Layer proven docType-agnostic |
|---|---|---|
| valid | `ok:true, over_threshold:true, verified` | accept + claim found under EU namespace |
| underage | `ok:true, over_threshold:false, claim_false` | the `ok`/`over_threshold` split |
| untrusted-issuer | `ok:true, over_threshold:false, issuer_untrusted` | chain validation |
| tampered | `ok:true, over_threshold:false, zk_proof_invalid` | the ZK math |

**Run: 4/4 pass (~105 s). Full suite: 24/24, 0 skipped, no regression to the mDL matrix.**

**Non-vacuity.** Two reject rows, each failing at a *different* layer (chain vs ZK), so
a pass cannot come from a verifier that accepts everything. And the accept rows keep
`ok` separate from `over_threshold`, so a pass cannot come from one that collapses them.

**Confound ruled out — did the test actually exercise the variable?** The minted EU
fixture's `ZKDeviceResponseCBOR` was decoded and checked: it contains the literal
`eu.europa.ec.av.1` and **not** `org.iso.18013`; the default mDL fixture is the exact
inverse. So the flags are not silently no-ops — the matrix genuinely ran under the EU
strings. (A missing version of this check is the classic trap: a test that "passes"
against a fixture that never actually changed.)

**Corroboration that the crypto layer agrees.** `mkfixture` refuses to emit a fixture
it has not itself put through longfellow's real prover *and* verifier
(`assertFixtureVerifies`). The EU-docType set minting at all means longfellow accepts
the EU-docType accept-fixtures and rejects the negatives — independently of 8een's
classification layer.

### 1.4 What rung 1 does and does not establish

**Establishes:** the necessary local precondition — 8een reads an EU-docType,
EU-namespace credential exactly as an mDL one, across accept and both reject layers,
and the proof system is provably identical. A real EU-app proof failing for a
docType/namespace reason is now ruled out.

**Does not establish:** that a *genuine EU-app proof* verifies. Every proof in rung 1
was still minted by 8een's own tooling under a CA 8een controls. The remaining gap —
a real device signature, a real EU issuer chain, a real session transcript — is what
rungs 2–3 close.

---

## Rung 2 — differential oracle (no emulator) — **PENDING**

Run the EU's own ZK verifier (`av-dc-api-backend`, vendored Multipaz) locally and feed
it the *same* fixtures 8een verifies; require both to agree on accept AND reject. An
independent implementation confirming 8een's reading. Still 8een-minted proofs, so not
sufficient alone — but it catches any disagreement without Android.

## Rung 3 — a real EU-app proof (emulator) — **PENDING**

Run the EU app (any flavor — ZK is in all of them), capture a genuine proof **over the
DC API or proximity, never OpenID4VP** (which cannot emit one — `EU-STACK-AUDIT.md` §2),
and verify it with 8een. The rung that actually closes M3's exit criterion. Cost is
unknown (build the app, enrol against the EU test issuer, drive a reader that requests
ZK); to be time-boxed and reported, not guessed.
