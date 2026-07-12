# M0 — POC spike evidence log

**Date:** 2026-07-12 · **Machine:** Fedora 44, gcc/clang 22.1.8, 8 cores · **Status: PASSED**

**Riskiest assumption under test:** "The longfellow-zk C++ core builds and runs
on this machine, and a real ZK age proof can be verified — and *rejected* when
it should be."

## What ran (reproducible)

1. `git clone --depth 1 https://github.com/google/longfellow-zk` into `poc/`
   — upstream HEAD `d8ad8f65187c7c364a3c2181ad484bcab03f0ec2`; the POC patch
   is preserved as `poc/patches/0001-zkverify-fake-time.patch` (the clone
   itself is gitignored). Negative fixtures regenerate byte-identically via
   `node poc/make-fixtures.mjs` (verified: sha256 of regenerated files
   matches the originals used in the runs below)
2. Deps: `dnf install clang libzstd-devel openssl-devel google-benchmark-devel gtest-devel libpfm-devel golang`
3. `CXX=clang++ cmake -D CMAKE_BUILD_TYPE=Release -S lib -B build` → `make -j8 install` — clean build, exit 0
4. C++ test suite `build/circuits/mdoc/mdoc_zk_test`: **10/10 passed** (110.5 s total)
5. Built the repo's Go reference verifier service (`reference/verifier-service/server`, links `libmdoc_static.a` via cgo) and ran it with the repo's 16 pre-built circuits + AAMVA VICAL trust list (22 issuer certs)
6. POSTed the repo's own example proof (`examples/post1.json` — an uncrafted, real Google-Wallet-produced `age_over_18` proof, 324,306-byte CBOR blob, OpenID4VP session transcript) plus two fixtures we derived from it

## Results (observed, not asserted)

| Case | Input | Expected | Observed | Time |
|---|---|---|---|---|
| 1 valid | repo's post1.json | accept | `{"Status":true,"Claims":[age_over_18=true]}` | **0.458 s** |
| 2 tampered | byte 162153 of proof XOR 0xFF | reject | `{"Status":false,...,"verification failure: return code 5"}` | 0.413 s |
| 3 transcript-tamper | valid proof, last transcript byte flipped | reject | `{"Status":false,...}` | 0.408 s |
| 4 stale chain | post1.json against real clock | reject | `x509: certificate has expired` (pre-proof, HTTP 400) | 0.005 s |

C++ suite highlights (independent of the Go service):
- `MdocZKTest.one_claim` — full prover→verifier roundtrip: **42.9 s** (proving dominates; a holder-side cost, not our component's. Phone proving performance was NOT measured here and is an open input to M4's UX assumptions)
- `MdocZKTest.wrong_witness` — prover refuses a lying witness: 2.8 s
- `MdocZKTest.bad_proofs` — verifier rejects corrupted proofs: 16.1 s

## Can-this-test-fail check

- Cases 2/3 differ from case 1 by exactly one byte each → the variable is wired in.
- Case 4 occurred *unplanned* (see deviation) — a genuine negative from real, uncrafted data.
- The one_claim/wrong_witness pair shows both verdict directions in the C++ path too.

## Deviations / honest notes

- **The repo's example proof carries a cert chain that expired 2026-05-07.**
  The service (correctly) rejects on chain validity before ZK verification.
  For cases 1–3 we patched the reference server with a POC-only
  `ZKVERIFY_FAKE_TIME` env override pinning x509 verification time to
  2026-04-01 (a ~10-line block plus two imports in `server/zk/cbor.go`,
  preserved as `poc/patches/0001-zkverify-fake-time.patch`). **The honest
  guarantee is not "real builds never get this switch" — nothing enforces
  that; the guarantee is that this patched clone is throwaway and M1 is a
  rewrite that never carries the switch.** A malformed value fails loudly
  (log.Fatalf, verified by run). Known interaction: with the var exported,
  the package's own `go test` fails (its test certs mint NotBefore=now) —
  unset it before testing. M2's test-CA will mint non-expired fixtures,
  removing the need entirely.
- Verify time (~0.41–0.46 s) includes HTTP + CBOR decode + chain check + ZK
  verify, single-shot, no warm-up discipline — good enough for M0, proper
  benchmarking belongs to M1.
- Circuit files load at server start: **measured 46.8 s** on this machine
  (first claim of "a few seconds" was wrong by an order of magnitude and is
  retracted — the number above is timed). Startup cost, not per-request; M1
  must account for it (preload/cache, health endpoint honest about readiness).

## Findings that reshape M1+

1. **A Go reference verifier service exists in-repo** (Docker/Go/cgo, AAMVA
   US-DMV trust list, no middleware, no npm story). 8een's niche is confirmed
   but must be stated precisely: not "no verifier exists" — "no adoptable
   drop-in exists, and the EU's official stack still can't consume ZK proofs."
   Dossier wording updated accordingly.
2. **The verify API surface is small and known:** `{Transcript,
   ZKDeviceResponseCBOR}` → `{Status, Claims, Message}`; C API is
   `run_mdoc_verifier` + `RequestedAttribute` + circuit bytes keyed by hash
   (`/specs` lists `circuit_hash` + `zk_spec_version`).
3. **Trust anchors are a PEM bundle + VICAL CBOR** — M1's trust-list config is
   a solved shape; EU anchors slot in the same way.
4. **Proving is expensive (42.9 s in the desktop test run; thread usage not
   examined), verifying is cheap (<0.5 s)** — the asymmetry favors the
   verifier side. What real phones achieve was not measured here; it gates
   M4's UX claims, not M1–M2.

## Post-hoc audit (owner challenge: "real POC, no fit-to-pass, negatives?")

Extra probes run 2026-07-12, same server, same fake-time condition:

| Probe | Input | Observed | Time | What it proves |
|---|---|---|---|---|
| Control ×2 | identical valid request, twice | `Status:true` both | 0.469 s / 0.452 s | Determinism; and **statelessness — a byte-identical replay IS accepted** |
| Flip byte 50 | envelope region | `Status:false`, code 5 | **0.401 s** | Full verify time spent → the **ZK math itself** rejected |
| Flip byte len−500 | cert region | HTTP 400 `x509: malformed extension` | **0.003 s** | Shallow parse-layer rejection, distinguishable |

**Rejection-layer attribution resolved:** two distinct reject layers exist and
are distinguishable by timing + message. The original CASE2 (byte 162153,
code 5, 0.41 s) and CASE3 (transcript flip, code 5, 0.41 s) both spent full
verify time → both were **deep ZK-verification failures**, not parse errors.
CASE3 additionally proves the session transcript participates in the proof
relation (binding is cryptographic, not envelope decoration).

**Fit-to-pass check:** the passing datum is uncrafted (Google-Wallet-produced;
we hold no signing keys and *cannot* author a passing proof). All negatives
are one-byte deltas of real data — the harness cannot have been shaped around
a desired result.

**Material finding for M4 (promoted to a requirement):** the verifier is
stateless by design — replay defense is entirely the relying party's duty.
8een's gate MUST issue a fresh transcript/nonce per session and treat it as
single-use. This is now evidence, not assumption.

**Named residual gaps (not fit-to-pass — just not coverable yet):**
- "under-threshold proof rejected" needs a credential we mint → M2 (test-CA).
- "wrong attribute claimed" was exercised only in the C++ suite
  (`MdocZKTest.attr_mismatch`, passed), not the HTTP path → M1 test matrix.

## Verdict

The riskiest assumption is dead: the core builds, verifies a real proof,
and — the half that matters — **says no to a tampered proof, a tampered
session transcript, and a stale trust chain.** (It says yes to a
byte-identical replay — by design; freshness is the relying party's duty,
now an M4 requirement.) M0 graduates. Per AGENT_RULES, nothing in `poc/`
ships; M1 rewrites.
