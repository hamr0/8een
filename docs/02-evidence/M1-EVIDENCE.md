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

## Tests — 30 green (20 unit, 10 integration against the real service)

**Trust discrimination (PRD §7.1, D5 — the owner's definition of success):**
the **same proof bytes** are **accepted** under the real trust list and
**rejected** under a stranger CA minted at test runtime. Same input, different
anchors, different verdict. The trust list is load-bearing, and it is checked.

| §7.1 negative | Status |
|---|---|
| Proof chained to a cert **not on the list** | **Covered** — stranger-CA test, both directions |
| **Tampered** proof (flipped byte) | **Covered** |
| Wrong **session transcript** | **Covered** |
| **Under-threshold** proof | **Partial** — a valid over-18 proof correctly fails a site asking for over-21 (`claim_absent`). A genuine *underage holder's* proof (`age_over_18 = false`) is unit-tested against the observed wire format, but **no real one exists to test against until M2's test-CA.** Stated, not glossed. |
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
- **Under-threshold is not fully closed** — see the matrix. M2.
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
