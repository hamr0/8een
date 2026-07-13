# 8een — Product Requirements Document (PRD)

**Status:** `v1.0` — signed off 2026-07-12 ("go"). **M0 PASSED** same day
(evidence: `../../poc/M0-EVIDENCE.md` — real `age_over_18` proof verified in
0.46 s; tampered proof byte, tampered session transcript, and stale cert
chain all rejected. Byte-identical replay is ACCEPTED by design — the
verifier is stateless; per-session nonce freshness is the relying party's
duty and is a hard M4 requirement). Precision note from M0: longfellow-zk ships a Go reference
verifier *service* (Docker/cgo, US-DMV trust list) — so the claim is not "no
verifier exists" but "no adoptable drop-in exists, and the EU's official
stack still cannot consume ZK proofs." **M1 PASSED** (2026-07-13, v0.1.0 —
[evidence](../02-evidence/M1-EVIDENCE.md)); M2 (test-CA + prover CLI) is next.
**Owner:** hamr0
**Last updated:** 2026-07-12

> **For future Claude:** This PRD is the canonical source of truth for *what
> 8een is and what it deliberately is not*. §8 (the NO-GO table) is the
> single biggest scope-creep guard — every entry was discussed and rejected
> with reasoning; check it before entertaining any feature request. The PRD
> wins on **intent**; the SPEC (when it lands) wins on **mechanism**. Design
> decisions get logged in `../03-logs/decisions-log.md` — don't re-litigate
> them unless the owner explicitly asks. **Dev standards live outside this repo**
> and are not vendored into it: `~/Documents/PycharmProjects/hamr0/AGENT_RULES.md`
> (POC-first, vanilla→stdlib→external, vetted crypto always, Testing Trophy) and
> `~/Documents/PycharmProjects/hamr0/LIBRARY_CONVENTIONS.md` (JS library shape,
> JSDoc → `.d.ts` with no drift, the doc set, CI, OIDC publishing, agent scratch
> out of git). Both bind this project; where they disagree with each other,
> **AGENT_RULES wins**, and where either disagrees with this PRD on *intent*, the
> PRD wins. The owner gates every milestone with an explicit "go" — never proceed
> to the next rung without it.

---

## 1. What 8een is

**8een is the verifier the EU didn't ship.**

A small, open, stateless component that checks a zero-knowledge age proof and
answers exactly one bit — `over_threshold: true/false` — while learning
nothing else about the person. No name, no birthdate, no document, no
identifier crosses the boundary. Proofs are fresh per presentation and
mathematically unlinkable: two sites comparing notes see two strangers.

It does one thing, does it well, and holds nothing: no storage, no accounts,
no telemetry, no UI beyond a drop-in gate, no runtime calls to anyone. A site
integrates it in one config block and forgets it.

The cryptography is **never ours**: proofs are generated and verified by
[google/longfellow-zk](https://github.com/google/longfellow-zk) (Apache-2.0,
IETF draft `draft-google-cfrg-libzk`, under independent security review) —
the same library the EU's own age-verification app uses in its demo build.
8een is the wrapper, the trust-anchor handling, the tests, the drop-in, and
the documentation that make it adoptable.

## 2. The problem it solves (and the claim it refutes)

Age-verification mandates are being implemented across the EU on the premise
that *to check a fact about a person you must collect the person*. The EU's
own architecture concedes this is false — and then declines to implement the
fix:

- **The statute** — eIDAS 2.0 Art. 5a(16) — mandates the unlinkability
  *outcome* but not the ZKP *technique*.
- **The spec** — the age-verification blueprint's Annex B — designates the
  Longfellow scheme, but as an optional "experimental feature"
  (should-implement, not must-implement).
- **The shipped code** — the EU AV app enables ZK proofs **only in the demo
  build**; no production build does. The official verifier stack cannot
  consume a ZK proof at all (it accepts only plain mdoc / SD-JWT VC, where
  the relying party sees the actual credential). The production privacy story
  is batch issuance of 30 single-use credentials — rate-limited linkability,
  not unlinkability (issuer collusion links; exhaustion forces passport
  re-scan). (Source: Yivi security analysis, 2026.)

**The refutation is an artifact, not an argument:** working, open code
proving the one-bit unlinkable version is real and cheap to adopt — so that
shipping the linkable version becomes the expensive, embarrassing,
indefensible option. The wallet side already exists (the EU app's own demo
build produces these proofs). The missing half is the verifier. 8een is the
missing half.

## 3. Who it's for

A **public open-source component** (GitHub `hamr0`, Apache-2.0, public from
day one — including dead ends; built-in-the-open is part of the refutation).

- **Primary adopter:** a developer adding an age gate to an existing site
  who would otherwise integrate a surveillance vendor's SDK.
- **Secondary audience:** policy/advocacy readers of the dossier (§6 M5),
  which cites the working demo instead of a diagram.

## 4. How it works (mechanism, plain)

Three actors; 8een is only the third:

1. **Issuer** (government/bank) — signs a credential (ISO mdoc containing a
   birthdate) onto the holder's phone, once. *Exists; never ours.*
2. **Holder** (wallet on the phone) — per visit, generates a fresh ZK proof:
   "a validly-signed credential behind this proof has
   `birthdate ≤ today − N years`", bound to the site's fresh nonce. The
   credential never leaves the phone; the proof shares no linkable pattern
   with any other proof. *Exists (EU app demo build); we build only a test
   prover for fixtures.*
3. **Verifier** (8een, site-side) — takes proof + issuer trust anchor +
   nonce, runs the longfellow verifier, returns the single bit. Stateless;
   amnesia after every check.

The verify flow a visitor sees: one button → wallet prompt showing exactly
what's disclosed ("over 18: yes/no") → one tap → in. No ID upload, no
account, no third party.

## 5. Scope — the components

| Component | Responsibility |
|---|---|
| **core wrapper** | Drive the longfellow-zk C++ binaries via subprocess (timeout/kill, ENOENT handling, output classified — never exit-code-trusted). Pattern: gitdone `app/src/ots.js`. |
| **verify** | Pure verdict module: proof + trust anchors + nonce + threshold in → `{ok, over_threshold, reason}` out. Never throws; machine-readable reason enum. Pattern: mailproof `classifier.js`. |
| **test-CA + prover CLI** | Mint synthetic mdocs under a test CA whose keypair is **generated fresh at test runtime — never written to the repo** (mailproof `makeDkimKeypair()` pattern); produce valid/tampered/underage/stale-nonce fixture proofs so the full loop runs offline with zero EU-app dependency. |
| **gate** | HTTP verify endpoint + drop-in middleware (`age: 18` config block) + session cookie. Vanilla `node:http`; no framework. |
| **demo site** | A live age-gated page proving the loop end to end. Responsive (mobile-first, per AGENT_RULES). |
| **dossier** | The refutation page: statute → spec → shipped default → working demo, every claim measured by our code or cited to a primary source. |

**Stack:** vanilla Node ≥ 22, `node:test`, zero frameworks, C++ core via
subprocess. Target runtime dep count: 0 (stdlib + the longfellow binary).
We author **zero cryptography**.

**Threshold:** configurable per site (`age: 15|16|18|21|…`) — the age is the
site's *question*, never the visitor's *answer*. Output is always the single
bit; the API physically cannot return an age.

## 6. Milestone ladder (owner gates each rung with "go")

| Rung | Deliverable | Riskiest assumption it kills |
|---|---|---|
| **M0 — POC spike** | Build longfellow-zk on Fedora; run its prover+verifier on its own sample credentials; observe valid→accept AND tampered→reject; **measure** verify time. Evidence log, not prose. Lives in `poc/`, never shipped. | "The C++ core builds and runs here at all." If M0 fails, everything re-plans. |
| **M1 — verify module** | The pure verdict module + core wrapper, behavior-level tests incl. all §7 negatives. | "The binary's output can be classified into a trustworthy one-bit verdict." |
| **M2 — full local loop** | Test-CA + prover CLI; end-to-end offline: mint → prove → verify. Unlinkability transcript check (§7.3). | "We can generate spec-conformant credentials/proofs ourselves." |
| **M3 — EU interop** | Verify a proof produced by the EU AV app's demo build (Android, driven via baremobile/emulator). | "The EU app's proofs are format-compatible with upstream longfellow." **Fallback if brittle:** interop vs. longfellow's reference prover; EU-app interop documented as pending in the dossier. |
| **M4 — the gate** | Endpoint + middleware + demo site. All AGENT_RULES invariants apply (rate-limiting, unhappy paths, no `0.0.0.0`). Probe-style check: middleware consumes only the verify module's public surface. | "A mid-size site can adopt this without thinking." |
| **M5 — dossier** | The refutation page with the live demo embedded. | "The argument survives being written down with citations." |

POC graduates by **rewriting, never shipping** (AGENT_RULES).

## 7. Success criteria (the tests that define "works")

### 7.1 Primary — trust discrimination (owner's definition)
The verifier **accepts** a valid proof from a credential signed by an issuer
**on the configured trust list**, and **rejects**:
- a proof chained to a cert NOT on the list (self-signed / wrong issuer /
  our own test-CA when untrusted)
- a tampered proof (any flipped byte)
- a replayed proof (wrong/stale nonce)
- an under-threshold proof

Every line above is an executable test by M2 — the negatives especially,
since "rejects others" is the half that usually goes untested.

### 7.2 Secondary — adoption cost
A developer integrates the gate into an existing vanilla-Node/Express site in
**under 30 minutes using only the README**. Timed with a real run before M4
closes, not asserted.

### 7.3 Unlinkability — honest split
- **Tested by us:** two presentations of the same credential yield
  verifier-side transcripts sharing no common identifier (black-box check).
- **Cited, not claimed:** full cryptographic unlinkability rests on the
  scheme's own security analysis (IETF draft + published reviews). The
  dossier says exactly which is which. No overselling.

## 8. NO-GO table (discussed and rejected — do not reopen silently)

| # | NO-GO | Why |
|---|---|---|
| 1 | **Fixing issuance integrity** (the EU app trusts a client-reported birthdate at enrollment — Yivi's finding) | Issuer-side flaw; out of our trust boundary. Pretending the verifier fixes it would be dishonest. Dossier states it plainly as out of scope. |
| 2 | **Being an issuer** (real credentials for real people) | We'd become custodian of identity — the exact thing 8een exists to make unnecessary. Test-CA is fixtures-only, loudly marked. |
| 3 | **Hosted verification service** (accounts, logs, telemetry, per-check fees) | Capability without custody. 8een is a component others run. A hosted *demo* that stores nothing is permitted (§9 A1). |
| 4 | **Building a wallet/holder app** | The EU app and eIDAS wallets exist; duplicating them dilutes the refutation ("the missing half was the verifier"). Test prover is CLI fixtures, not a wallet. |
| 5 | **Other proof systems in v1** (BBS+, SD-JWT ZK, Crescent…) | The refutation must hit the EU's own chosen stack (Longfellow over mdoc), not a nicer parallel universe. Revisit only after M5. |
| 6 | **Age estimation / biometrics / face scans** | The premise 8een refutes. Never. |
| 7 | **Storing anything about visitors** (proofs, transcripts, IPs beyond transient rate-limit state) | Statelessness *is* the security argument: nothing to breach, subpoena, or sell. |
| 8 | **Authoring cryptography** (own circuits, own signature checks, "small" crypto utilities) | Vetted-library rule is absolute here. We wrap longfellow-zk; we never reimplement any part of it. |
| 9 | **Frameworks / dependency creep** | Vanilla `node:http` + stdlib. Every dep is attack surface in a security component; target is 0 runtime deps. |
| 10 | **A revocation/identity registry** | Any server-side per-user state rebuilds the national identifier through the back door. |

## 9. Resolved interview decisions (owner-confirmed 2026-07-12)

| # | Decision |
|---|---|
| D1 | **The custody line is "never stores anything."** A hosted demo instance is permitted if and only if it stores nothing — no logs of proofs, no accounts, no telemetry; transient rate-limit state only. |
| D2 | **Android emulator is available** for M3 (EU app demo build, driven via baremobile). Fallback if interop proves brittle: longfellow's reference prover, EU-app interop marked pending in the dossier. |
| D3 | **Public GitHub from day one, Apache-2.0** (see §10). |
| D4 | **Stack is vanilla Node** — owner preference for simplicity/speed/vanilla, confirmed viable since the C++ core is subprocess-driven either way. |
| D5 | **Success = trust discrimination** (§7.1, owner's wording: "works on own cert and not others"). |
| D6 | **Threshold configurable** (the age in "over N"); output remains a single bit. |

## 10. Naming & publishing

- **Name:** the project is `8een` (= eighteen). **The npm package is `zk8een`.**
  npm permanently refuses the bare name: its typo-squat similarity filter rejects
  `8een` as too close to `open`/`when`/`leven`/`levn`, for everyone, with no appeal
  (verified 2026-07-13 — a publish attempt returns 403). So the name was never at
  risk of being taken; it simply cannot exist. Scoping (`@hamr0/8een`) was the
  alternative and was rejected: an unscoped name is the one people type.
- **Publishing:** OIDC trusted publishing via GitHub Actions (`publish.yml`,
  manual `workflow_dispatch`) — no npm token ever. `zk8een@0.0.0` is an inert,
  deprecated placeholder that exists only because npm requires a package to exist
  before a trusted publisher can be attached to it. **Nothing real is published
  until the longfellow binary problem is solved** (see NO-GO #9 / M2): `0.1.0`
  drives a verifier binary it does not ship and cannot verify a single proof. A
  correct publish pipeline is not clearance to use it.
- **License:** Apache-2.0 (matches longfellow-zk).
- **Repo:** public on GitHub under `hamr0` from day one. **No key material
  ever enters the tree** — AGENT_RULES' "never write keys into the tree" has
  no test-fixture exemption and none is needed: the test-CA generates its
  keypair fresh at test runtime, in memory or in a temp dir, per run
  (mailproof's `makeDkimKeypair()` pattern). Committed fixtures may contain
  only public artifacts (certs, proofs); anything with a private half is
  regenerated, never stored.
