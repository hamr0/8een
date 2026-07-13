# CLAUDE.md — agent doctrine for 8een

Repo-only. Never ships (not in `files`). Adopters read `README.md` +
`8een.context.md`; this is for whoever is *building* the thing.

**Parent standards, which this does not repeat:**
`~/Documents/PycharmProjects/hamr0/AGENT_RULES.md` (POC-first, dependency
hierarchy, simple-over-clever, security invariants, testing trophy) and
`LIBRARY_CONVENTIONS.md` (JS library shape, JSDoc → `.d.ts` with no drift, the
doc set, CI). When anything here seems to disagree with AGENT_RULES, **AGENT_RULES
wins.**

## The one invariant

**`ok` (did we get an answer) is separate from `over_threshold` (what the answer
was), and `ok:false` ⇒ `over_threshold:null`, never `false`.**

A verifier that cannot verify is broken, and a broken verifier reporting "no"
would turn away every legitimate adult while sounding exactly like a working one.
8een says *"I cannot verify."* It never says *"you are underage."* If a change
makes those two collapse into each other, the change is wrong, however elegant.

## The failure mode this project keeps finding

Every serious bug found so far is the same shape: **a security-critical resource
silently partially loads, and the verifier then rejects valid proofs
confidently.** It has turned up four times, in four different places:

1. **Zero circuits** — `/healthz` says `ok`, `/specs` lists 12 specs it doesn't
   have, valid proofs rejected in 7 ms.
2. **Partial circuits** — upstream skips a bad circuit and carries on; 12 of 17
   loaded, port open, "ready".
3. **Truncated trust list** — upstream's PEM loader breaks out of its parse loop
   and *returns success*: 19 certificates in the file, 17 loaded, no error.
4. **The `Claims` echo** — a *rejected* proof still reports `age_over_18: true`
   from its unverified envelope.

**So: never trust a health check, a config value, or a status field. Verify from
the child's own log what actually loaded, and refuse to serve if it isn't what you
asked for.** That is why readiness reads the log rather than pinging `/healthz`.
When you add a new dependency on some loaded resource, assume it can silently
half-load, and prove it can't.

## Most-litigated refusals

- **We never reimplement any part of longfellow** (PRD NO-GO #8). Not the CBOR
  parsing, not the certificate chain validation, not "a small crypto utility".
  If the answer is "write our own X" and X is cryptographic, the answer is wrong.
- **We store nothing** (NO-GO #7). Statelessness is the security argument, not a
  limitation.
- **Zero runtime dependencies** (NO-GO #9). Every dep is attack surface in a
  security component.
- **Replay is M4's problem, not M1's.** The verifier is stateless by design. Do
  not "fix" it in the verify module, and never describe 8een as replay-safe.
  There is a passing test asserting the replay is *accepted*; it exists so nobody
  forgets. Do not delete it because it looks like a failing expectation.
- **No test keys in the tree** (PRD §10). Generate at runtime, temp dirs only.

## Where the reasoning lives

- `docs/01-product/8een-prd.md` — the NO-GO table (§8) and owner decisions (§9).
  **Check §8 before proposing any feature.**
- `docs/02-evidence/M0-EVIDENCE.md`, `docs/02-evidence/M1-EVIDENCE.md` — every
  measurement, deviation, and retraction. Numbers here were measured, not guessed;
  if you need a number, take it from these, and if you produce a new one, measure it.
- `8een.context.md` — the adopter contract. If you change the public API, this
  changes too, in the same commit.

## Working rules specific to this repo

- **`main` is protected**: feature branch → PR → `gh pr merge --admin`, and only on
  the owner's explicit say-so. Never push to `main`.
- **The integration suite needs the POC clone** (`poc/M0-EVIDENCE.md` step 1) and
  takes minutes. It skips cleanly when the clone is absent. `npm test` is the fast
  gate; `npm run test:integration` is the real one. Do not claim the negative
  matrix passes without running the latter.
- **The accept path runs under a pinned verification clock** (`ZKVERIFY_FAKE_TIME`,
  injected by the test harness only, never in `src/`). The one real proof we have
  expired 2026-05-07. M2's test-CA removes the scaffolding.
- **Measure before you write a number.** "A few seconds" was wrong by 10× once
  already and had to be retracted in writing.
