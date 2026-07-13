# Stash: 8een — M0 passed, repo published, pre-M1

**Saved:** 2026-07-12 (evening) · **Session scope:** project inception → M0 → public repo

## Where things stand (restore point)

- **Repo:** https://github.com/hamr0/8een — public, Apache-2.0, `main` at
  `6c00d6e`, tree clean. Description + 8 topics set. **Branch protection on
  `main` is LIVE, field-identical to bareagent** (1 approving review, linear
  history, no force-push). Solo repo ⇒ all future merges: feature branch →
  PR → `gh pr merge --admin` on owner's explicit say-so. Never push junk to
  main to "test" protection.
- **PRD v1.0 signed off** (`docs/01-product/8een-prd.md`): identity ("the
  verifier the EU didn't ship"), §7 success = trust discrimination (accepts
  own-cert proofs, rejects wrong-cert/tampered/replayed/underage), §8 NO-GO
  table (10 entries — check before ANY feature talk), §9 owner decisions
  D1–D6 (never stores anything; Android emulator available for M3; public
  GH; vanilla Node; configurable threshold, single-bit output).
- **M0 PASSED** (`poc/M0-EVIDENCE.md` — the full record incl. post-hoc audit
  and retractions). Ladder: M1 (verify module) is NEXT, awaiting owner "go".

## M0 facts a future session must not re-derive

- longfellow-zk builds clean on this Fedora box (clang, deps installed via
  dnf). Upstream pinned `d8ad8f65`; clone+build+fixtures are **gitignored**,
  re-materialized via M0-EVIDENCE step 1 + `poc/patches/0001-...patch` +
  `node poc/make-fixtures.mjs` (regenerates byte-identical, sha-verified).
- Verify ≈ **0.41–0.46 s**; server circuit load = **46.8 s measured** (NOT
  "a few seconds" — that claim was retracted); proving ≈ 42.9 s desktop
  (holder-side cost; phone perf unmeasured, gates M4 UX claims only).
- Reference Go verifier service exists in-repo (`reference/verifier-service`)
  — API shape: POST `{Transcript, ZKDeviceResponseCBOR}` → `{Status, Claims,
  Message}`; `/specs` lists circuit_hash+version; trust anchors = PEM bundle
  (+ VICAL CBOR). Two distinguishable reject layers: deep ZK (code 5,
  ~0.4 s) vs shallow x509/CBOR parse (~3–5 ms).
- **Verifier is stateless: byte-identical replay is ACCEPTED by design.**
  Nonce freshness/single-use is the RP's duty → hard M4 requirement.
- Example proof's cert chain expired 2026-05-07 → POC patch adds
  `ZKVERIFY_FAKE_TIME` (RFC3339; malformed value = loud Fatalf, verified).
  With the var exported, upstream's own `go test ./zk` fails — unset first.
- Test keys decision: **runtime-generated only, never in the tree** (PRD §10;
  mailproof `makeDkimKeypair()` pattern) — resolves AGENT_RULES "Never keys"
  with no exemption needed.

## Key context/sources (for the M5 dossier later)

- Essay: `~/Downloads/four-locks.html` §VIII = the mission statement.
- EU AV app: ZKP demo-build-only; official verifier can't consume ZK; batch
  of 30 = rate-limited linkability (Yivi analysis,
  docs.yivi.app/blog/eu-age-verification-security-analysis). eIDAS 2.0 Art.
  5a(16) mandates unlinkability outcome, not ZKP technique. Blueprint Annex B
  = Longfellow "experimental/should". Precision (from M0): claim is "no
  adoptable drop-in exists + EU stack can't consume", NOT "no verifier
  exists" (Google's Go reference service exists).

## M1 plan (agreed shape, not yet started — owner gates with "go")

Vanilla Node ≥22, `node:test`, zero deps, feature branch. Rewrite (never
reuse) POC into: core subprocess wrapper (gitdone `app/src/ots.js` contract:
timeout/kill/ENOENT/classify-output-not-exit-codes) + pure verdict module
(mailproof `classifier.js` pattern: never-throw `{ok, over_threshold,
reason}` enum) + §7.1 negative matrix incl. wrong-attribute-via-HTTP-path
(only covered in C++ suite so far). Account for 46.8 s circuit load
(preload; health endpoint honest about readiness). Open M1 design Qs: wrap
the Go service vs call libmdoc directly via a thin C shim; where circuits
live (fetch vs vendor).

## Session lessons (candidates for /remember)

- Owner's POC bar applied twice this session: post-hoc audit probes
  (determinism control, rejection-layer attribution) and /code-review found
  8 real findings — incl. my own "few seconds" guess being 10× wrong and a
  security-relevant mislabel ("replay" row). Measure before writing.
- /release on a pre-package repo = honest Blocked verdict + bootstrap
  delivered instead; user accepted that framing ("no papering over it").
