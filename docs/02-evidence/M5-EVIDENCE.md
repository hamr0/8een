# M5 evidence — the dossier

**Date:** 2026-07-16 · **Scope:** the refutation page (`docs/index.html`) + the recorded
demo it embeds (`docs/assets/`). **Amended exit criterion (PRD D9):** GitHub-hosted page,
recorded demo, no live tier.

## What was built

- **`docs/index.html`** — the dossier: six exhibits (statute → spec → shipped default →
  the missing half → corrections → honesty ledger). Static HTML, **zero JavaScript, zero
  external requests** — no fonts, no analytics, nothing fetched from anyone; a privacy
  dossier that phones home would refute itself. Light (paper) and dark (archival) themes
  via `prefers-color-scheme`; system font stacks only.
- **`docs/assets/replay-demo.webm`** — the demo, recorded unedited (see below).
- **`docs/.nojekyll`** — serve the tree as-is when GitHub Pages is enabled (from `/docs`
  on `main`; enabling Pages is a repo-settings step done at merge time).
- Every content claim is lifted from an existing evidence doc — `EU-STACK-AUDIT.md`
  (exhibits I–III and the four retractions in exhibit V), `M0/M2/M3/M4-EVIDENCE.md`
  (every measured number in exhibit IV) — **no new claims were authored for the page.**

## Verification record

| Check | How | Result |
|---|---|---|
| External citations resolve | `curl -L` each of the 8 primary-source URLs (EUR-Lex, IETF datatracker, longfellow-zk, 5 EU repos) | 8/8 HTTP 200 |
| Internal links point at tracked files | `git ls-tree origin/main` on all 9 referenced repo paths | 9/9 tracked |
| Desktop render, dark | served over local HTTP, screenshotted top-to-bottom | clean |
| Desktop render, light (paper) | dark-mode CSS block stripped in a scratch copy, re-rendered | clean |
| Mobile render (390 px, full page) | headless Chromium full-height capture, inspected in slices | clean after 2 fixes (below) |
| Wide-content containment | ledger table / code blocks scroll inside their own `overflow-x` wrappers | no body-level horizontal scroll |
| Video decodes in-page | player shows 0:23 duration from `preload="metadata"` | plays |

**Two real bugs found by looking at renders, not source** (the project's standing lesson,
again):

1. The Art. 5a(16)(b) `[sic]` bracket was tautological — *“unlikeability [sic — the
   published OJ text reads ‘unlikeability’]”* explained nothing. Now states the intended
   word ("unlinkability").
2. The inline code token `ZkResponsePolicy.FallbackToFullDisclosure` cannot line-break and
   clipped off-screen at 390 px. Fixed with `overflow-wrap: anywhere` on `code`.

## The recording — provenance

- **What it shows:** session 1 proof accepted (`✅ over 18`, HTTP 200,
  `reason:"verified"`) → the byte-identical proof re-POSTed and refused (`⛔ cannot
  verify`, HTTP 503, `ok:false, over_threshold:null, reason:"replay_detected"`) → a fresh
  session accepted again (HTTP 200). The pool is deliberately **not** exhausted on camera:
  pool exhaustion is a demo-server artifact, not the property under proof.
- **How:** `demo/server.js` booted for real on this host (3 proofs minted by `mkfixture`,
  each self-verified; 17 circuits loaded, gate ready) and driven by a scripted headless
  browser (playwright-core 1.58.2 borrowed from a sibling checkout + system Chromium —
  **nothing was added to this repo's dependency tree**). Single take, no edits; the only
  post-processing is a poster frame (`replay-demo-poster.jpg`) extracted with ffmpeg.
- **Artifact:** 23.48 s, 1,761,586 bytes, VP8 WebM, 880×740. Content verified by frame
  extraction at 30/55/90 % — the three verdicts above are each on screen.
- **Code state:** commit `a023174` (v0.4.0, the M4 merge); the dossier branch's own
  changes are docs-only and do not touch the demo path. The caption in the page pins this
  commit and date.

## What M5 deliberately does NOT claim

- **No live instance.** D9 dropped the live tier; D1's hosted-demo permission stands
  unused. The "working demo" claim rests on the recording plus the public, reproducible
  repo (`node demo/server.js` after the documented build).
- **The on-phone gap stays open** — and is stated in the page's own ledger (exhibit VI):
  no proof from a real phone has ever reached this verifier, and with no public live
  endpoint, none can yet. This caveat has been carried since M3 and must keep being
  carried, not eroded.
- **The wallet in the recording is the stub** (pre-minted pool under a runtime test CA) —
  said in the caption itself, not buried.
