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
  **nothing was added to this repo's dependency tree**). Single take, no edits.
  Post-processing, disclosed in full: a VP9 transcode for size (original VP8 capture
  1,761,586 B → 419,658 B, −76 %, SSIM ≈ 0.985 — content unaltered, verified by re-extracting
  the three verdict frames below), and a poster frame (`replay-demo-poster.jpg`, extracted
  with ffmpeg, losslessly re-compressed 80,193 → 56,153 B).
- **Artifact:** 23.48 s, 419,658 bytes, VP9 WebM, 880×740. Content verified by frame
  extraction at 30/55/90 % — the three verdicts above are each on screen, before and after
  the transcode.
- **Re-record policy:** future recordings **overwrite this same path** (history growth
  accepted, ~0.5 MB/milestone); the commit/date caption in `docs/index.html` changes in the
  same commit — an HTML comment beside the `<video>` element enforces the pairing. Known
  accepted limitation: the player is WebM-only (no MP4 fallback) — pre-2021 Safari
  (< iOS 15 / < macOS 11.3) shows the poster but cannot play; measured cost judged < 1 % of
  2026 traffic, not worth a second megabyte-scale binary in the tree.
- **Code state:** commit `a023174` (v0.4.0, the M4 merge); the dossier branch's own
  changes are docs-only and do not touch the demo path. The caption in the page pins this
  commit and date.

## The review, and what it corrected (2026-07-17)

A medium-effort multi-angle review (8 finders → 3 independent verifiers) ran before
release. All 8 confirmed findings were fixed; the two that mattered most were **content
overclaims on the page itself**, which is exactly where this artifact cannot afford them:

1. The honesty ledger asserted an EU-wide negative ("real issuance exists nowhere in the
   EU yet") that no evidence doc supports — replaced with the audit's own restraint ("not
   answerable from the public repos; we claim neither direction").
2. The issuer-defence conclusion was attributed to Annex B, whose quoted wording is
   Relying-Party-scoped — re-scoped on the page AND corrected in `EU-STACK-AUDIT.md`
   (dated correction note there; the overreach was inherited from it).
3. A page-added "unconditionally" that the verbatim statute quote above it contradicts —
   removed. Three quieter strengthenings ("store anything" vs the spec's "any permanent
   information"; an unsourced "to the issuer"; an in-progress security review described as
   completed) — all restored to source wording.
4. Perf citations made faithful: verify time is now the measured **range** (0.41–0.47 s,
   M0), and the 44–73 s circuit-load range is attributed to **M1**, which measured it
   (M0's single 46.8 s run was a 16-circuit build).
5. The "pinned to a file, a line, and a commit" promise was softened to match what the
   links actually do (the pins live in the evidence log; the page's internal links are
   `blob/main` by choice, so citations always show their current, corrected state).
6. The footer's "zero network requests" regained the word "external" (the page fetches
   its own video/poster).
7. Status surfaces reconciled: README roadmap table (M4/M5 → PASSED + evidence links),
   badge, PRD M5 row (COMPLETE marker; the "proves" column reverted to its signed-off
   wording), CHANGELOG → evidence link added, `package-lock.json` regenerated (was two
   version bumps stale).
8. Video element hardened per measured verification: `preload="none"` (the poster makes
   metadata prefetch pure waste), `width`/`height` (kills the layout shift), `playsinline`
   (iOS), plus the VP9/poster size work above.

One review candidate was **REFUTED** and deliberately kept: "ZK is carried in every build
of the AV app" is measured true over the build space that exists (audit §1) and is the
PRD's own wording; Exhibit V carries the Member-State-production caveat.

## Post-merge steps (owned here — the release is not done until these pass)

1. Enable GitHub Pages: repo **Settings → Pages → Deploy from a branch → `main` / `docs/`**
   (or `gh api -X POST repos/hamr0/8een/pages -f 'source[branch]=main' -f 'source[path]=/docs'`).
2. Verify, then trust: `curl -sI https://hamr0.github.io/8een/ | head -1` → **HTTP 200**,
   and the video plays from the published URL. Until this passes, the README's dossier
   link and the CHANGELOG's "served via GitHub Pages" line are claims awaiting their
   evidence.
3. Note: Pages serves **all** of `docs/` (PRD, evidence, plans) — deliberate; everything
   under `docs/` is already public in the repo, and the dossier links into it.

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
