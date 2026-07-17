# EU stack audit — what the blueprint actually ships

**Date:** 2026-07-14 · **Method:** adversarial refutation against upstream source
and the live EU deployment. **Status: two 8een claims RETRACTED, thesis restated.**

This log exists because 8een's public argument was carrying two statements that are
**false**, and one that was **unfair to the EU**. They had been inherited from a
secondary source and from a reading of the EU repos that was a year stale, and they
were never checked. They are checked now.

Every claim below is pinned to a file, a line, and a commit. Nothing here is
paraphrased from a blog post. Where a claim survived, it survived an attempt to
kill it; where it died, the retraction is written down rather than quietly fixed.

**Method note.** Each claim was handed to an independent check whose instructions
were to *refute* it and to default to REFUTED on thin evidence — not to confirm it.
Three of the four claims 8een went in with came back altered. That is the point:
this project's recurring failure is a confident claim with nothing behind it, and
the behavioural version of that bug is the same bug.

## Sources, pinned

| Repo | Commit | Date |
|---|---|---|
| `eu-digital-identity-wallet/av-app-android-wallet-ui` | `f8fde51` | 2026-07-12 |
| `eu-digital-identity-wallet/eudi-srv-web-verifier-endpoint-23220-4-kt` | `de66a3e` | 2026-07-10 |
| `eu-digital-identity-wallet/av-dc-api-backend` | `2418006` | 2026-07-01 |
| `eu-digital-identity-wallet/av-doc-technical-specification` | `5eb8a03` (rel. 1.0.9) | 2026-03-19 |
| `eudi-lib-android-wallet-core` | v0.28.1 | (dep of the app) |
| `eudi-lib-android-iso18013-data-transfer` | v0.14.0 (`16998d4`) | (dep of the above) |

## 1. RETRACTED — "the EU app enables ZK proofs only in the demo build"

**Was in:** `README.md` (pitch + §Why), `PRD §2`. **Verdict: FALSE.**

`AppFlavor.kt:36-37` defines exactly two flavors, `Dev` and `Demo`. Both
`core-logic/src/{dev,demo}/java/.../WalletCoreConfigImpl.kt:81-85` call
`configureZkp(LongfellowZkSystemRepository(circuits = LongfellowCircuits.get(context)).build())`.
The two files differ only by a trailing comma and two comments. Neither is dead
code: `core-logic/src/main/` contains no `WalletCoreConfigImpl`, so each variant
must source its only copy from its flavor set. There is no build-type, remote-config,
or feature-toggle gate on ZK anywhere in the app.

**Caveat we must not overstate in the other direction:** this repo contains no
Member State *production* build at all — only `Dev` and `Demo`. "No production build
ships ZK" is therefore *unanswerable here*, not refuted. We say neither.

### 1a. The correction that matters more than the retraction

**Configuring a ZK system is not emitting a ZK proof. The verifier decides.**

Per-presentation, per-document, *all* of the following must hold before a real proof
is produced (`eudi-lib-android-iso18013-data-transfer` v0.14.0):

1. The reader's `DeviceRequest` carries `zkRequest.systemSpecs`
   (`DeviceRequestProcessor.kt:185`). **If the verifier does not ask, there is no
   proof.** `ZkpSupport.kt:54-55` returns null; `ProcessedDeviceRequest.kt:108-114`
   then emits a **plain, fully-disclosed mdoc**.
2. A loaded circuit matches the requested claims (`ZkpSupport.kt:93-97`).
3. Proof generation succeeds (`ProcessedDeviceRequest.kt:180`).

## 2. FINDING (new) — the OpenID4VP path cannot emit a ZK proof at all

In wallet-core v0.28.1, `EudiWallet.kt:435-443` constructs `OpenId4VpManager` with
`DcqlRequestProcessor(documentManager, readerTrustStore)` — and
`DcqlRequestProcessor` (`transfer/openId4vp/dcql/DcqlRequestProcessor.kt:63-66`) takes
**no `zkSystemRepository` parameter whatsoever**. Only `DCAPIRequestProcessor`
(`EudiWallet.kt:455`) and the proximity `TransferManager` (`:557`) receive it.

**OpenID4VP is the protocol a website uses.** On that path the EU wallet never emits
a Longfellow proof, regardless of what any verifier requests. ZK is reachable only
over the browser Digital Credentials API or ISO 18013-5 proximity (NFC/BLE).

## 3. FINDING (new) — on ZK failure the wallet silently discloses the whole document

`ProcessedDeviceRequest.kt:179-199` wraps proof generation in `runCatching`. On
failure, `ZkResponsePolicy.FallbackToFullDisclosure` → `addDocumentResponse(...)`:
**the full mdoc is disclosed instead.** That policy is the default
(`ProcessedDeviceRequest.kt:61`, `DeviceRequestProcessor.kt:55`,
`TransferManagerImpl.kt:334`), and **neither the AV app nor wallet-core ever sets it**
— grep for `zkResponsePolicy` across both returns nothing.

The library's own KDoc says of the safe setting `Strict`: *"Recommended for production
use to prevent unintended full document disclosure"* (`zkp/ZkResponsePolicy.kt:25-28`),
and of the default: *"current default for backwards compatibility and will be changed
to `Strict` in a future release"* (`:31-34`).

This is **8een's own recurring failure shape, in someone else's code**: a
security-critical resource fails, the status stays green, and the system silently does
the *wrong* thing — here, disclosing everything rather than proving nothing. It is the
strongest single piece of evidence the project has.

## 4. CONFIRMED — the flagship verifier cannot verify a ZK proof

`eudi-srv-web-verifier-endpoint-23220-4-kt` @ `de66a3e` has **no ZK support of any kind.**
This survived a deliberate attempt to break it:

- The only keyword hits are **coincidental base64**: the letters `ZKp` inside
  `security/pgp-key.txt:19`, and `ZKP` inside a base64 blob in
  `src/test/resources/06-pidPlusMdl-vpToken.json`. Both decode to a plain mdoc
  `DeviceResponse` (`{version: "1.0", documents: …}`); the bytes `ZKP` are absent from
  the decoded payload and exist only in the base64 alphabet.
- **No ZK arrives via a dependency.** The verification deps are
  `waltid-mdoc-credentials-jvm`, `eudi-lib-jvm-sdjwt-kt`, `cose-java`, BouncyCastle,
  Tink. No `multipaz`, no `longfellow`, nothing ZK in the version catalog.
- **The format dispatch is closed.**
  `ValidateSdJwtVcOrMsoMdocVerifiablePresentation.kt:63-95` is a `when` over
  `{SdJwtVc, MsoMdoc, else -> throw IllegalArgumentException("unsupported format")}`.
  And format is **not wallet-controlled**: `PostWalletResponse.kt:155-156` derives it
  from the verifier's own DCQL query, gated at `:168`. A wallet cannot smuggle a ZK
  format in.
- **Nothing is in flight.** `git log --all --grep` for `zk|zero.knowledge|longfellow|multipaz`
  → **zero commits in the entire history.** Four open PRs, none ZK.

## 5. CORRECTED — the one server-side ZK verifier is vendored Multipaz, and it is LIVE

8een previously implied no ZK verifier existed. **One does.** Two 8een framings of it
were also wrong and are retracted here.

**It is a vendored copy of Multipaz, and the EU wrote none of the cryptography.**
`av-dc-api-backend` is not a GitHub fork (`"fork": false`) but is one in substance:
`settings.gradle.kts:1` reads `rootProject.name = "MultipazProject"`, `README.md:1`
is verbatim `# Multipaz`, and `648a049a` is a literal
`Merge remote-tracking branch 'upstream/main'`. Authorship: Multipaz maintainers 693
commits; the EU developer **11**, of which three are features (~370 lines: trust-anchor
PEMs, an age-verification doctype, CORS/SKI). **No EU commit touches
`multipaz-longfellow`.** The commit titled *"feat: implement zkp"* (`5e7b3fa0`, 27+/13−)
implements no ZKP — it is a Gradle catalog entry, a CORS block, and two one-line calls.

**RETRACTED — "browser-only, behind a Chrome flag."** False twice over. It is a plain
HTTP server (`ApplicationExt.kt:24-28` mounts `get`/`post` on `/verifier/{command}`),
and `verifyProof()` (`verifier.kt:1734`) sits in the **shared** `handleGetDataMdoc`,
reached from all three transports — DC API (`:805`), OpenID4VP (`:1452`), and ISO
18013-5 proximity (`:771`). Confirmed **against the live deployment with curl**: every
transport routes and reaches its handler (schema errors, not 404s), against a clean
control (`bogusCommand` → `400 Unknown command`). And the
`chrome://flags#web-identity-digital-credentials` string at `dc-api.ts:18` is **stale
text in EU code** — the DC API shipped enabled by default in **Chrome 141 (Oct 2025)**.

**RETRACTED — "off by default, feature-flagged."** False. `VITE_FEATURE_FLAG_DC_API`
appears only in `.env.example:7` and a *type declaration* (`vite-env.d.ts:10`) — **it is
never read.** The real gate is `shouldUseDcApi()` = `isDcApiAvailable()`
(`dc-api.ts:30-32`), i.e. runtime browser capability detection: the ZK path switches
itself **ON** in any DC-API-capable browser, which post-Chrome-141 is stock Chrome. The
service is deployed and live; its hosts are hardcoded in `runServer.kt`
(`verifier.ageverification.dev`, `dc-verifier-backend.acc.ageverification.dev`, …).

**How we got this wrong:** we reasoned from an empty `.env.example` to "it's off,"
instead of reading what actually runs. That is the exact mistake `CLAUDE.md` forbids —
*never trust a health check, a config value, or a status field* — committed against
someone else's config file. Both stale artifacts (`chrome://flags`, the unread feature
flag) are themselves status fields that lie.

**Carve-out:** `av-lib-ios-longfellow-zkp` exposes `verifyProof(...)` as well as
`generateProof(...)`, so it is ZK-capable client-side. Say **"the only server-side ZK
verifier"**, never "the only ZK verifier." (Medium confidence — from delegated research,
not a direct read.)

## 6. CORRECTED — the spec: `SHOULD`, not "optional"; and "experimental"

`av-doc-technical-specification` rel. 1.0.9 binds itself to **RFC 2119** (§1.4, line 146).
So ZKP is **`SHOULD` = RECOMMENDED**, which is *not* `MAY` = optional. **Do not write
"optional"** — it is the one word a hostile expert can falsify.

- §4.2 (l.1051): an AV App **SHALL** implement the Annex A presentation protocols,
  **SHOULD** implement the ZKP mechanism.
- §4.4 (l.1095): a Relying Party **SHOULD** implement ZKP verification.
- §7 is titled **"Experimental features"**; §7.1 (l.1270): *"A next version … **will
  include as an experimental feature** the Zero-Knowledge Proof (ZKP) solution."*

The mandatory (`SHALL`) path is plain mdoc, where the relying party sees the actual
credential.

## 7. RETRACTED — "batches of 30 single-use credentials = rate-limited linkability"

**Was in:** `README.md §Why`, `PRD §2` (cited to a secondary source — the Yivi analysis).
**Verdict: UNFAIR TO THE EU, and wrong as stated.** This is the retraction that matters
most, because it is the one an expert reader would use to discredit everything else.

Against **colluding relying parties**, batch issuance **genuinely is unlinkable.** Each
attestation is bound to a *distinct* device key — Annex A (l.160): the AVI **MUST** use
the `proofs` parameter, an array of JWT proofs (OpenID4VCI batch issuance = one key per
credential). Two websites comparing notes see two different signatures over two
different device keys. **There is no credential-borne correlator. Calling that "linkable"
is simply false.**

What is true, and is the real gap:

- **Batch size 30 is a recommendation, not a `SHALL`** (§3.4.1, l.967). What *is* `SHALL`:
  the AP supports batch issuance (§4.3); the app uses each attestation **once** (§4.2);
  the AP truncates the `ValidityInfo` timestamp to limit linkability (§4.3).
- **It is a finite anonymity budget** — ~30 presentations, re-identification at least
  every 3 months (§3.4.2, §3.4.3).
- **It does not protect against the issuer.** The RP sees the AP's signature over a
  unique MSO; an AP retaining the batch→user mapping could re-identify. The spec's only
  answer is that it *"does not require the Attestation Provider to store any permanent
  information"* (§Data minimisation, l.514) — it does not **forbid** it. **That is a
  policy, not a cryptographic guarantee.**
- **The spec concedes the point.** Annex B §B.1: a ZKP-based approach *"enhances privacy
  by **ensuring unlinkability**, making it computationally infeasible for the Relying
  Party to associate multiple proofs with the same individual."*
- And §Unlinkability (l.518): *"**Initially, the solution will rely on batch issuance** to
  protect users from colluding RPs. Zero-Knowledge Proof (ZKP) mechanisms **will be
  considered**."*

## 8. CORRECTED — the statute, quoted properly

eIDAS 2.0 (Regulation (EU) 2024/1183) **Art. 5a(16)**, verbatim from the official OJ:

> **16.** The technical framework of the European Digital Identity Wallet shall:
> **(a)** not allow providers of electronic attestations of attributes or any other party,
> after the issuance of the attestation of attributes, to obtain data that allows
> transactions or user behaviour to be **tracked, linked or correlated**, or knowledge of
> transactions or user behaviour to be otherwise obtained, unless explicitly authorised
> by the user;
> **(b)** enable privacy preserving techniques which ensure **unlikeability** *[sic — the
> published OJ text reads "unlikeability"]*, where the attestation of attributes does not
> require the identification of the user.

Three corrections to how 8een cited this:

1. **The typo is real.** The official OJ HTML reads **"unlikeability"**. The Commission's
   own docs silently quote it as "unlinkability". If we quote it verbatim as
   "unlinkability", **we are misquoting the law.** Use `[sic]`.
2. **Lean on (a), not (b).** (a) is unconditional and outcome-shaped. (b) is weaker — a
   duty to *"enable"* techniques, conditioned on identification not being required. "5a(16)
   mandates unlinkability as an outcome" is defensible **via (a)**; leaning on (b) invites
   *"it only says enable."*
3. **Scope.** Art. 5a governs the **EUDI Wallet**. The AV app is a separate,
   blueprint-derived mini-wallet. Say the blueprint **inherits/aspires to** the 5a(16)
   design constraint — not that it is legally bound by it.

**The load-bearing sentence:** 5a(16)(a) names the **attestation provider** — the issuer —
as a party that must not be able to link transactions. Batch issuance defends against
relying parties. It does not defend against the issuer; the spec's only issuer-side
safeguard is the storage policy in §Data minimisation, and the only mechanism the spec
credits with *ensuring* unlinkability is ZKP (Annex B — whose own wording is
Relying-Party-scoped; no spec text promises issuer-unlinkability for any mechanism).
*(Corrected 2026-07-17: this sentence previously ended "The spec's own Annex B says ZKP is
what does [defend against the issuer]" — attributing to Annex B a claim its RP-scoped
wording does not make. Found by the M5 dossier review.)*

## 9. The thesis that survives

Not *"nobody can verify these proofs"* — a ZK verifier exists, it is live, and it works.
The evidenced argument is narrower and holds:

1. **On the protocol the web actually uses, the unlinkable path does not exist
   end-to-end.** The wallet cannot produce a ZK proof over OpenID4VP (§2); the flagship
   OpenID4VP verifier cannot check one (§4). ZK works only over the browser DC API or
   short-range proximity.
2. **The default is full disclosure.** ZK is `SHOULD` and lives under "Experimental
   features" (§6); the `SHALL` path shows the relying party the actual credential.
3. **When ZK fails, the wallet discloses everything anyway** — silently, by default (§3).
4. **The law names the issuer as the adversary** (§8); batch issuance does not defend
   against the issuer (§7); and the only mechanism the spec credits with ensuring
   unlinkability is ZKP (§7 — Annex B's own promise is RP-scoped; nothing in the spec
   promises unlinkability against the issuer for any mechanism).
5. **The one server-side ZK verifier is a vendored wallet SDK** (§5), not a component a
   mid-size site drops into a request path.

8een's case is therefore **not** that verification is impossible. It is that the
unlinkable path is not *reachable* on the mainstream protocol, not *default* anywhere,
not *fail-safe* when it breaks, and not *adoptable* as a small stateless dependency —
and that the party the statute names is the one the shipped default does not defend
against.

## What this costs us, honestly

The gap is **smaller** than the repo claimed. A working ZK verifier exists and is
deployed. Anyone who reads the old README and then the EU repos would conclude 8een had
not done its homework — and they would have been right. Four of the project's public
claims needed correction, two of them outright false, one of them unfair to the party
being criticised. All four are corrected in the same commit as this log.
