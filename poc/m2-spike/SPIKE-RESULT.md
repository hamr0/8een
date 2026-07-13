# M2 spike result — synthetic mdoc, real longfellow proof

**Verdict: DOUBLE SUCCESS.** `run_mdoc_prover` returns `MDOC_PROVER_SUCCESS`
and `run_mdoc_verifier` returns `MDOC_VERIFIER_SUCCESS`, on a `DeviceResponse`
synthesized in Go under a P-256 test CA generated at runtime, asserting
`age_over_18 = true`. Reproduced across repeated runs with fresh issuer + device
keys and a fresh random salt each time (nothing is pinned or memoized).

```
run_mdoc_prover   -> MDOC_PROVER_SUCCESS   (proof 359988 bytes)
run_mdoc_verifier -> MDOC_VERIFIER_SUCCESS
```

Circuit: `kZkSpecs[0]` — `8d079211…6182121`, 1 attribute, ZK spec **version 7**,
system `longfellow-libzk-v1`. Prebuilt circuit loaded from
`longfellow-zk/lib/circuits/mdoc/circuits/<hash>` (316385 bytes); no
`generate_circuit()` needed. Prove+verify wall time ≈ 2.5 s / ≈ 0.7 s
respectively on this box.

## How to run

```
cd poc/m2-spike
CGO_ENABLED=1 go build -o m2spike .
./m2spike            # add -dump to print the DeviceResponse hex
```

Deps (`fxamacker/cbor/v2`, `veraison/go-cose`) are in `go.mod` but **the minter
uses neither** — see "hand-encoded vs library" below. Only the stdlib
(`crypto/ecdsa`, `crypto/sha256`, `crypto/elliptic`) is used to mint.

## Notable: it passed on the first execution

No error-code iteration was required. That is a statement about **MINT-SPEC.md**,
not about the difficulty: the spec's byte layouts, the `≥256`/`0x59` rule, and
the two-signature preimages were accurate enough that a careful hand-encode hit
double-success directly. The error-code oracle was therefore never exercised in
anger — the gotchas below are the ones the spec pre-empted and that source
reading confirmed are load-bearing.

## The accepted DeviceResponse structure

Top level `A3{ "version":"1.0", "documents":[doc], "status":0 }` — only
`documents` is read; the rest is cosmetic. `documents[0]` =
`A3{ docType, issuerSigned, deviceSigned }`.

### issuerSigned
- `issuerAuth` = COSE_Sign1 array `84`:
  - `[0]` protected `43 A10126` (`{1:-7}`, ES256)
  - `[1]` unprotected `A0` (empty; **no x5chain** — the prover never parses
    `[0]`/`[1]`, so cert-chain identity is *only* the `(pkx,pky)` args)
  - `[2]` payload = `59 <len2>` bstr whose content is the inner tag24
    `D8 18 59 <msolen2> <MSO>`
  - `[3]` signature = `58 40 <r‖s>` (raw 64-byte P-256, big-endian each half)
- `nameSpaces` = `A1{ "org.iso.18013.5.1": [ D8 18 58 <len> A4{…} ] }`

### MSO (inside the tag24, 314 bytes here — must be ≥ 256)
`A6{ version, digestAlgorithm:"SHA-256", docType, valueDigests, deviceKeyInfo,
validityInfo }`. Field internals are rigid; overall map order is not (parser
looks up by name, circuit reads at parser-reported offsets).
- `validityInfo` = `A2{ validFrom: C0 74 <20ch>, validUntil: C0 74 <20ch> }`
- `deviceKeyInfo` = `A1{ "deviceKey":
  A4 01 02 20 01 21 58 20 <X32> 22 58 20 <Y32> }` — byte-exact
- `valueDigests` = `A1{ "org.iso.18013.5.1": A1{ 0: 58 20 <digest32> } }`
  where `digest32 = SHA-256(` the full tag24 IssuerSignedItem bytes
  `D8 18 58 <len> A4 …` `)`

### IssuerSignedItem (tag24, 83 bytes here)
`D8 18 58 4F A4{ digestID:0, random:bstr16, elementIdentifier:"age_over_18",
elementValue:F5 }`. Exactly 4 keys; `random` ≥ 1 byte.

### deviceSigned
`A2{ nameSpaces: D8 18 41 A0, deviceAuth: A1{ "deviceSignature": COSE_Sign1 } }`.
The device COSE_Sign1 has a detached (`F6`) payload; only `[3]` (the `r‖s` bstr)
is read.

## Gotchas that were load-bearing (confirmed against source)

1. **Two nested length prefixes on the MSO payload.** `issuerAuth[2]` is a bstr
   whose *content* is `D8 18 59 <msolen2> <MSO>`. The parser skips **exactly 5
   bytes** (`resp + pos + 5`, `mdoc_witness.h:248`) to reach the MSO, so the
   inner tag24 **must** use the `59` 2-byte-length form. That is only the
   canonical CBOR encoding when the MSO is ≥ 256 bytes — hence the ≥256 rule is
   really two constraints (canonical inner `0x59` *and* the prover's hard-coded
   `0x59` in `kCose1Prefix`, `mdoc_constants.h:34`). Our MSO is 314 bytes, so no
   padding field was needed; if a smaller MSO were ever used it would have to be
   padded, not force-encoded.

2. **The issuer signs a reconstructed preimage, not the raw payload.** The
   signed bytes are `kCose1Prefix ‖ be16(t_mso_.len) ‖ t_mso_content`
   (`mdoc_witness.h:309-315`), where `t_mso_.len = 5 + len(MSO)` (the length of
   the *outer* payload content, i.e. including the inner `D8 18 59 …` header),
   **not** `len(MSO)`. Getting this length wrong is the classic
   `MDOC_PROVER_SIGNATURE_FAILURE`.

3. **The device signature is over a hand-built preimage that embeds the
   docType and an empty-namespaces tag.** `compute_transcript_hash`
   (`mdoc_witness.h:436-484`) is `84 6A"Signature1" 43 A10126 40` `‖`
   `bstr_len(l2)` `‖ D8 18 ‖ bstr_len(l1) ‖` `[84 74"DeviceAuthentication" ‖
   transcript ‖ (0x60|len)‖docType ‖ D8 18 41 A0]`, with `l1 = len(da)`,
   `l2 = l1 + (l1<256?4:5)`. The transcript is inserted **verbatim** and must be
   byte-identical to the `transcript` passed to both prover and verifier. Any
   drift ⇒ `MDOC_PROVER_DEVICE_SIGNATURE_FAILURE`.

4. **COSE_Key coordinate labels.** The circuit's `kDeviceKeyInfoCheck`
   (`mdoc_hash.h:529-535`) fixes `21 58 20 <X>` (label −2) then `22 58 20 <Y>`
   (label −3). The parser's `lookup_negative(-1)`→X, `lookup_negative(-2)`→Y map
   onto those same 0x21/0x22 entries. Standard COSE EC2 order
   `{1:2,-1:1,-2:X,-3:Y}` is exactly right; coords are raw 32-byte big-endian
   (`FillBytes`), never DER/point-encoded.

5. **`pkx`/`pky` are decimal-or-hex strings, not bytes.** `parsePk` →
   `Nat::of_untrusted_string` (`nat.h:137`) accepts a `0x…` hex string. We pass
   `"0x" + hex(32-byte-BE)` of each issuer coordinate.

6. **The valueDigests digest is over the tag24 item _with_ its `D8 18 58 <len>`
   header** (`mdoc_witness.h:830`, `tag_len = bstr_len + 4`), not over the bare
   map. The circuit re-hashes the same 83 bytes and asserts equality
   (`mdoc_hash.h:258-283`).

7. **ECDSA malleability is a non-issue.** Go's `ecdsa.Sign` may emit high-`s`;
   longfellow's verify accepts it (verification is `s`-sign-agnostic), so no
   low-`s` normalization is required. Confirmed empirically over many fresh
   signatures.

8. **`age_over_18` value is 1 byte `0xF5`.** `RequestedAttribute.cbor_value`
   must be exactly that; the circuit forces the item's `elementValue` to equal
   the requested `cbor_value` byte-for-byte (`mdoc_hash.h:467-478`).

## Hand-encoded vs library

**Everything was hand-encoded** as raw byte slices (`mint.go`). fxamacker's
canonical mode was *not* used, deliberately: the circuit demands several
layouts that a general CBOR encoder will not reliably emit —
- the double-nested MSO length framing with a forced-2-byte inner `0x59`,
- the exact `A4 01 02 20 01 21 58 20 … 22 58 20 …` COSE_Key byte run,
- tag24 wrappers (`D8 18 …`) around bstrs,
- the COSE_Sign1 `Sig_structure` preimages, which are not CBOR the encoder
  would produce from a struct.

For M2 productionization this is the main decision point: hand-assembling these
byte runs is what made the spike pass first try, and I'd keep the
security-critical framings (MSO payload, COSE_Key, both `Sig_structure`
preimages, the tag24 item + its digest) as explicit byte builders with unit
tests over the exact hex. A library encoder is fine for the *cosmetic* outer
scaffolding (DeviceResponse map, status) that the prover never parses, but
mixing the two invites silent drift in exactly the fields that fail closed.

## Concerns / follow-ups for M2

- **Test-CA scaffolding replaces the pinned `ZKVERIFY_FAKE_TIME` clock.** This
  spike sets `validFrom=2020…`, `validUntil=2030…`, `now=2026-07-13…` (all
  20-char tdates, `validFrom ≤ now ≤ validUntil`, compared lexicographically).
  M2 should generate validity windows relative to a real clock, but keep the
  20-char exact-length invariant — the circuit asserts `C0 74` (tag0 + text-20)
  and reads exactly 20 date bytes.
- **The prover verifies both ECDSA signatures on the host** before proving
  (`mdoc_witness.h:634,649`). So `MDOC_PROVER_SIGNATURE_FAILURE` /
  `_DEVICE_SIGNATURE_FAILURE` are our fast, cheap oracle for signature-preimage
  bugs — worth surfacing distinctly in M2 error handling.
- **`0x59`/≥256 is a genuine trap for real issuers.** A production wallet whose
  MSO happens to be < 256 bytes would encode the inner tag24 with `0x58`
  (1-byte len) and the parser's `+5` skip would misread it. Real EU/ISO mdocs
  are comfortably larger, but M2's minter must guarantee ≥256 by construction
  (pad the MSO), and any *ingested* third-party mdoc should be validated for
  this before proving.
- **No x5chain is present or checked here.** The one-bit verdict's trust story
  depends entirely on the `(pkx,pky)` passed in. M2 must source that key from a
  vetted trust list (the truncated-trust-list failure mode in CLAUDE.md), and
  must never infer issuer identity from `issuerAuth[0]/[1]`, which the prover
  ignores entirely.
- **Circuit provenance.** We loaded the prebuilt `kZkSpecs[0]` circuit by hash
  from the clone. M2 must verify the loaded circuit's `circuit_id` against the
  hardcoded `kZkSpecs` hash (the reference server's `LoadCircuits` already does
  this) rather than trusting the filename — same "verify what actually loaded"
  doctrine as readiness.
- **cbor_value length ceiling.** `RequestedAttribute.cbor_value` is a fixed
  64-byte buffer; `age_over_18=F5` is trivially fine, but M2 attributes with
  larger values must respect the `MDOC_VERIFIER_INVALID_CBOR` / attribute-length
  limits seen in the longfellow tests.

## Files

- `mint.go` — runtime P-256 keygen + fully hand-encoded DeviceResponse.
- `prove.go` — cgo bindings for `run_mdoc_prover` **and** `run_mdoc_verifier`
  (mirrors `reference/.../zk/proofs.go`, adds the prover + `&kZkSpecs[0]`), with
  full error-code name tables.
- `main.go` — mint → prove → verify, prints the error-code name at each step.
