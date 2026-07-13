# Mint spec — bytes that `run_mdoc_prover` accepts

Extracted from longfellow's own parser/circuit (not the ISO spec). Every claim
cites `poc/longfellow-zk/lib/circuits/mdoc/`. **Two layers must both pass:**

1. **Host parser** `ParsedMdoc::parse_device_response` (`mdoc_witness.h:128-318`) —
   order-tolerant key lookup; also does both ECDSA verifies on the host
   (issuer `:634`, device `:649`).
2. **Circuit** `MdocHash::assert_valid_hash_mdoc` (`mdoc_hash.h:180-284`) — rigid
   byte patterns at recorded offsets. Parser-pass + circuit-fail ⇒ prover returns
   SUCCESS but the proof is garbage; failure only shows in the verifier.

**Success criterion for the spike: prover SUCCESS *and* verifier SUCCESS.**

## Top-level DeviceResponse
Full `DeviceResponse` map, but only `documents` is read (`:141`; `version`/`status`
never looked up). `documents[0]` (`:145`) must have `docType` TEXT (`:148`),
`issuerSigned` map (`:156`), `deviceSigned` map (`:235`).

## issuerSigned
- `issuerAuth` = COSE_Sign1 array (`:159`). Only `[2]` (payload) and `[3]` (sig)
  are read — `[0]`/`[1]` (incl. x5chain) are **never parsed**. No cert-chain
  validation in the prover; issuer identity is only the `(pkx,pky)` you pass.
- `nameSpaces` map (`:169`); each value an ARRAY (`:176`); each element
  `D8 18 58 <len> <IssuerSignedItem>` (tag24 → bstr → map).

## Issuer signature (ES256 / P-256, raw r||s — standard COSE)
Prover reconstructs `Sig_structure` (`mdoc_witness.h:309-315`, prefix
`mdoc_constants.h:32-36`):
```
84 6A "Signature1" 43 A10126 40 59 <len2> <payload>
```
`43 A10126` = protected {1:-7}; `40` = empty external_aad; payload =
`issuerAuth[2]` = tag24-wrapped MSO `D8 18 59 <len2> <MSO>`. Hash SHA-256, verify
against `(pkx,pky)`. **Prover hard-codes the `0x59` 2-byte length form ⇒ the
tagged MSO payload MUST be ≥ 256 and < 65536 bytes** (`:311-312`, `:248`).
Also tagged MSO < `kMaxMsoLen`=2533 (`:786`).

## Device signature (ES256 / P-256)
`compute_transcript_hash` (`:436-484`) uses the `transcript` buffer passed to
`run_mdoc_prover` **verbatim** (not one from the mdoc). DeviceAuthentication:
```
84 74 "DeviceAuthentication" <transcript bytes> <docType text> D8 18 41 A0
```
(`D8 18 41 A0` = tag24(empty map) = empty DeviceNameSpaces). Wrap in
`84 6A"Signature1" 43 A10126 40 <tag24(DeviceAuthentication)>`, SHA-256, verify
against deviceKey from MSO. Set `deviceSigned.nameSpaces = D8 18 41 A0`.

## MSO map (≥ 256 bytes serialized)
- `validityInfo` (`:253`): `validFrom` and `validUntil` each **tag(0) tdate,
  exactly 20 chars** — circuit asserts `C0 74` prefix (`mdoc_hash.h:512,517`).
  Enforced `validFrom ≤ now ≤ validUntil`, lexicographic over 20 bytes.
- `deviceKeyInfo` = single-entry map `{deviceKey: {1:2,-1:1,-2:bstr32 X,-3:bstr32 Y}}`,
  **exact canonical key order**, coords raw 32-byte BE. Circuit asserts the exact
  byte sequence `6D"deviceKeyInfo" A1 69"deviceKey" A4 01 02 20 01 21 58 20 <X> 22 58 20 <Y>`
  (`mdoc_hash.h:529-535`). No extra map entries.
- `valueDigests: {<ns>: {<digestID:uint>: bstr32}}`; digest = SHA-256 of the full
  tag24 IssuerSignedItemBytes. Digest bstr framed `58 20 <32>`.
- `docType`/`digestAlgorithm:"SHA-256"`/`version` present but not parsed
  (good for the Go server's separate validation).

## IssuerSignedItem
`D8 18 58 <len∈[24,255]> A4{digestID, random(≥1B), elementIdentifier, elementValue}`
— exactly 4 keys, any order, map content ≲ 119 bytes (2 SHA blocks). Matched to a
`RequestedAttribute` **on elementIdentifier only** (`:93-95`); circuit then forces
`cbor_value` to equal the item's elementValue CBOR. Budget: encoded id+value
≲ 56 bytes.

## RequestedAttribute (passed to prover, not in the mdoc)
`{namespace_id, id = elementIdentifier text, cbor_value = exact elementValue CBOR}`.
All requested attrs share ONE namespace present in nameSpaces. For
`age_over_18=true`: id=`"age_over_18"`, cbor_value = `F5` (CBOR true).
version ≥ 4 required (`:783`).

## Error codes = debugging oracle
Structural parse errors first. `SIGNATURE_FAILURE` (`:636`) = issuer Sig_structure
reconstruction or key off (check the ≥256-byte / `0x59` assumption).
`DEVICE_SIGNATURE_FAILURE` (`:651`) = DeviceAuthentication bytes (transcript /
docType / empty-ns / device key) off. `ATTRIBUTE_NOT_FOUND` (`:897`) =
elementIdentifier mismatch. Prover SUCCESS + verifier fail = a circuit byte-layout
constraint (deviceKey canonical bytes, `C0 74` date, `A4`/`58` item framing, wrong
cbor_value).
