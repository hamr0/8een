package main

// mint.go — synthesises a full ISO 18013-5 DeviceResponse under freshly generated
// P-256 test keys, as raw hand-encoded bytes.
//
// EVERYTHING in the inner mdoc is hand-encoded (never fxamacker/cbor), and that is
// deliberate: longfellow's circuit (MdocHash::assert_valid_hash_mdoc,
// lib/circuits/mdoc/mdoc_hash.h:180-284) asserts rigid byte patterns at recorded
// offsets. A general CBOR encoder will not reliably emit the double-nested MSO
// length framing, the exact COSE_Key byte run, the tag24 wrappers, or the
// Sig_structure preimages. The clean split (poc/m2-spike/SPIKE-RESULT.md,
// "Hand-encoded vs library") is: inner mdoc = hand-rolled bytes (this file);
// outer service wire structs = library cbor.Marshal (fixture.go). Mixing the two
// invites silent drift in exactly the fields that fail closed.
//
// This file is pure (no cgo): the byte builders below are unit-tested under plain
// `go test` even without the longfellow clone. See layout_test.go.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
)

// ---- byte/CBOR helpers (all hand-encoded for exact layout control) ----

// tstr encodes a CBOR text string. All our keys/values are < 24 bytes so the
// single-byte major-3 header (0x60|len) is always canonical here, except we
// guard the general case up to 255.
func tstr(s string) []byte {
	b := []byte(s)
	n := len(b)
	if n < 24 {
		return append([]byte{byte(0x60 | n)}, b...)
	}
	if n < 256 {
		return append([]byte{0x78, byte(n)}, b...)
	}
	panic("tstr too long")
}

// bstrLen returns the CBOR byte-string LENGTH HEADER for n, and is the single
// source of truth for that framing. It mirrors longfellow's own append_bytes_len
// (mdoc_witness.h:402-413) byte-for-byte, including its len < 65536 bound — the
// device-signature preimage in deviceAuthCose1 must reproduce upstream's bytes
// exactly, so this must not drift from it.
//
// The size thresholds are load-bearing: a byte string of >= 256 bytes gets the
// 0x59 two-byte length form, which is exactly what the prover hard-codes for the
// tagged MSO payload (see mintWith).
func bstrLen(n int) []byte {
	switch {
	case n < 24:
		return []byte{byte(0x40 | n)}
	case n < 256:
		return []byte{0x58, byte(n)}
	case n < 65536:
		return []byte{0x59, byte(n >> 8), byte(n)}
	default:
		panic("bstr too long")
	}
}

// bstr encodes a CBOR byte string: length header + payload.
func bstr(b []byte) []byte { return append(bstrLen(len(b)), b...) }

// cborUint encodes a CBOR unsigned int, immediate form only. Every uint we emit is
// a small map key (digestID), and the >= 24 forms are multi-byte: emitting one
// would shift every subsequent byte offset the circuit reads at. Refuse loudly
// rather than silently corrupt the layout — 0x18 alone (the value of byte(24)) is
// the "one length byte follows" header, so an unguarded byte(n) at n=24 produces a
// truncated header and a map the parser misreads at a shifted offset.
func cborUint(n int) []byte {
	if n < 0 || n >= 24 {
		panic(fmt.Sprintf("cborUint: %d out of range [0,24); a multi-byte uint would shift the circuit's byte offsets", n))
	}
	return []byte{byte(n)}
}

func be16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// coord32 returns the 32-byte big-endian encoding of an EC coordinate. Coords are
// raw 32-byte big-endian (FillBytes), never DER/point-encoded — the circuit's
// kDeviceKeyInfoCheck (mdoc_hash.h:529-535) asserts the raw 32-byte runs.
func coord32(x *big.Int) []byte {
	b := make([]byte, 32)
	x.FillBytes(b)
	return b
}

// pkString returns the "0x"+hex form the prover's parsePk (Nat::of_untrusted_string,
// nat.h:137) expects — a decimal-or-hex string, not bytes.
func pkString(x *big.Int) string {
	return "0x" + hex.EncodeToString(coord32(x))
}

// rawSig signs digest with priv and returns r||s, each 32 bytes big-endian —
// standard COSE ES256. Go's ecdsa.Sign may emit high-s; longfellow's verify is
// s-sign-agnostic and accepts it, so no low-s normalization is required
// (SPIKE-RESULT.md gotcha 7, confirmed empirically over many fresh signatures).
func rawSig(priv *ecdsa.PrivateKey, digest []byte) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// ---- domain constants ----

const (
	// circuitHash0 names kZkSpecs[0]: 1 attribute, ZK spec version 7, system
	// longfellow-libzk-v1. The prebuilt circuit file on disk is named by this hash;
	// it is also the ZkSystemId the service matches by GetCircuitByName + find_zk_spec.
	circuitHash0 = "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121"

	docType    = "org.iso.18013.5.1.mDL"
	namespace  = "org.iso.18013.5.1"
	elemID     = "age_over_18"
	validFrom  = "2020-01-01T00:00:00Z" // exactly 20 chars
	validUntil = "2030-01-01T00:00:00Z" // exactly 20 chars

	// nowStr is the circuit's clock: a 20-char tdate with validFrom <= now <=
	// validUntil, compared lexicographically inside the circuit. It is ENTIRELY
	// separate from the x509 chain clock (fixture.go's certWindow, real wall
	// time). It is also the wire Timestamp, which validateRequestIso hard-checks
	// is exactly 20 chars and equal to the prover's `now`.
	nowStr = "2026-07-13T00:00:00Z"
)

// MintResult carries everything the prover/verifier and the service wrapper need.
type MintResult struct {
	DeviceResponse []byte
	Transcript     []byte
	IssuerPkX      string
	IssuerPkY      string
	DocType        string
	// IssuerKey is the P-256 key that signed the MSO issuerAuth. The service wire
	// format (fixture.go) needs it to mint a document-signer (leaf) cert carrying
	// this exact public key, so the key validateIssuerKey extracts from the cert
	// equals the key the proof was generated under. This is the whole trust seam.
	IssuerKey *ecdsa.PrivateKey
}

// ---- rigid byte builders (unit-tested directly in layout_test.go) ----

// buildCOSEKey returns the exact deviceKey COSE_Key byte run the circuit's
// kDeviceKeyInfoCheck (mdoc_hash.h:529-535) asserts:
//
//	A4 01 02 20 01 21 58 20 <X32> 22 58 20 <Y32>
//
// i.e. the canonical EC2 map {1:2, -1:1, -2:bstr32 X, -3:bstr32 Y}. The parser's
// lookup_negative(-1)->X, lookup_negative(-2)->Y map onto the 0x21/0x22 entries
// (SPIKE-RESULT.md gotcha 4). Extra map entries are forbidden.
func buildCOSEKey(x, y []byte) []byte {
	return cat(
		[]byte{0xA4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20}, x,
		[]byte{0x22, 0x58, 0x20}, y,
	)
}

// buildTDate returns a tag(0) tdate: C0 74 <20 bytes>. The circuit asserts the
// C0 74 prefix (tag0 + text-20) and reads exactly 20 date bytes
// (mdoc_hash.h:512,517), so s MUST be exactly 20 chars.
func buildTDate(s string) []byte {
	if len(s) != 20 {
		panic("tdate must be exactly 20 chars: " + s)
	}
	return cat([]byte{0xC0, 0x74}, []byte(s))
}

// buildIssuerSignedItemMap returns the A4 IssuerSignedItem map with exactly 4
// keys: digestID, random, elementIdentifier, elementValue (MINT-SPEC.md:62-67).
// The item is matched to a RequestedAttribute on elementIdentifier only; the
// circuit then forces cbor_value to equal this elementValue byte-for-byte.
func buildIssuerSignedItemMap(digestID int, salt []byte, id string, elemValue []byte) []byte {
	return cat(
		[]byte{0xA4},
		tstr("digestID"), cborUint(digestID),
		tstr("random"), bstr(salt),
		tstr("elementIdentifier"), tstr(id),
		tstr("elementValue"), elemValue,
	)
}

// wrapTag24 wraps b in a tag24 (D8 18) around a CBOR byte string: D8 18 <bstr(b)>.
// The bstr length header is size-chosen, so an item (< 256 bytes) gets the 0x58
// form (D8 18 58 <len>) and the MSO (>= 256 bytes) gets the 0x59 two-byte form
// (D8 18 59 <len2>) — the latter is exactly the form the prover's +5 skip
// (mdoc_witness.h:248) and hard-coded 0x59 (mdoc_constants.h:34) require.
func wrapTag24(b []byte) []byte {
	return cat([]byte{0xD8, 0x18}, bstr(b))
}

// buildValidityInfo returns A2{ validFrom: tdate, validUntil: tdate }
// (MINT-SPEC.md:50-52). Enforced validFrom <= now <= validUntil, lexicographic.
func buildValidityInfo() []byte {
	return cat(
		[]byte{0xA2},
		tstr("validFrom"), buildTDate(validFrom),
		tstr("validUntil"), buildTDate(validUntil),
	)
}

// buildDeviceKeyInfo returns A1{ "deviceKey": <coseKey> }.
func buildDeviceKeyInfo(coseKey []byte) []byte {
	return cat([]byte{0xA1}, tstr("deviceKey"), coseKey)
}

// buildValueDigests returns A1{ <ns>: A1{ <digestID:uint>: bstr32(itemDigest) } }.
// itemDigest is SHA-256 of the FULL tag24 IssuerSignedItem bytes (D8 18 58 <len>
// A4 ...), not the bare map (mdoc_witness.h:830, tag_len = bstr_len + 4). The
// circuit re-hashes the same bytes and asserts equality (mdoc_hash.h:258-283).
func buildValueDigests(digestID int, itemDigest []byte) []byte {
	inner := cat(
		[]byte{0xA1},
		cborUint(digestID),
		bstr(itemDigest[:32]), // bstr32 -> 58 20 <32>
	)
	return cat([]byte{0xA1}, tstr(namespace), inner)
}

// buildMSO assembles the MSO map A6{...}. It MUST serialize to >= 256 bytes so the
// inner tag24 wrapper uses the 0x59 two-byte length form (see wrapTag24 / mintWith).
// Field internals are rigid; overall map order is not (parser looks up by name,
// circuit reads at parser-reported offsets).
func buildMSO(itemDigest, coseKey []byte) []byte {
	return cat(
		[]byte{0xA6},
		tstr("version"), tstr("1.0"),
		tstr("digestAlgorithm"), tstr("SHA-256"),
		tstr("docType"), tstr(docType),
		tstr("valueDigests"), buildValueDigests(0, itemDigest),
		tstr("deviceKeyInfo"), buildDeviceKeyInfo(coseKey),
		tstr("validityInfo"), buildValidityInfo(),
	)
}

// kCose1Prefix is the fixed COSE Sign1 Sig_structure prefix the issuer signs over
// (mdoc_witness.h:309-315, prefix mdoc_constants.h:32-36):
//
//	84 6A "Signature1" 43 A10126 40 59
//
// = [ "Signature1", protected {1:-7}=43 A10126, external_aad = empty (40) ] with
// the payload length introduced by a HARD-CODED 0x59 two-byte form — which is why
// the tagged MSO payload must be >= 256 and < 65536 bytes.
var kCose1Prefix = []byte{
	0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75,
	0x72, 0x65, 0x31, 0x43, 0xA1, 0x01, 0x26, 0x40, 0x59,
}

// Mint synthesises a full DeviceResponse under freshly generated test keys,
// asserting age_over_18 = elemValue (0xF5 = CBOR true, 0xF4 = CBOR false).
func Mint(elemValue []byte) (*MintResult, error) {
	// Fresh P-256 issuer (CA/MSO-signing) key and device key, generated at runtime.
	// No keys are ever written to the tree (PRD §10).
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	device, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	return mintWith(issuer, device, salt, elemValue)
}

// mintWith is the deterministic core of Mint: given fixed keys, salt and value it
// assembles a byte-identical DeviceResponse. Split out so layout_test.go can
// assert exact bytes without relying on runtime randomness.
func mintWith(issuer, device *ecdsa.PrivateKey, salt, elemValue []byte) (*MintResult, error) {
	const digestID = 0

	// ---- IssuerSignedItem (tag24-wrapped A4 map, exactly 4 keys) ----
	itemMap := buildIssuerSignedItemMap(digestID, salt, elemID, elemValue)
	taggedItem := wrapTag24(itemMap) // D8 18 58 <len> A4 ...
	// Digest over the FULL tagged item bytes (D8 18 58 <len> A4 ...).
	itemDigest := sha256.Sum256(taggedItem)

	// ---- deviceKeyInfo (exact rigid COSE_Key layout the circuit asserts) ----
	coseKey := buildCOSEKey(coord32(device.PublicKey.X), coord32(device.PublicKey.Y))

	// ---- MSO map (>= 256 bytes so inner tag24 uses the 0x59 2-byte form) ----
	mso := buildMSO(itemDigest[:], coseKey)
	if len(mso) < 256 {
		return nil, fmt.Errorf("MSO only %d bytes, need >= 256 (would break the 0x59 invariant)", len(mso))
	}
	if len(mso) >= 65536 {
		return nil, fmt.Errorf("MSO too big: %d bytes", len(mso))
	}

	// tmsoContent = D8 18 59 <msolen2> <MSO>  (inner tag24, forced 2-byte length).
	tmsoContent := wrapTag24(mso)
	tmsoLen := len(tmsoContent) // == 5 + len(mso), the parser's t_mso_.len

	// Sig_structure the issuer signs (mdoc_witness.h:309-315):
	//   kCose1Prefix(ends 0x59) || be16(tmsoLen) || tmsoContent
	// where tmsoLen is the length of the OUTER payload content (including the inner
	// D8 18 59 ... header), NOT len(MSO). Getting this length wrong is the classic
	// MDOC_PROVER_SIGNATURE_FAILURE.
	taggedMsoBytes := cat(kCose1Prefix, be16(tmsoLen), tmsoContent)
	issuerDigest := sha256.Sum256(taggedMsoBytes)
	issuerSig, err := rawSig(issuer, issuerDigest[:])
	if err != nil {
		return nil, err
	}

	// ---- issuerAuth COSE_Sign1 array [protected, unprotected, payload, sig] ----
	// [0]/[1] (incl. any x5chain) are NEVER parsed by the prover — cert-chain
	// identity is only the (pkx,pky) args. payload [2] is the tagged MSO bstr.
	// bstr(tmsoContent) IS the 0x59 two-byte form here, not by luck: tmsoContent is
	// 5 + len(MSO) and len(MSO) >= 256 is enforced above, so bstrLen always picks
	// 0x59. Hand-rolling the header again would just be a second place to get it
	// wrong.
	payload := bstr(tmsoContent)
	issuerAuth := cat(
		[]byte{0x84},
		bstr([]byte{0xA1, 0x01, 0x26}), // [0] protected {1:-7} = 43 A10126
		[]byte{0xA0},                   // [1] unprotected empty map
		payload,                        // [2] tagged MSO bstr
		bstr(issuerSig),                // [3] signature (58 40 <r||s>)
	)

	// ---- issuerSigned map ----
	nameSpaces := cat(
		[]byte{0xA1},
		tstr(namespace),
		cat([]byte{0x81}, taggedItem), // array of 1 tagged item
	)
	issuerSigned := cat(
		[]byte{0xA2},
		tstr("nameSpaces"), nameSpaces,
		tstr("issuerAuth"), issuerAuth,
	)

	// ---- deviceSigned ----
	// SessionTranscript stand-in, inserted VERBATIM into both the device signature
	// preimage and passed to run_mdoc_prover/verifier. Any drift between the two
	// yields MDOC_PROVER_DEVICE_SIGNATURE_FAILURE.
	transcript := []byte{0x83, 0xF6, 0xF6, 0xF6}
	deviceSig, err := deviceSignature(device, transcript)
	if err != nil {
		return nil, err
	}
	deviceSigCose := cat(
		[]byte{0x84},
		bstr([]byte{0xA1, 0x01, 0x26}),
		[]byte{0xA0},
		[]byte{0xF6}, // detached payload = null
		bstr(deviceSig),
	)
	deviceAuth := cat([]byte{0xA1}, tstr("deviceSignature"), deviceSigCose)
	deviceSigned := cat(
		[]byte{0xA2},
		tstr("nameSpaces"), []byte{0xD8, 0x18, 0x41, 0xA0}, // tag24(empty map)
		tstr("deviceAuth"), deviceAuth,
	)

	// ---- Document + DeviceResponse ----
	// Only `documents` is read by the parser; version/status are cosmetic.
	document := cat(
		[]byte{0xA3},
		tstr("docType"), tstr(docType),
		tstr("issuerSigned"), issuerSigned,
		tstr("deviceSigned"), deviceSigned,
	)
	deviceResponse := cat(
		[]byte{0xA3},
		tstr("version"), tstr("1.0"),
		tstr("documents"), cat([]byte{0x81}, document),
		tstr("status"), []byte{0x00},
	)

	return &MintResult{
		DeviceResponse: deviceResponse,
		Transcript:     transcript,
		IssuerPkX:      pkString(issuer.PublicKey.X),
		IssuerPkY:      pkString(issuer.PublicKey.Y),
		DocType:        docType,
		IssuerKey:      issuer,
	}, nil
}

// deviceSignature signs the SHA-256 of the DeviceAuthentication preimage with the
// device key (raw r||s).
func deviceSignature(device *ecdsa.PrivateKey, transcript []byte) ([]byte, error) {
	cose1, err := deviceAuthCose1(transcript)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(cose1)
	return rawSig(device, digest[:])
}

// deviceAuthCose1 rebuilds the COSE_Sign1 preimage that longfellow's
// compute_transcript_hash (mdoc_witness.h:436-484) hashes, byte for byte
// (SPIKE-RESULT.md gotcha 3). It embeds the docType and an empty-namespaces tag,
// and inserts the transcript VERBATIM — any drift from the transcript handed to
// run_mdoc_prover/verifier yields MDOC_PROVER_DEVICE_SIGNATURE_FAILURE.
//
// This is a REPLICA of upstream, not an independent encoder. The verifier hashes
// its own copy of these bytes and compares, so "more correct than upstream" is the
// same thing as "wrong". Split out from deviceSignature so it can be golden-tested
// without randomness (layout_test.go).
func deviceAuthCose1(transcript []byte) ([]byte, error) {
	deviceAuthentication := []byte{
		0x84, 0x74, 'D', 'e', 'v', 'i', 'c', 'e', 'A', 'u', 't',
		'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n',
	}
	// docType framing is upstream's append_text_len (mdoc_witness.h:417), which tstr
	// reproduces exactly (0x60|n under 24, else 0x78 n): docType is 21 chars, so
	// 0x75. tstr is used rather than a local 0x60|len because the latter silently
	// emits a headerless 0x78 at len >= 24.
	da := cat(
		deviceAuthentication,
		transcript,
		tstr(docType),
		[]byte{0xD8, 0x18, 0x41, 0xA0}, // DeviceNameSpacesBytes = tag24(empty map)
	)

	l1 := len(da)

	// Upstream computes `size_t l2 = l1 + (l1 < 256 ? 4 : 5);` (mdoc_witness.h:475).
	// DO NOT "correct" this to a canonical length. Below l1 = 24 the tag24 bstr
	// header is one byte, so the canonical length would be l1+3 and upstream's
	// formula over-declares by one — but the verifier recomputes the SAME formula,
	// so the two agree and the signature checks out. Making it canonical here would
	// diverge our preimage from the verifier's and fail every device signature.
	//
	// The guard keeps us out of that region entirely rather than relying on it being
	// self-consistent: da is 52 bytes for our fixed docType and 4-byte transcript.
	if l1 < 24 {
		return nil, fmt.Errorf(
			"DeviceAuthentication is %d bytes; under 24 upstream's l2 formula (mdoc_witness.h:475) leaves canonical CBOR", l1)
	}
	l2 := l1 + 4
	if l1 >= 256 {
		l2 = l1 + 5
	}

	// 84 6A "Signature1" 43 A10126 40 || bstrLen(l2) || D8 18 || bstrLen(l1) || da
	return cat(
		[]byte{
			0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
			0x43, 0xA1, 0x01, 0x26, 0x40,
		},
		bstrLen(l2),
		[]byte{0xD8, 0x18},
		bstrLen(l1),
		da,
	), nil
}
