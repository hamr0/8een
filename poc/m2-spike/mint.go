package main

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

// bstr encodes a CBOR byte string with a length header chosen by size.
func bstr(b []byte) []byte {
	n := len(b)
	switch {
	case n < 24:
		return append([]byte{byte(0x40 | n)}, b...)
	case n < 256:
		return append([]byte{0x58, byte(n)}, b...)
	case n < 65536:
		return append([]byte{0x59, byte(n >> 8), byte(n)}, b...)
	default:
		panic("bstr too long")
	}
}

func be16(n int) []byte { return []byte{byte(n >> 8), byte(n)} }

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// coord32 returns the 32-byte big-endian encoding of an EC coordinate.
func coord32(x *big.Int) []byte {
	b := make([]byte, 32)
	x.FillBytes(b)
	return b
}

// pkString returns the "0x"+hex form the prover's parsePk expects.
func pkString(x *big.Int) string {
	return "0x" + hex.EncodeToString(coord32(x))
}

// rawSig signs digest with priv and returns r||s, each 32 bytes big-endian.
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
	docType   = "org.iso.18013.5.1.mDL"
	namespace = "org.iso.18013.5.1"
	elemID    = "age_over_18"
	validFrom = "2020-01-01T00:00:00Z" // exactly 20 chars
	validUntil = "2030-01-01T00:00:00Z" // exactly 20 chars
	nowStr    = "2026-07-13T00:00:00Z" // 20 chars, validFrom <= now <= validUntil
)

// elementValue for age_over_18 = CBOR true (0xF5)
var elemValue = []byte{0xF5}

// MintResult carries everything the prover/verifier need.
type MintResult struct {
	DeviceResponse []byte
	Transcript     []byte
	IssuerPkX      string
	IssuerPkY      string
	DocType        string
}

// Mint synthesises a full DeviceResponse under freshly generated test keys.
func Mint() (*MintResult, error) {
	// Fresh P-256 issuer CA key and device key, generated at runtime.
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	device, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// ---- IssuerSignedItem (tag24-wrapped map A4) ----
	// exactly 4 keys: digestID, random, elementIdentifier, elementValue
	randomSalt := make([]byte, 16)
	if _, err := rand.Read(randomSalt); err != nil {
		return nil, err
	}
	digestID := 0
	itemMap := cat(
		[]byte{0xA4},
		tstr("digestID"), []byte{byte(digestID)}, // uint 0
		tstr("random"), bstr(randomSalt),
		tstr("elementIdentifier"), tstr(elemID),
		tstr("elementValue"), elemValue,
	)
	// tag24: D8 18 <bstr(itemMap)>
	taggedItem := cat([]byte{0xD8, 0x18}, bstr(itemMap))

	// Digest over the FULL tagged item bytes (D8 18 58 <len> A4 ...).
	itemDigest := sha256.Sum256(taggedItem)

	// ---- deviceKeyInfo (exact rigid layout the circuit asserts) ----
	// 6D "deviceKeyInfo" A1 69 "deviceKey" A4 01 02 20 01 21 58 20 <X> 22 58 20 <Y>
	dkX := coord32(device.PublicKey.X)
	dkY := coord32(device.PublicKey.Y)
	coseKey := cat(
		[]byte{0xA4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20}, dkX,
		[]byte{0x22, 0x58, 0x20}, dkY,
	)
	deviceKeyInfoVal := cat([]byte{0xA1}, tstr("deviceKey"), coseKey)

	// ---- valueDigests: { ns: { digestID: bstr32(digest) } } ----
	innerDigests := cat(
		[]byte{0xA1},
		[]byte{byte(digestID)},          // uint key 0
		[]byte{0x58, 0x20}, itemDigest[:], // bstr32
	)
	valueDigestsVal := cat([]byte{0xA1}, tstr(namespace), innerDigests)

	// ---- validityInfo ----
	tdate := func(s string) []byte { return cat([]byte{0xC0, 0x74}, []byte(s)) }
	validityVal := cat(
		[]byte{0xA2},
		tstr("validFrom"), tdate(validFrom),
		tstr("validUntil"), tdate(validUntil),
	)

	// ---- MSO map (>= 256 bytes so inner tag24 uses the 0x59 2-byte form) ----
	mso := cat(
		[]byte{0xA6},
		tstr("version"), tstr("1.0"),
		tstr("digestAlgorithm"), tstr("SHA-256"),
		tstr("docType"), tstr(docType),
		tstr("valueDigests"), valueDigestsVal,
		tstr("deviceKeyInfo"), deviceKeyInfoVal,
		tstr("validityInfo"), validityVal,
	)
	if len(mso) < 256 {
		return nil, fmt.Errorf("MSO only %d bytes, need >= 256 (add padding)", len(mso))
	}
	if len(mso) >= 65536 {
		return nil, fmt.Errorf("MSO too big: %d", len(mso))
	}

	// tmsoContent = D8 18 59 <msolen2> <MSO>   (inner tag24 with 2-byte length)
	tmsoContent := cat([]byte{0xD8, 0x18, 0x59}, be16(len(mso)), mso)
	tmsoLen := len(tmsoContent) // == 5 + len(mso), the parser's t_mso_.len

	// Sig_structure the issuer signs (mdoc_witness.h:309-315):
	//   kCose1Prefix(ends 0x59) || be16(tmsoLen) || tmsoContent
	kCose1Prefix := []byte{
		0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75,
		0x72, 0x65, 0x31, 0x43, 0xA1, 0x01, 0x26, 0x40, 0x59,
	}
	taggedMsoBytes := cat(kCose1Prefix, be16(tmsoLen), tmsoContent)
	issuerDigest := sha256.Sum256(taggedMsoBytes)
	issuerSig, err := rawSig(issuer, issuerDigest[:])
	if err != nil {
		return nil, err
	}

	// ---- issuerAuth COSE_Sign1 array [protected, unprotected, payload, sig] ----
	payload := cat([]byte{0x59}, be16(tmsoLen), tmsoContent) // bstr of tmsoContent
	issuerAuth := cat(
		[]byte{0x84},
		bstr([]byte{0xA1, 0x01, 0x26}), // protected {1:-7} = 43 A10126
		[]byte{0xA0},                   // unprotected empty map
		payload,                        // [2] tagged MSO bstr
		bstr(issuerSig),                // [3] signature
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
	transcript := []byte{0x83, 0xF6, 0xF6, 0xF6} // SessionTranscript stand-in
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
	}, nil
}

// deviceSignature replicates compute_transcript_hash (mdoc_witness.h:436-484)
// exactly, then signs the SHA-256 with the device key (raw r||s).
func deviceSignature(device *ecdsa.PrivateKey, transcript []byte) ([]byte, error) {
	deviceAuthentication := []byte{
		0x84, 0x74, 'D', 'e', 'v', 'i', 'c', 'e', 'A', 'u', 't',
		'h', 'e', 'n', 't', 'i', 'c', 'a', 't', 'i', 'o', 'n',
	}
	// docType (len 21 < 256) => append_text_len => 0x60|21 = 0x75
	docTypeBytes := append([]byte{byte(0x60 | len(docType))}, []byte(docType)...)
	deviceNameSpaces := []byte{0xD8, 0x18, 0x41, 0xA0}

	da := cat(deviceAuthentication, transcript, docTypeBytes, deviceNameSpaces)

	appendBytesLen := func(buf []byte, l int) []byte {
		switch {
		case l < 24:
			return append(buf, byte(0x40|l))
		case l < 256:
			return append(buf, 0x58, byte(l))
		default:
			return append(buf, 0x59, byte(l>>8), byte(l))
		}
	}

	cose1 := []byte{
		0x84, 0x6A, 0x53, 0x69, 0x67, 0x6E, 0x61, 0x74, 0x75, 0x72, 0x65, 0x31,
		0x43, 0xA1, 0x01, 0x26, 0x40,
	}
	l1 := len(da)
	l2 := l1
	if l1 < 256 {
		l2 += 4
	} else {
		l2 += 5
	}
	cose1 = appendBytesLen(cose1, l2)
	cose1 = append(cose1, 0xD8, 0x18)
	cose1 = appendBytesLen(cose1, l1)
	cose1 = append(cose1, da...)

	digest := sha256.Sum256(cose1)
	return rawSig(device, digest[:])
}
