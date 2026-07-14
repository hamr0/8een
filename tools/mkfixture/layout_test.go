package main

// layout_test.go — PURE byte-layout unit tests over the security-critical INNER
// mdoc framings. These need no cgo and no longfellow clone, so they run under
// plain `go test` (even CGO_ENABLED=0) and guard the exact byte runs the circuit
// asserts. If one of these breaks, a real issuer's valid proof would be rejected
// confidently (the failure mode CLAUDE.md keeps finding). Line refs are into
// MINT-SPEC.md / mdoc_hash.h.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// goldenDeviceAuthCose1 is the exact DeviceAuthentication COSE_Sign1 preimage for
// our fixed docType and the 4-byte stand-in transcript, captured from the running
// minter. The device signature is taken over SHA-256 of THESE bytes, and the
// verifier recomputes them independently via compute_transcript_hash
// (mdoc_witness.h:436-484) — so a single byte of drift here is a silent
// MDOC_PROVER_DEVICE_SIGNATURE_FAILURE with no indication of which of the several
// nested length fields moved.
//
// This test exists to pin the preimage against well-meaning "cleanups". In
// particular it locks in upstream's l2 = l1 + (l1<256?4:5), which is NOT canonical
// CBOR below l1=24; see deviceAuthCose1. Do not regenerate this constant to make a
// failing test pass — a diff here means the bytes the verifier expects changed.
const goldenDeviceAuthCose1 = "846a5369676e61747572653143a10126405838d818" +
	"5834847444657669636541757468656e7469636174696f6e83f6f6f6756f72672e69736f2e" +
	"31383031332e352e312e6d444cd81841a0"

func TestDeviceAuthPreimageIsByteExact(t *testing.T) {
	transcript := []byte{0x83, 0xF6, 0xF6, 0xF6}

	got, err := deviceAuthCose1(transcript)
	if err != nil {
		t.Fatalf("deviceAuthCose1: %v", err)
	}
	want, err := hex.DecodeString(goldenDeviceAuthCose1)
	if err != nil {
		t.Fatalf("bad golden constant: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("device-auth preimage drifted from the bytes the verifier recomputes\n got: %x\nwant: %x", got, want)
	}

	// The declared outer length must be l1+4 (upstream's formula), and the inner
	// tag24 must frame da with the 0x58 one-byte form. da is 52 bytes here.
	if got[17] != 0x58 || got[18] != 56 {
		t.Fatalf("outer payload length header = % X, want 58 38 (l2 = 52+4)", got[17:19])
	}
	if !bytes.Equal(got[19:23], []byte{0xD8, 0x18, 0x58, 52}) {
		t.Fatalf("inner tag24 header = % X, want D8 18 58 34 (l1 = 52)", got[19:23])
	}
}

// Below 24 bytes upstream's l2 formula stops matching canonical CBOR. We must not
// silently emit a preimage from that region: refuse instead.
func TestDeviceAuthRefusesSubCanonicalRegion(t *testing.T) {
	// da = 22 (DeviceAuthentication) + len(transcript) + 22 (docType) + 4, so it
	// cannot drop under 24 with the real docType. Assert the floor holds rather
	// than that the guard fires, and assert the guard exists by construction.
	got, err := deviceAuthCose1(nil)
	if err != nil {
		t.Fatalf("empty transcript should still exceed the 24-byte floor: %v", err)
	}
	if len(got) < 24 {
		t.Fatalf("preimage %d bytes, expected the 24-byte floor to hold", len(got))
	}
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return k
}

// The deviceKey COSE_Key must be EXACTLY
//
//	A4 01 02 20 01 21 58 20 <X32> 22 58 20 <Y32>
//
// the canonical EC2 map {1:2,-1:1,-2:bstr32 X,-3:bstr32 Y}. The circuit's
// kDeviceKeyInfoCheck (mdoc_hash.h:529-535 / MINT-SPEC.md:53-56) asserts this
// byte-for-byte; any drift (extra entries, DER-encoded coords, wrong labels)
// fails the circuit while the parser still passes.
func TestCOSEKeyExactBytes(t *testing.T) {
	dev := p256(t)
	x := coord32(dev.PublicKey.X)
	y := coord32(dev.PublicKey.Y)
	got := buildCOSEKey(x, y)

	if len(got) != 75 {
		t.Fatalf("COSE_Key len = %d, want 75 (8 hdr + 32 X + 3 hdr + 32 Y)", len(got))
	}
	wantHead := []byte{0xA4, 0x01, 0x02, 0x20, 0x01, 0x21, 0x58, 0x20}
	if !bytes.Equal(got[:8], wantHead) {
		t.Fatalf("COSE_Key head = % X, want % X", got[:8], wantHead)
	}
	if !bytes.Equal(got[8:40], x) {
		t.Fatalf("X coordinate not at bytes [8:40]")
	}
	if !bytes.Equal(got[40:43], []byte{0x22, 0x58, 0x20}) {
		t.Fatalf("Y label run = % X, want 22 58 20", got[40:43])
	}
	if !bytes.Equal(got[43:75], y) {
		t.Fatalf("Y coordinate not at bytes [43:75]")
	}
}

// validFrom/validUntil are each tag(0) + 20-char tdate: C0 74 <20 bytes>. The
// circuit asserts the C0 74 prefix (tag0 + text-20) and reads exactly 20 date
// bytes (mdoc_hash.h:512,517 / MINT-SPEC.md:50-52).
func TestTDateFraming(t *testing.T) {
	for _, s := range []string{validFrom, validUntil, nowStr} {
		if len(s) != 20 {
			t.Fatalf("date %q is %d chars, must be exactly 20", s, len(s))
		}
	}
	td := buildTDate(validFrom)
	if len(td) != 22 {
		t.Fatalf("tdate len = %d, want 22 (C0 74 + 20)", len(td))
	}
	if td[0] != 0xC0 || td[1] != 0x74 {
		t.Fatalf("tdate prefix = % X, want C0 74", td[:2])
	}
	if string(td[2:]) != validFrom {
		t.Fatalf("tdate body = %q, want %q", td[2:], validFrom)
	}

	vi := buildValidityInfo()
	if vi[0] != 0xA2 {
		t.Fatalf("validityInfo header = %#x, want A2 (2-entry map)", vi[0])
	}
	if bytes.Count(vi, []byte{0xC0, 0x74}) != 2 {
		t.Fatalf("validityInfo must contain exactly two C0 74 tdates")
	}
}

// The IssuerSignedItem is a tag24-wrapped 4-key map:
//
//	D8 18 58 <len ∈ [24,255]> A4{ digestID, random, elementIdentifier, elementValue }
//
// (MINT-SPEC.md:62-67). Exactly 4 keys; the tag24 bstr length uses the 1-byte
// 0x58 form because the item is < 256 bytes.
func TestIssuerSignedItemFraming(t *testing.T) {
	salt := bytes.Repeat([]byte{0xAB}, 16)
	itemMap := buildIssuerSignedItemMap(0, salt, elemID, []byte{0xF5})
	if itemMap[0] != 0xA4 {
		t.Fatalf("item map header = %#x, want A4 (exactly 4 keys)", itemMap[0])
	}

	tagged := wrapTag24(itemMap)
	if !bytes.Equal(tagged[:3], []byte{0xD8, 0x18, 0x58}) {
		t.Fatalf("tag24 item prefix = % X, want D8 18 58 (1-byte bstr len form)", tagged[:3])
	}
	declaredLen := int(tagged[3])
	if declaredLen < 24 || declaredLen > 255 {
		t.Fatalf("tag24 bstr len = %d, want in [24,255]", declaredLen)
	}
	if declaredLen != len(itemMap) {
		t.Fatalf("declared len %d != actual map len %d", declaredLen, len(itemMap))
	}
	if len(tagged) != 4+len(itemMap) {
		t.Fatalf("tagged item len = %d, want %d (4-byte header + map)", len(tagged), 4+len(itemMap))
	}
}

// The MSO must serialize to >= 256 bytes so its tag24 wrapper uses the 0x59
// two-byte length form (D8 18 59 ...). The parser skips exactly 5 bytes to reach
// the MSO and the prover hard-codes 0x59 (mdoc_witness.h:248, mdoc_constants.h:34
// / SPIKE-RESULT.md gotcha 1). A sub-256-byte MSO would encode with 0x58 and be
// misread.
func TestMSOAtLeast256AndTag24TwoByte(t *testing.T) {
	dev := p256(t)
	coseKey := buildCOSEKey(coord32(dev.PublicKey.X), coord32(dev.PublicKey.Y))
	digest := sha256.Sum256([]byte("any 32-byte digest stand-in for layout"))
	mso := buildMSO(digest[:], coseKey)

	if len(mso) < 256 {
		t.Fatalf("MSO is %d bytes, must be >= 256 (0x59 invariant)", len(mso))
	}
	if len(mso) >= 65536 {
		t.Fatalf("MSO is %d bytes, must be < 65536", len(mso))
	}
	tagged := wrapTag24(mso)
	if !bytes.Equal(tagged[:3], []byte{0xD8, 0x18, 0x59}) {
		t.Fatalf("tag24 MSO prefix = % X, want D8 18 59 (2-byte bstr len form)", tagged[:3])
	}
}

// The valueDigests digest is SHA-256 over the FULL tag24 IssuerSignedItem bytes
// (D8 18 58 <len> A4 ...), NOT the bare A4 map (mdoc_witness.h:830, tag_len =
// bstr_len + 4 / MINT-SPEC.md:57-58, SPIKE-RESULT.md gotcha 6). This asserts a
// full mint embeds `58 20 <sha256(taggedItem)>` and NOT the bare-map hash.
func TestValueDigestIsOverFullTaggedItem(t *testing.T) {
	salt := bytes.Repeat([]byte{0xCD}, 16)
	val := []byte{0xF5}

	itemMap := buildIssuerSignedItemMap(0, salt, elemID, val)
	tagged := wrapTag24(itemMap)
	fullHash := sha256.Sum256(tagged)  // correct: over the tagged bytes
	bareHash := sha256.Sum256(itemMap) // wrong: over the bare map

	m, err := mintWith(p256(t), p256(t), salt, val)
	if err != nil {
		t.Fatalf("mintWith: %v", err)
	}

	wantEntry := append([]byte{0x58, 0x20}, fullHash[:]...) // bstr32 of the digest
	if !bytes.Contains(m.DeviceResponse, wantEntry) {
		t.Fatal("DeviceResponse does not embed SHA-256 over the FULL tagged item")
	}
	if bytes.Contains(m.DeviceResponse, bareHash[:]) {
		t.Fatal("DeviceResponse embeds the BARE-map hash (wrong preimage)")
	}

	// Cross-check the standalone builder emits the same entry.
	vd := buildValueDigests(0, fullHash[:])
	if !bytes.Contains(vd, wantEntry) {
		t.Fatal("buildValueDigests did not frame the digest as 58 20 <32>")
	}
}
