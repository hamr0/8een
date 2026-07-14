//go:build cgo

package main

// The structural half of PRD §7.3. The behavioural half — that the verifier
// returns indistinguishable verdicts for every presentation — lives in the JS
// integration suite, against the real service.
//
// The split is not arbitrary. Reading DocumentData back out of a fixture means
// decoding CBOR, and 8een does not write CBOR parsing (NO-GO #8). Here in the
// dev-only generator the wire library is already a legitimate dependency, so the
// byte-level claim is asserted where it can be asserted honestly, rather than
// hand-rolled into the test suite of a package whose whole point is that it parses
// nothing itself.
//
// WHAT THIS DOES NOT SHOW, stated plainly: that longfellow's PROOF bytes carry no
// hidden per-credential identifier. That is the cryptographic claim, and PRD §7.3
// scopes it as "cited, not claimed" — it rests on the scheme's own security
// analysis, not on a test we could write. What is testable, and is tested here, is
// that the envelope the verifier reads alongside the proof leaks nothing.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

// documentDataAndProof decodes a fixture down to the two byte runs the verifier
// actually consumes.
func documentDataAndProof(t *testing.T, path string) (documentData, proof []byte) {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var wire struct {
		Transcript           string
		ZKDeviceResponseCBOR string
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	respBytes, err := base64.StdEncoding.DecodeString(wire.ZKDeviceResponseCBOR)
	if err != nil {
		t.Fatalf("base64 %s: %v", path, err)
	}
	var resp zkDeviceResponseIso
	if err := cbor.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("cbor %s: %v", path, err)
	}
	if len(resp.ZKDocuments) != 1 {
		t.Fatalf("%s: %d ZKDocuments, want 1", path, len(resp.ZKDocuments))
	}
	return resp.ZKDocuments[0].DocumentData, resp.ZKDocuments[0].Proof
}

// shareRunOfLength reports whether a and b share any contiguous run of exactly k
// bytes.
func shareRunOfLength(a, b []byte, k int) bool {
	if k <= 0 || len(a) < k || len(b) < k {
		return false
	}
	seen := make(map[string]struct{}, len(a))
	for i := 0; i+k <= len(a); i++ {
		seen[string(a[i:i+k])] = struct{}{}
	}
	for i := 0; i+k <= len(b); i++ {
		if _, ok := seen[string(b[i:i+k])]; ok {
			return true
		}
	}
	return false
}

// longestCommonRun returns the length of the longest contiguous byte run present in
// BOTH a and b.
//
// This is the detector for a stable per-credential identifier hiding in the proof
// bytes: any value of L bytes shared by two presentations forces the longest common
// run to at least L. It reads the proof as an opaque blob — exactly what a colluding
// pair of verifiers would do — and needs no knowledge of longfellow's internals.
//
// It replaces a "count shared 8-grams, allow a margin of 8" metric that a review
// showed was blind by construction: an identifier of L bytes contributes only L-7
// distinct 8-grams, so anything under 16 bytes — an 8-byte credential serial, say,
// the very thing the test hunts — fell under the margin and was invisible. A longest
// common RUN has no such floor: an 8-byte identifier moves it to 8, full stop.
//
// Binary search on length; the run-length property is monotone (if a run of length k
// is shared, so is every shorter one, since every k-run contains a (k-1)-run).
//
// The search is capped at maxRunProbe. That is not a fudge: it bounds memory (the
// probe holds a map of ~360k keys, so an uncapped search would first try a run of
// ~180 KB and allocate tens of gigabytes — it OOM-killed the test run that found
// this), and any shared run even approaching the cap is already a catastrophic
// finding. A capped result is reported as ">= maxRunProbe" by the caller, never
// silently clamped into a pass.
const maxRunProbe = 64

func longestCommonRun(a, b []byte) int {
	hi := maxRunProbe
	if len(a) < hi {
		hi = len(a)
	}
	if len(b) < hi {
		hi = len(b)
	}
	lo := 0
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if shareRunOfLength(a, b, mid) {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// TestProofBytesCarryNoPerCredentialIdentifier is the black-box unlinkability check
// that can actually FAIL.
//
// The two assertions in TestPresentationsOfSameCredentialAreUnlinkable cannot: the
// envelope is assembled by our own packageFixture out of fields that are constant
// across credentials, so its equality is a property of the generator, not a
// discovery about the protocol. That test is still worth keeping as a change
// detector -- see its comment -- but it is NOT evidence, and it must not be sold as
// evidence.
//
// This one compares the only thing that actually varies per presentation: the proof.
// If longfellow leaked a stable per-credential value into it, the same-credential
// overlap would exceed the different-credential overlap by roughly that value's
// size. The self-comparison is the harness control: it proves the detector can see
// an identifier when one is there, so a null result means "no identifier found"
// rather than "the test is broken".
// linkable is THE predicate, factored out so the positive control below runs the
// exact same decision the real assertion runs — not a paraphrase of it.
//
// A pair is linkable if the run it shares exceeds the BASELINE — what two DIFFERENT
// credentials from the same issuer already share — by more than measurement noise.
// Using the different-credential pair as the baseline is what makes this meaningful:
// it subtracts off whatever the proofs have in common structurally, leaving only what
// is specific to the credential.
func linkable(sameRun, diffRun, floor int) bool {
	baseline := diffRun
	if floor > baseline {
		baseline = floor
	}
	return sameRun > baseline+noiseMargin
}

// structuralFloor is the longest run ANY two of these proofs share, identifier or
// not: encoding constants, framing, padding. MEASURED at 8 bytes — for both the
// same-credential and the different-credential pair — which is well above the ~5 B a
// pair of truly random 360 KB blobs would collide on, so it is structure, not chance.
//
// noiseMargin keeps a one-off ±1 wobble in that background from being read as an
// identifier and making the suite flaky.
const (
	structuralFloor = 8
	noiseMargin     = 2
)

// DETECTION FLOOR, stated plainly rather than buried: this method detects a
// contiguous per-credential identifier of about 11 bytes or more (baseline 8 + margin
// 2, exceeded). It CANNOT detect one of 8 bytes or fewer — an 8-byte credential
// serial sits inside the structural background and is invisible to it. That is not a
// hypothetical: the positive control below was originally written with an 8-byte tag,
// and it correctly REFUSED to pass, which is how the floor was discovered rather than
// assumed. Nor can it detect an identifier that is encrypted, split, or spread across
// non-contiguous bytes. What it rules out is a naive, contiguous one of >= 11 bytes —
// which is the shape a leaked serial, UUID, device-key hash or unrandomised commitment
// would actually take. Full cryptographic unlinkability remains cited, not claimed
// (PRD §7.3).

func TestProofBytesCarryNoPerCredentialIdentifier(t *testing.T) {
	circuit := loadCircuit(t)

	fixtures, _, err := unlinkabilitySet(circuit)
	if err != nil {
		t.Fatalf("unlinkabilitySet: %v", err)
	}
	dir := t.TempDir()
	for name, fx := range fixtures {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), fx, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	_, proofA1 := documentDataAndProof(t, filepath.Join(dir, "unlinkable-a1.json"))
	_, proofA2 := documentDataAndProof(t, filepath.Join(dir, "unlinkable-a2.json"))
	_, proofB1 := documentDataAndProof(t, filepath.Join(dir, "unlinkable-b1.json"))

	sameRun := longestCommonRun(proofA1, proofA2) // SAME credential, two sessions
	diffRun := longestCommonRun(proofA1, proofB1) // DIFFERENT credentials, same issuer

	t.Logf("longest common run — same-credential:%dB  different-credential:%dB  (structural floor %dB, margin %dB)",
		sameRun, diffRun, structuralFloor, noiseMargin)

	// The measured background must not have drifted out from under the floor above; if
	// it has, the threshold is stale and the null result cannot be trusted.
	if diffRun > structuralFloor+noiseMargin {
		t.Fatalf("different-credential baseline is %dB, above the declared structural floor of %dB — "+
			"the threshold this test reasons against is stale; re-measure it, do not widen it to make this pass", diffRun, structuralFloor)
	}

	// POSITIVE CONTROL — the guard, watched firing.
	//
	// The previous version used sharedKGrams(proofA1, proofA1) as its "control": a blob
	// compared with itself. It could never fail, never once exercised cross-blob
	// detection, and certified a detector nobody had watched detect anything. A review
	// caught it. It is the same mistake this repo keeps finding — a guard you have not
	// watched FIRE is not a guard — committed inside the very test written to enforce it.
	//
	// So: plant a known identifier from a1 into a copy of b1 and require the REAL
	// predicate to flag it. This is what fixes the detection floor honestly: written
	// first with an 8-byte tag, it FAILED — the background is already 8 B — which is
	// how we learned an 8-byte identifier is invisible to this method, rather than
	// assuming it wasn't.
	const tagLen = 16 // a serial / UUID / key-hash — comfortably above the 8B background
	planted := append([]byte(nil), proofB1...)
	copy(planted[5000:], proofA1[1234:1234+tagLen])

	plantedRun := longestCommonRun(proofA1, planted)
	if plantedRun < tagLen {
		t.Fatalf("planted a %dB identifier and the detector only found a %dB run — it cannot see what it is looking for",
			tagLen, plantedRun)
	}
	if !linkable(plantedRun, diffRun, structuralFloor) {
		t.Fatalf("planted a %dB per-credential identifier (run=%dB, baseline=%dB) and the predicate did NOT call it linkable — "+
			"this test cannot fail, and the null result below would be worthless",
			tagLen, plantedRun, diffRun)
	}
	t.Logf("positive control: planted %dB identifier -> run %dB -> correctly flagged LINKABLE", tagLen, plantedRun)

	// THE ASSERTION. The detector has just been watched catching a planted identifier,
	// so a null result here is a finding rather than an artifact.
	if linkable(sameRun, diffRun, structuralFloor) {
		t.Fatalf("two presentations of the SAME credential share a %dB run, while two DIFFERENT credentials share only %dB — "+
			"the excess is a stable per-credential identifier in the proof bytes, and the presentations are LINKABLE",
			sameRun, diffRun)
	}
}

// TestEnvelopeCarriesNothingCredentialSpecific asserts that the verifier-visible
// envelope is byte-identical across a1, a2 AND b1 — so it distinguishes nothing at
// the credential level.
//
// BE HONEST ABOUT WHAT THIS IS: a CHANGE DETECTOR over our own wire format, not
// evidence about the protocol. packageFixture assembles DocumentData from the
// docType, the zk system id, the claimed element value, the cert chain and the
// timestamp — and unlinkabilitySet hands all three presentations the same leaf, the
// same CA and the same claimed value. The equality below is therefore guaranteed by
// construction: no code path exists by which a salt, an MSO digest or the device key
// could reach this struct. An earlier version of this comment called it "genuinely
// falsifiable", which was wrong, and a code review caught it. A test authored to
// contain the phenomenon it tests can only ever confirm it.
//
// It still earns its place: if someone later widens the envelope — a serial, a holder
// binding, a per-credential hint — b1 stops matching a1 and this goes red. That is
// worth having. It is simply not proof of anything.
//
// The falsifiable check is TestProofBytesCarryNoPerCredentialIdentifier above, which
// probes the only thing that genuinely varies per presentation: the proof bytes.
func TestEnvelopeCarriesNothingCredentialSpecific(t *testing.T) {
	circuit := loadCircuit(t)

	fixtures, _, err := unlinkabilitySet(circuit)
	if err != nil {
		t.Fatalf("unlinkabilitySet: %v", err)
	}

	dir := t.TempDir()
	for name, fx := range fixtures {
		if err := os.WriteFile(filepath.Join(dir, name+".json"), fx, 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	ddA1, proofA1 := documentDataAndProof(t, filepath.Join(dir, "unlinkable-a1.json"))
	ddA2, proofA2 := documentDataAndProof(t, filepath.Join(dir, "unlinkable-a2.json"))
	ddB1, proofB1 := documentDataAndProof(t, filepath.Join(dir, "unlinkable-b1.json"))

	// The same credential, presented twice, must not look the same on the wire --
	// otherwise "unlinkable" would just mean "we sent identical bytes twice", and
	// every assertion below would be vacuous.
	if bytes.Equal(proofA1, proofA2) {
		t.Fatal("two presentations of the same credential produced a byte-identical proof: " +
			"the proof is a stable per-credential identifier, which is exactly what must not happen")
	}
	if bytes.Equal(proofA1, proofB1) || bytes.Equal(proofA2, proofB1) {
		t.Fatal("different credentials produced an identical proof")
	}

	// The load-bearing assertion.
	if !bytes.Equal(ddA1, ddA2) {
		t.Fatalf("the verifier-visible envelope differs between two presentations of the SAME credential:\n a1: %x\n a2: %x",
			ddA1, ddA2)
	}
	if !bytes.Equal(ddA1, ddB1) {
		t.Fatalf("the verifier-visible envelope distinguishes two DIFFERENT credentials from the same issuer -- "+
			"something credential-specific (a salt? a digest? the device key?) is leaking into it, and it links presentations:\n a1: %x\n b1: %x",
			ddA1, ddB1)
	}

	// NON-VACUITY. Everything above is an equality assertion, and an equality
	// assertion over a field that is empty, constant, or never actually compared
	// would pass just as happily while proving nothing. So: show the comparison can
	// see a difference when there IS one. A second issuer means a second CA and a
	// second document-signer cert, both of which live in the envelope, so its
	// envelope MUST differ. If this comes back equal, the assertions above are
	// worthless and the test is lying.
	other, _, err := unlinkabilitySet(circuit)
	if err != nil {
		t.Fatalf("second issuer: %v", err)
	}
	otherDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(otherDir, "unlinkable-a1.json"), other["unlinkable-a1"], 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	ddOther, _ := documentDataAndProof(t, filepath.Join(otherDir, "unlinkable-a1.json"))
	if bytes.Equal(ddA1, ddOther) {
		t.Fatal("a credential from a DIFFERENT issuer produced an identical envelope -- " +
			"this comparison cannot detect a difference, so the equalities asserted above mean nothing")
	}

	t.Logf("envelope identical across all 3 presentations (%d bytes); proofs pairwise distinct (%d/%d/%d bytes); "+
		"a different issuer's envelope does differ (%d bytes) -- the comparison discriminates",
		len(ddA1), len(proofA1), len(proofA2), len(proofB1), len(ddOther))
}
