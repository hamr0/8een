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

// sharedKGrams counts the DISTINCT k-byte sequences that occur in both a and b.
//
// This is the detector for a stable per-credential identifier hiding in the proof
// bytes. If two presentations of one credential embedded a common value of k bytes
// or more -- a credential id, a device-key-derived tag, an unrandomised commitment
// -- they would share k-grams that presentations of DIFFERENT credentials do not.
// Comparing same-credential overlap against different-credential overlap is what
// turns that into a falsifiable statement, and it needs no knowledge of longfellow's
// internals: it reads the proof as an opaque blob, which is precisely what a
// colluding pair of verifiers would do.
func sharedKGrams(a, b []byte, k int) int {
	if len(a) < k || len(b) < k {
		return 0
	}
	seen := make(map[string]struct{}, len(a))
	for i := 0; i+k <= len(a); i++ {
		seen[string(a[i:i+k])] = struct{}{}
	}
	shared := make(map[string]struct{})
	for i := 0; i+k <= len(b); i++ {
		g := string(b[i : i+k])
		if _, ok := seen[g]; ok {
			shared[g] = struct{}{}
		}
	}
	return len(shared)
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

	const k = 8 // 8 bytes: far beyond what random 360 KB blobs collide on by chance

	self := sharedKGrams(proofA1, proofA1, k) // control: the detector working
	same := sharedKGrams(proofA1, proofA2, k) // SAME credential, two sessions
	diff := sharedKGrams(proofA1, proofB1, k) // DIFFERENT credentials, same issuer

	t.Logf("shared distinct %d-grams -- self:%d  same-credential:%d  different-credential:%d", k, self, same, diff)

	// HARNESS CONTROL. If this fails, every number above is meaningless and the
	// null result below would be an artifact rather than a finding.
	if self < 1000 {
		t.Fatalf("the detector cannot even find a proof inside itself (self=%d) -- the harness is broken, not the crypto", self)
	}

	// THE ASSERTION. Two presentations of the SAME credential must not share
	// materially more than two presentations of DIFFERENT credentials do. Whatever
	// baseline overlap exists (structural constants, encoding padding) is shared by
	// both pairs; an IDENTIFIER would show up only in `same`.
	//
	// The margin is deliberately tight: an identifier worth having is at least a few
	// bytes, and at k=8 even a single 16-byte tag would contribute ~9 distinct grams.
	const margin = 8
	if same > diff+margin {
		t.Fatalf("two presentations of the SAME credential share %d distinct %d-grams, but two DIFFERENT credentials "+
			"share only %d -- the excess is a stable per-credential identifier in the proof bytes, and the presentations are LINKABLE",
			same, k, diff)
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
