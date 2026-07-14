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

// TestPresentationsOfSameCredentialAreUnlinkable asserts the property PRD §7.3
// calls the black-box check, in the strong form: the verifier-visible envelope is
// identical not just across two presentations of ONE credential (which alone could
// be satisfied trivially), but across presentations of DIFFERENT credentials from
// the same issuer.
//
// That equality is what makes the claim mean something. It says the envelope
// distinguishes NOTHING at the credential level: a1 and a2 are linkable to each
// other by exactly as much as a1 is linkable to b1 — which is to say, by the
// issuer's own certificate, and nothing else.
//
// It is genuinely falsifiable: had the salt, an MSO digest, the device key, or the
// issuerAuth signature leaked into the wire envelope, b1 would differ from a1 and
// this test would go red. Those are precisely the credential-unique values, and
// they are precisely what the ZK proof exists to keep out of the envelope.
func TestPresentationsOfSameCredentialAreUnlinkable(t *testing.T) {
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
