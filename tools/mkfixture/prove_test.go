//go:build cgo

package main

// prove_test.go — cgo discrimination tests. These call the real prover/verifier,
// so they only run where the longfellow clone is materialized AND its static lib
// is linked (the whole package requires that to build under cgo). They skip
// cleanly when the circuit file is absent, mirroring how test/integration.test.js
// skips when the POC clone is not materialized.
//
// Ported verbatim in intent from poc/m2-spike/neg_test.go: a proof that verifies
// is worthless unless a proof that must NOT verify is rejected.

import (
	"os"
	"path/filepath"
	"testing"
)

// testCircuitDir mirrors main.go's default, resolved from the package dir.
const testCircuitDir = "../../poc/longfellow-zk/lib/circuits/mdoc/circuits"

// loadCircuit reads the 1-attribute circuit, or skips if the clone is absent.
func loadCircuit(t *testing.T) []byte {
	t.Helper()
	path := filepath.Join(testCircuitDir, circuitHash0)
	c, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("POC clone not materialized (see poc/M0-EVIDENCE.md step 1): %v", err)
	}
	return c
}

// TestAcceptThenReject proves DISCRIMINATION, not just acceptance:
//  1. a valid proof from our minted credential verifies (SUCCESS), and
//  2. the SAME proof verified against a DIFFERENT issuer key is REJECTED.
//
// (2) is the trust boundary. If a proof verified under an issuer key that did not
// sign it, the one-bit verdict would be meaningless — this is exactly the
// "rejects a proof chained to a cert NOT on the list" criterion (PRD §7.1).
func TestAcceptThenReject(t *testing.T) {
	circuit := loadCircuit(t)
	over18 := []byte{0xF5}

	m1, err := Mint(over18)
	if err != nil {
		t.Fatalf("mint m1: %v", err)
	}
	proof, _, pCode := RunProver(circuit, m1, over18)
	if pCode != 0 {
		t.Fatalf("prover on m1 failed: code %d", pCode)
	}

	// (1) correct issuer key -> accept.
	if _, vCode := RunVerifier(circuit, m1, proof, over18); vCode != 0 {
		t.Fatalf("valid proof rejected under its own issuer key: code %d", vCode)
	}
	t.Log("valid proof accepted under correct issuer key")

	// (2) wrong issuer key (a second, independently minted credential's key, so it
	// is a well-formed P-256 point that simply did not sign this proof) -> must
	// NOT succeed.
	m2, err := Mint(over18)
	if err != nil {
		t.Fatalf("mint m2: %v", err)
	}
	wrong := *m1 // same transcript, docType, proof context...
	wrong.IssuerPkX = m2.IssuerPkX
	wrong.IssuerPkY = m2.IssuerPkY // ...but the wrong issuer key

	name, vCode := RunVerifier(circuit, &wrong, proof, over18)
	if vCode == 0 {
		t.Fatal("SECURITY FAILURE: proof verified under an issuer key that did not sign it")
	}
	t.Logf("proof correctly REJECTED under wrong issuer key: %s", name)
}

// TestGeneratorRefusesFixtureThatDoesNotMatchItsClaim pins the self-check that
// stands between a generator bug and a red JS suite that blames the verifier.
//
// Both halves matter, and both are non-vacuous here:
//
//   - A leaf carrying a key OTHER than the one that signed the MSO must be refused.
//     Such a fixture chains and validates perfectly; the service just extracts the
//     wrong (pkx,pky), and every proof then fails looking exactly like bad crypto.
//   - A proof that VERIFIES must be refused when the scenario claims it should not.
//     That is what makes the "tampered" fixture trustworthy: if the byte-flip ever
//     lands on an inert byte, generation fails instead of shipping a negative test
//     that silently passes.
func TestGeneratorRefusesFixtureThatDoesNotMatchItsClaim(t *testing.T) {
	circuit := loadCircuit(t)
	over18 := []byte{0xF5}

	m, err := Mint(over18)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	proof, pName, pCode := RunProver(circuit, m, over18)
	if pCode != 0 {
		t.Fatalf("prover failed: %s", pName)
	}

	nb, na := certWindow()
	ca, caKey, err := makeCA("8een M2 self-check CA", nb, na)
	if err != nil {
		t.Fatalf("CA: %v", err)
	}

	// A second, unrelated issuer key — a well-formed P-256 key that simply did not
	// sign this MSO.
	other, err := Mint(over18)
	if err != nil {
		t.Fatalf("mint other: %v", err)
	}

	badLeaf, err := makeLeaf(ca, caKey, &other.IssuerKey.PublicKey, nb, na)
	if err != nil {
		t.Fatalf("bad leaf: %v", err)
	}
	if _, err := assertFixtureVerifies(circuit, m, proof, badLeaf, over18, expectAccept); err == nil {
		t.Fatal("generator emitted a fixture whose leaf does not carry the MSO-signing key")
	} else {
		t.Logf("refused wrong-key leaf: %v", err)
	}

	goodLeaf, err := makeLeaf(ca, caKey, &m.IssuerKey.PublicKey, nb, na)
	if err != nil {
		t.Fatalf("good leaf: %v", err)
	}

	// Non-vacuity: the correctly-wired fixture must PASS the same check.
	if _, err := assertFixtureVerifies(circuit, m, proof, goodLeaf, over18, expectAccept); err != nil {
		t.Fatalf("generator rejected a correctly-wired fixture: %v", err)
	}
	t.Log("accepted the correctly-wired fixture")

	// A verifying proof labelled expectReject must be refused — the guard that keeps
	// an inert byte-flip from shipping as a passing negative fixture.
	if _, err := assertFixtureVerifies(circuit, m, proof, goodLeaf, over18, expectReject); err == nil {
		t.Fatal("generator would have shipped a 'must not verify' fixture whose proof verifies")
	} else {
		t.Logf("refused a verifying proof labelled expectReject: %v", err)
	}
}

// TestCircuitIDIsCheckedNotAssumed: longfellow disables its own circuit-id
// enforcement (mdoc_zk.cc:112-113) and delegates the check to the application, so a
// corrupted circuit under the right FILENAME must be caught by us or not at all.
func TestCircuitIDIsCheckedNotAssumed(t *testing.T) {
	circuit := loadCircuit(t)

	id, err := CircuitID(circuit)
	if err != nil {
		t.Fatalf("circuit_id on the real circuit: %v", err)
	}
	if id != circuitHash0 {
		t.Fatalf("circuit id = %s, want %s", id, circuitHash0)
	}

	// A truncated circuit must NOT yield the expected id.
	truncated := circuit[:len(circuit)/2]
	badID, err := CircuitID(truncated)
	if err == nil && badID == circuitHash0 {
		t.Fatal("a truncated circuit produced the expected circuit id")
	}
	t.Logf("truncated circuit refused (id=%q err=%v)", badID, err)
}

// TestCannotForgeOver18FromUnder18 is THE product-defining test: a holder whose
// credential says age_over_18 = FALSE must not be able to produce a proof that
// verifies age_over_18 = TRUE. This is "turn away the minor." If it fails, the
// whole thing is worthless however cleanly it verifies honest proofs.
//
// We mint a validly-issuer-signed UNDER-18 credential (elementValue 0xF4 = false),
// then a malicious holder requests to open age_over_18 as TRUE (0xF5). The end
// result must be rejection — whether the prover refuses or the verifier rejects
// the resulting proof, both are correct; SUCCESS+SUCCESS would be catastrophic.
func TestCannotForgeOver18FromUnder18(t *testing.T) {
	circuit := loadCircuit(t)

	// Mint an under-18 credential: age_over_18 = false.
	m, err := Mint([]byte{0xF4})
	if err != nil {
		t.Fatalf("mint under-18 credential: %v", err)
	}

	// Malicious holder asks the prover to open age_over_18 = true (the lie).
	lie := []byte{0xF5}
	proof, pName, pCode := RunProver(circuit, m, lie)
	if pCode != 0 {
		t.Logf("prover REFUSED to forge over-18 from under-18 credential: %s", pName)
		return // correct outcome — no proof to check
	}

	// Prover produced a proof; the verifier MUST reject it.
	vName, vCode := RunVerifier(circuit, m, proof, lie)
	if vCode == 0 {
		t.Fatal("SECURITY FAILURE: verified age_over_18=true from an age_over_18=false credential")
	}
	t.Logf("verifier REJECTED forged over-18 proof: %s", vName)
}
