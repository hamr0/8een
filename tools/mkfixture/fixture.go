//go:build cgo

package main

// fixture.go — closes the loop from the raw run_mdoc_prover proof to the ACTUAL
// longfellow verifier SERVICE wire format ({Transcript, ZKDeviceResponseCBOR}
// JSON) with a real x509 issuer cert chain.
//
// The service (reference/verifier-service/server) does MORE than the raw prover:
// it decodes the ZKDeviceResponseCBOR, parses the MsoX5chain into x509 certs,
// requires the signer cert be ECDSA P-256, and VERIFIES THE CHAIN against the
// -cacerts PEM before extracting (pkx,pky) from the signer cert and calling
// run_mdoc_verifier. So the trust boundary IS the PEM. This generator produces,
// per scenario, a fixture JSON, and records which CA (if any) is trusted.
//
// The OUTER wire structs below are marshalled with fxamacker/cbor (a library),
// which is correct here and the exact opposite of the inner mdoc byte layout in
// mint.go: fxamacker encodes a Go struct as a CBOR map keyed by field NAME, and
// the service unmarshals by case-insensitive field name, so order is irrelevant
// and no canonical/CTAP2 mode is wanted (FIXTURE-RESULT.md gotcha 3).

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/fxamacker/cbor/v2"
)

// ---- service wire structs, replicated from reference/.../zk/cbor.go ----

type zkSignedItem struct {
	ElementIdentifier string
	ElementValue      cbor.RawMessage
}

type zkDocumentDataIso struct {
	DocType      string
	ZkSystemId   string
	IssuerSigned map[string][]zkSignedItem
	MsoX5chain   any
	Timestamp    string
}

type zkDocumentIso struct {
	DocumentData []byte
	Proof        []byte
}

type zkDeviceResponseIso struct {
	Version     string
	ZKDocuments []zkDocumentIso
	Status      uint
}

// serial hands out unique-enough cert serial numbers.
func serial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	return n
}

// certWindow is deliberately relative to the REAL wall clock: now-1yr .. now+1yr.
// This is the whole point: the fixtures are natively valid on the real clock, so
// the JS integration suite can drop ZKVERIFY_FAKE_TIME (the M0/M1 scaffolding
// that pinned x509 verification time to keep the stale upstream fixture's chain
// valid). This x509 clock is entirely separate from the circuit's `nowStr` clock.
func certWindow() (time.Time, time.Time) {
	now := time.Now()
	return now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0)
}

// makeCA mints a self-signed P-256 CA (IsCA), as the service's generateTestCA does.
func makeCA(org string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	nb, na := certWindow()
	tmpl := x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{Organization: []string{org}, CommonName: org},
		NotBefore:             nb,
		NotAfter:              na,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	return cert, priv, err
}

// makeLeaf mints a document-signer (leaf) cert whose SUBJECT PUBLIC KEY is the
// issuer MSO-signing key (subjectPub), signed by the CA. This is the load-bearing
// wiring (FIXTURE-RESULT.md gotcha 1): validateIssuerKey extracts (pkx,pky) from
// THIS cert and hands it to run_mdoc_verifier, and the proof only verifies under
// the key that signed the MSO issuerAuth. Get it wrong and you get Status:false
// with a valid chain — indistinguishable at a glance from a bad proof.
func makeLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, subjectPub *ecdsa.PublicKey) (*x509.Certificate, error) {
	nb, na := certWindow()
	tmpl := x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{Organization: []string{"8een M2 Document Signer"}, CommonName: "8een-test-ds"},
		NotBefore:    nb,
		NotAfter:     na,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, ca, subjectPub, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// packageFixture builds the {Transcript, ZKDeviceResponseCBOR} JSON the service
// consumes. wireValue is the CBOR the holder CLAIMS for age_over_18 in the wire
// envelope (normally identical to the proven value; a mismatch is how a lying
// echo / tamper scenario is expressed).
func packageFixture(m *MintResult, proof []byte, leaf, ca *x509.Certificate, wireValue []byte) ([]byte, error) {
	// x5chain as a single CBOR byte string = leaf DER || CA DER (FIXTURE-RESULT.md
	// gotcha 2). getFirstCert's []byte branch returns the whole run and
	// x509.ParseCertificates parses BOTH into [leaf, CA]; an [][]byte array would
	// drop everything past element 0, dropping the CA.
	x5 := append(append([]byte{}, leaf.Raw...), ca.Raw...)

	dd := zkDocumentDataIso{
		DocType:    m.DocType,
		ZkSystemId: circuitHash0,
		IssuerSigned: map[string][]zkSignedItem{
			namespace: {{
				ElementIdentifier: elemID,
				ElementValue:      cbor.RawMessage(append([]byte{}, wireValue...)),
			}},
		},
		MsoX5chain: x5,
		Timestamp:  nowStr,
	}
	ddBytes, err := cbor.Marshal(dd)
	if err != nil {
		return nil, fmt.Errorf("marshal DocumentData: %w", err)
	}
	resp := zkDeviceResponseIso{
		Version:     "1.0",
		ZKDocuments: []zkDocumentIso{{DocumentData: ddBytes, Proof: proof}},
		Status:      0,
	}
	respBytes, err := cbor.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshal DeviceResponse: %w", err)
	}
	out := map[string]string{
		"Transcript":           base64.StdEncoding.EncodeToString(m.Transcript),
		"ZKDeviceResponseCBOR": base64.StdEncoding.EncodeToString(respBytes),
	}
	return json.MarshalIndent(out, "", "  ")
}

// scenario mints a credential with a given age_over_18 value, produces a real
// proof (requesting that same value), wraps it in a fresh CA+leaf chain, and
// optionally tampers the proof. Returns the fixture JSON and the CA DER (for the
// trust PEM). credValue is both the minted elementValue AND the requested
// attribute value; wireValue is only what the wire envelope claims.
func scenario(circuit []byte, name string, credValue, wireValue []byte, tamper bool) (fixture, caDER []byte, err error) {
	m, err := Mint(credValue)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: mint: %w", name, err)
	}
	proof, pName, pCode := RunProver(circuit, m, credValue)
	if pCode != 0 {
		return nil, nil, fmt.Errorf("%s: prover failed: %s", name, pName)
	}

	if tamper {
		// Flip one byte deep in the proof body (avoid the very start/end framing).
		i := len(proof) / 2
		proof[i] ^= 0xFF
	}

	ca, caKey, err := makeCA("8een M2 Test Issuer CA")
	if err != nil {
		return nil, nil, fmt.Errorf("%s: CA: %w", name, err)
	}
	leaf, err := makeLeaf(ca, caKey, &m.IssuerKey.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: leaf: %w", name, err)
	}

	fixture, err = packageFixture(m, proof, leaf, ca, wireValue)
	if err != nil {
		return nil, nil, err
	}
	nb, naft := certWindow()
	fmt.Printf("  [%s] proof=%dB  DS-key=%s...  cert %s..%s\n",
		name, len(proof), m.IssuerPkX[:18], nb.Format("2006-01-02"), naft.Format("2006-01-02"))
	return fixture, ca.Raw, nil
}

// GenFixtures writes the four-scenario fixture set + trust PEM into outDir. The
// circuit is read from circuitDir/<circuitHash0>.
func GenFixtures(circuitDir, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	circuitPath := filepath.Join(circuitDir, circuitHash0)
	circuit, err := os.ReadFile(circuitPath)
	if err != nil {
		return fmt.Errorf("read circuit %s: %w", circuitPath, err)
	}
	fmt.Printf("generating fixtures into %s (real clock: %s)\n", outDir, time.Now().Format(time.RFC3339))

	f5 := []byte{0xF5} // CBOR true  (age_over_18 = true)
	f4 := []byte{0xF4} // CBOR false (age_over_18 = false)

	var trusted [][]byte // CA DERs that go into the trust PEM

	write := func(name string, fx []byte) error {
		return os.WriteFile(filepath.Join(outDir, name+".json"), fx, 0o644)
	}

	// 1. valid — age_over_18=true, DS chains to a trusted CA. -> ACCEPT.
	fx, caDER, err := scenario(circuit, "valid", f5, f5, false)
	if err != nil {
		return err
	}
	trusted = append(trusted, caDER)
	if err := write("valid", fx); err != nil {
		return err
	}

	// 2. untrusted-issuer — age_over_18=true, DS chains to a CA that is NOT in the
	//    trust PEM (its caDER is deliberately dropped, not appended). -> rejected
	//    at chain validation, PRE-ZK (ISSUER_UNTRUSTED).
	fx, _, err = scenario(circuit, "untrusted-issuer", f5, f5, false)
	if err != nil {
		return err
	}
	if err := write("untrusted-issuer", fx); err != nil {
		return err
	}

	// 3. underage — age_over_18=FALSE, honestly proven, DS chains to a trusted CA.
	//    The proof is VALID (Status:true) but the CLAIM is false: over-18 is
	//    (Status==true AND claim==true), so this is NOT over-18. A consumer reading
	//    Status alone would wrongly accept a validly-proven minor.
	fx, caDER, err = scenario(circuit, "underage", f4, f4, false)
	if err != nil {
		return err
	}
	trusted = append(trusted, caDER)
	if err := write("underage", fx); err != nil {
		return err
	}

	// 4. tampered — valid over-18 credential, one proof byte flipped. DS chains to
	//    a trusted CA (so rejection is the ZK math, not the chain). The wire still
	//    CLAIMS age_over_18=true — the CLAUDE.md failure-mode #4 echo trap: the
	//    service returns Status:false but Claims echoes true; when Status:false the
	//    echo is unverified noise and must be discarded. -> ZK_PROOF_INVALID.
	fx, caDER, err = scenario(circuit, "tampered", f5, f5, true)
	if err != nil {
		return err
	}
	trusted = append(trusted, caDER)
	if err := write("tampered", fx); err != nil {
		return err
	}

	// Trust PEM: exactly the CAs of the fixtures that should chain (valid,
	// underage, tampered). untrusted-issuer's CA is absent by construction.
	var pemBuf []byte
	for _, der := range trusted {
		pemBuf = append(pemBuf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.WriteFile(filepath.Join(outDir, "caCerts.pem"), pemBuf, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote 4 fixtures + caCerts.pem (%d trusted CA certs)\n", len(trusted))
	return nil
}
