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
// and no canonical/CTAP2 mode is wanted. The structs mirror
// reference/verifier-service/server/zk/cbor.go.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
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

// serial hands out unique-enough cert serial numbers. The CSPRNG error is
// propagated, not dropped: a nil SerialNumber would surface later as an opaque
// x509 error, and a key-minting tool must never let a failed rand read pass
// quietly.
func serial() (*big.Int, error) {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial number: %w", err)
	}
	return n, nil
}

// certWindow is deliberately relative to the REAL wall clock: now-1yr .. now+1yr.
// This is the whole point: the fixtures are natively valid on the real clock, so
// the JS integration suite can drop ZKVERIFY_FAKE_TIME (the M0/M1 scaffolding
// that pinned x509 verification time to keep the stale upstream fixture's chain
// valid). This x509 clock is entirely separate from the circuit's `nowStr` clock.
//
// It is computed ONCE per scenario and threaded into the CA, the leaf, and the log
// line, so all three describe the same window — calling time.Now() separately per
// certificate would print a window that belongs to no certificate we actually
// issued.
func certWindow() (time.Time, time.Time) {
	now := time.Now()
	return now.AddDate(-1, 0, 0), now.AddDate(1, 0, 0)
}

// makeCA mints a self-signed P-256 CA (IsCA), as the service's generateTestCA does.
func makeCA(org string, nb, na time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber:          sn,
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
// wiring: validateIssuerKey (reference/.../zk/cbor.go:260) extracts (pkx,pky) from
// THIS cert and hands it to run_mdoc_verifier, and the proof only verifies under
// the key that signed the MSO issuerAuth. Get it wrong and you get Status:false
// with a VALID chain — indistinguishable at a glance from a bad proof.
//
// assertFixtureVerifies is what stops that being a silent failure: the equality
// asserted in this comment is checked, not assumed.
func makeLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, subjectPub *ecdsa.PublicKey, nb, na time.Time) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: sn,
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
	// x5chain as a single CBOR byte string = leaf DER || CA DER. getFirstCert's
	// []byte branch (reference/.../zk/cbor.go:127) returns the whole run and
	// validateIssuerKey's x509.ParseCertificates (cbor.go:262) parses BOTH into
	// [leaf, CA]; an [][]byte array would drop everything past element 0, dropping
	// the CA and with it the chain.
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
		Timestamp:  m.clock.now,
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

// expectation is what run_mdoc_verifier MUST do with a scenario's proof. It is
// asserted before the fixture is written, never assumed.
//
// Note this is the ZK verdict only. untrusted-issuer carries a perfectly VALID
// proof — it is meant to be refused earlier, at chain validation, because its CA
// is withheld from the trust PEM. Conflating "this fixture should be rejected" with
// "this proof should fail to verify" is exactly the ok/over_threshold collapse
// CLAUDE.md forbids, so the two are kept apart here too.
type expectation int

const (
	expectAccept expectation = iota // run_mdoc_verifier must return SUCCESS
	expectReject                    // run_mdoc_verifier must NOT return SUCCESS
)

// assertFixtureVerifies refuses to emit a fixture that does not do what its
// scenario claims.
//
// This project's recurring bug is a security-critical resource that silently
// half-loads, leaving the verifier confidently rejecting valid proofs. A fixture
// generator that never checks its own output is that same bug one layer up:
// mkfixture would report success, the JS suite would go red, and the VERIFIER would
// take the blame for a generator defect. So both of the invariants that the code
// above merely asserts in prose get checked here:
//
//  1. The leaf cert carries the exact key the MSO was signed with. If it does not,
//     the chain still validates and the service still extracts a (pkx,pky) — just
//     the wrong one — and every proof fails while looking like bad crypto.
//  2. longfellow actually reaches the expected verdict on these exact bytes. In
//     particular a "tampered" fixture whose byte-flip landed somewhere inert would
//     otherwise ship as a negative test that silently passes.
//
// It returns longfellow's own verdict name, so a rejecting scenario can REPORT the
// reason it was refused rather than merely that it was. "Rejected" alone would let
// a fixture pass this guard for a reason that has nothing to do with what it claims
// to test.
func assertFixtureVerifies(circuit []byte, m *MintResult, proof []byte, leaf *x509.Certificate, requested []byte, want expectation) (string, error) {
	leafPub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("leaf public key is %T, want *ecdsa.PublicKey", leaf.PublicKey)
	}
	if !leafPub.Equal(&m.IssuerKey.PublicKey) {
		return "", fmt.Errorf(
			"leaf cert does not carry the MSO-signing key: the chain would validate, " +
				"the service would extract the WRONG (pkx,pky), and every proof would fail with a valid chain")
	}

	vName, vCode := RunVerifier(circuit, m, proof, requested)
	switch want {
	case expectAccept:
		if vCode != 0 {
			return vName, fmt.Errorf("proof must verify, but longfellow rejected it: %s", vName)
		}
	case expectReject:
		if vCode == 0 {
			return vName, fmt.Errorf("proof must NOT verify, but longfellow ACCEPTED it — this negative fixture would silently pass")
		}
	}
	return vName, nil
}

// mangleLeaf flips the last byte of a leaf cert's DER, which lands inside the
// ECDSA signatureValue: the ASN.1 lengths are untouched, so the certificate still
// PARSES and the failure lands where we want it — chain validation — rather than
// on a DER parse error that would exercise nothing.
//
// It then proves the mangle actually broke the chain. A byte-flip that left the
// signature verifiable would ship as a negative fixture that silently passes,
// which is the same vacuous-guard trap assertFixtureVerifies exists to close.
// Chain validation here is stdlib x509 over OUR OWN test fixture — it is not a
// reimplementation of longfellow's chain validation (NO-GO #8), which remains the
// service's job and is exactly what this fixture is built to exercise.
func mangleLeaf(leaf, ca *x509.Certificate) (*x509.Certificate, error) {
	der := append([]byte{}, leaf.Raw...)
	der[len(der)-1] ^= 0xFF

	mangled, err := x509.ParseCertificate(der)
	if err != nil {
		// Structurally broken rather than signature-broken: still a valid negative
		// (the service rejects it), but not the one this scenario claims to be.
		return nil, fmt.Errorf("mangled leaf no longer parses (%w) — wanted a parseable cert with a bad signature", err)
	}
	if err := mangled.CheckSignatureFrom(ca); err == nil {
		return nil, fmt.Errorf(
			"the byte-flip left the leaf signature VALID — this fixture would chain successfully and the mangled-chain test would silently pass")
	}
	return mangled, nil
}

// scenarioOpts describes one fixture. Each deviation from the happy path is named
// rather than passed as a positional bool, because they compose: a scenario can be
// under-age AND stale-nonced, and `scenario(c, n, v, w, false, true, false, ...)`
// is unreadable at the call site.
type scenarioOpts struct {
	name string

	// credValue is BOTH the minted elementValue and the requested attribute value.
	// wireValue is only what the wire envelope claims (a mismatch is how the
	// lying-echo trap is expressed).
	credValue []byte
	wireValue []byte

	tamperProof bool // flip a byte in the proof -> ZK math fails
	staleNonce  bool // prove under transcript A, present under B -> device-sig fails
	mangleCert  bool // corrupt the leaf signature -> chain validation fails

	// sessionNonce, when non-nil, is the exact session nonce to present under, in
	// place of a fresh random one. The M4 single-use fixture uses it to bind a proof
	// to a nonce 8een ISSUED (so src/challenge.js authenticates it via HMAC). The
	// bytes are opaque to longfellow (it hashes the transcript verbatim), so any
	// length works — see the piece-2 spike.
	sessionNonce []byte

	// clock is the credential's validity clock. The zero value means "fresh": a
	// real-time clock is filled in by scenario(). The expired-credential fixture is
	// the one caller that sets it, to a window that closed in the past.
	clock credClock

	// want is the ZK-layer verdict ONLY (see the expectation doc comment).
	want expectation
}

// scenario mints a credential, presents it under a fresh session nonce, produces a
// real proof, wraps it in a fresh CA+leaf chain, applies whichever deviation the
// scenario calls for, and then VERIFIES the result against `want` before handing it
// back. Returns the fixture JSON and the CA DER (for the trust PEM).
func scenario(circuit []byte, o scenarioOpts) (fixture, caDER []byte, err error) {
	// A zero clock means the default fresh (real-time) credential; only the
	// expired-credential scenario overrides it.
	if o.clock == (credClock{}) {
		o.clock = realTimeClock()
	}
	cred, err := MintCredentialClock(o.credValue, o.clock)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: mint: %w", o.name, err)
	}
	var transcript []byte
	if o.sessionNonce != nil {
		// Bind to a caller-supplied nonce (the M4 single-use fixture: a nonce 8een
		// issued). Same builder as the random path, so the frame bytes are identical.
		transcript = sessionTranscript(o.sessionNonce)
	} else if transcript, err = newSessionTranscript(); err != nil {
		return nil, nil, fmt.Errorf("%s: %w", o.name, err)
	}
	m, err := cred.Present(transcript)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: present: %w", o.name, err)
	}

	proof, pName, pCode := RunProver(circuit, m, o.credValue)
	if pCode != 0 {
		return nil, nil, fmt.Errorf("%s: prover failed: %s", o.name, pName)
	}

	if o.tamperProof {
		// Flip one byte deep in the proof body (avoid the very start/end framing).
		// assertFixtureVerifies below is what guarantees the flip actually broke the
		// proof rather than landing on an inert byte.
		i := len(proof) / 2
		proof[i] ^= 0xFF
	}

	// The stale/wrong-nonce negative (PRD §7.1 "a replayed proof (wrong/stale
	// nonce)"). The proof above is bound to `transcript`; we now SHIP a different
	// one. The verifier recomputes the device-auth preimage over the transcript it
	// was handed, which is no longer the one the device signed, so the device
	// signature fails.
	//
	// Everything downstream — the assertion included — runs on `m`, so the bytes we
	// prove reject are exactly the bytes we write. Asserting against the original
	// transcript would be checking a message nobody sends.
	if o.staleNonce {
		stale, err := newSessionTranscript()
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", o.name, err)
		}
		if bytes.Equal(stale, m.Transcript) {
			return nil, nil, fmt.Errorf("%s: stale nonce equals the fresh one", o.name)
		}
		m.Transcript = stale
	}

	// One window, shared by the CA, the leaf, and the log line below, so all three
	// describe the same validity period.
	nb, na := certWindow()
	ca, caKey, err := makeCA("8een M2 Test Issuer CA", nb, na)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: CA: %w", o.name, err)
	}
	leaf, err := makeLeaf(ca, caKey, &m.IssuerKey.PublicKey, nb, na)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: leaf: %w", o.name, err)
	}

	// Assert on the INTACT leaf: the "leaf carries the MSO-signing key" invariant is
	// about the wiring being right, and a corrupted cert cannot answer that question.
	//
	// Verify against wireValue, NOT credValue: the service derives the attribute value
	// it checks from the ENVELOPE (reference/.../zk/cbor.go:235 -- cborValList[i] =
	// attr.ElementValue), not from whatever the holder actually proved. For every
	// honest fixture the two are the same value. For substituted-claim they are not,
	// and that difference is the entire point of it -- asserting against credValue
	// there would model a request the service never makes.
	vName, err := assertFixtureVerifies(circuit, m, proof, leaf, o.wireValue, o.want)
	if err != nil {
		return nil, nil, fmt.Errorf("%s: %w", o.name, err)
	}

	shipLeaf := leaf
	if o.mangleCert {
		if shipLeaf, err = mangleLeaf(leaf, ca); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", o.name, err)
		}
	}

	fixture, err = packageFixture(m, proof, shipLeaf, ca, o.wireValue)
	if err != nil {
		return nil, nil, err
	}
	verdict := "verifies"
	if o.want == expectReject {
		verdict = "correctly refused: " + vName
	}
	fmt.Printf("  [%s] proof=%dB  DS-key=%s...  cert %s..%s  ZK: %s\n",
		o.name, len(proof), m.IssuerPkX[:18], nb.Format("2006-01-02"), na.Format("2006-01-02"), verdict)
	return fixture, ca.Raw, nil
}

// unlinkabilitySet emits the three presentations PRD §7.3's black-box check needs,
// all under ONE issuer, ONE CA and ONE document-signer cert — as a real issuer
// would:
//
//	a1, a2 — the SAME credential presented twice, under different session nonces
//	b1     — a DIFFERENT credential (fresh device key, fresh salt) from the same issuer
//
// b1 is the control, and it is what makes the check falsifiable. Without it,
// "a1 and a2 share no identifier" could be satisfied trivially. With it, the suite
// can assert the stronger and actually meaningful property: whatever the verifier
// can see is shared by a1 and a2 is shared by b1 too — i.e. it identifies the
// ISSUER, not the holder. A salt, an MSO digest, or a device key leaking into the
// verifier-visible envelope would make b1 differ, and the test would go red.
//
// Every presentation must ZK-verify: an unlinkability claim over proofs that do not
// verify is worthless.
func unlinkabilitySet(circuit []byte) (fixtures map[string][]byte, caDER []byte, err error) {
	issuer, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("unlinkable: issuer key: %w", err)
	}
	nb, na := certWindow()
	ca, caKey, err := makeCA("8een M2 Unlinkability Issuer CA", nb, na)
	if err != nil {
		return nil, nil, fmt.Errorf("unlinkable: CA: %w", err)
	}
	// ONE leaf, carrying the ONE issuer key, shared by both credentials — so the
	// cert chain cannot itself be the thing that distinguishes them.
	leaf, err := makeLeaf(ca, caKey, &issuer.PublicKey, nb, na)
	if err != nil {
		return nil, nil, fmt.Errorf("unlinkable: leaf: %w", err)
	}

	// Fresh (real-time) credential clock, shared by both credentials: the whole set
	// must ZK-verify AND pass the M4 freshness gate, since the §7.3 check asserts
	// every presentation is accepted.
	ck := realTimeClock()
	f5 := []byte{0xF5}
	credA, err := MintCredentialUnderClock(issuer, f5, ck)
	if err != nil {
		return nil, nil, fmt.Errorf("unlinkable: credential A: %w", err)
	}
	credB, err := MintCredentialUnderClock(issuer, f5, ck)
	if err != nil {
		return nil, nil, fmt.Errorf("unlinkable: credential B: %w", err)
	}

	present := func(name string, c *Credential) ([]byte, error) {
		transcript, err := newSessionTranscript()
		if err != nil {
			return nil, fmt.Errorf("unlinkable %s: %w", name, err)
		}
		m, err := c.Present(transcript)
		if err != nil {
			return nil, fmt.Errorf("unlinkable %s: present: %w", name, err)
		}
		proof, pName, pCode := RunProver(circuit, m, f5)
		if pCode != 0 {
			return nil, fmt.Errorf("unlinkable %s: prover failed: %s", name, pName)
		}
		if _, err := assertFixtureVerifies(circuit, m, proof, leaf, f5, expectAccept); err != nil {
			return nil, fmt.Errorf("unlinkable %s: %w", name, err)
		}
		fx, err := packageFixture(m, proof, leaf, ca, f5)
		if err != nil {
			return nil, err
		}
		fmt.Printf("  [unlinkable-%s] proof=%dB  DS-key=%s...  ZK: verifies\n", name, len(proof), m.IssuerPkX[:18])
		return fx, nil
	}

	a1, err := present("a1", credA)
	if err != nil {
		return nil, nil, err
	}
	a2, err := present("a2", credA)
	if err != nil {
		return nil, nil, err
	}
	b1, err := present("b1", credB)
	if err != nil {
		return nil, nil, err
	}

	// Two presentations that came out byte-identical would make the suite's
	// "different presentations" premise false, and its unlinkability assertions
	// vacuous. They are randomised (fresh nonce, fresh proof), so this should be
	// impossible — check it rather than trust it.
	if bytes.Equal(a1, a2) {
		return nil, nil, fmt.Errorf("unlinkable: a1 and a2 are byte-identical — the two presentations did not actually differ")
	}

	return map[string][]byte{"unlinkable-a1": a1, "unlinkable-a2": a2, "unlinkable-b1": b1}, ca.Raw, nil
}

// GenFixtures writes the fixture set + trust PEM into outDir. The circuit is read
// from circuitDir/<circuitHash0>.
func GenFixtures(circuitDir, outDir string) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	circuitPath := filepath.Join(circuitDir, circuitHash0)
	circuit, err := os.ReadFile(circuitPath)
	if err != nil {
		return fmt.Errorf("read circuit %s: %w", circuitPath, err)
	}

	// Verify the circuit by its ID, never by its filename. The file is NAMED for its
	// circuit id, but a name is not evidence: a truncated, corrupted or swapped file
	// at that path would otherwise be loaded silently and every fixture generated
	// against a circuit the verifier never uses. longfellow will not catch this for
	// us — mdoc_zk.cc:112-113 disables its internal id enforcement and states that
	// "the application is expected to check the ID once". We are the application.
	gotID, err := CircuitID(circuit)
	if err != nil {
		return fmt.Errorf("circuit %s: %w", circuitPath, err)
	}
	if gotID != circuitHash0 {
		return fmt.Errorf(
			"circuit id mismatch: %s holds a circuit whose id is %s, not %s — refusing to generate fixtures against an unknown circuit",
			circuitPath, gotID, circuitHash0)
	}

	fmt.Printf("generating fixtures into %s (real clock: %s)\n", outDir, time.Now().Format(time.RFC3339))
	fmt.Printf("circuit id verified by longfellow's own circuit_id(): %s\n", gotID)

	f5 := []byte{0xF5} // CBOR true  (age_over_18 = true)
	f4 := []byte{0xF4} // CBOR false (age_over_18 = false)

	// Clear any fixture from a previous run BEFORE writing this one's.
	//
	// Every run mints fresh CAs and rewrites caCerts.pem, so a fixture left over from
	// an earlier (or partially failed) run is keyed to a CA that is no longer in the
	// trust PEM. Run it and it fails at chain validation — for a reason that has
	// nothing to do with what it claims to test. That is this repo's silent-partial-load
	// shape, in the one tool whose entire job is refusing to emit a fixture it has not
	// verified. The output directory must describe exactly one run.
	stale, err := filepath.Glob(filepath.Join(outDir, "*.json"))
	if err != nil {
		return err
	}
	for _, f := range stale {
		if err := os.Remove(f); err != nil {
			return fmt.Errorf("clearing stale fixture %s: %w", f, err)
		}
	}
	if len(stale) > 0 {
		fmt.Printf("cleared %d fixture(s) from a previous run\n", len(stale))
	}

	var trusted [][]byte // CA DERs that go into the trust PEM
	var written []string // names actually written by THIS run — the count is not a guess

	write := func(name string, fx []byte) error {
		if err := os.WriteFile(filepath.Join(outDir, name+".json"), fx, 0o644); err != nil {
			return err
		}
		written = append(written, name)
		return nil
	}

	// 1. valid — age_over_18=true, DS chains to a trusted CA. -> ACCEPT.
	fx, caDER, err := scenario(circuit, scenarioOpts{
		name: "valid", credValue: f5, wireValue: f5, want: expectAccept,
	})
	if err != nil {
		return err
	}
	trusted = append(trusted, caDER)
	if err := write("valid", fx); err != nil {
		return err
	}

	// 2. untrusted-issuer — age_over_18=true, DS chains to a CA that is NOT in the
	//    trust PEM (its caDER is deliberately dropped, not appended). The ZK proof
	//    itself is perfectly VALID (hence expectAccept): the rejection must come
	//    earlier, at chain validation (ISSUER_UNTRUSTED). If this proof failed to
	//    verify we would be testing the wrong thing and would never learn whether
	//    the trust boundary works.
	fx, untrustedCA, err := scenario(circuit, scenarioOpts{
		name: "untrusted-issuer", credValue: f5, wireValue: f5, want: expectAccept,
	})
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
	fx, caDER, err = scenario(circuit, scenarioOpts{
		name: "underage", credValue: f4, wireValue: f4, want: expectAccept,
	})
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
	fx, caDER, err = scenario(circuit, scenarioOpts{
		name: "tampered", credValue: f5, wireValue: f5, tamperProof: true, want: expectReject,
	})
	if err != nil {
		return err
	}
	trusted = append(trusted, caDER)
	if err := write("tampered", fx); err != nil {
		return err
	}

	// 5. stale-nonce — PRD §7.1's "a replayed proof (wrong/stale nonce)". A perfectly
	//    good over-18 proof, bound to session transcript A, replayed into session B.
	//    The DS chains to a trusted CA and the ZK math is untouched: the ONLY thing
	//    wrong is that the proof belongs to another session. The device signature is
	//    what catches it.
	//
	//    This is the row that keeps the project honest about replay. A BYTE-IDENTICAL
	//    replay (same transcript) is still ACCEPTED by design — the verifier is
	//    stateless, and the integration suite has a passing test saying so. What must
	//    never be accepted is a proof lifted into a DIFFERENT session. Freshness of
	//    the nonce itself remains the gate's job (M4).
	fx, caDER, err = scenario(circuit, scenarioOpts{
		name: "stale-nonce", credValue: f5, wireValue: f5, staleNonce: true, want: expectReject,
	})
	if err != nil {
		return err
	}
	trusted = append(trusted, caDER)
	if err := write("stale-nonce", fx); err != nil {
		return err
	}

	// 6. mangled-cert — valid over-18 proof, trusted CA, but the leaf's signature is
	//    corrupted. The cert still parses; it just does not chain. Rejection must come
	//    from chain validation, NOT the ZK layer (hence expectAccept on the proof) —
	//    the same two-layer distinction as untrusted-issuer, and a crash here would be
	//    a robustness bug rather than a verdict.
	fx, caDER, err = scenario(circuit, scenarioOpts{
		name: "mangled-cert", credValue: f5, wireValue: f5, mangleCert: true, want: expectAccept,
	})
	if err != nil {
		return err
	}
	trusted = append(trusted, caDER)
	if err := write("mangled-cert", fx); err != nil {
		return err
	}

	// 7. substituted-claim — the sharpest form of the Claims-echo trap, and an attack
	//    the holder can mount entirely on their own.
	//
	//    An HONEST minor takes their own perfectly valid age_over_18=FALSE proof and
	//    edits ONE byte of the wire envelope: the IssuerSigned ElementValue, 0xF4 ->
	//    0xF5. Nothing is forged. The proof is untouched and the chain is genuine.
	//    The envelope now simply CLAIMS over-18 where the credential does not.
	//
	//    This must be refused, and the thing that refuses it is the binding: the
	//    service takes the attribute value it verifies FROM THE ENVELOPE
	//    (reference/.../zk/cbor.go:235), so the circuit is asked to prove that a
	//    credential committing 0xF4 has elementValue 0xF5, and the constraint fails.
	//    If that binding ever broke, a minor's own valid proof would be relabelled
	//    over-18 and ACCEPTED -- a false ACCEPT, the one direction 8een cannot
	//    tolerate. The knob to build this existed since the generator was written and
	//    was never turned; a code review caught that it was documented but untested.
	fx, caDER, err = scenario(circuit, scenarioOpts{
		name: "substituted-claim", credValue: f4, wireValue: f5, want: expectReject,
	})
	if err != nil {
		return err
	}
	trusted = append(trusted, caDER)
	if err := write("substituted-claim", fx); err != nil {
		return err
	}

	// 8. expired-credential — a valid over-18 proof from a TRUSTED issuer whose
	//    credential validity window CLOSED in the past. Its circuit `now` sits INSIDE
	//    that past window, so longfellow's own validFrom<=now<=validUntil check passes
	//    and the raw verifier ACCEPTS it (want: expectAccept). That acceptance IS the
	//    bug PRD §7.1a names: the credential clock is the prover's to declare, and the
	//    ZK layer never checks it against real time. Only the M4 freshness gate
	//    (src/verdict.js), which bounds this `now` against the real wall clock, can
	//    catch it — and here that `now` is years stale. The x509 chain is on the real
	//    clock (certWindow) and valid, so rejection cannot come from there either: this
	//    fixture reaches the accept path and is stopped by nothing below M4.
	fx, caDER, err = scenario(circuit, scenarioOpts{
		name: "expired-credential", credValue: f5, wireValue: f5,
		clock: expiredClock(), want: expectAccept,
	})
	if err != nil {
		return err
	}
	trusted = append(trusted, caDER)
	if err := write("expired-credential", fx); err != nil {
		return err
	}

	// 9. the unlinkability set (PRD §7.3) — three presentations under one issuer.
	unlinkable, caDER, err := unlinkabilitySet(circuit)
	if err != nil {
		return err
	}
	trusted = append(trusted, caDER)
	for name, b := range unlinkable {
		if err := write(name, b); err != nil {
			return err
		}
	}

	// 10. single-use (M4 piece 2) — a valid over-18 proof from a TRUSTED issuer, bound
	//     to a session nonce 8een ISSUED (passed in via -session-nonce). The proof
	//     itself ACCEPTS at every layer (ZK, chain, claim, currency) — nothing here is
	//     wrong with it. What the JS harness proves is orthogonal to the proof: submit
	//     it TWICE through a Verifier with requireSingleUse on, and the SECOND
	//     submission — byte-identical — must be refused as a replay. That refusal lives
	//     entirely in src/challenge.js (the spent-nonce set), never in the proof, so it
	//     can only be exercised with a nonce the verifier recognizes as its own. Emitted
	//     only when a nonce is supplied; otherwise skipped, so the base matrix is
	//     unchanged.
	if sessionNonceHex != "" {
		nonce, err := hex.DecodeString(sessionNonceHex)
		if err != nil {
			return fmt.Errorf("single-use: -session-nonce is not valid hex: %w", err)
		}
		fx, caDER, err := scenario(circuit, scenarioOpts{
			name: "single-use", credValue: f5, wireValue: f5,
			sessionNonce: nonce, want: expectAccept,
		})
		if err != nil {
			return err
		}
		trusted = append(trusted, caDER)
		if err := write("single-use", fx); err != nil {
			return err
		}
	}

	// Trust PEM: the CAs of every fixture that should chain — valid, underage,
	// tampered, stale-nonce, mangled-cert, substituted-claim, the unlinkability issuer,
	// and single-use (when emitted). ONLY untrusted-issuer's CA is withheld: that
	// omission is the entire
	// negative test, and it is exactly the kind of thing a later edit silently undoes.
	// Check it rather than trusting that we remembered.
	for _, der := range trusted {
		if bytes.Equal(der, untrustedCA) {
			return fmt.Errorf(
				"untrusted-issuer's CA leaked into the trust PEM — its fixture would be ACCEPTED and the trust-boundary test would silently pass")
		}
	}

	var pemBuf []byte
	for _, der := range trusted {
		pemBuf = append(pemBuf, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	if err := os.WriteFile(filepath.Join(outDir, "caCerts.pem"), pemBuf, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %d fixtures + caCerts.pem (%d trusted CA certs; untrusted-issuer's CA withheld)\n",
		len(written), len(trusted))
	return nil
}
