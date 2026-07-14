//go:build cgo

package main

// prove.go — cgo bindings for longfellow's run_mdoc_prover and run_mdoc_verifier
// (mirrors reference/verifier-service/server/zk/proofs.go, adds the prover +
// &kZkSpecs[0], with full error-code name tables).
//
// Requires the longfellow clone materialized with its install/ prefix built (the
// static lib + header). Guarded by //go:build cgo so the pure byte-layout code in
// mint.go + layout_test.go still compiles and its tests still run under
// CGO_ENABLED=0 even when the clone is absent.
//
// CFLAGS/LDFLAGS are COMPILE-TIME and relative to THIS package directory:
// tools/mkfixture -> ../../poc/longfellow-zk/...  (runtime paths are flags; see
// main.go). Do NOT hard-code runtime circuit/output paths here.

import (
	"fmt"
	"unsafe"
)

// #cgo LDFLAGS: -L../../poc/longfellow-zk/reference/verifier-service/install/lib -lmdoc_static -lcrypto -lzstd -lstdc++
// #cgo CFLAGS: -I../../poc/longfellow-zk/reference/verifier-service/install/include
// #include <stdlib.h>
// #include <stddef.h>
// #include <stdint.h>
// #include <string.h>
// #include "mdoc_zk.h"
//
// /* Helpers copied from reference/verifier-service/server/zk/proofs.go */
// RequestedAttribute* make_attribute(size_t len) {
//    return (RequestedAttribute*)malloc(sizeof(RequestedAttribute) * len);
// }
// void set_attribute(RequestedAttribute attrs[], size_t ind,
//                    const char* namespace_id, const char* id,
//                    const uint8_t* cborvalue, size_t cborvaluelen) {
//    strncpy((char *)attrs[ind].namespace_id, namespace_id, 64);
//    strncpy((char *)attrs[ind].id, id, 32);
//    if (cborvaluelen > 64) { cborvaluelen = 64; }
//    memcpy((char *)attrs[ind].cbor_value, cborvalue, cborvaluelen);
//    attrs[ind].namespace_len = strlen(namespace_id);
//    attrs[ind].id_len = strlen(id);
//    attrs[ind].cbor_value_len = cborvaluelen;
// }
// /* &kZkSpecs[0] : the 1-attribute, version-7 circuit spec. */
// const ZkSpecStruct* zkspec0() { return &kZkSpecs[0]; }
import "C"

var proverErrNames = map[int]string{
	0: "MDOC_PROVER_SUCCESS", 1: "MDOC_PROVER_NULL_INPUT", 2: "MDOC_PROVER_INVALID_INPUT",
	3: "MDOC_PROVER_CIRCUIT_PARSING_FAILURE", 4: "MDOC_PROVER_HASH_PARSING_FAILURE",
	5: "MDOC_PROVER_WITNESS_CREATION_FAILURE", 6: "MDOC_PROVER_GENERAL_FAILURE",
	7: "MDOC_PROVER_MEMORY_ALLOCATION_FAILURE", 8: "MDOC_PROVER_INVALID_ZK_SPEC_VERSION",
	9: "MDOC_PROVER_ROOT_DECODING_FAILURE", 10: "MDOC_PROVER_DOCUMENTS_MISSING",
	11: "MDOC_PROVER_DOCUMENT_0_MISSING", 12: "MDOC_PROVER_DOCTYPE_MISSING",
	13: "MDOC_PROVER_ISSUER_SIGNED_MISSING", 14: "MDOC_PROVER_ISSUER_AUTH_MISSING",
	15: "MDOC_PROVER_MSO_MISSING", 16: "MDOC_PROVER_NSIG_MISSING",
	17: "MDOC_PROVER_NAMESPACES_MISSING", 18: "MDOC_PROVER_DEVICE_SIGNED_MISSING",
	19: "MDOC_PROVER_DEVICE_AUTH_MISSING", 20: "MDOC_PROVER_DEVICE_SIGNATURE_MISSING",
	21: "MDOC_PROVER_DEVICE_KEY_MISSING", 22: "MDOC_PROVER_MSO_DECODING_FAILURE",
	23: "MDOC_PROVER_VALIDITY_INFO_MISSING", 24: "MDOC_PROVER_DEVICE_KEY_INFO_MISSING",
	25: "MDOC_PROVER_ATTRIBUTE_DECODE_FAILURE", 26: "MDOC_PROVER_ATTRIBUTE_EI_MISSING",
	27: "MDOC_PROVER_ATTRIBUTE_EV_MISSING", 28: "MDOC_PROVER_ATTRIBUTE_DID_MISSING",
	29: "MDOC_PROVER_SIGNATURE_FAILURE", 30: "MDOC_PROVER_DEVICE_SIGNATURE_FAILURE",
	31: "MDOC_PROVER_ATTRIBUTE_NOT_FOUND", 32: "MDOC_PROVER_ATTRIBUTE_TOO_LONG",
	33: "MDOC_PROVER_TAGGED_MSO_TOO_BIG", 34: "MDOC_PROVER_VERSION_NOT_SUPPORTED",
	35: "MDOC_PROVER_ATTRIBUTE_RANDOM_MISSING",
}

var verifierErrNames = map[int]string{
	0: "MDOC_VERIFIER_SUCCESS", 1: "MDOC_VERIFIER_CIRCUIT_PARSING_FAILURE",
	2: "MDOC_VERIFIER_PROOF_TOO_SMALL", 3: "MDOC_VERIFIER_HASH_PARSING_FAILURE",
	4: "MDOC_VERIFIER_SIGNATURE_PARSING_FAILURE", 5: "MDOC_VERIFIER_GENERAL_FAILURE",
	6: "MDOC_VERIFIER_NULL_INPUT", 7: "MDOC_VERIFIER_INVALID_INPUT",
	8: "MDOC_VERIFIER_ARGUMENTS_TOO_SMALL", 9: "MDOC_VERIFIER_ATTRIBUTE_NUMBER_MISMATCH",
	10: "MDOC_VERIFIER_INVALID_ZK_SPEC_VERSION", 11: "MDOC_VERIFIER_INVALID_CBOR",
}

func proverName(c int) string {
	if n, ok := proverErrNames[c]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(%d)", c)
}

func verifierName(c int) string {
	if n, ok := verifierErrNames[c]; ok {
		return n
	}
	return fmt.Sprintf("UNKNOWN(%d)", c)
}

// buildAttrs creates a single-attribute RequestedAttribute array for
// (namespace, elemID, requestedValue). requestedValue is the CBOR the holder asks
// to open age_over_18 as; the circuit forces the credential's elementValue to
// equal it byte-for-byte. It is passed explicitly (not read from a global) so a
// caller can request a value that differs from the minted one — that is exactly
// the forge test: mint 0xF4, request 0xF5.
func buildAttrs(requestedValue []byte) *C.RequestedAttribute {
	attrs := C.make_attribute(1)
	cns := C.CString(namespace)
	cid := C.CString(elemID)
	cval := C.CBytes(requestedValue)
	defer C.free(unsafe.Pointer(cns))
	defer C.free(unsafe.Pointer(cid))
	defer C.free(unsafe.Pointer(cval))
	C.set_attribute(attrs, 0, cns, cid, (*C.uint8_t)(cval), C.size_t(len(requestedValue)))
	return attrs
}

// RunProver calls run_mdoc_prover. Returns (proofBytes, codeName, code).
func RunProver(circuit []byte, m *MintResult, requestedValue []byte) ([]byte, string, int) {
	cCirc := (*C.uint8_t)(C.CBytes(circuit))
	defer C.free(unsafe.Pointer(cCirc))
	cMdoc := (*C.uint8_t)(C.CBytes(m.DeviceResponse))
	defer C.free(unsafe.Pointer(cMdoc))
	cTr := (*C.uint8_t)(C.CBytes(m.Transcript))
	defer C.free(unsafe.Pointer(cTr))
	cPkx := C.CString(m.IssuerPkX)
	cPky := C.CString(m.IssuerPkY)
	cNow := C.CString(nowStr)
	defer C.free(unsafe.Pointer(cPkx))
	defer C.free(unsafe.Pointer(cPky))
	defer C.free(unsafe.Pointer(cNow))

	attrs := buildAttrs(requestedValue)
	defer C.free(unsafe.Pointer(attrs))

	var prf *C.uint8_t
	var prfLen C.size_t

	ret := C.run_mdoc_prover(
		cCirc, C.size_t(len(circuit)),
		cMdoc, C.size_t(len(m.DeviceResponse)),
		cPkx, cPky,
		cTr, C.size_t(len(m.Transcript)),
		attrs, 1,
		cNow,
		&prf, &prfLen, C.zkspec0(),
	)
	code := int(ret)
	if code != 0 {
		return nil, proverName(code), code
	}
	proof := C.GoBytes(unsafe.Pointer(prf), C.int(prfLen))
	C.free(unsafe.Pointer(prf))
	return proof, proverName(code), code
}

// RunVerifier calls run_mdoc_verifier. Returns (codeName, code).
func RunVerifier(circuit []byte, m *MintResult, proof, requestedValue []byte) (string, int) {
	cCirc := (*C.uint8_t)(C.CBytes(circuit))
	defer C.free(unsafe.Pointer(cCirc))
	cTr := (*C.uint8_t)(C.CBytes(m.Transcript))
	defer C.free(unsafe.Pointer(cTr))
	cPkx := C.CString(m.IssuerPkX)
	cPky := C.CString(m.IssuerPkY)
	cNow := C.CString(nowStr)
	cDoc := C.CString(m.DocType)
	defer C.free(unsafe.Pointer(cPkx))
	defer C.free(unsafe.Pointer(cPky))
	defer C.free(unsafe.Pointer(cNow))
	defer C.free(unsafe.Pointer(cDoc))

	attrs := buildAttrs(requestedValue)
	defer C.free(unsafe.Pointer(attrs))

	cProof := (*C.uint8_t)(C.CBytes(proof))
	defer C.free(unsafe.Pointer(cProof))

	ret := C.run_mdoc_verifier(
		cCirc, C.size_t(len(circuit)),
		cPkx, cPky,
		cTr, C.size_t(len(m.Transcript)),
		attrs, 1,
		cNow,
		cProof, C.size_t(len(proof)),
		cDoc, C.zkspec0(),
	)
	return verifierName(int(ret)), int(ret)
}
