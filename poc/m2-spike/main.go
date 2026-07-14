package main

import (
	"encoding/hex"
	"fmt"
	"os"
)

// kZkSpecs[0]: 1 attribute, version 7. Circuit file is named by its hash.
const circuitHash0 = "8d079211715200ff06c5109639245502bfe94aa869908d31176aae4016182121"
const circuitDir = "../longfellow-zk/lib/circuits/mdoc/circuits/"

func main() {
	fmt.Println("=== m2-spike: mint -> prove -> verify ===")

	circuit, err := os.ReadFile(circuitDir + circuitHash0)
	if err != nil {
		fmt.Printf("FATAL: cannot read circuit %s: %v\n", circuitHash0, err)
		os.Exit(1)
	}
	fmt.Printf("loaded circuit %s... (%d bytes)\n", circuitHash0[:16], len(circuit))

	m, err := Mint()
	if err != nil {
		fmt.Printf("FATAL: mint failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("minted DeviceResponse: %d bytes\n", len(m.DeviceResponse))
	fmt.Printf("issuer pkx: %s\n", m.IssuerPkX)
	fmt.Printf("issuer pky: %s\n", m.IssuerPkY)
	if len(os.Args) > 1 && os.Args[1] == "-dump" {
		fmt.Printf("DeviceResponse hex:\n%s\n", hex.EncodeToString(m.DeviceResponse))
	}

	fmt.Println("\n--- PROVER ---")
	proof, pName, pCode := RunProver(circuit, m)
	fmt.Printf("run_mdoc_prover -> %s\n", pName)
	if pCode != 0 {
		fmt.Println("\nRESULT: prover FAILED. Not double-success.")
		os.Exit(2)
	}
	fmt.Printf("proof produced: %d bytes\n", len(proof))

	fmt.Println("\n--- VERIFIER ---")
	vName, vCode := RunVerifier(circuit, m, proof)
	fmt.Printf("run_mdoc_verifier -> %s\n", vName)

	fmt.Println()
	if pCode == 0 && vCode == 0 {
		fmt.Println("RESULT: DOUBLE SUCCESS (prover + verifier both accepted).")
		os.Exit(0)
	}
	fmt.Println("RESULT: prover succeeded but verifier FAILED (circuit byte-layout issue).")
	os.Exit(3)
}
