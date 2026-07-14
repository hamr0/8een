//go:build cgo

package main

// main.go — CLI driver for the M2 fixture generator.
//
//	mkfixture -circuit-dir <dir> -out <dir>
//
// Writes valid.json, untrusted-issuer.json, underage.json, tampered.json and
// caCerts.pem into -out. Runtime paths are FLAGS (not hard-coded relatives): the
// JS integration harness execs this built binary and passes paths explicitly.
// The cgo compile-time include/lib paths are in prove.go and are the only fixed
// relatives (compile-time, resolved against the package dir).

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	// Defaults are relative to the CWD the binary is run from. The JS harness
	// overrides both; the defaults match "run from tools/mkfixture" so a developer
	// can `./mkfixture` with no flags against the materialized clone.
	circuitDir := flag.String("circuit-dir", "../../poc/longfellow-zk/lib/circuits/mdoc/circuits",
		"directory containing the prebuilt circuit file named by its hash (kZkSpecs[0])")
	out := flag.String("out", "./fixtures",
		"output directory for the fixture JSONs + caCerts.pem")
	flag.Parse()

	if err := GenFixtures(*circuitDir, *out); err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: fixture generation failed: %v\n", err)
		os.Exit(1)
	}
}
