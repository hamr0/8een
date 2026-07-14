# mkfixture — dev-only M2 fixture generator

`mkfixture` mints synthetic ISO 18013-5 mdoc credentials under a **runtime P-256
test CA**, produces **real** longfellow ZK proofs (via `run_mdoc_prover`, cgo),
and packages them in the verifier **service** wire format
(`{Transcript, ZKDeviceResponseCBOR}` JSON with an x509 cert chain). Its output is
the discrimination matrix the M2 integration suite POSTs at the real
`reference/verifier-service/server`.

## This is repo tooling, not shipped code

- **It NEVER ships in the npm package.** `package.json` `files[]` is an allowlist
  (`src`, `types`, docs) — `tools/` is not in it, so `npm pack` excludes it. Do not
  add `tools/` to `files[]`.
- **It must NEVER be imported by `src/`.** It is a standalone Go module
  (`module mkfixture`) that links longfellow's static C++ lib via cgo. `src/` is
  the runtime library and depends on none of this. Keep that boundary absolute.
- Keys are **generated at runtime into memory** and never written to the tree
  (PRD §10). The only files written are the fixture JSONs and `caCerts.pem`.

## Requires the longfellow clone materialized

Building **and** running require the POC clone built with its `install/` prefix
(static lib + header) present — see [`poc/M0-EVIDENCE.md`](../../poc/M0-EVIDENCE.md)
step 1. Specifically:

- `poc/longfellow-zk/reference/verifier-service/install/include/mdoc_zk.h`
- `poc/longfellow-zk/reference/verifier-service/install/lib/libmdoc_static.a`
- `poc/longfellow-zk/lib/circuits/mdoc/circuits/8d0792…6182121` (the one circuit)

The cgo `CFLAGS`/`LDFLAGS` in `prove.go` are **compile-time** paths, relative to
this package directory (`../../poc/longfellow-zk/…`). Runtime paths are **flags**
(below), because the JS harness execs the built binary and passes them explicitly.

## Build

```sh
cd tools/mkfixture
CGO_ENABLED=1 go build -o mkfixture .
```

## Run

```sh
./mkfixture \
  -circuit-dir ../../poc/longfellow-zk/lib/circuits/mdoc/circuits \
  -out ./fixtures
```

| flag | default | meaning |
|------|---------|---------|
| `-circuit-dir` | `../../poc/longfellow-zk/lib/circuits/mdoc/circuits` | dir holding the prebuilt circuit file named by its hash (`kZkSpecs[0]`, 1 attribute, ZK spec v7) |
| `-out` | `./fixtures` | output dir for the 4 fixture JSONs + `caCerts.pem` |

## What it emits

Four fixtures plus a trust PEM. The over-18 verdict a consumer must compute is
**`Status==true AND claim==true`** — neither field alone is sufficient, and the
last two fixtures exist to prove that.

| file | scenario | expected service response |
|------|----------|---------------------------|
| `valid.json` | age_over_18=true, DS chains to a trusted CA | **200** `Status:true`, claim `9Q==` (0xF5=true) → **ACCEPT** |
| `untrusted-issuer.json` | same proof, DS chains to a CA **not** in the PEM | **400** cert-chain failure → **ISSUER_UNTRUSTED**, rejected **pre-ZK** |
| `underage.json` | age_over_18=**false**, honestly proven, trusted CA | **200** `Status:true`, claim `9A==` (0xF4=false) → **NOT over-18** (proof valid *for a false claim*; read the claim) |
| `tampered.json` | valid over-18 proof, one byte flipped, trusted CA | **200** `Status:false` + `return code 5`, `Claims` still echoes `9Q==` → **ZK_PROOF_INVALID** (when `Status:false` the echo is unverified noise — discard it) |
| `caCerts.pem` | the 3 CAs of valid/underage/tampered; untrusted-issuer's CA is deliberately absent | the trust boundary — same bytes, different PEM, is the discrimination test |

`untrusted-issuer` fails at chain validation (**400 + parse-error JSON**), a shape
**distinct** from a ZK rejection (**200 + `Status:false` + return code 5**); 8een's
reason mapping must keep `ISSUER_UNTRUSTED` and `ZK_PROOF_INVALID` apart.

## Real-clock validity (why `ZKVERIFY_FAKE_TIME` can be dropped)

The test CA + leaf carry a validity window relative to the **real wall clock**
(`now-1yr .. now+1yr`), so the x509 chain verifies natively — no
`ZKVERIFY_FAKE_TIME` needed for the ACCEPT path. That pin was M0/M1 scaffolding
for the one upstream fixture whose chain expired 2026-05-07; these fixtures remove
the need for it. (This x509 clock is separate from the circuit's own `now`/MSO
validity, which is a lexical 20-char string compare — see `mint.go`.)

## Tests

```sh
go test ./...
```

- **Pure byte-layout tests** (`layout_test.go`) assert the security-critical inner
  mdoc framings (COSE_Key byte run, tdate `C0 74`, tag24 item framing, MSO ≥256 /
  `0x59` invariant, digest-over-full-tagged-item). They need **no cgo and no
  clone**, so they run even under `CGO_ENABLED=0`.
- **cgo discrimination tests** (`prove_test.go`, build-tagged `cgo`) call the real
  prover/verifier: a valid proof accepts, the same proof under a wrong issuer key
  rejects, and an under-18 credential cannot be opened as over-18. They **skip
  cleanly** when the circuit file is absent, mirroring `test/integration.test.js`.

## Layout

| file | role |
|------|------|
| `mint.go` | runtime P-256 keygen + fully hand-encoded DeviceResponse (pure, no cgo) |
| `prove.go` | cgo bindings for `run_mdoc_prover` + `run_mdoc_verifier` (tag `cgo`) |
| `fixture.go` | test-CA + leaf cert + service wire-format packaging + `GenFixtures` (tag `cgo`) |
| `main.go` | CLI driver (tag `cgo`) |
| `layout_test.go` | pure byte-layout unit tests |
| `prove_test.go` | cgo discrimination tests (tag `cgo`) |

The clean split (per `poc/m2-spike/FIXTURE-RESULT.md` gotcha 3): the **inner mdoc**
is hand-encoded bytes because the circuit asserts rigid byte runs; the **outer
service wire structs** use library `cbor.Marshal`. Do not mix them.
