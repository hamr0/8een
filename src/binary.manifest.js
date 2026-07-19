// SPDX-License-Identifier: Apache-2.0
/**
 * Pinned prebuilt verifier binaries (PRD §9 D11).
 *
 * Plain ESM, not JSON, per LIBRARY_CONVENTIONS §1 ("pure ESM JS — the .js you
 * author is the .js that ships"): a JSON import needs an import attribute, and
 * tsc emits that import into the PUBLIC .d.ts, where the JSON is not shipped —
 * which broke every adopter typecheck with TS2307 (measured against a real npm
 * pack + install). As a .js module the types are INFERRED from this one source,
 * so there is no hand-written shape beside the data to drift from it.
 *
 * Frozen: it is a pin, and a pin that can be mutated at runtime is not a pin.
 */
export default Object.freeze({
    "upstream": "https://github.com/google/longfellow-zk",
    "commit": "d8ad8f65187c7c364a3c2181ad484bcab03f0ec2",
    "patches": [
      "0001-zkverify-fake-time.patch",
      "0002-eu-circuit-id-compat.patch",
      "0003-m4-echo-verified-timestamp.patch"
    ],
    "release": "longfellow-bin-1",
    "binaries": {
      "linux-x64": {
        "asset": "longfellow-verifier-linux-x64",
        "sha256": "756869602c84c116e9d94aa07b138a22373acd6f59b2b331e5bf7c0272175b00",
        "bytes": 10124224
      }
    }
  });
