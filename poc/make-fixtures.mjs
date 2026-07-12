#!/usr/bin/env node
// Regenerates the four M0 negative fixtures from longfellow-zk's own example
// proof. Each is a minimal delta of real, uncrafted data (see M0-EVIDENCE.md
// "Fit-to-pass check"). Deterministic: same input -> byte-identical output.
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const src = join(here, 'longfellow-zk/reference/verifier-service/server/examples/post1.json');
const { Transcript, ZKDeviceResponseCBOR } = JSON.parse(readFileSync(src, 'utf8'));

const write = (name, transcript, proofBuf) =>
  writeFileSync(join(here, name), JSON.stringify({
    Transcript: transcript,
    ZKDeviceResponseCBOR: proofBuf.toString('base64'),
  }));

const proof = Buffer.from(ZKDeviceResponseCBOR, 'base64');
const flip = (pos) => { const b = Buffer.from(proof); b[pos] ^= 0xff; return b; };

// CASE 2: one byte flipped mid-blob (deep ZK-verification rejection, code 5)
write('post1-tampered.json', Transcript, flip(Math.floor(proof.length / 2)));

// CASE 3: valid proof, last transcript byte flipped (cryptographic session
// binding; NOT a replay test — byte-identical replay is accepted, see audit)
const t = Buffer.from(Transcript, 'base64');
t[t.length - 1] ^= 0x01;
write('post1-wrong-transcript.json', t.toString('base64'), proof);

// PROBE A: byte 50 (envelope region -> still a deep code-5 rejection)
write('probe-flip-head.json', Transcript, flip(50));

// PROBE B: byte len-500 (cert region -> shallow x509 parse rejection, ~3 ms)
write('probe-flip-tail.json', Transcript, flip(proof.length - 500));

console.log(`fixtures regenerated from ${src} (proof ${proof.length} bytes)`);
