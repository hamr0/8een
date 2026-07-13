import test from 'node:test';
import assert from 'node:assert/strict';
import { splitLines } from '../src/service.js';

const ID = '137e5a75ce72735a37c8a72da1a8a0a5df8d13365c2ae3d2c2bd6a0e7197c7c6';
const CIRCUIT_LOADED = /(?:^|\s)Read ([0-9a-f]{64})\s*$/;

/** Feed a stream to the line splitter in arbitrary chunks and count circuit lines. */
function countAcrossChunks(chunks) {
  let residual = '';
  let n = 0;
  for (const chunk of chunks) {
    const out = splitLines(residual, chunk);
    residual = out.residual;
    for (const line of out.lines) if (CIRCUIT_LOADED.test(line)) n += 1;
  }
  return n;
}

const stream = (count) =>
  Array.from({ length: count }, (_, i) => `2026/07/13 10:00:0${i} Read ${ID}\n`).join('');

// The bug this fixes: a child's stdout is a byte stream, not a line stream. The
// original code split each chunk on '\n' in isolation, so a line straddling a
// chunk boundary matched nothing and its circuit vanished from the count.
// Measured before the fix, on identical bytes: 3 circuits when delivered whole,
// 2 when the boundary landed mid-line, and 0 when the only line was split --
// which made start() refuse to serve against a perfectly healthy verifier.
test('the circuit count does not depend on where the pipe happens to chunk', () => {
  const whole = stream(3);
  const expected = 3;

  assert.equal(countAcrossChunks([whole]), expected, 'delivered in one piece');

  // Every possible split point must give the same answer.
  for (let cut = 1; cut < whole.length; cut++) {
    const got = countAcrossChunks([whole.slice(0, cut), whole.slice(cut)]);
    assert.equal(got, expected, `lost a circuit when the chunk boundary fell at byte ${cut}`);
  }
});

test('a single circuit line survives a split anywhere inside it', () => {
  const one = stream(1);
  for (let cut = 1; cut < one.length; cut++) {
    assert.equal(
      countAcrossChunks([one.slice(0, cut), one.slice(cut)]),
      1,
      `counted 0 circuits with the boundary at byte ${cut} -- would refuse to start a healthy server`,
    );
  }
});

test('byte-at-a-time delivery still counts correctly', () => {
  assert.equal(countAcrossChunks([...stream(5)]), 5);
});

test('splitLines holds back an unterminated final line', () => {
  const a = splitLines('', 'complete\npartial');
  assert.deepEqual(a.lines, ['complete']);
  assert.equal(a.residual, 'partial', 'an unterminated line is not yet a line');

  const b = splitLines(a.residual, ' now finished\n');
  assert.deepEqual(b.lines, ['partial now finished']);
  assert.equal(b.residual, '');
});

test('splitLines handles empty chunks and bare newlines', () => {
  assert.deepEqual(splitLines('', ''), { lines: [], residual: '' });
  assert.deepEqual(splitLines('', '\n'), { lines: [''], residual: '' });
  assert.deepEqual(splitLines('x', ''), { lines: [], residual: 'x' });
});
