import { test } from 'node:test';
import assert from 'node:assert/strict';
import { computeBenchmark } from '../bench/run.js';

// Locks the published benchmark numbers: 100% recall on synthetic positives,
// zero false positives on the FP traps. If a detector change regresses either,
// this fails in `npm test` before the README claim can go stale.

test('benchmark: 100% recall on synthetic positives', () => {
  const { totals } = computeBenchmark();
  assert.equal(totals.fn, 0, 'expected zero false negatives');
  assert.equal(totals.recall, 1, 'expected 100% recall');
});

test('benchmark: zero false positives on traps', () => {
  const { totals } = computeBenchmark();
  assert.equal(totals.fp, 0, 'expected zero false positives');
});

test('benchmark: every case passes', () => {
  const { cases } = computeBenchmark();
  const failed = cases.filter((c) => !c.pass).map((c) => c.id);
  assert.deepEqual(failed, [], `failing cases: ${failed.join(', ')}`);
});
