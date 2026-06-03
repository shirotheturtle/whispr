// whispr detection benchmark — recall + false-positive report.
//
// Pure, network-free: it only calls scan() over the synthetic fixtures.
// Run with `npm run bench`. The same computeBenchmark() is asserted by
// tests/bench.test.js so the published numbers can never silently drift.

import { scan } from '../src/index.js';
import { POSITIVES, FP_TRAPS, ALL_CASES } from './fixtures.js';

function countByCategory(list) {
  const m = Object.create(null);
  for (const c of list) m[c] = (m[c] ?? 0) + 1;
  return m;
}

// Compare expected vs found categories for one case, counting per category.
function scoreCase(expect, foundCats) {
  const exp = countByCategory(expect);
  const got = countByCategory(foundCats);
  const cats = new Set([...Object.keys(exp), ...Object.keys(got)]);
  let tp = 0;
  let fn = 0;
  let fp = 0;
  for (const cat of cats) {
    const e = exp[cat] ?? 0;
    const g = got[cat] ?? 0;
    tp += Math.min(e, g);
    if (e > g) fn += e - g;
    if (g > e) fp += g - e;
  }
  return { tp, fn, fp };
}

export function computeBenchmark() {
  let tp = 0;
  let fn = 0;
  let fp = 0;
  const cases = [];

  for (const c of ALL_CASES) {
    const foundCats = scan(c.text).map((f) => f.category);
    const s = scoreCase(c.expect, foundCats);
    tp += s.tp;
    fn += s.fn;
    fp += s.fp;
    cases.push({
      id: c.id,
      expected: c.expect,
      found: foundCats,
      pass: s.fn === 0 && s.fp === 0,
      ...s,
    });
  }

  const recall = tp + fn === 0 ? 1 : tp / (tp + fn);
  const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
  return {
    totals: {
      positives: POSITIVES.length,
      traps: FP_TRAPS.length,
      tp,
      fn,
      fp,
      recall,
      precision,
    },
    cases,
  };
}

function pct(x) {
  return (x * 100).toFixed(1) + '%';
}

function main() {
  const { totals, cases } = computeBenchmark();
  console.log('whispr detection benchmark');
  console.log('='.repeat(60));
  for (const c of cases) {
    const mark = c.pass ? 'PASS' : 'FAIL';
    const detail = c.pass
      ? ''
      : `  expected=[${c.expected.join(',')}] found=[${c.found.join(',')}]`;
    console.log(`  [${mark}] ${c.id}${detail}`);
  }
  console.log('='.repeat(60));
  console.log(`positives: ${totals.positives}   fp-traps: ${totals.traps}`);
  console.log(`true positives: ${totals.tp}   false negatives: ${totals.fn}   false positives: ${totals.fp}`);
  console.log(`recall:    ${pct(totals.recall)}   (TP / (TP + FN))`);
  console.log(`precision: ${pct(totals.precision)}   (TP / (TP + FP))`);
  if (totals.fn === 0 && totals.fp === 0) {
    console.log('\nclean: 100% recall on synthetic positives, 0 false positives on traps.');
  }
}

// Run only when invoked directly (so importing for tests has no side effects).
if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('run.js')) {
  main();
}
