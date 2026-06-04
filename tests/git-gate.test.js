import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  runPrePushGate,
  parseRefUpdates,
  addedByFile,
  EMPTY_TREE,
} from '../src/git-gate.js';
import { generateKeypair } from '../src/sign.js';
import { verifyReceipt } from '../src/sign.js';

// IMPORTANT: all fixtures are SYNTHETIC — no real secrets. Keys use repeated/placeholder
// chars so they match a detector's SHAPE without ever being a real credential.

const SHA_A = 'a'.repeat(40);
const SHA_B = 'b'.repeat(40);
const ZERO = '0'.repeat(40);

// Build a minimal unified diff that addedByFile() understands.
function makeDiff(file, addedLines) {
  return [
    `diff --git a/${file} b/${file}`,
    `--- /dev/null`,
    `+++ b/${file}`,
    `@@ -0,0 +1,${addedLines.length} @@`,
    ...addedLines.map((l) => `+${l}`),
    '',
  ].join('\n');
}

const update = (over = {}) => ({
  localRef: 'refs/heads/main',
  localSha: SHA_A,
  remoteRef: 'refs/heads/main',
  remoteSha: SHA_B,
  ...over,
});

test('parseRefUpdates parses git pre-push stdin lines', () => {
  const ups = parseRefUpdates(`refs/heads/main ${SHA_A} refs/heads/main ${SHA_B}\n`);
  assert.equal(ups.length, 1);
  assert.equal(ups[0].localSha, SHA_A);
  assert.equal(ups[0].remoteSha, SHA_B);
});

test('addedByFile attributes added lines to their file (ignores +++ header)', () => {
  const diff = makeDiff('config.js', ['const ok = true;', 'const port = 3000;']);
  const map = addedByFile(diff);
  assert.deepEqual([...map.keys()], ['config.js']);
  assert.equal(map.get('config.js').length, 2);
});

test('secret in the diff → push BLOCKED, finding attributed to file, receipt emitted', () => {
  const apiKey = 'sk-ant-' + 'A'.repeat(30); // synthetic anthropic-shaped key (critical)
  const diff = makeDiff('src/leak.js', [`const key = "${apiKey}";`]);
  const { privateKey } = generateKeypair();
  const res = runPrePushGate({
    refUpdates: [update()],
    runGit: () => diff,
    signingKey: privateKey,
    repo: 'example/repo',
  });
  assert.equal(res.blocked, true);
  assert.ok(res.blocking.some((f) => f.category === 'api_key'));
  assert.ok(res.blocking.some((f) => f.file === 'src/leak.js'));
  assert.ok(res.receipt, 'a receipt is emitted even when blocked');
  assert.equal(res.receipt.credentialSubject.gitContext.blocked, true);
  // receipt must NOT leak the raw secret value anywhere
  assert.ok(!JSON.stringify(res.receipt).includes(apiKey), 'raw secret must never appear in the receipt');
});

test('clean diff → push ALLOWED + signed receipt that verifies', () => {
  const diff = makeDiff('src/app.js', ['function add(a, b) {', '  return a + b;', '}']);
  const { privateKey } = generateKeypair();
  const res = runPrePushGate({
    refUpdates: [update()],
    runGit: (args) => {
      // sanity: existing branch diffs against the remote sha
      assert.ok(args.join(' ').includes(`${SHA_B}..${SHA_A}`));
      return diff;
    },
    signingKey: privateKey,
    repo: 'example/repo',
  });
  assert.equal(res.blocked, false);
  assert.equal(res.findings.length, 0);
  assert.ok(res.receipt);
  assert.equal(verifyReceipt(res.receipt).valid, true, 'emitted receipt signature verifies');
});

test('fail-closed: a git error BLOCKS the push (never silently allows)', () => {
  const res = runPrePushGate({
    refUpdates: [update()],
    runGit: () => {
      throw new Error('git exploded');
    },
    repo: 'example/repo',
  });
  assert.equal(res.blocked, true);
  assert.match(res.reason, /fail-closed/);
  assert.equal(res.receipt, null);
});

test('new branch (remote all-zero) → diff vs the empty tree (scan full content)', () => {
  let seenBase = null;
  const diff = makeDiff('README.md', ['# hello']);
  runPrePushGate({
    refUpdates: [update({ remoteSha: ZERO })],
    runGit: (args) => {
      seenBase = args[args.length - 1];
      return diff;
    },
  });
  assert.equal(seenBase, `${EMPTY_TREE}..${SHA_A}`);
});

test('ref deletion (local all-zero) → nothing scanned, allowed', () => {
  let called = false;
  const res = runPrePushGate({
    refUpdates: [update({ localSha: ZERO })],
    runGit: () => {
      called = true;
      return '';
    },
  });
  assert.equal(called, false, 'no diff is requested for a deletion');
  assert.equal(res.blocked, false);
});

test('block threshold is configurable: a low-severity finding blocks only at blockSeverity=low', () => {
  const diff = makeDiff('notes.txt', ['contact me at user@example.com']); // email = low severity
  const high = runPrePushGate({ refUpdates: [update()], runGit: () => diff, blockSeverity: 'high' });
  assert.equal(high.blocked, false, 'low-severity PII does not block at default high threshold');
  assert.ok(high.findings.some((f) => f.category === 'email'), 'but it is still detected/recorded');

  const low = runPrePushGate({ refUpdates: [update()], runGit: () => diff, blockSeverity: 'low' });
  assert.equal(low.blocked, true, 'blocks at blockSeverity=low');
});

test('PEM private key in diff → blocked (reuses the existing PEM detector)', () => {
  const pem = [
    '-----BEGIN PRIVATE KEY-----',
    'MIIBVAIBADAN' + 'A'.repeat(40),
    '-----END PRIVATE KEY-----',
  ];
  const diff = makeDiff('id_ed25519', pem);
  const res = runPrePushGate({ refUpdates: [update()], runGit: () => diff, repo: 'r' });
  assert.equal(res.blocked, true);
  assert.ok(res.blocking.some((f) => f.category === 'private_key'));
});
