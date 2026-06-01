import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../src/redact.js';

test('redacts API key in place', () => {
  const input = 'export OPENAI_API_KEY=sk-' + 'X'.repeat(48);
  const { redacted, findings } = redact(input);
  assert.equal(findings.length, 1);
  assert.ok(redacted.includes('[REDACTED:API_KEY]'));
  assert.ok(!redacted.includes('sk-X'), 'raw API key bytes must not survive redaction');
});

test('redacts multiple findings with correct ordering', () => {
  const input = 'pk=' + 'a'.repeat(64) + ' wallet=0x' + 'B'.repeat(40);
  const { redacted, findings } = redact(input);
  assert.equal(findings.length, 2);
  assert.ok(redacted.includes('[REDACTED:PRIVATE_KEY]'));
  assert.ok(redacted.includes('[REDACTED:WALLET_ADDRESS]'));
  assert.ok(!redacted.includes('a'.repeat(64)));
  assert.ok(!redacted.includes('B'.repeat(40)));
});

test('preserves non-sensitive surrounding text', () => {
  const input = 'before sk-' + 'X'.repeat(48) + ' after';
  const { redacted } = redact(input);
  assert.ok(redacted.startsWith('before '));
  assert.ok(redacted.endsWith(' after'));
});

test('skip option leaves specified category unredacted', () => {
  const wallet = '0x' + 'B'.repeat(40);
  const input = `wallet=${wallet} key=sk-` + 'X'.repeat(48);
  const { redacted } = redact(input, { skip: ['wallet_address'] });
  assert.ok(redacted.includes(wallet), 'wallet should remain when skipped');
  assert.ok(redacted.includes('[REDACTED:API_KEY]'));
});

test('redacting benign text returns input unchanged', () => {
  const benign = 'hello world, nothing sensitive here';
  const { redacted, findings } = redact(benign);
  assert.equal(redacted, benign);
  assert.equal(findings.length, 0);
});

test('throws TypeError on non-string input', () => {
  assert.throws(() => redact(null), TypeError);
  assert.throws(() => redact(42), TypeError);
});
