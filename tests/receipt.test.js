import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../src/redact.js';
import {
  createPrivacyReceipt,
  RECEIPT_VERSION,
  SCANNER_VERSION,
} from '../src/receipt.js';

test('receipt has expected shape', () => {
  const input = 'key=sk-' + 'X'.repeat(48);
  const { redacted, findings } = redact(input);
  const receipt = createPrivacyReceipt({ input, redacted, findings });

  assert.equal(receipt.version, RECEIPT_VERSION);
  assert.equal(receipt.scannerVersion, SCANNER_VERSION);
  assert.match(receipt.receiptId, /^[0-9a-f-]{36}$/);
  assert.match(receipt.createdAt, /^\d{4}-\d{2}-\d{2}T/);
  assert.match(receipt.inputHash, /^sha256:[0-9a-f]{64}$/);
  assert.match(receipt.redactedHash, /^sha256:[0-9a-f]{64}$/);
  assert.equal(receipt.summary.totalFindings, 1);
  assert.equal(receipt.summary.byCategory.api_key, 1);
  assert.equal(receipt.summary.highestSeverity, 'high');
});

test('receipt does NOT leak the matched value', () => {
  const input = 'secret = sk-' + 'X'.repeat(48);
  const { redacted, findings } = redact(input);
  const receipt = createPrivacyReceipt({ input, redacted, findings });
  const serialised = JSON.stringify(receipt);
  assert.ok(!serialised.includes('sk-X'), 'receipt must not leak the raw API key');
});

test('receipt does NOT leak match indices or lengths', () => {
  const input = 'pk=' + 'a'.repeat(64);
  const { redacted, findings } = redact(input);
  const receipt = createPrivacyReceipt({ input, redacted, findings });
  for (const f of receipt.findings) {
    assert.equal(f.match, undefined, 'finding.match must be stripped from receipt');
    assert.equal(f.index, undefined, 'finding.index must be stripped from receipt');
    assert.equal(f.length, undefined, 'finding.length must be stripped from receipt');
  }
});

test('identical input + redacted produces identical hashes (verifiability)', () => {
  const a = createPrivacyReceipt({ input: 'foo', redacted: 'foo', findings: [] });
  const b = createPrivacyReceipt({ input: 'foo', redacted: 'foo', findings: [] });
  assert.equal(a.inputHash, b.inputHash);
  assert.equal(a.redactedHash, b.redactedHash);
  // receiptId and createdAt should differ (they are not part of the hash)
  assert.notEqual(a.receiptId, b.receiptId);
});

test('summary highestSeverity escalates correctly', () => {
  const r = createPrivacyReceipt({
    input: 'x',
    redacted: 'x',
    findings: [
      { category: 'wallet_address', severity: 'low' },
      { category: 'api_key',        severity: 'high' },
      { category: 'private_key',    severity: 'critical' },
    ],
  });
  assert.equal(r.summary.highestSeverity, 'critical');
  assert.equal(r.summary.totalFindings, 3);
  assert.deepEqual(r.summary.byCategory, {
    wallet_address: 1,
    api_key: 1,
    private_key: 1,
  });
});

test('empty findings list produces a valid receipt', () => {
  const r = createPrivacyReceipt({ input: 'foo', redacted: 'foo', findings: [] });
  assert.equal(r.summary.totalFindings, 0);
  assert.equal(r.summary.highestSeverity, null);
  assert.deepEqual(r.summary.byCategory, {});
});

test('throws TypeError on invalid arguments', () => {
  assert.throws(() => createPrivacyReceipt({ input: 123, redacted: '', findings: [] }), TypeError);
  assert.throws(() => createPrivacyReceipt({ input: '', redacted: null, findings: [] }), TypeError);
  assert.throws(() => createPrivacyReceipt({ input: '', redacted: '', findings: 'nope' }), TypeError);
});
