import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan } from '../src/scan.js';
import { redact } from '../src/redact.js';

// New S2 detectors: JWT, PEM private key, email, SSN, credit card (Luhn), high-entropy.
// All fixtures SYNTHETIC, valid-format only — no real/live secrets.

test('detects JWT (eyJ header.eyJ payload.sig)', () => {
  const jwt =
    'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
  const f = scan(`Authorization: Bearer ${jwt}`).filter((x) => x.category === 'jwt');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'high');
});

test('detects PEM private key block (subcategory pem)', () => {
  const pem =
    '-----BEGIN RSA PRIVATE KEY-----\nMIIBOgFAKEbodyXXXXXXXXXXXXXXXXXXXX\n-----END RSA PRIVATE KEY-----';
  const f = scan(pem).filter((x) => x.category === 'private_key');
  assert.equal(f.length, 1);
  assert.equal(f[0].subcategory, 'pem');
  assert.equal(f[0].severity, 'critical');
});

test('detects email (PII, low severity)', () => {
  const f = scan('reach me at jane.doe@example.com thanks').filter((x) => x.category === 'email');
  assert.equal(f.length, 1);
  assert.equal(f[0].severity, 'low');
});

test('detects valid-format SSN, rejects structurally-invalid ones', () => {
  assert.equal(scan('SSN 219-09-9999').filter((f) => f.category === 'ssn').length, 1);
  // area 000 / 666 / 9xx, group 00, serial 0000 are never issued -> not flagged.
  for (const bad of ['000-12-3456', '666-12-3456', '900-12-3456', '123-00-4567', '123-45-0000']) {
    assert.equal(scan(bad).filter((f) => f.category === 'ssn').length, 0, `should reject ${bad}`);
  }
});

test('detects credit card only when Luhn-valid', () => {
  assert.equal(scan('4111 1111 1111 1111').filter((f) => f.category === 'credit_card').length, 1);
  assert.equal(scan('5555555555554444').filter((f) => f.category === 'credit_card').length, 1);
  // Luhn-invalid 16-digit number -> not a card.
  assert.equal(scan('4111 1111 1111 1112').filter((f) => f.category === 'credit_card').length, 0);
});

test('high-entropy catch-all fires on random tokens, not on hex/UUID/prose', () => {
  const found = (t) => scan(t).filter((f) => f.category === 'high_entropy').length;
  assert.equal(found('token Kf3Jx9pQ2mZ7vL0aB8nR4tY6wC1dE5sG end'), 1);
  // UUID and 40-hex sha are hex/hyphen-shaped -> excluded.
  assert.equal(found('550e8400-e29b-41d4-a716-446655440000'), 0);
  assert.equal(found('9f86d081884c7d659a2feaa0c55ad015a3bf4f1b'), 0);
  // plain prose -> excluded.
  assert.equal(found('antidisestablishmentarianism internationalization'), 0);
});

test('64-hex: confirmed private_key on 0x/label, ambiguous_secret when bare (redact-if-in-doubt)', () => {
  const cat = (t) => scan(t).map((f) => f.category);
  // Strong signal (0x prefix or key-ish label) -> confirmed private_key / critical.
  assert.ok(cat('0x' + 'a'.repeat(64)).includes('private_key'));
  assert.ok(cat('pk=' + 'b'.repeat(64)).includes('private_key'));
  assert.ok(cat('private key: ' + 'c'.repeat(64)).includes('private_key'));
  // Bare, unlabelled 64-hex (SHA-256 OR a raw key — indistinguishable) -> NOT private_key,
  // but STILL flagged as ambiguous_secret so a real raw key is never silently passed.
  const sha = cat('build artifact sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.ok(!sha.includes('private_key'), 'bare 64-hex must not be a confirmed key');
  assert.ok(sha.includes('ambiguous_secret'), 'bare 64-hex must still be flagged (redact-if-in-doubt)');
  // The ambiguous finding is medium severity, not critical.
  const f = scan('wallet import ' + 'f'.repeat(64)).find((x) => x.category === 'ambiguous_secret');
  assert.equal(f.severity, 'medium');
});

test('redact replaces every new category with its labelled token', () => {
  const { redacted } = redact(
    'mail jane.doe@example.com card 4111 1111 1111 1111 ssn 219-09-9999 tok Kf3Jx9pQ2mZ7vL0aB8nR4tY6wC1dE5sG',
  );
  assert.ok(redacted.includes('[REDACTED:EMAIL]'));
  assert.ok(redacted.includes('[REDACTED:CREDIT_CARD]'));
  assert.ok(redacted.includes('[REDACTED:SSN]'));
  assert.ok(redacted.includes('[REDACTED:SECRET]'));
  assert.ok(!redacted.includes('example.com'));
  assert.ok(!redacted.includes('4111'));
});
