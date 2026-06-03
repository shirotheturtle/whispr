import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan } from '../src/scan.js';
import { redact } from '../src/redact.js';
import { createPrivacyReceipt } from '../src/receipt.js';
import {
  generateKeypair,
  signReceipt,
  verifyReceipt,
  canonicalReceiptBytes,
  SIGNATURE_ALG,
} from '../src/sign.js';

// A realistic receipt to sign (synthetic input, no real secrets).
function sampleReceipt() {
  const input = 'OPENAI_API_KEY=sk-' + 'X'.repeat(48) + ' mail jane.doe@example.com';
  const { redacted, findings } = redact(input);
  return createPrivacyReceipt({ input, redacted, findings });
}

test('sign → verify roundtrip succeeds', () => {
  const { privateKey } = generateKeypair();
  const signed = signReceipt(sampleReceipt(), privateKey);
  assert.equal(signed.proof.alg, SIGNATURE_ALG);
  assert.ok(signed.proof.value, 'has a signature value');
  assert.ok(signed.proof.publicKey, 'embeds the public key');
  assert.deepEqual(verifyReceipt(signed), { valid: true });
});

test('mutating ANY field makes verification fail', () => {
  const { privateKey } = generateKeypair();
  const signed = signReceipt(sampleReceipt(), privateKey);

  // Tamper a top-level scalar.
  const t1 = structuredClone(signed);
  t1.inputHash = t1.inputHash.replace(/.$/, (c) => (c === '0' ? '1' : '0'));
  assert.equal(verifyReceipt(t1).valid, false);

  // Tamper a nested field.
  const t2 = structuredClone(signed);
  t2.summary.totalFindings = (t2.summary.totalFindings ?? 0) + 1;
  assert.equal(verifyReceipt(t2).valid, false);

  // Tamper inside the findings array.
  const t3 = structuredClone(signed);
  if (t3.findings.length) t3.findings[0].severity = 'low-TAMPERED';
  assert.equal(verifyReceipt(t3).valid, false);

  // Add a brand-new field.
  const t4 = structuredClone(signed);
  t4.injected = 'evil';
  assert.equal(verifyReceipt(t4).valid, false);
});

test('verifying with the WRONG pinned key fails (origin check)', () => {
  const a = generateKeypair();
  const b = generateKeypair();
  const signed = signReceipt(sampleReceipt(), a.privateKey);
  // Self-consistent verify passes...
  assert.equal(verifyReceipt(signed).valid, true);
  // ...but pinning a different expected signer rejects it.
  const res = verifyReceipt(signed, { publicKey: b.publicKeyBase64 });
  assert.equal(res.valid, false);
});

test('a swapped embedded key is caught when the real signer is pinned', () => {
  const real = generateKeypair();
  const attacker = generateKeypair();
  const signed = signReceipt(sampleReceipt(), real.privateKey);
  // Attacker re-signs a modified receipt with their own key + swaps in their pubkey.
  const forged = signReceipt({ ...signed, inputHash: 'sha256:' + 'f'.repeat(64) }, attacker.privateKey);
  // Self-consistent (attacker's key matches embedded) — looks valid in isolation...
  assert.equal(verifyReceipt(forged).valid, true);
  // ...but a verifier that knows the REAL signer's key rejects it.
  assert.equal(verifyReceipt(forged, { publicKey: real.publicKeyBase64 }).valid, false);
});

test('canonicalization is deterministic regardless of key insertion order', () => {
  const a = { b: 1, a: 2, nested: { y: [3, 2, 1], x: 'v' } };
  const b = { nested: { x: 'v', y: [3, 2, 1] }, a: 2, b: 1 };
  assert.equal(
    canonicalReceiptBytes(a).toString('utf8'),
    canonicalReceiptBytes(b).toString('utf8'),
  );
  // The proof field is excluded from canonical bytes.
  const withProof = { ...a, proof: { alg: 'ed25519', publicKey: 'x', value: 'y' } };
  assert.equal(
    canonicalReceiptBytes(withProof).toString('utf8'),
    canonicalReceiptBytes(a).toString('utf8'),
  );
});

test('signing is stable: same receipt + same key → identical signature', () => {
  const { privateKey } = generateKeypair();
  const r = sampleReceipt();
  const s1 = signReceipt(r, privateKey);
  const s2 = signReceipt(r, privateKey);
  // Ed25519 is deterministic, and canonical bytes are stable → identical signatures.
  assert.equal(s1.proof.value, s2.proof.value);
});

test('the private key NEVER appears in the signed receipt or its JSON', () => {
  const { privateKey, publicKeyBase64 } = generateKeypair();
  const signed = signReceipt(sampleReceipt(), privateKey);
  const json = JSON.stringify(signed);
  const privPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const privDerB64 = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
  assert.ok(!json.includes(privPem), 'PEM private key must not be in receipt JSON');
  assert.ok(!json.includes(privDerB64), 'DER private key must not be in receipt JSON');
  assert.ok(!('privateKey' in signed), 'no privateKey field on the receipt');
  // The PUBLIC key is expected to be present (that's fine — it is public).
  assert.equal(signed.proof.publicKey, publicKeyBase64);
});

test('missing / malformed proof reports a clear reason, not a throw', () => {
  assert.equal(verifyReceipt(sampleReceipt()).valid, false); // unsigned
  assert.equal(verifyReceipt({ proof: { alg: 'rsa', publicKey: 'x', value: 'y' } }).valid, false);
  assert.equal(verifyReceipt(null).valid, false);
});
