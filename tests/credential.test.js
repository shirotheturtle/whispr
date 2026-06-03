import { test } from 'node:test';
import assert from 'node:assert/strict';
import { redact } from '../src/redact.js';
import { createPrivacyCredential, VC_CONTEXT } from '../src/receipt.js';
import { generateKeypair, signReceipt, verifyReceipt, PROOF_TYPE } from '../src/sign.js';

function build(issuer) {
  const input = 'key=sk-' + 'X'.repeat(48) + ' ssn 219-09-9999';
  const { redacted, findings } = redact(input);
  return createPrivacyCredential({ input, redacted, findings, issuer });
}

test('credential follows the VC data model shape', () => {
  const c = build('did:example:agent-1');
  assert.deepEqual(c['@context'], VC_CONTEXT);
  assert.deepEqual(c.type, ['VerifiableCredential', 'PrivacyReceipt']);
  assert.equal(c.issuer, 'did:example:agent-1');
  assert.ok(c.issuanceDate, 'has issuanceDate');
  assert.ok(c.credentialSubject, 'has credentialSubject');
  assert.match(c.credentialSubject.id, /^urn:uuid:/);
  assert.ok(c.credentialSubject.inputHash.startsWith('sha256:'));
  assert.ok(c.credentialSubject.summary.totalFindings >= 1);
});

test('issuer defaults to a placeholder when omitted', () => {
  assert.equal(build().issuer, 'urn:whispr:unspecified-issuer');
});

test('credentialSubject never leaks raw matches, indices, or text', () => {
  const c = build();
  const json = JSON.stringify(c);
  assert.ok(!json.includes('sk-XXXX'), 'no raw secret value');
  assert.ok(!json.includes('219-09-9999'), 'no raw SSN');
  for (const f of c.credentialSubject.findings) {
    assert.ok(!('match' in f), 'finding has no match');
    assert.ok(!('index' in f), 'finding has no index');
    assert.ok(!('length' in f), 'finding has no length');
  }
});

test('build → sign → verify roundtrip on the VC credential', () => {
  const { privateKey } = generateKeypair();
  const signed = signReceipt(build('did:example:agent-1'), privateKey);
  assert.equal(signed.proof.type, PROOF_TYPE);
  assert.equal(verifyReceipt(signed).valid, true);
});

test('tampering the credentialSubject after signing fails verification', () => {
  const { privateKey } = generateKeypair();
  const signed = signReceipt(build(), privateKey);
  const tampered = structuredClone(signed);
  tampered.credentialSubject.summary.totalFindings = 0;
  assert.equal(verifyReceipt(tampered).valid, false);
});

test('changing the issuer after signing fails verification', () => {
  const { privateKey } = generateKeypair();
  const signed = signReceipt(build('did:example:real'), privateKey);
  const tampered = { ...signed, issuer: 'did:example:attacker' };
  assert.equal(verifyReceipt(tampered).valid, false);
});
