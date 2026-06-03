// Signed privacy-receipts (whispr Phase 1).
//
// Turns a privacy receipt from "trust us, we redacted" into "here is proof you can
// verify": an Ed25519 signature over the canonical bytes of the receipt. Anyone with
// the public key can confirm the receipt was signed by that key and not altered since.
//
// What a signature proves: INTEGRITY (the receipt's fields are unchanged) + ORIGIN
// (the holder of the matching private key signed it). It does NOT prove the scan was
// complete or that the data is "safe" — only that this exact receipt was signed.
//
// Stays 100% offline: only node:crypto, no network. On-chain anchoring of the receipt
// hash is a separate, opt-in concern and never part of sign/verify.

import {
  generateKeyPairSync,
  createPublicKey,
  createPrivateKey,
  sign as edSign,
  verify as edVerify,
} from 'node:crypto';

export const SIGNATURE_ALG = 'ed25519';
// Honest, self-describing proof type. NOT a registered W3C Data-Integrity suite — it is
// Ed25519 over JCS-canonical (RFC 8785) bytes of the credential sans `proof`. The receipt
// is "VC-aligned" (uses the VC data model), not yet full VC Data-Integrity conformant.
export const PROOF_TYPE = 'Ed25519Jcs2026';

// --- Canonical serialization (JCS / RFC 8785 for our value types) ------------
// Deterministic so the same credential always produces the same bytes on any OS:
//   - object keys sorted (UTF-16 code-unit order, via default Array#sort on strings) [JCS]
//   - keys whose value is `undefined` are omitted (never emitted as null)
//   - no insignificant whitespace [JCS]
//   - arrays preserve order (order can be meaningful)
//   - strings/numbers via JSON.stringify (our receipts use only strings + safe integers,
//     for which JSON.stringify matches RFC 8785's ECMAScript number serialization)
// The top-level `proof` field is EXCLUDED before signing — you can't sign over the proof
// you're about to produce, and a verifier strips it identically. This byte-for-byte match
// between sign and verify is the crux; without it verification is impossible.
function canonicalize(value) {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return '[' + value.map((v) => canonicalize(v === undefined ? null : v)).join(',') + ']';
  }
  const keys = Object.keys(value)
    .filter((k) => value[k] !== undefined)
    .sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + canonicalize(value[k])).join(',') + '}';
}

/** Canonical UTF-8 bytes of a credential, with the `proof` field excluded. */
export function canonicalReceiptBytes(credential) {
  if (credential === null || typeof credential !== 'object' || Array.isArray(credential)) {
    throw new TypeError('canonicalReceiptBytes: credential must be an object');
  }
  const { proof, ...unsigned } = credential;
  return Buffer.from(canonicalize(unsigned), 'utf8');
}

// --- Keys --------------------------------------------------------------------
function publicKeyToBase64(publicKeyObj) {
  return publicKeyObj.export({ type: 'spki', format: 'der' }).toString('base64');
}

function toPrivateKeyObject(privateKey) {
  if (typeof privateKey === 'string') return createPrivateKey(privateKey);
  return privateKey; // assume a node KeyObject
}

function publicKeyObjectFromBase64(b64) {
  return createPublicKey({ key: Buffer.from(b64, 'base64'), format: 'der', type: 'spki' });
}

/**
 * Generate a dedicated Ed25519 signing keypair.
 * Returns the KeyObjects plus a portable base64 (SPKI DER) public key for embedding.
 * The private key is for the caller to hold securely — it is NEVER written into a receipt.
 */
export function generateKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  return { publicKey, privateKey, publicKeyBase64: publicKeyToBase64(publicKey) };
}

// --- Sign / verify -----------------------------------------------------------
/**
 * Sign a credential. Returns a NEW object with a VC-style `proof` block:
 *   proof: { type: 'Ed25519Jcs2026', alg: 'ed25519',
 *            publicKey: <base64 SPKI DER>, value: <base64 signature> }
 * Only the public key is embedded — the private key never appears in the output.
 */
export function signReceipt(credential, privateKey) {
  if (credential === null || typeof credential !== 'object' || Array.isArray(credential)) {
    throw new TypeError('signReceipt: credential must be an object');
  }
  const priv = toPrivateKeyObject(privateKey);
  const pub = createPublicKey(priv);
  const value = edSign(null, canonicalReceiptBytes(credential), priv).toString('base64');
  return {
    ...credential,
    proof: { type: PROOF_TYPE, alg: SIGNATURE_ALG, publicKey: publicKeyToBase64(pub), value },
  };
}

/**
 * Verify a signed credential → { valid, reason? }.
 * - With no options: checks INTEGRITY + that the embedded key signed it (self-consistent).
 * - With { publicKey: <base64> }: pins the EXPECTED signer, so a swapped embedded key is
 *   rejected — this is how you check ORIGIN (that key X, not just some key, signed it).
 */
export function verifyReceipt(credential, options = {}) {
  if (credential === null || typeof credential !== 'object' || Array.isArray(credential)) {
    return { valid: false, reason: 'credential is not an object' };
  }
  const proof = credential.proof;
  if (!proof || typeof proof !== 'object') return { valid: false, reason: 'missing proof' };
  if (proof.alg !== SIGNATURE_ALG) return { valid: false, reason: `unsupported alg: ${proof.alg}` };

  const expected = options.publicKey ?? proof.publicKey;
  if (!expected) return { valid: false, reason: 'no public key' };

  let pub;
  try {
    pub = publicKeyObjectFromBase64(expected);
  } catch {
    return { valid: false, reason: 'invalid public key' };
  }

  let ok;
  try {
    ok = edVerify(
      null,
      canonicalReceiptBytes(credential),
      pub,
      Buffer.from(proof.value ?? '', 'base64'),
    );
  } catch {
    return { valid: false, reason: 'malformed signature' };
  }
  return ok ? { valid: true } : { valid: false, reason: 'signature mismatch' };
}
