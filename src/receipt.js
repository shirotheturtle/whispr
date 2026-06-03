import { createHash, randomUUID } from 'node:crypto';

export const SCANNER_VERSION = '0.1.0';
export const RECEIPT_VERSION = 'whispr-receipt/v0';

const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };

function sha256(s) {
  return 'sha256:' + createHash('sha256').update(s, 'utf8').digest('hex');
}

export function createPrivacyReceipt({ input, redacted, findings }) {
  if (typeof input !== 'string') {
    throw new TypeError('createPrivacyReceipt: input must be a string');
  }
  if (typeof redacted !== 'string') {
    throw new TypeError('createPrivacyReceipt: redacted must be a string');
  }
  if (!Array.isArray(findings)) {
    throw new TypeError('createPrivacyReceipt: findings must be an array');
  }

  const byCategory = {};
  let highestSeverity = null;
  for (const f of findings) {
    byCategory[f.category] = (byCategory[f.category] ?? 0) + 1;
    if (
      highestSeverity === null ||
      (SEVERITY_RANK[f.severity] ?? -1) > (SEVERITY_RANK[highestSeverity] ?? -1)
    ) {
      highestSeverity = f.severity;
    }
  }

  // findings in the receipt MUST NOT include `match`, `index`, or `length`.
  // Receipts are designed to be safe to log / share / anchor — leaking position
  // or the raw match would defeat the purpose.
  const findingsSafe = findings.map((f) => {
    const safe = { category: f.category, severity: f.severity };
    if (f.subcategory) safe.subcategory = f.subcategory;
    return safe;
  });

  return {
    version: RECEIPT_VERSION,
    scannerVersion: SCANNER_VERSION,
    receiptId: randomUUID(),
    createdAt: new Date().toISOString(),
    inputHash: sha256(input),
    redactedHash: sha256(redacted),
    findings: findingsSafe,
    summary: {
      totalFindings: findings.length,
      byCategory,
      highestSeverity,
    },
  };
}

// W3C VC data-model context + a whispr-specific term context. The second URL is a
// namespace identifier for the PrivacyReceipt terms; it is a placeholder until a
// resolvable JSON-LD context is published (required for full VC conformance — see
// CREDENTIAL_PROFILE / the "VC-aligned, not yet conformant" note in the README).
export const VC_CONTEXT = [
  'https://www.w3.org/ns/credentials/v2',
  'https://shirotheturtle.github.io/whispr/contexts/privacy-receipt/v1',
];
export const CREDENTIAL_PROFILE = 'whispr-privacy-receipt/v1';

/**
 * Build a VC-aligned privacy receipt (unsigned). Pass it to `signReceipt` from
 * `whispr/sign` to attach an Ed25519 `proof`.
 *
 * Shape follows the W3C Verifiable Credential data model (@context, type, issuer,
 * issuanceDate, credentialSubject). The credentialSubject carries ONLY the safe
 * receipt fields (hashes + counts + categories) — never the raw matches, positions,
 * or original/redacted text. `issuer` is a caller-supplied identifier (e.g. an agent
 * DID or URL); it defaults to a placeholder when omitted.
 */
export function createPrivacyCredential({ input, redacted, findings, issuer } = {}) {
  const receipt = createPrivacyReceipt({ input, redacted, findings });
  return {
    '@context': VC_CONTEXT,
    type: ['VerifiableCredential', 'PrivacyReceipt'],
    issuer: issuer ?? 'urn:whispr:unspecified-issuer',
    issuanceDate: receipt.createdAt,
    credentialSubject: {
      id: `urn:uuid:${receipt.receiptId}`,
      profile: CREDENTIAL_PROFILE,
      scannerVersion: receipt.scannerVersion,
      inputHash: receipt.inputHash,
      redactedHash: receipt.redactedHash,
      findings: receipt.findings,
      summary: receipt.summary,
    },
  };
}
