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
