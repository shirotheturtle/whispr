// Pattern detectors for sensitive content.
// Each finding: { category, subcategory?, severity, match, index, length }

// Seed phrases: label-context only in S1 (e.g. "seed phrase: ...", "mnemonic ...").
// v0.2 roadmap: add BIP-39 wordlist validation for unlabelled phrases.
//
// The label part is case-insensitive (matches "Seed Phrase", "MNEMONIC", etc.) but the
// words part is STRICTLY lowercase — we don't use the /i flag because it would also make
// [a-z] case-insensitive, causing the regex to greedily absorb trailing uppercase prose
// (e.g. consuming "Thanks!" after a real seed phrase). Per-character char-classes for the
// labels keep case-insensitivity scoped where we want it.
const SEED_LABEL_RE = (() => {
  const labels = [
    'seed\\s*phrase',
    'mnemonic',
    'recovery\\s*phrase',
    'wallet\\s*phrase',
    'backup\\s*phrase',
    'secret\\s*phrase',
    'key\\s*phrase',
  ];
  // Make each lowercase letter case-insensitive, but DON'T touch chars inside escape
  // sequences like \s, \d, \n (otherwise \s becomes \[sS] which breaks the regex).
  const ci = (s) => {
    let out = '';
    for (let i = 0; i < s.length; i++) {
      if (s[i] === '\\' && i + 1 < s.length) {
        out += s[i] + s[i + 1];
        i++;
        continue;
      }
      out += /[a-z]/.test(s[i]) ? `[${s[i]}${s[i].toUpperCase()}]` : s[i];
    }
    return out;
  };
  return new RegExp(
    `(${labels.map(ci).join('|')})\\s*[:=]?\\s*\\n?\\s*((?:[a-z]{3,8}\\s+){11,23}[a-z]{3,8})`,
    'g',
  );
})();

// 64 hex chars (with optional 0x prefix). FP risk: SHA-256 hashes, UUIDs-as-hex.
// Flagged at critical severity since worst-case interpretation is a private key.
const HEX_PRIVATE_KEY_RE = /\b(?:0x)?[0-9a-fA-F]{64}\b/g;

// EVM-style wallet address: 0x + 40 hex. \b boundaries prevent overlap with 64-hex matches.
const EVM_ADDRESS_RE = /\b0x[0-9a-fA-F]{40}\b/g;

// Service-specific API key patterns. Order matters for sub-pattern overlap
// (e.g. sk-ant-... also matches sk-...) — caller may dedupe by index if desired.
const API_KEY_PATTERNS = [
  { name: 'anthropic_key',   re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,           severity: 'critical' },
  { name: 'openai_key',      re: /\bsk-[A-Za-z0-9_-]{20,}\b/g,               severity: 'high'     },
  { name: 'stripe_live_key', re: /\bsk_live_[A-Za-z0-9]{20,}\b/g,            severity: 'critical' },
  { name: 'stripe_test_key', re: /\bsk_test_[A-Za-z0-9]{20,}\b/g,            severity: 'high'     },
  { name: 'github_pat',      re: /\bghp_[A-Za-z0-9]{36,}\b/g,                severity: 'critical' },
  { name: 'github_oauth',    re: /\bgho_[A-Za-z0-9]{36,}\b/g,                severity: 'critical' },
  { name: 'aws_access_key',  re: /\bAKIA[A-Z0-9]{16}\b/g,                    severity: 'critical' },
  { name: 'slack_token',     re: /\bxox[bopa]-[A-Za-z0-9-]{10,}\b/g,         severity: 'high'     },
];

function rangesOverlap(aStart, aLen, bStart, bLen) {
  return aStart < bStart + bLen && bStart < aStart + aLen;
}

export function scan(input) {
  if (typeof input !== 'string') {
    throw new TypeError('scan() expects a string input');
  }
  if (input.length === 0) return [];

  const findings = [];

  for (const m of input.matchAll(SEED_LABEL_RE)) {
    const phrase = m[2];
    const phraseStart = m.index + m[0].indexOf(phrase);
    findings.push({
      category: 'seed_phrase',
      severity: 'critical',
      match: phrase,
      index: phraseStart,
      length: phrase.length,
    });
  }

  for (const m of input.matchAll(HEX_PRIVATE_KEY_RE)) {
    findings.push({
      category: 'private_key',
      severity: 'critical',
      match: m[0],
      index: m.index,
      length: m[0].length,
    });
  }

  for (const m of input.matchAll(EVM_ADDRESS_RE)) {
    findings.push({
      category: 'wallet_address',
      severity: 'low',
      match: m[0],
      index: m.index,
      length: m[0].length,
    });
  }

  // Dedupe overlapping API-key sub-pattern hits: keep the most specific (first hit at a given range wins,
  // since API_KEY_PATTERNS is ordered most-specific first).
  for (const { name, re, severity } of API_KEY_PATTERNS) {
    for (const m of input.matchAll(re)) {
      const overlaps = findings.some(
        (f) => f.category === 'api_key' && rangesOverlap(f.index, f.length, m.index, m[0].length),
      );
      if (overlaps) continue;
      findings.push({
        category: 'api_key',
        subcategory: name,
        severity,
        match: m[0],
        index: m.index,
        length: m[0].length,
      });
    }
  }

  findings.sort((a, b) => a.index - b.index);
  return findings;
}
