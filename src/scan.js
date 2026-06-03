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

// 64 hex chars (with optional 0x prefix). A bare 64-hex string is INDISTINGUISHABLE from a
// SHA-256 digest, which is everywhere in real agent output (lockfiles, git, Docker, CI logs).
// So we only treat 64-hex as a private key on a positive signal: a `0x` prefix, or a key-ish
// label immediately before it (KEY_CONTEXT_RE). Unlabelled bare 64-hex is left alone rather
// than flagging every checksum as a critical key — see README "Known limitations".
const HEX_PRIVATE_KEY_RE = /\b(?:0x)?[0-9a-fA-F]{64}\b/g;

// Key-ish label that must sit immediately before a bare 64-hex for it to count as a private key.
// The `$` anchor makes it positional (matches "pk=", "private key:" right before the hex —
// NOT "the key insight is <hex>" or "cache hash: <hex>").
const KEY_CONTEXT_RE =
  /(?:private[\s_-]*key|priv[\s_-]*key|privkey|secret[\s_-]*key|signing[\s_-]*key|\bpk\b|\bsk\b)\s*[:=]?\s*$/i;

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

// JWT: three base64url segments. Header AND payload both start with "eyJ" (base64url of `{"`),
// which makes this far more specific than a generic 3-segment match → very low FP rate.
const JWT_RE = /\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g;

// PEM private key block (RSA/EC/DSA/OpenSSH/PGP or unlabelled). Matches the whole armoured
// block so the entire secret is redacted, not just a header line.
const PEM_PRIVATE_KEY_RE =
  /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g;

// Email (PII). Standard local@domain.tld shape.
const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

// US SSN (PII). Negative lookaheads drop structurally-invalid SSNs (000/666/9xx area,
// 00 group, 0000 serial) — a cheap, large reduction in false positives on random 3-2-4 numbers.
const SSN_RE = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;

// Credit-card candidate: 13–19 digits, optionally space/dash grouped. This is only a CANDIDATE —
// every hit is Luhn-validated below, which is what actually distinguishes a card number from an
// arbitrary long number (a random 16-digit number passes Luhn only ~10% of the time).
const CC_CANDIDATE_RE = /\b\d(?:[ -]?\d){12,18}\b/g;

// Generic high-entropy secret catch-all (unknown/unbranded tokens). Deliberately the LAST pass,
// heavily guarded (mixed letter+digit, not hex/UUID-shaped, Shannon entropy ≥ threshold, no
// overlap with a more specific finding) to keep false positives low on prose, hashes, and IDs.
const HIGH_ENTROPY_RE = /[A-Za-z0-9_\-+/=]{24,}/g;
const HIGH_ENTROPY_MIN_BITS = 4.0;

function rangesOverlap(aStart, aLen, bStart, bLen) {
  return aStart < bStart + bLen && bStart < aStart + aLen;
}

// Luhn checksum — the gate that turns a "long number" into a probable card number.
function luhnValid(digits) {
  let sum = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alt) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alt = !alt;
  }
  return sum % 10 === 0;
}

// Shannon entropy in bits/char — measures randomness to separate real secrets from words/IDs.
function shannonEntropy(s) {
  const freq = Object.create(null);
  for (const ch of s) freq[ch] = (freq[ch] ?? 0) + 1;
  let e = 0;
  for (const k in freq) {
    const p = freq[k] / s.length;
    e -= p * Math.log2(p);
  }
  return e;
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

  // PEM blocks first so the hex pass below skips any 64-hex lines inside the armoured body.
  for (const m of input.matchAll(PEM_PRIVATE_KEY_RE)) {
    findings.push({
      category: 'private_key',
      subcategory: 'pem',
      severity: 'critical',
      match: m[0],
      index: m.index,
      length: m[0].length,
    });
  }

  for (const m of input.matchAll(HEX_PRIVATE_KEY_RE)) {
    if (findings.some((f) => rangesOverlap(f.index, f.length, m.index, m[0].length))) continue;
    const has0x = m[0].startsWith('0x');
    const labelled = has0x || KEY_CONTEXT_RE.test(input.slice(Math.max(0, m.index - 40), m.index));
    if (labelled) {
      // Strong signal (0x prefix or key-ish label) → confirmed private key.
      findings.push({
        category: 'private_key',
        severity: 'critical',
        match: m[0],
        index: m.index,
        length: m[0].length,
      });
    } else {
      // Bare unlabelled 64-hex is information-theoretically AMBIGUOUS: a SHA-256 digest and a
      // secp256k1/Ethereum private key are the exact same shape — you cannot tell them apart
      // from content alone. We can't skip it (that would silently pass a real raw key — the
      // worse failure for a privacy guard), and we can't call it a confirmed key (that would
      // flag every checksum as critical). So: redact-if-in-doubt at medium, honest about why.
      findings.push({
        category: 'ambiguous_secret',
        severity: 'medium',
        match: m[0],
        index: m.index,
        length: m[0].length,
        note: '64-hex: could be a SHA-256 digest or a private key',
      });
    }
  }

  for (const m of input.matchAll(JWT_RE)) {
    findings.push({
      category: 'jwt',
      severity: 'high',
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

  for (const m of input.matchAll(EMAIL_RE)) {
    findings.push({
      category: 'email',
      severity: 'low',
      match: m[0],
      index: m.index,
      length: m[0].length,
    });
  }

  for (const m of input.matchAll(SSN_RE)) {
    findings.push({
      category: 'ssn',
      severity: 'high',
      match: m[0],
      index: m.index,
      length: m[0].length,
    });
  }

  for (const m of input.matchAll(CC_CANDIDATE_RE)) {
    const digits = m[0].replace(/[ -]/g, '');
    if (digits.length < 13 || digits.length > 19) continue;
    if (!luhnValid(digits)) continue;
    if (findings.some((f) => rangesOverlap(f.index, f.length, m.index, m[0].length))) continue;
    findings.push({
      category: 'credit_card',
      severity: 'high',
      match: m[0],
      index: m.index,
      length: m[0].length,
    });
  }

  // High-entropy catch-all runs LAST so it only fires on tokens no specific detector claimed.
  for (const m of input.matchAll(HIGH_ENTROPY_RE)) {
    const tok = m[0];
    // Require BOTH a letter and a digit: drops prose and pure-number IDs.
    if (!/[A-Za-z]/.test(tok) || !/[0-9]/.test(tok)) continue;
    // Skip hex/UUID shapes (hashes, UUIDs) — handled elsewhere or intentionally not secret.
    if (/^[0-9a-fA-F-]+$/.test(tok)) continue;
    if (shannonEntropy(tok) < HIGH_ENTROPY_MIN_BITS) continue;
    if (findings.some((f) => rangesOverlap(f.index, f.length, m.index, tok.length))) continue;
    findings.push({
      category: 'high_entropy',
      severity: 'medium',
      match: tok,
      index: m.index,
      length: tok.length,
    });
  }

  findings.sort((a, b) => a.index - b.index);
  return findings;
}
