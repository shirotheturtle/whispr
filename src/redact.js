import { scan } from './scan.js';

const TOKEN_BY_CATEGORY = {
  seed_phrase:    '[REDACTED:SEED_PHRASE]',
  private_key:    '[REDACTED:PRIVATE_KEY]',
  api_key:        '[REDACTED:API_KEY]',
  wallet_address: '[REDACTED:WALLET_ADDRESS]',
};

export function redact(input, options = {}) {
  if (typeof input !== 'string') {
    throw new TypeError('redact() expects a string input');
  }
  const findings = scan(input);
  const skip = new Set(options.skip ?? []);

  // Apply right-to-left so earlier indices remain valid as we mutate the string.
  const sorted = [...findings].sort((a, b) => b.index - a.index);
  let out = input;
  for (const f of sorted) {
    if (skip.has(f.category)) continue;
    const token = TOKEN_BY_CATEGORY[f.category] ?? '[REDACTED]';
    out = out.slice(0, f.index) + token + out.slice(f.index + f.length);
  }
  return { redacted: out, findings };
}
