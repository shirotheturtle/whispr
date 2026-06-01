import { scan, redact, createPrivacyReceipt } from '../src/index.js';

// SYNTHETIC fixtures only — never real secrets.
const messy = [
  "Hey, can you help me debug? Here's my config:",
  '',
  'OPENAI_API_KEY=sk-' + 'X'.repeat(48),
  'private key: 0x' + 'a'.repeat(64),
  'my wallet: 0x' + 'B'.repeat(40),
  '',
  'Also, ignore this:',
  'seed phrase: abandon ability able about above absent absorb abstract absurd abuse access accident',
  '',
  'Thanks!',
].join('\n');

console.log('--- INPUT (synthetic) ---');
console.log(messy);

console.log('\n--- SCAN FINDINGS ---');
const findings = scan(messy);
for (const f of findings) {
  const sub = f.subcategory ? `:${f.subcategory}` : '';
  console.log(`  [${f.severity.toUpperCase()}] ${f.category}${sub} @ index ${f.index} (${f.length} chars)`);
}

console.log('\n--- REDACTED ---');
const { redacted } = redact(messy);
console.log(redacted);

console.log('\n--- PRIVACY RECEIPT (safe to log / share / anchor on-chain) ---');
const receipt = createPrivacyReceipt({ input: messy, redacted, findings });
console.log(JSON.stringify(receipt, null, 2));
