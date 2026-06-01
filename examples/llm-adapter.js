// OPTIONAL adapter example — this is the ONE example that makes a network call.
//
// It scrubs a (synthetic) secret out of a prompt, prints the privacy-receipt,
// and sends the *redacted* prompt to an OpenAI-compatible provider
// (Bankr or Surplus Intelligence).
//
// Run it:
//   export WHISPR_PROVIDER=surplus
//   export SURPLUS_API_KEY=inf_YOUR_KEY_HERE      # never commit a real key
//   node examples/llm-adapter.js
//
//   # or Bankr:
//   export WHISPR_PROVIDER=bankr
//   export BANKR_API_KEY=bk_YOUR_KEY_HERE
//   node examples/llm-adapter.js
//
// With no env vars set it REFUSES to run (and sends nothing) — by design.

import { guardedChatCompletion } from '../src/adapter.js';

const provider = process.env.WHISPR_PROVIDER; // 'bankr' | 'surplus'
const KEY_ENV = { bankr: 'BANKR_API_KEY', surplus: 'SURPLUS_API_KEY' };
const MODEL = process.env.WHISPR_MODEL || 'claude-opus-4.6';

if (!provider || !KEY_ENV[provider]) {
  console.error(
    'Refusing to run: set WHISPR_PROVIDER to "bankr" or "surplus" first.\n' +
      '  export WHISPR_PROVIDER=surplus\n' +
      '  export SURPLUS_API_KEY=inf_YOUR_KEY_HERE   # or BANKR_API_KEY for bankr\n' +
      '  node examples/llm-adapter.js',
  );
  process.exit(1);
}

const apiKey = process.env[KEY_ENV[provider]];
if (!apiKey) {
  console.error(`Refusing to run: ${KEY_ENV[provider]} is not set. Export it (never hardcode a key) and retry.`);
  process.exit(1);
}

// SYNTHETIC secret — fake-format, not a real key.
const messages = [
  { role: 'system', content: 'You are a helpful assistant. Reply in one short sentence.' },
  {
    role: 'user',
    content: 'Debug my setup — here is my key OPENAI_API_KEY=sk-' + 'X'.repeat(48) + ' . What does it do?',
  },
];

console.log(`--- Provider: ${provider} (model ${MODEL}) ---`);
console.log('--- Original messages (synthetic secret) ---');
console.log(messages.map((m) => `${m.role}: ${m.content}`).join('\n'));

const { ok, status, response, receipt, findings, redactedMessages } = await guardedChatCompletion({
  provider,
  apiKey,
  model: MODEL,
  messages,
});

console.log('\n--- Redacted messages (what actually left the process) ---');
console.log(redactedMessages.map((m) => `${m.role}: ${m.content}`).join('\n'));

console.log('\n--- Privacy receipt (safe to log / share / anchor) ---');
console.log(JSON.stringify(receipt, null, 2));
console.log(`\nfindings: ${findings.length}`);

console.log(`\n--- Provider response (HTTP ${status}, ok=${ok}) ---`);
console.log(JSON.stringify(response, null, 2));
