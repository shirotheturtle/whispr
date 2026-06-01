import { test } from 'node:test';
import assert from 'node:assert/strict';
import { guardedChatCompletion, redactMessages, PROVIDERS } from '../src/adapter.js';

// All fixtures synthetic. These tests are OFFLINE + deterministic: fetch is
// mocked, nothing leaves the process. We assert that what the adapter WOULD
// send is already redacted, and that a receipt is produced before the send.

// A fake API key shape — never a real key.
const FAKE_KEY = 'inf_' + 'X'.repeat(32);
const SECRET_PROMPT = 'here is my key sk-' + 'X'.repeat(48) + ' please use it';

// Build a mock fetch that records the single call it receives and returns a
// canned OpenAI-style response.
function mockFetch(responseBody = { choices: [{ message: { role: 'assistant', content: 'ok' } }] }) {
  const calls = [];
  const fn = async (url, options) => {
    calls.push({ url, options });
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify(responseBody),
    };
  };
  fn.calls = calls;
  return fn;
}

test('redactMessages: scrubs secrets and produces a receipt, no network', () => {
  const { redactedMessages, findings, receipt } = redactMessages([
    { role: 'user', content: SECRET_PROMPT },
  ]);
  assert.equal(findings.length, 1);
  assert.ok(redactedMessages[0].content.includes('[REDACTED:API_KEY]'));
  assert.ok(!redactedMessages[0].content.includes('sk-X'), 'raw key must not survive');
  assert.equal(receipt.summary.totalFindings, 1);
  assert.match(receipt.inputHash, /^sha256:[0-9a-f]{64}$/);
});

test('outbound body is redacted — the raw secret never hits the wire', async () => {
  const fetchImpl = mockFetch();
  const result = await guardedChatCompletion({
    provider: 'surplus',
    apiKey: FAKE_KEY,
    model: 'claude-opus-4.6',
    messages: [{ role: 'user', content: SECRET_PROMPT }],
    fetch: fetchImpl,
  });

  assert.equal(fetchImpl.calls.length, 1);
  const sentBody = fetchImpl.calls[0].options.body;
  assert.ok(!sentBody.includes('sk-X'), 'raw API key must not appear in the outbound payload');
  assert.ok(sentBody.includes('[REDACTED:API_KEY]'), 'outbound payload must contain the redaction token');
  // The model + redacted messages are what gets sent.
  const parsed = JSON.parse(sentBody);
  assert.equal(parsed.model, 'claude-opus-4.6');
  assert.ok(!JSON.stringify(parsed.messages).includes('sk-X'));

  // Receipt is produced and returned.
  assert.equal(result.receipt.summary.totalFindings, 1);
  assert.equal(result.findings.length, 1);
  assert.equal(result.ok, true);
  assert.equal(result.status, 200);
});

test('the API key itself is never placed in the request body', async () => {
  const fetchImpl = mockFetch();
  await guardedChatCompletion({
    provider: 'surplus',
    apiKey: FAKE_KEY,
    model: 'claude-opus-4.6',
    messages: [{ role: 'user', content: 'hello' }],
    fetch: fetchImpl,
  });
  const sentBody = fetchImpl.calls[0].options.body;
  assert.ok(!sentBody.includes(FAKE_KEY), 'the API key must only be in the header, never the body');
});

test('Surplus uses Authorization: Bearer', async () => {
  const fetchImpl = mockFetch();
  await guardedChatCompletion({
    provider: 'surplus',
    apiKey: FAKE_KEY,
    model: 'claude-opus-4.6',
    messages: [{ role: 'user', content: 'hi' }],
    fetch: fetchImpl,
  });
  const { url, options } = fetchImpl.calls[0];
  assert.equal(url, 'https://www.surplusintelligence.ai/api/inference/v1/chat/completions');
  assert.equal(options.headers['Authorization'], `Bearer ${FAKE_KEY}`);
  assert.equal(options.headers['X-API-Key'], undefined);
});

test('Bankr uses X-API-Key (no Bearer scheme)', async () => {
  const fetchImpl = mockFetch();
  await guardedChatCompletion({
    provider: 'bankr',
    apiKey: 'bk_' + 'Y'.repeat(24),
    model: 'claude-opus-4.6',
    messages: [{ role: 'user', content: 'hi' }],
    fetch: fetchImpl,
  });
  const { url, options } = fetchImpl.calls[0];
  assert.equal(url, 'https://llm.bankr.bot/v1/chat/completions');
  assert.equal(options.headers['X-API-Key'], 'bk_' + 'Y'.repeat(24));
  assert.equal(options.headers['Authorization'], undefined);
});

test('custom baseURL + default Bearer auth works without a preset', async () => {
  const fetchImpl = mockFetch();
  await guardedChatCompletion({
    baseURL: 'https://example.test/v1/',
    apiKey: FAKE_KEY,
    model: 'm',
    messages: [{ role: 'user', content: 'hi' }],
    fetch: fetchImpl,
  });
  const { url, options } = fetchImpl.calls[0];
  assert.equal(url, 'https://example.test/v1/chat/completions', 'trailing slash normalised');
  assert.equal(options.headers['Authorization'], `Bearer ${FAKE_KEY}`);
});

test('skip option is forwarded to redaction', async () => {
  const fetchImpl = mockFetch();
  const wallet = '0x' + 'B'.repeat(40);
  const result = await guardedChatCompletion({
    provider: 'surplus',
    apiKey: FAKE_KEY,
    model: 'm',
    messages: [{ role: 'user', content: `pay ${wallet}` }],
    skip: ['wallet_address'],
    fetch: fetchImpl,
  });
  assert.ok(fetchImpl.calls[0].options.body.includes(wallet), 'skipped category should pass through');
  assert.equal(result.findings.length, 1); // still reported in findings, just not redacted
});

test('non-string message content is passed through untouched', async () => {
  const fetchImpl = mockFetch();
  const parts = [{ type: 'text', text: 'hi' }];
  await guardedChatCompletion({
    provider: 'surplus',
    apiKey: FAKE_KEY,
    model: 'm',
    messages: [{ role: 'user', content: parts }],
    fetch: fetchImpl,
  });
  const parsed = JSON.parse(fetchImpl.calls[0].options.body);
  assert.deepEqual(parsed.messages[0].content, parts);
});

test('extra OpenAI params (temperature, max_tokens) are forwarded', async () => {
  const fetchImpl = mockFetch();
  await guardedChatCompletion({
    provider: 'surplus',
    apiKey: FAKE_KEY,
    model: 'm',
    messages: [{ role: 'user', content: 'hi' }],
    temperature: 0.2,
    max_tokens: 100,
    fetch: fetchImpl,
  });
  const parsed = JSON.parse(fetchImpl.calls[0].options.body);
  assert.equal(parsed.temperature, 0.2);
  assert.equal(parsed.max_tokens, 100);
});

test('throws without an apiKey', async () => {
  await assert.rejects(
    () => guardedChatCompletion({ provider: 'surplus', model: 'm', messages: [], fetch: mockFetch() }),
    /apiKey is required/,
  );
});

test('throws on unknown provider', async () => {
  await assert.rejects(
    () => guardedChatCompletion({ provider: 'nope', apiKey: FAKE_KEY, model: 'm', messages: [], fetch: mockFetch() }),
    /unknown provider/,
  );
});

test('throws without a baseURL or provider', async () => {
  await assert.rejects(
    () => guardedChatCompletion({ apiKey: FAKE_KEY, model: 'm', messages: [], fetch: mockFetch() }),
    /baseURL is required/,
  );
});

test('throws on non-array messages', async () => {
  await assert.rejects(
    () => guardedChatCompletion({ provider: 'surplus', apiKey: FAKE_KEY, model: 'm', messages: 'nope', fetch: mockFetch() }),
    /messages must be an array/,
  );
});

test('throws on empty/invalid model', async () => {
  await assert.rejects(
    () => guardedChatCompletion({ provider: 'surplus', apiKey: FAKE_KEY, model: '', messages: [], fetch: mockFetch() }),
    /model must be a non-empty string/,
  );
});

test('PROVIDERS presets expose both auth shapes', () => {
  assert.equal(PROVIDERS.bankr.authHeader, 'X-API-Key');
  assert.equal(PROVIDERS.bankr.authScheme, '');
  assert.equal(PROVIDERS.surplus.authHeader, 'Authorization');
  assert.equal(PROVIDERS.surplus.authScheme, 'Bearer ');
});
