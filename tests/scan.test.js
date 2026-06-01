import { test } from 'node:test';
import assert from 'node:assert/strict';
import { scan } from '../src/scan.js';

// IMPORTANT: All fixtures below are SYNTHETIC. No real secrets are committed.
// Hex blobs use repeated chars (e.g. 'a'.repeat(64)) so they match the shape
// without ever being a real key.

test('detects labelled seed phrase ("seed phrase:" prefix)', () => {
  const input =
    'seed phrase: abandon ability able about above absent absorb abstract absurd abuse access accident';
  const seeds = scan(input).filter((f) => f.category === 'seed_phrase');
  assert.equal(seeds.length, 1);
  assert.equal(seeds[0].severity, 'critical');
});

test('detects mnemonic with multiple label variants', () => {
  const variants = [
    'mnemonic: abandon ability able about above absent absorb abstract absurd abuse access accident',
    'recovery phrase: abandon ability able about above absent absorb abstract absurd abuse access accident',
    'Seed Phrase:\nabandon ability able about above absent absorb abstract absurd abuse access accident',
    'backup phrase = abandon ability able about above absent absorb abstract absurd abuse access accident',
  ];
  for (const input of variants) {
    const seeds = scan(input).filter((f) => f.category === 'seed_phrase');
    assert.equal(seeds.length, 1, `failed on: ${input.slice(0, 40)}...`);
  }
});

test('detects hex private key with 0x prefix', () => {
  const input = 'My private key is 0x' + 'a'.repeat(64);
  const keys = scan(input).filter((f) => f.category === 'private_key');
  assert.equal(keys.length, 1);
  assert.equal(keys[0].severity, 'critical');
});

test('detects hex private key without 0x prefix', () => {
  const input = 'pk=' + 'b'.repeat(64);
  const keys = scan(input).filter((f) => f.category === 'private_key');
  assert.equal(keys.length, 1);
});

test('detects EVM wallet address', () => {
  const input = 'send funds to 0x' + 'C'.repeat(40);
  const wallets = scan(input).filter((f) => f.category === 'wallet_address');
  assert.equal(wallets.length, 1);
  assert.equal(wallets[0].severity, 'low');
});

test('detects OpenAI-style API key (sk- prefix)', () => {
  const input = 'export OPENAI_API_KEY=sk-' + 'X'.repeat(48);
  const apiKeys = scan(input).filter((f) => f.category === 'api_key');
  assert.equal(apiKeys.length, 1);
  assert.equal(apiKeys[0].subcategory, 'openai_key');
});

test('detects GitHub PAT (ghp_ prefix)', () => {
  const input = 'token = ghp_' + 'a'.repeat(36);
  const apiKeys = scan(input).filter((f) => f.category === 'api_key');
  assert.equal(apiKeys.length, 1);
  assert.equal(apiKeys[0].subcategory, 'github_pat');
});

test('detects AWS access key (AKIA prefix)', () => {
  const input = 'AWS_ACCESS_KEY_ID=AKIA' + 'A'.repeat(16);
  const apiKeys = scan(input).filter((f) => f.category === 'api_key');
  assert.equal(apiKeys.length, 1);
  assert.equal(apiKeys[0].subcategory, 'aws_access_key');
});

test('detects Anthropic API key (sk-ant- prefix, more specific than sk-)', () => {
  const input = 'export ANTHROPIC_API_KEY=sk-ant-' + 'X'.repeat(40);
  const apiKeys = scan(input).filter((f) => f.category === 'api_key');
  // sk-ant- is listed first in API_KEY_PATTERNS so it wins via overlap-dedupe.
  assert.equal(apiKeys.length, 1);
  assert.equal(apiKeys[0].subcategory, 'anthropic_key');
});

test('detects Stripe live key as critical', () => {
  const input = 'STRIPE_SECRET=sk_live_' + 'X'.repeat(24);
  const apiKeys = scan(input).filter((f) => f.category === 'api_key');
  assert.equal(apiKeys.length, 1);
  assert.equal(apiKeys[0].subcategory, 'stripe_live_key');
  assert.equal(apiKeys[0].severity, 'critical');
});

test('benign English text produces NO findings', () => {
  const benign =
    'the quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet, consectetur adipiscing elit.';
  assert.equal(scan(benign).length, 0);
});

test('unlabelled 12-word lowercase phrase is NOT flagged as seed (S1 heuristic)', () => {
  // 12 short lowercase words, no seed/mnemonic/recovery label. Documented S1 limitation:
  // unlabelled mnemonics aren't detected; v0.2 will add wordlist validation.
  const input = 'these twelve harmless tokens form what looks kind almost like that today';
  const seeds = scan(input).filter((f) => f.category === 'seed_phrase');
  assert.equal(seeds.length, 0);
});

test('seed phrase regex does NOT absorb trailing uppercase prose', () => {
  // Regression: with /i flag on, [a-z] matches uppercase too and would consume "Thanks"
  // past the real seed phrase. Verifies the regex stops at the last lowercase word.
  const input =
    'seed phrase: abandon ability able about above absent absorb abstract absurd abuse access accident\n\nThanks!';
  const seeds = scan(input).filter((f) => f.category === 'seed_phrase');
  assert.equal(seeds.length, 1);
  assert.ok(!seeds[0].match.includes('Thanks'), 'must not absorb uppercase word');
  assert.ok(seeds[0].match.endsWith('accident'), 'match should end at the last lowercase seed word');
});

test('multiple secrets in one input are all detected', () => {
  const input =
    'OPENAI=sk-' + 'X'.repeat(48) +
    ' AND wallet=0x' + 'B'.repeat(40) +
    ' AND pk=0x' + 'a'.repeat(64);
  const findings = scan(input);
  const cats = findings.map((f) => f.category).sort();
  // Expect one of each: api_key, wallet_address, private_key
  assert.deepEqual(cats, ['api_key', 'private_key', 'wallet_address']);
});

test('findings are sorted by index', () => {
  const input =
    'one 0x' + 'a'.repeat(64) + ' two sk-' + 'X'.repeat(48) + ' three 0x' + 'B'.repeat(40);
  const findings = scan(input);
  for (let i = 1; i < findings.length; i++) {
    assert.ok(findings[i].index >= findings[i - 1].index, 'findings must be sorted by index');
  }
});

test('empty string produces no findings', () => {
  assert.deepEqual(scan(''), []);
});

test('throws TypeError on non-string input', () => {
  assert.throws(() => scan(null), TypeError);
  assert.throws(() => scan(undefined), TypeError);
  assert.throws(() => scan(123), TypeError);
  assert.throws(() => scan({}), TypeError);
});
