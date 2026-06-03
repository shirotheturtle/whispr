// whispr detection benchmark fixtures.
//
// ╔══════════════════════════════════════════════════════════════════════════╗
// ║ HARD RULE: every secret below is SYNTHETIC and valid-FORMAT only.         ║
// ║ - No real or real-looking-LIVE credentials, ever.                        ║
// ║ - API keys use throwaway/example shapes (AWS's published EXAMPLE key,     ║
// ║   placeholder bodies).                                                    ║
// ║ - Credit cards are the standard PUBLIC test numbers (4111…, 5555…, 3782…).║
// ║ - Emails use example.com (RFC 2606 reserved-for-docs).                    ║
// ║ - SSN uses a reserved/never-issued example.                              ║
// ║ - The PEM body is obviously fake (no real key material).                 ║
// ╚══════════════════════════════════════════════════════════════════════════╝
//
// Each case: { id, text, expect: [category, ...] }
//   POSITIVES  -> expect lists the categories that SHOULD be detected.
//   FP TRAPS   -> expect: [] (anything detected here is a false positive).

const SYNTH = {
  // 64-hex private key shape, repeated char -> never a real key.
  hexKey: '0x' + 'a'.repeat(64),
  wallet: '0x' + 'C'.repeat(40),
  openai: 'sk-' + 'T3stKeyAbc123T3stKeyAbc123T3stKeyAbc123T3stK1', // sk- + 45 chars
  anthropic: 'sk-ant-' + 'T3stKeyAbc123T3stKeyAbc123T3stKeyAb01', // sk-ant- + 37 chars
  stripeLive: 'sk_live_' + 'T3stKeyAbc123T3stKeyAb01', // sk_live_ + 24
  githubPat: 'ghp_' + 'T3stKeyAbc123T3stKeyAbc123T3stKey0001', // ghp_ + 37
  awsKey: 'AKIAIOSFODNN7EXAMPLE', // AWS's own published EXAMPLE access key id
  slack: 'xoxb-' + '0000000000-FAKEfakeTESTtoken',
  // jwt.io sample token — public, signature is the doc-example HS256 over "secret".
  jwt:
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' +
    '.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ' +
    '.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
  // Obviously-fake PEM — body is placeholder text, NOT real key material.
  pem:
    '-----BEGIN RSA PRIVATE KEY-----\n' +
    'MIIBOgFAKEKEYBODYdoNOTuseTHISisaSYNTHETICplaceholderXXXXXXXXXXXX\n' +
    'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n' +
    '-----END RSA PRIVATE KEY-----',
  email: 'jane.doe@example.com',
  ssn: '219-09-9999', // reserved example range; never issued
  ccVisa: '4111 1111 1111 1111', // standard public Visa test number (Luhn-valid)
  ccMc: '5555555555554444', // standard public Mastercard test number (Luhn-valid)
  ccAmex: '3782 822463 10005', // standard public Amex test number (Luhn-valid)
  // Mixed-case+digit, non-hex random-looking token -> high Shannon entropy.
  highEntropy: 'Kf3Jx9pQ2mZ7vL0aB8nR4tY6wC1dE5sG',
  seed:
    'abandon ability able about above absent absorb abstract absurd abuse access accident',
};

export const POSITIVES = [
  { id: 'seed-labelled', text: `seed phrase: ${SYNTH.seed}`, expect: ['seed_phrase'] },
  { id: 'private-key-hex', text: `my private key is ${SYNTH.hexKey}`, expect: ['private_key'] },
  // Bare 64-hex (no 0x) but with a key-ish label -> confirmed private_key via KEY_CONTEXT_RE.
  { id: 'private-key-labelled-bare', text: `pk=${'b'.repeat(64)}`, expect: ['private_key'] },
  // Bare 64-hex, NO 0x, NO label — indistinguishable from a SHA-256 digest. A raw secp256k1
  // key looks exactly like this, so redact-if-in-doubt: must be flagged (as ambiguous_secret),
  // NEVER silently passed. This is the case that protects against a leaked raw key.
  { id: 'private-key-bare-unlabelled', text: `wallet import ${'f'.repeat(64)}`, expect: ['ambiguous_secret'] },
  { id: 'private-key-pem', text: `here is the key:\n${SYNTH.pem}\nthanks`, expect: ['private_key'] },
  { id: 'api-openai', text: `OPENAI_API_KEY=${SYNTH.openai}`, expect: ['api_key'] },
  { id: 'api-anthropic', text: `ANTHROPIC_API_KEY=${SYNTH.anthropic}`, expect: ['api_key'] },
  { id: 'api-stripe-live', text: `STRIPE_SECRET=${SYNTH.stripeLive}`, expect: ['api_key'] },
  { id: 'api-github-pat', text: `token=${SYNTH.githubPat}`, expect: ['api_key'] },
  { id: 'api-aws', text: `AWS_ACCESS_KEY_ID=${SYNTH.awsKey}`, expect: ['api_key'] },
  { id: 'api-slack', text: `SLACK_BOT_TOKEN=${SYNTH.slack}`, expect: ['api_key'] },
  { id: 'jwt', text: `Authorization: Bearer ${SYNTH.jwt}`, expect: ['jwt'] },
  { id: 'wallet', text: `send to ${SYNTH.wallet}`, expect: ['wallet_address'] },
  { id: 'email', text: `contact me at ${SYNTH.email} please`, expect: ['email'] },
  { id: 'ssn', text: `SSN: ${SYNTH.ssn}`, expect: ['ssn'] },
  { id: 'cc-visa-spaced', text: `card ${SYNTH.ccVisa} exp 12/29`, expect: ['credit_card'] },
  { id: 'cc-mc-contiguous', text: `pay with ${SYNTH.ccMc}`, expect: ['credit_card'] },
  { id: 'cc-amex', text: `amex ${SYNTH.ccAmex}`, expect: ['credit_card'] },
  { id: 'high-entropy', text: `api_token = ${SYNTH.highEntropy}`, expect: ['high_entropy'] },
  // A SHA-256 digest is bare 64-hex, so under redact-if-in-doubt it is flagged as
  // ambiguous_secret (medium) — NOT critical, NOT silently passed. This is the accepted,
  // honest cost: a checksum gets redacted rather than risk passing a look-alike raw key.
  {
    id: 'sha256-digest-ambiguous',
    text: 'build artifact sha256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 verified',
    expect: ['ambiguous_secret'],
  },
  {
    id: 'multi-secret',
    text: `key=${SYNTH.openai} wallet=${SYNTH.wallet} pk=${SYNTH.hexKey} ssn=${SYNTH.ssn}`,
    expect: ['api_key', 'wallet_address', 'private_key', 'ssn'],
  },
];

export const FP_TRAPS = [
  {
    id: 'benign-prose',
    text: 'The quick brown fox jumps over the lazy dog. Lorem ipsum dolor sit amet.',
    expect: [],
  },
  { id: 'uuid', text: 'request id 550e8400-e29b-41d4-a716-446655440000 logged', expect: [] },
  { id: 'git-sha40', text: 'deployed commit 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b', expect: [] },
  // 16 digits but Luhn-INVALID (valid Visa ...1111 with last digit bumped to ...1112).
  { id: 'cc-bad-luhn', text: 'order ref 4111 1111 1111 1112 shipped', expect: [] },
  // Structurally-invalid SSN (area 666) -> must not match.
  { id: 'ssn-invalid-area', text: 'ticket 666-12-3456 in the queue', expect: [] },
  { id: 'phone', text: 'call +1 (555) 123-4567 for support', expect: [] },
  {
    id: 'long-word',
    text: 'antidisestablishmentarianism and internationalization are long words',
    expect: [],
  },
  { id: 'url', text: 'see https://example.com/docs/getting-started for setup', expect: [] },
  { id: 'version', text: 'running build v2.10.4-rc1 on node 20.11.0', expect: [] },
  { id: 'iso-date', text: 'event at 2026-06-03T10:40:51.000Z processed', expect: [] },
];

export const ALL_CASES = [...POSITIVES, ...FP_TRAPS];
