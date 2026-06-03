# whispr

**Local privacy guard for AI agent prompts and messages.** Detects and redacts sensitive content (seed phrases, private keys incl. PEM, API keys, JWTs, wallet addresses, and PII — emails, SSNs, credit cards — plus a high-entropy catch-all for unknown secrets) before it leaves your process, and emits a verifiable **privacy-receipt** proving redaction happened — without storing the original sensitive content.

- **Self-contained core.** Zero runtime dependencies. No backend. The core makes no network calls (an optional, separately-imported `whispr/adapter` can forward *redacted* prompts to an LLM — opt-in; see below).
- **Privacy-receipt.** Cryptographic receipt of what was scanned + redacted (hashes + counts, never raw content).
- **Open source.** MIT. Clone, copy, or import.
- **Zero config.** One function call to scan, redact, or receipt.

## Install

Repo-first package — three ways to use it today:

```bash
# 1. Clone and import directly
git clone <whispr-repo-url> whispr

# 2. Or copy src/ into your project
cp -r whispr/src my-project/lib/whispr

# 3. Or install via GitHub (once the repo is published)
npm install <whispr-github-url>
```

npm registry publish is intentionally deferred — see [Why no npm yet?](#why-no-npm-yet) below.

## Usage

```js
import { scan, redact, createPrivacyReceipt } from 'whispr';

const input = 'export OPENAI_API_KEY=sk-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX';

// 1. Scan — find sensitive content
const findings = scan(input);
// → [{ category: 'api_key', subcategory: 'openai_key', severity: 'high', match: '...', index: 21, length: 51 }]

// 2. Redact — replace findings with category tokens
const { redacted } = redact(input);
// → 'export OPENAI_API_KEY=[REDACTED:API_KEY]'

// 3. Receipt — verifiable proof that scan+redact happened
const receipt = createPrivacyReceipt({ input, redacted, findings });
// → { version: 'whispr-receipt/v0', inputHash: 'sha256:...', redactedHash: 'sha256:...', findings: [...], summary: {...} }
```

The receipt is **safe to log, share, or anchor on-chain** — it contains hashes and counts, but **never the original sensitive content, nor its position in the input.**

## What gets detected

| Category | Detector | Severity | Notes |
|---|---|---|---|
| `seed_phrase` | Label-context: `seed phrase:` / `mnemonic` / `recovery phrase` + 12–24 strictly-lowercase 3–8 char words | critical | Heuristic. Unlabelled mnemonics are NOT detected in S1 — v0.2 will add BIP-39 wordlist validation. |
| `private_key` | 64-hex **with a `0x` prefix or a key-ish label** (`pk=`, `private key:`, …), **and** PEM blocks (`-----BEGIN [RSA/EC/DSA/OPENSSH/PGP] PRIVATE KEY-----`, `subcategory: pem`) | critical | A *confirmed* key — there's a positive signal (0x or label). |
| `ambiguous_secret` | Bare *unlabelled* 64-hex (no `0x`, no label) | medium | A SHA-256 digest and a raw secp256k1/Ethereum private key are the **same shape** — indistinguishable from content. Redacted-if-in-doubt at medium (with a `note`) rather than silently passed (would leak a raw key) or flagged critical (would scream on every checksum). |
| `wallet_address` | `0x` + 40 hex chars (EVM-style) | low | Public by design, but flagged so callers can choose to redact for context-anonymity. Use `redact(input, { skip: ['wallet_address'] })` to keep them. |
| `api_key` | Service-prefix patterns: `sk-ant-`, `sk-`, `sk_live_`, `sk_test_`, `ghp_`, `gho_`, `AKIA`, `xox[bopa]-` | high–critical | Extend by adding patterns to `API_KEY_PATTERNS` in `src/scan.js`. |
| `jwt` | Three base64url segments where header **and** payload start with `eyJ` | high | The double-`eyJ` anchor keeps false positives very low vs. a generic 3-segment match. |
| `email` | `local@domain.tld` | low | PII. Common, so flagged low; `skip: ['email']` to keep them. |
| `ssn` | US `NNN-NN-NNNN`, with invalid area/group/serial ranges (000/666/9xx, 00, 0000) excluded | high | The range exclusions are the main false-positive filter on arbitrary 3-2-4 numbers. |
| `credit_card` | 13–19 digits (space/dash grouped or contiguous) **that pass the Luhn checksum** | high | Luhn validation is what separates a card number from any long number (~10% of random 16-digit numbers pass Luhn by chance). |
| `high_entropy` | Generic catch-all: 24+ char tokens with mixed letters+digits, not hex/UUID-shaped, Shannon entropy ≥ 4.0 bits/char | medium | Last-pass, only fires on tokens no specific detector claimed. Catches unbranded/unknown secrets while skipping prose, hashes, and IDs. |

### Detection benchmark

whispr ships a measurable benchmark so the "catches secrets" claim isn't just a claim. It runs the detectors over a synthetic fixture set — true positives (one per detector + a multi-secret case + the redact-if-in-doubt 64-hex cases) and false-positive traps (UUIDs, git SHAs, Luhn-invalid numbers, invalid-range SSNs, phone numbers, prose, URLs, version strings, timestamps) — and reports recall and false positives. **Network-free; no real secrets in the fixtures.**

```bash
npm run bench
```

Current result (`bench/fixtures.js`, scanner v0.1.0):

| Metric | Value |
|---|---|
| Synthetic positives | 21 cases (24 expected findings) |
| False-positive traps | 10 cases |
| **Recall** | **100.0%** (0 false negatives) |
| **False positives** | **0** (precision 100.0%) |

The benchmark is asserted by `tests/bench.test.js`, so any detector change that regresses recall or introduces a false positive fails `npm test` before the published numbers can drift.

**Honest reading of the numbers:** "false positives" means a finding in a case that should have produced none. A bare SHA-256 digest is **not** counted as a false positive — by design whispr redacts it as an `ambiguous_secret` (medium), because it's shape-identical to a raw private key (the benchmark includes this exact case as an expected `ambiguous_secret`, see the `private_key` / `ambiguous_secret` rows above). The numbers reflect this synthetic fixture set — detector behaviour against known shapes, not real-world recall across every possible secret format.

### Known limitations (honest scope)

- **Seed phrases need a label.** Minimises false positives. v0.2 roadmap: optional BIP-39 wordlist validation for unlabelled phrases.
- **Bare 64-hex is ambiguous (redact-if-in-doubt).** A SHA-256 digest and a raw secp256k1/Ethereum private key share the exact 64-hex shape. whispr is recall-first: bare unlabelled 64-hex is flagged as `ambiguous_secret` (medium) and **redacted**, rather than silently passed (would leak a real key) or marked critical (would scream on every checksum). It's only a confirmed `private_key` with a `0x` prefix or a key-ish label. Trade-off, stated plainly: some harmless checksums get redacted at medium — the accepted cost of never passing a look-alike key.
- **PII detection is format-based, region-limited.** SSN detection is US-format only; email/credit-card detection matches shape (and Luhn, for cards), not ownership or real-world validity.
- **The high-entropy catch-all is conservative by design.** It trades some recall on low-entropy or short secrets for a low false-positive rate (mixed letter+digit, non-hex, entropy ≥ 4.0). It will miss secrets that look like ordinary words or IDs.
- **API key patterns cover common services only.** PR new patterns for less-common services.
- **No language-specific syntax awareness.** The scanner is content-only; it doesn't know about comments, string literals, etc.

## Privacy-receipt format (`whispr-receipt/v0`)

```json
{
  "version": "whispr-receipt/v0",
  "scannerVersion": "0.1.0",
  "receiptId": "uuid-v4",
  "createdAt": "ISO-8601",
  "inputHash":   "sha256:<hex>",
  "redactedHash":"sha256:<hex>",
  "findings": [
    { "category": "api_key", "subcategory": "openai_key", "severity": "high" }
  ],
  "summary": {
    "totalFindings": 1,
    "byCategory": { "api_key": 1 },
    "highestSeverity": "high"
  }
}
```

**Receipt invariants — what's NOT in the receipt:**
- No `match` values (the raw secret bytes are never copied into the receipt).
- No `index` or `length` (position info would let an attacker locate secrets even after redaction).
- No raw input. No raw redacted text.

**What you CAN verify with a receipt:**
- *"This input was scanned by whispr v0.1.0 at this timestamp."* → version + scannerVersion + createdAt
- *"This is the same input I had."* → recompute `sha256:` on your input, compare to `inputHash`
- *"The redacted text matches."* → recompute `sha256:` on the redacted text, compare to `redactedHash`
- *"N sensitive items were found, of these severities."* → summary

S1 ships the receipt as inline JSON. Promotion to a formal `whispr-receipt-spec.md` (mirroring the Proof-of-Creation pattern) is a v0.2 candidate if the format gains external adopters.

## Signed receipts (VC-aligned)

A plain receipt is "trust us, we redacted." A **signed** receipt is proof anyone can check: an Ed25519 signature over the receipt, so a third party can confirm it was issued by a specific key and hasn't been altered.

```js
import { redact, createPrivacyCredential, generateKeypair, signReceipt, verifyReceipt } from 'whispr';

const { redacted, findings } = redact(input);

// Build a VC-aligned credential, then sign it with your key.
const credential = createPrivacyCredential({ input, redacted, findings, issuer: 'did:example:agent-1' });
const keypair = generateKeypair();              // hold the private key securely
const signed = signReceipt(credential, keypair.privateKey);

verifyReceipt(signed);                                   // { valid: true } (integrity + embedded key)
verifyReceipt(signed, { publicKey: keypair.publicKeyBase64 }); // pins the EXPECTED signer (origin)
```

The credential follows the **W3C Verifiable Credential data model** (`@context`, `type: ["VerifiableCredential","PrivacyReceipt"]`, `issuer`, `issuanceDate`, `credentialSubject`, `proof`). The `credentialSubject` carries only the safe receipt fields (hashes, counts, categories) — never raw matches, positions, or text. The `proof` is excluded from the canonical bytes that get signed.

**What a signed receipt proves:**
- **Integrity** — not one byte of the receipt changed since signing (any mutation → `valid: false`).
- **Origin** — the holder of the matching private key signed it. Pin the expected key via `verifyReceipt(receipt, { publicKey })` to reject a swapped-in key.

**What it does NOT prove:** that the scan was *complete*, or that the data is "safe" — only that this exact receipt was signed by that key.

> **Honesty note — "VC-aligned", not yet fully conformant.** This uses the VC data model and signs with **Ed25519 over JCS-canonical bytes (RFC 8785)** — deterministic and dependency-free, no JSON-LD/RDF toolchain. It is **not** yet a registered W3C Data-Integrity proof suite, and the term context URL is a placeholder, so a generic VC verifier won't validate it out of the box. Full VC Data-Integrity conformance (resolvable `@context` + a registered suite) is on the roadmap. Until then: *VC-aligned*, verifiable with this library's `verifyReceipt` — don't market it as a certified W3C Verifiable Credential.

Sign + verify are **100% offline** (only `node:crypto`). Anchoring a receipt hash on-chain is a separate, opt-in step, never part of signing.

## Run the example

```bash
npm run example
```

Prints scan findings, the redacted text, and the privacy-receipt for a mixed-content (synthetic) input.

## Run the tests

```bash
npm test
```

Uses Node's built-in test runner (`node --test`). No third-party test dependencies. Requires Node ≥20.

## Optional: LLM adapter (opt-in, the only part that touches the network)

whispr's core never makes a network call. The **adapter** is a separate, explicitly-imported module (`whispr/adapter`) that runs scan→redact→receipt over your chat messages and then sends the **redacted** messages to an OpenAI-compatible `/chat/completions` endpoint. Redaction happens *before* the send — that's the whole point. Importing the core (`whispr`) never reaches the adapter, so the "never phones home on its own" guarantee still holds.

```js
import { guardedChatCompletion } from 'whispr/adapter';

const { response, receipt, redactedMessages } = await guardedChatCompletion({
  provider: 'surplus',                 // 'bankr' | 'surplus', or pass baseURL directly
  apiKey: process.env.SURPLUS_API_KEY, // read from env — NEVER hardcode a key
  model: 'claude-opus-4.6',
  messages: [{ role: 'user', content: 'my key is sk-... please use it' }],
});
// → the API only ever received '[REDACTED:API_KEY]', and you get a receipt proving it.
```

**Providers** (two auth shapes, one adapter):

| Provider | Base URL | Auth header | Env var |
|---|---|---|---|
| `bankr` | `https://llm.bankr.bot/v1` | `X-API-Key: bk_…` | `BANKR_API_KEY` |
| `surplus` | `https://www.surplusintelligence.ai/api/inference/v1` | `Authorization: Bearer inf_…` | `SURPLUS_API_KEY` |

Any other OpenAI-compatible endpoint works too — pass `baseURL` (and `authHeader`/`authScheme` if it isn't `Authorization: Bearer`).

**Keys come from the environment, never the repo.** Run the example (it refuses to run, and sends nothing, without env vars):

```bash
export WHISPR_PROVIDER=surplus
export SURPLUS_API_KEY=inf_YOUR_KEY_HERE   # placeholder — use your own
npm run example:llm
```

The adapter's tests use a **mocked** fetch — they assert the outbound payload is already redacted and the key never appears in the body, all offline and deterministic (no network in `npm test`).

## Contributing

PRs welcome — especially for:

- Additional API-key detector patterns (open an issue first if it's a less-common service)
- BIP-39 wordlist validation for unlabelled seed-phrase detection (v0.2 roadmap)
- Additional test fixtures (**must be synthetic / fake-format — never real or expired secrets**)
- Improved severity heuristics

**Hard rule: never commit real secrets in tests, fixtures, examples, or anywhere else.** Even expired ones. All test data must be synthetic-shape (e.g. `'a'.repeat(64)` for hex blobs, fake-format API key prefixes like `sk-XXXXX...`).

## Why no npm yet?

S1 focuses on the package working as a clone-and-use repo. `npm publish` is deferred until the v0 API has external miles and the package name + scope decision is made by maintainers. Until then, `npm install <github-url>` works for early adopters.

## License

MIT — see [`LICENSE`](./LICENSE).
