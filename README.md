# whispr

**Local privacy guard for AI agent prompts and messages.** Detects and redacts sensitive content (seed phrases, private keys, API keys, wallet addresses) before it leaves your process, and emits a verifiable **privacy-receipt** proving redaction happened — without storing the original sensitive content.

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
| `private_key` | 64 hex chars, optional `0x` prefix | critical | FP risk: SHA-256 hashes, UUIDs-as-hex, etc. Worst-case-critical posture. |
| `wallet_address` | `0x` + 40 hex chars (EVM-style) | low | Public by design, but flagged so callers can choose to redact for context-anonymity. Use `redact(input, { skip: ['wallet_address'] })` to keep them. |
| `api_key` | Service-prefix patterns: `sk-ant-`, `sk-`, `sk_live_`, `sk_test_`, `ghp_`, `gho_`, `AKIA`, `xox[bopa]-` | high–critical | Extend by adding patterns to `API_KEY_PATTERNS` in `src/scan.js`. |

### Known limitations (honest scope)

- **Seed phrases need a label.** Minimises false positives. v0.2 roadmap: optional BIP-39 wordlist validation for unlabelled phrases.
- **64-hex matches are ambiguous.** A SHA-256 hash, a UUID-as-hex, and an actual private key all share the shape. The detector flags conservatively.
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
