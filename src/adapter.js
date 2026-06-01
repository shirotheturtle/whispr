// OPTIONAL, NETWORK-USING module — NOT part of whispr's core.
//
// whispr's core (index.js / scan / redact / receipt) makes ZERO network calls.
// This adapter is the only part of the package that talks to the outside world,
// and you have to import it explicitly (`whispr/adapter`). The core's
// "never phones home on its own" guarantee is unaffected: importing the core
// never reaches this file.
//
// What it does: takes OpenAI-compatible chat messages, runs whispr's scan→redact
// over each string message BEFORE anything leaves the process, emits a privacy-
// receipt, and only THEN POSTs the *redacted* messages to `{baseURL}/chat/completions`.
// Redaction happens before the send — that is the whole point.

import { redact } from './redact.js';
import { createPrivacyReceipt } from './receipt.js';

// Provider presets. Two providers, two auth-header shapes:
//   - Bankr   uses `X-API-Key: bk_...`        (no scheme prefix)
//   - Surplus uses `Authorization: Bearer inf_...`
// Pass `provider: 'bankr' | 'surplus'` to use a preset, or supply
// `baseURL` + `authHeader` + `authScheme` directly for any other
// OpenAI-compatible endpoint.
export const PROVIDERS = {
  bankr: {
    baseURL: 'https://llm.bankr.bot/v1',
    authHeader: 'X-API-Key',
    authScheme: '', // raw key, no "Bearer " prefix
  },
  surplus: {
    baseURL: 'https://www.surplusintelligence.ai/api/inference/v1',
    authHeader: 'Authorization',
    authScheme: 'Bearer ',
  },
};

function resolveTarget({ provider, baseURL, authHeader, authScheme }) {
  let preset = {};
  if (provider != null) {
    preset = PROVIDERS[provider];
    if (!preset) {
      throw new Error(
        `whispr adapter: unknown provider "${provider}" — known: ${Object.keys(PROVIDERS).join(', ')} (or pass baseURL directly)`,
      );
    }
  }
  const resolvedBaseURL = baseURL ?? preset.baseURL;
  if (!resolvedBaseURL) {
    throw new Error('whispr adapter: baseURL is required (pass `baseURL` or a known `provider`)');
  }
  return {
    baseURL: resolvedBaseURL.replace(/\/+$/, ''),
    authHeader: authHeader ?? preset.authHeader ?? 'Authorization',
    authScheme: authScheme ?? preset.authScheme ?? 'Bearer ',
  };
}

/**
 * Redact a list of OpenAI chat messages and produce a privacy-receipt,
 * WITHOUT sending anything. Useful on its own, and the building block the
 * network call below uses.
 *
 * Only string `content` is scanned. Non-string content (e.g. OpenAI
 * multimodal content-part arrays) is passed through untouched — documented
 * limitation, not silently scrubbed.
 *
 * @returns {{ redactedMessages: object[], findings: object[], receipt: object }}
 */
export function redactMessages(messages, { skip } = {}) {
  if (!Array.isArray(messages)) {
    throw new TypeError('whispr adapter: messages must be an array');
  }
  const allFindings = [];
  const redactedMessages = messages.map((m) => {
    if (typeof m?.content !== 'string') return m; // pass-through, untouched
    const { redacted, findings } = redact(m.content, { skip });
    allFindings.push(...findings);
    return { ...m, content: redacted };
  });

  // One receipt over the whole request: original vs redacted text. The receipt
  // never contains raw matches/positions (see receipt.js invariants), so it's
  // safe to log/share/anchor.
  const originalText = messages.map((m) => (typeof m?.content === 'string' ? m.content : '')).join('\n');
  const redactedText = redactedMessages
    .map((m) => (typeof m?.content === 'string' ? m.content : ''))
    .join('\n');
  const receipt = createPrivacyReceipt({ input: originalText, redacted: redactedText, findings: allFindings });

  return { redactedMessages, findings: allFindings, receipt };
}

/**
 * Guarded chat completion: scan→redact→receipt, THEN POST the redacted
 * messages to an OpenAI-compatible `/chat/completions` endpoint.
 *
 * The receipt is produced before the network call, so you get proof of what
 * was scrubbed even if the request later fails.
 *
 * @param {object} opts
 * @param {'bankr'|'surplus'} [opts.provider]  Preset provider (sets baseURL + auth shape).
 * @param {string} [opts.baseURL]              Override / custom OpenAI-compatible base URL.
 * @param {string} opts.apiKey                 API key. READ IT FROM AN ENV VAR — never hardcode.
 * @param {string} [opts.authHeader]           Override auth header name.
 * @param {string} [opts.authScheme]           Override auth scheme prefix (e.g. 'Bearer ').
 * @param {object[]} opts.messages             OpenAI chat messages.
 * @param {string} opts.model                  Model id (e.g. 'claude-opus-4.6').
 * @param {string[]} [opts.skip]               Redaction categories to skip (see redact()).
 * @param {function} [opts.fetch]              Injectable fetch (defaults to global fetch; tests pass a mock).
 * @param {object} [opts....rest]              Any other OpenAI body params (temperature, max_tokens, etc.).
 * @returns {Promise<{ok:boolean, status:number, response:object, receipt:object, findings:object[], redactedMessages:object[]}>}
 */
export async function guardedChatCompletion(opts = {}) {
  const {
    provider,
    baseURL,
    apiKey,
    authHeader,
    authScheme,
    messages,
    model,
    skip,
    fetch: fetchImpl = globalThis.fetch,
    ...rest
  } = opts;

  if (!apiKey) {
    throw new Error('whispr adapter: apiKey is required — read it from an env var, never hardcode a key');
  }
  if (typeof model !== 'string' || model.length === 0) {
    throw new TypeError('whispr adapter: model must be a non-empty string');
  }
  if (typeof fetchImpl !== 'function') {
    throw new TypeError('whispr adapter: no fetch available (use Node >=20, or pass opts.fetch)');
  }

  const target = resolveTarget({ provider, baseURL, authHeader, authScheme });

  // Scrub + receipt BEFORE the send.
  const { redactedMessages, findings, receipt } = redactMessages(messages, { skip });

  const headers = { 'Content-Type': 'application/json' };
  headers[target.authHeader] = target.authScheme + apiKey;

  const res = await fetchImpl(`${target.baseURL}/chat/completions`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ model, messages: redactedMessages, ...rest }),
  });

  const text = await res.text();
  let response;
  try {
    response = JSON.parse(text);
  } catch {
    response = { raw: text };
  }

  return {
    ok: res.ok,
    status: res.status,
    response,
    receipt,
    findings,
    redactedMessages,
  };
}
