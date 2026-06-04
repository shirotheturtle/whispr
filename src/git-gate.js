// whispr pre-push privacy gate (Phase: git gate).
//
// Before an agent pushes, scan the diff that is about to leave the repo for secrets,
// BLOCK the push if any are found, and emit a signed privacy-receipt proving the scan
// ran. This module is the pure logic — it reuses the existing whispr scanner/redactor
// (src/scan.js, src/redact.js), receipt builder (src/receipt.js) and signer (src/sign.js),
// and takes its side-effecting deps (git, signing key) by injection so it stays testable
// and 100% network-free (only node:crypto via the reused modules).
//
// What it proves: the scan ran over this exact diff, and DETECTED secrets were caught.
// It does NOT prove "nothing can ever leak" — only that the configured detectors ran and
// what they found. Undetected/novel secret shapes can still pass (claim discipline).

import { redact } from './redact.js';
import { createPrivacyCredential } from './receipt.js';
import { signReceipt } from './sign.js';

// git's well-known empty-tree object — diffing against it yields the FULL content of a
// new branch (everything is "new to the remote"), the conservative scan for a first push.
export const EMPTY_TREE = '4b825dc642cb6eb9a060e54bf8d69288fbee4904';

const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
const isZeroSha = (s) => /^0+$/.test(String(s ?? ''));

/**
 * Parse git's pre-push stdin payload. git passes one line per ref being pushed:
 *   "<localRef> <localSha> <remoteRef> <remoteSha>"
 */
export function parseRefUpdates(stdin) {
  return String(stdin ?? '')
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((line) => {
      const [localRef, localSha, remoteRef, remoteSha] = line.split(/\s+/);
      return { localRef, localSha, remoteRef, remoteSha };
    });
}

// The base sha to diff a ref update against → what is actually being pushed.
//   - local sha all-zero  → ref deletion, nothing to scan (null)
//   - remote sha all-zero → new branch, diff vs empty tree (scan full content)
//   - otherwise           → existing branch, diff only the new commits
function baseFor(u) {
  if (isZeroSha(u.localSha)) return null;
  return isZeroSha(u.remoteSha) ? EMPTY_TREE : u.remoteSha;
}

/**
 * Group a unified diff's ADDED lines by file path. We scan only added content (what this
 * push introduces), and attribute each line to its file so the verdict can list paths.
 * Returns Map<path, string[]> (added lines, leading '+' stripped).
 */
export function addedByFile(diff) {
  const files = new Map();
  let current = null;
  for (const line of String(diff ?? '').split('\n')) {
    if (line.startsWith('+++ ')) {
      const p = line.slice(4).trim().replace(/^b\//, '');
      current = p === '/dev/null' ? null : p;
      if (current && !files.has(current)) files.set(current, []);
      continue;
    }
    // a new "diff --git" block resets the file until its +++ header
    if (line.startsWith('diff --git ')) {
      current = null;
      continue;
    }
    if (current && line.startsWith('+') && !line.startsWith('+++')) {
      files.get(current).push(line.slice(1));
    }
  }
  return files;
}

/**
 * Run the pre-push gate.
 *
 * @param {object} o
 * @param {Array}  o.refUpdates  parsed ref updates (see parseRefUpdates)
 * @param {(args:string[])=>string} o.runGit  runs `git <args>` and returns stdout; MUST throw on failure
 * @param {object} [o.signingKey] ed25519 private KeyObject/PEM; if absent the receipt is unsigned
 * @param {string} [o.repo]       repo identifier for the receipt (url or name)
 * @param {string} [o.blockSeverity='high'] minimum severity that BLOCKS (low|medium|high|critical)
 * @param {string} [o.issuer]     receipt issuer id
 * @returns {{blocked:boolean, reason?:string, findings:Array, blocking:Array, refs:Array, receipt:object}}
 *
 * Fail-closed: any git/scan error → blocked:true (never silently allow).
 */
export function runPrePushGate(o) {
  const {
    refUpdates = [],
    runGit,
    signingKey = null,
    repo = null,
    blockSeverity = 'high',
    issuer,
  } = o ?? {};
  if (typeof runGit !== 'function') throw new TypeError('runPrePushGate: runGit must be a function');
  const threshold = SEVERITY_RANK[blockSeverity] ?? SEVERITY_RANK.high;

  const allFindings = [];
  const refs = [];
  let combinedInput = '';
  let combinedRedacted = '';

  try {
    for (const u of refUpdates) {
      const base = baseFor(u);
      if (base === null) continue; // ref deletion → nothing leaving
      const diff = runGit(['diff', '--no-color', `${base}..${u.localSha}`]);
      const byFile = addedByFile(diff);
      for (const [file, lines] of byFile) {
        const text = lines.join('\n');
        if (!text) continue;
        const { redacted, findings } = redact(text);
        for (const f of findings) allFindings.push({ file, category: f.category, severity: f.severity, subcategory: f.subcategory });
        combinedInput += text + '\n';
        combinedRedacted += redacted + '\n';
      }
      refs.push({ ref: u.localRef, localSha: u.localSha, remoteSha: isZeroSha(u.remoteSha) ? null : u.remoteSha });
    }
  } catch (err) {
    // Fail-closed: we could not reliably read/scan the diff → block the push.
    return {
      blocked: true,
      reason: `scan failed (fail-closed): ${err?.message ?? err}`,
      findings: [],
      blocking: [],
      refs,
      receipt: null,
    };
  }

  const blocking = allFindings.filter((f) => (SEVERITY_RANK[f.severity] ?? -1) >= threshold);
  const blocked = blocking.length > 0;

  // Build the signed receipt (reusing the existing VC-aligned format), augmented with the
  // git push context + the gate verdict so the receipt is bound to this exact push.
  let receipt;
  try {
    const credential = createPrivacyCredential({
      input: combinedInput,
      redacted: combinedRedacted,
      findings: allFindings,
      issuer,
    });
    credential.credentialSubject.gitContext = {
      repo: repo ?? null,
      refs,
      blockSeverity,
      blocked,
      // safe verdict detail: paths + types only (never the matched secret values)
      detected: allFindings.map((f) => ({ file: f.file, category: f.category, severity: f.severity })),
    };
    receipt = signingKey ? signReceipt(credential, signingKey) : credential;
  } catch (err) {
    // A receipt we cannot build/sign is also fail-closed — don't approve a push we can't attest.
    return {
      blocked: true,
      reason: `receipt build failed (fail-closed): ${err?.message ?? err}`,
      findings: allFindings,
      blocking,
      refs,
      receipt: null,
    };
  }

  return { blocked, findings: allFindings, blocking, refs, receipt };
}
