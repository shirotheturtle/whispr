#!/usr/bin/env node
// whispr CLI — currently exposes the git pre-push privacy gate.
//
//   whispr git install     install a local pre-push hook in the current repo
//   whispr git scan-push    (invoked by the hook) scan the push diff, block on secrets,
//                           emit a signed privacy-receipt. Reads git's ref-update lines on stdin.
//   whispr git uninstall    remove the hook
//
// The gate reuses whispr's scanner/receipt/signer (network-free). It blocks DETECTED secrets
// and proves the scan ran — it does not guarantee "nothing can ever leak".

import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  mkdirSync,
  writeFileSync,
  readFileSync,
  existsSync,
  chmodSync,
  appendFileSync,
} from 'node:fs';
import { join, basename } from 'node:path';
import { generateKeypair } from '../src/sign.js';
import { runPrePushGate, parseRefUpdates } from '../src/git-gate.js';

const BIN_PATH = fileURLToPath(import.meta.url);

function git(args, opts = {}) {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024, ...opts });
}

function gitDir() {
  try {
    return git(['rev-parse', '--git-dir']).trim();
  } catch {
    fail('not a git repository (run inside a git repo, or `git init` first)');
  }
}

function fail(msg, code = 1) {
  process.stderr.write(`whispr: ${msg}\n`);
  process.exit(code);
}

// Persisted signing key lives INSIDE .git (never committed). PEM round-trips through
// signReceipt (which accepts a PEM string), so we just store/read the PKCS8 PEM.
function loadOrCreateSigningKey(gd) {
  const dir = join(gd, 'whispr');
  const keyPath = join(dir, 'signing-ed25519.pem');
  if (existsSync(keyPath)) return readFileSync(keyPath, 'utf8');
  mkdirSync(dir, { recursive: true });
  const { privateKey, publicKeyBase64 } = generateKeypair();
  const pem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  writeFileSync(keyPath, pem, { mode: 0o600 });
  writeFileSync(join(dir, 'signing-ed25519.pub'), publicKeyBase64 + '\n');
  return pem;
}

function repoIdentifier() {
  try {
    const url = git(['config', '--get', 'remote.origin.url']).trim();
    if (url) return url;
  } catch {
    /* no origin */
  }
  try {
    return basename(git(['rev-parse', '--show-toplevel']).trim());
  } catch {
    return null;
  }
}

function cmdInstall() {
  const gd = gitDir();
  const hooksDir = join(gd, 'hooks');
  mkdirSync(hooksDir, { recursive: true });
  const hookPath = join(hooksDir, 'pre-push');
  if (existsSync(hookPath)) {
    const cur = readFileSync(hookPath, 'utf8');
    if (!cur.includes('whispr git scan-push')) {
      fail(
        `a pre-push hook already exists at ${hookPath} and is not whispr's.\n` +
          `  Inspect/merge it manually, then add this line:\n` +
          `    exec "${process.execPath.replace(/\\/g, '/')}" "${BIN_PATH.replace(/\\/g, '/')}" git scan-push "$@"`,
      );
    }
    process.stderr.write('whispr: pre-push hook already installed.\n');
    return;
  }
  // sh hook (git runs hooks via sh, even on Windows). Forward-slash paths are sh-safe.
  const node = process.execPath.replace(/\\/g, '/');
  const bin = BIN_PATH.replace(/\\/g, '/');
  const hook = `#!/bin/sh
# whispr pre-push privacy gate — installed by \`whispr git install\`.
# Scans the diff being pushed for secrets and blocks on detection.
exec "${node}" "${bin}" git scan-push "$@"
`;
  writeFileSync(hookPath, hook, { mode: 0o755 });
  try {
    chmodSync(hookPath, 0o755);
  } catch {
    /* windows: mode is advisory */
  }
  loadOrCreateSigningKey(gd);
  // keep the per-repo key/receipts out of version control
  try {
    const exclude = join(gd, 'info', 'exclude');
    mkdirSync(join(gd, 'info'), { recursive: true });
    const cur = existsSync(exclude) ? readFileSync(exclude, 'utf8') : '';
    if (!cur.includes('# whispr')) appendFileSync(exclude, '\n# whispr (local only)\n');
  } catch {
    /* best effort */
  }
  process.stderr.write(
    `whispr: installed pre-push gate → ${hookPath}\n` +
      `  signing key: ${join(gd, 'whispr', 'signing-ed25519.pem')} (local, not committed)\n` +
      `  pushes are now scanned for secrets; detections block the push.\n`,
  );
}

function cmdUninstall() {
  const gd = gitDir();
  const hookPath = join(gd, 'hooks', 'pre-push');
  if (existsSync(hookPath) && readFileSync(hookPath, 'utf8').includes('whispr git scan-push')) {
    writeFileSync(hookPath, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    process.stderr.write(`whispr: removed pre-push gate (${hookPath}).\n`);
  } else {
    process.stderr.write('whispr: no whispr pre-push hook found.\n');
  }
}

function cmdScanPush() {
  // Fail-closed wrapper: any unexpected error blocks the push.
  try {
    const stdin = readFileSync(0, 'utf8'); // git pipes "<localRef> <localSha> <remoteRef> <remoteSha>" lines
    const gd = gitDir();
    const refUpdates = parseRefUpdates(stdin);
    const blockSeverity = process.env.WHISPR_BLOCK_SEVERITY || 'high';
    const signingKey = loadOrCreateSigningKey(gd);
    const repo = repoIdentifier();

    const result = runPrePushGate({
      refUpdates,
      runGit: (args) => git(args),
      signingKey,
      repo,
      blockSeverity,
      issuer: repo ? `urn:whispr:repo:${repo}` : undefined,
    });

    // Write the receipt (proof the scan ran), local-only.
    let receiptPath = null;
    if (result.receipt) {
      const rdir = join(gd, 'whispr', 'receipts');
      mkdirSync(rdir, { recursive: true });
      const id = result.receipt.credentialSubject?.id?.replace(/[^\w.-]/g, '_') || `receipt-${Date.now()}`;
      receiptPath = join(rdir, `${id}.json`);
      writeFileSync(receiptPath, JSON.stringify(result.receipt, null, 2));
    }

    if (result.blocked) {
      process.stderr.write('\n🛡️  whispr BLOCKED this push.\n');
      if (result.reason) process.stderr.write(`  ${result.reason}\n`);
      if (result.blocking.length) {
        process.stderr.write(`  ${result.blocking.length} secret(s) detected in the diff:\n`);
        for (const f of result.blocking) {
          process.stderr.write(`    - ${f.file ?? '(diff)'} : ${f.category}${f.subcategory ? '/' + f.subcategory : ''} [${f.severity}]\n`);
        }
      }
      if (receiptPath) process.stderr.write(`  receipt: ${receiptPath}\n`);
      process.stderr.write(
        `  Remove the secret(s) from the commits being pushed, then push again.\n` +
          `  (override threshold via WHISPR_BLOCK_SEVERITY; not recommended.)\n\n`,
      );
      process.exit(1);
    }

    process.stderr.write(
      `🛡️  whispr: clean — no secrets detected in the pushed diff.` +
        (receiptPath ? `\n  signed receipt: ${receiptPath}\n` : '\n'),
    );
    process.exit(0);
  } catch (err) {
    // Fail-closed: never let a push through when the gate itself failed.
    process.stderr.write(`\n🛡️  whispr BLOCKED this push (gate error, fail-closed): ${err?.message ?? err}\n\n`);
    process.exit(1);
  }
}

function cmdHelp() {
  process.stdout.write(
    `whispr — local privacy guard\n\n` +
      `Usage:\n` +
      `  whispr git install      install the pre-push privacy gate in this repo\n` +
      `  whispr git uninstall    remove the gate\n` +
      `  whispr git scan-push    (invoked by the git pre-push hook)\n\n` +
      `The gate scans the diff being pushed for secrets (API keys, private keys, JWTs,\n` +
      `tokens, …), BLOCKS the push on detection, and writes a signed privacy-receipt.\n` +
      `Network-free. It gates DETECTED secrets — it does not guarantee nothing can leak.\n`,
  );
}

const [, , cmd, sub] = process.argv;
if (cmd === 'git' && sub === 'install') cmdInstall();
else if (cmd === 'git' && sub === 'uninstall') cmdUninstall();
else if (cmd === 'git' && sub === 'scan-push') cmdScanPush();
else if (!cmd || cmd === 'help' || cmd === '--help' || cmd === '-h') cmdHelp();
else fail(`unknown command: ${[cmd, sub].filter(Boolean).join(' ')} (try \`whispr help\`)`);
