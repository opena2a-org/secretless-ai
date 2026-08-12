/**
 * macOS Keychain backend — stores secrets in the system Keychain using the `security` CLI.
 *
 * Each secret is stored as a generic password with:
 *   service = "secretless"
 *   account = key (e.g. "mcp/claude-desktop/my-server/API_KEY")
 *
 * A lightweight key index file tracks stored key names for prefix-based lookups.
 * The index contains only key names — never secret values.
 *
 * Uses execFileSync (no shell) to prevent injection via secret values.
 */

import { execFileSync, spawnSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import type { WritableSecretBackend, BackendHealth } from './types';
import { readKeyIndex } from './key-index';
import { leaksAny, redactValues } from '../redact';

const LEGACY_SERVICE_NAME = 'secretless';
const INDEX_FILENAME = 'keychain-index.json';

/**
 * Derive a per-key service name so macOS Passwords.app shows a descriptive
 * name instead of "Secretless" for every entry.
 *
 * Examples:
 *   "secret/ANTHROPIC_API_KEY" → "Secretless: ANTHROPIC_API_KEY"
 *   "mcp/claude-desktop/server/TOKEN" → "Secretless: TOKEN"
 */
function serviceNameFor(key: string): string {
  const lastSegment = key.split('/').pop() ?? key;
  return `Secretless: ${lastSegment}`;
}

/**
 * macOS `security find-generic-password -w` hex-encodes passwords that contain
 * non-printable characters (e.g. newlines). Detect and decode hex output.
 *
 * **`-w` output cannot tell you which happened.** Measured:
 *
 *   stored text  "d259cc9961fbd259cc9961fbd259cc99" -> d259cc9961fbd259cc99...
 *   stored bytes  line1\nline2                      -> 6c696e65310a6c696e6532
 *
 * Identical shape. No content-based rule separates them, and the one this code
 * used to apply (decode if the decoded bytes hold a control character) silently
 * corrupted most 32-hex-character API keys. Those decode to 16 random bytes and
 * the control ranges it tested cover 32 of 256 values, so
 * `1 - (224/256)^16` = **88%** of such keys tripped it. A real HIBP key read
 * back as 16 bytes of binary. The keychain was never wrong; the read path was.
 *
 * `-g` settles it without guessing, because macOS states the encoding:
 *
 *   plain   -> password: "d259cc9961fbd259cc9961fbd259cc99"
 *   binary  -> password: 0x6C696E65310A6C696E6532  "line1\012line2"
 *
 * So: take the exact bytes from `-w`, and consult `-g` only when the shape is
 * ambiguous, which leaves the common case at one `security` call.
 *
 * There are THREE answers, not two. `-g` can say encoded, say not encoded, or
 * not complete at all — and the third is not the second. This used to return
 * the raw `-w` value whenever the probe failed, reasoning that "handing back a
 * secret verbatim is always safe". That reasoning holds against #107, which was
 * over-decoding, and fails in the other direction: when the value IS encoded
 * and the probe cannot say so, the raw value is the hex transcript of the
 * credential, not the credential. Injecting it is `run` handing a command a
 * value that is not the stored one, silently, exit 0 — the #104 complaint
 * exactly.
 *
 * So the old rationale is kept as a hazard rather than a rule: never decode on
 * an unanswered question. This code does not decode. It refuses.
 *
 * The refusal is narrow by construction. It needs a value shaped like hex AND a
 * `-g` that will not complete on an entry `-w` just read successfully — which
 * on a working machine does not happen.
 */
function looksLikeKeychainHex(raw: string): boolean {
  return raw.length >= 2 && raw.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(raw);
}

/**
 * @param isHexEncoded true / false / null, where null means "could not
 *   determine". Required, not optional: an omitted probe was a door back to
 *   guessing, and only tests ever went through it.
 */
export function decodeKeychainValue(
  raw: string,
  isHexEncoded: () => boolean | null,
  key?: string,
): string {
  if (!looksLikeKeychainHex(raw)) return raw;

  let encoded: boolean | null;
  try {
    // Caught here as well as inside the probe: this function is exported and
    // its contract should not depend on who supplies the callback.
    encoded = isHexEncoded();
  } catch {
    encoded = null;
  }

  if (encoded === null) throw undeterminedEncodingError(key);
  return encoded ? Buffer.from(raw, 'hex').toString('utf-8') : raw;
}

function undeterminedEncodingError(key?: string): Error {
  return new Error(
    [
      `Could not determine how the macOS Keychain stored ${key ? `"${key}"` : 'this secret'}.`,
      '',
      '  Nothing was read. The stored value is shaped like the hex transcript',
      '  macOS returns for a binary secret, and the check that settles it did not',
      '  complete. Returned either way, it may not be the value you stored.',
      '',
      '  Verify:  security default-keychain',
      '  Fix:     unlock the login keychain and retry, or run',
      '           secretless-ai backend set local  to use the encrypted file store',
    ].join('\n'),
  );
}

/**
 * Parse `security find-generic-password -g` output for the explicit `0x` marker.
 *
 * Anchored to the `password:` line so a `0x` appearing inside the ATTRIBUTE dump
 * that `-g` also prints cannot be mistaken for the encoding marker.
 */
export function keychainOutputIsHexEncoded(stderrAndStdout: string): boolean {
  return /^password:\s*0x[0-9A-Fa-f]+/m.test(stderrAndStdout);
}

/**
 * Turn a failed `security` invocation into an error that cannot carry the
 * secret.
 *
 * `security add-generic-password` takes the password as `-w <value>`, and its
 * own help says so plainly: "Use of the -p or -w options is insecure." Node's
 * `execFileSync` puts the entire argv into the thrown message, so the raw error
 * reads:
 *
 *   Command failed: security add-generic-password -s Secretless: K -a secret/K -w hunter2
 *
 * Printing that defeats the tool. The argv echo is our own command line and
 * tells the user nothing, so it is dropped entirely and the value is scrubbed
 * from whatever remains. The final guard is unconditional: if the value can
 * still be found in the message, the message is discarded rather than trimmed.
 */
export function redactSecurityError(err: unknown, value: string, key: string): Error {
  const raw = err instanceof Error ? err.message : String(err);
  const values = value.length > 0 ? [value] : [];

  // Scrub BEFORE any line filtering. A secret may contain newlines — that is
  // exactly why the read path has to handle hex-encoded values — and dropping
  // lines first can split the value across the boundary, leaving a fragment
  // that no longer matches `value` and so survives both the replace and the
  // containment backstop. Replace it while it is still contiguous.
  let detail = redactValues(raw, values);

  detail = detail
    .split('\n')
    .filter(line => !/^\s*Command failed:/.test(line))
    .join('\n')
    .trim();

  // Unconditional backstop. Any path that would still expose the value loses
  // the detail instead — a vaguer error is always preferable to a leaked one.
  // The line-based check this used to run missed escaped and truncated forms;
  // `leaksAny` works on runs, so it does not. See src/redact.ts.
  if (leaksAny(detail, values)) {
    detail = '';
  }

  const lines = [`Could not store "${key}" in the macOS Keychain.`];
  if (detail) lines.push(`  ${detail.split('\n').join('\n  ')}`);

  if (/authorization was canceled|User interaction is not allowed|interaction not allowed/i.test(detail)) {
    lines.push(
      '',
      '  The Keychain declined the write. It is usually locked, or the approval',
      '  dialog was dismissed or could not be shown.',
      '',
      '  Verify:  security default-keychain',
      '  Fix:     unlock the login keychain and retry, or run',
      '           secretless-ai backend set local  to use the encrypted file store',
    );
  } else {
    lines.push(
      '',
      '  Verify:  security default-keychain',
      '  Fix:     secretless-ai doctor',
    );
  }

  return new Error(lines.join('\n'));
}

/**
 * macOS `security` exit status for "The specified item could not be found in
 * the keychain". Measured, not assumed:
 *
 *   $ security find-generic-password -s no-such -a no-such -w; echo $?
 *   security: SecKeychainSearchCopyNext: The specified item could not be found...
 *   44
 *
 * The other statuses this tool can see are a locked or declined Keychain
 * (-25308 "User interaction is not allowed", -128 "User canceled"), and a usage
 * error (2). None of those mean the entry is absent.
 */
const SECURITY_ITEM_NOT_FOUND = 44;

function isItemNotFound(err: unknown): boolean {
  return (err as { status?: unknown } | null)?.status === SECURITY_ITEM_NOT_FOUND;
}

/**
 * The Keychain would not answer for this entry.
 *
 * Carries no `security` output: the failing command is `find-generic-password`,
 * whose argv holds no value, but its stderr is not ours to reason about and the
 * entry name says everything the user needs.
 */
function keychainUnreadableError(account: string, err: unknown): Error {
  const status = (err as { status?: unknown } | null)?.status;
  return new Error(
    [
      `The macOS Keychain would not return "${account}".`,
      '',
      '  Nothing was read. Refusing to report the secret as missing, because a',
      '  Keychain that will not answer is not a Keychain without the entry.',
      '',
      `  security exit status: ${typeof status === 'number' ? status : 'unknown'}`,
      '',
      '  The login keychain is usually locked, or an approval dialog was',
      '  dismissed or could not be shown.',
      '',
      '  Verify:  security default-keychain',
      '  Fix:     unlock the login keychain and retry, or run',
      '           secretless-ai backend set local  to use the encrypted file store',
    ].join('\n'),
  );
}

export class MacOSKeychainBackend implements WritableSecretBackend {
  readonly name = 'keychain-macos';
  private readonly indexPath: string;

  constructor(config?: Record<string, unknown>) {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
    const storeDir = (config?.storeDir as string) ?? path.join(home, '.secretless-ai', 'store');
    fs.mkdirSync(storeDir, { recursive: true, mode: 0o700 });
    this.indexPath = path.join(storeDir, INDEX_FILENAME);
  }

  async store(key: string, value: string): Promise<void> {
    const svc = serviceNameFor(key);

    // `-U` updates the entry in place if it already exists, so the previous
    // value is never deleted ahead of a write that might fail. Deleting first
    // and then failing to add leaves the user with no credential at all.
    try {
      execFileSync('security', [
        'add-generic-password',
        '-s', svc,
        '-a', key,
        '-l', `Secretless: ${key}`,
        '-U',
        '-w', value,
      ], { stdio: 'pipe' });
    } catch (err) {
      // Node puts the full argv in the error message, and the value is in it.
      // Rethrowing verbatim prints the secret to the terminal — which in this
      // tool's own threat model is the thing being prevented, since that output
      // is exactly what gets pasted into an AI chat when someone asks why the
      // command failed. Never let the raw message escape.
      throw redactSecurityError(err, value, key);
    }

    // Only once the new value is committed, retire the legacy entry (old
    // unified service name) so reads cannot resolve to a stale duplicate.
    try {
      execFileSync('security', [
        'delete-generic-password',
        '-s', LEGACY_SERVICE_NAME,
        '-a', key,
      ], { stdio: 'pipe' });
    } catch {
      // No legacy entry — that's fine
    }

    // Update index
    const index = this.readIndex();
    if (!index.includes(key)) {
      index.push(key);
      this.writeIndex(index);
    }
  }

  async resolve(secretPath: string): Promise<Record<string, string>> {
    const index = this.readIndex();
    const matchingKeys = index.filter(
      k => k === secretPath || k.startsWith(secretPath + '/'),
    );

    const results: Record<string, string> = {};
    for (const key of matchingKeys) {
      // Try new per-key service name first, fall back to legacy. Track WHICH
      // service answered: the hex-encoding question has to be asked of the same
      // entry the value came from, or the answer describes a different secret.
      let service = serviceNameFor(key);
      let raw = this.findPassword(service, key);
      if (raw === null) {
        service = LEGACY_SERVICE_NAME;
        raw = this.findPassword(service, key);
      }
      if (raw !== null) {
        const from = service;
        results[key] = decodeKeychainValue(raw, () => this.isHexEncoded(from, key), key);
      }
    }
    return results;
  }

  async delete(key: string): Promise<boolean> {
    let deleted = false;

    // Delete new-format entry
    try {
      execFileSync('security', [
        'delete-generic-password',
        '-s', serviceNameFor(key),
        '-a', key,
      ], { stdio: 'pipe' });
      deleted = true;
    } catch {
      // Not found with new service name
    }

    // Also delete legacy entry if it exists
    try {
      execFileSync('security', [
        'delete-generic-password',
        '-s', LEGACY_SERVICE_NAME,
        '-a', key,
      ], { stdio: 'pipe' });
      deleted = true;
    } catch {
      // No legacy entry
    }

    if (deleted) {
      const index = this.readIndex();
      const filtered = index.filter(k => k !== key);
      this.writeIndex(filtered);
    }

    return deleted;
  }

  async healthCheck(): Promise<BackendHealth> {
    const start = Date.now();
    try {
      execFileSync('security', ['default-keychain'], { stdio: 'pipe' });
      return {
        healthy: true,
        latencyMs: Date.now() - start,
        message: 'macOS Keychain available',
      };
    } catch {
      return {
        healthy: false,
        latencyMs: Date.now() - start,
        message: 'macOS Keychain not accessible',
      };
    }
  }

  /**
   * Ask macOS whether it hex-encoded this entry, using the `0x` marker on the
   * `-g` password line. Only called when `-w` output is ambiguously shaped.
   *
   * `-g` prints the password line to STDERR, so both streams are captured.
   *
   * Returns null for "could not determine". A non-zero exit means `security`
   * did not answer the question — it did not answer "no". Reading a failed
   * probe as "not encoded" is how a binary secret came back as its own hex
   * transcript, with nothing to indicate it.
   */
  private isHexEncoded(service: string, account: string): boolean | null {
    try {
      const res = spawnSync('security', [
        'find-generic-password',
        '-s', service,
        '-a', account,
        '-g',
      ], { encoding: 'utf-8' });
      if (res.error) return null;
      if (res.status !== 0) return null;
      return keychainOutputIsHexEncoded(`${res.stderr ?? ''}\n${res.stdout ?? ''}`);
    } catch {
      return null;
    }
  }

  /**
   * The stored value, or null when the entry genuinely is not there.
   *
   * `catch { return null }` conflated "no such entry" with "could not read this
   * entry", and the second is the one that matters: a locked Keychain, or a
   * dismissed approval dialog, made every secret read as absent. `resolve`
   * returned {}, `run` injected nothing, exit 0 — over a Keychain holding every
   * credential (#104).
   *
   * Measured on macOS: `security` exits 44 for "The specified item could not be
   * found in the keychain". Only 44 is absence; every other status is a
   * question we did not get an answer to.
   */
  private findPassword(service: string, account: string): string | null {
    try {
      return execFileSync('security', [
        'find-generic-password',
        '-s', service,
        '-a', account,
        '-w',
      ], { stdio: ['pipe', 'pipe', 'pipe'], encoding: 'utf-8' }).trimEnd();
    } catch (err) {
      if (isItemNotFound(err)) return null;
      throw keychainUnreadableError(account, err);
    }
  }

  private readIndex(): string[] {
    return readKeyIndex(this.indexPath);
  }

  private writeIndex(keys: string[]): void {
    const tmpPath = this.indexPath + '.tmp';
    fs.writeFileSync(tmpPath, JSON.stringify(keys, null, 2) + '\n', { mode: 0o600 });
    fs.renameSync(tmpPath, this.indexPath);
  }
}
