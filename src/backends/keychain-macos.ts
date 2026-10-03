/**
 * macOS Keychain backend — stores secrets in the system Keychain using the `security` CLI.
 *
 * Each secret is stored as a generic password with:
 *   service = "Secretless: <last key segment>"
 *   account = key (e.g. "mcp/claude-desktop/my-server/API_KEY")
 *
 * A lightweight key index file tracks stored key names for prefix-based lookups.
 * The index contains only key names — never secret values.
 *
 * How the value reaches `security`, and why it is not on argv:
 *
 *   `security add-generic-password -w <value>` puts the secret on the child's
 *   command line, where `ps` and /proc show it to every process on the machine
 *   for as long as the call runs, and where Node copies it into the thrown
 *   error. The CLI's own help says of `-w`: "Use of the -p or -w options is
 *   insecure."
 *
 *   The store instead runs `/usr/bin/security -i` and writes ONE command line
 *   to its stdin:
 *
 *     add-generic-password -s "<service>" -a "<account>" -l "<label>" -U -X <hex>
 *
 *   The value travels as `-X` hex, so no byte of it is ever parsed as command
 *   text, and the child's argv is the constant `['-i']` whatever the value is.
 *   The read path decodes the hex form `find-generic-password -w` returns for a
 *   value with a non-printable byte, so a value with a newline round-trips.
 *
 *   Measured on macOS 26.6.2 against `/usr/bin/security` alone (M1, 2026-10-02):
 *   - `-i` exits with the status of the LAST command on its stream, so one
 *     store sends exactly one command per invocation, and every store is
 *     followed by a read-back compare, because a write that reported success
 *     and did not land is the failure that matters.
 *   - An operand holding a space or a colon must be quoted; inside double
 *     quotes `"` is `\"` and `\` is `\\`. A newline in any operand splits the
 *     line into a second command, quoted or not, so the store refuses one.
 *   - An over-long line is not refused cleanly: a 4115-character line was
 *     truncated, the remainder parsed as further commands, and the status was
 *     1; a 4051-character line was accepted. The store bounds its line below
 *     that, and refuses a value that does not fit.
 *
 * `security` is always `/usr/bin/security`, by absolute path: it ships with
 * the OS, and a program of that name planted earlier on PATH never runs. The
 * only way to run something else is the constructor's internal seam, which no
 * environment variable, config key or flag reaches.
 *
 * Every child call is bounded in time (see bounded-child.ts).
 */

import * as fs from 'fs';
import * as path from 'path';
import type { WritableSecretBackend, BackendHealth } from './types';
import { readKeyIndex } from './key-index';
import { leaksAny, redactValues } from '../redact';
import {
  BACKEND_CHILD_TIMEOUT_MS,
  runBoundedChild,
  type BoundedChildResult,
} from './bounded-child';

const LEGACY_SERVICE_NAME = 'secretless';
const INDEX_FILENAME = 'keychain-index.json';

/** The one program this backend runs. Absolute: PATH is never consulted. */
export const SECURITY_PROGRAM = '/usr/bin/security';

/**
 * Longest line the store will write to `security -i`, in bytes, newline
 * included.
 *
 * Basis: M1 measured a 4051-character line accepted and a 4115-character line
 * truncated and mis-parsed, and inferred a buffer near 4095. 4000 sits under
 * the longest line measured to work, with margin for the inference being off
 * by a few bytes in either direction. It leaves room for a value of about
 * 1950 bytes with a typical key, which covers every API key and most private
 * keys this tool is pointed at.
 */
export const MAX_SECURITY_LINE_BYTES = 4000;

/**
 * Internal seam, for tests only. Not a config key: `createBackend` never
 * passes it, and nothing reads it from the environment or a flag. A recorder
 * stands in for `security` so the argv, environment and stdin of every child
 * can be observed on a machine with no Keychain.
 */
export interface MacOSKeychainInternals {
  /** Program run in place of `/usr/bin/security`. */
  securityProgram?: string;
  /** Per-child bound. The default is the one named source in bounded-child.ts. */
  childTimeoutMs?: number;
}

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
 * The store refused to build a `security -i` line. Named, so a caller can
 * tell a refused input from a Keychain failure. The message never holds the
 * value.
 */
export class KeychainLineError extends Error {
  override readonly name = 'KeychainLineError';
  constructor(
    readonly reason: 'operand-newline' | 'line-too-long' | 'empty-value',
    message: string,
  ) {
    super(message);
  }
}

/**
 * Quote one operand of the `add-generic-password` line the way M1 measured
 * `security -i` to parse it: double quotes, `"` as `\"`, `\` as `\\`.
 *
 * A newline or carriage return cannot be quoted: M1 measured a newline
 * splitting the line into a second command whether quoted or not. A NUL cannot
 * reach the child at all. Both are refused by name.
 */
export function quoteSecurityOperand(operand: string, what: string): string {
  if (/[\r\n\0]/.test(operand)) {
    throw new KeychainLineError(
      'operand-newline',
      [
        `Refusing to store: the ${what} contains a line break.`,
        '',
        '  The macOS Keychain CLI reads one command per line, and a line break',
        '  inside a name would be read as a second command. Nothing was written.',
        '',
        `  Verify:  secretless-ai secret list`,
        `  Fix:     choose a name without a line break and run  secretless-ai secret set <NAME>`,
      ].join('\n'),
    );
  }
  return `"${operand.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
}

/**
 * The one line a store writes to `security -i`. The value is present only as
 * `-X` hex; every other operand is quoted. Exported so the line can be checked
 * without a child.
 */
export function buildAddGenericPasswordLine(
  service: string,
  account: string,
  label: string,
  value: string,
): string {
  if (value.length === 0) {
    throw new KeychainLineError(
      'empty-value',
      [
        `Refusing to store "${account}": the value is empty.`,
        '',
        '  Nothing was written.',
        '',
        '  Verify:  secretless-ai secret list',
        `  Fix:     secretless-ai secret set <NAME>  with a value`,
      ].join('\n'),
    );
  }
  const hex = Buffer.from(value, 'utf-8').toString('hex');
  const line = [
    'add-generic-password',
    '-s', quoteSecurityOperand(service, 'service name'),
    '-a', quoteSecurityOperand(account, 'secret name'),
    '-l', quoteSecurityOperand(label, 'label'),
    '-U',
    '-X', hex,
  ].join(' ') + '\n';

  const bytes = Buffer.byteLength(line, 'utf-8');
  if (bytes > MAX_SECURITY_LINE_BYTES) {
    throw new KeychainLineError(
      'line-too-long',
      [
        `Refusing to store "${account}": the value is too long for the macOS Keychain CLI.`,
        '',
        `  The value is ${Buffer.byteLength(value, 'utf-8')} bytes. Carried as hex on one`,
        `  command line it would need ${bytes} bytes, and this store sends at most`,
        `  ${MAX_SECURITY_LINE_BYTES}, because the CLI truncates a longer line and parses`,
        '  the remainder as further commands. Nothing was written.',
        '',
        '  Verify:  secretless-ai secret list',
        '  Fix:     secretless-ai backend set local  to use the encrypted file store',
        '           for values of this size',
      ].join('\n'),
    );
  }
  return line;
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
 * The value is never on the child's argv, so the usual Node echo of the
 * command line (`Command failed: security -i`) holds nothing. But `security`
 * may echo its stdin — the hex of the value — into stderr when it rejects a
 * line, and an older error could still arrive with the value in it. So both
 * the value and its hex form are scrubbed from whatever remains, and the final
 * guard is unconditional: if either can still be found in the message, the
 * message is discarded rather than trimmed.
 */
export function redactSecurityError(err: unknown, value: string, key: string): Error {
  const raw = err instanceof Error ? err.message : String(err);
  const values = value.length > 0
    ? [value, Buffer.from(value, 'utf-8').toString('hex')]
    : [];

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

  if (/did not respond within/.test(detail)) {
    lines.push(
      '',
      '  The Keychain did not answer in time. It is usually locked, with an',
      '  unlock or approval dialog waiting that could not be shown or was not',
      '  answered. The write was abandoned and the Keychain process was ended.',
      '',
      '  Verify:  security default-keychain',
      '  Fix:     unlock the login keychain and retry, or run',
      '           secretless-ai backend set local  to use the encrypted file store',
    );
  } else if (/authorization was canceled|User interaction is not allowed|interaction not allowed/i.test(detail)) {
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
 * What a failed child run can say about itself, with no argv and no stdin in
 * it. This is the text `redactSecurityError` scrubs; it names the program's
 * output and its exit status and nothing of ours.
 */
function describeChildFailure(res: BoundedChildResult, timeoutMs: number): Error {
  if (res.spawnError) {
    return new Error(`security could not be started: ${res.spawnError.message}`);
  }
  if (res.timedOut) {
    return new Error(`security did not respond within ${timeoutMs / 1000}s`);
  }
  const output = `${res.stderr}\n${res.stdout}`.trim();
  const status = res.status === null ? `signal ${res.signal ?? 'unknown'}` : `exit status ${res.status}`;
  return new Error(output ? `${output}\nsecurity ${status}` : `security ${status}`);
}

/**
 * The store reported success and the read-back did not agree.
 *
 * `security -i` exits with the status of the last command on its stream, so
 * the status alone is not proof the entry landed. The entry is read back and
 * compared; a mismatch is a thrown failure, never a silent success. The
 * message holds the key and nothing of the value.
 */
function storeNotConfirmedError(key: string, service: string, found: boolean): Error {
  return new Error(
    [
      `Could not confirm "${key}" was stored in the macOS Keychain.`,
      '',
      found
        ? '  The write reported success, but the entry read back holds a different'
        : '  The write reported success, but no entry could be read back.',
      found
        ? '  value. Nothing is reported as stored.'
        : '  Nothing is reported as stored.',
      '',
      `  Verify:  security find-generic-password -s "${service}" -a "${key}"`,
      '  Fix:     secretless-ai doctor',
    ].join('\n'),
  );
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

/**
 * The Keychain would not answer for this entry.
 *
 * Carries no `security` output: the failing command is `find-generic-password`,
 * whose argv holds no value, but its stderr is not ours to reason about and the
 * entry name says everything the user needs.
 */
function keychainUnreadableError(account: string, res: BoundedChildResult, timeoutMs: number): Error {
  const how = res.timedOut
    ? `security did not respond within ${timeoutMs / 1000}s and was ended`
    : res.spawnError
      ? `security could not be started: ${res.spawnError.code ?? res.spawnError.message}`
      : `security exit status: ${typeof res.status === 'number' ? res.status : 'unknown'}`;
  return new Error(
    [
      `The macOS Keychain would not return "${account}".`,
      '',
      '  Nothing was read. Refusing to report the secret as missing, because a',
      '  Keychain that will not answer is not a Keychain without the entry.',
      '',
      `  ${how}`,
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
  private readonly securityProgram: string;
  private readonly childTimeoutMs: number;

  constructor(config?: Record<string, unknown>, internals?: MacOSKeychainInternals) {
    const home = process.env.HOME ?? process.env.USERPROFILE ?? '/tmp';
    const storeDir = (config?.storeDir as string) ?? path.join(home, '.secretless-ai', 'store');
    fs.mkdirSync(storeDir, { recursive: true, mode: 0o700 });
    this.indexPath = path.join(storeDir, INDEX_FILENAME);
    // Deliberately from `internals`, never from `config`: config is user data.
    this.securityProgram = internals?.securityProgram ?? SECURITY_PROGRAM;
    this.childTimeoutMs = internals?.childTimeoutMs ?? BACKEND_CHILD_TIMEOUT_MS;
  }

  async store(key: string, value: string): Promise<void> {
    const svc = serviceNameFor(key);

    // Built before any child starts: a refused operand or an over-long value
    // is a named error and no process has seen anything.
    const line = buildAddGenericPasswordLine(svc, key, `Secretless: ${key}`, value);

    // `-U` updates the entry in place if it already exists, so the previous
    // value is never deleted ahead of a write that might fail. Deleting first
    // and then failing to add leaves the user with no credential at all.
    //
    // argv is `['-i']`. The command, with the value as hex, is the one line on
    // stdin.
    const res = await this.security(['-i'], line);
    if (res.spawnError || res.timedOut || res.status !== 0) {
      throw redactSecurityError(describeChildFailure(res, this.childTimeoutMs), value, key);
    }

    // The write said 0. `security -i` reports the status of the last command
    // on its stream, which this is, but a status is not the entry: read it
    // back and compare before reporting success.
    const back = await this.readBack(svc, key);
    if (back !== value) {
      throw storeNotConfirmedError(key, svc, back !== null);
    }

    // Only once the new value is committed, retire the legacy entry (old
    // unified service name) so reads cannot resolve to a stale duplicate.
    // Its outcome does not matter: no legacy entry is the common case.
    await this.security(['delete-generic-password', '-s', LEGACY_SERVICE_NAME, '-a', key]);

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
      let raw = await this.findPassword(service, key);
      if (raw === null) {
        service = LEGACY_SERVICE_NAME;
        raw = await this.findPassword(service, key);
      }
      if (raw !== null) {
        results[key] = await this.decode(raw, service, key);
      }
    }
    return results;
  }

  async delete(key: string): Promise<boolean> {
    let deleted = false;

    // Delete new-format entry
    const current = await this.security(['delete-generic-password', '-s', serviceNameFor(key), '-a', key]);
    if (current.status === 0) deleted = true;

    // Also delete legacy entry if it exists
    const legacy = await this.security(['delete-generic-password', '-s', LEGACY_SERVICE_NAME, '-a', key]);
    if (legacy.status === 0) deleted = true;

    if (deleted) {
      const index = this.readIndex();
      const filtered = index.filter(k => k !== key);
      this.writeIndex(filtered);
    }

    return deleted;
  }

  async healthCheck(): Promise<BackendHealth> {
    const start = Date.now();
    const res = await this.security(['default-keychain']);
    if (res.status === 0) {
      return {
        healthy: true,
        latencyMs: Date.now() - start,
        message: 'macOS Keychain available',
      };
    }
    return {
      healthy: false,
      latencyMs: Date.now() - start,
      message: res.timedOut
        ? `macOS Keychain did not respond within ${this.childTimeoutMs / 1000}s`
        : 'macOS Keychain not accessible',
    };
  }

  /**
   * One place every `security` child starts: the absolute program, the argv
   * exactly as given, the bound from its one source, and nothing else.
   */
  private security(args: string[], input?: string): Promise<BoundedChildResult> {
    return runBoundedChild(this.securityProgram, args, {
      timeoutMs: this.childTimeoutMs,
      input,
    });
  }

  /**
   * The stored value as this tool would hand it back, or null when absent.
   * Used by the read-back compare after a store.
   */
  private async readBack(service: string, account: string): Promise<string | null> {
    const raw = await this.findPassword(service, account);
    if (raw === null) return null;
    return this.decode(raw, service, account);
  }

  /**
   * Settle the `-w` output's encoding. The `-g` probe is a child call of its
   * own, so it is awaited here and handed to `decodeKeychainValue` as a
   * settled answer; it is only asked when the shape is ambiguous.
   */
  private async decode(raw: string, service: string, account: string): Promise<string> {
    const encoded = looksLikeKeychainHex(raw) ? await this.isHexEncoded(service, account) : false;
    return decodeKeychainValue(raw, () => encoded, account);
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
  private async isHexEncoded(service: string, account: string): Promise<boolean | null> {
    const res = await this.security(['find-generic-password', '-s', service, '-a', account, '-g']);
    if (res.spawnError || res.timedOut) return null;
    if (res.status !== 0) return null;
    return keychainOutputIsHexEncoded(`${res.stderr}\n${res.stdout}`);
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
   *
   * `-w` prints the value and one newline. Exactly that newline is removed:
   * trimming further would lose a value's own trailing whitespace and make the
   * read-back compare after a store disagree with what was written.
   */
  private async findPassword(service: string, account: string): Promise<string | null> {
    const res = await this.security(['find-generic-password', '-s', service, '-a', account, '-w']);
    if (res.status === 0) {
      return res.stdout.endsWith('\n') ? res.stdout.slice(0, -1) : res.stdout;
    }
    if (res.status === SECURITY_ITEM_NOT_FOUND) return null;
    throw keychainUnreadableError(account, res, this.childTimeoutMs);
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
