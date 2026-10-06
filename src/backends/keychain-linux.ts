/**
 * Linux Secret Service backend — stores secrets via the `secret-tool` CLI (libsecret).
 *
 * Each secret is stored with attributes:
 *   service = "secretless"
 *   account = key (e.g. "mcp/claude-desktop/my-server/API_KEY")
 *
 * Secret values are passed via stdin (not CLI args) to avoid /proc exposure.
 *
 * A lightweight key index file tracks stored key names for prefix-based lookups.
 * The index contains only key names — never secret values.
 *
 * No shell is involved: argv is an array, and the value is on stdin only.
 * Every child call is bounded in time (see bounded-child.ts): `secret-tool`
 * blocks on the keyring unlock dialog when the collection is locked, and a
 * dialog nobody answers must not hang the user's command.
 */

import * as fs from 'fs';
import * as path from 'path';
import type { WritableSecretBackend, BackendHealth } from './types';
import { readKeyIndex } from './key-index';
import {
  BACKEND_CHILD_TIMEOUT_MS,
  runBoundedChild,
  type BoundedChildResult,
} from './bounded-child';

const LEGACY_SERVICE_NAME = 'secretless';
const INDEX_FILENAME = 'keychain-index.json';
const SECRET_TOOL_PROGRAM = 'secret-tool';

/**
 * Internal seam, for tests only. Not a config key: `createBackend` never
 * passes it, and nothing reads it from the environment or a flag.
 */
export interface LinuxKeychainInternals {
  /** Program run in place of `secret-tool`. */
  secretToolProgram?: string;
  /** Per-child bound. The default is the one named source in bounded-child.ts. */
  childTimeoutMs?: number;
}

/**
 * Derive a per-key service name so password managers show a descriptive
 * name instead of "secretless" for every entry.
 */
function serviceNameFor(key: string): string {
  const lastSegment = key.split('/').pop() ?? key;
  return `Secretless: ${lastSegment}`;
}

/**
 * The store did not land. The message carries what `secret-tool` said on
 * stderr, which holds attribute names and never the value (the value went in
 * on stdin and `secret-tool` does not echo it), and never our own argv.
 */
function secretToolStoreError(key: string, res: BoundedChildResult, timeoutMs: number): Error {
  const how = res.timedOut
    ? `secret-tool did not respond within ${timeoutMs / 1000}s and was ended.`
    : res.spawnError
      ? `secret-tool could not be started: ${res.spawnError.code ?? res.spawnError.message}`
      : `secret-tool exit status: ${typeof res.status === 'number' ? res.status : 'unknown'}`;
  const said = res.stderr.trim();
  return new Error(
    [
      `Could not store "${key}" in the Linux Secret Service.`,
      '',
      `  ${how}`,
      ...(said ? said.split('\n').map(l => `  ${l}`) : []),
      '',
      res.timedOut
        ? '  The keyring is usually locked, with an unlock dialog waiting that could'
        : '  The keyring is usually locked, or no Secret Service is running.',
      ...(res.timedOut ? ['  not be shown or was not answered.'] : []),
      '',
      '  Verify:  secret-tool search service secretless',
      '  Fix:     unlock the login keyring and retry, or run',
      '           secretless-ai backend set local  to use the encrypted file store',
    ].join('\n'),
  );
}

/**
 * What `secret-tool` does when asked for an entry, measured with libsecret
 * 0.20.5 and 0.21.7 against gnome-keyring:
 *
 *   lookup, entry present, collection unlocked   exit 0, value on stdout
 *   lookup, entry absent                         exit 1, nothing on either stream
 *   lookup, entry present, collection locked     exit 1, nothing on either stream
 *     (unlock dialog not shown or dismissed)
 *   lookup, no session bus                       exit 1, "Cannot autolaunch D-Bus ..."
 *   lookup, no Secret Service on the bus         exit 1, "The name org.freedesktop.secrets
 *                                                was not provided by any .service files"
 *   search, entry absent (locked or not)         exit 0, nothing on either stream
 *   search, entry present, collection locked     exit 0, the item listed on stdout
 *
 * There is no exit status for "absent": the miss and the locked entry are the
 * same bytes. `search` with the same attributes tells them apart, and it never
 * opens an unlock dialog. Only a silent `lookup` settled by a silent, empty
 * `search` is absence; every other outcome is a question we did not get an
 * answer to.
 */
const LOOKUP_NOTHING_RETURNED_STATUS = 1;
const SEARCH_COMPLETED_STATUS = 0;

function saidNothing(res: BoundedChildResult, status: number): boolean {
  return !res.spawnError && !res.timedOut && res.status === status
    && res.stdout.length === 0 && res.stderr.length === 0;
}

/** Read-only check of the default collection's lock state; prints no value. */
const LOCKED_CHECK =
  'gdbus call --session --dest org.freedesktop.secrets --object-path /org/freedesktop/secrets/aliases/default --method org.freedesktop.DBus.Properties.Get org.freedesktop.Secret.Collection Locked';

/**
 * The Secret Service would not answer for this entry.
 *
 * `said` is what `lookup` printed on stderr, which is an error text and never
 * the value (the value only goes to stdout on success). Nothing `search`
 * printed is carried: for an unlocked item it prints the secret on stdout.
 */
function secretServiceUnreadableError(account: string, how: string, said: string, timedOut: boolean): Error {
  return new Error(
    [
      `The Linux Secret Service would not return "${account}".`,
      '',
      '  Nothing was read. Refusing to report the secret as missing, because a',
      '  keyring that will not answer is not a keyring without the entry.',
      '',
      `  ${how}`,
      ...(said ? said.split('\n').map(l => `  ${l}`) : []),
      '',
      timedOut
        ? '  The keyring is usually locked, with an unlock dialog waiting that could'
        : '  The keyring is usually locked and its unlock dialog was dismissed or',
      timedOut
        ? '  not be shown or was not answered.'
        : '  could not be shown, or no Secret Service is reachable from this session.',
      '',
      `  Verify:  ${LOCKED_CHECK}`,
      '           (prints (<true>,) when the default collection is locked)',
      '  Fix:     unlock the login keyring and retry, or run',
      '           secretless-ai backend set local  to use the encrypted file store',
    ].join('\n'),
  );
}

function describeSecretToolFailure(verb: string, res: BoundedChildResult, timeoutMs: number): string {
  return res.timedOut
    ? `secret-tool ${verb} did not respond within ${timeoutMs / 1000}s and was ended.`
    : res.spawnError
      ? `secret-tool could not be started: ${res.spawnError.code ?? res.spawnError.message}`
      : `secret-tool ${verb} exit status: ${typeof res.status === 'number' ? res.status : `signal ${res.signal ?? 'unknown'}`}`;
}

export class LinuxKeychainBackend implements WritableSecretBackend {
  readonly name = 'keychain-linux';
  private readonly indexPath: string;
  private readonly secretToolProgram: string;
  private readonly childTimeoutMs: number;

  constructor(config?: Record<string, unknown>, internals?: LinuxKeychainInternals) {
    const home = process.env.HOME ?? '/tmp';
    const storeDir = (config?.storeDir as string) ?? path.join(home, '.secretless-ai', 'store');
    fs.mkdirSync(storeDir, { recursive: true, mode: 0o700 });
    this.indexPath = path.join(storeDir, INDEX_FILENAME);
    // Deliberately from `internals`, never from `config`: config is user data.
    this.secretToolProgram = internals?.secretToolProgram ?? SECRET_TOOL_PROGRAM;
    this.childTimeoutMs = internals?.childTimeoutMs ?? BACKEND_CHILD_TIMEOUT_MS;
  }

  async store(key: string, value: string): Promise<void> {
    const svc = serviceNameFor(key);

    // Delete legacy entry to prevent duplicates. No legacy entry is the common
    // case, so the outcome is not inspected.
    await this.secretTool(['clear', 'service', LEGACY_SERVICE_NAME, 'account', key]);

    // secret-tool store reads the value from stdin
    const res = await this.secretTool([
      'store',
      `--label=Secretless: ${key}`,
      'service', svc,
      'account', key,
    ], value);
    if (res.spawnError || res.timedOut || res.status !== 0) {
      throw secretToolStoreError(key, res, this.childTimeoutMs);
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
      // Try new per-key service name first, fall back to legacy
      const value = (await this.lookupSecret(serviceNameFor(key), key))
        ?? (await this.lookupSecret(LEGACY_SERVICE_NAME, key));
      if (value) {
        results[key] = value;
      }
    }
    return results;
  }

  async delete(key: string): Promise<boolean> {
    let deleted = false;

    // Delete new-format entry
    const current = await this.secretTool(['clear', 'service', serviceNameFor(key), 'account', key]);
    if (current.status === 0) deleted = true;

    // Also delete legacy entry if it exists
    const legacy = await this.secretTool(['clear', 'service', LEGACY_SERVICE_NAME, 'account', key]);
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
    const res = await runBoundedChild('which', [this.secretToolProgram], {
      timeoutMs: this.childTimeoutMs,
    });
    if (res.status === 0) {
      return {
        healthy: true,
        latencyMs: Date.now() - start,
        message: 'secret-tool available (Linux Secret Service)',
      };
    }
    return {
      healthy: false,
      latencyMs: Date.now() - start,
      message: 'secret-tool not found. Install libsecret-tools (Debian/Ubuntu) or libsecret (Fedora/RHEL).',
    };
  }

  /**
   * One place every `secret-tool` child starts: the program, the argv exactly
   * as given, the bound from its one source, and the value (when there is one)
   * on stdin.
   */
  private secretTool(args: string[], input?: string): Promise<BoundedChildResult> {
    return runBoundedChild(this.secretToolProgram, args, {
      timeoutMs: this.childTimeoutMs,
      input,
    });
  }

  /**
   * The stored value, or null when the entry genuinely is not there.
   *
   * Every failure used to answer null, so a locked collection, a dismissed
   * unlock dialog or a session with no Secret Service made every secret read
   * as absent: `resolve` returned {}, `run` injected nothing, exit 0 (#130).
   *
   * A silent exit 1 from `lookup` is either absence or a locked entry (see
   * the measurements above), so `search` is asked to settle it. Any other
   * outcome of either call throws.
   *
   * `lookup` prints the value with no trailing newline; a trailing newline
   * that does arrive is removed, as before.
   */
  private async lookupSecret(service: string, account: string): Promise<string | null> {
    const attrs = ['service', service, 'account', account];
    const res = await this.secretTool(['lookup', ...attrs]);
    if (res.status === 0) {
      const value = res.stdout.trimEnd();
      return value || null;
    }
    if (!saidNothing(res, LOOKUP_NOTHING_RETURNED_STATUS)) {
      throw secretServiceUnreadableError(
        account,
        describeSecretToolFailure('lookup', res, this.childTimeoutMs),
        res.stderr.trim(),
        res.timedOut,
      );
    }

    const found = await this.secretTool(['search', ...attrs]);
    if (saidNothing(found, SEARCH_COMPLETED_STATUS)) return null;
    const searchCompleted = !found.spawnError && !found.timedOut && found.status === SEARCH_COMPLETED_STATUS;
    const how = !searchCompleted
      ? describeSecretToolFailure('search', found, this.childTimeoutMs)
      : found.stdout.length > 0
        ? 'The keyring holds an entry with these attributes and did not return its value.'
        : 'secret-tool search exited 0 with output on stderr, which an empty result does not have.';
    throw secretServiceUnreadableError(account, how, '', found.timedOut);
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
