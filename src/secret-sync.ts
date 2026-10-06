/**
 * Secret sync — copy named secrets from a shared backend (1Password, Vault,
 * GCP Secret Manager) into this machine's store, so a new machine is seeded by
 * name instead of by hand (#176).
 *
 * Values move backend to backend inside this process. Nothing here returns,
 * logs or formats a value: the result names entries and says what happened to
 * each, and a backend error is carried as its first line only.
 *
 * Each name is read from the source by its own key rather than by listing the
 * source first. A Vault token with `read` but no `list` on the metadata path
 * answers a prefix listing with nothing at all, and a sync that started from a
 * listing would report "nothing to copy" from a store that holds every name
 * asked for. Reading by name works on every backend the factory builds.
 */

import { SECRET_PREFIX } from './secret-store';
import type { SecretStore } from './secret-store';
import type { SecretBackend } from './backends/types';

export type SyncAction =
  /** In the source, not stored on this machine. */
  | 'create'
  /** The local value differed from the source's and was replaced (--force). */
  | 'update'
  /** The local value already equals the source's. */
  | 'unchanged'
  /** The local value differs from the source's and was left as is. */
  | 'conflict'
  /** Not in the source; the local value was left as is. */
  | 'local-only'
  /** Neither in the source nor stored on this machine. */
  | 'not-found'
  /** Reading or storing it raised; see `error`. */
  | 'failed';

export interface SyncEntry {
  name: string;
  action: SyncAction;
  /** First line of the error, for `failed`. Backend errors name keys, never values. */
  error?: string;
}

export interface SyncOptions {
  /** Classify every name and write nothing. Values are read to compare them. */
  dryRun?: boolean;
  /** Replace a local value that differs from the source's. */
  force?: boolean;
}

export interface SyncResult {
  entries: SyncEntry[];
  dryRun: boolean;
  /**
   * Every selected name is (or, on a dry run, would be) stored on this machine
   * with nothing left over: no conflict, no name missing from both stores, no
   * failure.
   */
  ok: boolean;
}

/** Actions that leave the selected name stored locally and need nothing further. */
const SETTLED: ReadonlySet<SyncAction> = new Set<SyncAction>([
  'create', 'update', 'unchanged', 'local-only',
]);

/**
 * Copy `names` from `source` into `store`.
 *
 * Throws, before reading or writing any entry, when the source reports itself
 * unhealthy: a source that cannot answer would otherwise report every name as
 * "not found", which reads as a statement about the shared store's contents.
 */
export async function syncSecrets(
  source: SecretBackend,
  store: SecretStore,
  names: string[],
  options: SyncOptions = {},
): Promise<SyncResult> {
  const dryRun = options.dryRun === true;
  const force = options.force === true;
  const sourceName = displayName(source.name);

  const health = await source.healthCheck();
  if (!health.healthy) {
    throw new Error(
      [
        `Source backend "${sourceName}" is not reachable: ${oneLine(health.message ?? 'health check failed')}`,
        '',
        '  Nothing was read from it, and nothing on this machine was changed.',
      ].join('\n'),
    );
  }

  // Presence comes from the local name list, so a value is read locally only
  // for a name both stores hold — the one case a comparison needs.
  const localNames = new Set(await store.listSecrets());

  const entries: SyncEntry[] = [];
  for (const name of [...new Set(names)]) {
    entries.push(await syncOne(source, sourceName, store, name, localNames.has(name), dryRun, force));
  }

  return { entries, dryRun, ok: entries.every((e) => SETTLED.has(e.action)) };
}

async function syncOne(
  source: SecretBackend,
  sourceName: string,
  store: SecretStore,
  name: string,
  storedLocally: boolean,
  dryRun: boolean,
  force: boolean,
): Promise<SyncEntry> {
  const key = `${SECRET_PREFIX}/${name}`;

  let sourceValue: string | undefined;
  try {
    const resolved = await source.resolve(key);
    // Exact key only. Some backends answer an unknown name with a listing of
    // other entries (GCP Secret Manager falls back to listing the project);
    // none of those is the entry asked for.
    sourceValue = Object.prototype.hasOwnProperty.call(resolved, key) ? resolved[key] : undefined;
  } catch (err) {
    return { name, action: 'failed', error: `could not read it from ${sourceName}: ${firstLine(err)}` };
  }

  if (sourceValue === undefined) {
    return { name, action: storedLocally ? 'local-only' : 'not-found' };
  }

  let localValue: string | undefined;
  if (storedLocally) {
    try {
      localValue = await store.getSecret(name);
    } catch (err) {
      return { name, action: 'failed', error: `could not read the local value: ${firstLine(err)}` };
    }
  }

  if (localValue === sourceValue) return { name, action: 'unchanged' };

  const action: SyncAction = localValue === undefined ? 'create' : force ? 'update' : 'conflict';
  if (action === 'conflict' || dryRun) return { name, action };

  try {
    await store.setSecret(name, sourceValue);
  } catch (err) {
    return { name, action: 'failed', error: `could not store it: ${firstLine(err)}` };
  }
  return { name, action };
}

/** `cached(1password)` -> `1password`: the cache layer is not a backend anyone chose. */
export function displayName(backendName: string): string {
  return backendName.replace(/^cached\((.*)\)$/, '$1');
}

function firstLine(err: unknown): string {
  const message = err instanceof Error ? err.message : String(err);
  return oneLine(message.split('\n')[0] ?? '');
}

function oneLine(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}
