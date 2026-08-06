/**
 * Secret store — CRUD operations for user-managed secrets.
 *
 * Stores secrets with key prefix `secret/` to separate them from MCP secrets
 * (`mcp/` prefix). Uses the same pluggable backend infrastructure (local
 * encrypted file or OS keychain).
 */

import { createBackend } from './backends/factory';
import { resolveBackendType } from './backends/config';
import type { WritableSecretBackend } from './backends/types';
import type { SelectableBackendType } from './backends/config';

const SECRET_PREFIX = 'secret';

/** Validates secret names: alphanumeric, dash, underscore only. */
const SAFE_NAME = /^[a-zA-Z0-9_-]+$/;

export interface SecretStoreOptions {
  /** Backend type to use. Resolved from config if not provided. */
  backendType?: SelectableBackendType;
  /** Pre-constructed backend instance (overrides backendType). For DI/testing. */
  backend?: WritableSecretBackend;
}

export class SecretStore {
  private readonly backend: WritableSecretBackend;

  constructor(options?: SecretStoreOptions) {
    if (options?.backend) {
      this.backend = options.backend;
      return;
    }

    const backendType = resolveBackendType(options?.backendType);
    this.backend = createBackend(backendType);
  }

  /**
   * Human-readable name of the active backend (e.g. `local`, `keychain-macos`,
   * `1password`). Surfaced so commands can disclose WHERE secrets live — the
   * store is machine-global (one backend per machine config), not per-project.
   */
  get backendName(): string {
    // Unwrap the cache decorator's `cached(<inner>)` name — the in-memory cache
    // layer is an implementation detail, not a backend the user chose.
    return this.backend.name.replace(/^cached\((.*)\)$/, '$1');
  }

  /** Store a secret by name. */
  async setSecret(name: string, value: string): Promise<void> {
    validateSecretName(name);
    const key = `${SECRET_PREFIX}/${name}`;
    await this.backend.store(key, value);
  }

  /** Retrieve a secret value by name. Returns undefined if not found. */
  async getSecret(name: string): Promise<string | undefined> {
    validateSecretName(name);
    const key = `${SECRET_PREFIX}/${name}`;
    const result = await this.backend.resolve(key);
    return result[key];
  }

  /** List all stored secret names (no values). */
  async listSecrets(): Promise<string[]> {
    const all = await this.backend.resolve(SECRET_PREFIX);
    const names: string[] = [];
    for (const fullKey of Object.keys(all)) {
      // Keys are in format: secret/{name}
      const name = fullKey.slice(SECRET_PREFIX.length + 1);
      if (name) {
        names.push(name);
      }
    }
    return names.sort();
  }

  /** Remove a secret by name. Returns true if the secret existed. */
  async removeSecret(name: string): Promise<boolean> {
    validateSecretName(name);
    const key = `${SECRET_PREFIX}/${name}`;
    return this.backend.delete(key);
  }

  /**
   * Load all secrets as key-value pairs. Optionally filter by name list
   * (case-insensitive).
   *
   * Throws if any REQUESTED name resolved to nothing. This function used to
   * filter only what the backend RETURNED, so an unmatched name left no trace
   * and was indistinguishable downstream from a name nobody asked for. Callers
   * saw a count and guessed at the cause: `run --only MISSING` blamed the
   * backend, `run --only PRESENT,MISSING` ran the command a credential short and
   * exited 0, and on an empty store `--only` was ignored entirely and the
   * command ran with nothing injected (#110).
   *
   * Requested-vs-resolved is compared here because this is the only place both
   * are in scope. Failing closed matters more than the count: a command that
   * runs without a credential it asked for surfaces later as an auth error that
   * never mentions secretless.
   */
  async loadSecrets(only?: string[]): Promise<Record<string, string>> {
    const all = await this.backend.resolve(SECRET_PREFIX);
    const result: Record<string, string> = {};
    const normalizedOnly = only?.map((k) => k.toUpperCase());

    const available: string[] = [];
    for (const [fullKey, value] of Object.entries(all)) {
      const name = fullKey.slice(SECRET_PREFIX.length + 1);
      if (!name) continue;
      available.push(name);
      if (normalizedOnly && !normalizedOnly.includes(name.toUpperCase())) continue;
      result[name] = value;
    }

    if (normalizedOnly) {
      // `--only ,,` parses to an empty list, which would otherwise filter
      // everything out and inject nothing while looking like a successful run.
      if (normalizedOnly.length === 0) {
        throw new Error(
          '--only was given but named no secrets.\n\n' +
          '  Nothing was injected and the command was not run.\n\n' +
          '  Verify:  secretless-ai secret list\n' +
          '  Fix:     secretless-ai run --only NAME1,NAME2 -- <command>',
        );
      }
      const resolved = new Set(Object.keys(result).map((n) => n.toUpperCase()));
      const unmatched = [...new Set(normalizedOnly)].filter((n) => !resolved.has(n));
      if (unmatched.length > 0) {
        throw unmatchedSecretsError(unmatched, available);
      }
    }
    return result;
  }
}

/** Largest edit distance still shown as a "did you mean". */
const NEAR_MISS_MAX = 2;

/** Most unmatched names we compute a near-miss hint for. */
const MAX_HINTED = 10;

/** Anything above the threshold; all such values are equivalent to the caller. */
const OVER = NEAR_MISS_MAX + 1;

/**
 * Case-insensitive edit distance, only ever used to suggest a typo fix.
 * Any result above NEAR_MISS_MAX is returned as OVER, not computed exactly.
 *
 * BANDED. Only cells within NEAR_MISS_MAX of the diagonal are evaluated, so a
 * comparison costs O(n * k) rather than O(n^2) — bounded whether the two names
 * are similar or not.
 *
 * A row-minimum cutoff alone is not enough, and the measurement that suggested
 * it was misleading: it used maximally DIFFERENT names, which exit on the first
 * row. For names sharing a long prefix and differing only near the end — the
 * realistic shape, since stored names look alike — the band around the diagonal
 * stays under the threshold and the full table gets computed. Measured at 5000
 * stored names sharing a 60-char prefix, against 100 unmatched: 7814ms
 * unbounded, 840ms with the cutoff alone, 378ms banded. (The same shape with
 * maximally different names is 33ms — which is why benchmarking that shape hid
 * the problem.)
 */
function editDistance(a: string, b: string): number {
  const s = a.toUpperCase();
  const t = b.toUpperCase();
  // Names have no length limit; keep the table small regardless.
  if (s.length > 64 || t.length > 64) return OVER;
  if (Math.abs(s.length - t.length) > NEAR_MISS_MAX) return OVER;

  let prev: number[] = new Array(t.length + 1).fill(OVER);
  for (let j = 0; j <= Math.min(t.length, NEAR_MISS_MAX); j++) prev[j] = j;

  for (let i = 1; i <= s.length; i++) {
    const cur: number[] = new Array(t.length + 1).fill(OVER);
    cur[0] = i <= NEAR_MISS_MAX ? i : OVER;
    const lo = Math.max(1, i - NEAR_MISS_MAX);
    const hi = Math.min(t.length, i + NEAR_MISS_MAX);
    let rowMin = cur[0];
    for (let j = lo; j <= hi; j++) {
      const v = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (s[i - 1] === t[j - 1] ? 0 : 1),
      );
      cur[j] = v > OVER ? OVER : v;
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    // Every reachable cell already exceeds the threshold, so the final distance
    // cannot come back under it.
    if (rowMin > NEAR_MISS_MAX) return OVER;
    prev = cur;
  }
  return prev[t.length];
}

/**
 * Error for `--only` names that matched nothing.
 *
 * Names only NAMES, never values — `secret list` already prints names, and the
 * Verify line points at it. The near-miss hint is drawn from names actually in
 * the store, so it cannot suggest something that does not exist.
 */
function unmatchedSecretsError(unmatched: string[], available: string[]): Error {
  const plural = unmatched.length === 1 ? '' : 's';
  const lines = [
    `Requested secret${plural} not found in the store: ${unmatched.join(', ')}`,
    '',
    '  Nothing was injected and the command was not run.',
  ];

  // Hints are a bonus on top of naming every unmatched entry, so bound the work
  // rather than letting a long `--only` list multiply against a large store.
  const hints: string[] = [];
  for (const miss of unmatched.slice(0, MAX_HINTED)) {
    const near = available
      .map((name) => ({ name, d: editDistance(miss, name) }))
      .filter((c) => c.d > 0 && c.d <= NEAR_MISS_MAX)
      .sort((a, b) => a.d - b.d)[0];
    if (near) hints.push(`${miss} -> ${near.name}`);
  }
  if (hints.length > 0) {
    lines.push('', `  Did you mean:  ${hints.join('   ')}`);
  }

  lines.push(
    '',
    '  Verify:  secretless-ai secret list',
    `  Fix:     secretless-ai secret set ${unmatched[0]}`,
  );
  return new Error(lines.join('\n'));
}

/**
 * Whether a string is usable as a secret name. Shared so the manifest parser
 * applies the SAME rule as the store instead of restating it — `.secretless`
 * used to accept `required:` and `-` as names and report them as missing
 * secrets (#112).
 */
export function isValidSecretName(name: string): boolean {
  return SAFE_NAME.test(name);
}

function validateSecretName(name: string): void {
  if (!SAFE_NAME.test(name)) {
    throw new Error(
      `Invalid secret name: "${name}". Only alphanumeric, dash, and underscore allowed.`,
    );
  }
}
