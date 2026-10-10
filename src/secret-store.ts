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
import { findSecretValueProblem, unstorableSecretError } from './secret-value';
import { editDistance, NEAR_MISS_MAX } from './near-miss';
import { escapeForDisplay } from './display-safe';
import { SecretAnnotations, checkAnnotation, defaultAnnotationsPath, isEmptyUpdate } from './secret-annotations';
import type { AnnotationMap, AnnotationUpdate, SecretAnnotation } from './secret-annotations';
import { exposureUpdate, openExposure, rotationUpdate } from './secret-exposure';
import type { OpenExposure } from './secret-exposure';

/** Key prefix for user secrets: `secret/<NAME>` in every backend. */
export const SECRET_PREFIX = 'secret';

/** Validates secret names: alphanumeric, dash, underscore only. */
const SAFE_NAME = /^[a-zA-Z0-9_-]+$/;

export interface SecretStoreOptions {
  /** Backend type to use. Resolved from config if not provided. */
  backendType?: SelectableBackendType;
  /** Pre-constructed backend instance (overrides backendType). For DI/testing. */
  backend?: WritableSecretBackend;
  /**
   * File holding descriptions and metadata. Defaults to
   * `~/.secretless-ai/secret-annotations.json`, except with an injected
   * `backend`, where they are kept in memory unless a path is given here.
   */
  annotationsPath?: string;
}

export class SecretStore {
  private readonly backend: WritableSecretBackend;
  private readonly annotations: SecretAnnotations;

  constructor(options?: SecretStoreOptions) {
    this.annotations = new SecretAnnotations(
      options?.annotationsPath ?? (options?.backend ? null : defaultAnnotationsPath()),
    );
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

  /**
   * Store a secret by name.
   *
   * Validated here rather than in the prompt: `secret set` and `import` both
   * arrive at this method. The MCP write path does not, and applies the same
   * check in `McpVault.storeServerSecrets` (#104).
   *
   * `annotation` records what the secret is for (#172). It is checked against
   * the value, and the annotation file is read, BEFORE the value is stored, so
   * a refused annotation stores nothing. Without one, an existing annotation is
   * left as it is: rotating a value does not change what it is for.
   *
   * When the name has an open exposure (#236), the stored value is read and
   * compared with the new one in memory: a different value closes the exposure
   * and records `rotatedAt`; the same value leaves it open. Without an open
   * exposure the stored value is not read. A plain set whose annotation file
   * cannot be read still stores the value, and says the exposure could not be
   * checked, so a damaged metadata file never blocks a rotation.
   */
  async setSecret(name: string, value: string, annotation?: AnnotationUpdate): Promise<SetSecretResult> {
    validateSecretName(name);
    const problem = findSecretValueProblem(value);
    if (problem) throw unstorableSecretError(name, problem);
    const annotate = !isEmptyUpdate(annotation);
    if (annotate) {
      const reason = checkAnnotation(annotation!, value);
      if (reason) throw unrecordableAnnotationError(name, reason);
    }

    const key = `${SECRET_PREFIX}/${name}`;
    let rotation: RotationOutcome = { kind: 'none' };
    let current: SecretAnnotation | undefined;
    try {
      current = this.annotations.get(name);
    } catch (err) {
      if (annotate) throw err;
      rotation = { kind: 'unknown', reason: err instanceof Error ? err.message : String(err) };
    }
    let update = annotation;
    const exposure = openExposure(current);
    if (exposure) {
      const previous = (await this.backend.resolve(key))[key];
      if (previous === value) {
        rotation = { kind: 'still-open', exposure };
      } else {
        const now = new Date();
        rotation = { kind: 'closed', exposure, rotatedAt: now.toISOString() };
        update = rotationUpdate(now, annotation);
      }
    }

    const write = !isEmptyUpdate(update);
    // An unreadable file or too many keys refuses here, before the value
    // changes, rather than after it as a half-done write.
    if (write) this.annotations.preview(name, update!);
    await this.backend.store(key, value);
    if (!write) return { rotation };
    try {
      this.annotations.update(name, update!);
    } catch (err) {
      const what = rotation.kind === 'closed'
        ? 'the rotation was not recorded, so it is still listed as exposed'
        : 'its description and metadata were not recorded';
      throw new Error(`Stored ${name}, but ${what}: ${err instanceof Error ? err.message : String(err)}`);
    }
    return { rotation };
  }

  /**
   * Record that `name`'s stored value was exposed at `at`, and where (#236).
   *
   * The value is read to confirm it is stored and to refuse a note that holds
   * it; it goes no further. An open exposure is replaced, and returned so the
   * caller can say so.
   */
  async recordExposure(name: string, where: string, at: Date): Promise<{ previous: OpenExposure | null }> {
    validateSecretName(name);
    const value = await this.getSecret(name);
    if (value === undefined) throw notStoredError(name);
    const update = exposureUpdate(at, where);
    const reason = checkAnnotation(update, value);
    if (reason) throw unrecordableExposureError(name, reason.replace('--meta exposedWhere', '--where'));
    const previous = openExposure(this.annotations.get(name));
    this.annotations.update(name, update);
    return { previous };
  }

  /** Description and metadata recorded for a name. Never reads the value. */
  getAnnotation(name: string): SecretAnnotation | undefined {
    validateSecretName(name);
    return this.annotations.get(name);
  }

  /** Every recorded description and metadata, keyed by name. Never reads a value. */
  listAnnotations(): AnnotationMap {
    return this.annotations.all();
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

  /**
   * Remove a secret by name, and its description and metadata. Returns true if
   * the secret existed.
   *
   * The value goes first: a damaged annotation file must not keep a credential
   * in the store. If the annotation cannot be dropped afterwards, that is
   * thrown with the value's removal stated, not hidden behind a success.
   */
  async removeSecret(name: string): Promise<boolean> {
    validateSecretName(name);
    const key = `${SECRET_PREFIX}/${name}`;
    const removed = await this.backend.delete(key);
    try {
      this.annotations.remove(name);
    } catch (err) {
      const head = removed
        ? `Removed ${name} from the store, but its description and metadata were not removed`
        : `${name} is not in the store, and its description and metadata could not be removed`;
      throw new Error(`${head}: ${err instanceof Error ? err.message : String(err)}`);
    }
    return removed;
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

/** What `setSecret` did about an open exposure (#236). */
export type RotationOutcome =
  /** No exposure was open. */
  | { kind: 'none' }
  /** The new value differs from the stored one: the exposure is closed. */
  | { kind: 'closed'; exposure: OpenExposure; rotatedAt: string }
  /** The new value is the stored one: the exposure stays open. */
  | { kind: 'still-open'; exposure: OpenExposure }
  /** The annotation file could not be read, so it is not known. */
  | { kind: 'unknown'; reason: string };

export interface SetSecretResult {
  rotation: RotationOutcome;
}

/** `recordExposure` on a name with no stored value. */
function notStoredError(name: string): Error {
  return new Error(
    [
      `Secret not found: ${name}`,
      '',
      '  Nothing was recorded. An exposure is recorded against a stored value.',
      '',
      '  Verify:  secretless-ai secret list',
      `  Fix:     secretless-ai secret set ${name}`,
    ].join('\n'),
  );
}

/** An exposure note refused by `checkAnnotation`. Nothing was recorded. */
function unrecordableExposureError(name: string, reason: string): Error {
  return new Error(
    [
      reason,
      '',
      `  Nothing was recorded for ${name}.`,
      '',
      `  Fix:     secretless-ai secret exposed ${name} --where "where it was exposed, without the value"`,
    ].join('\n'),
  );
}

/** An annotation refused by `checkAnnotation`. Nothing was stored. */
function unrecordableAnnotationError(name: string, reason: string): Error {
  return new Error(
    [
      `${reason}`,
      '',
      `  Nothing was stored, and nothing recorded for ${name} changed.`,
      '',
      `  Verify:  secretless-ai secret show ${name}`,
      `  Fix:     secretless-ai secret set ${name} --description "what it is for" --meta key=value`,
    ].join('\n'),
  );
}

/** Most unmatched names we compute a near-miss hint for. */
const MAX_HINTED = 10;


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
    // Escaped: a command prints this message, and a line feed in the refused
    // name started a line of its own under it.
    throw new Error(
      `Invalid secret name: "${escapeForDisplay(name)}". Only alphanumeric, dash, and underscore allowed.`,
    );
  }
}
