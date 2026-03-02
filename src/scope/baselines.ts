/**
 * Scope baseline storage and comparison.
 *
 * Stores credential scope baselines in ~/.secretless-ai/scope-baselines.json.
 * Provides functions to save, load, compare, and reset baselines.
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import type { ScopeBaseline, ScopeCheckResult } from './types';

const CONFIG_DIR = path.join(os.homedir(), '.secretless-ai');
const BASELINES_FILE = path.join(CONFIG_DIR, 'scope-baselines.json');

interface BaselineStore {
  baselines: Record<string, ScopeBaseline>;
}

/**
 * Save a scope baseline for a credential.
 * If a baseline already exists, the previous permissions are preserved
 * for historical comparison.
 */
export function saveBaseline(baseline: ScopeBaseline): void {
  const store = loadStore();

  const existing = store.baselines[baseline.credentialName];
  if (existing) {
    baseline.previousPermissions = existing.permissions;
  }

  store.baselines[baseline.credentialName] = baseline;
  writeStore(store);
}

/**
 * Load a stored baseline for a credential.
 * Returns undefined if no baseline exists.
 */
export function loadBaseline(credentialName: string): ScopeBaseline | undefined {
  const store = loadStore();
  return store.baselines[credentialName];
}

/**
 * List all stored baselines.
 */
export function listBaselines(): ScopeBaseline[] {
  const store = loadStore();
  return Object.values(store.baselines);
}

/**
 * Compare current permissions against the stored baseline for a credential.
 * Returns a ScopeCheckResult with added/removed permissions and expansion flag.
 */
export function compareToBaseline(
  credentialName: string,
  provider: string,
  currentPermissions: string[],
): ScopeCheckResult {
  const baseline = loadBaseline(credentialName);
  const baselinePermissions = baseline?.permissions ?? [];
  const now = new Date().toISOString();

  const currentSet = new Set(currentPermissions);
  const baselineSet = new Set(baselinePermissions);

  const added = currentPermissions.filter(p => !baselineSet.has(p));
  const removed = baselinePermissions.filter(p => !currentSet.has(p));

  return {
    credentialName,
    provider,
    currentPermissions,
    baselinePermissions,
    added,
    removed,
    hasExpanded: added.length > 0,
    checkedAt: now,
  };
}

/**
 * Reset (clear) the baseline for a credential.
 * The next discover will create a fresh baseline.
 */
export function resetBaseline(credentialName: string): boolean {
  const store = loadStore();
  if (!(credentialName in store.baselines)) {
    return false;
  }
  delete store.baselines[credentialName];
  writeStore(store);
  return true;
}

// --- Internal helpers ---

function loadStore(): BaselineStore {
  try {
    const raw = fs.readFileSync(BASELINES_FILE, 'utf-8');
    const parsed = JSON.parse(raw) as BaselineStore;
    if (parsed && typeof parsed.baselines === 'object') {
      return parsed;
    }
    return { baselines: {} };
  } catch {
    return { baselines: {} };
  }
}

function writeStore(store: BaselineStore): void {
  fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });

  const tmpPath = BASELINES_FILE + '.tmp';
  fs.writeFileSync(tmpPath, JSON.stringify(store, null, 2) + '\n', { mode: 0o600 });
  fs.renameSync(tmpPath, BASELINES_FILE);
}
