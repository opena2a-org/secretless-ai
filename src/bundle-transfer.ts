/**
 * Store-to-store transfer through an encrypted bundle (#175): `export` reads
 * the selected secrets from this machine's backend into a bundle, `import`
 * writes a bundle's entries into this machine's backend. The format itself is
 * in bundle.ts, which scan and clean read without loading a backend.
 */

import * as fs from 'fs';
import { SecretStore, isValidSecretName } from './secret-store';
import type { SecretStoreOptions } from './secret-store';
import { findSecretValueProblem } from './secret-value';
import { readManifest } from './manifest';
import {
  sealBundle,
  openBundle,
  notABundle,
  BUNDLE_EXTENSION,
  MIN_PASSPHRASE_LENGTH,
  MAX_BUNDLE_BYTES,
  type BundleEntry,
  type KdfParams,
} from './bundle';

export interface ExportBundleOptions extends SecretStoreOptions {
  /** Names to export (case-insensitive, as `run --only`). Every name when absent. */
  only?: string[];
  /** Directory whose `.secretless` supplies manifest metadata. */
  projectDir?: string;
  kdf?: KdfParams;
}

export interface ExportBundleResult {
  names: string[];
  backendName: string;
}

/**
 * Write the selected secrets to `outPath` as a bundle. Refuses, before reading
 * any value, an `outPath` without the bundle extension or one that exists;
 * the file is created owner-only and never overwritten.
 */
export async function exportBundle(
  outPath: string,
  passphrase: string,
  options: ExportBundleOptions = {},
): Promise<ExportBundleResult> {
  if (!outPath.toLowerCase().endsWith(BUNDLE_EXTENSION)) {
    throw new Error(
      `The bundle file name must end in ${BUNDLE_EXTENSION}: ${outPath}\n\n` +
      '  Nothing was exported. scan and clean recognise a bundle by that extension.\n\n' +
      `  Fix:     --out ${outPath}${BUNDLE_EXTENSION}`,
    );
  }
  if (fs.existsSync(outPath)) {
    throw new Error(
      `${outPath} already exists. Nothing was exported, and the file was not changed.\n\n` +
      '  Fix:     choose another --out path, or delete the old bundle first',
    );
  }
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new Error(
      `The passphrase is shorter than ${MIN_PASSPHRASE_LENGTH} characters. Nothing was exported.\n\n` +
      '  A bundle can be guessed at offline by anyone who gets the file, so its\n' +
      '  passphrase has to be long. Several unrelated words work well.',
    );
  }

  const store = new SecretStore(options);
  const all = await store.loadSecrets();
  const stored = Object.keys(all).sort();
  let names = stored;
  if (options.only) {
    const wanted = [...new Set(options.only.map((n) => n.toUpperCase()))];
    if (wanted.length === 0) {
      throw new Error('--only was given but named no secrets. Nothing was exported.');
    }
    names = stored.filter((n) => wanted.includes(n.toUpperCase()));
    const found = new Set(names.map((n) => n.toUpperCase()));
    const missing = options.only.filter((n) => !found.has(n.toUpperCase()));
    if (missing.length > 0) {
      throw new Error(
        `Not in the store: ${[...new Set(missing)].join(', ')}. Nothing was exported.\n\n` +
        '  Verify:  secretless-ai secret list',
      );
    }
  }
  if (names.length === 0) {
    throw new Error('The secret store is empty. Nothing was exported.\n\n  Verify:  secretless-ai secret list');
  }

  const manifest = new Map((readManifest(options.projectDir ?? process.cwd()) ?? []).map((e) => [e.name, e]));
  const entries: BundleEntry[] = names.map((name) => {
    const entry: BundleEntry = { name, value: all[name] };
    const declared = manifest.get(name);
    if (declared) {
      entry.required = declared.required;
      if (declared.description) entry.description = declared.description;
    }
    return entry;
  });

  const content = await sealBundle(entries, passphrase, options.kdf);
  // `wx`: never replace a file, including one created since the check above.
  fs.writeFileSync(outPath, content, { mode: 0o600, flag: 'wx' });
  return { names, backendName: store.backendName };
}

export interface ImportBundleOptions extends SecretStoreOptions {
  /** Replace names that already exist in this machine's store. */
  force?: boolean;
}

export interface ImportBundleResult {
  entries: BundleEntry[];
  /** Names that existed before and were replaced (only with `force`). */
  replaced: string[];
  /** Names that did not read back with the imported value. Empty on success. */
  unresolved: string[];
  backendName: string;
}

/**
 * Decrypt a bundle and store its entries in this machine's backend.
 *
 * Every refusal — a wrong passphrase, a damaged file, a name or value the store
 * cannot hold, a name that already exists without `force` — happens before the
 * first write. After writing, each name is read back from the store and
 * compared with the bundle, so the result says whether the names resolve here,
 * not only that they were sent.
 */
export async function importBundle(
  bundlePath: string,
  passphrase: string,
  options: ImportBundleOptions = {},
): Promise<ImportBundleResult> {
  const size = fs.statSync(bundlePath).size;
  if (size > MAX_BUNDLE_BYTES) throw notABundle(`it is ${size} bytes, larger than any bundle export writes`);
  const entries = await openBundle(fs.readFileSync(bundlePath, 'utf-8'), passphrase);
  if (entries.length === 0) throw notABundle('it holds no secrets');

  const unstorable = entries
    .filter((e) => !isValidSecretName(e.name) || findSecretValueProblem(e.value) !== null)
    .map((e) => (isValidSecretName(e.name) ? e.name : '(an invalid name)'));
  if (unstorable.length > 0) {
    throw new Error(
      `The bundle holds entries this store cannot hold: ${unstorable.join(', ')}.\n\n` +
      '  Nothing was written.',
    );
  }

  const store = new SecretStore(options);
  const existing = new Set(await store.listSecrets());
  const replaced = entries.map((e) => e.name).filter((n) => existing.has(n));
  if (replaced.length > 0 && !options.force) {
    throw new Error(
      `Already in this machine's store: ${replaced.join(', ')}.\n\n` +
      '  Nothing was written.\n\n' +
      '  Fix:     secretless-ai import <bundle> --force   (replaces those names)',
    );
  }

  const written: string[] = [];
  for (const entry of entries) {
    try {
      await store.setSecret(entry.name, entry.value);
    } catch (err) {
      const rest = entries.map((e) => e.name).filter((n) => !written.includes(n));
      throw new Error(
        `Storing ${entry.name} failed: ${err instanceof Error ? err.message : String(err)}\n\n` +
        `  Stored: ${written.length > 0 ? written.join(', ') : 'none'}\n` +
        `  Not stored: ${rest.join(', ')}`,
      );
    }
    written.push(entry.name);
  }

  const unresolved: string[] = [];
  for (const entry of entries) {
    if ((await store.getSecret(entry.name)) !== entry.value) unresolved.push(entry.name);
  }
  return { entries, replaced, unresolved, backendName: store.backendName };
}
