/**
 * Project manifest (.secretless) — declares required secrets for a project.
 *
 * Replaces .env.example. Contains secret names and metadata (no values),
 * safe to commit to version control.
 *
 * Format:
 *   GITHUB_TOKEN                    # required, GitHub API access
 *   DATABASE_URL                    # required, PostgreSQL connection
 *   STRIPE_SECRET_KEY  optional     # only needed for payments
 *   # Lines starting with # are comments
 */

import * as fs from 'fs';
import * as path from 'path';
import { SecretStore } from './secret-store';
import type { SecretStoreOptions } from './secret-store';

const MANIFEST_FILENAME = '.secretless';

export interface ManifestEntry {
  name: string;
  required: boolean;
  description: string;
}

/**
 * Parse manifest content into structured entries.
 */
export function parseManifest(content: string): ManifestEntry[] {
  const entries: ManifestEntry[] = [];
  const lines = content.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();

    // Skip empty lines and full-line comments
    if (!line || line.startsWith('#')) continue;

    // Extract inline comment as description
    let description = '';
    const commentIdx = line.indexOf('#');
    const beforeComment = commentIdx !== -1 ? line.slice(0, commentIdx).trim() : line;
    if (commentIdx !== -1) {
      description = line.slice(commentIdx + 1).trim();
    }

    // Parse tokens: NAME [optional]
    const tokens = beforeComment.split(/\s+/);
    const name = tokens[0];
    if (!name) continue;

    const isOptional = tokens.includes('optional');

    entries.push({
      name,
      required: !isOptional,
      description,
    });
  }

  return entries;
}

/**
 * Read and parse the .secretless manifest from a directory.
 * Returns null if no manifest file exists.
 */
export function readManifest(dir: string): ManifestEntry[] | null {
  const manifestPath = path.join(dir, MANIFEST_FILENAME);
  if (!fs.existsSync(manifestPath)) return null;

  const content = fs.readFileSync(manifestPath, 'utf-8');
  return parseManifest(content);
}

export interface ManifestCheck {
  /** Required secrets that are missing from the store. */
  missing: ManifestEntry[];
  /** Optional secrets that are missing from the store. */
  optional: ManifestEntry[];
  /** Secrets that are already stored. */
  satisfied: ManifestEntry[];
}

/**
 * Check manifest entries against stored secrets.
 */
export async function checkManifest(
  dir: string,
  options?: SecretStoreOptions,
): Promise<ManifestCheck> {
  const entries = readManifest(dir);
  if (!entries) {
    return { missing: [], optional: [], satisfied: [] };
  }

  const store = new SecretStore(options);
  const storedNames = await store.listSecrets();
  const storedSet = new Set(storedNames);

  const missing: ManifestEntry[] = [];
  const optional: ManifestEntry[] = [];
  const satisfied: ManifestEntry[] = [];

  for (const entry of entries) {
    if (storedSet.has(entry.name)) {
      satisfied.push(entry);
    } else if (entry.required) {
      missing.push(entry);
    } else {
      optional.push(entry);
    }
  }

  return { missing, optional, satisfied };
}
