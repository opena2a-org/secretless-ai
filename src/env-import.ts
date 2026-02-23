/**
 * .env file importer — parse and import secrets from .env files.
 *
 * Supports KEY=VALUE, quoted values, comments, blank lines, and `export` prefix.
 * Does NOT expand $VAR references (keep it simple).
 */

import * as fs from 'fs';
import * as path from 'path';
import { SecretStore } from './secret-store';
import type { SecretStoreOptions } from './secret-store';

/** Known .env file names to auto-detect. */
const ENV_FILE_NAMES = [
  '.env',
  '.env.local',
  '.env.development',
  '.env.production',
  '.env.staging',
];

export interface EnvEntry {
  name: string;
  value: string;
}

/**
 * Parse a .env file content into key-value pairs.
 *
 * Handles:
 * - KEY=VALUE (basic)
 * - KEY="VALUE" and KEY='VALUE' (strips quotes)
 * - # comments and blank lines (skipped)
 * - export KEY=VALUE (strips export prefix)
 * - Does NOT expand $VAR references
 */
export function parseEnvFile(content: string): EnvEntry[] {
  const entries: EnvEntry[] = [];
  const lines = content.split('\n');

  for (const rawLine of lines) {
    const line = rawLine.trim();

    // Skip empty lines and comments
    if (!line || line.startsWith('#')) continue;

    // Strip optional 'export ' prefix
    const stripped = line.startsWith('export ')
      ? line.slice(7).trim()
      : line;

    // Find first = sign
    const eqIdx = stripped.indexOf('=');
    if (eqIdx === -1) continue;

    const name = stripped.slice(0, eqIdx).trim();
    if (!name) continue;

    let value = stripped.slice(eqIdx + 1).trim();

    // Strip surrounding quotes
    if (
      (value.startsWith('"') && value.endsWith('"')) ||
      (value.startsWith("'") && value.endsWith("'"))
    ) {
      value = value.slice(1, -1);
    }

    // Strip inline comment (only for unquoted values)
    // For quoted values, the comment would be inside the quotes if present
    if (!stripped.slice(eqIdx + 1).trim().startsWith('"') &&
        !stripped.slice(eqIdx + 1).trim().startsWith("'")) {
      const commentIdx = value.indexOf(' #');
      if (commentIdx !== -1) {
        value = value.slice(0, commentIdx).trim();
      }
    }

    entries.push({ name, value });
  }

  return entries;
}

export interface ImportResult {
  imported: number;
  skipped: number;
  entries: string[];
}

/**
 * Import secrets from a .env file into the secret store.
 */
export async function importEnvFile(
  filePath: string,
  options?: SecretStoreOptions,
): Promise<ImportResult> {
  const content = fs.readFileSync(filePath, 'utf-8');
  const entries = parseEnvFile(content);
  const store = new SecretStore(options);

  let imported = 0;
  let skipped = 0;
  const names: string[] = [];

  for (const entry of entries) {
    // Validate name is safe for storage
    if (!/^[a-zA-Z0-9_-]+$/.test(entry.name)) {
      skipped++;
      continue;
    }

    await store.setSecret(entry.name, entry.value);
    imported++;
    names.push(entry.name);
  }

  return { imported, skipped, entries: names };
}

/**
 * Detect .env files in the given directory.
 * Returns absolute paths to existing .env files.
 */
export function detectEnvFiles(dir: string): string[] {
  const found: string[] = [];
  for (const name of ENV_FILE_NAMES) {
    const fullPath = path.join(dir, name);
    if (fs.existsSync(fullPath)) {
      found.push(fullPath);
    }
  }
  return found;
}
