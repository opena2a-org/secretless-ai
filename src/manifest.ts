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
import { SecretStore, isValidSecretName } from './secret-store';
import type { SecretStoreOptions } from './secret-store';

const MANIFEST_FILENAME = '.secretless';

export interface ManifestEntry {
  name: string;
  required: boolean;
  description: string;
}

/** A manifest line that cannot be a secret name. */
export interface ManifestError {
  /** 1-based line number in the manifest file. */
  line: number;
  /** The offending text, as written. */
  text: string;
  /** Why it cannot be a name. */
  reason: string;
}

export interface ParsedManifest {
  entries: ManifestEntry[];
  errors: ManifestError[];
}

/** The format, shown whenever a manifest fails to parse. */
export const MANIFEST_FORMAT_HINT = [
  'Expected one secret name per line, no wrapper:',
  '',
  '    GITHUB_TOKEN                 # required, GitHub API access',
  '    DATABASE_URL                 # required, PostgreSQL connection',
  '    STRIPE_SECRET_KEY  optional  # only needed for payments',
  '',
  "Names allow letters, digits, '-' and '_'. It is not YAML, JSON, or dotenv.",
].join('\n');

/**
 * Parse manifest content, separating usable entries from lines that cannot be
 * secret names.
 *
 * A line that fails validation is a MANIFEST error, not a missing secret. The
 * parser used to accept any first token, so a YAML-shaped guess
 * (`required:` / `- NAME`) was silently misread into names that do not exist
 * and then reported as a definite count of missing entries (#112). "Missing: 3
 * required" is a measurement, and it was measuring punctuation.
 */
export function parseManifestDetailed(content: string): ParsedManifest {
  const entries: ManifestEntry[] = [];
  const errors: ManifestError[] = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

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
    const tokens = beforeComment.split(/\s+/).filter(Boolean);
    const name = tokens[0];
    if (!name) continue;

    if (!isValidSecretName(name)) {
      errors.push({ line: i + 1, text: line, reason: describeInvalidName(name) });
      continue;
    }

    // A trailing token that is neither `optional` nor a comment means the line
    // is not the shape we think it is — accepting it would repeat the original
    // defect one token to the right.
    const extra = tokens.slice(1).filter((t) => t !== 'optional');
    if (extra.length > 0) {
      errors.push({
        line: i + 1,
        text: line,
        reason: `unexpected "${extra[0]}" after the name (only "optional" and a # comment may follow)`,
      });
      continue;
    }

    entries.push({
      name,
      required: !tokens.includes('optional'),
      description,
    });
  }

  return { entries, errors };
}

/** Human-readable reason a token cannot be a secret name. */
function describeInvalidName(name: string): string {
  const bad = [...new Set(name.split('').filter((c) => !isValidSecretName(c)))];
  if (bad.length > 0) {
    return `contains ${bad.map((c) => `"${c}"`).join(', ')} — names allow letters, digits, '-' and '_' only`;
  }
  return "not a valid secret name — letters, digits, '-' and '_' only";
}

/**
 * Parse manifest content into structured entries.
 *
 * Invalid lines are omitted rather than returned as names. Use
 * `parseManifestDetailed` when you need to report them.
 */
export function parseManifest(content: string): ManifestEntry[] {
  return parseManifestDetailed(content).entries;
}

/**
 * Read and parse the .secretless manifest from a directory, keeping any
 * unparseable lines. Returns null if no manifest file exists.
 */
export function readManifestDetailed(dir: string): ParsedManifest | null {
  const manifestPath = path.join(dir, MANIFEST_FILENAME);
  if (!fs.existsSync(manifestPath)) return null;

  const content = fs.readFileSync(manifestPath, 'utf-8');
  return parseManifestDetailed(content);
}

/**
 * Read and parse the .secretless manifest from a directory.
 * Returns null if no manifest file exists.
 */
export function readManifest(dir: string): ManifestEntry[] | null {
  return readManifestDetailed(dir)?.entries ?? null;
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
