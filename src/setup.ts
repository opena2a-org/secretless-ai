/**
 * Interactive setup — prompts for missing secrets declared in .secretless manifest.
 *
 * When a developer clones a repo with a .secretless file, they run
 * `secretless-ai setup` and get prompted for each missing secret.
 */

import * as readline from 'readline';
import { readManifestDetailed, checkManifest, MANIFEST_FORMAT_HINT } from './manifest';
import type { ManifestError } from './manifest';
import { SecretStore } from './secret-store';
import type { SecretStoreOptions } from './secret-store';

export interface SetupOptions extends SecretStoreOptions {
  /** Check-only mode: exit 1 if required secrets are missing (for CI). */
  check?: boolean;
}

export interface SetupResult {
  /** Whether a .secretless manifest was found. When false, the counts below
   *  are vacuous — callers must not render a satisfied/missing tally. */
  manifestFound: boolean;
  /** Number of secrets newly set during setup. */
  set: number;
  /** Number of secrets that already existed. */
  existing: number;
  /** Number of required secrets still missing. */
  missing: number;
  /** Names of missing required secrets. */
  missingNames: string[];
  /** Number of optional secrets skipped. */
  skipped: number;
  /** Whether all required secrets are satisfied. */
  complete: boolean;
  /**
   * Lines of `.secretless` that are not secret names. When present the counts
   * above are vacuous — the manifest was not understood, so nothing was
   * checked. Callers must not render a satisfied/missing tally.
   */
  manifestErrors?: ManifestError[];
}

/**
 * Run the interactive setup flow.
 *
 * Reads .secretless manifest, checks which secrets are missing,
 * and prompts the user for each one.
 */
export async function runSetup(
  dir: string,
  options?: SetupOptions,
): Promise<SetupResult> {
  const parsed = readManifestDetailed(dir);
  if (!parsed) {
    process.stderr.write('  No .secretless manifest found in this directory.\n');
    process.stderr.write('  Create a .secretless file with one secret name per line:\n');
    process.stderr.write('    ANTHROPIC_API_KEY\n');
    process.stderr.write('    DATABASE_URL\n');
    // In check mode, missing manifest is a failure (nothing to verify against)
    if (options?.check) {
      return { manifestFound: false, set: 0, existing: 0, missing: 0, missingNames: [], skipped: 0, complete: false };
    }
    return { manifestFound: false, set: 0, existing: 0, missing: 0, missingNames: [], skipped: 0, complete: true };
  }

  // A manifest we cannot parse is a manifest error, not a store that is missing
  // things. Reporting a count derived from unparseable input is a confident
  // wrong answer, and in CI it is a red build pointing at the wrong file (#112).
  if (parsed.errors.length > 0) {
    process.stderr.write('\n  .secretless could not be parsed.\n\n');
    for (const e of parsed.errors) {
      process.stderr.write(`    line ${e.line}: ${e.text}\n`);
      process.stderr.write(`             ${e.reason}\n`);
    }
    process.stderr.write('\n  ' + MANIFEST_FORMAT_HINT.split('\n').join('\n  ') + '\n\n');
    process.stderr.write('  No secrets were checked, because the file does not say which to check.\n\n');
    return {
      manifestFound: true,
      set: 0,
      existing: 0,
      missing: 0,
      missingNames: [],
      skipped: 0,
      complete: false,
      manifestErrors: parsed.errors,
    };
  }

  const check = await checkManifest(dir, options);

  // Check-only mode: report and exit
  if (options?.check) {
    return {
      manifestFound: true,
      set: 0,
      existing: check.satisfied.length,
      missing: check.missing.length,
      missingNames: check.missing.map(e => e.name),
      skipped: check.optional.length,
      complete: check.missing.length === 0,
    };
  }

  // Interactive mode: prompt for missing secrets
  const store = new SecretStore(options);
  let setCount = 0;
  let skippedCount = check.optional.length;

  if (check.missing.length === 0 && check.optional.length === 0) {
    return {
      manifestFound: true,
      set: 0,
      existing: check.satisfied.length,
      missing: 0,
      missingNames: [],
      skipped: 0,
      complete: true,
    };
  }

  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
    terminal: process.stdin.isTTY === true,
  });

  const askQuestion = (prompt: string): Promise<string> => {
    return new Promise((resolve) => {
      rl.question(prompt, (answer) => resolve(answer.trim()));
    });
  };

  try {
    // Prompt for required secrets
    for (const entry of check.missing) {
      const desc = entry.description ? ` (${entry.description})` : '';
      const value = await askQuestion(`  ${entry.name}${desc}: `);
      if (value) {
        await store.setSecret(entry.name, value);
        setCount++;
      }
    }

    // Prompt for optional secrets
    for (const entry of check.optional) {
      const desc = entry.description ? ` (${entry.description})` : '';
      const value = await askQuestion(`  ${entry.name}${desc} [optional, press Enter to skip]: `);
      if (value) {
        await store.setSecret(entry.name, value);
        setCount++;
        skippedCount--;
      }
    }
  } finally {
    rl.close();
  }

  return {
    manifestFound: true,
    set: setCount,
    existing: check.satisfied.length,
    missing: 0,
    missingNames: [],
    skipped: skippedCount,
    complete: true,
  };
}
