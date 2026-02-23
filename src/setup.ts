/**
 * Interactive setup — prompts for missing secrets declared in .secretless manifest.
 *
 * When a developer clones a repo with a .secretless file, they run
 * `secretless-ai setup` and get prompted for each missing secret.
 */

import * as readline from 'readline';
import { readManifest, checkManifest } from './manifest';
import { SecretStore } from './secret-store';
import type { SecretStoreOptions } from './secret-store';

export interface SetupOptions extends SecretStoreOptions {
  /** Check-only mode: exit 1 if required secrets are missing (for CI). */
  check?: boolean;
}

export interface SetupResult {
  /** Number of secrets newly set during setup. */
  set: number;
  /** Number of secrets that already existed. */
  existing: number;
  /** Number of optional secrets skipped. */
  skipped: number;
  /** Whether all required secrets are satisfied. */
  complete: boolean;
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
  const entries = readManifest(dir);
  if (!entries) {
    process.stderr.write('  No .secretless manifest found in this directory.\n');
    process.stderr.write('  Create a .secretless file listing required secret names.\n');
    return { set: 0, existing: 0, skipped: 0, complete: true };
  }

  const check = await checkManifest(dir, options);

  // Check-only mode: report and exit
  if (options?.check) {
    return {
      set: 0,
      existing: check.satisfied.length,
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
      set: 0,
      existing: check.satisfied.length,
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
    set: setCount,
    existing: check.satisfied.length,
    skipped: skippedCount,
    complete: true,
  };
}
