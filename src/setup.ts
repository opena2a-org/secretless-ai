/**
 * Interactive setup — prompts for missing secrets declared in .secretless manifest.
 *
 * When a developer clones a repo with a .secretless file, they run
 * `secretless-ai setup` and get prompted for each missing secret.
 */

import * as readline from 'readline';
import { readManifestDetailed, checkManifest, MANIFEST_FORMAT_HINT } from './manifest';
import type { ManifestEntry, ManifestError } from './manifest';
import { SecretStore } from './secret-store';
import type { SecretStoreOptions } from './secret-store';
import { repositoryProjectNote } from './backends/gcp-project';

export interface SetupOptions extends SecretStoreOptions {
  /** Check-only mode: exit 1 if required secrets are missing (for CI). */
  check?: boolean;
  /**
   * Whether a prompt can be answered. Defaults to whether stdin is a terminal.
   * When false, nothing is prompted for and setup reports like `check` (#330).
   */
  interactive?: boolean;
  /** Environment consulted for names not in the store. Defaults to process.env. */
  env?: NodeJS.ProcessEnv;
  /** Where answers are read from. Defaults to stdin. For DI/testing. */
  input?: NodeJS.ReadableStream;
}

export interface SetupResult {
  /** Whether a .secretless manifest was found. When false, the counts below
   *  are vacuous — callers must not render a satisfied/missing tally. */
  manifestFound: boolean;
  /** Number of secrets newly set during setup. */
  set: number;
  /** Number of secrets that already existed. */
  existing: number;
  /**
   * Names not in the store but set, non-empty, in the environment, as CI
   * provides them. They count as present; setup never stores them (#330).
   */
  fromEnvironmentNames: string[];
  /** Number of required secrets still missing. */
  missing: number;
  /** Names of missing required secrets. */
  missingNames: string[];
  /** Number of optional secrets skipped. */
  skipped: number;
  /** Whether all required secrets are satisfied. */
  complete: boolean;
  /** The store that was checked, named so a CI log shows which one it was. */
  store?: string;
  /** True when stdin is not a terminal, so nothing was prompted for. */
  promptsSkipped?: boolean;
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
      return { manifestFound: false, set: 0, existing: 0, fromEnvironmentNames: [], missing: 0, missingNames: [], skipped: 0, complete: false };
    }
    return { manifestFound: false, set: 0, existing: 0, fromEnvironmentNames: [], missing: 0, missingNames: [], skipped: 0, complete: true };
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
      fromEnvironmentNames: [],
      missing: 0,
      missingNames: [],
      skipped: 0,
      complete: false,
      manifestErrors: parsed.errors,
    };
  }

  const store = new SecretStore(options);
  const check = await checkManifest(dir, options);

  // CI passes secrets as environment variables, so a name set there is
  // present even though it is not stored. An empty value is not: an unset
  // GitHub Actions secret reaches the job as an empty string (#330).
  const env = options?.env ?? process.env;
  const inEnvironment = (name: string): boolean => typeof env[name] === 'string' && env[name] !== '';

  // Without a terminal, setup used to take its answers from standard input: a
  // line was stored as the secret whose prompt was open when it arrived (two
  // lines piped at once stored the first name only), and when the input ended
  // with a prompt unanswered, setup exited 0 without a summary, whatever was
  // still missing. It reads nothing from a pipe now and reports instead;
  // `secret set NAME` takes a piped value (#330).
  const interactive = options?.interactive ?? process.stdin.isTTY === true;
  if (options?.check || !interactive) {
    const missing = check.missing.filter(e => !inEnvironment(e.name));
    return {
      manifestFound: true,
      set: 0,
      existing: check.satisfied.length,
      fromEnvironmentNames: [...check.missing, ...check.optional].filter(e => inEnvironment(e.name)).map(e => e.name),
      missing: missing.length,
      missingNames: missing.map(e => e.name),
      skipped: check.optional.filter(e => !inEnvironment(e.name)).length,
      complete: missing.length === 0,
      store: store.backendName,
      promptsSkipped: !options?.check,
    };
  }

  // Interactive mode: prompt for missing secrets
  let setCount = 0;
  let skippedCount = 0;
  const fromEnvironmentNames: string[] = [];
  const missingNames: string[] = [];

  if (check.missing.length === 0 && check.optional.length === 0) {
    return {
      manifestFound: true,
      set: 0,
      existing: check.satisfied.length,
      fromEnvironmentNames: [],
      missing: 0,
      missingNames: [],
      skipped: 0,
      complete: true,
      store: store.backendName,
    };
  }

  // Named before the first prompt, so the user knows where each value they
  // type will be written before writing it (#177, #365). Prompts go to stderr too.
  process.stderr.write(`  Store: ${store.backendName}\n`);
  const projectNote = repositoryProjectNote(store.backendName);
  if (projectNote) process.stderr.write(`  ${projectNote}\n`);
  process.stderr.write('\n');

  const input = options?.input ?? process.stdin;
  const rl = readline.createInterface({
    input,
    output: process.stderr,
    terminal: input === process.stdin && process.stdin.isTTY === true,
  });

  // Input that ends (Ctrl-D) answers the open prompt and every later one with
  // nothing. Without this the pending question never resolves, nothing keeps
  // the process alive, and it exits 0 with the summary unprinted.
  let inputClosed = false;
  let pending: ((answer: string) => void) | null = null;
  rl.on('close', () => {
    inputClosed = true;
    const resolve = pending;
    pending = null;
    resolve?.('');
  });

  const askQuestion = (prompt: string): Promise<string> => {
    return new Promise((resolve) => {
      if (inputClosed) {
        resolve('');
        return;
      }
      pending = resolve;
      rl.question(prompt, (answer) => {
        pending = null;
        resolve(answer.trim());
      });
    });
  };

  const promptFor = (entry: ManifestEntry, hint: string): Promise<string> => {
    const desc = entry.description ? ` (${entry.description})` : '';
    const note = inEnvironment(entry.name) ? ' [set in the environment, press Enter to use it]' : hint;
    return askQuestion(`  ${entry.name}${desc}${note}: `);
  };

  try {
    // Prompt for required secrets
    for (const entry of check.missing) {
      const value = await promptFor(entry, '');
      if (value) {
        await store.setSecret(entry.name, value);
        setCount++;
      } else if (inEnvironment(entry.name)) {
        fromEnvironmentNames.push(entry.name);
      } else {
        missingNames.push(entry.name);
      }
    }

    // Prompt for optional secrets
    for (const entry of check.optional) {
      const value = await promptFor(entry, ' [optional, press Enter to skip]');
      if (value) {
        await store.setSecret(entry.name, value);
        setCount++;
      } else if (inEnvironment(entry.name)) {
        fromEnvironmentNames.push(entry.name);
      } else {
        skippedCount++;
      }
    }
  } finally {
    rl.close();
  }

  return {
    manifestFound: true,
    set: setCount,
    existing: check.satisfied.length,
    fromEnvironmentNames,
    missing: missingNames.length,
    missingNames,
    skipped: skippedCount,
    complete: missingNames.length === 0,
    store: store.backendName,
  };
}
