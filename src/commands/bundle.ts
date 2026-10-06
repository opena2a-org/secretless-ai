import * as path from 'path';
import { exportBundle, importBundle } from '../bundle-transfer';
import { PASSPHRASE_ENV, BUNDLE_EXTENSION, type KdfParams } from '../bundle';
import { detectAgentRuntime } from '../env';
import { EXIT_USAGE } from '../argv';
import type { SecretStoreOptions } from '../secret-store';
import { CLI } from './utils';

/**
 * Where a passphrase comes from. Never an argument: an argument is visible in
 * the process list and saved in shell history. `confirm` asks twice, for export,
 * where a typo would otherwise seal the bundle under a passphrase nobody knows.
 */
export type PassphraseReader = (confirm: boolean) => Promise<string | null>;

export interface BundleCommandDeps {
  env?: NodeJS.ProcessEnv;
  readPassphrase?: PassphraseReader;
  /** For tests: a cheaper scrypt cost. */
  kdf?: KdfParams;
  /** For tests: the store to read from or write to. */
  storeOptions?: SecretStoreOptions;
}

/** Read one line from the terminal without echoing it. Null when cancelled. */
function readHiddenLine(prompt: string): Promise<string | null> {
  return new Promise((resolve) => {
    const stdin = process.stdin;
    process.stderr.write(prompt);
    stdin.setRawMode(true);
    stdin.setEncoding('utf-8');
    stdin.resume();
    let input = '';
    const finish = (value: string | null): void => {
      stdin.removeListener('data', onData);
      stdin.setRawMode(false);
      stdin.pause();
      process.stderr.write('\n');
      resolve(value);
    };
    const onData = (chunk: string): void => {
      for (const ch of chunk) {
        if (ch === '\r' || ch === '\n') return finish(input);
        // Raw mode delivers Ctrl-C and Ctrl-D as bytes instead of signals.
        if (ch === '\u0003' || ch === '\u0004') return finish(null);
        if (ch === '\u007f' || ch === '\b') {
          input = Array.from(input).slice(0, -1).join('');
          continue;
        }
        input += ch;
      }
    };
    stdin.on('data', onData);
  });
}

function passphraseReader(env: NodeJS.ProcessEnv): PassphraseReader {
  return async (confirm) => {
    const fromEnv = env[PASSPHRASE_ENV];
    if (fromEnv) return fromEnv;
    if (!process.stdin.isTTY) return null;
    const first = await readHiddenLine('  Bundle passphrase: ');
    if (first === null || !confirm) return first;
    const second = await readHiddenLine('  Repeat passphrase: ');
    if (second === null) return null;
    if (second !== first) throw new Error('The two passphrases differ. Nothing was exported.');
    return first;
  };
}

const NO_PASSPHRASE = [
  `  No passphrase. Run this in a terminal to be prompted, or set ${PASSPHRASE_ENV}.`,
  '  A passphrase is never accepted as an argument.',
];

function reportError(err: unknown): void {
  const message = err instanceof Error ? err.message : String(err);
  console.error(`\n  ${message.split('\n').join('\n  ')}\n`);
}

/** Value of a flag that takes one, or undefined when absent. */
function flagValue(args: string[], flag: string): string | undefined {
  const i = args.indexOf(flag);
  return i === -1 ? undefined : args[i + 1];
}

export async function runExport(args: string[], deps: BundleCommandDeps = {}): Promise<number> {
  const env = deps.env ?? process.env;
  const usage = `  Usage: ${CLI} export --out <file>${BUNDLE_EXTENSION} [--only KEY1,KEY2]`;

  // Same gate as `env`, for the same reason: an agent that can run export with
  // a passphrase it chose can decrypt the bundle and read every value.
  const agentRuntime = detectAgentRuntime(env);
  if (agentRuntime) {
    console.error(`\n  Refused: export writes every selected secret to a file whose passphrase the caller chooses.`);
    console.error(`  An AI agent runtime is set (${agentRuntime}). Run export from your own terminal.\n`);
    return 1;
  }

  const out = flagValue(args, '--out');
  const onlyRaw = flagValue(args, '--only');
  const stray = args.filter((a, i) => {
    const prev = args[i - 1];
    return a !== '--out' && a !== '--only' && prev !== '--out' && prev !== '--only';
  });
  if (out === undefined || out.startsWith('-') || stray.length > 0) {
    if (stray.length > 0) console.error(`\n  Unexpected argument: ${stray[0]}`);
    console.error(`\n${usage}\n`);
    return EXIT_USAGE;
  }
  // `--only ''` is the flag with an empty value, not the flag absent (#110).
  const only = onlyRaw === undefined ? undefined : onlyRaw.split(',').map((s) => s.trim()).filter(Boolean);

  console.log('\n  Secretless Export\n');
  const outPath = path.resolve(out);
  try {
    const passphrase = await (deps.readPassphrase ?? passphraseReader(env))(true);
    if (passphrase === null) {
      for (const line of NO_PASSPHRASE) console.error(line);
      console.error('  Nothing was exported.\n');
      return 1;
    }
    const result = await exportBundle(outPath, passphrase, { ...deps.storeOptions, only, kdf: deps.kdf });
    console.log(`  Exported ${result.names.length} secret(s) from ${result.backendName} to ${outPath}:\n`);
    for (const name of result.names) console.log(`    + ${name}`);
    console.log('\n  The file is encrypted with your passphrase. On the other machine run:');
    console.log(`    ${CLI} import ${path.basename(outPath)}`);
    console.log('  Then delete the bundle from both machines.\n');
    return 0;
  } catch (err) {
    reportError(err);
    return 1;
  }
}

/**
 * `import <bundle>`. Reached from `runImport` once the file is known to be a
 * bundle; the `.env` path there is unchanged.
 */
export async function runBundleImport(
  bundlePath: string,
  force: boolean,
  deps: BundleCommandDeps = {},
): Promise<number> {
  const env = deps.env ?? process.env;
  try {
    const passphrase = await (deps.readPassphrase ?? passphraseReader(env))(false);
    if (passphrase === null) {
      for (const line of NO_PASSPHRASE) console.error(line);
      console.error('  Nothing was written.\n');
      return 1;
    }
    const result = await importBundle(bundlePath, passphrase, { ...deps.storeOptions, force });
    const replaced = new Set(result.replaced);
    console.log(`  Imported ${result.entries.length} secret(s) from ${path.basename(bundlePath)} into ${result.backendName}:\n`);
    for (const entry of result.entries) {
      const notes: string[] = [];
      if (replaced.has(entry.name)) notes.push('replaced');
      if (entry.required !== undefined) notes.push(entry.required ? 'required' : 'optional');
      if (entry.description) notes.push(entry.description.replace(/[\u0000-\u001f\u007f]/g, ' '));
      console.log(`    + ${entry.name}${notes.length > 0 ? `   (${notes.join(', ')})` : ''}`);
    }
    if (result.unresolved.length > 0) {
      console.error(`\n  These names do not read back from ${result.backendName} with the imported value: ${result.unresolved.join(', ')}`);
      console.error(`  Verify:  ${CLI} secret list\n`);
      return 1;
    }
    console.log(`\n  All ${result.entries.length} resolve from this machine's store with the exported values.`);
    console.log(`  Delete ${path.basename(bundlePath)} now that it is imported.\n`);
    return 0;
  } catch (err) {
    reportError(err);
    return 1;
  }
}
