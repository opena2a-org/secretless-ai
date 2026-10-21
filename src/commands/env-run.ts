import * as path from 'path';
import { runWithSecrets } from '../run';
import { importEnvFile, detectEnvFiles } from '../env-import';
import { runSetup } from '../setup';
import { printCommandHelp } from '../command-help';
import { generateEnvExports, detectAgentRuntime } from '../env';
import { formatCommandError } from './utils';
import { isBundleFile } from '../bundle';
import { EXIT_USAGE } from '../argv';
import { escapeForDisplay } from '../display-safe';
import type { SelectableBackendType } from '../backends/config';
import { runBundleImport, type BundleCommandDeps } from './bundle';

export async function runRun(args: string[]): Promise<number> {
  // Parse --only flag before --
  let only: string[] | undefined;
  const separatorIdx = args.indexOf('--');

  // Check for --only before the separator
  const searchEnd = separatorIdx !== -1 ? separatorIdx : args.length;
  for (let i = 0; i < searchEnd; i++) {
    // `args[i + 1] !== undefined`, not a truthiness test: `--only ''` is the
    // flag WITH an empty value, and treating it as "flag absent" injected the
    // whole store and exited 0, while the equivalent `--only ,,` failed closed.
    // Same input, opposite fail direction (#110).
    if (args[i] === '--only' && args[i + 1] !== undefined) {
      only = args[i + 1].split(',').map(s => s.trim()).filter(Boolean);
      break;
    }
  }

  // Only before the separator: after it, `--allow-argv` is the child's own token.
  const allowArgv = args.slice(0, searchEnd).includes('--allow-argv');

  // Everything after -- is the child command. Without one, the usage is
  // printed and nothing runs: EXIT_USAGE, as for an unknown flag (#127).
  if (separatorIdx === -1 || separatorIdx >= args.length - 1) {
    console.error('\n  Usage: secretless-ai run [--only KEY1,KEY2] [--allow-argv] -- <command> [args...]\n');
    return EXIT_USAGE;
  }

  const childCommand = args[separatorIdx + 1];
  const childArgs = args.slice(separatorIdx + 2);

  try {
    return await runWithSecrets(childCommand, childArgs, { only, ...(allowArgv ? { allowArgv } : {}) });
  } catch (err) {
    // The same printer as the top-level handler in cli.ts and `secret`, so a
    // store error reads the same whichever command reached the store.
    console.error(formatCommandError(err));
    return 1;
  }
}

export async function runEnv(args: string[]): Promise<number> {
  // The layout every other command's help has (command-help.ts). Still
  // answered here, before anything is read, as OWN_HELP says.
  if (args.includes('--help') || args.includes('-h')) {
    printCommandHelp('env');
    return 0;
  }

  // Refuse inside a detected AI-agent runtime. `env` dumps every stored secret
  // as plaintext exports; the only legitimate caller is the shell-profile eval
  // hook, which runs in the user's own shell (no agent marker set), not the
  // agent. This check is on the runtime, not the command string, so it holds
  // however the agent spells the invocation (npx, quotes, a shell variable, a
  // tab) — all of which slip past the deny-glob and guard-hook layers. Emit
  // nothing to stdout; the eval hook's `2>/dev/null` keeps the user's shell
  // startup silent and unbroken, while a direct agent call sees the guidance.
  const agentRuntime = detectAgentRuntime();
  if (agentRuntime) {
    process.stderr.write(`\n  Refused: 'secretless-ai env' exports every stored secret as plaintext.\n`);
    process.stderr.write(`  An AI agent runtime is set (${agentRuntime}), so this output would enter the agent's context.\n\n`);
    process.stderr.write(`  Inject a specific secret into one command instead:\n`);
    process.stderr.write(`    secretless-ai run --only NAME -- <command>\n\n`);
    return 1;
  }

  // Parse --only flag
  let only: string[] | undefined;
  for (let i = 0; i < args.length; i++) {
    // `args[i + 1] !== undefined`, not a truthiness test: `--only ''` is the
    // flag WITH an empty value, and treating it as "flag absent" injected the
    // whole store and exited 0, while the equivalent `--only ,,` failed closed.
    // Same input, opposite fail direction (#110).
    if (args[i] === '--only' && args[i + 1] !== undefined) {
      only = args[i + 1].split(',').map(s => s.trim()).filter(Boolean);
      break;
    }
  }

  // Warn if outputting to an interactive terminal (not piped/eval)
  if (process.stdout.isTTY) {
    process.stderr.write('  Warning: This command outputs secret values.\n');
    process.stderr.write('  Intended usage: eval $(secretless-ai env)\n\n');
  }

  try {
    const output = await generateEnvExports({ only });
    if (output) {
      process.stdout.write(output + '\n');
    }
    return 0;
  } catch (err) {
    // Silently fail — this runs inside eval in shell profiles.
    process.stderr.write(`secretless: env: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

export async function runImport(args: string[], deps?: BundleCommandDeps): Promise<number> {
  console.log('\n  Secretless Import\n');

  // `--force` belongs to the bundle path only. The .env path has always
  // replaced existing names, so accepting the flag there would honour nothing.
  const force = args.includes('--force');
  const positional = args.filter((a) => a !== '--force');
  const bundleArg = positional[0];
  const exists = !!bundleArg && !bundleArg.startsWith('-')
    && (require('fs') as typeof import('fs')).existsSync(path.resolve(bundleArg));
  if (exists && isBundleFile(path.resolve(bundleArg))) {
    return runBundleImport(path.resolve(bundleArg), force, deps);
  }
  // A missing file falls through to "File not found" below, which is the answer.
  if (force && (exists || args.includes('--detect'))) {
    console.error('  --force applies only to an encrypted bundle from `export`.');
    console.error('  A .env import already replaces names that exist. Nothing was imported.\n');
    return EXIT_USAGE;
  }

  if (args.includes('--detect')) {
    const dir = process.cwd();
    const files = detectEnvFiles(dir);
    if (files.length === 0) {
      console.log('  No .env files found in current directory.\n');
      return 0;
    }

    let totalImported = 0;
    // Every file goes to the same store, so its project is named once (#177).
    let projectNamed = false;
    const beforeWrite = (projectNote: string): void => {
      if (projectNamed) return;
      projectNamed = true;
      console.log(`  ${projectNote}\n`);
    };
    for (const file of files) {
      try {
        const result = await importEnvFile(file, { beforeWrite });
        console.log(`  ${path.basename(file)}: ${result.imported} imported`);
        if (result.skipped > 0) {
          console.log(`    (${result.skipped} skipped — invalid names)`);
        }
        totalImported += result.imported;
      } catch (err) {
        console.error(`  Error importing ${file}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    console.log(`\n  Total: ${totalImported} secret(s) imported.\n`);
    return 0;
  }

  const filePath = positional[0];
  if (!filePath) {
    console.error('  Usage: secretless-ai import <file> or secretless-ai import --detect\n');
    return EXIT_USAGE;
  }

  const resolvedPath = path.resolve(filePath);
  const nodeFs = require('fs') as typeof import('fs');
  if (!nodeFs.existsSync(resolvedPath)) {
    console.error(`  File not found: ${filePath}`);
    console.error('  Check the path and try again.\n');
    return 1;
  }
  try {
    const result = await importEnvFile(resolvedPath, {
      // Named before the first write (#177).
      beforeWrite: (projectNote) => console.log(`  ${projectNote}\n`),
    });
    if (result.imported === 0) {
      console.log('  No secrets found in file.');
      console.log('  Expected format: KEY=value (one per line)\n');
      return 0;
    }

    console.log(`  Imported ${result.imported} secret(s) from ${path.basename(resolvedPath)}:\n`);
    for (const name of result.entries) {
      console.log(`    + ${name}`);
    }
    if (result.skipped > 0) {
      console.log(`\n  Skipped: ${result.skipped} (invalid names)`);
    }
    console.log();
    return 0;
  } catch (err) {
    console.error(`  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}

/** Backends `setup --backend` accepts: the ones `backend set` can select. */
const SETUP_BACKENDS = ['local', 'keychain', '1password', 'vault', 'gcp-sm'] as const satisfies readonly SelectableBackendType[];

/** A heading and one indented line per name; nothing for an empty list. */
function printSetupNames(heading: string, names: string[]): void {
  if (names.length === 0) return;
  console.log(`  ${heading}`);
  for (const name of names) console.log(`    - ${name}`);
  console.log();
}

export async function runSetupCommand(args: string[]): Promise<number> {
  // As for `env`: the shared layout, answered before the manifest is read.
  if (args.includes('--help') || args.includes('-h')) {
    printCommandHelp('setup');
    return 0;
  }

  const checkOnly = args.includes('--check');
  const dir = process.cwd();

  let backendType: SelectableBackendType | undefined;
  const backendIdx = args.indexOf('--backend');
  if (backendIdx !== -1) {
    const val = args[backendIdx + 1];
    if (!(SETUP_BACKENDS as readonly string[]).includes(val)) {
      console.error(`  Unknown backend type: ${val === undefined ? '(none)' : escapeForDisplay(val)}. Use ${SETUP_BACKENDS.map(b => `'${b}'`).join(', ')}.`);
      console.error('  `setup` was not run. Nothing was changed.\n');
      return EXIT_USAGE;
    }
    backendType = val as SelectableBackendType;
  }

  console.log('\n  Secretless Setup\n');

  try {
    const result = await runSetup(dir, { check: checkOnly, backendType, backendNamed: backendType !== undefined });

    // An unparseable manifest is not a store that is missing things. runSetup
    // already printed the offending lines and the expected format; a tally here
    // would be a count derived from input we could not read. Same reasoning as
    // the no-manifest case below (issue #97), applied to issue #112.
    if (result.manifestErrors && result.manifestErrors.length > 0) {
      console.log('  FAIL: .secretless could not be parsed. Nothing was checked.\n');
      return 1;
    }

    if (checkOnly || result.promptsSkipped) {
      // No manifest: runSetup already printed the create-a-manifest hint.
      // Rendering the satisfied/missing tally here would contradict it
      // ("Missing: 0 required" followed by FAIL — issue #97).
      if (!result.manifestFound) {
        console.log('  FAIL: No .secretless manifest to check against.\n');
        return 1;
      }
      const fromEnv = result.fromEnvironmentNames.length;
      if (result.store) console.log(`  Store:     ${escapeForDisplay(result.store)}`);
      console.log(`  Satisfied: ${result.existing + fromEnv} secret(s)${fromEnv > 0 ? ` (${fromEnv} from environment)` : ''}`);
      console.log(`  Missing:   ${result.missing} required`);
      console.log(`  Optional:  ${result.skipped} not set\n`);
      printSetupNames('From environment (not stored):', result.fromEnvironmentNames);

      if (!result.complete) {
        printSetupNames('Missing secrets:', result.missingNames);
        if (result.promptsSkipped) {
          console.log('  FAIL: Standard input is not a terminal, so setup did not prompt for them.');
          console.log('        Run `secretless-ai setup` in a terminal, or set them in the environment.\n');
          return 1;
        }
        console.log('  FAIL: Run `secretless-ai setup` to configure missing secrets.');
        console.log('        Or set them in the environment, as CI does.');
        console.log('        Or copy them from a shared backend: `secretless-ai secret sync --from <1password|vault|gcp-sm>`\n');
        return 1;
      }
      console.log('  PASS: All required secrets are configured.\n');
      return 0;
    }

    const fromEnv = result.fromEnvironmentNames.length;
    const tally = result.set > 0 || result.existing > 0 || fromEnv > 0;
    if (tally) {
      console.log(`\n  Set:      ${result.set} secret(s)`);
      console.log(`  Existing: ${result.existing}`);
      if (fromEnv > 0) console.log(`  From environment: ${fromEnv} (not stored)`);
      console.log(`  Skipped:  ${result.skipped} (optional)\n`);
    }
    if (!result.complete) {
      if (!tally) console.log();
      printSetupNames('Still missing (required):', result.missingNames);
      console.log('  FAIL: Run `secretless-ai setup` again and enter a value for each.\n');
      return 1;
    }
    return 0;
  } catch (err) {
    console.error(`  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}
