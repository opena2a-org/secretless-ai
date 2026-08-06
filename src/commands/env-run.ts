import * as path from 'path';
import { runWithSecrets } from '../run';
import { importEnvFile, detectEnvFiles } from '../env-import';
import { runSetup } from '../setup';
import { MANIFEST_FORMAT_HINT } from '../manifest';
import { generateEnvExports, detectAgentRuntime } from '../env';

export async function runRun(args: string[]): Promise<number> {
  // Parse --only flag before --
  let only: string[] | undefined;
  const separatorIdx = args.indexOf('--');

  // Check for --only before the separator
  const searchEnd = separatorIdx !== -1 ? separatorIdx : args.length;
  for (let i = 0; i < searchEnd; i++) {
    if (args[i] === '--only' && args[i + 1]) {
      only = args[i + 1].split(',').map(s => s.trim()).filter(Boolean);
      break;
    }
  }

  // Everything after -- is the child command
  if (separatorIdx === -1 || separatorIdx >= args.length - 1) {
    console.error('\n  Usage: secretless-ai run [--only KEY1,KEY2] -- <command> [args...]\n');
    return 1;
  }

  const childCommand = args[separatorIdx + 1];
  const childArgs = args.slice(separatorIdx + 2);

  try {
    return await runWithSecrets(childCommand, childArgs, { only });
  } catch (err) {
    // Indent every line, not just the first, matching the top-level handler in
    // cli.ts. Today's messages happen to indent their own continuation lines,
    // so this is not what saves the Verify/Fix block for them — it is what
    // keeps a message that does NOT self-indent from landing at column 0.
    const message = err instanceof Error ? err.message : String(err);
    console.error(`\n  ${message.split('\n').join('\n  ')}\n`);
    return 1;
  }
}

export async function runEnv(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log('\n  Usage: eval $(secretless-ai env [--only KEY1,KEY2])');
    console.log('\n  Export secrets as shell environment variables.');
    console.log('  Designed for use with eval in shell profiles.\n');
    console.log('  Options:');
    console.log('    --only KEY1,KEY2   Export only the specified secrets\n');
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
    if (args[i] === '--only' && args[i + 1]) {
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

export async function runImport(args: string[]): Promise<number> {
  console.log('\n  Secretless Import\n');

  if (args.includes('--detect')) {
    const dir = process.cwd();
    const files = detectEnvFiles(dir);
    if (files.length === 0) {
      console.log('  No .env files found in current directory.\n');
      return 0;
    }

    let totalImported = 0;
    for (const file of files) {
      try {
        const result = await importEnvFile(file);
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

  const filePath = args[0];
  if (!filePath) {
    console.error('  Usage: secretless-ai import <file> or secretless-ai import --detect\n');
    return 1;
  }

  const resolvedPath = path.resolve(filePath);
  const nodeFs = require('fs') as typeof import('fs');
  if (!nodeFs.existsSync(resolvedPath)) {
    console.error(`  File not found: ${filePath}`);
    console.error('  Check the path and try again.\n');
    return 1;
  }
  try {
    const result = await importEnvFile(resolvedPath);
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

export async function runSetupCommand(args: string[]): Promise<number> {
  if (args.includes('--help') || args.includes('-h')) {
    console.log('\n  Usage: secretless-ai setup [--check]');
    console.log('\n  Read .secretless and prompt for any declared secret not yet stored.');
    console.log('  --check verifies without prompting, for CI.\n');
    console.log('  ' + MANIFEST_FORMAT_HINT.split('\n').join('\n  ') + '\n');
    return 0;
  }

  const checkOnly = args.includes('--check');
  const dir = process.cwd();

  console.log('\n  Secretless Setup\n');

  try {
    const result = await runSetup(dir, { check: checkOnly });

    // An unparseable manifest is not a store that is missing things. runSetup
    // already printed the offending lines and the expected format; a tally here
    // would be a count derived from input we could not read. Same reasoning as
    // the no-manifest case below (issue #97), applied to issue #112.
    if (result.manifestErrors && result.manifestErrors.length > 0) {
      console.log('  FAIL: .secretless could not be parsed. Nothing was checked.\n');
      return 1;
    }

    if (checkOnly) {
      // No manifest: runSetup already printed the create-a-manifest hint.
      // Rendering the satisfied/missing tally here would contradict it
      // ("Missing: 0 required" followed by FAIL — issue #97).
      if (!result.manifestFound) {
        console.log('  FAIL: No .secretless manifest to check against.\n');
        return 1;
      }
      console.log(`  Satisfied: ${result.existing} secret(s)`);
      console.log(`  Missing:   ${result.missing} required`);
      console.log(`  Optional:  ${result.skipped} not set\n`);

      if (!result.complete) {
        console.log('  Missing secrets:');
        for (const name of result.missingNames) {
          console.log(`    - ${name}`);
        }
        console.log();
        console.log('  FAIL: Run `secretless-ai setup` to configure missing secrets.\n');
        return 1;
      }
      console.log('  PASS: All required secrets are configured.\n');
      return 0;
    }

    if (result.set > 0 || result.existing > 0) {
      console.log(`\n  Set:      ${result.set} secret(s)`);
      console.log(`  Existing: ${result.existing}`);
      console.log(`  Skipped:  ${result.skipped} (optional)\n`);
    }
    return 0;
  } catch (err) {
    console.error(`  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }
}
