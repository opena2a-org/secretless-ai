import * as path from 'path';
import { SecretStore } from '../secret-store';
import { runWithSecrets } from '../run';
import { importEnvFile, detectEnvFiles } from '../env-import';
import { runSetup } from '../setup';
import { generateEnvExports, getShellHookLine, SHELL_HOOK_MARKER } from '../env';

/**
 * Ensure the shell profile has the eval hook for auto-loading secrets.
 * Called after `secret set` to make stored secrets available as env vars.
 */
function ensureShellHook(): void {
  const os = require('os');
  const fs = require('fs');

  const home = os.homedir();
  const shell = process.env.SHELL ?? '';
  const platform = os.platform();

  // Determine the right profile to modify
  let profilePath: string;
  if (platform === 'darwin' || shell.endsWith('/zsh')) {
    profilePath = path.join(home, '.zshenv');
  } else {
    profilePath = path.join(home, '.bashrc');
  }

  // Check if hook already exists
  let existing = '';
  try {
    existing = fs.readFileSync(profilePath, 'utf-8');
  } catch {
    // File doesn't exist — will create it
  }

  if (existing.includes(SHELL_HOOK_MARKER) || existing.includes('secretless-ai env')) {
    return; // Already installed
  }

  // Append the hook
  const hookLine = getShellHookLine();
  const block = `\n${SHELL_HOOK_MARKER}\n${hookLine}\n`;
  fs.writeFileSync(profilePath, existing + block);

  const profileName = path.basename(profilePath);
  console.log(`  Shell hook installed in ~/${profileName}`);
  console.log(`  Run: source ~/${profileName}   (or open a new terminal)`);
}

export function runSecret(args: string[]): void {
  const subcommand = args[0];

  switch (subcommand) {
    case 'set': {
      const nameArg = args[1];
      if (!nameArg) {
        console.error('\n  Usage: secretless-ai secret set <NAME[=VALUE]>\n');
        process.exit(1);
      }

      // Validate secret name format
      const SECRET_NAME_RE = /^[a-zA-Z][a-zA-Z0-9_-]*$/;

      // Check for inline value: NAME=VALUE
      const eqIdx = nameArg.indexOf('=');
      if (eqIdx !== -1) {
        const name = nameArg.slice(0, eqIdx);
        const value = nameArg.slice(eqIdx + 1);
        if (!value) {
          console.error('  Error: no value provided.');
          console.error('  Usage: secretless-ai secret set NAME=VALUE\n');
          process.exit(1);
        }
        if (!SECRET_NAME_RE.test(name)) {
          console.error('  Error: Invalid secret name. Use letters, numbers, underscores, hyphens. Must start with a letter.\n');
          process.exit(1);
        }
        const store = new SecretStore();
        store.setSecret(name, value).then(() => {
          console.log(`  Stored: ${name}`);
          ensureShellHook();
        }).catch((err) => {
          console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
          process.exit(1);
        });
        return;
      }

      // Read value from stdin
      const name = nameArg;
      if (!SECRET_NAME_RE.test(name)) {
        console.error('  Error: Invalid secret name. Use letters, numbers, underscores, hyphens. Must start with a letter.\n');
        process.exit(1);
      }

      let input = '';
      process.stdin.setEncoding('utf-8');

      if (process.stdin.isTTY) {
        process.stderr.write(`  Enter value for ${name}: `);
      }

      process.stdin.on('data', (chunk) => {
        input += chunk;
        // In TTY mode, each Enter press delivers a line — store immediately.
        // In piped mode, we may get multiple chunks, but the first is usually all.
        if (process.stdin.isTTY) {
          const value = input.trim();
          if (!value) {
            console.error('  Error: no value provided.');
            console.error('  Usage: secretless-ai secret set NAME=VALUE');
            console.error('  Or:    echo "value" | secretless-ai secret set NAME\n');
            process.exit(1);
          }
          const store = new SecretStore();
          store.setSecret(name, value).then(() => {
            console.log(`  Stored: ${name}`);
            ensureShellHook();
            process.exit(0);
          }).catch((err) => {
            console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
            process.exit(1);
          });
        }
      });

      // Piped mode: wait for stdin to close, then store
      process.stdin.on('end', () => {
        const value = input.trim();
        if (!value) {
          console.error('  Error: no value provided.');
          console.error('  Usage: secretless-ai secret set NAME=VALUE');
          console.error('  Or:    echo "value" | secretless-ai secret set NAME\n');
          process.exit(1);
        }
        const store = new SecretStore();
        store.setSecret(name, value).then(() => {
          console.log(`  Stored: ${name}`);
          ensureShellHook();
          process.exit(0);
        }).catch((err) => {
          console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
          process.exit(1);
        });
      });
      break;
    }

    case 'list': {
      const store = new SecretStore();
      store.listSecrets().then((names) => {
        if (names.length === 0) {
          console.log('\n  No secrets stored.');
          console.log('  Store one:    npx secretless-ai secret set MY_KEY=my_value');
          console.log('  Import .env:  npx secretless-ai import .env\n');
          return;
        }
        console.log(`\n  ${names.length} secret(s):\n`);
        for (const name of names) {
          console.log(`    ${name}`);
        }
        console.log();
      }).catch((err) => {
        console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      });
      break;
    }

    case 'get': {
      const positional = args.slice(1).filter(a => !a.startsWith('--'));
      const name = positional[0];
      if (!name) {
        console.error('\n  Usage: secretless-ai secret get <NAME>\n');
        process.exit(1);
      }

      // Block output in non-interactive contexts (AI tools capture stdout).
      if (!process.stdout.isTTY && !args.includes('--force')) {
        console.error('  secretless: Blocked -- secret values cannot be read in non-interactive contexts.');
        console.error('  AI tools capture stdout, which would expose the secret in their context.');
        console.error('');
        console.error('  To inject secrets into a command:');
        console.error('    npx secretless-ai run -- <command>');
        console.error('');
        console.error('  To force output (e.g. piping to clipboard):');
        console.error('    npx secretless-ai secret get <NAME> --force');
        process.exit(1);
      }

      const store = new SecretStore();
      store.getSecret(name).then((value) => {
        if (value === undefined) {
          console.error(`  Secret not found: ${name}`);
          process.exit(1);
        }
        process.stdout.write(value);
        // Add newline if stdout is a terminal
        if (process.stdout.isTTY) {
          process.stdout.write('\n');
        }
      }).catch((err) => {
        console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      });
      break;
    }

    case 'rm':
    case 'remove':
    case 'delete': {
      const name = args[1];
      if (!name) {
        console.error('\n  Usage: secretless-ai secret rm <NAME>\n');
        process.exit(1);
      }
      const store = new SecretStore();
      store.removeSecret(name).then((removed) => {
        if (removed) {
          console.log(`  Removed: ${name}`);
        } else {
          console.error(`  Secret not found: ${name}`);
          process.exit(1);
        }
      }).catch((err) => {
        console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
        process.exit(1);
      });
      break;
    }

    default:
      console.error(`\n  Unknown secret command: ${subcommand ?? '(none)'}`);
      console.log('  Usage: secretless-ai secret <set|list|get|rm> [args]\n');
      process.exit(1);
  }
}

export function runRun(args: string[]): void {
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
    process.exit(1);
  }

  const childCommand = args[separatorIdx + 1];
  const childArgs = args.slice(separatorIdx + 2);

  runWithSecrets(childCommand, childArgs, { only }).then((code) => {
    process.exit(code);
  }).catch((err) => {
    console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(1);
  });
}

export function runEnv(args: string[]): void {
  if (args.includes('--help') || args.includes('-h')) {
    console.log('\n  Usage: eval $(secretless-ai env [--only KEY1,KEY2])');
    console.log('\n  Export secrets as shell environment variables.');
    console.log('  Designed for use with eval in shell profiles.\n');
    console.log('  Options:');
    console.log('    --only KEY1,KEY2   Export only the specified secrets\n');
    return;
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

  generateEnvExports({ only }).then((output) => {
    if (output) {
      process.stdout.write(output + '\n');
    }
  }).catch((err) => {
    // Silently fail — this runs inside eval in shell profiles.
    process.stderr.write(`secretless: env: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}

export function runImport(args: string[]): void {
  console.log('\n  Secretless Import\n');

  if (args.includes('--detect')) {
    const dir = process.cwd();
    const files = detectEnvFiles(dir);
    if (files.length === 0) {
      console.log('  No .env files found in current directory.\n');
      return;
    }

    let totalImported = 0;
    const importNext = (idx: number): void => {
      if (idx >= files.length) {
        console.log(`\n  Total: ${totalImported} secret(s) imported.\n`);
        return;
      }
      const file = files[idx];
      importEnvFile(file).then((result) => {
        console.log(`  ${path.basename(file)}: ${result.imported} imported`);
        if (result.skipped > 0) {
          console.log(`    (${result.skipped} skipped — invalid names)`);
        }
        totalImported += result.imported;
        importNext(idx + 1);
      }).catch((err) => {
        console.error(`  Error importing ${file}: ${err instanceof Error ? err.message : String(err)}`);
        importNext(idx + 1);
      });
    };
    importNext(0);
    return;
  }

  const filePath = args[0];
  if (!filePath) {
    console.error('  Usage: secretless-ai import <file> or secretless-ai import --detect\n');
    process.exit(1);
  }

  const resolvedPath = path.resolve(filePath);
  const nodeFs = require('fs') as typeof import('fs');
  if (!nodeFs.existsSync(resolvedPath)) {
    console.error(`  File not found: ${filePath}`);
    console.error('  Check the path and try again.\n');
    process.exit(1);
  }
  importEnvFile(resolvedPath).then((result) => {
    if (result.imported === 0) {
      console.log('  No secrets found in file.');
      console.log('  Expected format: KEY=value (one per line)\n');
      return;
    }

    console.log(`  Imported ${result.imported} secret(s) from ${path.basename(resolvedPath)}:\n`);
    for (const name of result.entries) {
      console.log(`    + ${name}`);
    }
    if (result.skipped > 0) {
      console.log(`\n  Skipped: ${result.skipped} (invalid names)`);
    }
    console.log();
  }).catch((err) => {
    console.error(`  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}

export function runSetupCommand(args: string[]): void {
  const checkOnly = args.includes('--check');
  const dir = process.cwd();

  console.log('\n  Secretless Setup\n');

  runSetup(dir, { check: checkOnly }).then((result) => {
    if (checkOnly) {
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
        process.exit(1);
      } else {
        console.log('  PASS: All required secrets are configured.\n');
      }
      return;
    }

    if (result.set > 0 || result.existing > 0) {
      console.log(`\n  Set:      ${result.set} secret(s)`);
      console.log(`  Existing: ${result.existing}`);
      console.log(`  Skipped:  ${result.skipped} (optional)\n`);
    }
  }).catch((err) => {
    console.error(`  Error: ${err instanceof Error ? err.message : String(err)}\n`);
    process.exit(1);
  });
}
