import * as path from 'path';
import { SecretStore } from '../secret-store';
import { getShellHookLine, SHELL_HOOK_MARKER } from '../env';

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

export async function runSecret(args: string[]): Promise<number> {
  const subcommand = args[0];

  switch (subcommand) {
    case 'set': {
      const nameArg = args[1];
      if (!nameArg) {
        console.error('\n  Usage: secretless-ai secret set <NAME[=VALUE]>\n');
        return 1;
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
          return 1;
        }
        if (!SECRET_NAME_RE.test(name)) {
          console.error('  Error: Invalid secret name. Use letters, numbers, underscores, hyphens. Must start with a letter.\n');
          return 1;
        }
        const store = new SecretStore();
        try {
          await store.setSecret(name, value);
          console.log(`  Stored: ${name}`);
          ensureShellHook();
          return 0;
        } catch (err) {
          console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
          return 1;
        }
      }

      // Read value from stdin
      const name = nameArg;
      if (!SECRET_NAME_RE.test(name)) {
        console.error('  Error: Invalid secret name. Use letters, numbers, underscores, hyphens. Must start with a letter.\n');
        return 1;
      }

      const value = await readSecretFromStdin(name);
      if (value === null) {
        console.error('  Error: no value provided.');
        console.error('  Usage: secretless-ai secret set NAME=VALUE');
        console.error('  Or:    echo "value" | secretless-ai secret set NAME\n');
        return 1;
      }
      const store = new SecretStore();
      try {
        await store.setSecret(name, value);
        console.log(`  Stored: ${name}`);
        ensureShellHook();
        return 0;
      } catch (err) {
        console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
        return 1;
      }
    }

    case 'list': {
      const store = new SecretStore();
      try {
        const names = await store.listSecrets();
        if (names.length === 0) {
          console.log('\n  No secrets stored.');
          console.log('  Store one:    npx secretless-ai secret set MY_KEY=my_value');
          console.log('  Import .env:  npx secretless-ai import .env\n');
          return 0;
        }
        console.log(`\n  ${names.length} secret(s):\n`);
        for (const n of names) {
          console.log(`    ${n}`);
        }
        console.log();
        return 0;
      } catch (err) {
        console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
        return 1;
      }
    }

    case 'get': {
      const positional = args.slice(1).filter(a => !a.startsWith('--'));
      const name = positional[0];
      if (!name) {
        console.error('\n  Usage: secretless-ai secret get <NAME>\n');
        return 1;
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
        return 1;
      }

      const store = new SecretStore();
      try {
        const value = await store.getSecret(name);
        if (value === undefined) {
          console.error(`  Secret not found: ${name}`);
          return 1;
        }
        process.stdout.write(value);
        // Add newline if stdout is a terminal
        if (process.stdout.isTTY) {
          process.stdout.write('\n');
        }
        return 0;
      } catch (err) {
        console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
        return 1;
      }
    }

    case 'rm':
    case 'remove':
    case 'delete': {
      const name = args[1];
      if (!name) {
        console.error('\n  Usage: secretless-ai secret rm <NAME>\n');
        return 1;
      }
      const store = new SecretStore();
      try {
        const removed = await store.removeSecret(name);
        if (removed) {
          console.log(`  Removed: ${name}`);
          return 0;
        }
        console.error(`  Secret not found: ${name}`);
        return 1;
      } catch (err) {
        console.error(`  Error: ${err instanceof Error ? err.message : String(err)}`);
        return 1;
      }
    }

    default:
      // No subcommand is an exploration, not an error — show usage cleanly and succeed
      // (#80). Reserve the "Unknown secret command" error for a real unrecognized token.
      if (subcommand === undefined) {
        console.log('\n  Usage: secretless-ai secret <set|list|get|rm> [args]\n');
        return 0;
      }
      console.error(`\n  Unknown secret command: ${subcommand}`);
      console.log('  Usage: secretless-ai secret <set|list|get|rm> [args]\n');
      return 1;
  }
}

/**
 * Read a secret value from stdin. In TTY mode, reads one line (until Enter).
 * In piped mode, reads until stdin closes. Returns null if value is empty.
 */
function readSecretFromStdin(name: string): Promise<string | null> {
  return new Promise((resolve) => {
    let input = '';
    process.stdin.setEncoding('utf-8');

    if (process.stdin.isTTY) {
      process.stderr.write(`  Enter value for ${name}: `);
    }

    let resolved = false;
    const finish = (value: string): void => {
      if (resolved) return;
      resolved = true;
      const trimmed = value.trim();
      resolve(trimmed === '' ? null : trimmed);
    };

    process.stdin.on('data', (chunk) => {
      input += chunk;
      // In TTY mode, each Enter press delivers a line — store immediately.
      // In piped mode, we may get multiple chunks; wait for 'end'.
      if (process.stdin.isTTY) {
        finish(input);
      }
    });

    // Piped mode: wait for stdin to close, then store
    process.stdin.on('end', () => {
      finish(input);
    });
  });
}
