/**
 * Secret injection — run any command with secrets injected as env vars.
 *
 * Replaces .env files entirely. Loads secrets from the SecretStore,
 * merges them into the environment, and spawns the child process.
 */

import { spawn } from 'child_process';
import { SecretStore } from './secret-store';
import type { SecretStoreOptions } from './secret-store';

export interface RunOptions extends SecretStoreOptions {
  /** Only inject these specific secret names. If undefined, inject all. */
  only?: string[];
}

/**
 * Run a command with secrets injected as environment variables.
 *
 * Returns the child process exit code.
 */
export async function runWithSecrets(
  command: string,
  args: string[],
  options?: RunOptions,
): Promise<number> {
  const store = new SecretStore(options);
  const secrets = await store.loadSecrets(options?.only);

  const secretCount = Object.keys(secrets).length;
  if (secretCount === 0) {
    // Check if the store actually has secrets (backend may have failed to load them)
    const allSecrets = await store.listSecrets();
    if (allSecrets.length > 0) {
      process.stderr.write(
        `secretless: Backend returned 0 secrets but the store contains ${allSecrets.length} entries. ` +
        'This may indicate a backend failure. Aborting to prevent running without secrets.\n',
      );
      return 1;
    }
    process.stderr.write(
      'secretless: No secrets found. Use `secretless-ai secret set <NAME>` to store secrets.\n',
    );
  }

  const childEnv = { ...process.env, ...secrets };

  const child = spawn(command, args, {
    env: childEnv,
    stdio: 'inherit',
  });

  // Forward signals to child
  const signals: NodeJS.Signals[] = ['SIGTERM', 'SIGINT', 'SIGHUP'];
  const handlers: Array<() => void> = [];
  for (const sig of signals) {
    const handler = () => child.kill(sig);
    handlers.push(handler);
    process.on(sig, handler);
  }

  return new Promise<number>((resolve) => {
    child.on('close', (code) => {
      // Clean up signal handlers
      for (let i = 0; i < signals.length; i++) {
        process.removeListener(signals[i], handlers[i]);
      }
      resolve(code ?? 1);
    });

    child.on('error', (err) => {
      process.stderr.write(`secretless: Failed to start ${command}: ${err.message}\n`);
      for (let i = 0; i < signals.length; i++) {
        process.removeListener(signals[i], handlers[i]);
      }
      resolve(1);
    });
  });
}
