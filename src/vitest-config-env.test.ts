import { describe, it, expect, afterEach } from 'vitest';
import * as path from 'path';
import { pathToFileURL } from 'url';

/**
 * An embedding host sets SECRETLESS_CLI_PREFIX so the CLI prints the host's
 * command name. The suite asserts the default `npx secretless-ai`, so
 * vitest.config.ts removes a prefix set where the suite runs before vitest
 * copies process.env into the workers (#349).
 */

// Outside src/, so loaded by URL rather than through the compiler's module resolution.
const CONFIG = pathToFileURL(path.resolve(__dirname, '..', 'vitest.config.ts')).href;

interface ConfigModule {
  default: { test?: { env?: Record<string, string> } };
}

// Read before this file loads the config, which removes the variable here too.
const PREFIX_IN_WORKER = process.env.SECRETLESS_CLI_PREFIX;

const before = process.env.SECRETLESS_CLI_PREFIX;
afterEach(() => {
  if (before === undefined) delete process.env.SECRETLESS_CLI_PREFIX;
  else process.env.SECRETLESS_CLI_PREFIX = before;
});

describe('vitest.config.ts and SECRETLESS_CLI_PREFIX', () => {
  it('the prefix is unset in this worker; if this fails, vitest.config.ts lost its delete line and a prefix set where the suite runs reaches every test', () => {
    expect(PREFIX_IN_WORKER).toBeUndefined();
  });

  it('loading the config removes a prefix set in the process that loads it, and keeps the keychain switch', async () => {
    process.env.SECRETLESS_CLI_PREFIX = 'host secrets';

    const { default: config } = (await import(CONFIG)) as ConfigModule;

    expect(process.env.SECRETLESS_CLI_PREFIX).toBeUndefined();
    expect(config.test?.env).toEqual({ SECRETLESS_OS_KEYCHAIN: 'off' });
  });
});
