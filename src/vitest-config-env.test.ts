import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as path from 'path';
import { pathToFileURL } from 'url';

/**
 * An embedding host sets SECRETLESS_CLI_PREFIX so the CLI prints the host's
 * command name. The suite asserts the default `npx secretless-ai`, so
 * vitest.config.ts removes a prefix set where the suite runs before vitest
 * copies process.env into the workers (#349).
 */

const REPO_ROOT = path.resolve(__dirname, '..');
// Outside src/, so loaded by URL rather than through the compiler's module resolution.
const CONFIG = pathToFileURL(path.join(REPO_ROOT, 'vitest.config.ts')).href;
const VITEST = path.join(REPO_ROOT, 'node_modules', 'vitest', 'vitest.mjs');

const FIRST_CASE = 'the prefix is unset in this worker';

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
  it(`${FIRST_CASE}; if this fails, vitest.config.ts lost its delete line and a prefix set where the suite runs reaches every test`, () => {
    expect(PREFIX_IN_WORKER).toBeUndefined();
  });

  it('the first case passes in a run started with a prefix set, so it holds whatever the environment of this run', { timeout: 120_000 }, () => {
    // The case above can fail only when a prefix is set where the suite runs,
    // so it is run again in a vitest started with one. vitest's own variables
    // are dropped, as they would mark the new run as a worker of this one.
    const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('VITEST')));
    const run = spawnSync(
      process.execPath,
      [VITEST, 'run', 'src/vitest-config-env.test.ts', '--testNamePattern', FIRST_CASE],
      { cwd: REPO_ROOT, env: { ...env, SECRETLESS_CLI_PREFIX: 'host secrets' }, encoding: 'utf8' },
    );

    const output = (run.stdout + run.stderr).replace(/\x1b\[[0-9;]*m/g, '');
    expect(output).toMatch(/Tests\s+1 passed/);
    expect(run.status, output).toBe(0);
  });

  it('loading the config removes a prefix set in the process that loads it, and keeps the keychain switch', async () => {
    process.env.SECRETLESS_CLI_PREFIX = 'host secrets';

    const { default: config } = (await import(CONFIG)) as ConfigModule;

    expect(process.env.SECRETLESS_CLI_PREFIX).toBeUndefined();
    expect(config.test?.env).toEqual({ SECRETLESS_OS_KEYCHAIN: 'off' });
  });
});
