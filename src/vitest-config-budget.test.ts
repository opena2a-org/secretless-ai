import { describe, it, expect } from 'vitest';
import * as path from 'path';
import { pathToFileURL } from 'url';

/**
 * Tests here start the built CLI, git and recorder programs as child
 * processes, and hooks start them too. vitest.config.ts gives each test and
 * each hook a 60 s budget in place of vitest's own defaults, 5 s for a test
 * and 10 s for a hook. #525 records tests that pass on an idle CI runner
 * running past the 5 s default on a loaded host. This file asserts that the
 * config sets both budgets, each to at least 60 s.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
// Outside src/, so loaded by URL rather than through the compiler's module resolution.
const CONFIG = pathToFileURL(path.join(REPO_ROOT, 'vitest.config.ts')).href;

/** The least budget a test or a hook that names no bound of its own may get. */
const MIN_BUDGET_MS = 60_000;

interface Budgets {
  testTimeout?: unknown;
  hookTimeout?: unknown;
}

interface ConfigModule {
  default: { test?: Budgets };
}

async function budgets(): Promise<Budgets> {
  const { default: config } = (await import(CONFIG)) as ConfigModule;
  return config.test ?? {};
}

describe('vitest.config.ts budgets', () => {
  it('test.testTimeout is at least 60 s, so a test that names no bound of its own gets at least 60 s', async () => {
    const { testTimeout } = await budgets();
    expect(testTimeout, 'vitest.config.ts sets no numeric test.testTimeout, so vitest gives each test 5 s').toBeTypeOf('number');
    expect(testTimeout as number).toBeGreaterThanOrEqual(MIN_BUDGET_MS);
  });

  it('test.hookTimeout is at least 60 s, so a hook that names no bound of its own gets at least 60 s', async () => {
    const { hookTimeout } = await budgets();
    expect(hookTimeout, 'vitest.config.ts sets no numeric test.hookTimeout, so vitest gives each hook 10 s').toBeTypeOf('number');
    expect(hookTimeout as number).toBeGreaterThanOrEqual(MIN_BUDGET_MS);
  });
});
