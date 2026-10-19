import { describe, it, expect, afterEach } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { pathToFileURL } from 'url';

/**
 * An embedding host sets SECRETLESS_CLI_PREFIX so the CLI prints the host's
 * command name. The suite asserts the default `npx secretless-ai`, so
 * vitest.config.ts removes a prefix set where the suite runs before vitest
 * copies process.env into the workers (#349).
 *
 * CLAUDE_CONFIG_DIR moves the default transcript directory away from
 * ~/.claude (#237). The tests give each CLI child its own HOME to keep it off
 * real transcripts, so vitest.config.ts removes that variable the same way.
 */

const REPO_ROOT = path.resolve(__dirname, '..');
// Outside src/, so loaded by URL rather than through the compiler's module resolution.
const CONFIG = pathToFileURL(path.join(REPO_ROOT, 'vitest.config.ts')).href;
const VITEST = path.join(REPO_ROOT, 'node_modules', 'vitest', 'vitest.mjs');

const FIRST_CASE = 'the prefix is unset in this worker';
const CONFIG_DIR_CASE = 'CLAUDE_CONFIG_DIR is unset in this worker';

/** A configuration directory as a Claude Code session sets it; never created. */
const HOST_CONFIG_DIR = path.join(os.tmpdir(), 'secretless-host-claude-config');

interface ConfigModule {
  default: { test?: { env?: Record<string, string> } };
}

// Read before this file loads the config, which removes the variables here too.
const PREFIX_IN_WORKER = process.env.SECRETLESS_CLI_PREFIX;
const CONFIG_DIR_IN_WORKER = process.env.CLAUDE_CONFIG_DIR;

const before = process.env.SECRETLESS_CLI_PREFIX;
const configDirBefore = process.env.CLAUDE_CONFIG_DIR;
afterEach(() => {
  if (before === undefined) delete process.env.SECRETLESS_CLI_PREFIX;
  else process.env.SECRETLESS_CLI_PREFIX = before;
  if (configDirBefore === undefined) delete process.env.CLAUDE_CONFIG_DIR;
  else process.env.CLAUDE_CONFIG_DIR = configDirBefore;
});

// Each start of the nested run is bounded: `vitest run` sometimes prints
// nothing at start and never exits (seen on macOS arm64 with vitest 4.1.5), and
// spawnSync would wait on it for good, as the case's own timeout cannot end a
// synchronous wait. Two bounded starts fit inside the case's timeout.
const START_LIMIT_MS = 50_000;

interface Start {
  status: number | null;
  output: string;
  timedOut: boolean;
}

/** One start of `node <entry>` on the first case, or on `testName`, ended with SIGKILL after `limitMs`. */
function startFirstCase(entry: string, env: NodeJS.ProcessEnv, limitMs: number, testName: string = FIRST_CASE): Start {
  const run = spawnSync(process.execPath, [entry, 'run', 'src/vitest-config-env.test.ts', '--testNamePattern', testName], {
    cwd: REPO_ROOT,
    env,
    encoding: 'utf8',
    timeout: limitMs,
    killSignal: 'SIGKILL',
  });
  return {
    status: run.status,
    output: `${run.stdout ?? ''}${run.stderr ?? ''}`.replace(/\x1b\[[0-9;]*m/g, ''),
    timedOut: (run.error as NodeJS.ErrnoException | undefined)?.code === 'ETIMEDOUT',
  };
}

/**
 * The first of at most two starts that printed something, or null when both
 * printed nothing before they were ended. A start that printed and then ran
 * past the limit is returned, not retried: it is a run that hung, not one
 * that never started.
 */
function firstStartThatPrinted(start: () => Start): Start | null {
  for (let attempt = 0; attempt < 2; attempt++) {
    const run = start();
    if (!run.timedOut || run.output.trim() !== '') return run;
  }
  return null;
}

describe('vitest.config.ts and SECRETLESS_CLI_PREFIX', () => {
  it(`${FIRST_CASE}; if this fails, vitest.config.ts lost its delete line and a prefix set where the suite runs reaches every test`, () => {
    expect(PREFIX_IN_WORKER).toBeUndefined();
  });

  it('the first case passes in a run started with a prefix set, so it holds whatever the environment of this run', { timeout: 120_000 }, (ctx) => {
    // The case above can fail only when a prefix is set where the suite runs,
    // so it is run again in a vitest started with one. vitest's own variables
    // are dropped, so the new run starts from the environment `npm test` gives
    // it rather than from this worker's.
    const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('VITEST')));
    const run = firstStartThatPrinted(() =>
      startFirstCase(VITEST, { ...env, SECRETLESS_CLI_PREFIX: 'host secrets' }, START_LIMIT_MS),
    );
    if (run === null) {
      return ctx.skip(`not measured: two starts of vitest run printed nothing in ${START_LIMIT_MS / 1000} s and were ended`);
    }

    expect(run.output).toMatch(/Tests\s+1 passed/);
    expect(run.status, run.output).toBe(0);
  });

  describe('a start of the nested run that hangs', () => {
    let dir: string | undefined;
    afterEach(() => {
      if (dir) fs.rmSync(dir, { recursive: true, force: true });
      dir = undefined;
    });

    /** A stand-in for vitest that counts its starts in `starts` and runs `body`. */
    function standIn(body: string): { entry: string; starts: () => number } {
      dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vitest-stand-in-'));
      const log = path.join(dir, 'starts');
      const entry = path.join(dir, 'stand-in.cjs');
      fs.writeFileSync(
        entry,
        [
          "const fs = require('fs');",
          `fs.appendFileSync(${JSON.stringify(log)}, 'x');`,
          `const start = fs.readFileSync(${JSON.stringify(log)}, 'utf8').length;`,
          body,
          '',
        ].join('\n'),
      );
      return { entry, starts: () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').length : 0) };
    }

    const HANG = 'setInterval(() => {}, 1000);';

    it('is ended at the limit and started once more; two starts that print nothing are not measured', () => {
      const { entry, starts } = standIn(HANG);
      const began = Date.now();

      const run = firstStartThatPrinted(() => startFirstCase(entry, process.env, 1000));

      expect(run).toBeNull();
      expect(starts()).toBe(2);
      expect(Date.now() - began).toBeLessThan(30_000);
    });

    it('a second start that prints is the one read', () => {
      const { entry, starts } = standIn(
        `if (start === 1) { ${HANG} } else { console.log('Tests  1 passed'); }`,
      );

      const run = firstStartThatPrinted(() => startFirstCase(entry, process.env, 1000));

      expect(starts()).toBe(2);
      expect(run).toEqual({ status: 0, output: 'Tests  1 passed\n', timedOut: false });
    });

    it('a start that printed before it hung is not started again, and is read as a failed run', () => {
      const { entry, starts } = standIn(`console.log('RUN'); ${HANG}`);

      const run = firstStartThatPrinted(() => startFirstCase(entry, process.env, 1000));

      expect(starts()).toBe(1);
      expect(run).toEqual({ status: null, output: 'RUN\n', timedOut: true });
    });
  });

  // The one import of the config in this worker, so CLAUDE_CONFIG_DIR is
  // checked here too: a second import would not run the config again.
  it('loading the config removes a prefix and a CLAUDE_CONFIG_DIR set in the process that loads it, and keeps the keychain and telemetry switches', async () => {
    process.env.SECRETLESS_CLI_PREFIX = 'host secrets';
    process.env.CLAUDE_CONFIG_DIR = HOST_CONFIG_DIR;

    const { default: config } = (await import(CONFIG)) as ConfigModule;

    expect(process.env.SECRETLESS_CLI_PREFIX).toBeUndefined();
    expect(process.env.CLAUDE_CONFIG_DIR).toBeUndefined();
    expect(config.test?.env).toEqual({ SECRETLESS_OS_KEYCHAIN: 'off', OPENA2A_TELEMETRY: 'off' });
  });
});

describe('vitest.config.ts and CLAUDE_CONFIG_DIR', () => {
  it(`${CONFIG_DIR_CASE}; if this fails, vitest.config.ts lost its delete line and a CLI child started with its own HOME reads the transcripts of the session running the suite`, () => {
    expect(CONFIG_DIR_IN_WORKER).toBeUndefined();
  });

  it('the case above passes in a run started with CLAUDE_CONFIG_DIR set, so it holds whatever the environment of this run', { timeout: 120_000 }, (ctx) => {
    const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('VITEST')));
    const run = firstStartThatPrinted(() =>
      startFirstCase(VITEST, { ...env, CLAUDE_CONFIG_DIR: HOST_CONFIG_DIR }, START_LIMIT_MS, CONFIG_DIR_CASE),
    );
    if (run === null) {
      return ctx.skip(`not measured: two starts of vitest run printed nothing in ${START_LIMIT_MS / 1000} s and were ended`);
    }

    expect(run.output).toMatch(/Tests\s+1 passed/);
    expect(run.status, run.output).toBe(0);
  });
});
