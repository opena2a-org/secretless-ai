/**
 * Per-command help (SLS-08).
 *
 * `migrate --help` used to print the 150-line global help, which names neither
 * `--from` nor `--to` — the two flags the refusal `migrate` prints points the
 * user at. Every registered verb now answers `--help` with its own flags, and
 * these tests walk the `VERBS` registry at run time so a verb or flag added
 * later is covered without editing this file.
 *
 * Spawns the built entry point (`dist/cli.js`), as cli.test.ts does, because
 * the property under test is what a real user sees. Unlike cli.test.ts there is
 * NO skip when the build is missing: `npm test` builds first (`pretest`), and a
 * skipped case here would satisfy nothing.
 */
import { describe, it, expect } from 'vitest';
import { spawnSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { VERBS } from './argv';

const CLI_PATH = path.resolve(__dirname, '..', 'dist', 'cli.js');

/** Every registered verb, read when the suite loads. */
const verbs = Object.keys(VERBS);

/** Runners that print their own help, outside this unit's branding rules (AC4). */
const OWN_HELP_RUNNERS = ['setup', 'env'];

/** Telemetry off, colour off, and the embedding prefix UNSET unless a case sets it. */
function baseEnv(overrides: Record<string, string> = {}): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, OPENA2A_TELEMETRY: 'off', NO_COLOR: '1' };
  delete env.SECRETLESS_CLI_PREFIX;
  return { ...env, ...overrides };
}

function cli(args: string[], opts: { cwd: string; env?: NodeJS.ProcessEnv }) {
  return spawnSync(process.execPath, [CLI_PATH, ...args], {
    encoding: 'utf-8',
    stdio: ['pipe', 'pipe', 'pipe'],
    cwd: opts.cwd,
    env: opts.env ?? baseEnv(),
  });
}

function scratch(prefix: string): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

describe('SLS-08 every registered command answers --help with its own flags', () => {
  it('SLS-08.AC2 the VERBS registry is non-empty, so the walks below are not vacuous', () => {
    expect(verbs.length).toBeGreaterThan(0);
    expect(verbs).toContain('migrate');
  });

  it.each(['--help', '-h'])('SLS-08.AC1 migrate %s prints help for migrate itself, not the global help', (flag) => {
    const tmp = scratch('sls08-ac1-');
    try {
      const res = cli(['migrate', flag], { cwd: tmp });
      expect(res.status, res.stderr).toBe(0);
      expect(res.stdout).toContain('--from');
      expect(res.stdout).toContain('--to');
      expect(res.stdout).toContain('migrate');
      expect(res.stdout).not.toContain('Quick start:');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it.each(verbs)('SLS-08.AC2 %s --help exits 0 and names every flag registered for it', (verb) => {
    const tmp = scratch('sls08-ac2-');
    try {
      const res = cli([verb, '--help'], { cwd: tmp });
      expect(res.status, res.stderr).toBe(0);
      for (const flag of Object.keys(VERBS[verb].flags)) {
        expect(res.stdout, `${verb} --help must name ${flag}`).toContain(flag);
      }
      expect(res.stdout).not.toContain('Quick start:');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it.each(verbs)('SLS-08.AC3 %s --help performs no action: exit 0 and the working directory is untouched', (verb) => {
    const home = scratch('sls08-ac3-home-');
    const cwd = scratch('sls08-ac3-cwd-');
    try {
      const before = fs.readdirSync(cwd);
      const res = cli([verb, '--help'], { cwd, env: baseEnv({ HOME: home }) });
      expect(res.status, res.stderr).toBe(0);
      expect(fs.readdirSync(cwd)).toEqual(before);
    } finally {
      fs.rmSync(home, { recursive: true, force: true });
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it.each(verbs.filter((v) => !OWN_HELP_RUNNERS.includes(v)))(
    'SLS-08.AC4 %s --help keeps the global help branding rules standalone and under a host prefix',
    (verb) => {
      const tmp = scratch('sls08-ac4-');
      try {
        const standalone = cli([verb, '--help'], { cwd: tmp });
        expect(standalone.status, standalone.stderr).toBe(0);
        expect(standalone.stdout).toMatch(/Secretless v/);

        const embedded = cli([verb, '--help'], {
          cwd: tmp,
          env: baseEnv({ SECRETLESS_CLI_PREFIX: 'opena2a secrets' }),
        });
        expect(embedded.status, embedded.stderr).toBe(0);
        expect(embedded.stdout).toContain(`opena2a secrets ${verb}`);
        expect(embedded.stdout).not.toMatch(/Secretless v/);
        expect(embedded.stdout).not.toMatch(/npx secretless-ai/);
        expect(embedded.stdout).not.toMatch(/^\s*secretless-ai\s/m);
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    },
  );

  it.each([['--help'], ['-h'], ['(no argument)']])(
    'SLS-08.AC5 bare `%s` still prints the global help',
    (arg) => {
      const tmp = scratch('sls08-ac5-');
      try {
        const args = arg === '(no argument)' ? [] : [arg];
        const res = cli(args, { cwd: tmp });
        expect(res.status, res.stderr).toBe(0);
        expect(res.stdout).toContain('Quick start:');
      } finally {
        fs.rmSync(tmp, { recursive: true, force: true });
      }
    },
  );
});
